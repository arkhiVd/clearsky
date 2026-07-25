# API Lambda behind a function URL. CloudFront routes /api/* here with an
# Origin Access Control (SigV4) — AuthType AWS_IAM means only CloudFront
# (and IAM principals we grant) can invoke it. User identity is verified
# in-process from the Cognito Bearer token (clearsky.authn).

resource "aws_lambda_function" "api" {
  function_name    = "${var.project_name}-api"
  role             = aws_iam_role.api.arn
  runtime          = "python3.13"
  handler          = "clearsky.api.lambda_handler"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 29
  memory_size      = 256

  environment {
    variables = {
      FINDINGS_TABLE    = aws_dynamodb_table.findings.name
      REPORTS_BUCKET    = aws_s3_bucket.reports.bucket
      CHAT_TABLE        = aws_dynamodb_table.chat.name
      CHAT_FUNCTION     = aws_lambda_function.chat.function_name
      CHAT_CONFIG_PARAM = aws_ssm_parameter.chat_config.name
      SCANNER_FUNCTION  = aws_lambda_function.scanner.function_name
      ARCH_FUNCTION     = aws_lambda_function.arch.function_name
      SCAN_REGIONS      = var.scan_regions
      ACCOUNTS_PARAM    = aws_ssm_parameter.accounts.name
      MEMBER_ROLE_NAME  = var.member_role_name
      TRUSTED_ROLE_ARNS = join(",", [
        aws_iam_role.scanner.arn, aws_iam_role.chat.arn,
        aws_iam_role.arch.arn, aws_iam_role.api.arn,
      ])
      COGNITO_POOL_ID   = aws_cognito_user_pool.users.id
      COGNITO_CLIENT_ID = aws_cognito_user_pool_client.dashboard.id
      ORIGIN_VERIFY     = random_password.origin_verify.result
    }
  }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/lambda/${aws_lambda_function.api.function_name}"
  retention_in_days = 14
}

# The URL itself is unauthenticated, but unreachable in practice: every
# request must carry the CloudFront-injected x-origin-verify secret (checked
# first in the handler) AND a valid Cognito JWT (verified by clearsky.authn).
resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "public_url" {
  statement_id           = "AllowPublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.api.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "random_password" "origin_verify" {
  length  = 32
  special = false
}

resource "aws_iam_role" "api" {
  name = "${var.project_name}-api"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "api" {
  name = "api-permissions"
  role = aws_iam_role.api.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadFindings"
        Effect   = "Allow"
        Action   = ["dynamodb:Scan"]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Sid      = "ListRegions"
        Effect   = "Allow"
        Action   = ["ec2:DescribeRegions"]
        Resource = "*"
      },
      {
        Sid      = "ReadReports"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.reports.arn}/*"
      },
      {
        Sid      = "ListReports"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.reports.arn
      },
      {
        Sid      = "ChatConversations"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
        Resource = aws_dynamodb_table.chat.arn
      },
      {
        Sid    = "InvokeWorkers"
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          aws_lambda_function.chat.arn,
          aws_lambda_function.scanner.arn,
          aws_lambda_function.arch.arn,
        ]
      },
      {
        Sid    = "WriteJobArtifacts"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = [
          "${aws_s3_bucket.reports.arn}/architecture/*",
          "${aws_s3_bucket.reports.arn}/costexplore/*",
        ]
      },
      {
        Sid      = "CostExplorer"
        Effect   = "Allow"
        Action   = ["ce:GetCostAndUsage"]
        Resource = "*"
      },
      {
        Sid      = "ProviderAndAccountsConfig"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = [aws_ssm_parameter.chat_config.arn, aws_ssm_parameter.accounts.arn]
      },
      {
        # onboarding validation: prove the pasted member role's trust
        # policy actually lets us in before saving it to the registry
        Sid      = "AssumeOnboardedMemberRoles"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = "arn:aws:iam::*:role/${var.member_role_name}"
      },
      {
        Sid    = "Logs"
        Effect = "Allow"
        Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.api.arn}:*"
      },
    ]
  })
}
