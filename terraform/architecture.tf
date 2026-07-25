# Architecture diagram worker: discovers resources (read-only) and renders a
# draw.io file to S3 under architecture/jobs/<id>.json for the dashboard to
# poll and download. Read-only by construction (ViewOnlyAccess boundary); the
# only write is PutObject into the reports bucket's architecture/ prefix.

resource "aws_lambda_function" "arch" {
  function_name    = "${var.project_name}-arch"
  role             = aws_iam_role.arch.arn
  runtime          = "python3.13"
  handler          = "clearsky.architecture.lambda_handler"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      REPORTS_BUCKET    = aws_s3_bucket.reports.bucket
      SCAN_REGIONS      = var.scan_regions
      CHAT_CONFIG_PARAM = aws_ssm_parameter.chat_config.name
      FINDINGS_TABLE    = aws_dynamodb_table.findings.name
      ACCOUNTS_PARAM    = aws_ssm_parameter.accounts.name
    }
  }
}

resource "aws_cloudwatch_log_group" "arch" {
  name              = "/aws/lambda/${aws_lambda_function.arch.function_name}"
  retention_in_days = 14
}

resource "aws_iam_role" "arch" {
  name = "${var.project_name}-arch"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Read-only discovery boundary — describe/list across services.
resource "aws_iam_role_policy_attachment" "arch_readonly" {
  role       = aws_iam_role.arch.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy" "arch" {
  name = "arch-permissions"
  role = aws_iam_role.arch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CostOverlay"
        Effect   = "Allow"
        Action   = ["ce:GetCostAndUsage"]
        Resource = "*"
      },
      {
        Sid      = "WriteDiagram"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.reports.arn}/architecture/*"
      },
      {
        # cached auto-discovered region list (written by the scanner)
        Sid      = "ReadRegionCache"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.reports.arn}/meta/*"
      },
      {
        # findings overlay: badge diagram nodes with open findings
        Sid      = "ReadFindings"
        Effect   = "Allow"
        Action   = ["dynamodb:Scan"]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Sid      = "ReadProviderConfig"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = [aws_ssm_parameter.chat_config.arn, aws_ssm_parameter.accounts.arn]
      },
      {
        # diagram discovery inside dashboard-onboarded member accounts
        Sid      = "AssumeOnboardedMemberRoles"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = "arn:aws:iam::*:role/${var.member_role_name}"
      },
      {
        Sid    = "Logs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.arch.arn}:*"
      },
    ]
  })
}
