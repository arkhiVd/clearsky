# Agentic chat: "Ask the Detective". A separate Lambda runs a Bedrock
# Converse tool-use loop (may take minutes), so the API Lambda async-invokes
# it and the SPA polls. Read-only by construction: the aws_read tool is
# bounded by the AWS-managed ViewOnlyAccess policy on this role, on top of
# the code-level verb allowlist / data-plane denylist in chat.py.

# ---------- Conversation table ----------

resource "aws_dynamodb_table" "chat" {
  name         = "${var.project_name}-chat"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }
}

# ---------- Chat agent Lambda ----------

resource "aws_lambda_function" "chat" {
  function_name    = "${var.project_name}-chat"
  role             = aws_iam_role.chat.arn
  runtime          = "python3.13"
  handler          = "clearsky.chat.lambda_handler"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      CHAT_TABLE        = aws_dynamodb_table.chat.name
      FINDINGS_TABLE    = aws_dynamodb_table.findings.name
      REPORTS_BUCKET    = aws_s3_bucket.reports.bucket
      CHAT_API_BASE     = var.chat_api_base
      CHAT_MODEL_ID     = var.chat_model_id
      CHAT_CONFIG_PARAM = aws_ssm_parameter.chat_config.name
      ACCOUNTS_PARAM    = aws_ssm_parameter.accounts.name
    }
  }
}

resource "aws_cloudwatch_log_group" "chat" {
  name              = "/aws/lambda/${aws_lambda_function.chat.function_name}"
  retention_in_days = 14
}

# ---------- Chat agent IAM ----------

resource "aws_iam_role" "chat" {
  name = "${var.project_name}-chat"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Hard read-only boundary for the aws_read tool. The code allowlist narrows
# this further (describe_/list_/get_ only, secretsmanager/kms denied), but
# this managed policy is the actual security guarantee. Inference is
# external (OpenAI-compatible endpoint), so no bedrock permission is needed.
resource "aws_iam_role_policy_attachment" "chat_readonly" {
  role       = aws_iam_role.chat.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy" "chat" {
  name = "chat-permissions"
  role = aws_iam_role.chat.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CostExplorer"
        Effect   = "Allow"
        Action   = ["ce:GetCostAndUsage"]
        Resource = "*"
      },
      {
        Sid      = "ConversationTable"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.chat.arn
      },
      {
        # AI investigation: read findings, record AI-discovered ones, and
        # mark findings resolved after live verification
        Sid    = "Findings"
        Effect = "Allow"
        Action = [
          "dynamodb:Scan", "dynamodb:GetItem",
          "dynamodb:PutItem", "dynamodb:UpdateItem",
        ]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        # diagram edit tools: read the job artifact, write re-rendered revisions
        Sid      = "ArchitectureJobs"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.reports.arn}/architecture/jobs/*"
      },
      {
        Sid      = "ReadProviderConfig"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = [aws_ssm_parameter.chat_config.arn, aws_ssm_parameter.accounts.arn]
      },
      {
        # aws_read against dashboard-onboarded member accounts (their
        # trust policy is the gate; role is ViewOnly+SecurityAudit)
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
        Resource = "${aws_cloudwatch_log_group.chat.arn}:*"
      },
    ]
  })
}
