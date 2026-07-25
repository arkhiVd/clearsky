data "aws_caller_identity" "current" {}

# ---------- Findings table ----------

resource "aws_dynamodb_table" "findings" {
  name         = "${var.project_name}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }
}

# ---------- Reports bucket (cost snapshots, later inventory CSVs) ----------

resource "aws_s3_bucket" "reports" {
  bucket = "${var.project_name}-reports-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "expire-old-reports"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------- Notification topic ----------

resource "aws_sns_topic" "reports" {
  name = "${var.project_name}-reports"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.reports.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------- Scanner Lambda ----------

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/.build/clearsky.zip"
}

resource "aws_lambda_function" "scanner" {
  function_name    = "${var.project_name}-scanner"
  role             = aws_iam_role.scanner.arn
  runtime          = "python3.13"
  handler          = "clearsky.handler.lambda_handler"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 600
  memory_size      = 512

  environment {
    variables = {
      FINDINGS_TABLE    = aws_dynamodb_table.findings.name
      REPORT_TOPIC_ARN  = aws_sns_topic.reports.arn
      REPORTS_BUCKET    = aws_s3_bucket.reports.bucket
      SCAN_REGIONS      = var.scan_regions
      MEMBER_ROLE_ARNS  = join(",", var.member_role_arns)
      ACCOUNTS_PARAM    = aws_ssm_parameter.accounts.name
      AI_TRIAGE_ENABLED = var.ai_triage_enabled ? "true" : "false"
      BEDROCK_MODEL_ID  = var.bedrock_model_id
      BEDROCK_REGION    = var.aws_region
    }
  }
}

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${aws_lambda_function.scanner.function_name}"
  retention_in_days = 14
}

# ---------- Daily schedule ----------

resource "aws_scheduler_schedule" "daily" {
  name                         = "${var.project_name}-daily"
  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = "UTC"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.scanner.arn
    role_arn = aws_iam_role.scheduler.arn
  }
}

# ---------- Account budget guardrail ----------

resource "aws_budgets_budget" "monthly" {
  name         = "${var.project_name}-monthly-guardrail"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}
