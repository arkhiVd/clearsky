# Deploy this in each MEMBER account. It creates the read-only role the
# home-account lambdas (scanner, chat agent, architecture generator, api)
# assume. Then onboard the role ARN in the Clearsky dashboard Accounts panel.
#
#   terraform apply -var 'trusted_role_arns=["arn:aws:iam::<HOME_ACCT>:role/cloud-detective-scanner", ...]'
#
# The dashboard's Accounts panel prints the exact ARN list to pass.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "trusted_role_arns" {
  description = "ARNs of the cloud-detective lambda roles in the home account (scanner, chat, arch, api)"
  type        = list(string)
}

variable "role_name" {
  type    = string
  default = "clearsky-readonly"
}

resource "aws_iam_role" "readonly" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.trusted_role_arns }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Same read surface the lambdas use at home: detector describe/list APIs
# plus the ViewOnlyAccess boundary chat/architecture already run under.
# No mutations in any of these.
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.readonly.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.readonly.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy" "extra_reads" {
  name = "detector-extra-reads"
  role = aws_iam_role.readonly.id

  # reads SecurityAudit lacks (cost/metrics/backup)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ce:GetCostAndUsage",
        "cloudwatch:GetMetricData",
        "backup:ListBackupJobs",
        "eks:ListClusters",
        "eks:DescribeCluster",
        "s3:ListBucketMultipartUploads",
      ]
      Resource = "*"
    }]
  })
}

output "role_arn" {
  value = aws_iam_role.readonly.arn
}
