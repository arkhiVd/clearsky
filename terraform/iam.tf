# Scanner Lambda role: read-only against scanned services, write only to
# its own findings table, SNS topic, and logs. Detection never mutates
# scanned resources; keep it that way as detectors are added.

resource "aws_iam_role" "scanner" {
  name = "${var.project_name}-scanner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "scanner" {
  name = "scanner-permissions"
  role = aws_iam_role.scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(length(var.member_role_arns) > 0 ? [{
      Sid      = "AssumeMemberRoles"
      Effect   = "Allow"
      Action   = ["sts:AssumeRole"]
      Resource = var.member_role_arns
      }] : [], [{
      # dashboard-onboarded accounts: any account whose conventional
      # readonly role trusts us (trust policy is the real gate)
      Sid      = "AssumeOnboardedMemberRoles"
      Effect   = "Allow"
      Action   = ["sts:AssumeRole"]
      Resource = "arn:aws:iam::*:role/${var.member_role_name}"
      }, {
      Sid      = "ReadAccountsRegistry"
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = aws_ssm_parameter.accounts.arn
      }], var.ai_triage_enabled ? [{
      Sid      = "BedrockTriage"
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel"]
      Resource = "arn:aws:bedrock:*::foundation-model/anthropic.*"
      }] : [], [
      {
        Sid    = "ReadOnlyDetectorApis"
        Effect = "Allow"
        Action = [
          "ec2:DescribeAddresses",
          "ec2:DescribeRegions",
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "sts:GetCallerIdentity",
          "ce:GetCostAndUsage",
          "ce:GetSavingsPlansPurchaseRecommendation",
          "ce:GetReservationPurchaseRecommendation",
          "rds:DescribeDBInstances",
          "lambda:ListFunctions",
          "eks:ListClusters",
          "backup:ListBackupJobs",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetLifecycleConfiguration",
          "s3:GetBucketLogging",
          "s3:ListBucketMultipartUploads",
          "dynamodb:ListTables",
          "logs:DescribeLogGroups",
          "cloudwatch:GetMetricData",
          "iam:ListUsers",
          "iam:ListMFADevices",
          "iam:ListAccessKeys",
          "iam:ListAttachedUserPolicies",
          "iam:GetLoginProfile",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketPolicyStatus",
          "cloudtrail:DescribeTrails",
          "ec2:DescribeNatGateways",
          "ec2:DescribeVpcEndpoints",
          "eks:DescribeCluster",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
        ]
        Resource = "*"
      },
      {
        Sid    = "ReportSnapshots"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = [
          "${aws_s3_bucket.reports.arn}/costwatch/*",
          "${aws_s3_bucket.reports.arn}/inventory/*",
          "${aws_s3_bucket.reports.arn}/posture/*",
          "${aws_s3_bucket.reports.arn}/meta/*",
        ]
      },
      {
        Sid    = "ReadPreviousSnapshots"
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = [
          "${aws_s3_bucket.reports.arn}/inventory/*",
          "${aws_s3_bucket.reports.arn}/posture/*",
          "${aws_s3_bucket.reports.arn}/meta/*",
        ]
      },
      {
        # Without ListBucket, GetObject on a missing key returns
        # AccessDenied instead of NoSuchKey, breaking first-run detection.
        Sid       = "ListReportsBucket"
        Effect    = "Allow"
        Action    = ["s3:ListBucket"]
        Resource  = aws_s3_bucket.reports.arn
        Condition = { StringLike = { "s3:prefix" = ["inventory/*", "posture/*"] } }
      },
      {
        Sid    = "FindingsTable"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Scan",
        ]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Sid      = "PublishReport"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.reports.arn
      },
      {
        Sid    = "Logs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.scanner.arn}:*"
      },
    ])
  })
}

resource "aws_iam_role" "scheduler" {
  name = "${var.project_name}-scheduler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "invoke-scanner"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = aws_lambda_function.scanner.arn
    }]
  })
}
