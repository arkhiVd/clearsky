# --- CI roles assumed by GitHub Actions via OIDC ---

locals {
  state_arn = aws_s3_bucket.tfstate.arn
}

data "aws_iam_policy_document" "state_access" {
  statement {
    sid       = "ListStateBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketVersioning"]
    resources = [local.state_arn]
  }
  statement {
    sid       = "RWStateObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${local.state_arn}/*"]
  }
}

# ===================== PLAN role (read-only) =====================
resource "aws_iam_role" "ci_plan" {
  name                 = "clearsky-ci-plan"
  assume_role_policy   = data.aws_iam_policy_document.assume_plan.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.ci_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "plan_state" {
  name   = "state-access"
  role   = aws_iam_role.ci_plan.id
  policy = data.aws_iam_policy_document.state_access.json
}

# ===================== APPLY role =====================
# Clearsky's stack spans many services (Lambda, DynamoDB, Cognito,
# CloudFront, S3, SNS, SSM, Scheduler, Budgets, ACM, Logs), so the apply
# role uses PowerUserAccess (which excludes IAM) plus an IAM statement
# scoped to this project's role-name prefix — CI can manage clearsky-*
# roles but cannot touch any other principal or escalate beyond it.
resource "aws_iam_role" "ci_apply" {
  name                 = "clearsky-ci-apply"
  assume_role_policy   = data.aws_iam_policy_document.assume_apply.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "apply_state" {
  name   = "state-access"
  role   = aws_iam_role.ci_apply.id
  policy = data.aws_iam_policy_document.state_access.json
}

resource "aws_iam_role_policy_attachment" "apply_poweruser" {
  role       = aws_iam_role.ci_apply.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_iam_role_policy" "apply_iam_scoped" {
  name = "iam-clearsky-roles-only"
  role = aws_iam_role.ci_apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ManageProjectRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:TagRole",
          "iam:UntagRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy",
          "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy",
          "iam:ListInstanceProfilesForRole", "iam:PassRole",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/clearsky-*"
      },
    ]
  })
}
