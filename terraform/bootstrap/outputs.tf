output "state_bucket" {
  description = "S3 bucket holding the main stack's Terraform state (set as backend bucket)."
  value       = aws_s3_bucket.tfstate.bucket
}

output "ci_plan_role_arn" {
  description = "Role ARN for the PR plan workflow (GitHub secret AWS_PLAN_ROLE_ARN)."
  value       = aws_iam_role.ci_plan.arn
}

output "ci_apply_role_arn" {
  description = "Role ARN for the main-branch apply workflow (GitHub secret AWS_APPLY_ROLE_ARN)."
  value       = aws_iam_role.ci_apply.arn
}

output "oidc_provider_arn" {
  value = data.aws_iam_openid_connect_provider.github.arn
}
