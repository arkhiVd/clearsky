output "scanner_function_name" {
  value = aws_lambda_function.scanner.function_name
}

output "findings_table" {
  value = aws_dynamodb_table.findings.name
}

output "report_topic_arn" {
  value = aws_sns_topic.reports.arn
}

output "manual_run_command" {
  value = "aws lambda invoke --function-name ${aws_lambda_function.scanner.function_name} --region ${var.aws_region} /dev/stdout"
}

# Home-side role ARNs a member account's readonly role must trust
# (also shown in the dashboard Accounts panel via TRUSTED_ROLE_ARNS)
output "trusted_role_arns" {
  value = [
    aws_iam_role.scanner.arn,
    aws_iam_role.chat.arn,
    aws_iam_role.arch.arn,
    aws_iam_role.api.arn,
  ]
}

output "dashboard_url" {
  value = var.enable_custom_domain ? "https://${var.custom_domain}/" : "https://${aws_cloudfront_distribution.site.domain_name}/"
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.site.id
}

output "site_bucket" {
  value = aws_s3_bucket.site.bucket
}

output "cognito_pool_id" {
  value = aws_cognito_user_pool.users.id
}

output "cognito_client_id" {
  value = aws_cognito_user_pool_client.dashboard.id
}

output "create_dashboard_user_command" {
  value = "aws cognito-idp admin-create-user --user-pool-id ${aws_cognito_user_pool.users.id} --username <email> --user-attributes Name=email,Value=<email> Name=email_verified,Value=true --region ${var.aws_region}"
}

# Add these in Cloudflare (DNS-only/grey cloud), then set enable_custom_domain=true:
#   1. the cert validation CNAME below
#   2. CNAME  clearsky -> cloudfront_domain below
output "acm_validation_records" {
  value = var.custom_domain != "" ? [
    for o in aws_acm_certificate.site[0].domain_validation_options :
    { name = o.resource_record_name, type = o.resource_record_type, value = o.resource_record_value }
  ] : []
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.site.domain_name
}
