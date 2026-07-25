# Provider config for the chat agent (api_base + model_id + api_key), set from
# the dashboard Settings panel and read by the api/chat Lambdas at runtime.
# SecureString (AWS-managed alias/aws/ssm key). Terraform seeds an empty
# placeholder and ignores the value so UI writes are not reverted on apply.

resource "aws_ssm_parameter" "chat_config" {
  name  = "/${var.project_name}/chat/config"
  type  = "SecureString"
  value = "{}"

  lifecycle {
    ignore_changes = [value]
  }
}

# Member-account registry: JSON list of {account_id, role_arn, label,
# added_at}, written by the dashboard Accounts panel and read by the
# scanner/chat/arch lambdas to know which accounts they may assume into.
resource "aws_ssm_parameter" "accounts" {
  name  = "/${var.project_name}/accounts"
  type  = "String"
  value = "[]"

  lifecycle {
    ignore_changes = [value]
  }
}
