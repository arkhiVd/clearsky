variable "project_name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "clearsky"
}

variable "aws_region" {
  description = "Region the tool itself is deployed in"
  type        = string
  default     = "us-east-1"
}

variable "scan_regions" {
  description = "Comma-separated regions the detectors scan"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address that receives daily digests (must confirm SNS subscription)"
  type        = string
}

variable "schedule_expression" {
  description = "When the daily scan runs (UTC). 01:30 UTC = 07:00 IST"
  type        = string
  default     = "cron(30 1 * * ? *)"
}

variable "member_role_arns" {
  description = "Cross-account read-only role ARNs to scan (deploy terraform/member-role in each member account)"
  type        = list(string)
  default     = []
}

variable "member_role_name" {
  description = "Conventional role name the lambdas may assume in ANY member account (dashboard-onboarded accounts use this instead of member_role_arns)"
  type        = string
  default     = "clearsky-readonly"
}

variable "ai_triage_enabled" {
  description = "Prepend a Bedrock (Claude) executive triage to the digest. Costs Bedrock tokens; detection is unaffected."
  type        = bool
  default     = false
}

variable "bedrock_model_id" {
  description = "Bedrock model for AI triage"
  type        = string
  default     = "anthropic.claude-opus-4-8"
}

# ---- Agentic chat model (external OpenAI-compatible endpoint) ----
# This account's Free-tier plan blocks Bedrock inference, so the chat agent
# calls an external provider (OpenAI / Google Gemini / Z.ai — all expose an
# OpenAI-compatible /chat/completions API). Only the LLM call leaves the
# account; the AWS read tools still run on the Lambda's IAM role.

variable "chat_api_base" {
  description = "OpenAI-compatible API base URL for the chat agent"
  type        = string
  default     = "https://generativelanguage.googleapis.com/v1beta/openai"
}

variable "chat_model_id" {
  description = "Model id on the chat_api_base provider"
  type        = string
  default     = "gemini-2.5-flash-lite"
}

variable "monthly_budget_usd" {
  description = "Account-wide monthly budget guardrail"
  type        = string
  default     = "10"
}

variable "custom_domain" {
  description = "Dashboard domain (DNS on Cloudflare; cert validated manually). Empty = CloudFront default URL only."
  type        = string
  default     = "clearsky.aravindakrishnan.cloud"
}

variable "enable_custom_domain" {
  description = "Attach custom_domain + ACM cert to CloudFront. Flip to true only after the cert is ISSUED (validation CNAME added in Cloudflare)."
  type        = bool
  default     = false
}
