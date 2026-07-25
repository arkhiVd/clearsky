variable "aws_region" {
  description = "Region for the Terraform state bucket and IAM (IAM is global; region is for the bucket)."
  type        = string
  default     = "us-east-1"
}

variable "github_owner" {
  description = "GitHub user/org that owns the repo allowed to assume the CI roles."
  type        = string
  default     = "arkhiVd"
}

variable "github_repo" {
  description = "GitHub repo name allowed to assume the CI roles (OIDC subject scoping)."
  type        = string
  default     = "clearsky"
}

variable "state_bucket_name" {
  description = "Globally unique S3 bucket name holding the main stack's Terraform state."
  type        = string
}
