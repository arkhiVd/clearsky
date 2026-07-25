terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Bootstrap uses LOCAL state on purpose: it creates the very S3 bucket the
  # main stack stores its state in, so it cannot depend on that bucket itself.
  # Keep bootstrap/terraform.tfstate out of git (gitignored).
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "clearsky"
      ManagedBy = "Terraform"
      Stack     = "bootstrap"
    }
  }
}
