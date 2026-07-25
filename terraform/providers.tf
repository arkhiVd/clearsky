terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Phase 0: local state. Move to S3 backend once the S3 state bucket
  # pattern from portfolio-infra is replicated here.
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Owner       = "aravindakrishnan"
      Project     = var.project_name
      Environment = "lab"
      ManagedBy   = "terraform"
    }
  }
}
