terraform {
  # bucket supplied at init time: terraform init -backend-config="bucket=..."
  backend "s3" {
    key          = "main/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}
