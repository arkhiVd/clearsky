# Static multipage dashboard: private S3 bucket + CloudFront with OAC.
# /api/* is a second origin — the API Lambda's function URL, gated by a
# CloudFront-injected x-origin-verify secret (checked in the handler).
# Cost: CloudFront + S3 sit inside the always-free tier at this traffic.

resource "aws_s3_bucket" "site" {
  bucket = "${var.project_name}-site-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "CloudFrontOACRead"
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.site.arn}/*"
      Condition = {
        StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.site.arn }
      }
    }]
  })
}

resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "${var.project_name}-s3-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Pretty URLs: /findings -> /findings.html, / -> /index.html
resource "aws_cloudfront_function" "rewrite" {
  name    = "${var.project_name}-page-rewrite"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = <<-EOT
    function handler(event) {
      var req = event.request;
      var uri = req.uri;
      if (uri === "/") { req.uri = "/index.html"; return req; }
      if (!uri.includes(".") && !uri.startsWith("/api/")) {
        req.uri = uri.replace(/\/$/, "") + ".html";
      }
      return req;
    }
  EOT
}

locals {
  api_origin_domain = replace(replace(aws_lambda_function_url.api.function_url,
    "https://", ""), "/", "")
  aliases = var.enable_custom_domain ? [var.custom_domain] : []
}

# Forward only what the API needs — never the Authorization header, which
# would stop CloudFront from SigV4-signing the OAC request to the lambda URL.
resource "aws_cloudfront_origin_request_policy" "api" {
  name = "${var.project_name}-api"

  headers_config {
    header_behavior = "whitelist"
    headers {
      # note: the viewer-supplied x-amz-content-sha256 (required for
      # OAC-signed POST/PUT) is reserved — CloudFront forwards it as part
      # of signing and rejects it in a whitelist
      items = ["x-authorization", "content-type", "accept"]
    }
  }
  query_strings_config {
    query_string_behavior = "all"
  }
  cookies_config {
    cookie_behavior = "none"
  }
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  comment             = "${var.project_name} dashboard"
  default_root_object = "index.html"
  price_class         = "PriceClass_100" # cheapest edge set (NA + EU)
  aliases             = local.aliases

  origin {
    origin_id                = "site-s3"
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  origin {
    origin_id   = "api-lambda"
    domain_name = local.api_origin_domain

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    # the lambda handler rejects any request without this secret, so the
    # public function URL is only usable through this distribution
    custom_header {
      name  = "x-origin-verify"
      value = random_password.origin_verify.result
    }
  }

  default_cache_behavior {
    target_origin_id       = "site-s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    # managed CachingOptimized
    cache_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6"

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.rewrite.arn
    }
  }

  ordered_cache_behavior {
    path_pattern           = "/api/*"
    target_origin_id       = "api-lambda"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    # managed CachingDisabled + a custom origin-request policy: OAC only
    # SigV4-signs the origin request when the policy cannot forward the
    # viewer's Authorization header, so the JWT rides in x-authorization
    cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    origin_request_policy_id = aws_cloudfront_origin_request_policy.api.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = var.enable_custom_domain ? false : true
    acm_certificate_arn            = var.enable_custom_domain ? aws_acm_certificate.site[0].arn : null
    ssl_support_method             = var.enable_custom_domain ? "sni-only" : null
    minimum_protocol_version       = var.enable_custom_domain ? "TLSv1.2_2021" : "TLSv1"
  }

}

# ACM cert (us-east-1, free). DNS lives on Cloudflare, so validation is
# manual: terraform outputs the CNAMEs to add there. Flip
# enable_custom_domain=true only after the cert shows ISSUED.
resource "aws_acm_certificate" "site" {
  count             = var.custom_domain != "" ? 1 : 0
  domain_name       = var.custom_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}
