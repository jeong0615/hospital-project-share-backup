terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100"
    }
  }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.expected_account_id]

  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_vpcs" "existing" {
  count = local.enabled ? 1 : 0
}
data "aws_vpc" "existing" {
  for_each = local.enabled ? toset(data.aws_vpcs.existing[0].ids) : toset([])
  id       = each.value
}
data "aws_ami" "synthetic" {
  count       = local.enabled ? 1 : 0
  owners      = ["137112412989"]
  most_recent = false
  filter {
    name   = "image-id"
    values = [var.synthetic_ami_id]
  }
}

# Inspect the pre-existing customer-managed TLS key; this stack never creates
# or changes a KMS key.
data "aws_kms_key" "tls" {
  count  = local.enabled ? 1 : 0
  key_id = var.kms_key_arn
}
