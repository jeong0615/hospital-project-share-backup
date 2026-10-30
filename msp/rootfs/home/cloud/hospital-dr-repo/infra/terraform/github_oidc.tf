# GitHub Actions OIDC is limited to the Docker image publisher role.
# It does not grant Terraform, EC2, VPC, NAT, Cloudflare, or ECR repository admin access.

variable "github_repository" {
  description = "GitHub repository allowed to assume the ECR push role"
  type        = string
  default     = "jeong0615/hospital-dr"

  validation {
    condition     = can(regex("^[^/]+/[^/]+$", var.github_repository))
    error_message = "github_repository must be in OWNER/REPOSITORY format."
  }
}

variable "github_actions_branch" {
  description = "Git branch allowed to assume the ECR push role"
  type        = string
  default     = "main"

  validation {
    condition     = var.github_actions_branch != "" && !can(regex("[\\r\\n]", var.github_actions_branch))
    error_message = "github_actions_branch must be a non-empty single-line branch name."
  }
}

locals {
  github_repository_owner = split("/", var.github_repository)[0]
  github_repository_name  = split("/", var.github_repository)[1]
  github_oidc_subject     = "repo:${var.github_repository}:ref:refs/heads/${var.github_actions_branch}"

  # GitHub can include owner/repository numeric IDs in sub for newer repositories.
  # The owner and repository names plus the branch remain exact; only those IDs vary.
  github_oidc_immutable_subject = "repo:${local.github_repository_owner}@*/${local.github_repository_name}@*:ref:refs/heads/${var.github_actions_branch}"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = {
    Name    = "Hospital-DR-GitHub-Actions-OIDC"
    Purpose = "GitHub-Actions-ECR-Push"
  }
}

data "aws_iam_policy_document" "github_actions_ecr_push_assume_role" {
  statement {
    sid     = "GitHubActionsClassicSubject"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_oidc_subject]
    }
  }

  statement {
    sid     = "GitHubActionsImmutableSubject"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_oidc_immutable_subject]
    }
  }
}

resource "aws_iam_role" "github_actions_ecr_push" {
  name               = "hospital-dr-github-actions-ecr-push"
  assume_role_policy = data.aws_iam_policy_document.github_actions_ecr_push_assume_role.json

  tags = {
    Name    = "Hospital-DR-GitHub-Actions-ECR-Push"
    Purpose = "GitHub-Actions-ECR-Push"
  }
}

data "aws_iam_policy_document" "github_actions_ecr_push" {
  statement {
    sid       = "EcrAuthorizationToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "PushHospitalDrImages"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [
      aws_ecr_repository.dr_web.arn,
      aws_ecr_repository.dr_emr.arn,
    ]
  }
}

resource "aws_iam_role_policy" "github_actions_ecr_push" {
  name   = "hospital-dr-github-actions-ecr-push-policy"
  role   = aws_iam_role.github_actions_ecr_push.id
  policy = data.aws_iam_policy_document.github_actions_ecr_push.json
}

output "github_actions_ecr_push_role_arn" {
  description = "IAM role ARN for the future GitHub Actions ECR push job"
  value       = aws_iam_role.github_actions_ecr_push.arn
}
