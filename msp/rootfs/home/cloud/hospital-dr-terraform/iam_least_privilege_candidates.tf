# Review-only IAM candidates.
#
# These policy documents are deliberately not attached to any principal.  They
# provide an explicit, Terraform-rendered starting point for the approved
# migration away from the AWS-managed administrator policy.  The migration still requires IAM
# simulation and a controlled live validation window.

locals {
  dr_candidate_account_id = data.aws_caller_identity.current.account_id

  dr_candidate_iam_role_arns = [
    "arn:aws:iam::${local.dr_candidate_account_id}:role/hospital-dr-ecr-pull-role",
    "arn:aws:iam::${local.dr_candidate_account_id}:role/hospital-dr-github-actions-ecr-push",
    "arn:aws:iam::${local.dr_candidate_account_id}:role/hospital-dr-cost-guard-role",
  ]

  dr_candidate_instance_profile_arns = [
    "arn:aws:iam::${local.dr_candidate_account_id}:instance-profile/hospital-dr-ecr-pull-profile",
  ]

  dr_candidate_oidc_provider_arn = "arn:aws:iam::${local.dr_candidate_account_id}:oidc-provider/token.actions.githubusercontent.com"

  dr_candidate_lambda_arn    = aws_lambda_function.dr_cost_guard.arn
  dr_candidate_log_group_arn = aws_cloudwatch_log_group.dr_cost_guard.arn
  dr_candidate_event_rule_arns = [
    "arn:aws:events:${var.aws_region}:${local.dr_candidate_account_id}:rule/hospital-dr-daily-safety-shutdown",
  ]
}

# Daily Terraform candidate.  Destructive resource deletion is intentionally
# kept in the separate break-glass document below.
data "aws_iam_policy_document" "terraform_admin_least_privilege_candidate" {
  statement {
    sid       = "TerraformIdentityRead"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformEc2InventoryRead"
    effect = "Allow"
    actions = [
      "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeInstanceStatus",
      "ec2:DescribeInstances",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeKeyPairs",
      "ec2:DescribeNatGateways",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    sid    = "TerraformEcrRead"
    effect = "Allow"
    actions = [
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetLifecyclePolicy",
      "ecr:GetRepositoryPolicy",
      "ecr:ListTagsForResource",
    ]
    resources = [aws_ecr_repository.dr_web.arn, aws_ecr_repository.dr_emr.arn]
  }

  statement {
    sid    = "TerraformIamRoleRead"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
    ]
    resources = local.dr_candidate_iam_role_arns
  }

  statement {
    sid    = "TerraformIamProfileRead"
    effect = "Allow"
    actions = [
      "iam:GetInstanceProfile",
      "iam:ListInstanceProfileTags",
      "iam:ListInstanceProfilesForRole",
    ]
    resources = local.dr_candidate_instance_profile_arns
  }

  statement {
    sid       = "TerraformIamOidcRead"
    effect    = "Allow"
    actions   = ["iam:GetOpenIDConnectProvider"]
    resources = [local.dr_candidate_oidc_provider_arn]
  }

  statement {
    sid       = "TerraformIamProviderInventory"
    effect    = "Allow"
    actions   = ["iam:ListOpenIDConnectProviders"]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformS3Read"
    effect = "Allow"
    actions = [
      "s3:GetBucketEncryption",
      "s3:GetBucketLifecycleConfiguration",
      "s3:GetBucketLocation",
      "s3:GetBucketOwnershipControls",
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:GetBucketVersioning",
      "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.db_backup.arn]
  }

  statement {
    sid    = "TerraformEventBridgeRead"
    effect = "Allow"
    actions = [
      "events:DescribeRule",
      "events:ListTagsForResource",
      "events:ListTargetsByRule",
    ]
    resources = local.dr_candidate_event_rule_arns
  }

  statement {
    sid    = "TerraformLambdaRead"
    effect = "Allow"
    actions = [
      "lambda:GetFunction",
      "lambda:GetFunctionConfiguration",
      "lambda:GetPolicy",
      "lambda:ListTags",
    ]
    resources = [local.dr_candidate_lambda_arn]
  }

  statement {
    sid       = "TerraformLogsInventoryRead"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }

  statement {
    sid       = "TerraformSecretRead"
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.aws_region}:${local.dr_candidate_account_id}:parameter/hospital-dr/cloudflare/api-token"]
  }

  statement {
    sid       = "TerraformDecryptSsmSecureString"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.aws_region}.amazonaws.com"]
    }
  }

  # EC2 creation/update APIs often require Resource="*" during a fresh VPC
  # bootstrap because one call spans subnets, network interfaces, volumes,
  # security groups, AMIs, and key pairs.  The action list is explicit and
  # region-scoped; destructive deletion stays in break-glass.
  statement {
    sid    = "TerraformEc2BootstrapAndUpdate"
    effect = "Allow"
    actions = [
      "ec2:AllocateAddress",
      "ec2:AssociateAddress",
      "ec2:AssociateRouteTable",
      "ec2:AttachInternetGateway",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateInternetGateway",
      "ec2:CreateKeyPair",
      "ec2:CreateNatGateway",
      "ec2:CreateRoute",
      "ec2:CreateRouteTable",
      "ec2:CreateSecurityGroup",
      "ec2:CreateSubnet",
      "ec2:CreateTags",
      "ec2:CreateVpc",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifySubnetAttribute",
      "ec2:ModifyVpcAttribute",
      "ec2:ReplaceRoute",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RunInstances",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    sid       = "TerraformEcrRepositoryCreate"
    effect    = "Allow"
    actions   = ["ecr:CreateRepository"]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformEcrLifecycleManagement"
    effect = "Allow"
    actions = [
      "ecr:DeleteLifecyclePolicy",
      "ecr:PutImageScanningConfiguration",
      "ecr:PutImageTagMutability",
      "ecr:PutLifecyclePolicy",
      "ecr:TagResource",
      "ecr:UntagResource",
    ]
    resources = [aws_ecr_repository.dr_web.arn, aws_ecr_repository.dr_emr.arn]
  }

  statement {
    sid       = "TerraformIamCreateNamedResources"
    effect    = "Allow"
    actions   = ["iam:CreateInstanceProfile", "iam:CreateOpenIDConnectProvider", "iam:CreateRole"]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformIamRoleManagement"
    effect = "Allow"
    actions = [
      "iam:DeleteRolePolicy",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
    ]
    resources = local.dr_candidate_iam_role_arns
  }

  statement {
    sid    = "TerraformIamProfileManagement"
    effect = "Allow"
    actions = [
      "iam:AddRoleToInstanceProfile",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:TagInstanceProfile",
      "iam:UntagInstanceProfile",
    ]
    resources = local.dr_candidate_instance_profile_arns
  }

  statement {
    sid       = "TerraformIamOidcManagement"
    effect    = "Allow"
    actions   = ["iam:TagOpenIDConnectProvider", "iam:UntagOpenIDConnectProvider", "iam:UpdateOpenIDConnectProviderThumbprint"]
    resources = [local.dr_candidate_oidc_provider_arn]
  }

  statement {
    sid       = "TerraformPassOnlyDrRoles"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = local.dr_candidate_iam_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com", "lambda.amazonaws.com"]
    }
  }

  statement {
    sid    = "TerraformS3Configuration"
    effect = "Allow"
    actions = [
      "s3:DeleteBucketPolicy",
      "s3:DeleteBucketTagging",
      "s3:PutBucketEncryption",
      "s3:PutBucketLifecycleConfiguration",
      "s3:PutBucketOwnershipControls",
      "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketTagging",
      "s3:PutBucketVersioning",
    ]
    resources = [aws_s3_bucket.db_backup.arn]
  }

  statement {
    sid    = "TerraformEventBridgeManagement"
    effect = "Allow"
    actions = [
      "events:PutRule",
      "events:PutTargets",
      "events:RemoveTargets",
      "events:TagResource",
      "events:UntagResource",
    ]
    resources = local.dr_candidate_event_rule_arns
  }

  statement {
    sid    = "TerraformLambdaManagement"
    effect = "Allow"
    actions = [
      "lambda:AddPermission",
      "lambda:RemovePermission",
      "lambda:TagResource",
      "lambda:UntagResource",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
    ]
    resources = [local.dr_candidate_lambda_arn]
  }

  statement {
    sid    = "TerraformLogsManagement"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:ListTagsForResource",
      "logs:PutRetentionPolicy",
      "logs:TagResource",
      "logs:UntagResource",
    ]
    resources = [local.dr_candidate_log_group_arn]
  }
}

# Explicit break-glass candidate.  Keep this separate from the daily policy;
# attach only during a reviewed Terraform replacement/destroy window.
data "aws_iam_policy_document" "terraform_admin_break_glass_candidate" {
  statement {
    sid    = "TerraformEc2DestructiveRecovery"
    effect = "Allow"
    actions = [
      "ec2:DeleteInternetGateway",
      "ec2:DeleteKeyPair",
      "ec2:DeleteNatGateway",
      "ec2:DeleteRoute",
      "ec2:DeleteRouteTable",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteSubnet",
      "ec2:DeleteTags",
      "ec2:DeleteVpc",
      "ec2:DetachInternetGateway",
      "ec2:DisassociateAddress",
      "ec2:DisassociateRouteTable",
      "ec2:ReleaseAddress",
      "ec2:TerminateInstances",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    sid    = "TerraformNamedServiceCleanup"
    effect = "Allow"
    actions = [
      "events:DeleteRule",
      "ecr:DeleteRepository",
      "iam:DeleteInstanceProfile",
      "iam:DeleteOpenIDConnectProvider",
      "iam:DeleteRole",
      "iam:RemoveRoleFromInstanceProfile",
      "lambda:DeleteFunction",
      "logs:DeleteLogGroup",
      "s3:DeleteBucket",
    ]
    resources = concat(
      [local.dr_candidate_lambda_arn, local.dr_candidate_log_group_arn],
      local.dr_candidate_event_rule_arns,
      local.dr_candidate_iam_role_arns,
      local.dr_candidate_instance_profile_arns,
      [local.dr_candidate_oidc_provider_arn],
      [aws_ecr_repository.dr_web.arn, aws_ecr_repository.dr_emr.arn, aws_s3_bucket.db_backup.arn],
    )
  }
}

# Cost Guard candidate.  Describe APIs remain Resource="*" because EC2 does
# not support resource scoping for them.  Mutations are scoped to tagged DR
# instances/gateways/EIPs and the Lambda's own log group.
data "aws_iam_policy_document" "dr_cost_guard_least_privilege_candidate" {
  statement {
    sid    = "CostGuardEc2InventoryRead"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    sid       = "CostGuardStopTaggedDrInstances"
    effect    = "Allow"
    actions   = ["ec2:StopInstances"]
    resources = ["arn:aws:ec2:${var.aws_region}:${local.dr_candidate_account_id}:instance/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "ec2:ResourceTag/Name"
      values   = ["Hospital-Real-Web-Server", "Hospital-DR-Doc-Server", "Hospital-DR-DB-Server"]
    }
  }

  statement {
    sid       = "CostGuardReadCloudflareToken"
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.aws_region}:${local.dr_candidate_account_id}:parameter/hospital-dr/cloudflare/api-token"]
  }

  statement {
    sid       = "CostGuardWriteOwnLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${local.dr_candidate_log_group_arn}:log-stream:*"]
  }
}

# Read-only AWS CloudTrail Event History collector candidate.  This is not
# attached automatically; the MSP operator must provide the existing AWS
# credential chain to the collector after reviewing the simulation result.
data "aws_iam_policy_document" "aws_cloud_security_collector_readonly_candidate" {
  statement {
    sid       = "AwsCloudSecurityLookupEventHistory"
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }
}

# Candidate for the controller that invokes the already-installed SSM agent.
# It deliberately contains no EC2 start/stop, IAM, networking, DNS, or
# Terraform mutation permissions.
data "aws_iam_policy_document" "aws_endpoint_security_ssm_controller_candidate" {
  statement {
    sid    = "AwsEndpointSsmInventoryRead"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ssm:DescribeInstanceInformation",
      "ssm:GetCommandInvocation",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "AwsEndpointSsmRunShellScriptDocument"
    effect    = "Allow"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ssm:${var.aws_region}:*:document/AWS-RunShellScript"]
  }

  statement {
    sid     = "AwsEndpointSsmRunOnlyTaggedDrInstances"
    effect  = "Allow"
    actions = ["ssm:SendCommand"]
    resources = [
      "arn:aws:ec2:${var.aws_region}:${local.dr_candidate_account_id}:instance/*",
    ]

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "ssm:resourceTag/Name"
      values   = ["Hospital-Real-Web-Server", "Hospital-DR-Doc-Server", "Hospital-DR-DB-Server"]
    }
  }
}
