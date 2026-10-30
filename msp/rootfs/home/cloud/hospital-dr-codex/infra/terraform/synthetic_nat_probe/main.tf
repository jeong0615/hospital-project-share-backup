locals {
  enabled = var.enable_probe && var.confirmation == "CREATE_SYNTHETIC_NAT_PROBE"
  run_tag = local.enabled ? var.run_id : "disabled"
  common_tags = {
    Project     = "hospital-dr-synthetic-nat-probe"
    ProbeRunId  = local.run_tag
    Environment = "synthetic"
    DataClass   = "synthetic-only"
    ManagedBy   = "terraform"
  }
  cert_path   = trimprefix(var.certificate_parameter_name, "/")
  key_path    = trimprefix(var.private_key_parameter_name, "/")
  source_path = "/hospital-dr/synthetic-nat-probe/${var.run_id}/allowed-web-eip"
  source_ip   = var.allowed_web_eip_ipv4 == "DISABLED" ? "DISABLED" : trimsuffix(var.allowed_web_eip_ipv4, "/32")
  allowed_dns_domains = [
    "ssm.${var.region}.amazonaws.com",
    "ssmmessages.${var.region}.amazonaws.com",
  ]
  ipv4_weights = [16777216, 65536, 256, 1]
  range = {
    vpc = {
      start = sum([for i, octet in split(".", cidrhost(var.vpc_cidr, 0)) : tonumber(octet) * local.ipv4_weights[i]])
      end   = sum([for i, octet in split(".", cidrhost(var.vpc_cidr, -1)) : tonumber(octet) * local.ipv4_weights[i]])
    }
    subnet = {
      start = sum([for i, octet in split(".", cidrhost(var.subnet_cidr, 0)) : tonumber(octet) * local.ipv4_weights[i]])
      end   = sum([for i, octet in split(".", cidrhost(var.subnet_cidr, -1)) : tonumber(octet) * local.ipv4_weights[i]])
    }
    host = sum([for i, octet in split(".", var.probe_private_ip) : tonumber(octet) * local.ipv4_weights[i]])
  }
  existing_ranges = flatten([
    for vpc in data.aws_vpc.existing : [for cidr in concat([vpc.cidr_block], [for association in vpc.cidr_block_associations : association.cidr_block]) : {
      start = sum([for i, octet in split(".", cidrhost(cidr, 0)) : tonumber(octet) * local.ipv4_weights[i]])
      end   = sum([for i, octet in split(".", cidrhost(cidr, -1)) : tonumber(octet) * local.ipv4_weights[i]])
    } if lookup(vpc.tags, "ProbeRunId", "") != var.run_id && !strcontains(cidr, ":")]
  ])
  source_enabled = local.enabled && var.allowed_web_eip_ipv4 != "DISABLED"
}

resource "aws_vpc" "probe" {
  count                            = local.enabled ? 1 : 0
  cidr_block                       = var.vpc_cidr
  enable_dns_support               = true
  enable_dns_hostnames             = true
  assign_generated_ipv6_cidr_block = false
  tags                             = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-vpc" })

  lifecycle {
    precondition {
      condition = alltrue(flatten([for existing in local.existing_ranges : [
        local.range.vpc.end < existing.start || existing.end < local.range.vpc.start
      ]]))
      error_message = "Probe VPC CIDR overlaps an existing VPC (including the separate Canary VPC)."
    }
    precondition {
      condition = (
        local.range.subnet.start >= local.range.vpc.start && local.range.subnet.end <= local.range.vpc.end &&
        local.range.host >= local.range.subnet.start && local.range.host <= local.range.subnet.end
      )
      error_message = "Probe subnet or private IP is outside the dedicated VPC/subnet range."
    }
    precondition {
      condition = (
        var.certificate_parameter_name == "/hospital-dr/synthetic-nat-probe/${var.run_id}/fullchain" &&
        var.private_key_parameter_name == "/hospital-dr/synthetic-nat-probe/${var.run_id}/privkey"
      )
      error_message = "TLS SecureString parameter names must be scoped to this exact Run ID."
    }
    precondition {
      condition = (
        data.aws_ami.synthetic[0].id == "AWS_RESOURCE_ID_REDACTED" &&
        data.aws_ami.synthetic[0].owner_id == "AWS_ACCOUNT_ID_REDACTED" &&
        data.aws_ami.synthetic[0].public && data.aws_ami.synthetic[0].state == "available" &&
        data.aws_ami.synthetic[0].architecture == "x86_64" &&
        data.aws_ami.synthetic[0].virtualization_type == "hvm" &&
        data.aws_ami.synthetic[0].root_device_type == "ebs" &&
        can(regex("^al2023-ami-.+-x86_64$", data.aws_ami.synthetic[0].name))
      )
      error_message = "Pinned AMI is not an available Amazon-owned AL2023 x86_64 HVM/EBS image."
    }
    precondition {
      condition = (
        data.aws_kms_key.tls[0].arn == var.kms_key_arn &&
        data.aws_kms_key.tls[0].aws_account_id == var.expected_account_id &&
        data.aws_kms_key.tls[0].key_state == "Enabled" &&
        data.aws_kms_key.tls[0].key_manager == "CUSTOMER" &&
        data.aws_kms_key.tls[0].key_usage == "ENCRYPT_DECRYPT" &&
        data.aws_kms_key.tls[0].key_spec == "SYMMETRIC_DEFAULT"
      )
      error_message = "The existing Run-ID TLS CMK must be enabled, customer-managed, same-account, symmetric, and usable for encryption/decryption."
    }
    precondition {
      condition     = var.probe_domain == "nat-probe.hospital-web.pp.ua"
      error_message = "The probe hostname must match the approved DNS-only A-record and TLS certificate contract."
    }
  }
}

resource "aws_subnet" "probe" {
  count                   = local.enabled ? 1 : 0
  vpc_id                  = aws_vpc.probe[0].id
  cidr_block              = var.subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-public" })
}

resource "aws_internet_gateway" "probe" {
  count  = local.enabled ? 1 : 0
  vpc_id = aws_vpc.probe[0].id
  tags   = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-igw" })
}

resource "aws_route_table" "probe" {
  count  = local.enabled ? 1 : 0
  vpc_id = aws_vpc.probe[0].id
  tags   = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-rt" })
}

resource "aws_route" "internet" {
  count                  = local.enabled ? 1 : 0
  route_table_id         = aws_route_table.probe[0].id
  destination_cidr_block = "AWS_PUBLIC_IP_REDACTED/0"
  gateway_id             = aws_internet_gateway.probe[0].id
}

resource "aws_route_table_association" "probe" {
  count          = local.enabled ? 1 : 0
  subnet_id      = aws_subnet.probe[0].id
  route_table_id = aws_route_table.probe[0].id
}

resource "aws_default_route_table" "probe" {
  count                  = local.enabled ? 1 : 0
  default_route_table_id = aws_vpc.probe[0].default_route_table_id
  tags                   = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-default-route-table-unused" })
}

resource "aws_default_network_acl" "probe" {
  count                  = local.enabled ? 1 : 0
  default_network_acl_id = aws_vpc.probe[0].default_network_acl_id
  tags                   = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-default-nacl-locked" })
}

resource "aws_security_group" "probe" {
  count       = local.enabled ? 1 : 0
  name        = "dr-probe-${var.run_id}-instance"
  description = "Synthetic IP echo server; ingress restricted to the exact Canary Web EIP/32."
  vpc_id      = aws_vpc.probe[0].id
  tags        = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-instance" })
}

resource "aws_default_security_group" "probe" {
  count   = local.enabled ? 1 : 0
  vpc_id  = aws_vpc.probe[0].id
  ingress = []
  egress  = []
  tags    = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-default-sg-empty" })
}

resource "aws_vpc_security_group_ingress_rule" "https_from_canary" {
  count             = local.source_enabled ? 1 : 0
  security_group_id = aws_security_group.probe[0].id
  description       = "Exact synthetic Web/NAT EIP only."
  cidr_ipv4         = var.allowed_web_eip_ipv4
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  tags              = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-https-source" })
}

resource "aws_security_group" "ssm_endpoint" {
  count       = local.enabled ? 1 : 0
  name        = "dr-probe-${var.run_id}-ssm-endpoint"
  description = "SSM interface endpoints for the synthetic probe instance only."
  vpc_id      = aws_vpc.probe[0].id
  tags        = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-ssm-endpoint" })
}

resource "aws_vpc_security_group_ingress_rule" "endpoint_from_probe" {
  count                        = local.enabled ? 1 : 0
  security_group_id            = aws_security_group.ssm_endpoint[0].id
  description                  = "SSM HTTPS from the sole tagged probe instance SG."
  referenced_security_group_id = aws_security_group.probe[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  tags                         = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-endpoint-from-instance" })
}

resource "aws_vpc_security_group_egress_rule" "probe_to_ssm" {
  count                        = local.enabled ? 1 : 0
  security_group_id            = aws_security_group.probe[0].id
  description                  = "Probe instance SSM control-plane HTTPS only."
  referenced_security_group_id = aws_security_group.ssm_endpoint[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  tags                         = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-egress-ssm" })
}

resource "aws_network_acl" "probe" {
  count      = local.enabled ? 1 : 0
  vpc_id     = aws_vpc.probe[0].id
  subnet_ids = [aws_subnet.probe[0].id]
  tags       = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-nacl" })
}

resource "aws_network_acl_rule" "https_ingress" {
  count          = local.source_enabled ? 1 : 0
  network_acl_id = aws_network_acl.probe[0].id
  rule_number    = 100
  protocol       = "6"
  rule_action    = "allow"
  egress         = false
  cidr_block     = var.allowed_web_eip_ipv4
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "ssm_return_ingress" {
  count          = local.enabled ? 1 : 0
  network_acl_id = aws_network_acl.probe[0].id
  rule_number    = 110
  protocol       = "6"
  rule_action    = "allow"
  egress         = false
  cidr_block     = var.subnet_cidr
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "ssm_egress" {
  count          = local.enabled ? 1 : 0
  network_acl_id = aws_network_acl.probe[0].id
  rule_number    = 100
  protocol       = "6"
  rule_action    = "allow"
  egress         = true
  cidr_block     = var.subnet_cidr
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "https_return_egress" {
  count          = local.source_enabled ? 1 : 0
  network_acl_id = aws_network_acl.probe[0].id
  rule_number    = 110
  protocol       = "6"
  rule_action    = "allow"
  egress         = true
  cidr_block     = var.allowed_web_eip_ipv4
  from_port      = 1024
  to_port        = 65535
}

# Apply Resolver filtering only to this synthetic VPC. The exact private SSM
# endpoint names remain resolvable; other Resolver queries receive NXDOMAIN.
resource "aws_route53_resolver_firewall_config" "probe" {
  count              = local.enabled ? 1 : 0
  resource_id        = aws_vpc.probe[0].id
  firewall_fail_open = "DISABLED"
}

resource "aws_route53_resolver_firewall_domain_list" "ssm_allow" {
  count   = local.enabled ? 1 : 0
  name    = "dr-probe-${var.run_id}-ssm-allow"
  domains = [for d in local.allowed_dns_domains : format("%s.", trimsuffix(d, "."))]
  tags    = local.common_tags
}

resource "aws_route53_resolver_firewall_domain_list" "block_all" {
  count   = local.enabled ? 1 : 0
  name    = "dr-probe-${var.run_id}-block-all"
  domains = ["*."]
  tags    = local.common_tags
}

resource "aws_route53_resolver_firewall_rule_group" "probe" {
  count = local.enabled ? 1 : 0
  name  = "dr-probe-${var.run_id}"
  tags  = local.common_tags
}

resource "aws_route53_resolver_firewall_rule" "ssm_allow" {
  count                   = local.enabled ? 1 : 0
  name                    = "dr-probe-${var.run_id}-ssm-allow"
  action                  = "ALLOW"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.ssm_allow[0].id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.probe[0].id
  priority                = 10
}

resource "aws_route53_resolver_firewall_rule" "block_all" {
  count                   = local.enabled ? 1 : 0
  name                    = "dr-probe-${var.run_id}-block-all"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.block_all[0].id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.probe[0].id
  priority                = 100
}

resource "aws_route53_resolver_firewall_rule_group_association" "probe" {
  count                  = local.enabled ? 1 : 0
  name                   = "dr-probe-${var.run_id}-vpc"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.probe[0].id
  vpc_id                 = aws_vpc.probe[0].id
  priority               = 200
  mutation_protection    = "DISABLED"
  tags                   = local.common_tags
  depends_on             = [aws_route53_resolver_firewall_rule.ssm_allow, aws_route53_resolver_firewall_rule.block_all]
}

resource "aws_vpc_endpoint" "ssm" {
  for_each            = local.enabled ? toset(["ssm", "ssmmessages"]) : toset([])
  vpc_id              = aws_vpc.probe[0].id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.probe[0].id]
  security_group_ids  = [aws_security_group.ssm_endpoint[0].id]
  private_dns_enabled = true
  tags                = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-${each.value}" })
}

resource "aws_ec2_tag" "ssm_endpoint_eni_run_id" {
  for_each    = local.enabled ? toset(["ssm", "ssmmessages"]) : toset([])
  resource_id = one(aws_vpc_endpoint.ssm[each.value].network_interface_ids)
  key         = "ProbeRunId"
  value       = var.run_id
}

resource "aws_ec2_tag" "probe_eni_run_id" {
  count       = local.enabled ? 1 : 0
  resource_id = aws_instance.probe[0].primary_network_interface_id
  key         = "ProbeRunId"
  value       = var.run_id
}

resource "aws_iam_role" "probe" {
  count = local.enabled ? 1 : 0
  name  = "dr-synthetic-probe-${var.run_id}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "probe" {
  count = local.enabled ? 1 : 0
  name  = "dr-synthetic-probe-${var.run_id}"
  role  = aws_iam_role.probe[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ssm:UpdateInstanceInformation"]
        Resource = "arn:${data.aws_partition.current.partition}:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*"
        Condition = {
          StringEquals = { "aws:ResourceTag/ProbeRunId" = var.run_id }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["ssm:GetParameter"]
        Resource = [
          "arn:${data.aws_partition.current.partition}:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.cert_path}",
          "arn:${data.aws_partition.current.partition}:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.key_path}",
          "arn:${data.aws_partition.current.partition}:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${trimprefix(local.source_path, "/")}"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = { "kms:ViaService" = "ssm.${var.region}.amazonaws.com" }
          StringLike = {
            "kms:EncryptionContext:PARAMETER_ARN" = [
              "arn:${data.aws_partition.current.partition}:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.cert_path}",
              "arn:${data.aws_partition.current.partition}:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.key_path}"
            ]
          }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "probe" {
  count = local.enabled ? 1 : 0
  name  = "dr-synthetic-probe-${var.run_id}"
  role  = aws_iam_role.probe[0].name
  tags  = local.common_tags
}

resource "aws_ssm_parameter" "allowed_web_eip" {
  count       = local.enabled ? 1 : 0
  name        = local.source_path
  description = "Exact synthetic Canary Web EIP allowlist for this ProbeRunId."
  type        = "String"
  value       = local.source_ip
  # A reused Run ID must fail on create rather than overwrite a pre-existing
  # parameter. Terraform-managed updates remain explicit stateful updates.
  overwrite = false
  tags      = local.common_tags
}

resource "aws_eip" "probe" {
  count  = local.enabled ? 1 : 0
  domain = "vpc"
  tags   = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-eip" })
}

resource "aws_instance" "probe" {
  count                       = local.enabled ? 1 : 0
  ami                         = var.synthetic_ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.probe[0].id
  private_ip                  = var.probe_private_ip
  vpc_security_group_ids      = [aws_security_group.probe[0].id]
  iam_instance_profile        = aws_iam_instance_profile.probe[0].name
  associate_public_ip_address = false
  user_data = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    region           = var.region
    domain           = var.probe_domain
    cert_parameter   = var.certificate_parameter_name
    key_parameter    = var.private_key_parameter_name
    source_parameter = local.source_path
    probe_source     = file("${path.module}/probe_server.py")
  })
  user_data_replace_on_change = false
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    volume_size           = var.root_volume_size_gib
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }
  volume_tags = local.common_tags
  tags        = merge(local.common_tags, { Name = "dr-probe-${var.run_id}-instance" })
  depends_on = [
    aws_ec2_tag.ssm_endpoint_eni_run_id,
    aws_network_acl_rule.ssm_egress,
    aws_network_acl_rule.ssm_return_ingress,
    aws_network_acl_rule.https_ingress,
    aws_network_acl_rule.https_return_egress,
    aws_route_table_association.probe,
    aws_ssm_parameter.allowed_web_eip,
    aws_iam_role_policy.probe,
    aws_route53_resolver_firewall_config.probe,
    aws_route53_resolver_firewall_rule_group_association.probe,
  ]

  lifecycle {
    # AWS reports the associated Elastic IP as the instance's public-IP
    # association after launch. Ignore only this computed/effective value so a
    # routine variable-only ingress plan cannot replace the existing Probe.
    # Launch still explicitly disables automatic public-IP assignment.
    ignore_changes = [associate_public_ip_address]
    precondition {
      condition     = data.aws_ami.synthetic[0].id == var.synthetic_ami_id
      error_message = "The pinned Amazon-owned synthetic AMI could not be verified."
    }
  }
}

resource "aws_eip_association" "probe" {
  count         = local.enabled ? 1 : 0
  allocation_id = aws_eip.probe[0].id
  instance_id   = aws_instance.probe[0].id
}
