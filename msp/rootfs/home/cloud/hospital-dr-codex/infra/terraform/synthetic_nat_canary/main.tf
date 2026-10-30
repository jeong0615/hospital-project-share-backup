data "aws_vpcs" "existing" {
  count = var.enable_canary ? 1 : 0
}

data "aws_vpc" "existing" {
  for_each = var.enable_canary ? toset(data.aws_vpcs.existing[0].ids) : toset([])
  id       = each.value
}

locals {
  ipv4_weights = [16777216, 65536, 256, 1]
  enabled      = var.enable_canary && var.confirmation == "CREATE_SYNTHETIC_NAT_CANARY"
  run_tag      = local.enabled ? var.run_id : "disabled"

  common_tags = {
    Project     = "hospital-dr-synthetic-nat-canary"
    CanaryRunId = local.run_tag
    Environment = "synthetic"
    DataClass   = "synthetic-only"
    ManagedBy   = "terraform"
  }

  ssm_services = toset(concat(
    ["ssm", "ssmmessages"],
    var.enable_ec2messages_endpoint ? ["ec2messages"] : []
  ))
  allowed_dns_domains = concat(
    [
      "ssm.${var.region}.amazonaws.com",
      "ssmmessages.${var.region}.amazonaws.com",
      var.probe_domain,
    ],
    var.enable_ec2messages_endpoint ? ["ec2messages.${var.region}.amazonaws.com"] : []
  )
  web_nacl_ingress = [
    { number = 100, cidr = "${var.emr_private_ip}/32", from = 443, to = 443 },
    { number = 110, cidr = "${var.probe_ipv4}/32", from = 1024, to = 65535 },
    { number = 120, cidr = var.private_subnet_cidr, from = 1024, to = 65535 },
  ]
  web_nacl_egress = [
    { number = 100, cidr = "${var.probe_ipv4}/32", from = 443, to = 443 },
    { number = 110, cidr = var.private_subnet_cidr, from = 443, to = 443 },
    { number = 120, cidr = "${var.emr_private_ip}/32", from = 1024, to = 65535 },
  ]
  emr_nacl_ingress = [
    { number = 100, cidr = "${var.web_private_ip}/32", from = 443, to = 443 },
    { number = 110, cidr = "${var.emr_private_ip}/32", from = 443, to = 443 },
    { number = 120, cidr = "${var.probe_ipv4}/32", from = 1024, to = 65535 },
    { number = 130, cidr = var.private_subnet_cidr, from = 1024, to = 65535 },
  ]
  emr_nacl_egress = [
    { number = 100, cidr = "${var.probe_ipv4}/32", from = 443, to = 443 },
    { number = 110, cidr = "${var.web_private_ip}/32", from = 1024, to = 65535 },
    { number = 120, cidr = "${var.emr_private_ip}/32", from = 1024, to = 65535 },
    { number = 130, cidr = var.private_subnet_cidr, from = 443, to = 443 },
  ]
  existing_vpc_ipv4_cidrs = flatten([
    for vpc in data.aws_vpc.existing : concat(
      [vpc.cidr_block],
      [for association in vpc.cidr_block_associations : association.cidr_block]
    )
  ])
  ipv4_ranges = {
    vpc = {
      start = sum([for i, octet in split(".", cidrhost(var.vpc_cidr, 0)) : tonumber(octet) * local.ipv4_weights[i]])
      end   = sum([for i, octet in split(".", cidrhost(var.vpc_cidr, -1)) : tonumber(octet) * local.ipv4_weights[i]])
    }
    public = {
      start = sum([for i, octet in split(".", cidrhost(var.public_subnet_cidr, 0)) : tonumber(octet) * local.ipv4_weights[i]])
      end   = sum([for i, octet in split(".", cidrhost(var.public_subnet_cidr, -1)) : tonumber(octet) * local.ipv4_weights[i]])
    }
    private = {
      start = sum([for i, octet in split(".", cidrhost(var.private_subnet_cidr, 0)) : tonumber(octet) * local.ipv4_weights[i]])
      end   = sum([for i, octet in split(".", cidrhost(var.private_subnet_cidr, -1)) : tonumber(octet) * local.ipv4_weights[i]])
    }
    web_ip = sum([for i, octet in split(".", var.web_private_ip) : tonumber(octet) * local.ipv4_weights[i]])
    emr_ip = sum([for i, octet in split(".", var.emr_private_ip) : tonumber(octet) * local.ipv4_weights[i]])
  }
  existing_vpc_ipv4_ranges = [
    for cidr in local.existing_vpc_ipv4_cidrs : {
      start = sum([for i, octet in split(".", cidrhost(cidr, 0)) : tonumber(octet) * local.ipv4_weights[i]])
      end   = sum([for i, octet in split(".", cidrhost(cidr, -1)) : tonumber(octet) * local.ipv4_weights[i]])
    }
  ]
}

resource "aws_vpc" "canary" {
  count                            = local.enabled ? 1 : 0
  cidr_block                       = var.vpc_cidr
  enable_dns_support               = true
  enable_dns_hostnames             = true
  assign_generated_ipv6_cidr_block = false
  tags                             = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-vpc" })

  lifecycle {
    precondition {
      condition = alltrue(flatten([
        for existing_range in local.existing_vpc_ipv4_ranges : [
          local.ipv4_ranges.vpc.end < existing_range.start || existing_range.end < local.ipv4_ranges.vpc.start
        ]
      ]))
      error_message = "Synthetic VPC CIDR overlaps an existing VPC in this account/region. Choose a different range."
    }
    precondition {
      condition = (
        local.ipv4_ranges.public.start >= local.ipv4_ranges.vpc.start &&
        local.ipv4_ranges.public.end <= local.ipv4_ranges.vpc.end &&
        local.ipv4_ranges.private.start >= local.ipv4_ranges.vpc.start &&
        local.ipv4_ranges.private.end <= local.ipv4_ranges.vpc.end &&
        local.ipv4_ranges.web_ip >= local.ipv4_ranges.public.start &&
        local.ipv4_ranges.web_ip <= local.ipv4_ranges.public.end &&
        local.ipv4_ranges.emr_ip >= local.ipv4_ranges.private.start &&
        local.ipv4_ranges.emr_ip <= local.ipv4_ranges.private.end &&
        (local.ipv4_ranges.public.end < local.ipv4_ranges.private.start || local.ipv4_ranges.private.end < local.ipv4_ranges.public.start)
      )
      error_message = "VPC/subnet CIDRs, host private IPs, or subnet overlap do not meet the synthetic topology."
    }
  }
}

resource "aws_subnet" "public" {
  count                           = local.enabled ? 1 : 0
  vpc_id                          = aws_vpc.canary[0].id
  cidr_block                      = var.public_subnet_cidr
  availability_zone               = var.availability_zone
  map_public_ip_on_launch         = false
  assign_ipv6_address_on_creation = false
  tags                            = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-public" })
}

resource "aws_subnet" "private" {
  count                           = local.enabled ? 1 : 0
  vpc_id                          = aws_vpc.canary[0].id
  cidr_block                      = var.private_subnet_cidr
  availability_zone               = var.availability_zone
  map_public_ip_on_launch         = false
  assign_ipv6_address_on_creation = false
  tags                            = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-private" })
}

resource "aws_network_acl" "web" {
  count      = local.enabled ? 1 : 0
  vpc_id     = aws_vpc.canary[0].id
  subnet_ids = [aws_subnet.public[0].id]
  tags       = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-web-nacl" })
}

resource "aws_network_acl" "emr" {
  count      = local.enabled ? 1 : 0
  vpc_id     = aws_vpc.canary[0].id
  subnet_ids = [aws_subnet.private[0].id]
  tags       = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-emr-nacl" })
}

resource "aws_network_acl_rule" "web_ingress" {
  for_each       = local.enabled ? { for rule in local.web_nacl_ingress : tostring(rule.number) => rule } : {}
  network_acl_id = aws_network_acl.web[0].id
  rule_number    = each.value.number
  protocol       = "6"
  rule_action    = "allow"
  egress         = false
  cidr_block     = each.value.cidr
  from_port      = each.value.from
  to_port        = each.value.to
}

resource "aws_network_acl_rule" "web_egress" {
  for_each       = local.enabled ? { for rule in local.web_nacl_egress : tostring(rule.number) => rule } : {}
  network_acl_id = aws_network_acl.web[0].id
  rule_number    = each.value.number
  protocol       = "6"
  rule_action    = "allow"
  egress         = true
  cidr_block     = each.value.cidr
  from_port      = each.value.from
  to_port        = each.value.to
}

resource "aws_network_acl_rule" "emr_ingress" {
  for_each       = local.enabled ? { for rule in local.emr_nacl_ingress : tostring(rule.number) => rule } : {}
  network_acl_id = aws_network_acl.emr[0].id
  rule_number    = each.value.number
  protocol       = "6"
  rule_action    = "allow"
  egress         = false
  cidr_block     = each.value.cidr
  from_port      = each.value.from
  to_port        = each.value.to
}

resource "aws_network_acl_rule" "emr_egress" {
  for_each       = local.enabled ? { for rule in local.emr_nacl_egress : tostring(rule.number) => rule } : {}
  network_acl_id = aws_network_acl.emr[0].id
  rule_number    = each.value.number
  protocol       = "6"
  rule_action    = "allow"
  egress         = true
  cidr_block     = each.value.cidr
  from_port      = each.value.from
  to_port        = each.value.to
}

resource "aws_internet_gateway" "canary" {
  count  = local.enabled ? 1 : 0
  vpc_id = aws_vpc.canary[0].id
  tags   = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-igw" })
}

resource "aws_route_table" "public" {
  count  = local.enabled ? 1 : 0
  vpc_id = aws_vpc.canary[0].id
  tags   = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-public-rt" })
}

resource "aws_route" "public_default" {
  count                  = local.enabled ? 1 : 0
  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "AWS_PUBLIC_IP_REDACTED/0"
  gateway_id             = aws_internet_gateway.canary[0].id
}

resource "aws_route_table_association" "public" {
  count          = local.enabled ? 1 : 0
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count  = local.enabled ? 1 : 0
  vpc_id = aws_vpc.canary[0].id
  tags   = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-private-rt" })
}

resource "aws_route_table_association" "private" {
  count          = local.enabled ? 1 : 0
  subnet_id      = aws_subnet.private[0].id
  route_table_id = aws_route_table.private[0].id
}

resource "aws_security_group" "web" {
  count       = local.enabled ? 1 : 0
  name        = "dr-synth-${var.run_id}-web"
  description = "Synthetic NAT host; no public ingress; transit only from exact synthetic EMR IP."
  vpc_id      = aws_vpc.canary[0].id
  tags        = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-web-sg" })
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "emr" {
  count       = local.enabled ? 1 : 0
  name        = "dr-synth-${var.run_id}-emr"
  description = "Synthetic probe only; no inbound or unrestricted egress."
  vpc_id      = aws_vpc.canary[0].id
  tags        = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-emr-sg" })
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "ssm_endpoint" {
  count       = local.enabled ? 1 : 0
  name        = "dr-synth-${var.run_id}-ssm-endpoint"
  description = "HTTPS from only the two synthetic hosts to SSM interface endpoints."
  vpc_id      = aws_vpc.canary[0].id
  tags        = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-ssm-endpoint-sg" })
  lifecycle { create_before_destroy = true }
}

resource "aws_default_security_group" "canary" {
  count   = local.enabled ? 1 : 0
  vpc_id  = aws_vpc.canary[0].id
  ingress = []
  egress  = []
  tags = merge(local.common_tags, {
    Name = "dr-synth-${var.run_id}-default-sg-locked"
  })
}

resource "aws_default_network_acl" "canary" {
  count                  = local.enabled ? 1 : 0
  default_network_acl_id = aws_vpc.canary[0].default_network_acl_id
  tags = merge(local.common_tags, {
    Name = "dr-synth-${var.run_id}-default-nacl-locked"
  })
}

resource "aws_default_route_table" "canary" {
  count                  = local.enabled ? 1 : 0
  default_route_table_id = aws_vpc.canary[0].default_route_table_id
  tags = merge(local.common_tags, {
    Name = "dr-synth-${var.run_id}-default-rt-unused"
  })
}

resource "aws_vpc_security_group_ingress_rule" "web_transit_from_emr" {
  count             = local.enabled ? 1 : 0
  security_group_id = aws_security_group.web[0].id
  cidr_ipv4         = "${var.emr_private_ip}/32"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "Middlebox forwarded probe flow from the exact synthetic EMR IPv4."
  tags              = local.common_tags
}

resource "aws_vpc_security_group_egress_rule" "web_ssm" {
  count                        = local.enabled ? 1 : 0
  security_group_id            = aws_security_group.web[0].id
  referenced_security_group_id = aws_security_group.ssm_endpoint[0].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "Web host SSM interface endpoint only."
  tags                         = local.common_tags
}

resource "aws_vpc_security_group_egress_rule" "web_probe" {
  count             = local.enabled ? 1 : 0
  security_group_id = aws_security_group.web[0].id
  cidr_ipv4         = "${var.probe_ipv4}/32"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "Forwarded synthetic probe destination only. HTTPS content itself is not restricted by SG."
  tags              = local.common_tags
}

resource "aws_vpc_security_group_egress_rule" "emr_ssm" {
  count                        = local.enabled ? 1 : 0
  security_group_id            = aws_security_group.emr[0].id
  referenced_security_group_id = aws_security_group.ssm_endpoint[0].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "EMR probe host SSM interface endpoint only."
  tags                         = local.common_tags
}

resource "aws_vpc_security_group_egress_rule" "emr_probe" {
  count             = local.enabled ? 1 : 0
  security_group_id = aws_security_group.emr[0].id
  cidr_ipv4         = "${var.probe_ipv4}/32"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "Synthetic HTTPS probe only."
  tags              = local.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "endpoint_from_web" {
  count                        = local.enabled ? 1 : 0
  security_group_id            = aws_security_group.ssm_endpoint[0].id
  referenced_security_group_id = aws_security_group.web[0].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "SSM TLS from synthetic Web/NAT instance."
  tags                         = local.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "endpoint_from_emr" {
  count                        = local.enabled ? 1 : 0
  security_group_id            = aws_security_group.ssm_endpoint[0].id
  referenced_security_group_id = aws_security_group.emr[0].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "SSM TLS from synthetic EMR probe instance."
  tags                         = local.common_tags
}

resource "aws_network_interface" "web" {
  count             = local.enabled ? 1 : 0
  subnet_id         = aws_subnet.public[0].id
  private_ips       = [var.web_private_ip]
  security_groups   = [aws_security_group.web[0].id]
  source_dest_check = false
  tags              = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-web-eni" })
}

resource "aws_network_interface" "emr" {
  count           = local.enabled ? 1 : 0
  subnet_id       = aws_subnet.private[0].id
  private_ips     = [var.emr_private_ip]
  security_groups = [aws_security_group.emr[0].id]
  tags            = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-emr-eni" })
}

resource "aws_iam_role" "ssm" {
  count = local.enabled ? 1 : 0
  name  = "dr-synth-${var.run_id}-ssm"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.${data.aws_partition.current.dns_suffix}" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "ssm_agent_minimum" {
  count = local.enabled ? 1 : 0
  name  = "synthetic-ssm-agent-minimum"
  role  = aws_iam_role.ssm[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect   = "Allow"
        Action   = ["ssm:UpdateInstanceInformation"]
        Resource = "arn:${data.aws_partition.current.partition}:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*"
        Condition = {
          StringEquals = { "aws:ResourceTag/CanaryRunId" = var.run_id }
        }
        }, {
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
        ]
        Resource = "*"
      }],
      var.enable_ec2messages_endpoint ? [{
        Effect = "Allow"
        Action = [
          "ec2messages:AcknowledgeMessage",
          "ec2messages:DeleteMessage",
          "ec2messages:FailMessage",
          "ec2messages:GetEndpoint",
          "ec2messages:GetMessages",
          "ec2messages:SendReply",
        ]
        Resource = "*"
      }] : []
    )
  })
}

resource "aws_iam_instance_profile" "ssm" {
  count = local.enabled ? 1 : 0
  name  = "dr-synth-${var.run_id}-ssm"
  role  = aws_iam_role.ssm[0].name
  tags  = local.common_tags
}

# Resolve and validate a pinned Amazon-published AL2023 image during planning,
# before any network or compute resources can be created. The exact AMI ID is
# supplied per Run ID; only Amazon's canonical public x86_64 AL2023 owner/name
# contract is accepted. No hospital/application AMI is accepted by this stack.
data "aws_ami" "synthetic" {
  count       = local.enabled ? 1 : 0
  most_recent = false
  owners      = ["137112412989"]

  filter {
    name   = "image-id"
    values = [var.synthetic_ami_id]
  }
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "is-public"
    values = ["true"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

resource "aws_vpc_endpoint" "ssm" {
  for_each            = local.enabled ? local.ssm_services : toset([])
  vpc_id              = aws_vpc.canary[0].id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.private[0].id]
  security_group_ids  = [aws_security_group.ssm_endpoint[0].id]
  tags                = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-${each.key}" })
}

# AWS creates requester-managed ENIs for interface endpoints. Tag those ENIs
# separately so Run-ID inventory and state-less cleanup can find every ENI.
resource "aws_ec2_tag" "ssm_endpoint_eni_run_id" {
  for_each    = local.enabled ? local.ssm_services : toset([])
  resource_id = one(aws_vpc_endpoint.ssm[each.key].network_interface_ids)
  key         = "CanaryRunId"
  value       = var.run_id
}

resource "aws_route53_resolver_firewall_config" "canary" {
  count              = local.enabled ? 1 : 0
  resource_id        = aws_vpc.canary[0].id
  firewall_fail_open = "DISABLED"
}

resource "aws_route53_resolver_firewall_domain_list" "allow" {
  count   = local.enabled ? 1 : 0
  name    = "dr-synth-${var.run_id}-allow"
  domains = [for d in local.allowed_dns_domains : format("%s.", trimsuffix(d, "."))]
  tags    = local.common_tags
}

resource "aws_route53_resolver_firewall_domain_list" "block_all" {
  count   = local.enabled ? 1 : 0
  name    = "dr-synth-${var.run_id}-block-all"
  domains = ["*."]
  tags    = local.common_tags
}

resource "aws_route53_resolver_firewall_rule_group" "canary" {
  count = local.enabled ? 1 : 0
  name  = "dr-synth-${var.run_id}"
  tags  = local.common_tags
}

resource "aws_route53_resolver_firewall_rule" "allow" {
  count                   = local.enabled ? 1 : 0
  name                    = "dr-synth-${var.run_id}-allow"
  action                  = "ALLOW"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.allow[0].id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.canary[0].id
  priority                = 10
}

resource "aws_route53_resolver_firewall_rule" "block_all" {
  count                   = local.enabled ? 1 : 0
  name                    = "dr-synth-${var.run_id}-block-all"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.block_all[0].id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.canary[0].id
  priority                = 100
}

resource "aws_route53_resolver_firewall_rule_group_association" "canary" {
  count                  = local.enabled ? 1 : 0
  name                   = "dr-synth-${var.run_id}-vpc"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.canary[0].id
  vpc_id                 = aws_vpc.canary[0].id
  priority               = 200
  mutation_protection    = "DISABLED"
  tags                   = local.common_tags
  depends_on             = [aws_route53_resolver_firewall_rule.allow, aws_route53_resolver_firewall_rule.block_all]
}

resource "aws_eip" "web" {
  count  = local.enabled ? 1 : 0
  domain = "vpc"
  tags   = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-web-eip" })
}

resource "aws_instance" "web" {
  count                = local.enabled ? 1 : 0
  ami                  = data.aws_ami.synthetic[0].id
  instance_type        = var.instance_type
  iam_instance_profile = aws_iam_instance_profile.ssm[0].name
  network_interface {
    network_interface_id = aws_network_interface.web[0].id
    device_index         = 0
  }
  user_data                   = ""
  user_data_replace_on_change = true
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  root_block_device {
    volume_size           = var.root_volume_size_gib
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }
  volume_tags = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-web-root" })
  tags        = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-web" })
  depends_on = [
    aws_iam_role_policy.ssm_agent_minimum,
    aws_vpc_endpoint.ssm,
    aws_route53_resolver_firewall_config.canary,
    aws_route53_resolver_firewall_rule_group_association.canary,
    aws_network_acl_rule.web_ingress,
    aws_network_acl_rule.web_egress,
    aws_network_acl_rule.emr_ingress,
    aws_network_acl_rule.emr_egress,
  ]
}

resource "aws_eip_association" "web" {
  count                = local.enabled ? 1 : 0
  allocation_id        = aws_eip.web[0].id
  network_interface_id = aws_network_interface.web[0].id
  private_ip_address   = var.web_private_ip
}

resource "aws_ec2_instance_state" "web_stopped" {
  count       = local.enabled ? 1 : 0
  instance_id = aws_instance.web[0].id
  state       = "stopped"
}

resource "aws_route" "private_default" {
  count                  = local.enabled ? 1 : 0
  route_table_id         = aws_route_table.private[0].id
  destination_cidr_block = "AWS_PUBLIC_IP_REDACTED/0"
  network_interface_id   = aws_network_interface.web[0].id
  depends_on             = [aws_eip_association.web]
}

resource "aws_instance" "emr" {
  count                = local.enabled ? 1 : 0
  ami                  = data.aws_ami.synthetic[0].id
  instance_type        = var.instance_type
  iam_instance_profile = aws_iam_instance_profile.ssm[0].name
  network_interface {
    network_interface_id = aws_network_interface.emr[0].id
    device_index         = 0
  }
  user_data                   = ""
  user_data_replace_on_change = true
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  root_block_device {
    volume_size           = var.root_volume_size_gib
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }
  volume_tags = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-emr-root" })
  tags        = merge(local.common_tags, { Name = "dr-synth-${var.run_id}-emr" })
  depends_on = [
    aws_iam_role_policy.ssm_agent_minimum,
    aws_ec2_instance_state.web_stopped,
    aws_route.private_default,
    aws_vpc_endpoint.ssm,
    aws_route53_resolver_firewall_rule_group_association.canary,
    aws_network_acl_rule.web_ingress,
    aws_network_acl_rule.web_egress,
    aws_network_acl_rule.emr_ingress,
    aws_network_acl_rule.emr_egress,
  ]
}

resource "aws_ec2_instance_state" "emr_stopped" {
  count       = local.enabled ? 1 : 0
  instance_id = aws_instance.emr[0].id
  state       = "stopped"
}
