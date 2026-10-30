# ==========================================
# 1. Input variables
# ==========================================
variable "aws_region" {
  default = "ap-northeast-2"
}

variable "ssh_public_key_path" {
  description = "Local path to the SSH public key used for full DR EC2 provisioning; omitted by NAT-only lifecycle operations"
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  default = "IP_REDACTED/16"
}

variable "private_web_subnet_cidr" {
  default = "IP_REDACTED/24"
}

variable "private_doc_subnet_cidr" {
  default = "IP_REDACTED/24"
}

variable "private_db_subnet_cidr" {
  default = "IP_REDACTED/24"
}

variable "ubuntu_ami_id" {
  description = "Pinned Ubuntu 22.04 AMI for stable DR rebuilds"
  type        = string
  default     = "AWS_RESOURCE_ID_REDACTED"
}

variable "enable_nat_gateway" {
  description = "Manage the NAT Gateway resource. In Web NAT mode this must be false for blackhole recovery, or true only when an existing NAT Gateway is intentionally retained."
  type        = bool
  default     = false
}

variable "private_egress_mode" {
  description = "Private-subnet default egress target. web_nat_instance is an explicit, reviewed migration/recovery mode; it never authorizes NAT Gateway creation by itself."
  type        = string
  default     = "nat_gateway"

  validation {
    condition     = contains(["nat_gateway", "web_nat_instance", "none"], var.private_egress_mode)
    error_message = "private_egress_mode must be nat_gateway, web_nat_instance, or none."
  }
}

variable "aws_web_nat_instance_enabled" {
  description = "Opt in to the existing approved Web instance acting as a NAT Instance; false leaves current firewall and route behavior unchanged"
  type        = bool
  default     = false
}

variable "enable_s3_gateway_endpoint" {
  description = "Optional, no-hourly-charge S3 Gateway Endpoint for the private route table; disabled by default"
  type        = bool
  default     = false
}

variable "aws_dr_wg_enabled" {
  description = "Enable the optional, dedicated On-Prem DB to AWS DR WireGuard path"
  type        = bool
  default     = false
}

variable "aws_dr_wg_cidr" {
  description = "Dedicated AWS DR WireGuard address space; never overlap MSP or legacy AWS tunnels"
  type        = string
  default     = "IP_REDACTED/24"

  validation {
    condition     = var.aws_dr_wg_cidr == "AWS_PUBLIC_IP_REDACTED/24"
    error_message = "aws_dr_wg_cidr is fixed to the dedicated AWS_PUBLIC_IP_REDACTED/24 AWS DR range."
  }
}

variable "aws_dr_wg_peer_ipv4" {
  description = "On-Prem DB WireGuard address used by the dedicated AWS DR path"
  type        = string
  default     = "IP_REDACTED/32"

  validation {
    condition     = var.aws_dr_wg_peer_ipv4 == "AWS_PUBLIC_IP_REDACTED/32"
    error_message = "aws_dr_wg_peer_ipv4 is fixed to AWS_PUBLIC_IP_REDACTED/32 for the AWS DR path."
  }
}

variable "aws_dr_wg_port" {
  description = "Dedicated AWS DR WireGuard UDP listen port"
  type        = number
  default     = 51821

  validation {
    condition     = var.aws_dr_wg_port == 51821
    error_message = "aws_dr_wg_port must remain UDP 51821 for the AWS DR path."
  }
}

variable "aws_dr_wg_peer_ingress_ipv4_cidrs" {
  description = "Controlled On-Prem egress CIDRs allowed to reach the AWS DR WireGuard listener"
  type        = list(string)
  default     = ["IP_REDACTED/32"]

  validation {
    condition = alltrue([
      for cidr in var.aws_dr_wg_peer_ingress_ipv4_cidrs :
      can(cidrhost(cidr, 0)) && cidr != "IP_REDACTED/0"
    ])
    error_message = "AWS DR WireGuard ingress must contain valid, non-broad IPv4 CIDRs; AWS_PUBLIC_IP_REDACTED/0 is forbidden."
  }
}

variable "cost_guard_enabled" {
  description = "Enable the AWS-side daily DNS safety check; DR EC2 lifecycle is operator-managed"
  type        = bool
  default     = true
}

variable "enable_static_web_eip" {
  description = "Attach a stable Elastic IP to the DR Web origin endpoint"
  type        = bool
  default     = true
}

variable "enable_dump_restore_isolated_host" {
  description = "Opt in to a private, isolated one-purpose MySQL host for validating encrypted dump restores; disabled by default"
  type        = bool
  default     = false
}

variable "enable_dump_restore_service_sg" {
  description = "Create the isolated Dump DB's private MySQL service SG. This SG is deliberately not attached by Terraform; the explicit service-preparation workflow attaches it only after restore and identity checks."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_dump_restore_service_sg || var.enable_dump_restore_isolated_host
    error_message = "The isolated Dump DB service SG requires enable_dump_restore_isolated_host=true."
  }
}

variable "dump_restore_isolated_service_promoted" {
  description = "Operator-recorded state for the isolated DB after separate service promotion; this is not a promotion action or a substitute for the always-on Terraform deletion guards"
  type        = bool
  default     = false

  validation {
    condition = !var.dump_restore_isolated_service_promoted || (
      var.enable_dump_restore_isolated_host && var.enable_dump_restore_service_sg
    )
    error_message = "A promoted isolated service DB must keep its host and dedicated service SG enabled in Terraform."
  }
}

variable "dump_restore_isolated_instance_type" {
  description = "Instance size for the optional isolated dump validation host"
  type        = string
  default     = "t3.small"

  validation {
    condition     = contains(["t3.small", "t3.medium", "t3.large"], var.dump_restore_isolated_instance_type)
    error_message = "The isolated dump restore host must use an explicitly supported t3.small, t3.medium, or t3.large size."
  }
}

variable "dump_restore_isolated_data_volume_size" {
  description = "Encrypted, dedicated MySQL data EBS volume size for the optional isolated restore host"
  type        = number
  default     = 50

  validation {
    condition     = var.dump_restore_isolated_data_volume_size >= 20 && var.dump_restore_isolated_data_volume_size <= 2000
    error_message = "The isolated MySQL data volume must be between 20 and 2000 GiB."
  }
}

variable "dump_restore_isolated_stage_volume_size" {
  description = "Encrypted staging EBS size for the optional isolated dump restore host"
  type        = number
  default     = 100

  validation {
    condition     = var.dump_restore_isolated_stage_volume_size >= 20 && var.dump_restore_isolated_stage_volume_size <= 2000
    error_message = "The isolated dump staging volume must be between 20 and 2000 GiB."
  }
}

variable "enable_dump_restore_lease_store" {
  description = "Opt in to a protected DynamoDB control record and separate least-privilege roles for Dump-restore/shutdown lease coordination; no runtime is connected automatically"
  type        = bool
  default     = false
}

variable "dump_restore_lease_ttl_seconds" {
  description = "Operator-selected lease duration; must be set before enabling the shared lease store"
  type        = number
  default     = 0

  validation {
    condition = !var.enable_dump_restore_lease_store || (
      var.dump_restore_lease_ttl_seconds > 0 &&
      var.dump_restore_lease_ttl_seconds == floor(var.dump_restore_lease_ttl_seconds) &&
      var.dump_restore_lease_ttl_seconds <= 604800
    )
    error_message = "When enabled, lease duration must be positive and no longer than the seven-day safety ceiling."
  }
}

variable "dump_restore_lease_renew_interval_seconds" {
  description = "Operator-selected lease heartbeat interval; must be shorter than the lease duration"
  type        = number
  default     = 0

  validation {
    condition = !var.enable_dump_restore_lease_store || (
      var.dump_restore_lease_renew_interval_seconds > 0 &&
      var.dump_restore_lease_renew_interval_seconds == floor(var.dump_restore_lease_renew_interval_seconds) &&
      var.dump_restore_lease_renew_interval_seconds < var.dump_restore_lease_ttl_seconds
    )
    error_message = "When enabled, lease renewal interval must be positive and shorter than the lease duration."
  }
}

variable "dump_restore_lease_max_duration_seconds" {
  description = "Operator-selected absolute lease lifetime across renewals; must cover one lease and remain below the seven-day safety ceiling"
  type        = number
  default     = 0

  validation {
    condition = !var.enable_dump_restore_lease_store || (
      var.dump_restore_lease_max_duration_seconds >= var.dump_restore_lease_ttl_seconds &&
      var.dump_restore_lease_max_duration_seconds == floor(var.dump_restore_lease_max_duration_seconds) &&
      var.dump_restore_lease_max_duration_seconds <= 604800
    )
    error_message = "When enabled, maximum lease duration must cover the lease duration and not exceed seven days."
  }
}

variable "dump_restore_lease_controller_principal_arns" {
  description = "Exact AWS IAM principal ARNs allowed to assume the separate Dump lease controller role; no wildcard principals"
  type        = list(string)
  default     = []

  validation {
    condition = !var.enable_dump_restore_lease_store || (
      length(var.dump_restore_lease_controller_principal_arns) > 0 &&
      alltrue([
        for principal in var.dump_restore_lease_controller_principal_arns :
        can(regex("^arn:[A-Za-z0-9-]+:iam::[0-9]{12}:(role|user)/[^*?]+$", principal))
      ])
    )
    error_message = "When enabled, configure one or more exact AWS principal ARNs; wildcard principals are forbidden."
  }
}

variable "onprem_web_public_ip" {
  description = "Public IP for the on-premises Web reverse proxy"
  type        = string
  default     = "IP_REDACTED"
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID supplied by the external DR secret/configuration"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{32}$", var.cloudflare_zone_id))
    error_message = "cloudflare_zone_id must be a 32-character hexadecimal Cloudflare zone ID."
  }
}

variable "management_ipv4_cidrs" {
  description = "Trusted administrator and Ansible controller public IPv4 CIDRs"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.management_ipv4_cidrs :
      can(regex("^[0-9]{1,3}(\\.[0-9]{1,3}){3}/[0-9]{1,2}$", cidr)) &&
      can(cidrhost(cidr, 0)) &&
      try(tonumber(split("/", cidr)[1]), -1) > 0
    ])
    error_message = "management_ipv4_cidrs must contain only valid non-zero IPv4 CIDRs; IP_REDACTED/0 is not allowed."
  }
}

variable "cloudflare_ipv4_cidrs" {
  description = "Cloudflare IPv4 ranges allowed to reach the DR Web origin"
  type        = list(string)
  default = [
    "IP_REDACTED/20",
    "IP_REDACTED/22",
    "IP_REDACTED/22",
    "IP_REDACTED/22",
    "IP_REDACTED/18",
    "IP_REDACTED/18",
    "IP_REDACTED/20",
    "IP_REDACTED/20",
    "IP_REDACTED/22",
    "IP_REDACTED/17",
    "IP_REDACTED/15",
    "IP_REDACTED/13",
    "IP_REDACTED/14",
    "IP_REDACTED/13",
    "IP_REDACTED/22",
  ]

  validation {
    condition     = length(var.cloudflare_ipv4_cidrs) > 0 && alltrue([for cidr in var.cloudflare_ipv4_cidrs : can(cidrhost(cidr, 0))])
    error_message = "cloudflare_ipv4_cidrs must contain at least one valid IPv4 CIDR."
  }
}

variable "zabbix_agent_source_ipv4_cidrs" {
  description = "Optional Zabbix server or proxy IPv4 CIDRs allowed to poll TCP 10050 directly"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.zabbix_agent_source_ipv4_cidrs : can(cidrhost(cidr, 0))])
    error_message = "zabbix_agent_source_ipv4_cidrs must contain only valid IPv4 CIDRs."
  }
}

variable "s3_backup_bucket_name" {
  description = "Optional globally unique S3 bucket name for encrypted MSP database backups"
  type        = string
  default     = ""
}

variable "s3_backup_lifecycle_days" {
  description = "Days before current backup objects expire"
  type        = number
  default     = 365
}

variable "s3_backup_noncurrent_days" {
  description = "Days before noncurrent backup object versions expire"
  type        = number
  default     = 90
}

variable "ecr_web_repository_name" {
  description = "Private ECR repository for the DR Web image"
  type        = string
  default     = "hospital-dr-web"
}

variable "ecr_emr_repository_name" {
  description = "Private ECR repository for the DR EMR image"
  type        = string
  default     = "hospital-dr-emr"
}

variable "ecr_tagged_image_retention_count" {
  description = "Number of immutable tagged ECR images to retain per repository"
  type        = number
  default     = 10
}

# ==========================================
# 2. Terraform and provider configuration
# ==========================================
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

locals {
  s3_backup_bucket_name = var.s3_backup_bucket_name != "" ? var.s3_backup_bucket_name : "hospital-dr-db-backup-${data.aws_caller_identity.current.account_id}"
  s3_backup_prefix      = "mysql/hospital_db/"
}

provider "cloudflare" {}

# ==========================================
# 3. AWS AMI and SSH key configuration
# ==========================================

resource "aws_key_pair" "dr_key" {
  key_name   = "hospital-dr-key-v2"
  public_key = trimspace(var.ssh_public_key_path) == "" ? "" : file(var.ssh_public_key_path)

  lifecycle {
    precondition {
      condition     = length(trimspace(var.ssh_public_key_path)) > 0
      error_message = "ssh_public_key_path must be supplied for full DR EC2 provisioning; NAT-only lifecycle operations must target only NAT resources."
    }
  }
}

# ==========================================
# 3a. Private ECR repositories and least-privilege image access
# Images are built outside the DR failover path and pulled at runtime.
# ==========================================
resource "aws_ecr_repository" "dr_web" {
  name                 = var.ecr_web_repository_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name    = "Hospital-DR-Web-Images"
    Purpose = "DR-Prebuilt-Container"
  }
}

resource "aws_ecr_repository" "dr_emr" {
  name                 = var.ecr_emr_repository_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name    = "Hospital-DR-EMR-Images"
    Purpose = "DR-Prebuilt-Container"
  }
}

resource "aws_ecr_lifecycle_policy" "dr_web" {
  repository = aws_ecr_repository.dr_web.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Retain the newest immutable tagged Web images"
        selection = {
          tagStatus      = "tagged"
          tagPatternList = ["*"]
          countType      = "imageCountMoreThan"
          countNumber    = var.ecr_tagged_image_retention_count
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Remove untagged Web image manifests"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = { type = "expire" }
      }
    ]
  })
}

resource "aws_ecr_lifecycle_policy" "dr_emr" {
  repository = aws_ecr_repository.dr_emr.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Retain the newest immutable tagged EMR images"
        selection = {
          tagStatus      = "tagged"
          tagPatternList = ["*"]
          countType      = "imageCountMoreThan"
          countNumber    = var.ecr_tagged_image_retention_count
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Remove untagged EMR image manifests"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = { type = "expire" }
      }
    ]
  })
}

data "aws_iam_policy_document" "dr_ecr_pull_assume_role" {
  statement {
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dr_ecr_pull" {
  name               = "hospital-dr-ecr-pull-role"
  assume_role_policy = data.aws_iam_policy_document.dr_ecr_pull_assume_role.json

  tags = {
    Name    = "Hospital-DR-ECR-Pull-Role"
    Purpose = "DR-Container-Pull"
  }
}

resource "aws_iam_role_policy" "dr_ecr_pull" {
  name = "hospital-dr-ecr-pull-policy"
  role = aws_iam_role.dr_ecr_pull.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EcrAuthToken"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "PullHospitalDrImages"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer"
        ]
        Resource = [
          aws_ecr_repository.dr_web.arn,
          aws_ecr_repository.dr_emr.arn
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "dr_ecr_pull" {
  name = "hospital-dr-ecr-pull-profile"
  role = aws_iam_role.dr_ecr_pull.name

  tags = {
    Name    = "Hospital-DR-ECR-Pull-Profile"
    Purpose = "DR-Container-Pull"
  }
}

# ==========================================
# 4. AWS network foundation (VPC, IGW, NAT, subnets)
# ==========================================
resource "aws_vpc" "dr_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "Hospital-DR-VPC" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.dr_vpc.id
  tags   = { Name = "Hospital-DR-IGW" }
}

resource "aws_eip" "nat_eip" {
  domain = "vpc"

  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name     = "Hospital-DR-NAT-EIP"
    Purpose  = "MySQL-NR-Egress"
    Preserve = "true"
  }
}

resource "aws_nat_gateway" "nat_gw" {
  count         = var.enable_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet.id
  tags          = { Name = "Hospital-DR-NAT-GW" }

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.dr_vpc.id
  cidr_block              = "IP_REDACTED/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"
  tags                    = { Name = "Hospital-DR-Public-Subnet" }
}

resource "aws_subnet" "private_web_subnet" {
  vpc_id            = aws_vpc.dr_vpc.id
  cidr_block        = var.private_web_subnet_cidr
  availability_zone = "${var.aws_region}a"
  tags              = { Name = "Hospital-DR-Private-Web-Subnet" }
}

resource "aws_subnet" "private_doc_subnet" {
  vpc_id            = aws_vpc.dr_vpc.id
  cidr_block        = var.private_doc_subnet_cidr
  availability_zone = "${var.aws_region}a"
  tags              = { Name = "Hospital-DR-Private-Doc-Subnet" }
}

resource "aws_subnet" "private_db_subnet" {
  vpc_id            = aws_vpc.dr_vpc.id
  cidr_block        = var.private_db_subnet_cidr
  availability_zone = "${var.aws_region}c"
  tags              = { Name = "Hospital-DR-Private-DB-Subnet" }
}

# ==========================================
# 5. AWS route tables and associations
# ==========================================
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.dr_vpc.id
  route {
    cidr_block = "IP_REDACTED/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "Hospital-DR-Public-RT" }
}

resource "aws_route_table_association" "public_rt_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.dr_vpc.id
  tags   = { Name = "Hospital-DR-Private-RT" }
}

# Optional routed path for AWS DB -> On-Prem DB over the dedicated Web gateway.
# This resource is deliberately absent while aws_dr_wg_enabled is false.
resource "aws_route" "aws_dr_wg_onprem_db" {
  count                  = var.aws_dr_wg_enabled ? 1 : 0
  route_table_id         = aws_route_table.private_rt.id
  destination_cidr_block = var.aws_dr_wg_cidr
  network_interface_id   = aws_instance.hospital_real_web.primary_network_interface_id

  lifecycle {
    precondition {
      condition     = aws_vpc.dr_vpc.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "AWS DR WireGuard requires the approved Hospital DR VPC AWS_RESOURCE_ID_REDACTED."
    }
    precondition {
      condition     = aws_route_table.private_rt.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "AWS DR WireGuard requires private route table AWS_RESOURCE_ID_REDACTED."
    }
    precondition {
      condition     = aws_instance.hospital_real_web.private_ip == "AWS_PUBLIC_IP_REDACTED"
      error_message = "AWS DR WireGuard requires the approved Web gateway private IP AWS_PUBLIC_IP_REDACTED."
    }
    precondition {
      condition     = aws_instance.hospital_real_web.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "AWS DR WireGuard requires the approved Web gateway instance AWS_RESOURCE_ID_REDACTED."
    }
    precondition {
      condition     = try(aws_eip.web_eip[0].public_ip, "") == "AWS_PUBLIC_IP_REDACTED"
      error_message = "AWS DR WireGuard requires the preserved Web EIP AWS_PUBLIC_IP_REDACTED."
    }
    precondition {
      condition     = aws_instance.db_server.id == "AWS_RESOURCE_ID_REDACTED" && aws_instance.db_server.private_ip == "AWS_PUBLIC_IP_REDACTED"
      error_message = "AWS DR WireGuard requires the approved DB instance AWS_RESOURCE_ID_REDACTED at AWS_PUBLIC_IP_REDACTED."
    }
  }
}

resource "aws_route" "private_internet" {
  # Keep the existing resource address so a migration/recovery changes only the
  # route target. In web_nat_instance mode, enable_nat_gateway=false is the
  # BLACKHOLE recovery contract: no NAT Gateway is created or recreated.
  count                  = var.private_egress_mode == "none" || (var.private_egress_mode == "nat_gateway" && !var.enable_nat_gateway) ? 0 : 1
  route_table_id         = aws_route_table.private_rt.id
  destination_cidr_block = "AWS_PUBLIC_IP_REDACTED/0"
  nat_gateway_id         = var.private_egress_mode == "nat_gateway" ? aws_nat_gateway.nat_gw[0].id : null
  network_interface_id   = var.private_egress_mode == "web_nat_instance" ? aws_instance.hospital_real_web.primary_network_interface_id : null

  lifecycle {
    precondition {
      condition     = var.private_egress_mode != "nat_gateway" || var.enable_nat_gateway
      error_message = "nat_gateway private_egress_mode requires enable_nat_gateway=true."
    }
    precondition {
      condition     = var.private_egress_mode != "web_nat_instance" || var.aws_web_nat_instance_enabled
      error_message = "web_nat_instance private_egress_mode requires aws_web_nat_instance_enabled=true."
    }
    precondition {
      condition     = var.private_egress_mode != "web_nat_instance" || aws_vpc.dr_vpc.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "Web NAT Instance mode requires the approved Hospital DR VPC AWS_RESOURCE_ID_REDACTED."
    }
    precondition {
      condition     = var.private_egress_mode != "web_nat_instance" || aws_route_table.private_rt.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "Web NAT Instance mode requires private route table AWS_RESOURCE_ID_REDACTED."
    }
    precondition {
      condition     = var.private_egress_mode != "web_nat_instance" || aws_instance.hospital_real_web.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "Web NAT Instance mode requires the approved Web instance AWS_RESOURCE_ID_REDACTED."
    }
    precondition {
      condition     = var.private_egress_mode != "web_nat_instance" || aws_instance.hospital_real_web.private_ip == "AWS_PUBLIC_IP_REDACTED"
      error_message = "Web NAT Instance mode requires Web private IP AWS_PUBLIC_IP_REDACTED."
    }
    precondition {
      condition     = var.private_egress_mode != "web_nat_instance" || try(aws_eip.web_eip[0].public_ip, "") == "AWS_PUBLIC_IP_REDACTED"
      error_message = "Web NAT Instance mode requires the preserved Web EIP AWS_PUBLIC_IP_REDACTED."
    }
  }
}

resource "aws_route_table_association" "private_web_rt_assoc" {
  subnet_id      = aws_subnet.private_web_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "private_doc_rt_assoc" {
  subnet_id      = aws_subnet.private_doc_subnet.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_db_rt_assoc" {
  subnet_id      = aws_subnet.private_db_subnet.id
  route_table_id = aws_route_table.private_rt.id
}

# Optional, no-hourly-charge S3 Gateway Endpoint candidate. It is deliberately
# disabled by default and is independent of the NAT migration route target.
resource "aws_vpc_endpoint" "s3_gateway" {
  count             = var.enable_s3_gateway_endpoint ? 1 : 0
  vpc_id            = aws_vpc.dr_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private_rt.id]

  lifecycle {
    precondition {
      condition     = aws_vpc.dr_vpc.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "The optional S3 Gateway Endpoint is restricted to the approved Hospital DR VPC."
    }
    precondition {
      condition     = aws_route_table.private_rt.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "The optional S3 Gateway Endpoint is restricted to the approved private route table."
    }
  }

  tags = {
    Name    = "Hospital-DR-S3-Gateway-Endpoint"
    Purpose = "Private-Subnet-S3-Access"
  }
}

# ==========================================
# 6. AWS security groups
# ==========================================
resource "aws_security_group" "web_sg" {
  name   = "hospital-dr-web-sg"
  vpc_id = aws_vpc.dr_vpc.id

  lifecycle {
    precondition {
      condition     = !var.aws_dr_wg_enabled || aws_vpc.dr_vpc.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "AWS DR WireGuard cannot be enabled outside the approved Hospital DR VPC."
    }
  }

  ingress {
    description = "HTTP from Cloudflare proxy"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.cloudflare_ipv4_cidrs
  }
  ingress {
    description = "HTTPS from Cloudflare proxy"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.cloudflare_ipv4_cidrs
  }
  ingress {
    description = "HTTPS origin health checks from the DR controller"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.management_ipv4_cidrs
  }
  ingress {
    description = "SSH from trusted administrators and Ansible controller"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.management_ipv4_cidrs
  }
  dynamic "ingress" {
    for_each = length(var.zabbix_agent_source_ipv4_cidrs) == 0 ? [] : [1]
    content {
      description = "Zabbix passive agent checks from configured server or proxy"
      from_port   = 10050
      to_port     = 10050
      protocol    = "tcp"
      cidr_blocks = var.zabbix_agent_source_ipv4_cidrs
    }
  }
  dynamic "ingress" {
    for_each = var.aws_dr_wg_enabled ? [1] : []
    content {
      description = "AWS DR DB forwarded traffic to the dedicated WireGuard peer"
      from_port   = 3306
      to_port     = 3306
      protocol    = "tcp"
      cidr_blocks = ["IP_REDACTED/32"]
    }
  }
  # Preserve the existing wg0 listener. The dedicated wg-aws-dr interface
  # uses aws_dr_wg_port separately and must never replace UDP/51820.
  ingress {
    description = "Dedicated On-Prem egress for the AWS DR WireGuard listener"
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["IP_REDACTED/32"]
  }

  dynamic "ingress" {
    for_each = var.aws_dr_wg_enabled ? [1] : []
    content {
      description = "Dedicated On-Prem egress for the AWS DR WireGuard listener"
      from_port   = var.aws_dr_wg_port
      to_port     = var.aws_dr_wg_port
      protocol    = "udp"
      cidr_blocks = var.aws_dr_wg_peer_ingress_ipv4_cidrs
    }
  }
  dynamic "ingress" {
    # Forwarded EMR web requests retain their private source address at the
    # existing Web NAT ENI. Limit the opt-in rule to the EMR subnet and the
    # HTTP(S) ports needed for outbound web traffic.
    for_each = var.aws_web_nat_instance_enabled ? toset([80, 443]) : toset([])
    content {
      description = "HTTP(S) forwarded from DR EMR through the opt-in Web NAT Instance"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = [var.private_doc_subnet_cidr]
    }
  }
  egress {
    description = "Required for package installation, APIs, monitoring, and DR recovery"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["IP_REDACTED/0"]
  }
}

resource "aws_security_group" "doc_sg" {
  name   = "hospital-dr-doc-sg"
  vpc_id = aws_vpc.dr_vpc.id

  ingress {
    description     = "EMR reverse proxy traffic from DR Web"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id]
  }
  ingress {
    description     = "SSH from Ansible through the DR Web bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id]
  }
  dynamic "ingress" {
    for_each = length(var.zabbix_agent_source_ipv4_cidrs) == 0 ? [] : [1]
    content {
      description = "Zabbix passive agent checks from configured server or proxy"
      from_port   = 10050
      to_port     = 10050
      protocol    = "tcp"
      cidr_blocks = var.zabbix_agent_source_ipv4_cidrs
    }
  }
  egress {
    description = "Required for packages, DB access, monitoring, and DR recovery"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["IP_REDACTED/0"]
  }
}

resource "aws_security_group" "db_sg" {
  name   = "hospital-dr-db-sg"
  vpc_id = aws_vpc.dr_vpc.id

  lifecycle {
    precondition {
      condition     = !var.aws_dr_wg_enabled || aws_vpc.dr_vpc.id == "AWS_RESOURCE_ID_REDACTED"
      error_message = "AWS DR WireGuard cannot be enabled outside the approved Hospital DR VPC."
    }
  }

  ingress {
    description     = "MySQL from DR Web"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id]
  }
  ingress {
    description     = "MySQL from DR Doc"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.doc_sg.id]
  }
  ingress {
    description     = "SSH from Ansible through the DR Web bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id]
  }
  dynamic "ingress" {
    for_each = length(var.zabbix_agent_source_ipv4_cidrs) == 0 ? [] : [1]
    content {
      description = "Zabbix passive agent checks from configured server or proxy"
      from_port   = 10050
      to_port     = 10050
      protocol    = "tcp"
      cidr_blocks = var.zabbix_agent_source_ipv4_cidrs
    }
  }
  egress {
    description = "Required for packages, replication, monitoring, and failback"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["IP_REDACTED/0"]
  }
}

# ==========================================
# 7. AWS EC2 instances
# ==========================================
resource "aws_instance" "hospital_real_web" {
  ami                         = var.ubuntu_ami_id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private_web_subnet.id
  private_ip                  = "IP_REDACTED"
  vpc_security_group_ids      = [aws_security_group.web_sg.id]
  key_name                    = aws_key_pair.dr_key.key_name
  associate_public_ip_address = true
  source_dest_check           = false
  iam_instance_profile        = aws_iam_instance_profile.dr_ecr_pull.name
  tags                        = { Name = "Hospital-Real-Web-Server" }
}

resource "aws_eip" "web_eip" {
  count    = var.enable_static_web_eip ? 1 : 0
  domain   = "vpc"
  instance = aws_instance.hospital_real_web.id

  lifecycle {
    prevent_destroy = true
  }

  tags = { Name = "Hospital-DR-Web-WG-EIP" }

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_instance" "doc_server" {
  ami                         = var.ubuntu_ami_id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private_doc_subnet.id
  private_ip                  = "IP_REDACTED"
  vpc_security_group_ids      = [aws_security_group.doc_sg.id]
  key_name                    = aws_key_pair.dr_key.key_name
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.dr_ecr_pull.name
  tags                        = { Name = "Hospital-DR-Doc-Server" }
}

resource "aws_instance" "db_server" {
  ami                         = var.ubuntu_ami_id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private_db_subnet.id
  private_ip                  = "IP_REDACTED"
  vpc_security_group_ids      = [aws_security_group.db_sg.id]
  key_name                    = aws_key_pair.dr_key.key_name
  associate_public_ip_address = false
  tags                        = { Name = "Hospital-DR-DB-Server" }
}

# This optional host is deliberately not the service DB. It has no public IP,
# accepts SSH only from the reviewed Web bastion, exposes no MySQL ingress,
# and stores MySQL data on its own encrypted EBS volume. It is disabled unless
# explicitly enabled for a separately reviewed restore-validation deployment.
resource "aws_security_group" "dump_restore_isolated" {
  count       = var.enable_dump_restore_isolated_host ? 1 : 0
  name        = "hospital-dr-dump-restore-isolated-sg"
  description = "Private SSH-only access to the isolated dump validation host; no MySQL ingress"
  vpc_id      = aws_vpc.dr_vpc.id

  ingress {
    description     = "SSH only from the DR Web bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id]
  }

  egress {
    description = "HTTPS package and security updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["IP_REDACTED/0"]
  }

  egress {
    description = "HTTP package mirrors when required by the pinned Ubuntu image"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["IP_REDACTED/0"]
  }

  tags = { Name = "Hospital-DR-Dump-Restore-Isolated-SG" }

  lifecycle {
    prevent_destroy = true
  }
}

# A distinct, inert-by-default service SG. It is intentionally not attached
# here: only the explicit isolated DB service-preparation workflow may attach
# it after validating the restored EBS-backed database. No CIDR ingress is
# allowed; MySQL is reachable only from the DR Web and Doc security groups.
resource "aws_security_group" "dump_restore_service" {
  count       = var.enable_dump_restore_service_sg ? 1 : 0
  name        = "hospital-dr-dump-restore-service-sg"
  description = "Private isolated Dump DB MySQL service access from DR Web and Doc only"
  vpc_id      = aws_vpc.dr_vpc.id

  ingress {
    description     = "MySQL service port from DR Web and EMR security groups only"
    from_port       = 3307
    to_port         = 3307
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id, aws_security_group.doc_sg.id]
  }

  egress {
    description     = "MySQL responses/client traffic only to DR Web and EMR security groups"
    from_port       = 3307
    to_port         = 3307
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id, aws_security_group.doc_sg.id]
  }

  tags = {
    Name         = "Hospital-DR-Dump-Restore-Service-SG"
    Purpose      = "Isolated-Dump-DB-Service-Only"
    ServiceState = var.dump_restore_isolated_service_promoted ? "promoted-service-db" : "restore-validation"
    Retention    = "operator-approved-disposal-only"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_instance" "dump_restore_isolated" {
  count                       = var.enable_dump_restore_isolated_host ? 1 : 0
  disable_api_termination     = true
  ami                         = var.ubuntu_ami_id
  instance_type               = var.dump_restore_isolated_instance_type
  subnet_id                   = aws_subnet.private_db_subnet.id
  vpc_security_group_ids      = [aws_security_group.dump_restore_isolated[0].id]
  key_name                    = aws_key_pair.dr_key.key_name
  associate_public_ip_address = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = 20
    delete_on_termination = false

    tags = {
      Name         = "Hospital-DR-Dump-Restore-Isolated-Root"
      Role         = "isolated-dump-restore-root"
      ServiceState = var.dump_restore_isolated_service_promoted ? "promoted-service-db" : "restore-validation"
      Retention    = "operator-approved-disposal-only"
    }
  }

  tags = {
    Name         = "Hospital-DR-Dump-Restore-Isolated"
    Role         = "isolated-dump-restore-validation"
    ServiceState = var.dump_restore_isolated_service_promoted ? "promoted-service-db" : "restore-validation"
    Retention    = "operator-approved-disposal-only"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ebs_volume" "dump_restore_isolated_data" {
  count             = var.enable_dump_restore_isolated_host ? 1 : 0
  availability_zone = aws_subnet.private_db_subnet.availability_zone
  size              = var.dump_restore_isolated_data_volume_size
  type              = "gp3"
  encrypted         = true

  tags = {
    Name         = "Hospital-DR-Dump-Restore-Isolated-Data"
    Role         = "isolated-dump-restore-data"
    ServiceState = var.dump_restore_isolated_service_promoted ? "promoted-service-db" : "restore-validation"
    Retention    = "operator-approved-disposal-only"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ebs_volume" "dump_restore_isolated_stage" {
  count             = var.enable_dump_restore_isolated_host ? 1 : 0
  availability_zone = aws_subnet.private_db_subnet.availability_zone
  size              = var.dump_restore_isolated_stage_volume_size
  type              = "gp3"
  encrypted         = true

  tags = {
    Name         = "Hospital-DR-Dump-Restore-Isolated-Stage"
    Role         = "isolated-dump-restore-staging"
    ServiceState = var.dump_restore_isolated_service_promoted ? "promoted-service-db" : "restore-validation"
    Retention    = "operator-approved-disposal-only"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_volume_attachment" "dump_restore_isolated_data" {
  count       = var.enable_dump_restore_isolated_host ? 1 : 0
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.dump_restore_isolated_data[0].id
  instance_id = aws_instance.dump_restore_isolated[0].id

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_volume_attachment" "dump_restore_isolated_stage" {
  count       = var.enable_dump_restore_isolated_host ? 1 : 0
  device_name = "/dev/sdg"
  volume_id   = aws_ebs_volume.dump_restore_isolated_stage[0].id
  instance_id = aws_instance.dump_restore_isolated[0].id

  lifecycle {
    prevent_destroy = true
  }
}

locals {
  web_public_endpoint = var.enable_static_web_eip ? aws_eip.web_eip[0].public_ip : aws_instance.hospital_real_web.public_ip
}

# ==========================================
# false = route traffic to on-premises web endpoint / true = route traffic to AWS DR endpoint
# ==========================================
variable "is_dr_mode" {
  description = "DR 모드 가동 여부"
  type        = bool
  default     = false
}

# ==========================================
# 8. Cloudflare DNS configuration
# ==========================================
resource "cloudflare_record" "hospital_web" {
  zone_id = var.cloudflare_zone_id
  name    = "hospital-web.pp.ua"
  content = var.is_dr_mode ? local.web_public_endpoint : "e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com"
  type    = var.is_dr_mode ? "A" : "CNAME"
  ttl     = 1
  proxied = true

  # Failover/failback updates this record through the runtime DNS transaction
  # helper, which verifies each API update and compensates by restoring the
  # snapshot if the Web/EMR pair or public health check fails. Updates are sequential.
  # Terraform retains zone/name ownership but must not undo a live cutover later.
  lifecycle {
    ignore_changes = [type, content, ttl, proxied]
  }
}

resource "cloudflare_record" "hospital_emr" {
  zone_id = var.cloudflare_zone_id
  name    = "emr.hospital-web.pp.ua"
  content = var.is_dr_mode ? local.web_public_endpoint : var.onprem_web_public_ip
  type    = "A"
  ttl     = 1
  proxied = true

  # The EMR record follows the same verified, sequential runtime DNS transaction.
  lifecycle {
    ignore_changes = [type, content, ttl, proxied]
  }
}

# ==========================================
# 9. Terraform outputs
# ==========================================
output "web_server_public_ip" {
  value = local.web_public_endpoint
}

output "web_server_private_ip" {
  value = aws_instance.hospital_real_web.private_ip
}

output "cloudflare_web_record_id" {
  value = cloudflare_record.hospital_web.id
}

output "cloudflare_emr_record_id" {
  value = cloudflare_record.hospital_emr.id
}

output "doc_server_private_ip" {
  value = aws_instance.doc_server.private_ip
}

output "db_server_private_ip" {
  value = aws_instance.db_server.private_ip
}

output "dump_restore_isolated_instance_id" {
  value = var.enable_dump_restore_isolated_host ? aws_instance.dump_restore_isolated[0].id : ""
}

output "dump_restore_isolated_private_ip" {
  value = var.enable_dump_restore_isolated_host ? aws_instance.dump_restore_isolated[0].private_ip : ""
}

output "dump_restore_isolated_data_volume_id" {
  value = var.enable_dump_restore_isolated_host ? aws_ebs_volume.dump_restore_isolated_data[0].id : ""
}

output "dump_restore_isolated_stage_volume_id" {
  value = var.enable_dump_restore_isolated_host ? aws_ebs_volume.dump_restore_isolated_stage[0].id : ""
}

output "dump_restore_isolated_service_security_group_id" {
  value = var.enable_dump_restore_service_sg ? aws_security_group.dump_restore_service[0].id : ""
}

output "dump_restore_lease_table_name" {
  value = var.enable_dump_restore_lease_store ? aws_dynamodb_table.dump_restore_lease[0].name : ""
}

output "dump_restore_lease_controller_role_arn" {
  value = var.enable_dump_restore_lease_store ? aws_iam_role.dump_restore_lease_controller[0].arn : ""
}

output "nat_gateway_enabled" {
  value = var.enable_nat_gateway
}

output "private_egress_mode" {
  value = var.private_egress_mode
}

output "aws_web_nat_instance_enabled" {
  value = var.aws_web_nat_instance_enabled
}

output "nat_gateway_id" {
  value = var.enable_nat_gateway ? aws_nat_gateway.nat_gw[0].id : null
}

output "nat_eip_public_ip" {
  value = aws_eip.nat_eip.public_ip
}

output "aws_dr_wg_enabled" {
  value = var.aws_dr_wg_enabled
}

output "aws_dr_wg_cidr" {
  value = var.aws_dr_wg_cidr
}

output "aws_dr_wg_peer_ipv4" {
  value = var.aws_dr_wg_peer_ipv4
}

# ==========================================
# 11. MSP encrypted DB dump off-site backup
# The MSP uploads already-encrypted artifacts; no plaintext SQL is stored here.
# ==========================================
resource "aws_s3_bucket" "db_backup" {
  bucket = local.s3_backup_bucket_name

  tags = {
    Name    = "Hospital-DR-DB-Backup"
    Purpose = "Encrypted-DB-Dump-Offsite"
  }
}

resource "aws_s3_bucket_public_access_block" "db_backup" {
  bucket                  = aws_s3_bucket.db_backup.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "db_backup" {
  bucket = aws_s3_bucket.db_backup.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "db_backup" {
  bucket = aws_s3_bucket.db_backup.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "db_backup" {
  bucket = aws_s3_bucket.db_backup.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "db_backup" {
  bucket = aws_s3_bucket.db_backup.id

  rule {
    id     = "encrypted-db-backup-retention"
    status = "Enabled"

    filter {
      prefix = local.s3_backup_prefix
    }

    expiration {
      days = var.s3_backup_lifecycle_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.s3_backup_noncurrent_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "db_backup" {
  bucket = aws_s3_bucket.db_backup.id

  depends_on = [aws_s3_bucket_public_access_block.db_backup]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.db_backup.arn,
        "${aws_s3_bucket.db_backup.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

resource "aws_iam_user" "db_backup_uploader" {
  name = "hospital-dr-db-backup-uploader"

  tags = {
    Purpose = "Hospital-DR-DB-Backup-Upload"
    Managed = "Terraform"
  }
}

resource "aws_iam_user_policy" "db_backup_uploader" {
  name = "HospitalDRS3EncryptedBackupUpload"
  user = aws_iam_user.db_backup_uploader.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListOnlyBackupPrefix"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.db_backup.arn
        Condition = {
          StringLike = { "s3:prefix" = ["${local.s3_backup_prefix}*"] }
        }
      },
      {
        Sid    = "WriteEncryptedBackupObjects"
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.db_backup.arn}/${local.s3_backup_prefix}*"
      }
    ]
  })
}

output "s3_backup_bucket_name" {
  value = aws_s3_bucket.db_backup.bucket
}

output "s3_backup_uploader_user" {
  value = aws_iam_user.db_backup_uploader.name
}

# ==========================================
# 10. AWS-side cost guard
# Checks and returns DNS even if the local controller is powered off. The
# existing DR EC2 lifecycle is operator-managed; NAT remains manual-only.
# ==========================================
data "archive_file" "dr_cost_guard" {
  type        = "zip"
  source_file = "${path.module}/lambda/dr_cost_guard.py"
  output_path = "${path.module}/.terraform/dr_cost_guard.zip"
}

resource "aws_iam_role" "dr_cost_guard" {
  name = "hospital-dr-cost-guard-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "dr_cost_guard" {
  name = "hospital-dr-cost-guard-policy"
  role = aws_iam_role.dr_cost_guard.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeAddresses"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:Region" = var.aws_region
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:log-group:/aws/lambda/hospital-dr-cost-guard:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/hospital-dr/cloudflare/api-token"
      }
    ]
  })
}

# Shared arbitration store is opt-in and intentionally not wired to the
# existing cost-guard Lambda or Dump restore controller in this phase.
resource "aws_dynamodb_table" "dump_restore_lease" {
  count                       = var.enable_dump_restore_lease_store ? 1 : 0
  name                        = "hospital-dr-dump-restore-lease"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = true

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  # Do not configure DynamoDB TTL: lease expiry is evaluated by comparing the
  # stored epoch time on every strongly-consistent read, never by item deletion.
  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name      = "hospital-dr-dump-restore-lease"
    Purpose   = "Dump restore and scheduled shutdown arbitration"
    DataClass = "OperationalStateAndAudit"
  }
}

resource "aws_iam_role" "dump_restore_lease_controller" {
  count = var.enable_dump_restore_lease_store ? 1 : 0
  name  = "hospital-dr-dump-restore-lease-controller"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.dump_restore_lease_controller_principal_arns }
    }]
  })
}

resource "aws_iam_role_policy" "dump_restore_lease_controller" {
  count = var.enable_dump_restore_lease_store ? 1 : 0
  name  = "hospital-dr-dump-restore-lease-controller-policy"
  role  = aws_iam_role.dump_restore_lease_controller[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem"]
      Resource = aws_dynamodb_table.dump_restore_lease[0].arn
      Condition = {
        "ForAllValues:StringEquals" = {
          "dynamodb:LeadingKeys" = ["HOSPITAL_DR#DUMP_RESTORE", "HOSPITAL_DR#DUMP_RESTORE_AUDIT"]
        }
      }
      }, {
      Effect   = "Allow"
      Action   = ["dynamodb:UpdateItem"]
      Resource = aws_dynamodb_table.dump_restore_lease[0].arn
      Condition = {
        "ForAllValues:StringEquals" = {
          "dynamodb:LeadingKeys" = ["HOSPITAL_DR#DUMP_RESTORE"]
        }
        "ForAnyValue:StringEquals" = {
          "dynamodb:EnclosingOperation" = ["TransactWriteItems"]
        }
      }
      }, {
      Effect   = "Allow"
      Action   = ["dynamodb:PutItem"]
      Resource = aws_dynamodb_table.dump_restore_lease[0].arn
      Condition = {
        "ForAllValues:StringEquals" = {
          "dynamodb:LeadingKeys" = ["HOSPITAL_DR#DUMP_RESTORE_AUDIT"]
        }
        "ForAnyValue:StringEquals" = {
          "dynamodb:EnclosingOperation" = ["TransactWriteItems"]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "dump_restore_lease_cost_guard" {
  count = var.enable_dump_restore_lease_store ? 1 : 0
  name  = "hospital-dr-dump-restore-lease-cost-guard-policy"
  role  = aws_iam_role.dr_cost_guard.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem"]
      Resource = aws_dynamodb_table.dump_restore_lease[0].arn
      Condition = {
        "ForAllValues:StringEquals" = {
          "dynamodb:LeadingKeys" = ["HOSPITAL_DR#DUMP_RESTORE", "HOSPITAL_DR#DUMP_RESTORE_AUDIT"]
        }
      }
      }, {
      Effect   = "Allow"
      Action   = ["dynamodb:UpdateItem"]
      Resource = aws_dynamodb_table.dump_restore_lease[0].arn
      Condition = {
        "ForAllValues:StringEquals" = {
          "dynamodb:LeadingKeys" = ["HOSPITAL_DR#DUMP_RESTORE"]
        }
        "ForAnyValue:StringEquals" = {
          "dynamodb:EnclosingOperation" = ["TransactWriteItems"]
        }
      }
      }, {
      Effect   = "Allow"
      Action   = ["dynamodb:PutItem"]
      Resource = aws_dynamodb_table.dump_restore_lease[0].arn
      Condition = {
        "ForAllValues:StringEquals" = {
          "dynamodb:LeadingKeys" = ["HOSPITAL_DR#DUMP_RESTORE_AUDIT"]
        }
        "ForAnyValue:StringEquals" = {
          "dynamodb:EnclosingOperation" = ["TransactWriteItems"]
        }
      }
    }]
  })
}

resource "aws_cloudwatch_log_group" "dr_cost_guard" {
  name              = "/aws/lambda/hospital-dr-cost-guard"
  retention_in_days = 7
}

resource "aws_lambda_function" "dr_cost_guard" {
  function_name    = "hospital-dr-cost-guard"
  role             = aws_iam_role.dr_cost_guard.arn
  handler          = "dr_cost_guard.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.dr_cost_guard.output_path
  source_code_hash = data.archive_file.dr_cost_guard.output_base64sha256
  timeout          = 60
  memory_size      = 128

  environment {
    variables = {
      INSTANCE_NAMES = "Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server"
      INSTANCE_ID_MAP = jsonencode({
        web = aws_instance.hospital_real_web.id
        doc = aws_instance.doc_server.id
        db  = aws_instance.db_server.id
      })
      CF_TOKEN_PARAM_NAME = "/hospital-dr/cloudflare/api-token"
      CF_ZONE_ID          = var.cloudflare_zone_id
      CF_RECORD_ID        = cloudflare_record.hospital_web.id
      CF_EMR_RECORD_ID    = cloudflare_record.hospital_emr.id
      CF_DOMAIN           = "hospital-web.pp.ua"
      CF_EMR_DOMAIN       = "emr.hospital-web.pp.ua"
      DR_ORIGIN_IP        = local.web_public_endpoint
      ONPREM_TUNNEL_HOST  = "e6d3babc-8da8-45b4-85a3-a674302785fc.cfargotunnel.com"
      ONPREM_EMR_DNS_IP   = var.onprem_web_public_ip
      NAT_EIP_NAME        = "Hospital-DR-NAT-EIP"
      NAT_EIP_PURPOSE     = "MySQL-NR-Egress"
    }
  }

  depends_on = [
    aws_iam_role_policy.dr_cost_guard,
    aws_cloudwatch_log_group.dr_cost_guard
  ]
}

resource "aws_cloudwatch_event_rule" "dr_cost_guard_shutdown" {
  count               = var.cost_guard_enabled ? 1 : 0
  name                = "hospital-dr-daily-safety-shutdown"
  description         = "Check and return Hospital DR DNS every day at 19:00 KST; EC2 lifecycle is operator-managed"
  schedule_expression = "cron(0 10 * * ? *)"
}

resource "aws_cloudwatch_event_target" "dr_cost_guard_shutdown" {
  count     = var.cost_guard_enabled ? 1 : 0
  rule      = aws_cloudwatch_event_rule.dr_cost_guard_shutdown[0].name
  target_id = "HospitalDRCostGuardShutdown"
  arn       = aws_lambda_function.dr_cost_guard.arn
  input     = jsonencode({ action = "shutdown" })
}

resource "aws_lambda_permission" "dr_cost_guard_shutdown" {
  count         = var.cost_guard_enabled ? 1 : 0
  statement_id  = "AllowEventBridgeShutdown"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dr_cost_guard.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.dr_cost_guard_shutdown[0].arn
}
