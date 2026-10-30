variable "region" {
  description = "Region dedicated to the synthetic test stack."
  type        = string
  default     = "ap-northeast-2"
  validation {
    condition     = var.region == "ap-northeast-2"
    error_message = "The synthetic Canary is pinned to ap-northeast-2."
  }
}

variable "expected_account_id" {
  description = "Explicit AWS account allowlist. No resources can be planned in another account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be a 12-digit AWS account ID."
  }
}

variable "enable_canary" {
  description = "Must be explicitly enabled for a separately approved synthetic stack deployment."
  type        = bool
  default     = false
}

variable "confirmation" {
  description = "Exact deployment confirmation; required only when enable_canary is true."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_canary || var.confirmation == "CREATE_SYNTHETIC_NAT_CANARY"
    error_message = "Enabling this stack requires confirmation=CREATE_SYNTHETIC_NAT_CANARY."
  }
}

variable "run_id" {
  description = "Unique lower-case Run ID used on every taggable resource."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_canary || can(regex("^[a-z0-9][a-z0-9-]{7,31}$", var.run_id))
    error_message = "When enabled, run_id must be 8-32 lowercase letters, digits, or hyphens."
  }
}

variable "availability_zone" {
  description = "One AZ in region; one subnet per tier keeps endpoint cost to one ENI per service."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_canary || trimspace(var.availability_zone) != ""
    error_message = "availability_zone is required when the stack is enabled."
  }
}

variable "vpc_cidr" {
  description = "New, non-overlapping synthetic VPC CIDR; must not be an existing production range."
  type        = string
  default     = ""
}

variable "public_subnet_cidr" {
  description = "Synthetic Web/NAT public subnet CIDR."
  type        = string
  default     = ""
}

variable "private_subnet_cidr" {
  description = "Synthetic EMR/SSM endpoint private subnet CIDR."
  type        = string
  default     = ""
}

variable "web_private_ip" {
  description = "Explicit private IPv4 for the synthetic Web/NAT host."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_canary || can(cidrhost("${var.web_private_ip}/32", 0))
    error_message = "web_private_ip must be an IPv4 address."
  }
}

variable "emr_private_ip" {
  description = "Explicit private IPv4 for the synthetic EMR probe host."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_canary || can(cidrhost("${var.emr_private_ip}/32", 0))
    error_message = "emr_private_ip must be an IPv4 address."
  }
}

variable "synthetic_ami_id" {
  description = "Pinned AWS-published AL2023 x86_64 AMI ID; Terraform verifies Amazon owner, public/available state, HVM and EBS root. Refresh and inspect in ap-northeast-2 before approval."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_canary || var.synthetic_ami_id == "AWS_RESOURCE_ID_REDACTED"
    error_message = "The Canary must use the approved pinned Amazon Linux 2023 x86_64 AMI."
  }
}

variable "probe_ipv4" {
  description = "Operator-verified IPv4 of the approved HTTPS egress-IP echo probe."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_canary || can(cidrhost("${var.probe_ipv4}/32", 0))
    error_message = "probe_ipv4 must be an explicitly verified IPv4 address."
  }
}

variable "probe_domain" {
  description = "Exact DNS name of the approved HTTPS egress-IP echo probe."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_canary || var.probe_domain == "nat-probe.hospital-web.pp.ua"
    error_message = "probe_domain must be nat-probe.hospital-web.pp.ua."
  }
}

variable "instance_type" {
  description = "Small synthetic-only instance type."
  type        = string
  default     = "t3.micro"
}

variable "root_volume_size_gib" {
  description = "Encrypted, delete-on-termination root volume size."
  type        = number
  default     = 8
  validation {
    condition     = var.root_volume_size_gib >= 8 && var.root_volume_size_gib <= 30
    error_message = "Synthetic root volumes must be between 8 and 30 GiB."
  }
}

variable "enable_ec2messages_endpoint" {
  description = "Enable only if the approved AMI's SSM Agent version requires the legacy ec2messages channel."
  type        = bool
  default     = false
}
