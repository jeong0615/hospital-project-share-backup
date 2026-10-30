variable "region" {
  type    = string
  default = "ap-northeast-2"
  validation {
    condition     = var.region == "ap-northeast-2"
    error_message = "The synthetic Probe is pinned to ap-northeast-2."
  }
}

variable "expected_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be an explicit 12-digit AWS account ID."
  }
}

variable "enable_probe" {
  type        = bool
  default     = false
  description = "No resources are created unless explicitly enabled with the exact confirmation."
}

variable "confirmation" {
  type    = string
  default = ""
  validation {
    condition     = !var.enable_probe || var.confirmation == "CREATE_SYNTHETIC_NAT_PROBE"
    error_message = "Set confirmation=CREATE_SYNTHETIC_NAT_PROBE only for an approved deployment."
  }
}

variable "run_id" {
  type    = string
  default = ""
  validation {
    condition     = !var.enable_probe || can(regex("^[a-z0-9][a-z0-9-]{7,31}$", var.run_id))
    error_message = "When enabled, run_id must contain 8-32 lowercase letters, digits, or hyphens."
  }
}

variable "availability_zone" {
  type    = string
  default = ""
  validation {
    condition     = !var.enable_probe || trimspace(var.availability_zone) != ""
    error_message = "An explicit single Availability Zone is required when enabled."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "IP_REDACTED/16"
  validation {
    condition     = !var.enable_probe || (can(cidrhost(var.vpc_cidr, 0)) && !strcontains(var.vpc_cidr, ":"))
    error_message = "vpc_cidr must be an explicit IPv4 CIDR."
  }
}

variable "subnet_cidr" {
  type    = string
  default = "IP_REDACTED/24"
  validation {
    condition     = !var.enable_probe || (can(cidrhost(var.subnet_cidr, 0)) && !strcontains(var.subnet_cidr, ":"))
    error_message = "subnet_cidr must be an explicit IPv4 CIDR."
  }
}

variable "probe_private_ip" {
  type    = string
  default = "IP_REDACTED"
  validation {
    condition     = !var.enable_probe || can(cidrhost("${var.probe_private_ip}/32", 0))
    error_message = "probe_private_ip must be an explicit IPv4 address."
  }
}

variable "synthetic_ami_id" {
  type        = string
  default     = "AWS_RESOURCE_ID_REDACTED"
  description = "Pin an Amazon-owned AL2023 AMI after read-only provenance verification in ap-northeast-2."
  validation {
    condition     = !var.enable_probe || var.synthetic_ami_id == "AWS_RESOURCE_ID_REDACTED"
    error_message = "The Probe must use the approved pinned Amazon Linux 2023 x86_64 AMI."
  }
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
  validation {
    condition     = var.instance_type == "t3.micro"
    error_message = "The probe is intentionally limited to t3.micro."
  }
}

variable "root_volume_size_gib" {
  type    = number
  default = 8
  validation {
    condition     = var.root_volume_size_gib == 8
    error_message = "The probe root volume is fixed at 8 GiB."
  }
}

variable "probe_domain" {
  type    = string
  default = "nat-probe.hospital-web.pp.ua"
  validation {
    condition     = !var.enable_probe || var.probe_domain == "nat-probe.hospital-web.pp.ua"
    error_message = "The Probe hostname must be nat-probe.hospital-web.pp.ua."
  }
}

variable "certificate_parameter_name" {
  type    = string
  default = ""
  validation {
    condition     = !var.enable_probe || can(regex("^/hospital-dr/synthetic-nat-probe/[a-z0-9][a-z0-9-]{7,31}/fullchain$", var.certificate_parameter_name))
    error_message = "Use the exact Run-ID-scoped SecureString fullchain parameter path."
  }
}

variable "private_key_parameter_name" {
  type    = string
  default = ""
  validation {
    condition     = !var.enable_probe || can(regex("^/hospital-dr/synthetic-nat-probe/[a-z0-9][a-z0-9-]{7,31}/privkey$", var.private_key_parameter_name))
    error_message = "Use the exact Run-ID-scoped SecureString private-key parameter path."
  }
}

variable "kms_key_arn" {
  type    = string
  default = ""
  validation {
    condition     = !var.enable_probe || can(regex("^arn:aws:kms:ap-northeast-2:${var.expected_account_id}:key/[0-9a-f-]{36}$", var.kms_key_arn))
    error_message = "Provide an existing customer-managed KMS key ARN in expected_account_id and ap-northeast-2."
  }
}

variable "allowed_web_eip_ipv4" {
  type        = string
  default     = "DISABLED"
  description = "Keep DISABLED until the Synthetic NAT stack has returned its Web EIP. Otherwise set exactly that IPv4/32."
  validation {
    condition     = var.allowed_web_eip_ipv4 == "DISABLED" || (can(regex("/32$", var.allowed_web_eip_ipv4)) && can(cidrhost(var.allowed_web_eip_ipv4, 0)) && !strcontains(var.allowed_web_eip_ipv4, ":"))
    error_message = "allowed_web_eip_ipv4 must be DISABLED or one IPv4 /32."
  }
}
