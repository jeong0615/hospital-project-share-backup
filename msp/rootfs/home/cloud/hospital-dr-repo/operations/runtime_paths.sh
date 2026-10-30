#!/usr/bin/env bash

# Resolve repository-local paths while allowing an installed deployment to
# override the root without changing the workflow scripts.
_dr_paths_source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DR_REPO_ROOT="${DR_REPO_ROOT:-$(cd -- "$_dr_paths_source_dir/.." && pwd)}"
DR_TERRAFORM_DIR="${DR_TERRAFORM_DIR:-$DR_REPO_ROOT/infra/terraform}"
DR_ANSIBLE_DIR="${DR_ANSIBLE_DIR:-$DR_REPO_ROOT/automation/ansible}"
# Keep generated inventory/config artifacts separate from the canonical playbook source.
DR_ANSIBLE_SOURCE_DIR="${DR_ANSIBLE_SOURCE_DIR:-$DR_REPO_ROOT/automation/ansible}"
# One controller-side key contract.  SSH_KEY and DR_SSH_KEY remain accepted
# as compatibility aliases for existing operators and installed wrappers.
DR_SSH_PRIVATE_KEY="${DR_SSH_PRIVATE_KEY:-${SSH_KEY:-${DR_SSH_KEY:-}}}"
DR_OPERATIONS_DIR="${DR_OPERATIONS_DIR:-$DR_REPO_ROOT/operations}"
DR_DB_DIR="${DR_DB_DIR:-$DR_OPERATIONS_DIR/db}"
DR_FAILOVER_DIR="${DR_FAILOVER_DIR:-$DR_OPERATIONS_DIR/failover}"
DR_FINOPS_DIR="${DR_FINOPS_DIR:-$DR_OPERATIONS_DIR/finops}"
DR_TIMING_SCRIPT="${DR_TIMING_SCRIPT:-$DR_DB_DIR/dr_timing.sh}"
DR_ZBX_SCRIPT="${DR_ZBX_SCRIPT:-$DR_DB_DIR/zbx_send.sh}"
DR_CLOUDFLARE_AUTH_SCRIPT="${DR_CLOUDFLARE_AUTH_SCRIPT:-$DR_OPERATIONS_DIR/cloudflare_ssm_auth.sh}"
DR_LOG_DIR="${DR_LOG_DIR:-$DR_REPO_ROOT/var/log}"

DR_RUNTIME_DIR="${DR_RUNTIME_DIR:-${DR_OPERATIONS_DIR}/runtime}"
DR_STATE_HELPER="${DR_STATE_HELPER:-${DR_RUNTIME_DIR}/dr_state.sh}"
DR_DNS_HELPER="${DR_DNS_HELPER:-${DR_FAILOVER_DIR}/dns_transaction.sh}"

unset _dr_paths_source_dir
