#!/usr/bin/env bash
set -euo pipefail

export DR_REPO_ROOT="${DR_REPO_ROOT:-/home/cloud/hospital-dr-codex}"
export DR_TERRAFORM_DIR="${DR_TERRAFORM_DIR:-/home/cloud/hospital-dr-terraform}"
export DR_ANSIBLE_DIR="${DR_ANSIBLE_DIR:-/home/cloud/hospital-dr-ansible}"
export DR_OPERATIONS_DIR="${DR_OPERATIONS_DIR:-$DR_REPO_ROOT/operations}"
export DR_LOG_DIR="${DR_LOG_DIR:-/home/cloud/hospital-dr-terraform}"
export DR_SECRET_FILE="${DR_SECRET_FILE:-/home/cloud/hospital-dr-secrets/dr.env}"

exec bash "$DR_OPERATIONS_DIR/db/db_failback_to_onprem.sh" "$@"
