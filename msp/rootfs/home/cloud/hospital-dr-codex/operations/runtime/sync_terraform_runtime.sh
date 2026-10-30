#!/usr/bin/env bash
set -euo pipefail

# Safely synchronize only canonical Terraform module inputs into the existing
# operational Terraform directory.  State, tfvars, provider data, plans,
# secrets, logs, and generated artifacts are never copied or removed.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"

case "${1:---check}" in
  --check|--apply) MODE="$1" ;;
  *)
    echo "Usage: $0 [--check|--apply]" >&2
    exit 2
    ;;
esac

CANONICAL_TF_DIR="${DR_CANONICAL_TERRAFORM_DIR:-$DR_REPO_ROOT/infra/terraform}"
RUNTIME_TF_DIR="${DR_TERRAFORM_RUNTIME_DIR:-/home/cloud/hospital-dr-terraform}"
BACKUP_ROOT="${DR_TERRAFORM_SYNC_BACKUP_DIR:-$DR_STATE_DIR/terraform-sync-backups}"

SYNC_FILES=(
  main.tf
  github_oidc.tf
  iam_least_privilege_candidates.tf
  .terraform.lock.hcl
  lambda/dr_cost_guard.py
  iam-policies/HospitalDRSecretReadPolicy.json
  iam-policies/HospitalDRTerraformIAMPolicy.json
  iam-policies/HospitalDRTerraformProvisionerPolicy.json
  iam-policies/HospitalDRTerraformServerlessPolicy.json
)

for relative_path in "${SYNC_FILES[@]}"; do
  case "$relative_path" in
    terraform.tfstate|terraform.tfstate.*|*.tfvars|*.auto.tfvars|.terraform/*|*.tfplan|*.plan)
      echo "[TF SYNC ERROR] Unsafe path entered the sync manifest: $relative_path" >&2
      exit 1
      ;;
  esac
done

if [ ! -d "$CANONICAL_TF_DIR" ]; then
  echo "[TF SYNC ERROR] Canonical Terraform directory is missing: $CANONICAL_TF_DIR" >&2
  exit 1
fi
if [ ! -d "$RUNTIME_TF_DIR" ]; then
  echo "[TF SYNC ERROR] Operational Terraform directory is missing: $RUNTIME_TF_DIR" >&2
  exit 1
fi
if [ ! -r "$RUNTIME_TF_DIR/terraform.tfstate" ]; then
  echo "[TF SYNC ERROR] Existing Terraform state is missing or unreadable: $RUNTIME_TF_DIR/terraform.tfstate" >&2
  exit 1
fi

drift_count=0
changed_count=0

report_or_sync() {
  local relative_path="$1"
  local source_path="$CANONICAL_TF_DIR/$relative_path"
  local target_path="$RUNTIME_TF_DIR/$relative_path"
  local target_dir target_mode temporary backup_path

  if [ ! -f "$source_path" ]; then
    echo "[TF SYNC ERROR] Canonical sync input is missing: $source_path" >&2
    exit 1
  fi

  if [ -f "$target_path" ] && cmp -s "$source_path" "$target_path"; then
    echo "[TF SYNC MATCH] $relative_path"
    return 0
  fi

  drift_count=$((drift_count + 1))
  if [ "$MODE" = "--check" ]; then
    if [ -f "$target_path" ]; then
      echo "[TF SYNC DRIFT] different: $target_path"
    else
      echo "[TF SYNC DRIFT] missing: $target_path"
    fi
    return 0
  fi

  target_dir="$(dirname -- "$target_path")"
  mkdir -p "$target_dir"
  mkdir -p "$BACKUP_ROOT/$(dirname -- "$relative_path")"
  if [ -f "$target_path" ]; then
    backup_path="$BACKUP_ROOT/$relative_path"
    cp -p -- "$target_path" "$backup_path"
    echo "[TF SYNC BACKUP] $relative_path"
  fi

  target_mode="$(stat -c '%a' "$target_path" 2>/dev/null || stat -c '%a' "$source_path")"
  temporary="$(mktemp "$target_dir/.codex-sync.XXXXXX")"
  trap 'rm -f -- "${temporary:-}"' RETURN
  cp -- "$source_path" "$temporary"
  chmod "$target_mode" "$temporary"
  mv -f -- "$temporary" "$target_path"
  trap - RETURN
  changed_count=$((changed_count + 1))
  echo "[TF SYNC APPLY] $relative_path"
}

echo "[TF SYNC] mode=$MODE"
echo "[TF SYNC] canonical=$CANONICAL_TF_DIR"
echo "[TF SYNC] runtime=$RUNTIME_TF_DIR"
echo "[TF SYNC] state preserved=$RUNTIME_TF_DIR/terraform.tfstate"

if [ "$MODE" = "--apply" ]; then
  mkdir -p "$BACKUP_ROOT"
  chmod 0700 "$BACKUP_ROOT"
fi

for relative_path in "${SYNC_FILES[@]}"; do
  report_or_sync "$relative_path"
done

if [ "$MODE" = "--check" ]; then
  if [ "$drift_count" -ne 0 ]; then
    printf 'TERRAFORM_SOURCE_READY=false\n'
    printf '[TF SYNC] drift_or_missing=%s\n' "$drift_count"
    exit 1
  fi
  printf 'TERRAFORM_SOURCE_READY=true\n'
  echo "[TF SYNC] no canonical Terraform source drift found."
  exit 0
fi

if [ "$changed_count" -ne 0 ]; then
  export AWS_EC2_METADATA_DISABLED="${AWS_EC2_METADATA_DISABLED:-true}"
  terraform -chdir="$RUNTIME_TF_DIR" fmt -check -recursive
  terraform -chdir="$RUNTIME_TF_DIR" init -backend=false -input=false -lockfile=readonly -no-color
  terraform -chdir="$RUNTIME_TF_DIR" validate -no-color
  terraform -chdir="$RUNTIME_TF_DIR" state list >/dev/null
fi

printf 'TERRAFORM_SOURCE_READY=true\n'
printf '[TF SYNC] changed=%s; operational state was preserved.\n' "$changed_count"
