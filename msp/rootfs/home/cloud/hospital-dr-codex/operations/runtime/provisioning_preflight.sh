#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"
# shellcheck disable=SC1091
source "$DR_STATE_HELPER"

CHECK_ECR=true
case "${1:-}" in
  "") ;;
  --skip-ecr) CHECK_ECR=false ;;
  *)
    echo "Usage: $0 [--skip-ecr]" >&2
    exit 2
    ;;
esac

SECRET_FILE="$DR_SECRET_FILE"
SECRET_CONFIG_READY=false
OPTIONAL_SECRET_FILE_ERROR=""
if [ -f "$SECRET_FILE" ] && [ -r "$SECRET_FILE" ]; then
  if dr_load_secret_file; then
    SECRET_CONFIG_READY=true
  fi
elif [ -e "$SECRET_FILE" ]; then
  OPTIONAL_SECRET_FILE_ERROR="DR_SECRET_FILE exists but is unreadable"
fi
if [ -n "${DR_PROVISIONING_SECRET_FILE:-}" ] && [ "${DR_PROVISIONING_SECRET_FILE}" != "$SECRET_FILE" ]; then
  if [ ! -f "$DR_PROVISIONING_SECRET_FILE" ]; then
    OPTIONAL_SECRET_FILE_ERROR="DR_PROVISIONING_SECRET_FILE does not exist: $DR_PROVISIONING_SECRET_FILE"
  else
    # shellcheck disable=SC1090
    source "$DR_PROVISIONING_SECRET_FILE"
  fi
fi

DR_SSH_PRIVATE_KEY="${DR_SSH_PRIVATE_KEY:-${SSH_KEY:-${DR_SSH_KEY:-}}}"
DR_IMAGE_TAG="${DR_IMAGE_TAG:-$(git -C "$DR_REPO_ROOT" rev-parse HEAD 2>/dev/null || true)}"
AWS_REGION="${AWS_REGION:-ap-northeast-2}"
INVENTORY="${INVENTORY:-$DR_ANSIBLE_DIR/inventory.ini}"
CANONICAL_TF_DIR="${DR_CANONICAL_TERRAFORM_DIR:-$DR_REPO_ROOT/infra/terraform}"
TF_PUBLIC_KEY="${TF_VAR_ssh_public_key_path:-${DR_SSH_PRIVATE_KEY}.pub}"
MANAGEMENT_IPV4_CIDRS="${TF_VAR_management_ipv4_cidrs:-${DR_MANAGEMENT_IPV4_CIDRS:-}}"
RUNTIME_DRIFT_CHECK="${RUNTIME_DRIFT_CHECK:-true}"
RUNTIME_DRIFT_HELPER="$SCRIPT_DIR/runtime_drift_check.sh"
TERRAFORM_RUNTIME_DIR="${DR_TERRAFORM_RUNTIME_DIR:-/home/cloud/hospital-dr-terraform}"
TERRAFORM_SOURCE_HELPER="$SCRIPT_DIR/sync_terraform_runtime.sh"
TERRAFORM_DRIFT_HELPER="$SCRIPT_DIR/terraform_drift_check.sh"
TERRAFORM_DRIFT_PLAN_JSON="${DR_TERRAFORM_PLAN_JSON:-}"
GITHUB_ACTIONS_READY="${GITHUB_ACTIONS_READY:-UNVERIFIED}"

failures=0
needs_input=0
prepared=true
secrets_ready=true
runtime_source_ready=true
terraform_source_ready=true
terraform_state_ready=true
ecr_images_ready=true
ssh_ready=true
fresh_host_ready=true
tls_status="NEEDS_AWS_INSPECTION"
terraform_drift_status="NOT_REQUESTED"

pass_check() {
  printf '[PREFLIGHT PASS] %s\n' "$1"
}

warn_check() {
  printf '[PREFLIGHT WARN] %s\n' "$1"
}

fail_check() {
  printf '[PREFLIGHT BLOCKED] %s\n' "$1"
  failures=$((failures + 1))
  prepared=false
}

input_check() {
  printf '[PREFLIGHT NEEDS_INPUT] %s\n' "$1"
  needs_input=$((needs_input + 1))
}

require_value() {
  local name="$1"
  if [ -n "${!name:-}" ]; then
    pass_check "$name is supplied."
  else
    fail_check "$name is missing from the external provisioning configuration."
    secrets_ready=false
  fi
}

require_readable_file() {
  local label="$1"
  local path="$2"
  if [ -n "$path" ] && [ -r "$path" ]; then
    pass_check "$label is readable: $path"
  else
    fail_check "$label is not readable: ${path:-<unset>}"
  fi
}

require_nonempty_regular_file() {
  local label="$1"
  local path="$2"
  if [ -n "$path" ] && [ -f "$path" ] && [ -s "$path" ] && [ -r "$path" ]; then
    pass_check "$label is a readable non-empty file: $path"
  else
    fail_check "$label is not a readable non-empty file: ${path:-<unset>}"
  fi
}

check_secret_mode() {
  local label="$1"
  local path="$2"
  local secret_mode
  if [ -f "$path" ]; then
    secret_mode="$(stat -c '%a' "$path" 2>/dev/null || true)"
    if [ "$secret_mode" != "600" ] && [ "$secret_mode" != "640" ]; then
      secrets_ready=false
      fail_check "$label must use mode 0600 or 0640; current mode is ${secret_mode:-unknown}."
    fi
  fi
}

if [ -n "$OPTIONAL_SECRET_FILE_ERROR" ]; then
  fail_check "$OPTIONAL_SECRET_FILE_ERROR"
fi
check_secret_mode "DR_SECRET_FILE" "$SECRET_FILE"
if [ -n "${DR_PROVISIONING_SECRET_FILE:-}" ] && [ "$DR_PROVISIONING_SECRET_FILE" != "$SECRET_FILE" ]; then
  check_secret_mode "DR_PROVISIONING_SECRET_FILE" "$DR_PROVISIONING_SECRET_FILE"
fi

echo "[PREFLIGHT] Read-only DR provisioning checks started."
echo "[PREFLIGHT] Secret values are never printed."

if [ "$SECRET_CONFIG_READY" != "true" ]; then
  fail_check "DR_SECRET_FILE is missing or unreadable."
elif ! dr_resolve_ssh_key_config; then
  fail_check "SSH_KEY is missing from DR_SECRET_FILE."
elif ! dr_validate_ssh_key_files; then
  fail_check "SSH private/public key path is missing or unreadable."
fi

if [ "$GITHUB_ACTIONS_READY" = "true" ]; then
  pass_check "GitHub Actions quality gate was externally confirmed."
else
  input_check "GITHUB_ACTIONS_READY is not confirmed; remote quality validation is required."
fi

require_value AWS_REGION
if [ "$AWS_REGION" = "ap-northeast-2" ]; then
  pass_check "AWS_REGION is ap-northeast-2."
else
  fail_check "AWS_REGION must be ap-northeast-2 for this DR environment."
fi

if [[ "$DR_IMAGE_TAG" =~ ^[0-9a-fA-F]{40}$ ]]; then
  pass_check "DR_IMAGE_TAG is an immutable 40-character commit SHA: $DR_IMAGE_TAG"
else
  fail_check "DR_IMAGE_TAG must be an immutable 40-character commit SHA."
fi

require_readable_file "DR_SSH_PRIVATE_KEY" "$DR_SSH_PRIVATE_KEY"
if [ -n "$DR_SSH_PRIVATE_KEY" ]; then
  key_mode="$(stat -c '%a' "$DR_SSH_PRIVATE_KEY" 2>/dev/null || true)"
  if [ "$key_mode" = "600" ] || [ "$key_mode" = "400" ]; then
    pass_check "DR_SSH_PRIVATE_KEY has a private-key-safe mode: $key_mode"
  else
    ssh_ready=false
    fail_check "DR_SSH_PRIVATE_KEY must use mode 0600 or 0400; current mode is ${key_mode:-unknown}."
  fi
else
  ssh_ready=false
fi
require_readable_file "SSH public key" "$TF_PUBLIC_KEY"
if [ ! -r "$TF_PUBLIC_KEY" ]; then
  ssh_ready=false
fi
if [ -n "$MANAGEMENT_IPV4_CIDRS" ]; then
  pass_check "External management IPv4 CIDRs are supplied for the Web SG."
else
  fail_check "TF_VAR_management_ipv4_cidrs or DR_MANAGEMENT_IPV4_CIDRS is required; no TEST-NET or implicit management CIDR is used."
fi

if [ -d "$DR_STATE_DIR" ] && [ -w "$DR_STATE_DIR" ]; then
  pass_check "Persistent runtime directory is writable: $DR_STATE_DIR"
else
  fail_check "Persistent runtime directory is missing or not writable: $DR_STATE_DIR"
fi

if [ -d "$CANONICAL_TF_DIR" ]; then
  pass_check "Canonical Terraform source directory is present: $CANONICAL_TF_DIR"
else
  fail_check "Canonical Terraform source path is not ready: $CANONICAL_TF_DIR"
  terraform_state_ready=false
fi
if [ -d "$TERRAFORM_RUNTIME_DIR" ] && [ -r "$TERRAFORM_RUNTIME_DIR/terraform.tfstate" ]; then
  pass_check "Operational Terraform directory and existing state are present: $TERRAFORM_RUNTIME_DIR"
else
  fail_check "Operational Terraform runtime/state path is not ready: $TERRAFORM_RUNTIME_DIR"
  terraform_state_ready=false
fi
if [ -x "$TERRAFORM_SOURCE_HELPER" ] \
    && DR_REPO_ROOT="$DR_REPO_ROOT" \
       DR_CANONICAL_TERRAFORM_DIR="$CANONICAL_TF_DIR" \
       DR_TERRAFORM_RUNTIME_DIR="$TERRAFORM_RUNTIME_DIR" \
       DR_STATE_DIR="$DR_STATE_DIR" \
       "$TERRAFORM_SOURCE_HELPER" --check; then
  pass_check "Canonical Terraform source matches the operational state runtime."
else
  terraform_source_ready=false
  fail_check "Canonical Terraform source drift or missing runtime inputs detected."
fi

if [ -n "$TERRAFORM_DRIFT_PLAN_JSON" ]; then
  if [ ! -x "$TERRAFORM_DRIFT_HELPER" ]; then
    terraform_drift_status="BLOCKED"
    fail_check "Terraform drift classifier is missing or not executable: $TERRAFORM_DRIFT_HELPER"
  elif [ ! -r "$TERRAFORM_DRIFT_PLAN_JSON" ]; then
    terraform_drift_status="BLOCKED"
    fail_check "DR_TERRAFORM_PLAN_JSON is missing or unreadable: $TERRAFORM_DRIFT_PLAN_JSON"
  else
    drift_report=""
    drift_rc=0
    drift_report="$($TERRAFORM_DRIFT_HELPER --plan-json "$TERRAFORM_DRIFT_PLAN_JSON" 2>&1)" || drift_rc=$?
    printf '%s\n' "$drift_report"
    if [ "$drift_rc" -eq 0 ]; then
      terraform_drift_status="READY"
      pass_check "Terraform plan contains no resource drift."
    else
      terraform_drift_status="BLOCKED"
      fail_check "Terraform drift requires explicit reconciliation; no automatic apply is authorized."
    fi
  fi
else
  echo "[PREFLIGHT] Terraform drift classifier not requested; set DR_TERRAFORM_PLAN_JSON to a terraform show -json output."
fi

if [ -f "$INVENTORY" ]; then
  if grep -Fqx '[web_servers]' "$INVENTORY" \
      && grep -Fqx '[doc_servers]' "$INVENTORY" \
      && grep -Fqx '[db_servers]' "$INVENTORY"; then
    pass_check "Ansible inventory contains Web, EMR, and DB groups: $INVENTORY"
  else
    fail_check "Ansible inventory is missing one or more required host groups: $INVENTORY"
  fi
  while IFS= read -r inventory_key; do
    if [ -n "$inventory_key" ] && [ ! -r "$inventory_key" ]; then
      warn_check "Existing inventory has a stale key path and must be regenerated before Ansible: $inventory_key"
    fi
  done < <(grep -oE 'ansible_ssh_private_key_file=[^[:space:]]+' "$INVENTORY" | cut -d= -f2)
else
  warn_check "Inventory will be generated by the DR lifecycle entry point before Ansible: $INVENTORY"
fi

if [ -n "${CF_ZONE_ID:-}" ] && [[ "$CF_ZONE_ID" =~ ^[0-9a-fA-F]{32}$ ]]; then
  pass_check "CF_ZONE_ID has the required external 32-character format."
else
  fail_check "CF_ZONE_ID is missing or invalid in the external runtime configuration."
fi

if [ "$RUNTIME_DRIFT_CHECK" = "true" ]; then
  if [ -x "$RUNTIME_DRIFT_HELPER" ] && "$RUNTIME_DRIFT_HELPER" --check; then
    runtime_source_ready=true
    pass_check "Canonical/runtime source manifests match."
  else
    runtime_source_ready=false
    fail_check "Canonical/runtime source drift or missing installed files detected."
  fi
else
  runtime_source_ready=false
  fail_check "Runtime source drift check was disabled; runtime readiness cannot be proven."
fi

for required_secret in MYSQL_ROOT_PASS WEB_DB_PASSWORD DOC_DB_PASSWORD SESSION_SECRET; do
  require_value "$required_secret"
done

if [ "${DB_ALLOW_EXISTING_DATA:-false}" = "true" ]; then
  fresh_host_ready=false
  if [ -n "${DB_BACKUP_ENCRYPTION_KEY:-}" ] || [ -n "${DB_BACKUP_FILE:-}" ]; then
    fail_check "DB_ALLOW_EXISTING_DATA=true cannot be combined with backup restore inputs."
  else
    pass_check "DB_ALLOW_EXISTING_DATA=true protects the existing DR database data."
  fi
else
  if [ -n "${DB_BACKUP_ENCRYPTION_KEY:-}" ] && [ -n "${DB_BACKUP_FILE:-}" ]; then
    if [[ "$DB_BACKUP_FILE" =~ \.sql\.gz\.enc$ ]]; then
      require_nonempty_regular_file "DB_BACKUP_FILE" "$DB_BACKUP_FILE"
      backup_status_file="${DB_BACKUP_FILE%.sql.gz.enc}.master_status"
      require_nonempty_regular_file "Matching DB backup status file" "$backup_status_file"
    else
      fail_check "DB_BACKUP_FILE must use the .sql.gz.enc naming contract."
    fi
  else
    fail_check "DB_ALLOW_EXISTING_DATA=true or a complete DB_BACKUP_ENCRYPTION_KEY/DB_BACKUP_FILE pair is required."
  fi
fi

if [ "${DB_NR_ENABLED:-false}" = "false" ]; then
  pass_check "DB_NR_ENABLED=false; Direct NR is not changed by provisioning."
else
  fail_check "DB_NR_ENABLED must remain false for this preflight/provisioning run."
fi

if [ "${DB_PROMOTE_ON_FAILOVER:-false}" = "false" ]; then
  pass_check "DB_PROMOTE_ON_FAILOVER=false; standby promotion is disabled."
else
  fail_check "DB_PROMOTE_ON_FAILOVER must remain false for this provisioning run."
fi

if [ "$CHECK_ECR" = "true" ]; then
  if ! command -v aws >/dev/null 2>&1; then
    ecr_images_ready=false
    fail_check "AWS CLI is unavailable for the read-only ECR image check."
  elif ! aws sts get-caller-identity >/dev/null 2>&1; then
    ecr_images_ready=false
    fail_check "AWS credentials are unavailable for the read-only ECR image check."
  else
    for repository in hospital-dr-web hospital-dr-emr; do
      image_digest=""
      if image_digest="$(aws ecr describe-images \
        --region "$AWS_REGION" \
        --repository-name "$repository" \
        --image-ids "imageTag=$DR_IMAGE_TAG" \
        --query 'imageDetails[0].imageDigest' \
        --output text 2>/dev/null)" \
        && [ -n "$image_digest" ] \
        && [ "$image_digest" != "None" ]; then
        pass_check "$repository:$DR_IMAGE_TAG exists in ECR ($image_digest)."
      else
        ecr_images_ready=false
        fail_check "$repository:$DR_IMAGE_TAG is not available in ECR."
      fi
    done
  fi
else
  ecr_images_ready=false
  fail_check "ECR checks were explicitly skipped; this is not an AWS-ready result."
fi

if [ -n "${DR_TLS_CERT_FILE:-}" ] && [ -n "${DR_TLS_KEY_FILE:-}" ] \
    && [ -r "$DR_TLS_CERT_FILE" ] && [ -r "$DR_TLS_KEY_FILE" ]; then
  tls_status="READY"
  pass_check "External TLS certificate and key sources are readable."
elif [ "${REQUIRE_PRODUCTION_TLS:-false}" = "true" ]; then
  tls_status="BLOCKED"
  fail_check "Production TLS sources are required but were not supplied."
else
  tls_status="NEEDS_AWS_INSPECTION"
  input_check "Production TLS source is not configured; the current Web role will use its non-production origin-certificate fallback."
fi

if [ -d /opt/hospital-dr ]; then
  pass_check "/opt/hospital-dr exists for installed-runtime consumers."
elif [ "$DR_REPO_ROOT" = "/home/cloud/hospital-dr-codex" ]; then
  pass_check "/opt/hospital-dr is not required when DR_REPO_ROOT points to the canonical repository."
else
  input_check "/opt/hospital-dr is absent and the selected runtime root is not the canonical repository."
fi

if [ "$failures" -ne 0 ] || [ "$needs_input" -ne 0 ]; then
  printf 'GITHUB_ACTIONS_READY=%s\n' "$GITHUB_ACTIONS_READY"
  printf 'ECR_IMAGES_READY=%s\n' "$ecr_images_ready"
  printf 'SSH_READY=%s\n' "$ssh_ready"
  printf 'SECRETS_READY=%s\n' "$secrets_ready"
  printf 'RUNTIME_SOURCE_READY=%s\n' "$runtime_source_ready"
  printf 'TERRAFORM_SOURCE_READY=%s\n' "$terraform_source_ready"
  printf 'TERRAFORM_STATE_READY=%s\n' "$terraform_state_ready"
  printf 'TERRAFORM_DRIFT_CHECK=%s\n' "$terraform_drift_status"
  printf 'FRESH_HOST_READY=false\n'
  printf 'TLS_STATUS=%s\n' "$tls_status"
  printf 'AWS_REPROVISION_E2E_PREPARED=%s\n' "$prepared"
  printf 'AWS_REPROVISION_E2E_READY=false\n'
  printf '[PREFLIGHT] blocked=%s needs_input=%s\n' "$failures" "$needs_input"
  exit 1
fi

printf 'GITHUB_ACTIONS_READY=%s\n' "$GITHUB_ACTIONS_READY"
printf 'ECR_IMAGES_READY=%s\n' "$ecr_images_ready"
printf 'SSH_READY=%s\n' "$ssh_ready"
printf 'SECRETS_READY=%s\n' "$secrets_ready"
printf 'RUNTIME_SOURCE_READY=%s\n' "$runtime_source_ready"
printf 'TERRAFORM_SOURCE_READY=%s\n' "$terraform_source_ready"
printf 'TERRAFORM_STATE_READY=%s\n' "$terraform_state_ready"
printf 'TERRAFORM_DRIFT_CHECK=%s\n' "$terraform_drift_status"
printf 'FRESH_HOST_READY=%s\n' "$fresh_host_ready"
printf 'TLS_STATUS=%s\n' "$tls_status"
printf 'AWS_REPROVISION_E2E_PREPARED=%s\n' "$prepared"
printf 'AWS_REPROVISION_E2E_READY=true\n'
echo "[PREFLIGHT] All read-only provisioning checks passed."
