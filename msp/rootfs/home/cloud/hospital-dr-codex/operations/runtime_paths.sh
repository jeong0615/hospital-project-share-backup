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
DR_SECRET_FILE="${DR_SECRET_FILE:-/home/cloud/hospital-dr-secrets/dr.env}"
export DR_SECRET_FILE
DR_STATE_DIR="${DR_STATE_DIR:-/var/lib/hospital-dr}"
DR_SSH_KNOWN_HOSTS_FILE="${DR_SSH_KNOWN_HOSTS_FILE:-${DR_STATE_DIR}/ssh/known_hosts}"
# Production provisioning uses the externally managed Cloudflare Origin CA
# pair by default.  Operators must explicitly opt into a non-production
# self-signed fallback instead of silently accepting one on a fresh host.
DR_TLS_CERT_FILE="${DR_TLS_CERT_FILE:-/home/cloud/hospital-dr-secrets/tls/hospital-web.crt}"
DR_TLS_KEY_FILE="${DR_TLS_KEY_FILE:-/home/cloud/hospital-dr-secrets/tls/hospital-web.key}"
REQUIRE_PRODUCTION_TLS="${REQUIRE_PRODUCTION_TLS:-true}"
DR_OPERATIONS_DIR="${DR_OPERATIONS_DIR:-$DR_REPO_ROOT/operations}"
DR_DB_DIR="${DR_DB_DIR:-$DR_OPERATIONS_DIR/db}"
DR_FAILOVER_DIR="${DR_FAILOVER_DIR:-$DR_OPERATIONS_DIR/failover}"
DR_FINOPS_DIR="${DR_FINOPS_DIR:-$DR_OPERATIONS_DIR/finops}"
DR_NAT_DIR="${DR_NAT_DIR:-$DR_OPERATIONS_DIR/nat}"
DR_TIMING_SCRIPT="${DR_TIMING_SCRIPT:-$DR_DB_DIR/dr_timing.sh}"
DR_ZBX_SCRIPT="${DR_ZBX_SCRIPT:-$DR_DB_DIR/zbx_send.sh}"
DR_CLOUDFLARE_AUTH_SCRIPT="${DR_CLOUDFLARE_AUTH_SCRIPT:-$DR_OPERATIONS_DIR/cloudflare_ssm_auth.sh}"
DR_LOG_DIR="${DR_LOG_DIR:-$DR_REPO_ROOT/var/log}"

DR_RUNTIME_DIR="${DR_RUNTIME_DIR:-${DR_OPERATIONS_DIR}/runtime}"
DR_STATE_HELPER="${DR_STATE_HELPER:-${DR_RUNTIME_DIR}/dr_state.sh}"
DR_DNS_HELPER="${DR_DNS_HELPER:-${DR_FAILOVER_DIR}/dns_transaction.sh}"
DR_SSM_SSH_HELPER="${DR_SSM_SSH_HELPER:-${DR_RUNTIME_DIR}/ssm_ssh.sh}"
DR_SSH_CONFIG_FILE="${DR_SSH_CONFIG_FILE:-${DR_STATE_DIR}/ssh/config}"

# Keep host-key verification enabled while allowing a genuinely new DR host
# to be enrolled non-interactively. OpenSSH still rejects a changed key; an
# operator must explicitly rotate that entry when an instance is replaced.
dr_prepare_ssh_known_hosts() {
    local known_hosts_file="${DR_SSH_KNOWN_HOSTS_FILE:-}"
    local known_hosts_dir

    if [ -z "$known_hosts_file" ] || [ "$known_hosts_file" = "/dev/null" ]; then
        echo "[SSH CONFIG ERROR] DR_SSH_KNOWN_HOSTS_FILE must reference a persistent file." >&2
        return 1
    fi

    known_hosts_dir="$(dirname -- "$known_hosts_file")"
    if [ ! -d "$known_hosts_dir" ]; then
        install -d -m 0700 -- "$known_hosts_dir"
    fi
    if [ -e "$known_hosts_file" ] && [ ! -f "$known_hosts_file" ]; then
        echo "[SSH CONFIG ERROR] DR_SSH_KNOWN_HOSTS_FILE is not a regular file: $known_hosts_file" >&2
        return 1
    fi
    if [ ! -e "$known_hosts_file" ]; then
        (umask 077 && touch -- "$known_hosts_file")
    fi
    chmod 0600 -- "$known_hosts_file"
}

# Read the same external configuration file used by ChatOps and its read-only
# preflights. Values remain shell-local unless a workflow explicitly exports
# the small set it needs for its child processes.
dr_load_secret_file() {
    local secret_file="${DR_SECRET_FILE:-/home/cloud/hospital-dr-secrets/dr.env}"
    local exported_name
    local caller_request_id="${DR_FAILOVER_REQUEST_ID-}"
    local caller_request_id_set="${DR_FAILOVER_REQUEST_ID+x}"
    local caller_recovery_mode="${DR_FAILOVER_RECOVERY_MODE-}"
    local caller_recovery_mode_set="${DR_FAILOVER_RECOVERY_MODE+x}"
    local caller_dump_backup_id="${DR_FAILOVER_DUMP_BACKUP_ID-}"
    local caller_dump_backup_id_set="${DR_FAILOVER_DUMP_BACKUP_ID+x}"
    local caller_dump_sha256="${DR_FAILOVER_DUMP_SHA256-}"
    local caller_dump_sha256_set="${DR_FAILOVER_DUMP_SHA256+x}"
    local caller_dump_sidecar_sha256="${DR_FAILOVER_DUMP_SIDECAR_SHA256-}"
    local caller_dump_sidecar_sha256_set="${DR_FAILOVER_DUMP_SIDECAR_SHA256+x}"
    local caller_dump_authorization_id="${DR_FAILOVER_DUMP_AUTHORIZATION_ID-}"
    local caller_dump_authorization_id_set="${DR_FAILOVER_DUMP_AUTHORIZATION_ID+x}"
    local caller_dump_followup_resume="${DR_FAILOVER_DUMP_FOLLOWUP_RESUME-}"
    local caller_dump_followup_resume_set="${DR_FAILOVER_DUMP_FOLLOWUP_RESUME+x}"
    local caller_dump_fallback="${DR_DUMP_FAILOVER_FALLBACK-}"
    local caller_dump_fallback_set="${DR_DUMP_FAILOVER_FALLBACK+x}"
    local caller_dump_fallback_request_id="${DR_DUMP_FALLBACK_REQUEST_ID-}"
    local caller_dump_fallback_request_id_set="${DR_DUMP_FALLBACK_REQUEST_ID+x}"
    local caller_workflow_lock_held="${DR_WORKFLOW_LOCK_HELD-}"
    local caller_workflow_lock_held_set="${DR_WORKFLOW_LOCK_HELD+x}"
    local caller_failover_lock_held="${DR_FAILOVER_LOCK_HELD-}"
    local caller_failover_lock_held_set="${DR_FAILOVER_LOCK_HELD+x}"
    local caller_workflow_lock_file="${DR_WORKFLOW_LOCK_FILE-}"
    local caller_workflow_lock_file_set="${DR_WORKFLOW_LOCK_FILE+x}"
    local caller_failover_lock_file="${DR_FAILOVER_LOCK_FILE-}"
    local caller_failover_lock_file_set="${DR_FAILOVER_LOCK_FILE+x}"
    local -A exported_before=()
    if [ ! -f "$secret_file" ] || [ ! -r "$secret_file" ]; then
        echo "[CONFIG ERROR] DR_SECRET_FILE is missing or unreadable."
        return 1
    fi
    while IFS= read -r exported_name; do
        exported_before["$exported_name"]=1
    done < <(compgen -e)
    if ! source "$secret_file" >/dev/null 2>&1; then
        echo "[CONFIG ERROR] DR_SECRET_FILE could not be loaded."
        return 1
    fi
    # A dr.env line may use `export`; keep its value available to this runner,
    # but remove the export attribute unless it was already part of the
    # caller's process environment. SSH aliases are exported later, explicitly.
    while IFS= read -r exported_name; do
        if [ -z "${exported_before[$exported_name]+present}" ] \
            && [ "$exported_name" != "DR_SECRET_FILE" ]; then
            export -n "$exported_name"
        fi
    done < <(compgen -e)
    # A request-scoped execution ID is supplied by the approved ChatOps
    # child, never by the long-lived secret file. Prevent an old static value
    # in dr.env from replacing the request whose approval launched this run.
    if [ "$caller_request_id_set" = "x" ]; then
        DR_FAILOVER_REQUEST_ID="$caller_request_id"
        export DR_FAILOVER_REQUEST_ID
    else
        unset DR_FAILOVER_REQUEST_ID
    fi
    # Recovery plan inputs are request-scoped ChatOps child values, never
    # static dr.env settings. Preserve the caller's contract or unset stale
    # values loaded from the persistent secret file.
    if [ "$caller_recovery_mode_set" = "x" ]; then
        DR_FAILOVER_RECOVERY_MODE="$caller_recovery_mode"
        export DR_FAILOVER_RECOVERY_MODE
    else
        unset DR_FAILOVER_RECOVERY_MODE
    fi
    if [ "$caller_dump_backup_id_set" = "x" ]; then
        DR_FAILOVER_DUMP_BACKUP_ID="$caller_dump_backup_id"
        export DR_FAILOVER_DUMP_BACKUP_ID
    else
        unset DR_FAILOVER_DUMP_BACKUP_ID
    fi
    if [ "$caller_dump_sha256_set" = "x" ]; then
        DR_FAILOVER_DUMP_SHA256="$caller_dump_sha256"
        export DR_FAILOVER_DUMP_SHA256
    else
        unset DR_FAILOVER_DUMP_SHA256
    fi
    if [ "$caller_dump_sidecar_sha256_set" = "x" ]; then
        DR_FAILOVER_DUMP_SIDECAR_SHA256="$caller_dump_sidecar_sha256"
        export DR_FAILOVER_DUMP_SIDECAR_SHA256
    else
        unset DR_FAILOVER_DUMP_SIDECAR_SHA256
    fi
    if [ "$caller_dump_authorization_id_set" = "x" ]; then
        DR_FAILOVER_DUMP_AUTHORIZATION_ID="$caller_dump_authorization_id"
        export DR_FAILOVER_DUMP_AUTHORIZATION_ID
    else
        unset DR_FAILOVER_DUMP_AUTHORIZATION_ID
    fi
    if [ "$caller_dump_followup_resume_set" = "x" ]; then
        DR_FAILOVER_DUMP_FOLLOWUP_RESUME="$caller_dump_followup_resume"
        export DR_FAILOVER_DUMP_FOLLOWUP_RESUME
    else
        unset DR_FAILOVER_DUMP_FOLLOWUP_RESUME
    fi
    if [ "$caller_dump_fallback_set" = "x" ]; then
        DR_DUMP_FAILOVER_FALLBACK="$caller_dump_fallback"
        export DR_DUMP_FAILOVER_FALLBACK
    else
        unset DR_DUMP_FAILOVER_FALLBACK
    fi
    if [ "$caller_dump_fallback_request_id_set" = "x" ]; then
        DR_DUMP_FALLBACK_REQUEST_ID="$caller_dump_fallback_request_id"
        export DR_DUMP_FALLBACK_REQUEST_ID
    else
        unset DR_DUMP_FALLBACK_REQUEST_ID
    fi
    if [ "$caller_workflow_lock_held_set" = "x" ]; then
        DR_WORKFLOW_LOCK_HELD="$caller_workflow_lock_held"
        export DR_WORKFLOW_LOCK_HELD
    else
        unset DR_WORKFLOW_LOCK_HELD
    fi
    if [ "$caller_failover_lock_held_set" = "x" ]; then
        DR_FAILOVER_LOCK_HELD="$caller_failover_lock_held"
        export DR_FAILOVER_LOCK_HELD
    else
        unset DR_FAILOVER_LOCK_HELD
    fi
    if [ "$caller_workflow_lock_file_set" = "x" ]; then
        DR_WORKFLOW_LOCK_FILE="$caller_workflow_lock_file"
        export DR_WORKFLOW_LOCK_FILE
    else
        unset DR_WORKFLOW_LOCK_FILE
    fi
    if [ "$caller_failover_lock_file_set" = "x" ]; then
        DR_FAILOVER_LOCK_FILE="$caller_failover_lock_file"
        export DR_FAILOVER_LOCK_FILE
    else
        unset DR_FAILOVER_LOCK_FILE
    fi
    DR_SECRET_FILE="$secret_file"
    export DR_SECRET_FILE
}

dr_resolve_ssh_key_config() {
    local ssh_key="${DR_SSH_PRIVATE_KEY:-${SSH_KEY:-${DR_SSH_KEY:-}}}"
    if [ -z "$ssh_key" ]; then
        echo "[CONFIG ERROR] SSH_KEY is missing from DR_SECRET_FILE."
        return 1
    fi
    SSH_KEY="$ssh_key"
    DR_SSH_PRIVATE_KEY="$ssh_key"
    DR_SSH_KEY="$ssh_key"
    TF_VAR_ssh_public_key_path="${TF_VAR_ssh_public_key_path:-${ssh_key}.pub}"
    export SSH_KEY DR_SSH_PRIVATE_KEY DR_SSH_KEY TF_VAR_ssh_public_key_path
}

# Revalidate the current ChatOps request and its approved RPO handling policy at
# the actual Failover boundary. The helper opens SQLite read-only; RPO status is
# reported as advisory while recovery-source validation remains mandatory.
dr_verify_chatops_failover_launch() {
    local request_id="${DR_FAILOVER_REQUEST_ID:-}"
    local state_db="${CHATOPS_STATE_DB:-}"
    local gate="${DR_FAILOVER_DIR:-}/chatops_launch_gate.py"
    local result
    local rpo_status
    local dump_receipt
    local -a gate_args
    if ! [[ "$request_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
        || [ -z "$state_db" ] || [ ! -r "$gate" ] || [ -L "$gate" ] \
        || ! command -v python3 >/dev/null 2>&1; then
        echo "[FAILOVER BLOCKED] Authoritative ChatOps request context is unavailable; no AWS action was started."
        return 1
    fi
    gate_args=(--database "$state_db" --request-id "$request_id")
    if [ "${DR_FAILOVER_DUMP_FOLLOWUP_RESUME:-0}" = "1" ] \
        || [ "${DR_FAILOVER_RECOVERY_MODE:-AUTO}" = "APPROVED_DUMP" ]; then
        if ! [[ "${DR_FAILOVER_DUMP_BACKUP_ID:-}" =~ ^db_backup_[0-9]{8}_[0-9]{4,6}\.sql\.gz\.enc$ ]] \
            || ! [[ "${DR_FAILOVER_DUMP_SHA256:-}" =~ ^[0-9a-fA-F]{64}$ ]]; then
            echo "[FAILOVER BLOCKED] Approved Dump follow-up identity is incomplete; no AWS action was started."
            return 1
        fi
        dump_receipt="${DEMO_DUMP_RESTORE_STATE_DIR:-${DR_STATE_DIR}/demo-dump-restores}/${request_id}/result.json"
        gate_args+=(
            --dump-restore-followup
            --backup-id "${DR_FAILOVER_DUMP_BACKUP_ID}"
            --sha256 "${DR_FAILOVER_DUMP_SHA256,,}"
            --dump-receipt "$dump_receipt"
        )
        if [ "${DR_FAILOVER_DUMP_FOLLOWUP_RESUME:-0}" = "1" ]; then
            gate_args+=(--dump-followup-resume)
        fi
    fi
    if ! result="$(python3 "$gate" "${gate_args[@]}" 2>/dev/null)"; then
        case "$result" in
            "FAILOVER_LAUNCH=BLOCKED reason="*)
                echo "[FAILOVER BLOCKED] ${result#FAILOVER_LAUNCH=BLOCKED }; no AWS action was started."
                ;;
            *)
                echo "[FAILOVER BLOCKED] Authoritative ChatOps approval/RPO verification failed; no AWS action was started."
                ;;
        esac
        return 1
    fi
    case "$result" in
        "FAILOVER_LAUNCH=VERIFIED request_id=$request_id "*)
            rpo_status="${result##* rpo=}"
            case "$rpo_status" in
                WITHIN_900_SECONDS|NOT_MEASURED|EXCEEDED_900_SECONDS) ;;
                *)
                    echo "[FAILOVER BLOCKED] ChatOps RPO status was invalid; no AWS action was started."
                    return 1
                    ;;
            esac
            DR_FAILOVER_RPO_STATUS="$rpo_status"
            export DR_FAILOVER_RPO_STATUS
            echo "[FAILOVER LAUNCH] Server-side two-admin approval and recovery policy verified; RPO=$rpo_status."
            if [ "$rpo_status" = "NOT_MEASURED" ]; then
                echo "[RPO WARNING] RPO=NOT_MEASURED; data loss is possible. The two distinct administrator approvals explicitly accept this risk; usable existing DR DB patient data remains mandatory before promotion."
            elif [ "$rpo_status" = "EXCEEDED_900_SECONDS" ]; then
                echo "[RPO WARNING] RPO exceeds 900 seconds; data loss is possible. The two distinct administrator approvals explicitly accept this risk; usable existing DR DB patient data remains mandatory before promotion."
            fi
            ;;
        *)
            echo "[FAILOVER BLOCKED] ChatOps launch-gate response was invalid; no AWS action was started."
            return 1
            ;;
    esac
}

dr_validate_ssh_key_files() {
    if [ -z "${SSH_KEY:-}" ] || [ ! -r "$SSH_KEY" ]; then
        echo "[CONFIG ERROR] SSH private key is missing or unreadable."
        return 1
    fi
    if [ -z "${TF_VAR_ssh_public_key_path:-}" ] || [ ! -r "$TF_VAR_ssh_public_key_path" ]; then
        echo "[CONFIG ERROR] SSH public key is missing or unreadable."
        return 1
    fi
}

unset _dr_paths_source_dir
