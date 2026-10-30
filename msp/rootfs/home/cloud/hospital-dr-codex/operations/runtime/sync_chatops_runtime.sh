#!/usr/bin/env bash
set -euo pipefail

# Synchronize only the ChatOps application modules.  Secrets, state databases,
# audit logs, virtual environments, and unrelated runtime components are never
# copied by this script.

CANONICAL_SOURCE_DIR="/home/cloud/hospital-dr-codex/operations/chatops"
CANONICAL_RUNTIME_DIR="/home/cloud/dr_project"
SOURCE_DIR="${CHATOPS_SOURCE_DIR:-$CANONICAL_SOURCE_DIR}"
RUNTIME_DIR="${CHATOPS_RUNTIME_DIR:-$CANONICAL_RUNTIME_DIR}"
BACKUP_ROOT="${CHATOPS_RUNTIME_BACKUP_DIR:-$RUNTIME_DIR/backups}"
SERVICE_NAME="hospital-dr-chatops.service"
DRY_RUN=false
RESTART=false

SYNC_FILES=(
    chatops_core.py
    emergency_dr.py
    network_dr_health.py
    wazuh_failback_gate.py
    wazuh_live_provider.py
    rto_timeline.py
    zabbix_alerts.py
)

usage() {
    cat <<'EOF'
Usage: sync_chatops_runtime.sh [--dry-run] [--restart]

  --dry-run  Validate and report code differences without copying files.
  --restart  Restart hospital-dr-chatops.service only after a successful sync
             and runtime validation.  Never used with --dry-run.
EOF
}

fail() {
    printf 'CHATOPS_SYNC_ERROR=%s\n' "$1" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            ;;
        --restart)
            RESTART=true
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "unknown option: $1"
            ;;
    esac
    shift
done

if [[ "$DRY_RUN" == true && "$RESTART" == true ]]; then
    fail "--restart cannot be combined with --dry-run"
fi
if [[ "$RESTART" == true && EUID -ne 0 ]]; then
    fail "--restart requires root; use sudo"
fi

[[ "$SOURCE_DIR" == "$CANONICAL_SOURCE_DIR" ]] || fail "source path is not the canonical ChatOps source"
[[ "$RUNTIME_DIR" == "$CANONICAL_RUNTIME_DIR" ]] || fail "runtime path is not the approved ChatOps runtime"

VALIDATION_USER=""
VALIDATION_HOME=""
if ((EUID == 0)); then
    command -v runuser >/dev/null 2>&1 || fail "runuser is required for root validation"
    if command -v systemctl >/dev/null 2>&1; then
        VALIDATION_USER="$(systemctl show --property=User --value "$SERVICE_NAME" 2>/dev/null || true)"
    fi
    if [[ -z "$VALIDATION_USER" ]]; then
        for unit_file in \
            "/etc/systemd/system/$SERVICE_NAME" \
            "/lib/systemd/system/$SERVICE_NAME"; do
            if [[ -r "$unit_file" ]]; then
                VALIDATION_USER="$(awk -F= '/^[[:space:]]*User[[:space:]]*=/{print $2; exit}' "$unit_file")"
                [[ -n "$VALIDATION_USER" ]] && break
            fi
        done
    fi
    [[ -n "$VALIDATION_USER" ]] || fail "could not determine $SERVICE_NAME User"
    [[ "$VALIDATION_USER" != "root" ]] || fail "$SERVICE_NAME must not validate ChatOps as root"
    id "$VALIDATION_USER" >/dev/null 2>&1 || fail "service user does not exist: $VALIDATION_USER"
    VALIDATION_HOME="$(getent passwd "$VALIDATION_USER" | awk -F: 'NR == 1 {print $6}')"
    [[ -n "$VALIDATION_HOME" ]] || fail "could not determine home for service user: $VALIDATION_USER"
else
    VALIDATION_USER="$(id -un)"
    VALIDATION_HOME="${HOME:-$(getent passwd "$VALIDATION_USER" | awk -F: 'NR == 1 {print $6}')}"
fi

run_validation() {
    if ((EUID == 0)); then
        runuser -u "$VALIDATION_USER" -- "$@"
    else
        "$@"
    fi
}

SOURCE_REAL="$(realpath -e "$SOURCE_DIR" 2>/dev/null || true)"
RUNTIME_REAL="$(realpath -e "$RUNTIME_DIR" 2>/dev/null || true)"
[[ "$SOURCE_REAL" == "$CANONICAL_SOURCE_DIR" ]] || fail "canonical source path is unavailable"
[[ "$RUNTIME_REAL" == "$CANONICAL_RUNTIME_DIR" ]] || fail "approved runtime path is unavailable"
[[ "$SOURCE_REAL" != "$RUNTIME_REAL" ]] || fail "source and runtime paths must differ"

for command_name in realpath python3 sha256sum install mv cp mktemp awk id getent chown; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required command missing: $command_name"
done

for file_name in "${SYNC_FILES[@]}"; do
    [[ -f "$SOURCE_DIR/$file_name" ]] || fail "source file missing: $file_name"
    [[ -f "$RUNTIME_DIR/$file_name" ]] || fail "runtime file missing: $file_name"
done

VALIDATION_PYTHON="/usr/bin/python3"
[[ -x "$VALIDATION_PYTHON" ]] || fail "runtime Python is unavailable: $VALIDATION_PYTHON"

COMPILE_DIR="$(mktemp -d)"
if ((EUID == 0)); then
    chown "$VALIDATION_USER" "$COMPILE_DIR"
fi
VALIDATION_SECRET_FILE="$COMPILE_DIR/validation.env"
: > "$VALIDATION_SECRET_FILE"
chmod 600 "$VALIDATION_SECRET_FILE"
if ((EUID == 0)); then
    chown "$VALIDATION_USER" "$VALIDATION_SECRET_FILE"
fi
BACKUP_DIR=""
SYNC_APPLIED=false
RESTART_ATTEMPTED=false
restore_backup() {
    [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]] || return 0
    local restore_failed=0
    for file_name in "${SYNC_FILES[@]}"; do
        if ! cp -a "$BACKUP_DIR/$file_name" "$RUNTIME_DIR/$file_name"; then
            restore_failed=1
        fi
    done
    if ((restore_failed)); then
        printf 'CHATOPS_ROLLBACK=FAIL\n' >&2
        return 1
    fi
    printf 'CHATOPS_ROLLBACK=PASS\n' >&2
}

cleanup() {
    rm -rf "$COMPILE_DIR"
}

on_exit() {
    exit_code=$?
    if ((exit_code != 0)) && [[ "$SYNC_APPLIED" == true ]]; then
        if restore_backup && [[ "$RESTART_ATTEMPTED" == true ]]; then
            if systemctl restart "$SERVICE_NAME" \
                && systemctl is-active --quiet "$SERVICE_NAME"; then
                printf 'CHATOPS_ROLLBACK_RESTART=PASS\n' >&2
            else
                printf 'CHATOPS_ROLLBACK_RESTART=FAIL\n' >&2
            fi
        fi
    fi
    cleanup
    exit "$exit_code"
}
trap on_exit EXIT

VALIDATION_ENV=(
    "HOME=$VALIDATION_HOME"
    "DR_SECRET_FILE=$VALIDATION_SECRET_FILE"
    "DR_STATE_DIR=$COMPILE_DIR"
    "CHATOPS_STATE_DB=$COMPILE_DIR/chatops_state.sqlite3"
    "CHATOPS_AUDIT_FILE=$COMPILE_DIR/chatops_audit.jsonl"
    "CHATOPS_EXECUTION_LOCK_FILE=$COMPILE_DIR/pipeline.lock"
    "WAZUH_CORRELATION_STATE_FILE=$COMPILE_DIR/wazuh_correlation.json"
    "DUMP_BACKUP_DIR=$COMPILE_DIR/backups"
    "NETWORK_DR_HEALTH_ENABLED=false"
    "WAZUH_SECURITY_SLACK_ENABLED=false"
    "SLACK_EMERGENCY_CHANNEL_ID="
    "CHATOPS_SLACK_CLEANUP_INTERVAL_SECONDS=3600"
    "EMERGENCY_CONSOLE_WATCHDOG_INTERVAL_SECONDS=60"
    "EXPIRY_INTERVAL_SECONDS=3600"
)

# Import only side-effect-free application modules here.  Importing wsgi would
# construct the Flask app and start its daemon expiry/cleanup workers; a short
# validation process must never start service workers.  Compile wsgi.py above
# to catch syntax errors without executing its production entry point.
run_validation env -u PYTHONNOUSERSITE \
    "${VALIDATION_ENV[@]}" \
    "PYTHONPYCACHEPREFIX=$COMPILE_DIR" \
    "$VALIDATION_PYTHON" -m py_compile \
    "$SOURCE_DIR/chatops_core.py" \
    "$SOURCE_DIR/chatops_audit.py" \
    "$SOURCE_DIR/emergency_dr.py" \
    "$SOURCE_DIR/wazuh_alerts.py" \
    "$SOURCE_DIR/wazuh_correlation.py" \
    "$SOURCE_DIR/wazuh_failback_gate.py" \
    "$SOURCE_DIR/wazuh_live_provider.py" \
    "$SOURCE_DIR/network_dr_health.py" \
    "$SOURCE_DIR/rto_timeline.py" \
    "$SOURCE_DIR/zabbix_alerts.py" \
    "$SOURCE_DIR/wsgi.py" \
    || fail "source py_compile failed"

run_validation env -u PYTHONNOUSERSITE \
    "${VALIDATION_ENV[@]}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$SOURCE_DIR" \
    "$VALIDATION_PYTHON" - <<'PY'
import flask
import chatops_audit
import chatops_core
import emergency_dr
import network_dr_health
import wazuh_alerts
import wazuh_correlation
import wazuh_failback_gate
import wazuh_live_provider
import rto_timeline
import zabbix_alerts
PY

changed_files=()
for file_name in "${SYNC_FILES[@]}"; do
    source_hash="$(sha256sum "$SOURCE_DIR/$file_name" | awk '{print $1}')"
    runtime_hash="$(sha256sum "$RUNTIME_DIR/$file_name" | awk '{print $1}')"
    if [[ "$source_hash" != "$runtime_hash" ]]; then
        changed_files+=("$file_name")
    fi
done

printf 'CHATOPS_SOURCE=%s\n' "$SOURCE_DIR"
printf 'CHATOPS_RUNTIME=%s\n' "$RUNTIME_DIR"
printf 'CHATOPS_VALIDATION_USER=%s\n' "$VALIDATION_USER"
printf 'CHATOPS_DRY_RUN=%s\n' "$DRY_RUN"

if ((${#changed_files[@]} == 0)); then
    printf 'CHATOPS_SYNC=NO_CHANGES\n'
    exit 0
fi

for file_name in "${changed_files[@]}"; do
    if [[ "$DRY_RUN" == true ]]; then
        printf 'WOULD_SYNC=%s\n' "$file_name"
    else
        printf 'SYNC=%s\n' "$file_name"
    fi
done

if [[ "$DRY_RUN" == true ]]; then
    printf 'CHATOPS_SYNC=DRY_RUN_PASS\n'
    exit 0
fi

BACKUP_DIR="$BACKUP_ROOT/chatops-sync-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

for file_name in "${SYNC_FILES[@]}"; do
    cp -a "$RUNTIME_DIR/$file_name" "$BACKUP_DIR/$file_name"
done

SYNC_APPLIED=true
for file_name in "${changed_files[@]}"; do
    temporary_path="$RUNTIME_DIR/.chatops-sync-${file_name}.$$"
    install -m 0644 "$SOURCE_DIR/$file_name" "$temporary_path"
    mv -f "$temporary_path" "$RUNTIME_DIR/$file_name"
done

if ! run_validation env -u PYTHONNOUSERSITE \
    "${VALIDATION_ENV[@]}" \
    "PYTHONPYCACHEPREFIX=$COMPILE_DIR" \
    "$VALIDATION_PYTHON" -m py_compile \
    "$RUNTIME_DIR/chatops_core.py" \
    "$RUNTIME_DIR/chatops_audit.py" \
    "$RUNTIME_DIR/emergency_dr.py" \
    "$RUNTIME_DIR/wazuh_alerts.py" \
    "$RUNTIME_DIR/wazuh_correlation.py" \
    "$RUNTIME_DIR/wazuh_failback_gate.py" \
    "$RUNTIME_DIR/wazuh_live_provider.py" \
    "$RUNTIME_DIR/network_dr_health.py" \
    "$RUNTIME_DIR/rto_timeline.py" \
    "$RUNTIME_DIR/zabbix_alerts.py" \
    "$RUNTIME_DIR/wsgi.py"; then
    fail "runtime py_compile failed; restored backup"
fi

if ! run_validation env -u PYTHONNOUSERSITE \
    "${VALIDATION_ENV[@]}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$RUNTIME_DIR" \
    "$VALIDATION_PYTHON" - <<'PY'
import flask
import chatops_audit
import chatops_core
import emergency_dr
import network_dr_health
import wazuh_alerts
import wazuh_correlation
import wazuh_failback_gate
import wazuh_live_provider
import rto_timeline
import zabbix_alerts
PY
then
    fail "runtime import validation failed; restored backup"
fi

printf 'CHATOPS_BACKUP=%s\n' "$BACKUP_DIR"
printf 'CHATOPS_SYNC=PASS\n'

if [[ "$RESTART" == true ]]; then
    RESTART_ATTEMPTED=true
    systemctl restart "$SERVICE_NAME" || fail "ChatOps service restart failed; restoring backup"
    systemctl is-active --quiet "$SERVICE_NAME" || fail "ChatOps service is not active after restart; restoring backup"
    printf 'CHATOPS_RESTART=PASS\n'
else
    printf 'CHATOPS_RESTART=SKIPPED\n'
fi

SYNC_APPLIED=false
