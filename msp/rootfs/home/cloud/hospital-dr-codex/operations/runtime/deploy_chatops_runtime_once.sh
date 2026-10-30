#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# One-click, operator-run deployment wrapper.  This script is intentionally
# run as cloud; only fixed, narrowly scoped systemd/lock/restore operations use
# sudo.  The established sync script itself is never run as root.

readonly REPO_ROOT="/home/cloud/hospital-dr-codex"
readonly RUNTIME_DIR="/home/cloud/dr_project"
readonly SECRET_FILE="/home/cloud/hospital-dr-secrets/dr.env"
readonly STATE_DIR="/var/lib/hospital-dr"
readonly STATE_DB="$STATE_DIR/chatops_state.sqlite3"
readonly SERVICE="hospital-dr-chatops.service"
readonly SYNC_SCRIPT="$REPO_ROOT/operations/runtime/sync_chatops_runtime.sh"
readonly BACKUP_PARENT="$RUNTIME_DIR/backups/chatops-runtime-deploy"
readonly TARGET_FILES=(chatops_core.py wazuh_failback_gate.py wazuh_live_provider.py rto_timeline.py)
readonly CHECK_FILES=(
    chatops_core.py chatops_audit.py emergency_dr.py network_dr_health.py
    wazuh_alerts.py wazuh_correlation.py wazuh_failback_gate.py wazuh_live_provider.py
    rto_timeline.py zabbix_alerts.py
)

declare -A ORIGINAL_HASH=() SOURCE_HASH=() ORIGINAL_UID=() ORIGINAL_GID=() ORIGINAL_MODE=()
declare -a SYNC_TARGETS=()
SYNC_ATTEMPTED=false
BACKUP_READY=false
SYNC_OUTPUT=""
BACKUP_DIR=""
START_EPOCH=""

fail() {
    printf 'CHATOPS_DEPLOY_BLOCKED=%s\n' "$1" >&2
    exit 1
}

validate_dry_run_output() {
    local output="$1" line file state="" source_count=0 runtime_count=0 user_count=0 dry_run_count=0
    local -a reported_targets=()
    local -A seen_targets=()
    while IFS= read -r line; do
        case "$line" in
            CHATOPS_SOURCE=*)
                ((source_count += 1))
                [[ "$line" == "CHATOPS_SOURCE=$REPO_ROOT/operations/chatops" ]] || fail "dry_run_source_path_unexpected"
                ;;
            CHATOPS_RUNTIME=*)
                ((runtime_count += 1))
                [[ "$line" == "CHATOPS_RUNTIME=$RUNTIME_DIR" ]] || fail "dry_run_runtime_path_unexpected"
                ;;
            CHATOPS_VALIDATION_USER=*)
                ((user_count += 1))
                [[ "$line" == "CHATOPS_VALIDATION_USER=cloud" ]] || fail "dry_run_validation_user_unexpected"
                ;;
            CHATOPS_DRY_RUN=*)
                ((dry_run_count += 1))
                [[ "$line" == "CHATOPS_DRY_RUN=true" ]] || fail "sync_dry_run_not_read_only"
                ;;
            WOULD_SYNC=*)
                file="${line#WOULD_SYNC=}"
                [[ -n "$file" ]] || fail "dry_run_target_invalid"
                [[ " ${TARGET_FILES[*]} " == *" $file "* ]] || fail "dry_run_target_outside_allowlist"
                [[ -z "${seen_targets[$file]:-}" ]] || fail "dry_run_target_duplicated"
                [[ -f "$REPO_ROOT/operations/chatops/$file" && ! -L "$REPO_ROOT/operations/chatops/$file" ]] \
                    || fail "canonical_target_invalid"
                [[ -f "$RUNTIME_DIR/$file" && ! -L "$RUNTIME_DIR/$file" ]] \
                    || fail "runtime_target_invalid"
                seen_targets[$file]=1
                reported_targets+=("$file")
                ;;
            CHATOPS_SYNC=*)
                [[ -z "$state" ]] || fail "dry_run_result_duplicated"
                state="${line#CHATOPS_SYNC=}"
                ;;
            SYNC=*|WOULD_*)
                fail "dry_run_mutation_protocol_unexpected"
                ;;
            "") ;;
            *)
                # Accept only the sync script's documented dry-run protocol.
                # Unknown operation/path records must never be silently ignored.
                fail "dry_run_output_unexpected"
                ;;
        esac
    done <<< "$output"

    [[ "$source_count" == 1 && "$runtime_count" == 1 && "$user_count" == 1 && "$dry_run_count" == 1 ]] \
        || fail "dry_run_contract_incomplete"
    case "$state:${#reported_targets[@]}" in
        "DRY_RUN_PASS:"[1-4]) ;;
        "NO_CHANGES:0") ;;
        *) fail "dry_run_result_target_mismatch" ;;
    esac

    for file in "${TARGET_FILES[@]}"; do
        [[ -f "$REPO_ROOT/operations/chatops/$file" && ! -L "$REPO_ROOT/operations/chatops/$file" ]] \
            || fail "canonical_allowlist_file_invalid"
        [[ -f "$RUNTIME_DIR/$file" && ! -L "$RUNTIME_DIR/$file" ]] \
            || fail "runtime_allowlist_file_invalid"
    done
    SYNC_TARGETS=("${reported_targets[@]}")
}

hash_file() {
    /usr/bin/sha256sum -- "$1" | /usr/bin/awk '{print $1}'
}

check_active_requests() {
    /usr/bin/python3 - "$STATE_DB" <<'PY'
import os
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote

path = Path(sys.argv[1])
try:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("state database missing or not a regular file")
    resolved = path.resolve(strict=True)
    db = sqlite3.connect(f"file:{quote(str(resolved))}?mode=ro", uri=True, timeout=5)
    db.execute("PRAGMA query_only=ON")
    row = db.execute(
        "SELECT COUNT(*) FROM approval_requests "
        "WHERE status IN ('PENDING','PARTIALLY_APPROVED','EXECUTING')"
    ).fetchone()
    db.close()
    count = int(row[0])
except Exception:
    print("APPROVAL_DB=UNREADABLE")
    raise SystemExit(2)
print(f"ACTIVE_APPROVAL_REQUESTS={count}")
if count:
    raise SystemExit(3)
PY
}

check_privileged_state() {
    sudo -n /usr/bin/python3 - "${1:-normal}" <<'PY'
import fcntl
import os
import pwd
import shlex
import stat
import subprocess
import sys

SERVICE = "hospital-dr-chatops.service"
RUNTIME = "/home/cloud/dr_project"
SECRET = "<SET_IN_SECRET_STORE>"
STATE = "/var/lib/hospital-dr"
EXPECTED_ENV = {
    "DR_SECRET_FILE": SECRET,
    "DR_STATE_DIR": STATE,
    "CHATOPS_STATE_DB": STATE + "/chatops_state.sqlite3",
    "CHATOPS_EXECUTION_LOCK_FILE": STATE + "/chatops.pipeline.lock",
}
STAGE_GATES = (
    "DUMP_DB_SERVICE_CUTOVER_ENABLED",
    "DUMP_DB_SERVICE_PROMOTION_ENABLED",
    "DUMP_DB_DNS_PREFLIGHT_ENABLED",
    "DUMP_DB_READONLY_HEALTH_ENABLED",
    "DUMP_DB_PUBLIC_READINESS_ENABLED",
    "DUMP_DB_DNS_TRANSACTION_ENABLED",
    "DUMP_DB_SERVICE_OPEN_ENABLED",
)
WAZUH_PROVIDER_SETTINGS = (
    "WAZUH_API_URL",
    "WAZUH_API_USER",
    "WAZUH_API_PASSWORD",
    "WAZUH_INDEXER_URL",
    "WAZUH_INDEXER_USER",
    "WAZUH_INDEXER_PASSWORD",
)
WAZUH_REQUIRED_AGENTS_KEY = "WAZUH_FAILBACK_REQUIRED_AGENTS"
wazuh_risk_warnings = []
failback_security_warnings = []
BOOL_GATES = (
    "DUMP_RESTORE_EXEC_ENABLED",
    "DEMO_DUMP_APPS_START_ENABLED",
    "DEMO_DUMP_FINALIZE_ENABLED",
)
RUNNERS = {
    "full_failover.sh", "full_failback.sh", "failover.sh", "failback.sh",
    "dr_environment_control.sh", "dr_project_resume.sh", "post_demo_suspend.sh",
    "recover_active_dr_after_cost_shutdown.sh", "demo_dump_restore_existing_dr.sh",
    "demo_dump_restore_existing_dr_apps.sh", "demo_dump_finalize_existing_dr.sh",
    "dump_failover_executor.sh", "dump_db_service_open.sh", "run_demo.sh",
    "terraform", "ansible-playbook",
}
MODE = sys.argv[1] if len(sys.argv) > 1 else "normal"
if MODE not in {"normal", "rollback", "gates"}:
    raise SystemExit(2)

def show(prop):
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", "--property=" + prop, "--value", SERVICE],
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    return result.stdout.strip()

def parse_env_file(path):
    values = {}
    if os.path.islink(path) or not os.path.isfile(path) or not os.access(path, os.R_OK):
        raise RuntimeError("secret file unavailable")
    st = os.stat(path, follow_symlinks=False)
    if st.st_uid != pwd.getpwnam("cloud").pw_uid or st.st_mode & 0o077:
        raise RuntimeError("secret file permissions are too broad")
    with open(path, encoding="utf-8") as stream:
        for raw in stream:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
    return values

def is_disabled(value):
    return str(value or "").strip().lower() in {"", "false", "0", "no", "off"}

try:
    if show("FragmentPath") != "/etc/systemd/system/" + SERVICE:
        raise RuntimeError("unexpected systemd unit source")
    if show("DropInPaths"):
        raise RuntimeError("systemd drop-in overrides are present")
    if show("EnvironmentFiles"):
        raise RuntimeError("systemd EnvironmentFile overrides are present")
    if show("User") != "cloud" or show("WorkingDirectory") != RUNTIME:
        raise RuntimeError("unexpected service user or working directory")
    if MODE != "rollback" and (show("ActiveState") != "active" or int(show("MainPID")) <= 1):
        raise RuntimeError("ChatOps service is not active")

    exec_start = show("ExecStart")
    if "/usr/bin/python3" not in exec_start or "--chdir " + RUNTIME not in exec_start or "wsgi:app" not in exec_start:
        raise RuntimeError("unexpected ChatOps ExecStart")

    # systemd's Environment property is parsed in memory only; never print it,
    # because a locally customized unit could contain credentials.
    unit_env = {}
    for token in shlex.split(show("Environment")):
        if "=" in token:
            key, value = token.split("=", 1)
            unit_env[key] = value
    for key, expected in EXPECTED_ENV.items():
        if unit_env.get(key) != expected:
            raise RuntimeError("unexpected service environment configuration")

    secret = parse_env_file(SECRET)
    state_dir = secret.get("DR_STATE_DIR", unit_env.get("DR_STATE_DIR", STATE))
    if os.path.realpath(state_dir) != STATE:
        raise RuntimeError("DR state directory override is outside the verified runtime")

    # App-level values in dr.env override these inherited environment values.
    effective = dict(unit_env)
    effective.update(secret)
    if MODE != "rollback":
        # These checks are advisory for deploying the ChatOps code only.
        # The runtime risk display remains UNKNOWN when its provider is
        # unavailable. Failback still requires a complete live snapshot and
        # WAZUH_FAILBACK_REQUIRED_AGENTS; the approval gate remains fail-closed.
        if any(not str(effective.get(key, "")).strip() for key in WAZUH_PROVIDER_SETTINGS):
            wazuh_risk_warnings.append("provider_settings_missing")
            failback_security_warnings.append("provider_settings_missing")
        required_agents = tuple(
            item.strip()
            for item in str(effective.get(WAZUH_REQUIRED_AGENTS_KEY, "")).split(",")
            if item.strip()
        )
        if not required_agents:
            failback_security_warnings.append("required_agents_missing")
        ca_cert = str(effective.get("WAZUH_CA_CERT", "")).strip()
        if ca_cert and (not os.path.isfile(ca_cert) or not os.access(ca_cert, os.R_OK)):
            wazuh_risk_warnings.append("ca_certificate_unavailable")
            failback_security_warnings.append("ca_certificate_unavailable")
        lookback = str(effective.get("WAZUH_SECURITY_LOOKBACK_MINUTES", "15")).strip()
        try:
            if int(lookback) <= 0:
                raise ValueError
        except ValueError:
            wazuh_risk_warnings.append("lookback_configuration_invalid")
            failback_security_warnings.append("lookback_configuration_invalid")
    for key in BOOL_GATES:
        if not is_disabled(effective.get(key, "false")):
            raise RuntimeError("a Dump execution opt-in is enabled")
    if str(effective.get("DUMP_RESTORE_EXECUTOR", "")).strip():
        raise RuntimeError("Dump executor path is configured")
    # Stage opt-ins are sourced exclusively from dr.env by ChatOps.
    for key in STAGE_GATES:
        if not is_disabled(secret.get(key, "")):
            raise RuntimeError("a Dump stage opt-in is enabled")

    lock_paths = {
        STATE + "/chatops.pipeline.lock",
        STATE + "/workflow.lock",
        STATE + "/failover.lock",
        STATE + "/failback.lock",
        STATE + "/environment.lock",
        STATE + "/terraform.lock",
        STATE + "/project-resume.lock",
        STATE + "/post-demo-suspend.lock",
        STATE + "/failback-dns.lock",
        STATE + "/dump-service-open.lock",
    }
    for key, value in secret.items():
        if key.endswith("_LOCK_FILE") and value.strip():
            path = value.strip()
            if not os.path.isabs(path) or os.path.commonpath((STATE, os.path.realpath(os.path.dirname(path)))) != STATE:
                raise RuntimeError("a configured lock path is outside DR state")
            lock_paths.add(path)
    for key, value in unit_env.items():
        if key.endswith("_LOCK_FILE") and value.strip():
            path = value.strip()
            if not os.path.isabs(path) or os.path.commonpath((STATE, os.path.realpath(os.path.dirname(path)))) != STATE:
                raise RuntimeError("a service lock path is outside DR state")
            lock_paths.add(path)

    for path in sorted(lock_paths) if MODE != "gates" else ():
        if os.path.islink(path):
            raise RuntimeError("a lock path is a symlink")
        try:
            fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o022:
                raise RuntimeError("a lock file is not a safe regular file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("an execution lock is held")
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            os.close(fd)

    # Lock files are checked together with process identity so missing lock
    # files cannot hide a currently running workflow.
    for entry in os.scandir("/proc") if MODE != "gates" else ():
        if not entry.name.isdigit():
            continue
        try:
            with open(os.path.join(entry.path, "cmdline"), "rb") as stream:
                raw = stream.read(65536)
        except FileNotFoundError:
            continue
        except PermissionError:
            raise RuntimeError("process list could not be fully inspected")
        if not raw:
            continue
        argv = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
        for arg in argv:
            base = os.path.basename(arg)
            if base in RUNNERS or any(name in arg for name in RUNNERS):
                raise RuntimeError("a DR workflow process is running")

except Exception as exc:
    # Deliberately print only a fixed, non-sensitive reason category.
    reason = str(exc)
    allowed = {
        "unexpected systemd unit source", "systemd drop-in overrides are present",
        "systemd EnvironmentFile overrides are present", "unexpected service user or working directory",
        "ChatOps service is not active", "unexpected ChatOps ExecStart",
        "unexpected service environment configuration", "secret file unavailable",
        "secret file permissions are too broad", "DR state directory override is outside the verified runtime",
        "a Dump execution opt-in is enabled", "Dump executor path is configured",
        "a Dump stage opt-in is enabled", "a configured lock path is outside DR state",
        "a service lock path is outside DR state", "a lock path is a symlink",
        "a lock file is not a safe regular file", "an execution lock is held",
        "process list could not be fully inspected", "a DR workflow process is running",
    }
    print("PRIVILEGED_PREFLIGHT=BLOCKED reason=" + (reason if reason in allowed else "state_unverifiable"))
    raise SystemExit(1)

print("SERVICE_CONFIG=PASS")
print("DUMP_GATES=DISABLED")
if MODE != "rollback":
    if wazuh_risk_warnings:
        print("WARN WAZUH_RISK_DISPLAY=UNKNOWN reason=" + ",".join(sorted(set(wazuh_risk_warnings))))
    else:
        print("WAZUH_RISK_DISPLAY=CONFIGURED connectivity=NOT_CHECKED")
    if failback_security_warnings:
        print(
            "WARN FAILBACK_SECURITY_GATE=UNKNOWN reason="
            + ",".join(sorted(set(failback_security_warnings)))
            + " runtime=FAIL_CLOSED"
        )
    else:
        print("FAILBACK_SECURITY_GATE=NOT_VERIFIED runtime_approval_recheck_required")
print(f"EXECUTION_LOCKS=FREE checked={len(lock_paths)} processes=clear")
PY
}

run_dry_run() {
    local output
    output="$(/usr/bin/bash "$SYNC_SCRIPT" --dry-run 2>&1)" || {
        printf '%s\n' "$output" | /usr/bin/sed -E 's/(TOKEN|PASSWORD|SECRET|KEY)=[^[:space:]]+/\1=[redacted]/Ig' >&2
        fail "sync_dry_run_failed"
    }
    validate_dry_run_output "$output"
    if ((${#SYNC_TARGETS[@]} == 0)); then
        printf 'DRY_RUN_TARGETS=none\n'
    else
        printf 'DRY_RUN_TARGETS=%s\n' "$(IFS=,; printf '%s' "${SYNC_TARGETS[*]}")"
    fi
}

snapshot_runtime() {
    local file
    [[ -d "$BACKUP_PARENT" && ! -L "$BACKUP_PARENT" ]] || {
        [[ ! -e "$BACKUP_PARENT" ]] || fail "backup_parent_is_not_a_safe_directory"
        /usr/bin/mkdir -p -m 0700 -- "$BACKUP_PARENT"
    }
    [[ -O "$BACKUP_PARENT" && -w "$BACKUP_PARENT" ]] || fail "backup_parent_not_owned_by_cloud"
    BACKUP_DIR="$BACKUP_PARENT/$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)-$$"
    [[ ! -e "$BACKUP_DIR" ]] || fail "backup_directory_collision"
    /usr/bin/mkdir -m 0700 -- "$BACKUP_DIR"

    for file in "${CHECK_FILES[@]}"; do
        [[ -f "$REPO_ROOT/operations/chatops/$file" && ! -L "$REPO_ROOT/operations/chatops/$file" ]] \
            || fail "canonical_file_invalid"
        [[ -f "$RUNTIME_DIR/$file" && ! -L "$RUNTIME_DIR/$file" ]] || fail "runtime_file_invalid"
        SOURCE_HASH[$file]="$(hash_file "$REPO_ROOT/operations/chatops/$file")"
        ORIGINAL_HASH[$file]="$(hash_file "$RUNTIME_DIR/$file")"
        ORIGINAL_UID[$file]="$(/usr/bin/stat -c '%u' -- "$RUNTIME_DIR/$file")"
        ORIGINAL_GID[$file]="$(/usr/bin/stat -c '%g' -- "$RUNTIME_DIR/$file")"
        ORIGINAL_MODE[$file]="$(/usr/bin/stat -c '%a' -- "$RUNTIME_DIR/$file")"
        if [[ " ${SYNC_TARGETS[*]} " == *" $file "* ]]; then
            /usr/bin/install -m 0600 -- "$RUNTIME_DIR/$file" "$BACKUP_DIR/$file"
            [[ "$(hash_file "$BACKUP_DIR/$file")" == "${ORIGINAL_HASH[$file]}" ]] || fail "runtime_backup_verification_failed"
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$file" "${ORIGINAL_HASH[$file]}" "${ORIGINAL_UID[$file]}" \
                "${ORIGINAL_GID[$file]}" "${ORIGINAL_MODE[$file]}" >> "$BACKUP_DIR/manifest.tsv"
        fi
    done
    /usr/bin/chmod 0600 "$BACKUP_DIR/manifest.tsv"
    BACKUP_READY=true
    printf 'RUNTIME_BACKUP=%s\n' "$BACKUP_DIR"
}

verify_snapshot_stable() {
    local file
    for file in "${CHECK_FILES[@]}"; do
        [[ "$(hash_file "$REPO_ROOT/operations/chatops/$file")" == "${SOURCE_HASH[$file]}" ]] \
            || fail "canonical_changed_during_deployment"
        [[ "$(hash_file "$RUNTIME_DIR/$file")" == "${ORIGINAL_HASH[$file]}" ]] \
            || fail "runtime_changed_before_sync"
    done
}

restore_runtime() {
    local file current expected restore_failed=false
    [[ "$BACKUP_READY" == true ]] || { printf 'ROLLBACK=BLOCKED no_verified_backup\n' >&2; return 1; }
    local -A restore_set=()
    if ! check_active_requests >/dev/null 2>&1 || ! check_privileged_state rollback >/dev/null 2>&1; then
        printf 'ROLLBACK=DEFERRED_ACTIVE_WORK_OR_LOCK backup=%s\n' "$BACKUP_DIR" >&2
        return 1
    fi
    for file in "${SYNC_TARGETS[@]}"; do restore_set[$file]=1; done

    for file in "${!restore_set[@]}"; do
        current="$(hash_file "$RUNTIME_DIR/$file" 2>/dev/null || true)"
        expected="${ORIGINAL_HASH[$file]:-}"
        [[ -n "$expected" ]] || { restore_failed=true; continue; }
        [[ "$current" == "$expected" ]] && continue
        if [[ "$current" != "${SOURCE_HASH[$file]:-}" ]]; then
            printf 'ROLLBACK_CONFLICT=%s\n' "$file" >&2
            restore_failed=true
            continue
        fi
        if ! sudo -n /usr/bin/python3 - "$BACKUP_DIR" "$file" "$expected" \
            "${ORIGINAL_UID[$file]}" "${ORIGINAL_GID[$file]}" "${ORIGINAL_MODE[$file]}" <<'PY'
import hashlib
import os
import pwd
import secrets
import stat
import sys

backup_dir, name, expected, uid_raw, gid_raw, mode_raw = sys.argv[1:]
allowed = {
    "chatops_core.py", "chatops_audit.py", "emergency_dr.py",
    "wazuh_alerts.py", "wazuh_failback_gate.py", "wazuh_live_provider.py",
    "rto_timeline.py", "zabbix_alerts.py",
}
runtime = "/home/cloud/dr_project"
backup_root = runtime + "/backups/chatops-runtime-deploy"
try:
    if name not in allowed or os.path.realpath(runtime) != runtime:
        raise RuntimeError("invalid fixed path")
    if os.path.realpath(backup_root) != backup_root or os.path.realpath(backup_dir) != backup_dir:
        raise RuntimeError("backup path is not canonical")
    if os.path.commonpath((backup_root, backup_dir)) != backup_root:
        raise RuntimeError("backup path outside approved directory")
    owner = pwd.getpwnam("cloud").pw_uid
    owner_group = pwd.getpwnam("cloud").pw_gid
    directory_stat = os.stat(backup_dir, follow_symlinks=False)
    if not stat.S_ISDIR(directory_stat.st_mode) or directory_stat.st_uid != owner or stat.S_IMODE(directory_stat.st_mode) != 0o700:
        raise RuntimeError("backup directory permissions invalid")
    source = os.path.join(backup_dir, name)
    fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        source_stat = os.fstat(fd)
        if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_uid != owner or stat.S_IMODE(source_stat.st_mode) != 0o600:
            raise RuntimeError("backup file permissions invalid")
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        content = b"".join(chunks)
    finally:
        os.close(fd)
    if hashlib.sha256(content).hexdigest() != expected:
        raise RuntimeError("backup checksum mismatch")
    target = os.path.join(runtime, name)
    target_stat = os.stat(target, follow_symlinks=False)
    if not stat.S_ISREG(target_stat.st_mode):
        raise RuntimeError("runtime target is not a regular file")
    uid, gid, mode = int(uid_raw), int(gid_raw), int(mode_raw, 8)
    if uid not in {0, owner} or gid not in {0, owner_group} or mode & 0o022 or not mode & 0o400:
        raise RuntimeError("original runtime metadata is outside allowed bounds")
    temp = os.path.join(runtime, ".chatops-restore-" + name + "-" + secrets.token_hex(8))
    out_fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(out_fd, view)
            view = view[written:]
        os.fsync(out_fd)
        os.fchown(out_fd, uid, gid)
        os.fchmod(out_fd, mode)
    except Exception:
        os.close(out_fd)
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    os.close(out_fd)
    os.replace(temp, target)
    directory_fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    raise SystemExit(1)
PY
        then
            restore_failed=true
            continue
        fi
        [[ "$(hash_file "$RUNTIME_DIR/$file")" == "$expected" ]] || restore_failed=true
    done

    if [[ "$restore_failed" == true ]]; then
        printf 'ROLLBACK=FAILED backup=%s\n' "$BACKUP_DIR" >&2
        return 1
    fi
    if ! check_active_requests >/dev/null 2>&1 || ! check_privileged_state rollback >/dev/null 2>&1; then
        printf 'ROLLBACK=FILES_RESTORED_RESTART_DEFERRED_ACTIVE_WORK backup=%s\n' "$BACKUP_DIR" >&2
        return 1
    fi
    if ! sudo -n /usr/bin/systemctl restart "$SERVICE" \
        || ! sudo -n /usr/bin/systemctl is-active --quiet "$SERVICE"; then
        printf 'ROLLBACK=FILES_RESTORED_SERVICE_RESTART_FAILED backup=%s\n' "$BACKUP_DIR" >&2
        return 1
    fi
    printf 'ROLLBACK=PASS files_restored_service_restarted backup=%s\n' "$BACKUP_DIR" >&2
    return 0
}

on_exit() {
    local rc=$?
    trap - EXIT
    if ((rc != 0)) && [[ "$SYNC_ATTEMPTED" == true ]]; then
        restore_runtime || printf 'MANUAL_RECOVERY_REQUIRED backup=%s\n' "$BACKUP_DIR" >&2
    fi
    exit "$rc"
}
trap on_exit EXIT

[[ "$EUID" -ne 0 ]] || fail "run_as_cloud_not_root"
[[ "$(/usr/bin/id -un)" == cloud ]] || fail "must_run_as_cloud"
[[ "$(/usr/bin/realpath -e -- "$REPO_ROOT")" == "$REPO_ROOT" ]] || fail "canonical_path_mismatch"
[[ "$(/usr/bin/realpath -e -- "$RUNTIME_DIR")" == "$RUNTIME_DIR" ]] || fail "runtime_path_mismatch"
[[ -f "$SYNC_SCRIPT" && ! -L "$SYNC_SCRIPT" ]] || fail "sync_script_invalid"
[[ "$(/usr/bin/realpath -e -- "$SYNC_SCRIPT")" == "$SYNC_SCRIPT" ]] || fail "sync_script_path_mismatch"
[[ -x /usr/bin/sudo && -x /usr/bin/python3 && -x /usr/bin/systemctl && -x /usr/bin/curl ]] \
    || fail "required_system_command_missing"

printf 'SUDO_AUTH=REQUESTED\n'
sudo -v || fail "sudo_authentication_failed"
sudo -n true || fail "sudo_noninteractive_verification_failed"
check_privileged_state || fail "service_lock_or_gate_check_failed"
check_active_requests || fail "active_request_check_failed"
run_dry_run
if ((${#SYNC_TARGETS[@]} == 0)); then
    printf 'SYNC=NO_CHANGES\n'
    printf 'CHATOPS_DEPLOY=NO_CHANGES service_restart=skipped\n'
    SYNC_ATTEMPTED=false
    exit 0
fi
INITIAL_SYNC_TARGETS=("${SYNC_TARGETS[@]}")
snapshot_runtime

# Revalidate directly before syncing.  The canonical sync script runs as cloud
# and has its own automatic rollback if its compile/import validation fails.
check_privileged_state || fail "pre_sync_lock_or_gate_recheck_failed"
check_active_requests || fail "pre_sync_active_request_recheck_failed"
run_dry_run
initial_targets="$(printf '%s\n' "${INITIAL_SYNC_TARGETS[@]}" | /usr/bin/sort)"
current_targets="$(printf '%s\n' "${SYNC_TARGETS[@]}" | /usr/bin/sort)"
[[ "$current_targets" == "$initial_targets" ]] || fail "dry_run_targets_changed_before_sync"
verify_snapshot_stable
SYNC_ATTEMPTED=true
if ! SYNC_OUTPUT="$(/usr/bin/bash "$SYNC_SCRIPT" 2>&1)"; then
    printf 'SYNC_SCRIPT=FAILED\n' >&2
    exit 1
fi

mapfile -t actual_targets < <(printf '%s\n' "$SYNC_OUTPUT" | /usr/bin/awk -F= '$1 == "SYNC" {print $2}' | /usr/bin/sort)
expected_targets="$(printf '%s\n' "${SYNC_TARGETS[@]}" | /usr/bin/sort)"
[[ "${actual_targets[*]:-}" == "${expected_targets//$'\n'/ }" ]] || fail "sync_changed_unexpected_files"
[[ "$(printf '%s\n' "${actual_targets[@]}" | /usr/bin/uniq -d | /usr/bin/wc -l)" -eq 0 ]] \
    || fail "sync_reported_duplicate_targets"
for sync_file in "${actual_targets[@]}"; do
    [[ " ${TARGET_FILES[*]} " == *" $sync_file "* ]] || fail "sync_changed_file_outside_allowlist"
done
[[ "$SYNC_OUTPUT" == *"CHATOPS_SYNC=PASS"* ]] || fail "sync_validation_not_passed"
for expected_line in \
    "CHATOPS_SOURCE=$REPO_ROOT/operations/chatops" \
    "CHATOPS_RUNTIME=$RUNTIME_DIR" \
    "CHATOPS_VALIDATION_USER=cloud" \
    "CHATOPS_DRY_RUN=false"; do
    /usr/bin/grep -Fqx -- "$expected_line" <<< "$SYNC_OUTPUT" || fail "sync_output_path_or_mode_unexpected"
done

for file in "${CHECK_FILES[@]}"; do
    [[ "$(hash_file "$REPO_ROOT/operations/chatops/$file")" == "${SOURCE_HASH[$file]}" ]] \
        || fail "canonical_changed_during_sync"
    if [[ " ${TARGET_FILES[*]} " == *" $file "* ]]; then
        [[ "$(hash_file "$RUNTIME_DIR/$file")" == "${SOURCE_HASH[$file]}" ]] || fail "target_hash_mismatch"
    else
        [[ "$(hash_file "$RUNTIME_DIR/$file")" == "${ORIGINAL_HASH[$file]}" ]] || fail "non_target_runtime_file_changed"
    fi
done
printf 'SYNC=PASS files=%s\n' "$(IFS=,; printf '%s' "${SYNC_TARGETS[*]}")"

# Do not restart if a request or workflow appeared during synchronization.
check_privileged_state || fail "pre_restart_lock_or_gate_recheck_failed"
check_active_requests || fail "pre_restart_active_request_recheck_failed"

START_EPOCH="$(/usr/bin/date +%s)"
sudo -n /usr/bin/systemctl restart "$SERVICE" || fail "service_restart_failed"
sudo -n /usr/bin/systemctl is-active --quiet "$SERVICE" || fail "service_not_active_after_restart"
main_pid="$(sudo -n /usr/bin/systemctl show --property=MainPID --value "$SERVICE")"
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]] || fail "service_mainpid_invalid"

env -u PYTHONNOUSERSITE PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$RUNTIME_DIR" \
    /usr/bin/python3 - <<'PY' || fail "runtime_import_failed"
import pathlib
import chatops_audit
import chatops_core
import emergency_dr
import network_dr_health
import rto_timeline
import wazuh_failback_gate
import wazuh_live_provider
import wazuh_alerts
import wazuh_correlation
import zabbix_alerts

expected = pathlib.Path("/home/cloud/dr_project").resolve()
for module in (
    chatops_core,
    chatops_audit,
    emergency_dr,
    network_dr_health,
    rto_timeline,
    wazuh_alerts,
    wazuh_correlation,
    wazuh_failback_gate,
    wazuh_live_provider,
    zabbix_alerts,
):
    if pathlib.Path(module.__file__).resolve().parent != expected:
        raise SystemExit("module imported outside ChatOps Runtime")
print("RUNTIME_IMPORT=PASS")
PY

http_code=""
http_ready=false
http_attempt=0
for ((http_attempt = 1; http_attempt <= 30; http_attempt++)); do
    if http_code="$(/usr/bin/curl --silent --max-time 1 -o /dev/null \
        -w '%{http_code}' http://IP_REDACTED:5000/ 2>/dev/null)" \
        && [[ "$http_code" == 200 ]]; then
        http_ready=true
        break
    fi
    if ((http_attempt < 30)); then
        /usr/bin/sleep 1
    fi
done
if [[ "$http_ready" != true ]]; then
    printf 'HTTP_READONLY_CHECK=FAILED status=%s attempts=%s\n' \
        "${http_code:-NO_RESPONSE}" "$http_attempt" >&2
    fail "chatops_readonly_http_check_failed"
fi

check_privileged_state gates || fail "post_restart_gate_check_failed"
error_log="$(sudo -n /usr/bin/journalctl -u "$SERVICE" --since "@$START_EPOCH" \
    --priority=err --no-pager --output=cat --lines=200 2>/dev/null)" \
    || fail "journal_check_unavailable"
if [[ -n "$error_log" ]]; then
    unset error_log
    fail "new_service_errors_detected_check_journal"
fi
unset error_log

SYNC_ATTEMPTED=false
printf 'SERVICE=ACTIVE MainPID=%s\n' "$main_pid"
printf 'RUNTIME_IMPORT=PASS modules=chatops_core,rto_timeline,wazuh_failback_gate,wazuh_live_provider\n'
printf 'HTTP_READONLY_CHECK=PASS status=%s\n' "$http_code"
printf 'DUMP_GATES=DISABLED\n'
printf 'RECENT_SERVICE_ERRORS=0\n'
printf 'CHATOPS_DEPLOY=PASS\n'
