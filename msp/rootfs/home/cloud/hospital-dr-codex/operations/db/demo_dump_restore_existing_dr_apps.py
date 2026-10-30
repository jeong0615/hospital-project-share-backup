#!/usr/bin/env python3
"""Start DR Web/EMR after a verified DB-only Dump restore.

Consumes the existing request-bound receipt. It never reruns restoration,
starts host proxies, changes DNS, or records DR_ACTIVE.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operations.db import demo_dump_restore_existing_dr as restore  # noqa: E402


RESTORE_STAGES = {
    "TARGET_IDENTITY", "SSM_TRANSPORT", "APPLICATION_FENCE",
    "PRESNAPSHOT_PREFLIGHT", "PRESNAPSHOT", "SELECTED_DUMP_REVALIDATION",
    "SELECTED_DUMP_STAGE", "FINAL_FENCE_AND_AUTHORIZATION_CHECK",
    "RESTORE_ATTEMPTED", "POST_RESTORE_DB_VERIFICATION",
}
APP_SPECS = (
    {"kind": "web", "host": "dr-web", "container": "hospital-dr-web", "proxy": "nginx"},
    {"kind": "emr", "host": "dr-doc", "container": "hospital-dr-emr", "proxy": "apache2"},
)
DB_HOST = restore.DB_PRIVATE_IP
DB_PORT = 3306
DB_INSTANCE_ID = restore.DB_INSTANCE_ID
SAFE_CODE_RE = re.compile(r"[A-Z0-9_]{1,96}\Z")
INSTANCE_ID_RE = re.compile(r"i-[0-9a-f]{8,17}\Z")
DUMP_REQUEST_SOURCES = {
    "GENERAL": ("failover", "dump_restore_console"),
    "EMERGENCY": ("emergency", "emergency_dump_restore_console"),
}


class AppsStartError(RuntimeError):
    """Stable non-sensitive failure code."""

    def __init__(self, code: str):
        super().__init__(code if SAFE_CODE_RE.fullmatch(code) else "UNEXPECTED_APPS_START_ERROR")
        self.code = str(self)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_root(env: Mapping[str, str]) -> Path:
    explicit = str(env.get("DEMO_DUMP_RESTORE_STATE_DIR") or "").strip()
    root = Path(explicit) if explicit else Path(
        env.get("DR_STATE_DIR", "/var/lib/hospital-dr")
    ) / "demo-dump-restores"
    if not root.is_absolute():
        raise AppsStartError("RESTORE_STATE_PATH_INVALID")
    return root


def _request_dir(root: Path, request_id: str) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise AppsStartError("RESTORE_STATE_DIRECTORY_UNAVAILABLE")
    root_stat = root.lstat()
    if (
        not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.geteuid()
        or stat.S_IMODE(root_stat.st_mode) & 0o022
    ):
        raise AppsStartError("RESTORE_STATE_DIRECTORY_UNTRUSTED")
    path = root / request_id
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AppsStartError("RESTORE_REQUEST_DIRECTORY_UNAVAILABLE") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AppsStartError("RESTORE_REQUEST_DIRECTORY_UNTRUSTED")
    return path


def _read_private_json(path: Path, limit: int = 1024 * 1024) -> tuple[dict, bytes]:
    descriptor = None
    try:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 2 <= info.st_size <= limit
        ):
            raise AppsStartError("RECEIPT_FILE_UNTRUSTED")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise AppsStartError("RECEIPT_FILE_UNTRUSTED")
        value = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(value, dict):
            raise AppsStartError("RECEIPT_CONTENT_INVALID")
        return value, raw
    except AppsStartError:
        raise
    except FileNotFoundError as exc:
        raise AppsStartError("RESTORE_RECEIPT_MISSING") from exc
    except PermissionError as exc:
        raise AppsStartError("RESTORE_RECEIPT_PERMISSION_DENIED") from exc
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise AppsStartError("RESTORE_RECEIPT_UNREADABLE") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _instance_matches(targets, key, *, expected_id, name, private_ip) -> bool:
    item = targets.get(key) if isinstance(targets, dict) else None
    if not isinstance(item, dict):
        return False
    instance_id = str(item.get("instance_id") or "")
    return (
        bool(INSTANCE_ID_RE.fullmatch(instance_id))
        and (expected_id is None or instance_id == expected_id)
        and item.get("name") == name and item.get("private_ip") == private_ip
        and item.get("state") == "running"
    )


def validate_restore_receipt(receipt, *, request_id, backup_id, expected_sha256) -> None:
    origin = str(receipt.get("request_origin") or "").strip().upper()
    source_contract = DUMP_REQUEST_SOURCES.get(origin)
    if (
        receipt.get("request_type") != "DUMP_RESTORE_FAILOVER"
        or source_contract is None
        or receipt.get("request_origin") != origin
        or receipt.get("request_source") != source_contract[1]
        or receipt.get("slack_client_key") != source_contract[0]
    ):
        raise AppsStartError("RESTORE_RECEIPT_REQUEST_ORIGIN_INVALID")
    if (
        receipt.get("request_id") != request_id or receipt.get("backup_id") != backup_id
        or str(receipt.get("expected_sha256") or "").lower() != expected_sha256
        or receipt.get("status") != "DB_RESTORED_NOT_FAILOVER_COMPLETE"
        or receipt.get("phase") != "DB_RESTORED_NOT_FAILOVER_COMPLETE"
        or receipt.get("target") != {
            "instance_id": DB_INSTANCE_ID, "private_ip": DB_HOST, "port": DB_PORT,
        }
        or receipt.get("restore_attempted") is not True
        or receipt.get("apps_fenced") is not True
        or receipt.get("apps_fence_state") != "VERIFIED"
        or receipt.get("dns_changed") is not False
        or receipt.get("dr_active_recorded") is not False
        or receipt.get("automatic_db_rollback") is not False
        or receipt.get("operator_intervention_required") is not False
        or receipt.get("failure_code") is not None
    ):
        raise AppsStartError("RESTORE_RECEIPT_IDENTITY_OR_STATUS_MISMATCH")

    evidence = receipt.get("approval_evidence")
    approvers = evidence.get("approver_ids") if isinstance(evidence, dict) else None
    if (
        not isinstance(evidence, dict) or evidence.get("approval_required") != 2
        or evidence.get("approval_count") != 2
        or not isinstance(evidence.get("execution_id"), str) or not evidence.get("execution_id")
        or not isinstance(approvers, list) or len(approvers) != 2
        or any(not isinstance(item, str) or not item for item in approvers)
        or len(set(approvers)) != 2
    ):
        raise AppsStartError("TWO_ADMIN_APPROVAL_EVIDENCE_INVALID")

    targets = receipt.get("aws_targets")
    if not (
        _instance_matches(targets, "db", expected_id=DB_INSTANCE_ID,
                          name=restore.DB_NAME_TAG, private_ip=DB_HOST)
        and _instance_matches(targets, "web", expected_id=None,
                              name=restore.WEB_NAME_TAG, private_ip=restore.WEB_PRIVATE_IP)
        and _instance_matches(targets, "doc", expected_id=None,
                              name=restore.DOC_NAME_TAG, private_ip=restore.DOC_PRIVATE_IP)
    ):
        raise AppsStartError("RESTORE_RECEIPT_AWS_TARGETS_INVALID")

    snapshot = receipt.get("presnapshot")
    if not isinstance(snapshot, dict) or (
        not re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("sha256") or ""))
        or not isinstance(snapshot.get("size_bytes"), int)
        or isinstance(snapshot.get("size_bytes"), bool) or snapshot.get("size_bytes", 0) <= 0
        or snapshot.get("integrity") != "OPENSSL_GZIP_PASS"
        or snapshot.get("remote_path") != (
            f"/home/ubuntu/db_backups/pre-restore/{request_id}/hospital_db.sql.gz.enc"
        )
    ):
        raise AppsStartError("RESTORE_RECEIPT_PRESNAPSHOT_INVALID")
    stages = receipt.get("stages")
    if not isinstance(stages, dict) or any(
        not isinstance(stages.get(name), dict) or stages[name].get("status") != "COMPLETE"
        for name in RESTORE_STAGES
    ):
        raise AppsStartError("RESTORE_RECEIPT_STAGES_INCOMPLETE")
    verification = receipt.get("database_verification")
    if not isinstance(verification, dict) or verification.get("mysql_responded") is not True:
        raise AppsStartError("RESTORE_RECEIPT_DATABASE_CHECK_MISSING")
    expected_tables = {name.lower() for name in restore.CORE_TABLES}
    tables, counts = verification.get("core_tables"), verification.get("row_counts")
    if (
        not isinstance(tables, list)
        or not expected_tables <= {str(name).lower() for name in tables}
        or not isinstance(counts, dict)
        or not expected_tables <= {str(name).lower() for name in counts}
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for name, value in counts.items() if str(name).lower() in expected_tables
        )
    ):
        raise AppsStartError("RESTORE_RECEIPT_DATABASE_CHECK_INVALID")


def _write_private_json(path: Path, value: dict, *, exclusive=False) -> None:
    if exclusive:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(path, 0o600)
            return
        except FileExistsError as exc:
            raise AppsStartError("APPS_FOLLOWUP_ALREADY_ATTEMPTED") from exc
        except OSError as exc:
            raise AppsStartError("APPS_RECEIPT_CREATE_FAILED") from exc
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise AppsStartError("APPS_RECEIPT_WRITE_FAILED") from exc


@contextlib.contextmanager
def _request_lock(request_dir: Path):
    path = request_dir / "apps-start.lock"
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
        ):
            raise AppsStartError("APPS_FOLLOWUP_LOCK_UNTRUSTED")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AppsStartError("APPS_FOLLOWUP_ALREADY_RUNNING") from exc
        yield
    except AppsStartError:
        raise
    except OSError as exc:
        raise AppsStartError("APPS_FOLLOWUP_LOCK_UNAVAILABLE") from exc
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)


def _app_remote_script(spec: Mapping[str, str], *, start: bool) -> str:
    container, proxy = spec["container"], spec["proxy"]
    health_url = "http://IP_REDACTED:3000/__hospital_dr/health"
    before = (
        f'''test "$(docker inspect --format '{{{{.State.Running}}}}|{{{{.HostConfig.RestartPolicy.Name}}}}' "{container}")" = 'false|no'
'''
        if start else
        f'''test "$(docker inspect --format '{{{{.State.Running}}}}|{{{{.HostConfig.RestartPolicy.Name}}}}|{{{{.State.Health.Status}}}}' "{container}")" = 'true|no|healthy'
'''
    )
    start_command = f'docker start "{container}" >/dev/null' if start else ":"
    wait_block = (
        "for attempt in $(seq 1 30); do\n"
        "  docker_health=\"$(docker inspect --format '{{.State.Health.Status}}' \"$container\" 2>/dev/null || true)\"\n"
        "  http_status=\"$(curl --silent --max-time 5 --output /dev/null --write-out '%{http_code}' \"$health_url\" 2>/dev/null || true)\"\n"
        "  if [[ \"$docker_health\" == healthy && \"$http_status\" == 204 ]]; then break; fi\n"
        "  sleep 5\n"
        "done\n"
        if start else
        "docker_health=\"$(docker inspect --format '{{.State.Health.Status}}' \"$container\" 2>/dev/null || true)\"\n"
        "http_status=\"$(curl --silent --max-time 5 --output /dev/null --write-out '%{http_code}' \"$health_url\" 2>/dev/null || true)\"\n"
    )
    binding_template = (
        "{{range $port, $bindings := .HostConfig.PortBindings}}"
        "{{range $bindings}}{{printf \"%s=%s:%s \" $port .HostIp .HostPort}}{{end}}{{end}}"
    )
    env_template = "{{range .Config.Env}}{{println .}}{{end}}"
    running_template = "{{.State.Running}}|{{.HostConfig.RestartPolicy.Name}}|{{.State.Health.Status}}"
    return f'''set -euo pipefail
container="{container}"
proxy="{proxy}"
health_url="{health_url}"
command -v docker >/dev/null
command -v curl >/dev/null
! systemctl is-active --quiet "$proxy"
test "$(systemctl is-enabled "$proxy" 2>/dev/null || true)" = disabled
test -z "$(ss -H -ltn '( sport = :80 or sport = :443 )')"
endpoint_check="$(docker inspect --format '{env_template}' "$container" | awk -F= '
$1 == "DB_HOST" {{ host=$2; hc++ }}
$1 == "DB_PORT" {{ port=$2; pc++ }}
END {{ if (hc != 1 || pc != 1 || host != "{DB_HOST}" || port != "{DB_PORT}") exit 1; print "DB_ENDPOINT_PASS" }}')"
test "$endpoint_check" = DB_ENDPOINT_PASS
binding="$(docker inspect --format '{binding_template}' "$container")"
test "$binding" = '3000/tcp=IP_REDACTED:3000 '
{before}{start_command}
{wait_block}test "$(docker inspect --format '{running_template}' "$container")" = 'true|no|healthy'
test "$http_status" = 204
! systemctl is-active --quiet "$proxy"
test "$(systemctl is-enabled "$proxy" 2>/dev/null || true)" = disabled
test -z "$(ss -H -ltn '( sport = :80 or sport = :443 )')"
test "$(docker inspect --format '{binding_template}' "$container")" = '3000/tcp=IP_REDACTED:3000 '
printf 'APP_{spec['kind'].upper()}_READY\\n'
'''


class AppsOperations(restore.SystemOperations):
    def start_app_and_health(self, spec: Mapping[str, str]) -> str:
        return self._require_remote_success(
            spec["host"], _app_remote_script(spec, start=True),
            f"{spec['kind'].upper()}_APP_START_OR_HEALTH_FAILED",
        )

    def verify_app_health(self, spec: Mapping[str, str]) -> str:
        return self._require_remote_success(
            spec["host"], _app_remote_script(spec, start=False),
            f"{spec['kind'].upper()}_APP_FINAL_HEALTH_FAILED",
        )


def _validate_gates(env: Mapping[str, str], request_id: str) -> None:
    if str(env.get("DEMO_DUMP_APPS_START_ENABLED", "false")).strip().lower() != "true":
        raise AppsStartError("APPS_START_DISABLED")
    if env.get("DEMO_DUMP_APPS_START_APPROVED_REQUEST_ID") != request_id:
        raise AppsStartError("APPS_START_REQUEST_ID_NOT_AUTHORIZED")


def _safe_operations_environment(env: Mapping[str, str]) -> dict[str, str]:
    safe = restore._safe_env(env)
    for key in (
        "DR_STATE_DIR", "DR_WORKFLOW_LOCK_FILE", "DR_FAILOVER_LOCK_FILE",
        "DR_SSH_CONFIG_FILE", "DR_SSH_KNOWN_HOSTS_FILE", "SSH_KEY",
    ):
        if str(env.get(key) or "").strip():
            safe[key] = str(env[key])
    return safe


def execute_apps(args: argparse.Namespace, *, environment=None, operations=None) -> dict:
    env = dict(environment if environment is not None else os.environ)
    request_id, backup_id, checksum = restore.validate_cli_identity(args)
    _validate_gates(env, request_id)
    request_dir = _request_dir(_state_root(env), request_id)
    receipt_path = request_dir / "result.json"
    restore_receipt, raw = _read_private_json(receipt_path)
    validate_restore_receipt(
        restore_receipt, request_id=request_id, backup_id=backup_id, expected_sha256=checksum
    )
    receipt_hash = hashlib.sha256(raw).hexdigest()

    if operations is None:
        if not str(env.get("SSH_KEY") or "").strip():
            raise AppsStartError("SSH_KEY_UNAVAILABLE")
        operations = AppsOperations(_safe_operations_environment(env), Path("/"))

    result_path = request_dir / "apps_result.json"
    result = {
        "request_id": request_id, "backup_id": backup_id, "expected_sha256": checksum,
        "request_type": restore_receipt["request_type"],
        "request_origin": restore_receipt["request_origin"],
        "request_source": restore_receipt["request_source"],
        "slack_client_key": restore_receipt["slack_client_key"],
        "restore_receipt_sha256": receipt_hash,
        "target": {"instance_id": DB_INSTANCE_ID, "private_ip": DB_HOST, "port": DB_PORT},
        "status": "EXECUTING", "phase": "INITIALIZED", "started_at_utc": _utc_now(),
        "stages": {}, "dns_changed": False, "dr_active_recorded": False,
        "operator_intervention_required": False, "failure_code": None,
    }
    remote_may_need_fence = False
    with _request_lock(request_dir):
        if result_path.exists() or result_path.is_symlink():
            raise AppsStartError("APPS_FOLLOWUP_ALREADY_ATTEMPTED")
        _write_private_json(result_path, result, exclusive=True)

        def advance(phase):
            result["phase"] = phase
            result["stages"][phase] = {"status": "STARTED", "started_at_utc": _utc_now()}
            _write_private_json(result_path, result)

        def complete(phase):
            result["stages"][phase].update({"status": "COMPLETE", "completed_at_utc": _utc_now()})
            _write_private_json(result_path, result)

        try:
            with operations.locks():
                current, current_raw = _read_private_json(receipt_path)
                validate_restore_receipt(
                    current, request_id=request_id, backup_id=backup_id, expected_sha256=checksum
                )
                if hashlib.sha256(current_raw).hexdigest() != receipt_hash:
                    raise AppsStartError("RESTORE_RECEIPT_CHANGED")
                advance("TARGET_REVALIDATION")
                targets = operations.validate_targets()
                if targets != restore_receipt.get("aws_targets"):
                    raise AppsStartError("AWS_DR_TARGET_CHANGED_SINCE_RESTORE")
                result["aws_targets"] = targets
                complete("TARGET_REVALIDATION")
                advance("SSM_TRANSPORT")
                operations.prepare_ssh(targets)
                complete("SSM_TRANSPORT")
                remote_may_need_fence = True
                advance("PRESTART_FENCE_CHECK")
                operations.verify_apps_fenced()
                complete("PRESTART_FENCE_CHECK")
                for spec in APP_SPECS:
                    phase = f"{spec['kind'].upper()}_START_AND_HEALTH"
                    advance(phase)
                    if operations.start_app_and_health(spec) != f"APP_{spec['kind'].upper()}_READY":
                        raise AppsStartError(f"{spec['kind'].upper()}_APP_READY_MARKER_INVALID")
                    complete(phase)
                advance("FINAL_APP_HEALTH")
                for spec in APP_SPECS:
                    if operations.verify_app_health(spec) != f"APP_{spec['kind'].upper()}_READY":
                        raise AppsStartError(f"{spec['kind'].upper()}_FINAL_HEALTH_MARKER_INVALID")
                complete("FINAL_APP_HEALTH")
                advance("FINAL_TARGET_AND_RECEIPT_REVALIDATION")
                final_targets = operations.validate_targets()
                final_receipt, final_raw = _read_private_json(receipt_path)
                validate_restore_receipt(
                    final_receipt, request_id=request_id, backup_id=backup_id, expected_sha256=checksum
                )
                if final_targets != targets or hashlib.sha256(final_raw).hexdigest() != receipt_hash:
                    raise AppsStartError("FINAL_IDENTITY_OR_RECEIPT_REVALIDATION_FAILED")
                complete("FINAL_TARGET_AND_RECEIPT_REVALIDATION")
                result.update({
                    "status": "APPS_READY_NOT_DNS_SWITCHED",
                    "phase": "APPS_READY_NOT_DNS_SWITCHED", "completed_at_utc": _utc_now(),
                    "web_health": "HTTP_204", "emr_health": "HTTP_204",
                    "db_endpoint": {"host": DB_HOST, "port": DB_PORT},
                    "proxies_remain_stopped": True, "apps_fenced": False,
                    "dns_changed": False, "dr_active_recorded": False,
                    "operator_intervention_required": False, "failure_code": None,
                })
                _write_private_json(result_path, result)
                return result
        except Exception as exc:
            code = exc.code if isinstance(exc, (AppsStartError, restore.DemoRestoreError)) else "APPS_START_OR_HEALTH_RESULT_UNCERTAIN"
            refenced = False
            if remote_may_need_fence:
                try:
                    operations.fence_apps({})
                    operations.verify_apps_fenced()
                    refenced = True
                except Exception:
                    pass
            result.update({
                "status": "FAILED" if not remote_may_need_fence or refenced else "PARTIAL_FAILURE",
                "completed_at_utc": _utc_now(), "apps_fenced": refenced,
                "dns_changed": False, "dr_active_recorded": False,
                "operator_intervention_required": remote_may_need_fence and not refenced,
                "failure_code": code,
            })
            phase = result.get("phase")
            if phase in result.get("stages", {}):
                result["stages"][phase].update({
                    "status": "FAILED_OR_UNCERTAIN", "failure_code": code,
                    "completed_at_utc": _utc_now(),
                })
            try:
                _write_private_json(result_path, result)
            except Exception:
                result.update({
                    "status": "PARTIAL_FAILURE", "operator_intervention_required": True,
                    "failure_code": "APPS_RECEIPT_WRITE_FAILED",
                })
            return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--backup-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_apps(args)
    except (AppsStartError, restore.DemoRestoreError) as exc:
        code = exc.code if hasattr(exc, "code") else "EXECUTION_BLOCKED"
        print(f"DEMO_DUMP_APPS=BLOCKED code={code}", file=sys.stderr)
        return 1
    print(
        f"DEMO_DUMP_APPS status={result['status']} request_id={result['request_id']} "
        f"backup_id={result['backup_id']} failure_code={result.get('failure_code') or 'NONE'}",
        flush=True,
    )
    return 0 if result["status"] == "APPS_READY_NOT_DNS_SWITCHED" else (2 if result["status"] == "PARTIAL_FAILURE" else 1)


if __name__ == "__main__":
    raise SystemExit(main())
