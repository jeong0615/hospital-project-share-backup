#!/usr/bin/env python3
"""Finish the public DNS step for a verified general or emergency Dump restore.

This is a separate, one-shot operator follow-up, not a ChatOps executor. It
revalidates the terminal two-admin request and both receipts, publishes the
existing Web/EMR proxies in maintenance mode, reuses the Cloudflare transaction
helpers, and checks the public origin through Cloudflare. A live On-Prem
MySQL writer-fence verifier is not currently available, so finalization fails
before publication or DNS mutation rather than switching DNS and discovering
the missing proof afterward. This command never releases maintenance or
records DR_ACTIVE.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operations.db import demo_dump_restore_existing_dr as restore  # noqa: E402
from operations.db import demo_dump_restore_existing_dr_apps as apps  # noqa: E402
from operations.db import dump_db_dns_transaction as dns_common  # noqa: E402
from operations.db import dump_db_external_fence as external_fence  # noqa: E402
from operations.db import dump_db_public_readiness as public_readiness  # noqa: E402

REQUEST_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
RECORD_RE = re.compile(r"[0-9a-f]{32}\Z")
SAFE_CODE_RE = re.compile(r"[A-Z0-9_]{1,96}\Z")
USER_ID_RE = re.compile(r"[A-Z0-9]{2,32}\Z")
DOMAIN_RE = re.compile(r"[A-Za-z0-9.-]{1,253}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{40,64}\Z")
CIDR_RE = re.compile(r"[0-9.]+/[0-9]{1,2}\Z")
DR_EIP = "AWS_PUBLIC_IP_REDACTED"
WEB_DOMAIN = "hospital-web.pp.ua"
EMR_DOMAIN = "emr.hospital-web.pp.ua"
DNS_ACTIVE_MAINTENANCE = "DUMP_DNS_ACTIVE_MAINTENANCE_WRITES_BLOCKED"
PARTIAL = "PARTIAL_FAILURE"


class FinalizeError(RuntimeError):
    """Stable non-sensitive operator error."""

    def __init__(self, code: str):
        self.code = code if SAFE_CODE_RE.fullmatch(str(code)) else "FINALIZATION_FAILED"
        super().__init__(self.code)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid(value: str) -> str:
    try:
        canonical = str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise FinalizeError("REQUEST_ID_INVALID") from exc
    if canonical != str(value).lower() or not REQUEST_RE.fullmatch(canonical):
        raise FinalizeError("REQUEST_ID_INVALID")
    return canonical


def _read_json(path: Path, *, code: str, owner_uid: int, limit: int = 1024 * 1024) -> tuple[dict, bytes]:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size < 2 or info.st_size > limit
        ):
            raise FinalizeError(code)
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise FinalizeError(code)
        value = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(value, dict):
            raise FinalizeError(code)
        return value, raw
    except FinalizeError:
        raise
    except FileNotFoundError as exc:
        raise FinalizeError(code) from exc
    except PermissionError as exc:
        raise FinalizeError(code) from exc
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise FinalizeError(code) from exc
    finally:
        if fd is not None:
            os.close(fd)


def _atomic_json(path: Path, value: dict, *, exclusive: bool = False) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        else:
            os.replace(temporary, path)
        os.chmod(path, 0o600)
    except FileExistsError as exc:
        temporary.unlink(missing_ok=True)
        raise FinalizeError("FINALIZATION_ALREADY_ATTEMPTED") from exc
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise FinalizeError("FINALIZATION_RECEIPT_WRITE_FAILED") from exc


def _append_private(path: Path, line: str, *, owner_uid: int) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != owner_uid:
        raise FinalizeError("EXECUTION_LOG_DIRECTORY_UNTRUSTED")
    os.chmod(parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        item = os.fstat(fd)
        if not stat.S_ISREG(item.st_mode) or item.st_uid != owner_uid or item.st_nlink != 1:
            raise FinalizeError("EXECUTION_LOG_FILE_UNTRUSTED")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            fd = -1
            stream.write(line[:1000].replace("\n", " ") + "\n")
    finally:
        if fd >= 0:
            os.close(fd)


def _request_root(env: Mapping[str, str]) -> Path:
    explicit = str(env.get("DEMO_DUMP_RESTORE_STATE_DIR") or "").strip()
    root = Path(explicit) if explicit else Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "demo-dump-restores"
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise FinalizeError("RESTORE_STATE_DIRECTORY_UNAVAILABLE")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise FinalizeError("RESTORE_STATE_DIRECTORY_UNTRUSTED")
    return root


def _request_dir(root: Path, request_id: str) -> Path:
    path = root / request_id
    try:
        info = path.lstat()
    except OSError as exc:
        raise FinalizeError("RESTORE_REQUEST_DIRECTORY_UNAVAILABLE") from exc
    if (
        not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise FinalizeError("RESTORE_REQUEST_DIRECTORY_UNTRUSTED")
    return path


def validate_apps_receipt(
    receipt: dict, *, request_id: str, backup_id: str, checksum: str,
    restore_receipt_sha256: str, restore_receipt: dict,
) -> None:
    origin = str(restore_receipt.get("request_origin") or "").strip().upper()
    source_contract = apps.DUMP_REQUEST_SOURCES.get(origin)
    required_stages = {
        "TARGET_REVALIDATION", "SSM_TRANSPORT", "PRESTART_FENCE_CHECK",
        "WEB_START_AND_HEALTH", "EMR_START_AND_HEALTH", "FINAL_APP_HEALTH",
        "FINAL_TARGET_AND_RECEIPT_REVALIDATION",
    }
    stages = receipt.get("stages")
    if (
        receipt.get("request_id") != request_id or receipt.get("backup_id") != backup_id
        or str(receipt.get("expected_sha256") or "").lower() != checksum
        or source_contract is None
        or receipt.get("request_type") != "DUMP_RESTORE_FAILOVER"
        or receipt.get("request_origin") != origin
        or receipt.get("request_source") != source_contract[1]
        or receipt.get("slack_client_key") != source_contract[0]
        or receipt.get("request_origin") != restore_receipt.get("request_origin")
        or receipt.get("request_source") != restore_receipt.get("request_source")
        or receipt.get("slack_client_key") != restore_receipt.get("slack_client_key")
        or receipt.get("restore_receipt_sha256") != restore_receipt_sha256
        or receipt.get("status") != "APPS_READY_NOT_DNS_SWITCHED"
        or receipt.get("phase") != "APPS_READY_NOT_DNS_SWITCHED"
        or receipt.get("target") != restore_receipt.get("target")
        or receipt.get("db_endpoint") != {"host": restore.DB_PRIVATE_IP, "port": 3306}
        or receipt.get("web_health") != "HTTP_204" or receipt.get("emr_health") != "HTTP_204"
        or receipt.get("proxies_remain_stopped") is not True
        or receipt.get("apps_fenced") is not False
        or receipt.get("dns_changed") is not False
        or receipt.get("dr_active_recorded") is not False
        or receipt.get("operator_intervention_required") is not False
        or receipt.get("failure_code") is not None
        or not isinstance(stages, dict)
        or any(not isinstance(stages.get(name), dict) or stages[name].get("status") != "COMPLETE" for name in required_stages)
    ):
        raise FinalizeError("APPS_READY_RECEIPT_IDENTITY_OR_STATUS_INVALID")


def _read_chatops_request(database: Path, *, request_id: str, backup_id: str, checksum: str,
                          restore_receipt: dict, admin_ids: set[str]) -> dict:
    origin = str(restore_receipt.get("request_origin") or "").strip().upper()
    source_contract = apps.DUMP_REQUEST_SOURCES.get(origin)
    if (
        source_contract is None
        or restore_receipt.get("request_type") != "DUMP_RESTORE_FAILOVER"
        or restore_receipt.get("request_source") != source_contract[1]
        or restore_receipt.get("slack_client_key") != source_contract[0]
    ):
        raise FinalizeError("TWO_ADMIN_DUMP_APPROVAL_EVIDENCE_INVALID")
    try:
        info = database.lstat()
    except OSError as exc:
        raise FinalizeError("CHATOPS_APPROVAL_STATE_UNAVAILABLE") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise FinalizeError("CHATOPS_APPROVAL_STATE_PERMISSIONS_INVALID")
    try:
        uri = database.absolute().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            row = connection.execute("SELECT * FROM approval_requests WHERE request_id=?", (request_id,)).fetchone()
            another_running = connection.execute(
                "SELECT 1 FROM approval_requests WHERE status='EXECUTING' LIMIT 1"
            ).fetchone()
    except sqlite3.Error as exc:
        raise FinalizeError("CHATOPS_APPROVAL_STATE_UNAVAILABLE") from exc
    if row is None:
        raise FinalizeError("CHATOPS_APPROVED_REQUEST_NOT_FOUND")
    try:
        incidents = json.loads(row["incidents"])
        approvers = json.loads(row["approvers"])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise FinalizeError("CHATOPS_APPROVAL_STATE_INVALID") from exc
    evidence = restore_receipt.get("approval_evidence")
    receipt_approvers = evidence.get("approver_ids") if isinstance(evidence, dict) else None
    request = incidents[-1] if isinstance(incidents, list) and incidents else None
    if (
        another_running is not None
        or row["action"] != "failover" or row["slack_client_key"] != source_contract[0]
        or row["status"] != "DB_RESTORED_NOT_FAILOVER_COMPLETE"
        or row["finished_at"] is None
        or row["cancelled_by"] is not None
        or int(row["approval_required"] or 0) != 2
        or row["first_approved_at"] is None
        or row["execution_started_at"] is None
        or float(row["execution_started_at"]) > float(row["expires_at"] or 0)
        or float(row["finished_at"]) < float(row["execution_started_at"])
        or not isinstance(approvers, list) or len(approvers) != 2 or len(set(approvers)) != 2
        or not all(isinstance(item, str) and USER_ID_RE.fullmatch(item) for item in approvers)
        or not admin_ids or not set(approvers).issubset(admin_ids)
        or not isinstance(receipt_approvers, list) or set(receipt_approvers) != set(approvers)
        or not isinstance(evidence, dict)
        or evidence.get("approval_required") != 2 or evidence.get("approval_count") != 2
        or evidence.get("execution_id") != row["execution_id"] or not row["execution_id"]
        or not isinstance(request, dict)
        or request.get("request_type") != "DUMP_RESTORE_FAILOVER"
        or str(request.get("request_origin") or "").upper() != origin
        or request.get("source") != source_contract[1]
        or request.get("slack_client_key") != source_contract[0]
        or restore_receipt.get("request_origin") != origin
        or request.get("backup_id") != backup_id
        or str(request.get("backup_checksum") or "").lower() != checksum
    ):
        raise FinalizeError("TWO_ADMIN_DUMP_APPROVAL_EVIDENCE_INVALID")
    channel_id = str(row["slack_channel_id"] or "")
    message_ts = str(row["slack_message_ts"] or "")
    if not re.fullmatch(r"[A-Z0-9]{6,32}", channel_id) or not re.fullmatch(r"[0-9]{10,20}\.[0-9]{6,12}", message_ts):
        raise FinalizeError("ORIGINAL_SLACK_MESSAGE_REFERENCE_INVALID")
    return {
        "channel_id": channel_id, "message_ts": message_ts,
        "approver_ids": list(approvers), "execution_id": str(row["execution_id"]),
        "request_origin": origin, "request_source": source_contract[1],
        "slack_client_key": source_contract[0],
    }


def validate_gates(env: Mapping[str, str], request_id: str, args: argparse.Namespace) -> None:
    if env.get("DEMO_DUMP_FINALIZE_ENABLED", "false").strip().lower() != "true":
        raise FinalizeError("DUMP_FINALIZE_DISABLED")
    if env.get("DEMO_DUMP_FINALIZE_APPROVED_REQUEST_ID") != request_id:
        raise FinalizeError("DUMP_FINALIZE_REQUEST_NOT_AUTHORIZED")
    if env.get("DEMO_DUMP_FINALIZE_APPROVED_BACKUP_ID") != args.backup_id:
        raise FinalizeError("DUMP_FINALIZE_BACKUP_NOT_AUTHORIZED")
    if str(env.get("DEMO_DUMP_FINALIZE_APPROVED_SHA256") or "").lower() != str(args.expected_sha256 or "").lower():
        raise FinalizeError("DUMP_FINALIZE_CHECKSUM_NOT_AUTHORIZED")
    if not args.confirm_finalize:
        raise FinalizeError("EXPLICIT_FINALIZATION_CONFIRMATION_REQUIRED")
    if env.get("DUMP_RESTORE_EXEC_ENABLED", "false").strip().lower() != "false" or env.get("DUMP_RESTORE_EXECUTOR", "").strip():
        raise FinalizeError("RESTORE_EXECUTOR_MUST_REMAIN_DISABLED_AND_UNSET")
    if not env.get("CLOUDFLARE_API_TOKEN"):
        raise FinalizeError("CLOUDFLARE_API_CREDENTIAL_UNAVAILABLE")
    if not env.get("SLACK_FAILOVER_BOT_TOKEN"):
        raise FinalizeError("SLACK_FINAL_RESULT_CREDENTIAL_UNAVAILABLE")


def _load_root_password(env: Mapping[str, str]) -> str:
    path = Path(str(env.get("DEMO_DUMP_FINALIZE_MYSQL_SECRET_FILE") or ""))
    try:
        info = path.lstat()
    except OSError as exc:
        raise FinalizeError("MYSQL_SECRET_FILE_UNAVAILABLE") from exc
    try:
        in_tmpfs = path.resolve(strict=True).is_relative_to(Path("/dev/shm"))
        fs_type = subprocess.run(
            ["findmnt", "-n", "-o", "FSTYPE", "--target", str(path)],
            capture_output=True, text=True, check=False,
        )
    except (OSError, RuntimeError):
        in_tmpfs, fs_type = False, None
    if (
        not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size < 1 or info.st_size > 4096
        or not in_tmpfs or fs_type is None or fs_type.returncode != 0
        or fs_type.stdout.strip() != "tmpfs"
    ):
        raise FinalizeError("MYSQL_SECRET_FILE_PERMISSIONS_INVALID")
    try:
        value = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise FinalizeError("MYSQL_SECRET_FILE_UNAVAILABLE") from exc
    if not value:
        raise FinalizeError("MYSQL_SECRET_UNAVAILABLE")
    return value


def _validate_origin_pair(snapshots: dict, *, web_id: str, emr_id: str,
                          tunnel: str, expected_emr_ip: str) -> None:
    web, emr = snapshots["web"], snapshots["emr"]
    if (
        web.get("id") != web_id or emr.get("id") != emr_id
        or web["payload"].get("type") != "CNAME"
        or web["payload"].get("name") != WEB_DOMAIN
        or str(web["payload"].get("content", "")).rstrip(".").lower() != tunnel.rstrip(".").lower()
        or web["payload"].get("proxied") is not True
        or emr["payload"].get("type") != "A" or emr["payload"].get("name") != EMR_DOMAIN
        or emr["payload"].get("content") != str(ipaddress.IPv4Address(expected_emr_ip))
        or emr["payload"].get("proxied") is not True
    ):
        raise FinalizeError("CURRENT_CLOUDFLARE_RECORDS_NOT_APPROVED_ONPREM_PAIR")


def _payload_for_dr(snapshot: dict, domain: str) -> dict:
    # Preserve current proxy/TTL settings; only the origin record type/content
    # change. Cloudflare uses TTL=1 for proxied records.
    payload = dict(snapshot["payload"])
    payload.pop("data", None)
    payload.update({"type": "A", "name": domain, "content": DR_EIP})
    if payload.get("proxied") is True:
        payload["ttl"] = 1
    return payload


def _snapshot_value(path: Path, *, record_id: str, name: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise FinalizeError("CLOUDFLARE_SNAPSHOT_INVALID") from exc
    if (
        not isinstance(value, dict) or value.get("id") != record_id
        or not isinstance(value.get("payload"), dict)
        or value["payload"].get("name") != name
        or not isinstance(value["payload"].get("proxied"), bool)
        or any(key not in value["payload"] for key in ("type", "content", "ttl", "proxied"))
    ):
        raise FinalizeError("CLOUDFLARE_SNAPSHOT_INVALID")
    return value


def _pair_matches(actual: dict, expected: dict) -> bool:
    return all(actual.get(alias) == expected.get(alias) for alias in ("web", "emr"))


class CloudflareClient:
    """Read and update records only through the repository's DNS helpers."""

    def __init__(self, zone_id: str, token: str, runner: Callable = subprocess.run):
        self.client = dns_common.DNSHelperClient(zone_id=zone_id, token=token, runner=runner)

    def snapshot(self, name: str, path: Path, record_id: str) -> dict:
        result_id = self.client.snapshot(name, path, record_id)
        return _snapshot_value(path, record_id=result_id, name=name)

    def update(self, record_id: str, payload: dict, label: str) -> None:
        self.client.update(record_id, payload, label)

    def current(self, name: str, record_id: str, directory: Path, alias: str) -> dict:
        return self.snapshot(name, directory / f"current-{alias}.json", record_id)


class Operations(restore.SystemOperations):
    def __init__(self, env: Mapping[str, str], mysql_password: str):
        super().__init__(env, Path("/"))
        self.mysql_password = mysql_password
        self.publication_request_id = ""
        self.cloudflare_ipv4_cidrs: tuple[str, ...] = ()

    def validate_network(self) -> dict:
        try:
            cf_cidrs = public_readiness.load_configured_cloudflare_ipv4_cidrs(environment=self.env)
            management = public_readiness.load_management_ipv4_cidrs(self.env)
            zabbix = public_readiness.load_terraform_ipv4_cidrs("zabbix_ipv4_cidrs", environment=self.env)
            wireguard = public_readiness.load_terraform_ipv4_cidrs("wireguard_peer_ipv4_cidrs", environment=self.env)
            enabled = str(self.env.get("TF_VAR_enable_wireguard", "false")).lower() in {"1", "true", "yes", "on"}
            runner = lambda command, **kwargs: self._run(list(command))
            return public_readiness.read_and_validate_app_security_groups(
                region=self.region, cloudflare_ipv4_cidrs=cf_cidrs,
                management_ipv4_cidrs=management, zabbix_ipv4_cidrs=zabbix,
                wireguard_peer_ipv4_cidrs=wireguard, wireguard_enabled=enabled,
                expected_eip=DR_EIP, runner=runner,
            )
        except Exception as exc:
            code = getattr(exc, "code", "AWS_DR_INGRESS_OR_EIP_VALIDATION_FAILED")
            raise FinalizeError(code if SAFE_CODE_RE.fullmatch(str(code)) else "AWS_DR_INGRESS_OR_EIP_VALIDATION_FAILED") from exc

    def verify_db_write_fence(self) -> None:
        secret = restore._remote_secret_prefix({"MYSQL_ROOT_PASS": self.mysql_password})
        script = secret + r'''set -euo pipefail
umask 077
tmp="$(mktemp -d /dev/shm/hospital-dr-finalize-db.XXXXXX)"
trap 'rm -f "$tmp/mysql.cnf"; rmdir "$tmp" 2>/dev/null || true' EXIT
escaped="$(printf '%s' "$MYSQL_ROOT_PASS" | sed 's/\\/\\\\/g; s/"/\\"/g')"
printf '[client]\nuser=root\npassword="%s"\n' "$escaped" >"$tmp/mysql.cnf"
chmod 0600 "$tmp/mysql.cnf"
flags="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e 'SELECT @@global.read_only, @@global.super_read_only')"
read -r read_only super_read_only <<< "$flags"
[[ "$read_only" == 1 && "$super_read_only" == 1 ]]
for account in "root@10.20.10.%:hospital-dr-web" "root@10.20.20.%:hospital-dr-emr"; do
  user="${account%%@*}"
  rest="${account#*@}"
  host="${rest%%:*}"
  container="${rest#*:}"
  app_user="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" | awk -F= '$1 == "DB_USER" { if (seen++) exit 1; print $2 }')"
  [[ "$app_user" == "$user" ]]
  grant_host="${host//./\\.}"
  grants="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e "SHOW GRANTS FOR '$user'@'$host'")"
  [[ -n "$grants" ]]
  GRANTS="$grants" python3 - <<'PY'
import os, sys
rows = os.environ.get("GRANTS", "").splitlines()
if not rows:
    raise SystemExit(1)
for row in rows:
    lower = row.lower()
    if any(word in lower for word in ("super", "system_user", "grant option", "proxy on")):
        raise SystemExit(1)
    if " on *.* " in lower and "usage on *.*" not in lower:
        raise SystemExit(1)
    if " on `hospital_db`.* " not in lower and " usage on *.* " not in lower:
        raise SystemExit(1)
PY
  unset GRANTS
done
printf 'DB_WRITE_FENCE=VERIFIED\n'
'''
        output = self._require_remote_success("dr-db", script, "DR_DATABASE_WRITE_FENCE_NOT_VERIFIED")
        if output != "DB_WRITE_FENCE=VERIFIED":
            raise FinalizeError("DR_DATABASE_WRITE_FENCE_NOT_VERIFIED")

    def verify_apps_ready(self) -> None:
        for spec in apps.APP_SPECS:
            try:
                output = self._require_remote_success(
                    spec["host"], apps._app_remote_script(spec, start=False),
                    "APP_HEALTH_OR_DB_ENDPOINT_REVALIDATION_FAILED",
                )
            except Exception as exc:
                raise FinalizeError("APP_HEALTH_OR_DB_ENDPOINT_REVALIDATION_FAILED") from exc
            if output != f"APP_{spec['kind'].upper()}_READY":
                raise FinalizeError("APP_HEALTH_OR_DB_ENDPOINT_REVALIDATION_FAILED")

    def _remote_fence(self, host: str, role: str, request_id: str, cidrs: tuple[str, ...], command: str) -> None:
        helper = Path(__file__).with_name("dump_db_external_fence.py")
        try:
            helper_source = base64.b64encode(helper.read_bytes()).decode("ascii")
            validated_cidrs = external_fence.validate_cloudflare_ipv4_cidrs(list(cidrs))
        except (OSError, external_fence.FenceError) as exc:
            raise FinalizeError("DUMP_EXTERNAL_FENCE_HELPER_OR_CIDRS_INVALID") from exc
        helper_args = ["--role", role, "--cutover-id", request_id]
        for cidr in validated_cidrs:
            helper_args.extend(("--cloudflare-ipv4-cidr", cidr))
        safe_args = " ".join(shlex.quote(item) for item in helper_args)
        if command not in {"prepare", "verify-prepared", "restore-strict"}:
            raise FinalizeError("DUMP_EXTERNAL_FENCE_COMMAND_INVALID")
        script = f'''set -euo pipefail
umask 077
tmp="$(mktemp -d /dev/shm/hospital-dr-finalize-fence.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
printf '%s' '{helper_source}' | base64 -d > "$tmp/fence.py"
chmod 0700 "$tmp/fence.py"
'''
        if command != "verify-prepared":
            script += '''python3 "$tmp/fence.py" ensure >/dev/null
'''
        script += f'''python3 "$tmp/fence.py" {command} {safe_args} >/dev/null
'''
        if command == "restore-strict":
            script += '''python3 "$tmp/fence.py" verify >/dev/null
'''
        else:
            script += f'''python3 "$tmp/fence.py" verify-prepared {safe_args} >/dev/null
'''
        script += f'''printf 'DUMP_FENCE={role.upper()}_{command.upper().replace('-', '_')}_PASS\\n'
'''
        output = self._require_remote_success(host, script, "DUMP_EXTERNAL_FENCE_TRANSITION_FAILED")
        expected = f"DUMP_FENCE={role.upper()}_{command.upper().replace('-', '_')}_PASS"
        if output != expected:
            raise FinalizeError("DUMP_EXTERNAL_FENCE_TRANSITION_UNVERIFIED")

    def _restore_strict_fences(self, request_id: str) -> bool:
        success = True
        for host, role in (("dr-web", "web"), ("dr-doc", "emr")):
            try:
                self._remote_fence(host, role, request_id, self.cloudflare_ipv4_cidrs, "restore-strict")
            except Exception:
                success = False
        return success

    def prepare_publication(self, request_id: str, token: str, cloudflare_ipv4_cidrs: tuple[str, ...]) -> None:
        self.publication_request_id = request_id
        self.cloudflare_ipv4_cidrs = external_fence.validate_cloudflare_ipv4_cidrs(list(cloudflare_ipv4_cidrs))
        self._remote_fence("dr-doc", "emr", request_id, self.cloudflare_ipv4_cidrs, "prepare")
        self._require_remote_success(
            "dr-doc",
            "set -euo pipefail\n! systemctl is-active --quiet apache2\ntest \"$(systemctl is-enabled apache2 2>/dev/null || true)\" = disabled\nsystemctl start apache2 >/dev/null\nsystemctl is-active --quiet apache2\ntest \"$(systemctl is-enabled apache2 2>/dev/null || true)\" = disabled\n",
            "EMR_PROXY_START_FAILED",
        )
        content = (
            "# request-scoped Dump maintenance; all user traffic remains fenced\n"
            "map $host $hospital_dr_dump_maintenance { default 1; }\n"
            "map $hospital_dr_dump_maintenance $hospital_dr_dump_maintenance_cache_control { default \"\"; 1 \"no-store, private\"; }\n"
            "map $http_x_hospital_dr_probe $hospital_dr_dump_probe_authorized { default 0; \""
            + token + "\" 1; }\n"
        )
        encoded = content.encode("ascii").hex()
        script = f'''set -euo pipefail
test "$(docker inspect --format '{{{{.State.Running}}}}|{{{{.HostConfig.RestartPolicy.Name}}}}|{{{{.State.Health.Status}}}}' hospital-dr-web)" = 'true|no|healthy'
test "$(docker inspect --format '{{{{.State.Running}}}}|{{{{.HostConfig.RestartPolicy.Name}}}}|{{{{.State.Health.Status}}}}' hospital-dr-emr)" = 'true|no|healthy'
test -z "$(ss -H -ltn '( sport = :80 or sport = :443 )')"
backup_dir="/var/lib/hospital-dr/demo-dump-finalize/{request_id}"
install -d -o root -g root -m 0700 "$backup_dir"
test "$(stat -c '%u:%a' "$backup_dir")" = '0:700'
mode_file=/etc/nginx/conf.d/hospital-dr-dump-mode.conf
backup_file="$backup_dir/hospital-dr-dump-mode.conf.before"
test -f "$mode_file" && test ! -L "$mode_file"
test ! -e "$backup_file"
cp -a "$mode_file" "$backup_file"
chown root:root "$backup_file"
tmp_file="$(mktemp /etc/nginx/conf.d/.hospital-dr-dump-mode.XXXXXX)"
trap 'rm -f "$tmp_file"' EXIT
printf '%s' '{encoded}' | xxd -r -p > "$tmp_file"
chown root:root "$tmp_file"
chmod 0600 "$tmp_file"
mv -f "$tmp_file" "$mode_file"
test "$(readlink -f /etc/nginx/sites-enabled/hospital-web)" = /etc/nginx/sites-available/hospital-web
grep -Fq 'include /etc/nginx/snippets/hospital-dr-dump-maintenance.inc;' /etc/nginx/sites-available/hospital-web
grep -Fq 'location = /__hospital_dr/health {{' /etc/nginx/sites-available/hospital-web
nginx -t >/dev/null
systemctl start nginx >/dev/null
systemctl is-active --quiet nginx
test "$(systemctl is-enabled nginx 2>/dev/null || true)" = disabled
test -n "$(ss -H -ltn '( sport = :80 or sport = :443 )')"
'''
        self._remote_fence("dr-web", "web", request_id, self.cloudflare_ipv4_cidrs, "prepare")
        self._require_remote_success("dr-web", script, "PUBLICATION_PREPARATION_FAILED")
        self._verify_maintenance_health(token)

    def _verify_maintenance_health(self, token: str) -> None:
        script = f'''set -euo pipefail
command -v curl >/dev/null
tmp="$(mktemp -d /dev/shm/hospital-dr-finalize-web.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
printf 'X-Hospital-DR-Probe: %s\\n' '{token}' > "$tmp/probe-header"
chmod 0600 "$tmp/probe-header"
for host in {WEB_DOMAIN} {EMR_DOMAIN}; do
  status="$(curl --silent --show-error --max-time 10 --resolve "$host:443:IP_REDACTED" \\
    --cacert /etc/nginx/ssl/hospital-web.crt --header "@$tmp/probe-header" \\
    -D "$tmp/headers" -o "$tmp/body" -w '%{{http_code}}' "https://$host/__hospital_dr/health" 2>/dev/null || true)"
  test "$status" = 204
  test ! -s "$tmp/body"
  grep -qi '^Cache-Control:.*no-store' "$tmp/headers"
  status="$(curl --silent --max-time 10 --resolve "$host:443:IP_REDACTED" \\
    --cacert /etc/nginx/ssl/hospital-web.crt -o /dev/null -w '%{{http_code}}' "https://$host/" 2>/dev/null || true)"
  test "$status" = 503
done
status="$(curl --silent --max-time 10 --resolve "{WEB_DOMAIN}:443:IP_REDACTED" \\
  --cacert /etc/nginx/ssl/hospital-web.crt --header "@$tmp/probe-header" \\
  -o "$tmp/body" -w '%{{http_code}}' "https://{WEB_DOMAIN}/emr/__hospital_dr/health" 2>/dev/null || true)"
test "$status" = 204 && test ! -s "$tmp/body"
for path in /emr/ /api/patients; do
  status="$(curl --silent --max-time 10 --resolve "{WEB_DOMAIN}:443:IP_REDACTED" \\
    --cacert /etc/nginx/ssl/hospital-web.crt -o "$tmp/body" -w '%{{http_code}}' "https://{WEB_DOMAIN}$path" 2>/dev/null || true)"
  test "$status" = 503
done
printf 'PUBLICATION=MAINTENANCE_HEALTH_PASS\\n'
'''
        output = self._require_remote_success("dr-web", script, "MAINTENANCE_OR_ORIGIN_HEALTH_NOT_VERIFIED")
        if output != "PUBLICATION=MAINTENANCE_HEALTH_PASS":
            raise FinalizeError("MAINTENANCE_OR_ORIGIN_HEALTH_NOT_VERIFIED")

    def stop_publication_and_restore(self, request_id: str) -> bool:
        strict_ok = self._restore_strict_fences(request_id)
        web_restored = False
        emr_stopped = False
        web_script = f'''set -euo pipefail
systemctl stop nginx >/dev/null 2>&1 || true
backup_file="/var/lib/hospital-dr/demo-dump-finalize/{request_id}/hospital-dr-dump-mode.conf.before"
mode_file=/etc/nginx/conf.d/hospital-dr-dump-mode.conf
map_restored=0
if test -f "$backup_file" && test ! -L "$backup_file"; then
  cp -a "$backup_file" "$mode_file.rollback"
  mv -f "$mode_file.rollback" "$mode_file"
  nginx -t >/dev/null
  map_restored=1
fi
! systemctl is-active --quiet nginx
test -z "$(ss -H -ltn '( sport = :80 or sport = :443 )')"
printf 'PUBLICATION=WEB_STOPPED_MAP_RESTORED:%s\\n' "$map_restored"
'''
        try:
            output = self._require_remote_success("dr-web", web_script, "PUBLICATION_CONTAINMENT_FAILED")
            web_restored = output == "PUBLICATION=WEB_STOPPED_MAP_RESTORED:1"
        except Exception:
            web_restored = False
        try:
            self._require_remote_success(
                "dr-doc",
                "set -euo pipefail\nsystemctl stop apache2 >/dev/null 2>&1 || true\n! systemctl is-active --quiet apache2\ntest -z \"$(ss -H -ltn '( sport = :80 or sport = :443 )')\"\n",
                "PUBLICATION_CONTAINMENT_FAILED",
            )
            emr_stopped = True
        except Exception:
            emr_stopped = False
        return strict_ok and web_restored and emr_stopped

    def verify_maintenance(self, token: str) -> None:
        if not self.publication_request_id or not self.cloudflare_ipv4_cidrs:
            raise FinalizeError("PUBLICATION_FENCE_CONTEXT_UNAVAILABLE")
        self._remote_fence(
            "dr-web", "web", self.publication_request_id,
            self.cloudflare_ipv4_cidrs, "verify-prepared",
        )
        self._remote_fence(
            "dr-doc", "emr", self.publication_request_id,
            self.cloudflare_ipv4_cidrs, "verify-prepared",
        )
        self._verify_maintenance_health(token)

    def mark_dr_state(self, state: str) -> None:
        if state != "PARTIAL_FAILURE":
            raise FinalizeError("UNAUTHORIZED_DR_STATE_TRANSITION")
        helper = REPO_ROOT / "operations/runtime/dr_state.sh"
        command = ["bash", "-c", 'source "$1"; dr_state_write PARTIAL_FAILURE', "dr-state", str(helper)]
        result = self._run(command)
        if result.returncode:
            raise FinalizeError("DR_PARTIAL_STATE_WRITE_FAILED")


@contextlib.contextmanager
def _finalize_lock(request_dir: Path):
    path = request_dir / "finalize.lock"
    fd = None
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise FinalizeError("FINALIZATION_LOCK_UNTRUSTED")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise FinalizeError("FINALIZATION_ALREADY_RUNNING") from exc
        yield
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)


def _validate_receipts(args: argparse.Namespace, env: Mapping[str, str]) -> tuple[dict, bytes, dict, bytes, Path]:
    request_id, backup_id, checksum = restore.validate_cli_identity(args)
    root = _request_root(env)
    request_dir = _request_dir(root, request_id)
    restore_receipt, restore_raw = apps._read_private_json(request_dir / "result.json")
    apps.validate_restore_receipt(restore_receipt, request_id=request_id, backup_id=backup_id, expected_sha256=checksum)
    apps_receipt, apps_raw = apps._read_private_json(request_dir / "apps_result.json")
    validate_apps_receipt(
        apps_receipt, request_id=request_id, backup_id=backup_id, checksum=checksum,
        restore_receipt_sha256=hashlib.sha256(restore_raw).hexdigest(),
        restore_receipt=restore_receipt,
    )
    backup = Path(env.get("DUMP_BACKUP_DIR", "")) / backup_id
    try:
        pair = restore.validate_backup_pair(backup, checksum)
    except Exception as exc:
        raise FinalizeError("SELECTED_DUMP_OR_MASTER_STATUS_REVALIDATION_FAILED") from exc
    if not isinstance(pair, dict) or str(pair.get("sha256", "")).lower() != checksum:
        raise FinalizeError("SELECTED_DUMP_CHECKSUM_MISMATCH")
    return restore_receipt, restore_raw, apps_receipt, apps_raw, request_dir


def _write_token_file(request_dir: Path) -> tuple[str, Path]:
    token = __import__("secrets").token_urlsafe(32)
    if not TOKEN_RE.fullmatch(token):
        raise FinalizeError("PROBE_TOKEN_GENERATION_FAILED")
    path = request_dir / "finalize-probe-token"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(token)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise FinalizeError("FINALIZATION_ALREADY_ATTEMPTED") from exc
    except OSError as exc:
        raise FinalizeError("PROBE_TOKEN_WRITE_FAILED") from exc
    return token, path


def _read_token_file(request_dir: Path) -> str:
    path = request_dir / "finalize-probe-token"
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 40 <= metadata.st_size <= 64
        ):
            raise FinalizeError("PROBE_TOKEN_FILE_UNTRUSTED")
        value = path.read_text(encoding="ascii")
    except FinalizeError:
        raise
    except (OSError, UnicodeError) as exc:
        raise FinalizeError("PROBE_TOKEN_FILE_UNAVAILABLE") from exc
    if not TOKEN_RE.fullmatch(value):
        raise FinalizeError("PROBE_TOKEN_FILE_INVALID")
    return value


def _read_dns_pair(client, *, web_id: str, emr_id: str, directory: Path) -> dict:
    web = client.current(WEB_DOMAIN, web_id, directory, "web")
    emr = client.current(EMR_DOMAIN, emr_id, directory, "emr")
    return {"web": web, "emr": emr}


def _is_origin_or_dr(current: dict, origin: dict, desired: dict) -> bool:
    for alias in ("web", "emr"):
        if current[alias] != origin[alias] and current[alias] != desired[alias]:
            return False
    return True


def _conditional_dns_rollback(client, *, origin: dict, desired: dict, ids: dict,
                              directory: Path, operations, token: str) -> bool:
    try:
        operations.verify_db_write_fence()
        operations.verify_maintenance(token)
        current = _read_dns_pair(client, web_id=ids["web"], emr_id=ids["emr"], directory=directory)
        if not _is_origin_or_dr(current, origin, desired):
            return False
        for alias, domain in (("web", WEB_DOMAIN), ("emr", EMR_DOMAIN)):
            latest = client.current(domain, ids[alias], directory, f"rollback-{alias}")
            if latest != origin[alias] and latest != desired[alias]:
                return False
            if latest != origin[alias]:
                client.update(ids[alias], origin[alias]["payload"], f"demo-rollback:{alias}")
        restored = _read_dns_pair(client, web_id=ids["web"], emr_id=ids["emr"], directory=directory)
        return _pair_matches(restored, origin)
    except Exception:
        return False


def _stored_dns_pairs(result: dict) -> tuple[dict, dict, dict]:
    snapshots = result.get("dns_snapshot")
    targets = result.get("dns_target")
    if not isinstance(snapshots, dict) or not isinstance(targets, dict):
        raise FinalizeError("DNS_ROLLBACK_EVIDENCE_MISSING")
    origin: dict = {}
    desired: dict = {}
    record_ids: dict = {}
    for alias, name in (("web", WEB_DOMAIN), ("emr", EMR_DOMAIN)):
        item = snapshots.get(alias)
        target = targets.get(alias)
        original_payload = (
            {key: item[key] for key in ("type", "name", "content", "ttl", "proxied")}
            if isinstance(item, dict)
            and all(key in item for key in ("type", "name", "content", "ttl", "proxied"))
            else {}
        )
        if isinstance(item, dict) and "data" in item:
            original_payload["data"] = item["data"]
        if (
            not isinstance(item, dict) or not isinstance(target, dict)
            or item.get("type") not in {"A", "CNAME"}
            or item.get("name") != name or not isinstance(item.get("content"), str)
            or not isinstance(item.get("ttl"), int)
            or not isinstance(item.get("proxied"), bool)
            or not RECORD_RE.fullmatch(str(item.get("record_id") or ""))
            or target != _payload_for_dr({"payload": original_payload}, name)
        ):
            raise FinalizeError("DNS_ROLLBACK_EVIDENCE_INVALID")
        record_id = item["record_id"]
        origin[alias] = {
            "id": record_id,
            "payload": original_payload,
        }
        desired[alias] = {"id": record_id, "payload": target}
        record_ids[alias] = record_id
    if (
        origin["web"]["payload"].get("type") != "CNAME"
        or origin["web"]["payload"].get("proxied") is not True
        or origin["emr"]["payload"].get("type") != "A"
        or origin["emr"]["payload"].get("proxied") is not True
        or origin["web"]["id"] == origin["emr"]["id"]
    ):
        raise FinalizeError("DNS_ROLLBACK_ORIGIN_NOT_APPROVED")
    return origin, desired, record_ids


def _record_ids_from_environment(env: Mapping[str, str]) -> dict[str, str]:
    ids = {
        "web": str(
            env.get("DR_CF_WEB_RECORD_ID_EXPECTED")
            or env.get("CF_RECORD_ID_EXPECTED")
            or env.get("CF_RECORD_ID")
            or ""
        ),
        "emr": str(
            env.get("DR_CF_EMR_RECORD_ID_EXPECTED")
            or env.get("CF_EMR_RECORD_ID_EXPECTED")
            or env.get("CF_EMR_RECORD_ID")
            or ""
        ),
    }
    if any(not RECORD_RE.fullmatch(value) for value in ids.values()) or ids["web"] == ids["emr"]:
        raise FinalizeError("CLOUDFLARE_RECORD_ID_INVALID")
    return ids


def _require_onprem_write_fence(operations, env: Mapping[str, str]) -> None:
    """Require a live On-Prem DB proof before any public/DNS mutation.

    Do not accept environment flags, receipts, or operator assertions here.
    The production Operations adapter currently has no direct On-Prem MySQL
    query path; absence of a live verifier is therefore a hard stop.
    """
    verifier = getattr(operations, "verify_onprem_write_fence", None)
    if not callable(verifier):
        raise FinalizeError("ONPREM_DB_READONLY_PROBE_UNAVAILABLE")
    expected_uuid = str(env.get("ONPREM_DB_SERVER_UUID_EXPECTED") or "").lower()
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        expected_uuid,
    ):
        raise FinalizeError("ONPREM_DB_SERVER_IDENTITY_NOT_PINNED")
    try:
        evidence = verifier()
    except FinalizeError:
        raise
    except Exception as exc:
        raise FinalizeError("ONPREM_DB_READONLY_PROBE_FAILED") from exc

    # A single boolean is not proof. A future live verifier must return the
    # identity and both server-enforced read-only values from its SQL query.
    server_uuid = evidence.get("server_uuid") if isinstance(evidence, dict) else None
    if (
        not isinstance(evidence, dict)
        or evidence.get("probe_source") != "LIVE_MYSQL_QUERY"
        or evidence.get("host") != "IP_REDACTED"
        or evidence.get("port") != 3306
        or not isinstance(server_uuid, str) or server_uuid.lower() != expected_uuid
        or type(evidence.get("read_only")) is not int or evidence.get("read_only") != 1
        or type(evidence.get("super_read_only")) is not int or evidence.get("super_read_only") != 1
        or evidence.get("writer_block_scope") != "GLOBAL_SUPER_READ_ONLY"
    ):
        raise FinalizeError("ONPREM_DB_READONLY_PROOF_INVALID")


def _post_slack(token: str, request: dict, text: str) -> bool:
    payload = {
        "channel": request["channel_id"], "thread_ts": request["message_ts"],
        "text": text, "unfurl_links": False, "unfurl_media": False,
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage", data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read(65536).decode("utf-8"))
        return bool(result.get("ok"))
    except (OSError, TimeoutError, ValueError, urllib.error.URLError, json.JSONDecodeError):
        return False


def _append_chatops_log(env: Mapping[str, str], request_id: str, event: str) -> None:
    configured = str(env.get("CHATOPS_EXECUTION_LOG_DIR") or "").strip()
    if configured:
        directory = Path(configured)
    else:
        db = Path(env.get("CHATOPS_STATE_DB", ""))
        directory = db.parent / "execution-logs"
    _append_private(directory / f"{request_id}.log", f"[{_now()}] {event}", owner_uid=os.geteuid())


def _execute_finalization_once(
    args: argparse.Namespace, *, environment: Mapping[str, str] | None = None,
    operations=None, cloudflare=None,
    public_health_checker: Callable = dns_common.check_public_health,
    slack_poster: Callable = _post_slack,
    clock: Callable = _now,
) -> dict:
    env = dict(environment if environment is not None else os.environ)
    request_id, backup_id, checksum = restore.validate_cli_identity(args)
    validate_gates(env, request_id, args)
    mysql_password = _load_root_password(env)
    root = _request_root(env)
    request_dir = _request_dir(root, request_id)
    restore_receipt, restore_raw, apps_receipt, apps_raw, request_dir = _validate_receipts(args, env)
    admins = {item.strip() for item in env.get("SLACK_ADMIN_USER_IDS", "").split(",") if item.strip()}
    if len(admins) < 2 or not all(USER_ID_RE.fullmatch(item) for item in admins):
        raise FinalizeError("SLACK_ADMIN_ALLOWLIST_INVALID")
    chat_request = _read_chatops_request(
        Path(env.get("CHATOPS_STATE_DB", "")), request_id=request_id,
        backup_id=backup_id, checksum=checksum, restore_receipt=restore_receipt,
        admin_ids=admins,
    )
    if operations is None:
        if not env.get("SSH_KEY"):
            raise FinalizeError("SSH_KEY_UNAVAILABLE")
        operations = Operations(env, mysql_password)
    if cloudflare is None:
        zone = str(env.get("CF_ZONE_ID") or "")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", zone):
            raise FinalizeError("CLOUDFLARE_ZONE_ID_INVALID")
        cloudflare = CloudflareClient(zone, env["CLOUDFLARE_API_TOKEN"])

    attempt_path = request_dir / "finalize_result.json"
    log_path = request_dir / "finalize.log"
    result = {
        "request_id": request_id, "backup_id": backup_id, "expected_sha256": checksum,
        "request_type": "DUMP_RESTORE_FAILOVER",
        "request_origin": chat_request["request_origin"],
        "request_source": chat_request["request_source"],
        "slack_client_key": chat_request["slack_client_key"],
        "restore_receipt_sha256": hashlib.sha256(restore_raw).hexdigest(),
        "apps_receipt_sha256": hashlib.sha256(apps_raw).hexdigest(),
        "status": "EXECUTING", "phase": "INITIALIZED", "started_at_utc": clock(),
        "stages": {}, "dns_changed": False, "dns_change_attempted": False,
        "writes_opened": False, "dr_active_recorded": False,
        "automatic_rollback_allowed": False, "operator_intervention_required": False,
        "rto": "NOT_MEASURED", "rpo": "NOT_MEASURED", "failure_code": None,
    }
    dns_mutation_attempted = False
    publication_started = False
    token = ""
    snapshots: dict = {}
    desired: dict = {}
    record_ids: dict = {}
    snapshot_dir = request_dir / "finalize-dns-snapshot"

    def emit(phase: str, status: str) -> None:
        if not re.fullmatch(r"[A-Z0-9_]{1,80}", phase) or not re.fullmatch(r"[A-Z0-9_]{1,80}", status):
            raise FinalizeError("AUDIT_EVENT_INVALID")
        now = clock()
        result["phase"] = phase
        result["stages"].setdefault(phase, {"started_at_utc": now})["status"] = status
        result["stages"][phase]["updated_at_utc"] = now
        _atomic_json(attempt_path, result, exclusive=not attempt_path.exists())
        line = f"DUMP_FINALIZE request_id={request_id} phase={phase} status={status}"
        _append_private(log_path, line, owner_uid=os.geteuid())
        _append_chatops_log(env, request_id, line)

    with _finalize_lock(request_dir):
        if attempt_path.exists() or attempt_path.is_symlink():
            raise FinalizeError("FINALIZATION_ALREADY_ATTEMPTED")
        with operations.locks():
            # Re-read both receipts and the completed ChatOps row under the shared DR lock.
            current_restore, current_restore_raw = apps._read_private_json(request_dir / "result.json")
            current_apps, current_apps_raw = apps._read_private_json(request_dir / "apps_result.json")
            if current_restore_raw != restore_raw or current_apps_raw != apps_raw:
                raise FinalizeError("RESTORE_OR_APPS_RECEIPT_CHANGED")
            current_chat_request = _read_chatops_request(
                Path(env["CHATOPS_STATE_DB"]), request_id=request_id, backup_id=backup_id,
                checksum=checksum, restore_receipt=current_restore, admin_ids=admins,
            )
            if current_chat_request != chat_request:
                raise FinalizeError("CHATOPS_APPROVAL_CHANGED_DURING_FINALIZATION")
            if operations.validate_targets() != restore_receipt.get("aws_targets"):
                raise FinalizeError("AWS_DR_TARGET_CHANGED_SINCE_RESTORE")
            initial_network = operations.validate_network()
            cloudflare_cidrs = tuple(initial_network.get("cloudflare_ipv4_cidrs", ()))
            if not cloudflare_cidrs:
                raise FinalizeError("CLOUDFLARE_ORIGIN_INGRESS_NOT_VERIFIED")
            state_file = Path(
                env.get("DR_STATE_FILE")
                or (Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "dr_state")
            )
            try:
                state = state_file.read_text(encoding="ascii").strip()
            except OSError as exc:
                raise FinalizeError("DR_STATE_UNAVAILABLE") from exc
            if state not in {"IDLE", "FAILED"}:
                raise FinalizeError("DR_STATE_NOT_SAFE_FOR_DUMP_FINALIZATION")

            # The current app image uses root-scoped DB grants. Keep MySQL
            # read-only and reject any remote app account with global grants.
            operations.prepare_ssh(restore_receipt["aws_targets"])
            operations.verify_db_write_fence()
            operations.verify_apps_ready()
            emit("ONPREM_WRITE_FENCE", "STARTED")
            _require_onprem_write_fence(operations, env)
            result["onprem_write_fence"] = {
                "host": "IP_REDACTED", "port": 3306,
                "server_uuid": str(env["ONPREM_DB_SERVER_UUID_EXPECTED"]).lower(),
                "read_only": True, "super_read_only": True,
                "verified_at_utc": clock(),
            }
            emit("ONPREM_WRITE_FENCE", "COMPLETE")
            token, _token_path = _write_token_file(request_dir)
            emit("PRECHECK", "COMPLETE")
            result["approval"] = {
                "approval_required": 2, "approval_count": 2,
                "approver_ids": chat_request["approver_ids"],
                "execution_id": chat_request["execution_id"],
                "request_origin": chat_request["request_origin"],
                "request_source": chat_request["request_source"],
                "slack_client_key": chat_request["slack_client_key"],
            }

            snapshot_dir.mkdir(mode=0o700)
            if stat.S_IMODE(snapshot_dir.stat().st_mode) != 0o700:
                raise FinalizeError("DNS_SNAPSHOT_DIRECTORY_PERMISSIONS_INVALID")
            record_ids = _record_ids_from_environment(env)
            tunnel = str(env.get("ONPREM_TUNNEL_HOST") or "")
            origin_emr = str(env.get("ONPREM_EMR_DNS_IP_EXPECTED") or "")
            if not DOMAIN_RE.fullmatch(tunnel) or not origin_emr:
                raise FinalizeError("APPROVED_ONPREM_DNS_ORIGIN_CONFIG_REQUIRED")
            try:
                origin_emr = str(ipaddress.IPv4Address(origin_emr))
            except ValueError as exc:
                raise FinalizeError("APPROVED_ONPREM_DNS_ORIGIN_CONFIG_INVALID") from exc
            emit("PUBLICATION_PREPARATION", "STARTED")
            publication_started = True
            operations.prepare_publication(request_id, token, cloudflare_cidrs)
            operations.verify_db_write_fence()
            operations.verify_maintenance(token)
            if operations.validate_targets() != restore_receipt.get("aws_targets"):
                raise FinalizeError("AWS_DR_TARGET_CHANGED_DURING_PUBLICATION_PREPARATION")
            prepared_network = operations.validate_network()
            if tuple(prepared_network.get("cloudflare_ipv4_cidrs", ())) != cloudflare_cidrs:
                raise FinalizeError("CLOUDFLARE_INGRESS_CHANGED_DURING_PUBLICATION_PREPARATION")
            operations.verify_db_write_fence()
            emit("PUBLICATION_PREPARATION", "COMPLETE")

            for alias, domain in (("web", WEB_DOMAIN), ("emr", EMR_DOMAIN)):
                snap_path = snapshot_dir / f"{alias}.json"
                record = cloudflare.snapshot(domain, snap_path, record_ids[alias])
                snapshots[alias] = _snapshot_value(snap_path, record_id=record_ids[alias], name=domain)
            _validate_origin_pair(
                snapshots, web_id=record_ids["web"], emr_id=record_ids["emr"],
                tunnel=tunnel, expected_emr_ip=origin_emr,
            )
            current_before = _read_dns_pair(
                cloudflare, web_id=record_ids["web"], emr_id=record_ids["emr"], directory=snapshot_dir,
            )
            if not _pair_matches(current_before, snapshots):
                raise FinalizeError("CLOUDFLARE_DNS_CHANGED_AFTER_SNAPSHOT")
            desired = {
                "web": _payload_for_dr(snapshots["web"], WEB_DOMAIN),
                "emr": _payload_for_dr(snapshots["emr"], EMR_DOMAIN),
            }
            result["dns_snapshot"] = {
                alias: {"record_id": snapshots[alias]["id"], **snapshots[alias]["payload"]}
                for alias in ("web", "emr")
            }
            result["dns_target"] = desired
            emit("ONPREM_WRITE_FENCE_RECHECK", "STARTED")
            _require_onprem_write_fence(operations, env)
            result["onprem_write_fence"] = {
                "host": "IP_REDACTED", "port": 3306,
                "server_uuid": str(env["ONPREM_DB_SERVER_UUID_EXPECTED"]).lower(),
                "read_only": True, "super_read_only": True,
                "verified_at_utc": clock(),
            }
            emit("ONPREM_WRITE_FENCE_RECHECK", "COMPLETE")
            emit("DNS_TRANSACTION", "STARTED")
            dns_mutation_attempted = True
            result["dns_change_attempted"] = True
            _atomic_json(attempt_path, result)
            for alias in ("web", "emr"):
                # Recheck before each PUT; the existing Cloudflare API has no
                # compare-and-swap, so unexpected concurrent edits fail closed.
                latest = cloudflare.current(
                    WEB_DOMAIN if alias == "web" else EMR_DOMAIN,
                    record_ids[alias], snapshot_dir, f"before-{alias}-put",
                )
                allowed = (snapshots[alias], {"id": record_ids[alias], "payload": desired[alias]})
                if latest not in allowed:
                    raise FinalizeError("CLOUDFLARE_DNS_CHANGED_DURING_TRANSACTION")
                cloudflare.update(record_ids[alias], desired[alias], f"demo-dump:{alias}")
            current_after = _read_dns_pair(
                cloudflare, web_id=record_ids["web"], emr_id=record_ids["emr"], directory=snapshot_dir,
            )
            desired_records = {
                alias: {"id": record_ids[alias], "payload": desired[alias]}
                for alias in ("web", "emr")
            }
            if not _pair_matches(current_after, desired_records):
                raise FinalizeError("CLOUDFLARE_DNS_READBACK_MISMATCH")
            result["dns_changed"] = True
            emit("DNS_TRANSACTION", "COMPLETE")

            if operations.validate_targets() != restore_receipt.get("aws_targets"):
                raise FinalizeError("AWS_DR_TARGET_CHANGED_AFTER_DNS_SWITCH")
            if not _pair_matches(
                _read_dns_pair(cloudflare, web_id=record_ids["web"], emr_id=record_ids["emr"], directory=snapshot_dir),
                desired_records,
            ):
                raise FinalizeError("CLOUDFLARE_DNS_CHANGED_BEFORE_PUBLIC_HEALTH")

            emit("PUBLIC_HEALTH", "STARTED")
            try:
                cf_cidrs = public_readiness.load_configured_cloudflare_ipv4_cidrs(environment=env)
                for domain in (WEB_DOMAIN, EMR_DOMAIN):
                    public_health_checker(
                        host=domain, token=token, cloudflare_ipv4_cidrs=cf_cidrs,
                        attempts=int(env.get("DEMO_DUMP_PUBLIC_HEALTH_ATTEMPTS", "6")),
                        interval_seconds=int(env.get("DEMO_DUMP_PUBLIC_HEALTH_INTERVAL_SECONDS", "5")),
                    )
            except Exception as exc:
                raise FinalizeError(getattr(exc, "code", "PUBLIC_CLOUDFLARE_HEALTH_FAILED")) from exc
            operations.verify_db_write_fence()
            operations.verify_maintenance(token)
            if operations.validate_targets() != restore_receipt.get("aws_targets"):
                raise FinalizeError("AWS_DR_TARGET_CHANGED_AFTER_PUBLIC_HEALTH")
            if tuple(operations.validate_network().get("cloudflare_ipv4_cidrs", ())) != cloudflare_cidrs:
                raise FinalizeError("CLOUDFLARE_INGRESS_CHANGED_AFTER_PUBLIC_HEALTH")
            if not _pair_matches(
                _read_dns_pair(cloudflare, web_id=record_ids["web"], emr_id=record_ids["emr"], directory=snapshot_dir),
                desired_records,
            ):
                raise FinalizeError("CLOUDFLARE_DNS_CHANGED_AFTER_PUBLIC_HEALTH")
            result["public_health"] = {
                "web": "CLOUDFLARE_TLS_204_DR_PROBE", "emr": "CLOUDFLARE_TLS_204_DR_PROBE",
                "origin_evidence": "REQUEST_SCOPED_RANDOM_PROBE_TOKEN_ONLY_INSTALLED_ON_APPROVED_DR_WEB",
            }
            emit("PUBLIC_HEALTH", "COMPLETE")

            # The On-Prem application/DB path cannot be remotely fenced or
            # proven inactive from the current managed runtime. Leave all user
            # routes in maintenance and MySQL read-only; never claim recovery.
            result.update({
                "status": PARTIAL, "phase": DNS_ACTIVE_MAINTENANCE,
                "completed_at_utc": clock(), "dns_changed": True,
                "writes_opened": False, "maintenance_mode": True,
                "mysql_read_only": True, "dr_active_recorded": False,
                "automatic_rollback_allowed": False,
                "operator_intervention_required": True,
                "failure_code": "ONPREM_SINGLE_WRITER_EXCLUSIVITY_UNPROVEN",
                "rto": "NOT_MEASURED", "rpo": "NOT_MEASURED",
            })
            try:
                operations.mark_dr_state("PARTIAL_FAILURE")
                result["dr_state"] = "PARTIAL_FAILURE"
            except Exception:
                result["failure_code"] = "DR_STATE_AND_SINGLE_WRITER_STATUS_UNCERTAIN"
            _atomic_json(attempt_path, result)
            flow_title = (
                "[EMERGENCY DUMP RESTORE FAILOVER]"
                if result["request_origin"] == "EMERGENCY"
                else "[DUMP RESTORE FAILOVER]"
            )
            final_text = (
                f"{flow_title} [PARTIAL_FAILURE] Dump Failover DNS는 AWS DR로 전환되고 Cloudflare 공개 Health가 확인됐습니다. "
                "단, On-Prem 단일 쓰기 경로를 입증할 수 없어 유지보수/DB 읽기 전용을 유지했고 DR_ACTIVE는 기록하지 않았습니다.\n"
                f"요청 ID: {request_id}\n백업 ID: {backup_id}\n"
                "외부 Health: Web/EMR 204 (Cloudflare TLS, 요청별 DR probe)\n"
                "자동 DNS/DB 롤백: 금지(현재 결과는 운영자 확인 필요)\n"
                "RTO: NOT_MEASURED / RPO: NOT_MEASURED\n"
                "실행 단계 로그는 기존 [실행 로그 확인]에서 확인하세요."
            )
            result["slack_final_posted"] = bool(slack_poster(env["SLACK_FAILOVER_BOT_TOKEN"], chat_request, final_text))
            _atomic_json(attempt_path, result)
            log_event = (
                f"DUMP_FINALIZE request_origin={result['request_origin']} status={PARTIAL} phase={DNS_ACTIVE_MAINTENANCE} "
                f"failure_code={result['failure_code']} writes_opened=false dr_active_recorded=false "
                f"slack_final_posted={str(result['slack_final_posted']).lower()}"
            )
            _append_private(log_path, log_event, owner_uid=os.geteuid())
            _append_chatops_log(env, request_id, f"[{clock()}] {log_event}")
            return result

    # Exiting the shared-lock scope is not expected on a normal path.


def _record_finalization_failure(
    args: argparse.Namespace, *, env: Mapping[str, str], operations,
    cloudflare, error: Exception, slack_poster: Callable, clock: Callable,
) -> dict | None:
    if getattr(error, "code", "") == "FINALIZATION_ALREADY_RUNNING":
        return None
    request_id, backup_id, checksum = restore.validate_cli_identity(args)
    request_dir = _request_dir(_request_root(env), request_id)
    attempt_path = request_dir / "finalize_result.json"
    if not attempt_path.exists() or attempt_path.is_symlink():
        return None
    try:
        result, _raw = _read_json(attempt_path, code="FINALIZATION_RECEIPT_UNTRUSTED", owner_uid=os.geteuid())
    except FinalizeError:
        # If the execution receipt is not trustworthy, close the request's
        # public listeners and retain the DR DNS as-is for operator review.
        try:
            operations.stop_publication_and_restore(request_id)
            operations.mark_dr_state("PARTIAL_FAILURE")
        except Exception:
            pass
        return None
    if (
        result.get("request_id") != request_id or result.get("backup_id") != backup_id
        or str(result.get("expected_sha256") or "").lower() != checksum
    ):
        try:
            operations.stop_publication_and_restore(request_id)
            operations.mark_dr_state("PARTIAL_FAILURE")
        except Exception:
            pass
        return None
    if result.get("status") != "EXECUTING":
        return result

    failure_code = getattr(error, "code", "FINALIZATION_UNEXPECTED_FAILURE")
    if not SAFE_CODE_RE.fullmatch(str(failure_code)):
        failure_code = "FINALIZATION_UNEXPECTED_FAILURE"
    phase = str(result.get("phase") or "UNKNOWN")
    if not re.fullmatch(r"[A-Z0-9_]{1,80}", phase):
        phase = "UNKNOWN"
    stages = result.get("stages") if isinstance(result.get("stages"), dict) else {}
    if phase in stages and isinstance(stages[phase], dict):
        stages[phase].update({
            "status": "FAILED_OR_UNCERTAIN", "failure_code": failure_code,
            "completed_at_utc": clock(),
        })
    token = ""
    try:
        token = _read_token_file(request_dir)
    except FinalizeError:
        pass

    dns_attempted = result.get("dns_change_attempted") is True
    publication_started = "PUBLICATION_PREPARATION" in stages
    rollback_performed = False
    containment_ok = True
    outcome_status = "FAILED"
    result_phase = phase
    rollback_failure = None

    try:
        with _finalize_lock(request_dir):
            with operations.locks():
                if dns_attempted:
                    safe_to_rollback = False
                    if token:
                        try:
                            operations.verify_db_write_fence()
                            operations.verify_maintenance(token)
                            safe_to_rollback = True
                        except Exception:
                            safe_to_rollback = False
                    if safe_to_rollback and cloudflare is not None:
                        try:
                            origin, desired, ids = _stored_dns_pairs(result)
                            rollback_performed = _conditional_dns_rollback(
                                cloudflare, origin=origin, desired=desired, ids=ids,
                                directory=request_dir / "finalize-dns-snapshot",
                                operations=operations, token=token,
                            )
                        except Exception:
                            rollback_performed = False
                    if rollback_performed:
                        result["dns_changed"] = False
                        result["dns_state"] = "ORIGINAL_SNAPSHOT_RESTORED_AND_READBACK_VERIFIED"
                        result["automatic_rollback_allowed"] = True
                        result["automatic_rollback_performed"] = True
                        result_phase = "DNS_ROLLED_BACK_WRITES_BLOCKED"
                        containment_ok = operations.stop_publication_and_restore(request_id)
                        outcome_status = "FAILED" if containment_ok else PARTIAL
                        if not containment_ok:
                            rollback_failure = "POST_ROLLBACK_CONTAINMENT_FAILED"
                    else:
                        result["dns_state"] = "UNKNOWN_OR_DR_TARGET_REQUIRES_OPERATOR_REVIEW"
                        result["automatic_rollback_allowed"] = False
                        result["automatic_rollback_performed"] = False
                        containment_ok = operations.stop_publication_and_restore(request_id)
                        outcome_status = PARTIAL
                        result_phase = "DNS_ROLLBACK_NOT_PROVEN"
                        rollback_failure = "DNS_ROLLBACK_OR_WRITE_FENCE_UNVERIFIED"
                elif publication_started:
                    containment_ok = operations.stop_publication_and_restore(request_id)
                    outcome_status = "FAILED" if containment_ok else PARTIAL
                    result_phase = "PUBLICATION_CONTAINED" if containment_ok else "PUBLICATION_CONTAINMENT_FAILED"
                    if not containment_ok:
                        rollback_failure = "PUBLICATION_CONTAINMENT_FAILED"
                else:
                    outcome_status = "FAILED"
    except Exception:
        containment_ok = False
        outcome_status = PARTIAL
        result_phase = "LOCK_OR_CONTAINMENT_UNCERTAIN"
        rollback_failure = "SHARED_LOCK_OR_CONTAINMENT_UNAVAILABLE"

    result.update({
        "status": outcome_status,
        "phase": result_phase,
        "completed_at_utc": clock(),
        "writes_opened": False,
        "dr_active_recorded": False,
        "operator_intervention_required": outcome_status == PARTIAL,
        "failure_code": rollback_failure or failure_code,
        "automatic_rollback_allowed": result.get("automatic_rollback_allowed", False),
        "containment_verified": containment_ok,
        "rto": "NOT_MEASURED", "rpo": "NOT_MEASURED",
    })
    if outcome_status == PARTIAL:
        try:
            operations.mark_dr_state("PARTIAL_FAILURE")
            result["dr_state"] = "PARTIAL_FAILURE"
        except Exception:
            result["dr_state"] = "UNKNOWN"
            result["failure_code"] = "DR_STATE_WRITE_FAILED"
    try:
        _atomic_json(attempt_path, result)
    except Exception:
        # Preserve the original error and still attempt the Slack/audit trail.
        result["status"] = PARTIAL
        result["operator_intervention_required"] = True
        result["failure_code"] = "FINALIZATION_RECEIPT_WRITE_FAILED"
        result["phase"] = "FINALIZATION_RECEIPT_WRITE_FAILED"
    flow_title = (
        "[EMERGENCY DUMP RESTORE FAILOVER]"
        if result.get("request_origin") == "EMERGENCY"
        else "[DUMP RESTORE FAILOVER]"
    )
    final_text = (
        f"{flow_title} [{result['status']}] Dump Failover 후속 단계가 완료되지 않았습니다.\n"
        f"요청 ID: {request_id}\n백업 ID: {backup_id}\n"
        f"마지막 단계: {result['phase']}\n오류 코드: {result['failure_code']}\n"
        f"DNS 상태: {result.get('dns_state', '변경 전 또는 미확인')}\n"
        f"자동 DNS 롤백: {'완료' if rollback_performed else '금지/미확인'}\n"
        f"운영자 개입: {'필요' if result['status'] == PARTIAL else '불필요'}\n"
        "DB 복원은 반복하지 않았습니다. DB 쓰기 권한은 개방하지 않았고 DR_ACTIVE는 기록하지 않았습니다.\n"
        "RTO: NOT_MEASURED / RPO: NOT_MEASURED\n"
        "단계별 로그는 기존 [실행 로그 확인]에서 확인하세요."
    )
    try:
        admins = {item.strip() for item in env.get("SLACK_ADMIN_USER_IDS", "").split(",") if item.strip()}
        restore_receipt, _ = apps._read_private_json(request_dir / "result.json")
        request = _read_chatops_request(
            Path(env["CHATOPS_STATE_DB"]), request_id=request_id, backup_id=backup_id,
            checksum=checksum, restore_receipt=restore_receipt, admin_ids=admins,
        )
        result["slack_final_posted"] = bool(slack_poster(env["SLACK_FAILOVER_BOT_TOKEN"], request, final_text))
    except Exception:
        result["slack_final_posted"] = False
    log_event = (
        f"DUMP_FINALIZE request_origin={result.get('request_origin', 'UNKNOWN')} status={result['status']} phase={result['phase']} "
        f"failure_code={result['failure_code']} dns_rollback={str(rollback_performed).lower()} "
        f"containment_verified={str(containment_ok).lower()} dr_active_recorded=false"
    )
    try:
        _atomic_json(attempt_path, result)
    except Exception:
        pass
    for log_path, line in (
        (request_dir / "finalize.log", log_event),
        (Path(env.get("CHATOPS_EXECUTION_LOG_DIR") or Path(env.get("CHATOPS_STATE_DB", "")).parent / "execution-logs") / f"{request_id}.log", f"[{clock()}] {log_event}"),
    ):
        try:
            _append_private(log_path, line, owner_uid=os.geteuid())
        except Exception:
            pass
    return result


def execute_finalization(
    args: argparse.Namespace, *, environment: Mapping[str, str] | None = None,
    operations=None, cloudflare=None, public_health_checker: Callable = dns_common.check_public_health,
    slack_poster: Callable = _post_slack, clock: Callable = _now,
) -> dict:
    env = dict(environment if environment is not None else os.environ)
    request_id, _backup_id, _checksum = restore.validate_cli_identity(args)
    validate_gates(env, request_id, args)
    if operations is None:
        if not env.get("SSH_KEY"):
            raise FinalizeError("SSH_KEY_UNAVAILABLE")
        operations = Operations(env, _load_root_password(env))
    if cloudflare is None:
        zone = str(env.get("CF_ZONE_ID") or "")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", zone):
            raise FinalizeError("CLOUDFLARE_ZONE_ID_INVALID")
        cloudflare = CloudflareClient(zone, env["CLOUDFLARE_API_TOKEN"])
    try:
        return _execute_finalization_once(
            args, environment=env, operations=operations, cloudflare=cloudflare,
            public_health_checker=public_health_checker, slack_poster=slack_poster, clock=clock,
        )
    except Exception as exc:
        try:
            _record_finalization_failure(
                args, env=env, operations=operations, cloudflare=cloudflare,
                error=exc, slack_poster=slack_poster, clock=clock,
            )
        except Exception:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--backup-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--confirm-finalize", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_finalization(args)
    except (FinalizeError, restore.DemoRestoreError, apps.AppsStartError) as exc:
        code = getattr(exc, "code", "FINALIZATION_BLOCKED")
        print(f"DEMO_DUMP_FINALIZE=BLOCKED code={code}", file=sys.stderr)
        return 1
    except Exception:
        print("DEMO_DUMP_FINALIZE=BLOCKED code=FINALIZATION_UNEXPECTED_FAILURE", file=sys.stderr)
        return 1
    print(
        f"DEMO_DUMP_FINALIZE status={result['status']} request_id={result['request_id']} "
        f"backup_id={result['backup_id']} dr_active_recorded=false failure_code={result['failure_code']}",
        flush=True,
    )
    return 2 if result["status"] == PARTIAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
