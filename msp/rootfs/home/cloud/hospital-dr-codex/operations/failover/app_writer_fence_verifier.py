#!/usr/bin/env python3
"""Collect fresh, request-bound read-only evidence for On-Prem app writers.

This collector never stops a service or changes a host.  It accepts only
pre-pinned SSH host keys and verifies each host's machine identity, configured
writer process, optional systemd unit, and established MySQL TCP sessions.
The caller separately verifies the On-Prem MySQL read-only fence before it
accepts this proof.  Missing host data, tools, or connectivity is fail-closed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "hospital-dr-app-writer-fence/v1"
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SAFE_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z")
SAFE_USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")
SAFE_PROCESS_RE = re.compile(r"[A-Za-z0-9_.+-]{1,64}\Z")


class ProbeBlocked(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


REMOTE_PROBE = r"""set -eu
role=$1
expected_host_id=$2
service_unit=$3
process_comm=$4
process_arg=$5
db_port=$6
hostname_value=$(hostname -s)
machine_id=$(tr 'A-F' 'a-f' </etc/machine-id)
if [ "$machine_id" != "$expected_host_id" ]; then
  printf 'HOST_PROBE_ERROR\t%s\thost_identity_mismatch\n' "$role"
  exit 42
fi
service_state=NOT_CONFIGURED
if [ -n "$service_unit" ]; then
service_state=$(systemctl show --property=ActiveState --value "$service_unit" 2>/dev/null || printf 'UNKNOWN')
fi
process_count=$(ps -eo comm=,args= | awk -v comm="$process_comm" -v fragment="$process_arg" \
  '$1 == comm && index($0, fragment) > 0 { count++ } END { print count+0 }')
db_sessions=$(ss -Hnt state established 2>/dev/null | awk -v suffix=":$db_port" \
  '$5 ~ (suffix "$") { count++ } END { print count+0 }')
printf 'HOST_PROBE\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$role" "$hostname_value" "$machine_id" "$service_state" "$process_count" "$db_sessions"
"""


def _safe_args(args: argparse.Namespace) -> dict[str, dict[str, str]]:
    subjects = {}
    for role in ("web", "emr"):
        host = getattr(args, f"{role}_host")
        user = getattr(args, f"{role}_user")
        host_id = getattr(args, f"{role}_host_id")
        fingerprint = getattr(args, f"{role}_fingerprint")
        service = getattr(args, f"{role}_service_unit") or ""
        process_comm = getattr(args, f"{role}_process_comm")
        process_arg = getattr(args, f"{role}_process_arg")
        if not host or not SAFE_HOST_RE.fullmatch(host):
            raise ProbeBlocked(f"{role}_management_host_unconfigured_or_invalid")
        if not user or not SAFE_USER_RE.fullmatch(user):
            raise ProbeBlocked(f"{role}_ssh_user_unconfigured_or_invalid")
        if not host_id or not SAFE_ID_RE.fullmatch(host_id):
            raise ProbeBlocked(f"{role}_host_identity_unconfigured_or_invalid")
        if not fingerprint or not FINGERPRINT_RE.fullmatch(fingerprint):
            raise ProbeBlocked(f"{role}_host_fingerprint_unconfigured_or_invalid")
        if service and not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", service):
            raise ProbeBlocked(f"{role}_service_unit_invalid")
        if not process_comm or not SAFE_PROCESS_RE.fullmatch(process_comm):
            raise ProbeBlocked(f"{role}_process_comm_unconfigured_or_invalid")
        if not process_arg or len(process_arg) > 128 or any(c in process_arg for c in "\r\n\x00"):
            raise ProbeBlocked(f"{role}_process_signature_unconfigured_or_invalid")
        subjects[role] = {
            "host": host,
            "user": user,
            "host_id": host_id,
            "fingerprint": fingerprint,
            "service_unit": service,
            "process_comm": process_comm,
            "process_arg": process_arg,
        }
    return subjects


def _validate_local_files(key_path: Path, known_hosts: Path) -> None:
    uid = os.geteuid()
    for path, exact_mode, reason in (
        (key_path, 0o600, "app_ssh_key_permissions_invalid"),
        (known_hosts, None, "app_known_hosts_permissions_invalid"),
    ):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ProbeBlocked("app_ssh_material_unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or path.is_symlink():
            raise ProbeBlocked(reason)
        mode = stat.S_IMODE(metadata.st_mode)
        if exact_mode is not None and mode != exact_mode:
            raise ProbeBlocked(reason)
        if exact_mode is None and mode & 0o022:
            raise ProbeBlocked(reason)
        if not os.access(path, os.R_OK):
            raise ProbeBlocked(reason)


def _known_fingerprints(host: str, known_hosts: Path) -> set[str]:
    found = subprocess.run(
        ["ssh-keygen", "-F", host, "-f", str(known_hosts)],
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    if found.returncode != 0:
        raise ProbeBlocked("app_host_key_not_pinned")
    key_lines = [line for line in found.stdout.splitlines() if line and not line.startswith("#")]
    if not key_lines:
        raise ProbeBlocked("app_host_key_not_pinned")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as stream:
        os.chmod(stream.name, 0o600)
        temp_path = Path(stream.name)
        stream.write("\n".join(key_lines) + "\n")
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", str(temp_path), "-E", "sha256"],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    finally:
        temp_path.unlink(missing_ok=True)
    if result.returncode != 0:
        raise ProbeBlocked("app_host_key_fingerprint_read_failed")
    return set(re.findall(r"SHA256:[A-Za-z0-9+/]{43}", result.stdout))


def _probe_one(role: str, spec: dict[str, str], args: argparse.Namespace) -> dict:
    key_path = Path(args.ssh_key)
    known_hosts = Path(args.known_hosts)
    fingerprints = _known_fingerprints(spec["host"], known_hosts)
    if spec["fingerprint"] not in fingerprints:
        raise ProbeBlocked(f"{role}_host_key_fingerprint_mismatch")

    remote_args = [
        role,
        spec["host_id"],
        spec["service_unit"],
        spec["process_comm"],
        spec["process_arg"],
        str(args.db_port),
    ]
    remote_command = "bash -s -- " + " ".join(shlex.quote(value) for value in remote_args)
    command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=20",
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        "-i", str(key_path),
        f"{spec['user']}@{spec['host']}",
        remote_command,
    ]
    try:
        result = subprocess.run(
            command,
            input=REMOTE_PROBE,
            text=True,
            capture_output=True,
            timeout=28,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeBlocked(f"{role}_ssh_probe_timeout") from exc
    except OSError as exc:
        raise ProbeBlocked("app_ssh_runtime_unavailable") from exc
    if result.returncode != 0:
        if "HOST_PROBE_ERROR" in result.stdout and "host_identity_mismatch" in result.stdout:
            raise ProbeBlocked(f"{role}_host_identity_mismatch")
        raise ProbeBlocked(f"{role}_ssh_probe_failed")
    rows = [line.split("\t") for line in result.stdout.splitlines() if line.startswith("HOST_PROBE\t")]
    if len(rows) != 1 or len(rows[0]) != 7 or rows[0][1] != role:
        raise ProbeBlocked(f"{role}_probe_output_invalid")
    _, _, hostname, machine_id, service_state, process_count, db_sessions = rows[0]
    if machine_id != spec["host_id"] or not SAFE_ID_RE.fullmatch(hostname):
        raise ProbeBlocked(f"{role}_host_identity_mismatch")
    if not process_count.isdecimal() or not db_sessions.isdecimal():
        raise ProbeBlocked(f"{role}_writer_probe_values_invalid")
    process_count_num = int(process_count)
    db_sessions_num = int(db_sessions)
    if service_state not in {"inactive", "NOT_CONFIGURED"}:
        raise ProbeBlocked(f"{role}_service_not_stopped")
    if process_count_num != 0:
        raise ProbeBlocked(f"{role}_writer_process_present")
    if db_sessions_num != 0:
        raise ProbeBlocked(f"{role}_database_sessions_present")
    if service_state == "NOT_CONFIGURED" and role == "web":
        raise ProbeBlocked("web_service_unit_unverified")

    evidence_id = hashlib.sha256(
        "\0".join((args.request_id, args.phase, role, hostname, machine_id, service_state, process_count, db_sessions)).encode()
    ).hexdigest()[:32]
    return {
        "role": role,
        "method": "ssh_host_probe",
        "host_id": machine_id,
        "host_key_fingerprint": spec["fingerprint"],
        "writer_state": "STOPPED",
        "writer_process_count": process_count_num,
        "write_path_state": "BLOCKED",
        "readback": "VERIFIED",
        "evidence_id": evidence_id,
        "hostname": hostname,
        "service_state": service_state,
        "database_session_count": db_sessions_num,
    }


def collect(args: argparse.Namespace) -> dict:
    if not UUID_RE.fullmatch(args.request_id or ""):
        raise ProbeBlocked("request_id_invalid")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", args.phase or ""):
        raise ProbeBlocked("phase_invalid")
    if not args.ssh_key or not args.known_hosts:
        raise ProbeBlocked("app_ssh_material_unconfigured")
    if not Path(args.ssh_key).is_absolute() or not Path(args.known_hosts).is_absolute():
        raise ProbeBlocked("app_ssh_paths_must_be_absolute")
    if not args.db_port.isdecimal() or not 1 <= int(args.db_port) <= 65535:
        raise ProbeBlocked("database_port_invalid")
    try:
        subjects = _safe_args(args)
    except ProbeBlocked:
        raise
    key_path, known_hosts = Path(args.ssh_key), Path(args.known_hosts)
    _validate_local_files(key_path, known_hosts)
    collected = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(_probe_one, role, subjects[role], args): role
            for role in ("web", "emr")
        }
        for future in concurrent.futures.as_completed(futures, timeout=32):
            collected.append(future.result())
    if {item["role"] for item in collected} != {"web", "emr"}:
        raise ProbeBlocked("application_subjects_incomplete")
    return {
        "schema": SCHEMA,
        "request_id": args.request_id,
        "phase": args.phase,
        "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "result": "VERIFIED",
        "subjects": sorted(collected, key=lambda item: item["role"]),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--ssh-key", default="")
    parser.add_argument("--known-hosts", default="")
    parser.add_argument("--db-port", default="3306")
    for role in ("web", "emr"):
        parser.add_argument(f"--{role}-host", default="")
        parser.add_argument(f"--{role}-user", default="")
        parser.add_argument(f"--{role}-host-id", default="")
        parser.add_argument(f"--{role}-fingerprint", default="")
        parser.add_argument(f"--{role}-service-unit", default="")
        parser.add_argument(f"--{role}-process-comm", default="")
        parser.add_argument(f"--{role}-process-arg", default="")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = collect(args)
    except ProbeBlocked as exc:
        print(json.dumps({"schema": SCHEMA, "request_id": args.request_id, "phase": args.phase,
                          "result": "BLOCKED", "failure_code": exc.code}, separators=(",", ":")))
        return 0
    except (OSError, subprocess.SubprocessError, concurrent.futures.TimeoutError):
        print(json.dumps({"schema": SCHEMA, "request_id": args.request_id, "phase": args.phase,
                          "result": "BLOCKED", "failure_code": "probe_collection_failed"}, separators=(",", ":")))
        return 0
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
