#!/usr/bin/env python3
"""Request-bound restore path for the existing AWS DR DB.

It reuses running approved EC2s, starts only required stopped targets, and
fences Web/EMR application containers without stopping their EC2 hosts. It
restores the DB to a persistent read-only standby and does not change DNS or
the overall Failover result.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from operations.db.dump_execution_contract import (  # noqa: E402
    acquire_shared_dr_locks,
    validate_inherited_failover_locks,
)
from operations.db.dump_failover_executor import _validate_approval as _validate_chatops_approval  # noqa: E402
from operations.db.isolated_dump_restore import (  # noqa: E402
    BACKUP_NAME_RE,
    SHA256_RE,
    validate_backup_pair,
)
from operations.failover.nr_readiness import validate_dump_restore_receipt  # noqa: E402

DB_INSTANCE_ID = "AWS_RESOURCE_ID_REDACTED"
DB_PRIVATE_IP = "IP_REDACTED"
DB_NAME_TAG = "Hospital-DR-DB-Server"
WEB_INSTANCE_ID = "AWS_RESOURCE_ID_REDACTED"
WEB_PRIVATE_IP = "IP_REDACTED"
WEB_NAME_TAG = "Hospital-Real-Web-Server"
DOC_INSTANCE_ID = "AWS_RESOURCE_ID_REDACTED"
DOC_PRIVATE_IP = "IP_REDACTED"
DOC_NAME_TAG = "Hospital-DR-Doc-Server"
CORE_TABLES = {"users", "patients", "doctors", "medicalrecords", "accesslogs", "reservationposts"}
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SAFE_CODE_RE = re.compile(r"[A-Z0-9_]{1,96}\Z")


def _mysql_boolean_option_state(arguments: list[str], variable: str) -> str:
    """Summarize all occurrences; contradictory or unknown values never pass."""
    wanted = variable.replace("_", "-").lower()
    observed: list[str] = []
    for index, argument in enumerate(arguments):
        if not argument.startswith("--"):
            continue
        name, separator, value = argument[2:].partition("=")
        name = name.replace("_", "-").lower()
        enabled = True
        for prefix in ("skip-", "disable-"):
            if name.startswith(prefix):
                name = name[len(prefix):]
                enabled = False
                break
        if name.startswith("loose-"):
            name = name[len("loose-"):]
        if name != wanted:
            continue
        if not separator and index + 1 < len(arguments):
            next_value = arguments[index + 1].strip().upper()
            if next_value in {"ON", "1", "TRUE", "YES", "OFF", "0", "FALSE", "NO"}:
                separator, value = "=", arguments[index + 1]
        if separator:
            normalized = value.strip().upper()
            if normalized in {"ON", "1", "TRUE", "YES"}:
                enabled = True
            elif normalized in {"OFF", "0", "FALSE", "NO"}:
                enabled = False
            else:
                observed.append("INVALID")
                continue
        observed.append("ON" if enabled else "OFF")
    if not observed:
        return "MISSING"
    if "INVALID" in observed:
        return "INVALID"
    if len(set(observed)) != 1:
        return "CONFLICT"
    return observed[0]


def _persistent_read_only_source(
    *, runtime_read_only: str, runtime_super_read_only: str,
    persisted_read_only: str, persisted_super_read_only: str,
    startup_read_only: str, startup_super_read_only: str,
    startup_source_verified: bool,
) -> str | None:
    """Accept durable standby settings only from persisted vars or proven startup config."""
    if runtime_read_only != "1" or runtime_super_read_only != "1" or not startup_source_verified:
        return None
    startup_values = {startup_read_only, startup_super_read_only}
    if startup_values & {"OFF", "CONFLICT", "INVALID"}:
        return None
    if persisted_read_only == "ON" and persisted_super_read_only == "ON":
        return "PERSISTED_VARIABLES"
    if (
        persisted_read_only == "MISSING" and persisted_super_read_only == "MISSING"
        and startup_read_only == "ON" and startup_super_read_only == "ON"
    ):
        return "MYSQL_STARTUP_CONFIGURATION"
    return None


def _valid_preflight_read_only_standby(value: object) -> bool:
    if not isinstance(value, dict) or value.get("read_only") is not True or value.get("super_read_only") is not True:
        return False
    source = _persistent_read_only_source(
        runtime_read_only="1", runtime_super_read_only="1",
        persisted_read_only=str(value.get("persisted_read_only", "")),
        persisted_super_read_only=str(value.get("persisted_super_read_only", "")),
        startup_read_only=str(value.get("startup_read_only", "")),
        startup_super_read_only=str(value.get("startup_super_read_only", "")),
        startup_source_verified=value.get("startup_source_verified") is True,
    )
    return source is not None and value.get("persistence_source") == source


def _parse_database_preflight_response(output: str, request_id: str) -> dict:
    lines = output.splitlines()
    if len(lines) != 2:
        raise DemoRestoreError("DR_DATABASE_PREFLIGHT_RESPONSE_INVALID")
    match = re.fullmatch(
        r"PREFLIGHT\|([0-9]+)\|([0-9]+)\|0\|"
        r"([0-9a-f-]{36})\|([0-9]+)\|([A-Za-z0-9_.-]+)\|3306\|"
        r"(?P<read_only>[01])\|(?P<super_read_only>[01])\|"
        r"(?P<persisted_read_only>ON|OFF|MISSING)\|"
        r"(?P<persisted_super_read_only>ON|OFF|MISSING)\|" + re.escape(request_id),
        lines[0],
    )
    startup = re.fullmatch(
        r"STARTUP\|(VERIFIED|UNVERIFIED)\|"
        r"(ON|OFF|MISSING|CONFLICT|INVALID)\|"
        r"(ON|OFF|MISSING|CONFLICT|INVALID)\|([1-9][0-9]*)",
        lines[1],
    )
    if not match or not startup or not UUID_RE.fullmatch(match.group(3)):
        raise DemoRestoreError("DR_DATABASE_PREFLIGHT_RESPONSE_INVALID")
    if int(match.group(4)) != 20:
        raise DemoRestoreError("DR_DATABASE_SERVER_ID_MISMATCH")
    startup_verified = startup.group(1) == "VERIFIED"
    persistence_source = _persistent_read_only_source(
        runtime_read_only=match.group("read_only"),
        runtime_super_read_only=match.group("super_read_only"),
        persisted_read_only=match.group("persisted_read_only"),
        persisted_super_read_only=match.group("persisted_super_read_only"),
        startup_read_only=startup.group(2), startup_super_read_only=startup.group(3),
        startup_source_verified=startup_verified,
    )
    if persistence_source is None:
        raise DemoRestoreError("DR_DATABASE_NOT_PERSISTENT_READ_ONLY_STANDBY")
    return {
        "database_bytes": int(match.group(1)),
        "remote_free_bytes": int(match.group(2)),
        "remote_sessions": 0,
        "identity": {
            "server_uuid": match.group(3), "server_id": int(match.group(4)),
            "hostname": match.group(5), "port": 3306,
        },
        "read_only_standby": {
            "read_only": True, "super_read_only": True,
            "persisted_read_only": match.group("persisted_read_only"),
            "persisted_super_read_only": match.group("persisted_super_read_only"),
            "startup_read_only": startup.group(2),
            "startup_super_read_only": startup.group(3),
            "startup_source_verified": startup_verified,
            "persistence_source": persistence_source,
        },
    }


_MYSQL_STARTUP_PROBE = r'''import os, pathlib, shlex, subprocess, sys

def emit(status, read_only="MISSING", super_read_only="MISSING", pid="1"):
    print("STARTUP|{}|{}|{}|{}".format(status, read_only, super_read_only, pid))

def state(arguments, variable):
    wanted = variable.replace("_", "-").lower()
    seen = []
    for index, argument in enumerate(arguments):
        if not argument.startswith("--"):
            continue
        name, separator, value = argument[2:].partition("=")
        name = name.replace("_", "-").lower()
        enabled = True
        for prefix in ("skip-", "disable-"):
            if name.startswith(prefix):
                name, enabled = name[len(prefix):], False
                break
        if name.startswith("loose-"):
            name = name[len("loose-"):]
        if name != wanted:
            continue
        if not separator and index + 1 < len(arguments):
            next_value = arguments[index + 1].strip().upper()
            if next_value in ("ON", "1", "TRUE", "YES", "OFF", "0", "FALSE", "NO"):
                separator, value = "=", arguments[index + 1]
        if separator:
            normalized = value.strip().upper()
            if normalized in ("ON", "1", "TRUE", "YES"):
                enabled = True
            elif normalized in ("OFF", "0", "FALSE", "NO"):
                enabled = False
            else:
                seen.append("INVALID")
                continue
        seen.append("ON" if enabled else "OFF")
    if not seen:
        return "MISSING"
    if "INVALID" in seen:
        return "INVALID"
    if len(set(seen)) != 1:
        return "CONFLICT"
    return seen[0]

def selector_args(argv, service_cwd):
    selected, index, saw_regular = [], 1, False
    while index < len(argv):
        token = argv[index]
        key, separator, value = token.partition("=")
        if key in ("--no-defaults", "--defaults-file", "--defaults-extra-file", "--defaults-group-suffix"):
            if saw_regular:
                raise ValueError("defaults selector order")
            if key == "--no-defaults":
                if separator:
                    raise ValueError("invalid no-defaults")
                selected.append(key)
            else:
                if not separator:
                    index += 1
                    if index >= len(argv):
                        raise ValueError("missing defaults selector value")
                    value = argv[index]
                if key != "--defaults-group-suffix":
                    path = pathlib.Path(value)
                    if not path.is_absolute():
                        path = service_cwd / path
                    if not path.resolve(strict=True).is_file():
                        raise ValueError("defaults source unavailable")
                selected.append(key + "=" + value)
        else:
            saw_regular = True
        index += 1
    return selected

try:
    expected_pid = os.environ.get("MYSQL_EXPECTED_PID", "")
    active = subprocess.run(["systemctl", "is-active", "--quiet", "mysql.service"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    main_pid = subprocess.run(["systemctl", "show", "--property=MainPID", "--value", "mysql.service"],
                              capture_output=True, text=True, timeout=5, check=False)
    pid = main_pid.stdout.strip()
    if (active.returncode != 0 or main_pid.returncode != 0 or not pid.isdigit()
            or pid == "0" or pid != expected_pid):
        raise ValueError("mysql service process unavailable")
    proc = pathlib.Path("/proc") / pid
    executable = os.readlink(str(proc / "exe"))
    if executable.endswith(" (deleted)") or pathlib.Path(executable).name != "mysqld":
        raise ValueError("unexpected mysql executable")
    executable = str(pathlib.Path(executable).resolve(strict=True))
    running_stat, installed_stat = os.stat(str(proc / "exe")), os.stat(executable)
    if (running_stat.st_dev, running_stat.st_ino) != (installed_stat.st_dev, installed_stat.st_ino):
        raise ValueError("running mysql binary differs from installed binary")
    service_cwd = pathlib.Path(os.readlink(str(proc / "cwd"))).resolve(strict=True)
    argv = [os.fsdecode(part) for part in (proc / "cmdline").read_bytes().split(b"\0") if part]
    if not argv or pathlib.Path(argv[0]).name != "mysqld":
        raise ValueError("unexpected service arguments")
    process_status = (proc / "status").read_text()
    uid_line = next(line for line in process_status.splitlines() if line.startswith("Uid:"))
    gid_line = next(line for line in process_status.splitlines() if line.startswith("Gid:"))
    groups_line = next(line for line in process_status.splitlines() if line.startswith("Groups:"))
    effective_uid, effective_gid = uid_line.split()[2], gid_line.split()[2]
    supplementary_groups = groups_line.split()[1:]
    if not effective_uid.isdigit() or not effective_gid.isdigit():
        raise ValueError("mysql process identity unavailable")
    environment = {}
    for item in (proc / "environ").read_bytes().split(b"\0"):
        if b"=" in item:
            key, value = item.split(b"=", 1)
            if key in (b"HOME", b"MYSQL_HOME"):
                environment[os.fsdecode(key)] = os.fsdecode(value)
    defaults = selector_args(argv, service_cwd)
    probe_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    probe_env.update(environment)
    privilege = ["setpriv", "--reuid=" + effective_uid, "--regid=" + effective_gid]
    privilege.append("--groups=" + ",".join(supplementary_groups) if supplementary_groups else "--clear-groups")
    probe = subprocess.run([*privilege, "--", executable, *defaults, "--print-defaults"],
                           capture_output=True, text=True, timeout=10, cwd=str(service_cwd),
                           env=probe_env, check=False)
    if probe.returncode != 0:
        raise ValueError("mysqld defaults parser failed")
    try:
        printed = shlex.split(probe.stdout)
    except ValueError:
        raise ValueError("mysqld defaults output invalid")
    default_args = [item for item in printed if item.startswith("--")]
    result = []
    for variable in ("read_only", "super_read_only"):
        default_state = state(default_args, variable)
        process_state = state(argv[1:], variable)
        if "INVALID" in (default_state, process_state):
            result.append("INVALID")
        elif "CONFLICT" in (default_state, process_state):
            result.append("CONFLICT")
        elif default_state != "MISSING" and process_state != "MISSING" and default_state != process_state:
            result.append("CONFLICT")
        else:
            result.append(process_state if process_state != "MISSING" else default_state)
    emit("VERIFIED", result[0], result[1], pid)
except Exception:
    emit("UNVERIFIED", "MISSING", "MISSING", "1")
'''


class DemoRestoreError(RuntimeError):
    """Stable safe refusal reason; never contains command output or secrets."""

    def __init__(self, code: str):
        super().__init__(code if SAFE_CODE_RE.fullmatch(code) else "UNEXPECTED_EXECUTION_ERROR")
        self.code = str(self)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_cli_identity(args: argparse.Namespace) -> tuple[str, str, str]:
    request_id = str(args.request_id or "").lower()
    try:
        canonical = str(uuid.UUID(request_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DemoRestoreError("REQUEST_ID_INVALID") from exc
    if canonical != request_id or not UUID_RE.fullmatch(request_id):
        raise DemoRestoreError("REQUEST_ID_INVALID")
    backup_id = str(args.backup_id or "")
    if not BACKUP_NAME_RE.fullmatch(backup_id) or Path(backup_id).name != backup_id:
        raise DemoRestoreError("BACKUP_ID_INVALID")
    checksum = str(args.expected_sha256 or "").lower()
    if not SHA256_RE.fullmatch(checksum):
        raise DemoRestoreError("BACKUP_CHECKSUM_INVALID")
    return request_id, backup_id, checksum


def _enabled(env: Mapping[str, str], name: str) -> bool:
    return str(env.get(name, "false")).strip().lower() == "true"


def validate_execution_gates(
    env: Mapping[str, str], *, request_id: str, wrapper: Path | None = None,
) -> None:
    if not _enabled(env, "DUMP_RESTORE_EXEC_ENABLED"):
        raise DemoRestoreError("DUMP_RESTORE_EXECUTOR_DISABLED")
    configured = str(env.get("DUMP_RESTORE_EXECUTOR", "")).strip()
    expected = (wrapper or (REPO_ROOT / "operations/db/demo_dump_restore_existing_dr.sh")).resolve()
    if not configured:
        raise DemoRestoreError("DUMP_RESTORE_EXECUTOR_NOT_CONFIGURED")
    path = Path(configured)
    if not path.is_absolute() or path.is_symlink():
        raise DemoRestoreError("DUMP_RESTORE_EXECUTOR_PATH_INVALID")
    try:
        if path.resolve(strict=True) != expected:
            raise DemoRestoreError("DUMP_RESTORE_EXECUTOR_PATH_MISMATCH")
    except OSError as exc:
        raise DemoRestoreError("DUMP_RESTORE_EXECUTOR_PATH_INVALID") from exc


def _safe_env(env: Mapping[str, str]) -> dict[str, str]:
    allow = {
        "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR",
        "AWS_DEFAULT_REGION", "AWS_REGION", "AWS_PROFILE", "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE", "SSH_AUTH_SOCK",
    }
    result = {key: value for key, value in env.items() if key in allow or key.startswith("AWS_")}
    result.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    result["LC_ALL"] = "C"
    return result


def validate_aws_instance_record(
    instance: dict, *, expected_id: str | None, name: str, private_ip: str,
    allowed_states: tuple[str, ...] = ("running",),
) -> dict:
    tags = {str(item.get("Key")): str(item.get("Value")) for item in instance.get("Tags", [])}
    instance_id = str(instance.get("InstanceId", ""))
    state = str(instance.get("State", {}).get("Name", ""))
    if (
        state not in allowed_states
        or instance.get("PrivateIpAddress") != private_ip
        or tags.get("Name") != name
        or (expected_id and instance_id != expected_id)
    ):
        raise DemoRestoreError("AWS_DR_INSTANCE_IDENTITY_OR_STATE_MISMATCH")
    profile = instance.get("IamInstanceProfile") or {}
    return {
        "instance_id": instance_id, "private_ip": private_ip, "name": name,
        "state": state, "ssm_profile_present": bool(profile.get("Arn")),
    }


def _private_request_dir(state_dir: Path, request_id: str) -> Path:
    if state_dir.is_symlink():
        raise DemoRestoreError("EXECUTION_STATE_DIRECTORY_INVALID")
    try:
        state_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        metadata = state_dir.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise DemoRestoreError("EXECUTION_STATE_DIRECTORY_PERMISSIONS_INVALID")
        request_dir = state_dir / request_id
        request_dir.mkdir(mode=0o700)
        request_stat = request_dir.lstat()
        if not stat.S_ISDIR(request_stat.st_mode) or request_stat.st_uid != os.geteuid() or stat.S_IMODE(request_stat.st_mode) != 0o700:
            raise DemoRestoreError("EXECUTION_REQUEST_DIRECTORY_PERMISSIONS_INVALID")
        return request_dir
    except FileExistsError as exc:
        raise DemoRestoreError("REQUEST_ALREADY_HAS_RESTORE_RECORD") from exc
    except DemoRestoreError:
        raise
    except OSError as exc:
        raise DemoRestoreError("EXECUTION_STATE_DIRECTORY_UNAVAILABLE") from exc


def _write_private_json(path: Path, value: dict) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temporary, flags, 0o600)
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
        raise DemoRestoreError("EXECUTION_RECEIPT_WRITE_FAILED") from exc


def _read_existing_private_json(path: Path) -> dict:
    descriptor = None
    try:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
            or not 2 <= metadata.st_size <= 1024 * 1024
        ):
            raise DemoRestoreError("EXECUTION_RECEIPT_UNTRUSTED")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = None
            value = json.load(stream)
    except DemoRestoreError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DemoRestoreError("EXECUTION_RECEIPT_UNAVAILABLE") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise DemoRestoreError("EXECUTION_RECEIPT_INVALID")
    return value


def _append_log(path: Path, event: str) -> None:
    if not SAFE_CODE_RE.fullmatch(event.replace("=", "_").replace("-", "_")):
        raise DemoRestoreError("EXECUTION_LOG_EVENT_INVALID")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "a", encoding="ascii") as stream:
            stream.write(f"{_utc_now()} {event}\n")
        os.chmod(path, 0o600)
    except OSError as exc:
        raise DemoRestoreError("EXECUTION_LOG_WRITE_FAILED") from exc


class SystemOperations:
    """Only existing-instance read calls and SSM SSH commands are used."""

    def __init__(self, env: Mapping[str, str], backup_dir: Path):
        self.env = dict(env)
        self.child_env = _safe_env(env)
        self.backup_dir = backup_dir
        self.region = str(env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or "ap-northeast-2")
        self.state_dir = Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr"))
        self.ssh_config = Path(env.get("DR_SSH_CONFIG_FILE", str(self.state_dir / "ssh/config")))
        self.known_hosts = Path(env.get("DR_SSH_KNOWN_HOSTS_FILE", str(self.state_dir / "ssh/known_hosts")))
        self.ssh_key = Path(env.get("SSH_KEY", ""))

    @contextlib.contextmanager
    def locks(self):
        if self.env.get("DR_DUMP_FAILOVER_FALLBACK") == "1":
            request_id = str(self.env.get("DR_FAILOVER_REQUEST_ID") or "")
            if (
                request_id != str(self.env.get("DR_DUMP_FALLBACK_REQUEST_ID") or "")
                or not UUID_RE.fullmatch(request_id)
                or self.env.get("DR_WORKFLOW_LOCK_HELD") != "1"
                or self.env.get("DR_FAILOVER_LOCK_HELD") != "1"
            ):
                raise DemoRestoreError("FAILOVER_FALLBACK_REQUEST_OR_LOCK_INVALID")
            try:
                validate_inherited_failover_locks(self.env)
            except Exception as exc:
                raise DemoRestoreError("ACTIVE_DR_WORKFLOW_OR_LOCK_INVALID") from exc
            yield
            return
        workflow = Path(self.env.get("DR_WORKFLOW_LOCK_FILE", str(self.state_dir / "workflow.lock")))
        failover = Path(self.env.get("DR_FAILOVER_LOCK_FILE", str(self.state_dir / "failover.lock")))
        if workflow == failover:
            raise DemoRestoreError("SHARED_DR_EXECUTION_LOCK_CONFIGURATION_INVALID")
        for path in (workflow, failover):
            try:
                path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
                fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
            except OSError as exc:
                raise DemoRestoreError("SHARED_DR_EXECUTION_LOCK_REQUIRED") from exc
        try:
            descriptors = acquire_shared_dr_locks({
                **self.env,
                "DR_WORKFLOW_LOCK_FILE": str(workflow),
                "DR_FAILOVER_LOCK_FILE": str(failover),
            })
        except Exception as exc:
            raise DemoRestoreError("ACTIVE_DR_WORKFLOW_OR_LOCK_INVALID") from exc
        try:
            yield
        finally:
            import fcntl
            for descriptor in descriptors:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    os.close(descriptor)
                except OSError:
                    pass

    def _run(self, command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                command, input=input_text, text=True, capture_output=True,
                check=False, env=self.child_env,
            )
        except OSError as exc:
            raise DemoRestoreError("REQUIRED_COMMAND_UNAVAILABLE") from exc

    def _aws_instance(
        self, *, instance_id: str = "", name: str, private_ip: str,
        allowed_states: tuple[str, ...] = ("running",),
    ) -> dict:
        command = ["aws", "ec2", "describe-instances", "--region", self.region]
        if instance_id:
            command += ["--instance-ids", instance_id]
        else:
            command += [
                "--filters", f"Name=tag:Name,Values={name}",
                f"Name=private-ip-address,Values={private_ip}",
            ]
        command += ["--output", "json"]
        result = self._run(command)
        if result.returncode:
            raise DemoRestoreError("AWS_INSTANCE_IDENTITY_QUERY_FAILED")
        try:
            data = json.loads(result.stdout)
            instances = [item for group in data.get("Reservations", []) for item in group.get("Instances", [])]
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DemoRestoreError("AWS_INSTANCE_IDENTITY_RESPONSE_INVALID") from exc
        if len(instances) != 1:
            raise DemoRestoreError("AWS_INSTANCE_IDENTITY_NOT_UNIQUE")
        return validate_aws_instance_record(
            instances[0], expected_id=instance_id or None,
            name=name, private_ip=private_ip, allowed_states=allowed_states,
        )

    def validate_targets(self) -> dict:
        db = self._aws_instance(
            instance_id=DB_INSTANCE_ID, name=DB_NAME_TAG, private_ip=DB_PRIVATE_IP,
            allowed_states=("stopped", "running"),
        )
        web = self._aws_instance(
            instance_id=WEB_INSTANCE_ID, name=WEB_NAME_TAG, private_ip=WEB_PRIVATE_IP,
            allowed_states=("stopped", "running"),
        )
        doc = self._aws_instance(
            instance_id=DOC_INSTANCE_ID, name=DOC_NAME_TAG, private_ip=DOC_PRIVATE_IP,
            allowed_states=("stopped", "running"),
        )
        return {"db": db, "web": web, "doc": doc}

    def start_database_target(self, targets: dict) -> dict:
        expected = {
            "db": (DB_INSTANCE_ID, DB_PRIVATE_IP),
            "web": (WEB_INSTANCE_ID, WEB_PRIVATE_IP),
            "doc": (DOC_INSTANCE_ID, DOC_PRIVATE_IP),
        }
        current = self.validate_targets()
        for role, (instance_id, private_ip) in expected.items():
            observed = current.get(role, {})
            supplied = targets.get(role, {})
            if (
                observed.get("instance_id") != instance_id
                or observed.get("private_ip") != private_ip
                or supplied.get("instance_id") != instance_id
                or supplied.get("private_ip") != private_ip
                or observed.get("state") not in {"stopped", "running"}
            ):
                raise DemoRestoreError("AWS_DR_INSTANCE_IDENTITY_OR_STATE_MISMATCH")
        if current["db"].get("ssm_profile_present") is not True:
            raise DemoRestoreError("AWS_DR_INSTANCE_IDENTITY_OR_STATE_MISMATCH")

        started = {"web": False, "db": False}
        for role in ("web", "db"):
            instance = current[role]
            instance_id = expected[role][0]
            if instance.get("state") == "stopped":
                result = self._run([
                    "aws", "ec2", "start-instances", "--region", self.region,
                    "--instance-ids", instance_id,
                ])
                if result.returncode:
                    raise DemoRestoreError("AWS_DR_INSTANCE_START_FAILED")
                result = self._run([
                    "aws", "ec2", "wait", "instance-running", "--region", self.region,
                    "--instance-ids", instance_id,
                ])
                if result.returncode:
                    raise DemoRestoreError("AWS_DR_INSTANCE_START_FAILED")
                started[role] = True
            result = self._run([
                "aws", "ec2", "wait", "instance-status-ok", "--region", self.region,
                "--instance-ids", instance_id,
            ])
            if result.returncode:
                code = "DR_DATABASE_STATUS_CHECK_FAILED" if role == "db" else "DR_WEB_STATUS_CHECK_FAILED"
                raise DemoRestoreError(code)

        refreshed = self.validate_targets()
        if refreshed["db"]["state"] != "running" or refreshed["web"]["state"] != "running":
            raise DemoRestoreError("DR_DATABASE_OR_WEB_NOT_RUNNING")
        if refreshed["doc"]["state"] not in {"stopped", "running"}:
            raise DemoRestoreError("AWS_DR_INSTANCE_IDENTITY_OR_STATE_MISMATCH")
        return {
            "targets": refreshed,
            "started_by_request": started["db"],
            "web_started_by_request": started["web"],
        }

    def verify_source_writer_fence(self) -> None:
        runner = REPO_ROOT / "operations/finops/dr_environment_control.sh"
        if runner.is_symlink() or not runner.is_file() or not os.access(runner, os.R_OK | os.X_OK):
            raise DemoRestoreError("SOURCE_WRITE_FENCE_EXECUTOR_UNAVAILABLE")
        child_env = dict(self.child_env)
        child_env.update({
            "DR_SECRET_FILE": str(self.env.get("DR_SECRET_FILE", "/home/cloud/hospital-dr-secrets/dr.env")),
            "DR_STATE_DIR": str(self.state_dir),
            "DR_WORKFLOW_LOCK_FILE": str(self.env.get("DR_WORKFLOW_LOCK_FILE", self.state_dir / "workflow.lock")),
            "DR_WORKFLOW_LOCK_HELD": "1",
            "DR_SSH_CONFIG_FILE": str(self.ssh_config),
            "DR_SSH_KNOWN_HOSTS_FILE": str(self.known_hosts),
            "SSH_KEY": str(self.ssh_key),
        })
        try:
            result = subprocess.run(
                ["bash", str(runner), "verify-source-writer-fence"],
                cwd=str(REPO_ROOT), env=child_env, text=True, capture_output=True,
                check=False, timeout=90,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DemoRestoreError("ONPREM_SOURCE_WRITE_FENCE_UNVERIFIED") from exc
        expected = "[SOURCE WRITE FENCE] On-Prem MySQL read_only=1 super_read_only=1 verified."
        if result.returncode != 0 or expected not in result.stdout.splitlines():
            raise DemoRestoreError("ONPREM_SOURCE_WRITE_FENCE_UNVERIFIED")

    def prepare_ssh(self, targets: dict) -> None:
        for command in ("aws", "ssh", "scp", "python3", "session-manager-plugin"):
            if shutil.which(command, path=self.child_env.get("PATH")) is None:
                raise DemoRestoreError("SSM_SSH_TOOLING_UNAVAILABLE")
        if not self.ssh_key.is_absolute() or self.ssh_key.is_symlink() or not self.ssh_key.is_file() or not os.access(self.ssh_key, os.R_OK):
            raise DemoRestoreError("SSH_PRIVATE_KEY_UNAVAILABLE")
        key_mode = self.ssh_key.stat().st_mode & 0o777
        if key_mode & 0o077:
            raise DemoRestoreError("SSH_PRIVATE_KEY_PERMISSIONS_INVALID")
        helper = REPO_ROOT / "operations/runtime/ssm_ssh.sh"
        paths = REPO_ROOT / "operations/runtime_paths.sh"
        shell = (
            'source "$1"; source "$2"; dr_prepare_ssh_known_hosts && '
            'dr_ssm_write_ssh_config "$3" "$4" "$5" "$6" "$7" "$8" "$9" && '
            'dr_ssm_wait_for_ssh "DR DB direct SSM target" dr-db 18 5'
        )
        self.child_env.update({
            **self.child_env,
            "DR_STATE_DIR": str(self.state_dir),
            "DR_SSH_CONFIG_FILE": str(self.ssh_config),
            "DR_SSH_KNOWN_HOSTS_FILE": str(self.known_hosts),
            "SSH_KEY": str(self.ssh_key),
        })
        result = self._run([
            "bash", "-c", shell, "demo-restore-ssh", str(paths), str(helper),
            self.region, targets["web"]["instance_id"], str(self.ssh_key),
            str(self.known_hosts), DOC_PRIVATE_IP, DB_PRIVATE_IP,
            targets["db"]["instance_id"],
        ])
        if result.returncode:
            raise DemoRestoreError("DR_DATABASE_DIRECT_SSM_UNAVAILABLE")
        for path, expected_mode, code in (
            (self.ssh_config, 0o600, "SSM_SSH_CONFIG_PERMISSIONS_INVALID"),
            (self.known_hosts, 0o600, "SSH_KNOWN_HOSTS_PERMISSIONS_INVALID"),
        ):
            try:
                item = path.lstat()
            except OSError as exc:
                raise DemoRestoreError(code) from exc
            if (
                stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode)
                or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != expected_mode
            ):
                raise DemoRestoreError(code)

    def _ssh_script(self, host: str, script: str) -> subprocess.CompletedProcess:
        if self.ssh_config.is_symlink() or not self.ssh_config.is_file() or not os.access(self.ssh_config, os.R_OK):
            raise DemoRestoreError("SSM_SSH_CONFIG_UNAVAILABLE")
        result = self._run([
            "ssh", "-F", str(self.ssh_config), "-o", "BatchMode=yes",
            host, "sudo", "-n", "bash", "-s",
        ], input_text=script)
        return result

    def _require_remote_success(self, host: str, script: str, code: str) -> str:
        result = self._ssh_script(host, script)
        if result.returncode:
            raise DemoRestoreError(code)
        return result.stdout.strip()

    def fence_apps(self, targets: dict) -> None:
        refreshed = self.validate_targets()
        for role, host, container in (
            ("web", "dr-web", "hospital-dr-web"),
            ("doc", "dr-doc", "hospital-dr-emr"),
        ):
            if (
                targets.get(role, {}).get("instance_id") != refreshed[role].get("instance_id")
                or refreshed[role].get("state") not in {"stopped", "running"}
            ):
                raise DemoRestoreError("DR_APPLICATION_INSTANCE_IDENTITY_OR_STATE_MISMATCH")
            if refreshed[role].get("state") == "stopped":
                continue
            script = (
                "set -euo pipefail\n"
                f"container={_shell_quote(container)}\n"
                "command -v docker >/dev/null\n"
                "docker inspect \"$container\" >/dev/null\n"
                "if [ \"$(docker inspect --format '{{.State.Running}}' \"$container\")\" = true ]; then\n"
                "  docker stop --time 20 \"$container\" >/dev/null\n"
                "fi\n"
                "test \"$(docker inspect --format '{{.State.Running}}' \"$container\")\" = false\n"
                "printf 'APP_WRITE_FENCE_VERIFIED:%s\\n' \"$container\"\n"
            )
            result = self._require_remote_success(host, script, "APPLICATION_WRITE_FENCE_FAILED")
            if result != f"APP_WRITE_FENCE_VERIFIED:{container}":
                raise DemoRestoreError("APPLICATION_WRITE_FENCE_UNVERIFIED")

    def verify_apps_fenced(self) -> None:
        try:
            refreshed = self.validate_targets()
        except DemoRestoreError as exc:
            raise DemoRestoreError("APPLICATION_FENCE_RECHECK_FAILED") from exc
        for role, host, container in (
            ("web", "dr-web", "hospital-dr-web"),
            ("doc", "dr-doc", "hospital-dr-emr"),
        ):
            if refreshed[role].get("state") not in {"stopped", "running"}:
                raise DemoRestoreError("APPLICATION_FENCE_RECHECK_FAILED")
            if refreshed[role].get("state") == "stopped":
                continue
            script = (
                "set -euo pipefail\n"
                f"container={_shell_quote(container)}\n"
                "test \"$(docker inspect --format '{{.State.Running}}' \"$container\")\" = false\n"
                "printf 'APP_WRITE_FENCE_VERIFIED:%s\\n' \"$container\"\n"
            )
            try:
                result = self._require_remote_success(host, script, "APPLICATION_FENCE_RECHECK_FAILED")
            except DemoRestoreError as exc:
                raise DemoRestoreError("APPLICATION_FENCE_RECHECK_FAILED") from exc
            if result != f"APP_WRITE_FENCE_VERIFIED:{container}":
                raise DemoRestoreError("APPLICATION_FENCE_RECHECK_FAILED")

    def verify_no_application_db_sessions(self, secrets: dict[str, str], request_id: str) -> None:
        script = _remote_secret_prefix(secrets) + f'''set -euo pipefail
tmp="$(mktemp -d /dev/shm/hospital-dr-db-boundary.XXXXXX)"
trap 'rm -f "$tmp/mysql.cnf"; rmdir "$tmp" 2>/dev/null || true' EXIT
escaped="$(printf '%s' "$MYSQL_ROOT_PASS" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')"
printf '[client]\\nuser=root\\npassword="%s"\\n' "$escaped" >"$tmp/mysql.cnf"
chmod 0600 "$tmp/mysql.cnf"
mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e 'SELECT 1' >/dev/null
sessions="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e \\
  "SELECT COUNT(*) FROM information_schema.processlist WHERE HOST IS NOT NULL AND HOST NOT LIKE 'localhost%' AND HOST NOT LIKE 'IP_REDACTED%'")"
[[ "$sessions" == 0 ]]
printf 'DB_WRITE_FENCE_VERIFIED:{request_id}\\n'
'''
        output = self._require_remote_success("dr-db", script, "APPLICATION_DB_SESSION_RECHECK_FAILED")
        if output != f"DB_WRITE_FENCE_VERIFIED:{request_id}":
            raise DemoRestoreError("APPLICATION_DB_SESSION_RECHECK_FAILED")

    def database_preflight(self, secrets: dict[str, str], request_id: str) -> dict:
        script = _remote_secret_prefix(secrets) + f'''set -euo pipefail
umask 077
tmp="$(mktemp -d /dev/shm/hospital-dr-db-check.XXXXXX)"
trap 'rm -f "$tmp/mysql.cnf"; rmdir "$tmp" 2>/dev/null || true' EXIT
escaped="$(printf '%s' "$MYSQL_ROOT_PASS" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')"
printf '[client]\\nuser=root\\npassword="%s"\\n' "$escaped" >"$tmp/mysql.cnf"
chmod 0600 "$tmp/mysql.cnf"
database_bytes="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e \
  "SELECT COALESCE(SUM(data_length + index_length),0) FROM information_schema.tables WHERE table_schema='hospital_db'")"
database_exists="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e \
  "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='hospital_db'")"
remote_sessions="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e \
  "SELECT COUNT(*) FROM information_schema.processlist WHERE HOST IS NOT NULL AND HOST NOT LIKE 'localhost%' AND HOST NOT LIKE 'IP_REDACTED%'")"
db_identity="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e \
  "SELECT CONCAT(LOWER(@@server_uuid),'|',@@server_id,'|',@@hostname,'|',@@port,'|',@@global.read_only,'|',@@global.super_read_only,'|',COALESCE((SELECT CASE WHEN UPPER(variable_value) IN ('ON','1') THEN 'ON' ELSE 'OFF' END FROM performance_schema.persisted_variables WHERE LOWER(variable_name)='read_only' LIMIT 1),'MISSING'),'|',COALESCE((SELECT CASE WHEN UPPER(variable_value) IN ('ON','1') THEN 'ON' ELSE 'OFF' END FROM performance_schema.persisted_variables WHERE LOWER(variable_name)='super_read_only' LIMIT 1),'MISSING'))")"
mysql_pid_file="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e 'SELECT @@pid_file')"
available_bytes="$(df -PB1 /home/ubuntu | awk 'NR==2 {{print $4}}')"
service_pid="$(systemctl show --property=MainPID --value mysql.service)"
[[ "$database_bytes" =~ ^[0-9]+$ && "$database_exists" == 1 && "$remote_sessions" == 0 && "$available_bytes" =~ ^[0-9]+$ && -n "$db_identity" ]]
[[ "$mysql_pid_file" =~ ^/[A-Za-z0-9_./-]+$ && -f "$mysql_pid_file" && ! -L "$mysql_pid_file" ]]
[[ "$service_pid" =~ ^[1-9][0-9]*$ && "$(cat -- "$mysql_pid_file")" == "$service_pid" ]]
'''
        script += 'startup_proof="$(MYSQL_EXPECTED_PID="$service_pid" python3 - <<\'PY_STARTUP\'\n'
        script += _MYSQL_STARTUP_PROBE
        script += '\nPY_STARTUP\n)"\n'
        script += f'''printf 'PREFLIGHT|%s|%s|%s|%s|{request_id}\n' "$database_bytes" "$available_bytes" "$remote_sessions" "$db_identity"
printf '%s\n' "$startup_proof"
'''
        output = self._require_remote_success("dr-db", script, "DR_DATABASE_PREFLIGHT_FAILED")
        return _parse_database_preflight_response(output, request_id)

    def create_snapshot(self, secrets: dict[str, str], request_id: str) -> dict:
        remote_path = f"/home/ubuntu/db_backups/pre-restore/{request_id}/hospital_db.sql.gz.enc"
        script = _remote_secret_prefix(secrets) + f'''set -euo pipefail
umask 077
snapshot_dir="/home/ubuntu/db_backups/pre-restore/{request_id}"
install -d -m 0700 "$snapshot_dir"
chown ubuntu:ubuntu "$snapshot_dir"
snapshot="$snapshot_dir/hospital_db.sql.gz.enc"
part="$snapshot.part"
[[ ! -e "$snapshot" && ! -e "$part" ]]
tmp="$(mktemp -d /dev/shm/hospital-dr-db-backup.XXXXXX)"
cleanup() {{ rm -f "$tmp/mysql.cnf" "$tmp/backup.key"; rmdir "$tmp" 2>/dev/null || true; rm -f "$part"; }}
trap cleanup EXIT
escaped="$(printf '%s' "$MYSQL_ROOT_PASS" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')"
printf '[client]\\nuser=root\\npassword="%s"\\n' "$escaped" >"$tmp/mysql.cnf"
printf '%s' "$DB_BACKUP_ENCRYPTION_KEY" >"$tmp/backup.key"
chmod 0600 "$tmp/mysql.cnf" "$tmp/backup.key"
mysqldump --defaults-extra-file="$tmp/mysql.cnf" --single-transaction --routines --triggers --events --hex-blob hospital_db \\
  | gzip -c \\
  | openssl enc -aes-256-cbc -salt -pbkdf2 -pass "file:$tmp/backup.key" -out "$part" 2>/dev/null
test -s "$part"
openssl enc -d -aes-256-cbc -salt -pbkdf2 -in "$part" -pass "file:$tmp/backup.key" 2>/dev/null | gzip -t >/dev/null 2>&1
chmod 0600 "$part"
mv -- "$part" "$snapshot"
chown ubuntu:ubuntu "$snapshot"
chmod 0600 "$snapshot"
sha="$(sha256sum "$snapshot" | awk '{{print $1}}')"
size="$(stat -c %s "$snapshot")"
printf 'SNAPSHOT:{request_id}:%s:%s:%s\\n' "$sha" "$size" "$snapshot"
'''
        output = self._require_remote_success("dr-db", script, "DR_DATABASE_PRESNAPSHOT_FAILED")
        match = re.fullmatch(r"SNAPSHOT:" + re.escape(request_id) + r":([0-9a-f]{64}):([0-9]+):(.+)", output)
        if not match or match.group(3) != remote_path:
            raise DemoRestoreError("DR_DATABASE_PRESNAPSHOT_RESPONSE_INVALID")
        local_dir = self._active_request_dir / "pre-restore"
        local_dir.mkdir(mode=0o700)
        local_path = local_dir / "hospital_db.sql.gz.enc"
        result = self._run(["scp", "-F", str(self.ssh_config), "--", f"dr-db:{remote_path}", str(local_path)])
        if result.returncode or not local_path.is_file() or local_path.is_symlink():
            raise DemoRestoreError("DR_DATABASE_PRESNAPSHOT_FETCH_FAILED")
        os.chmod(local_path, 0o600)
        digest, size = _sha256(local_path)
        if digest != match.group(1) or size != int(match.group(2)):
            raise DemoRestoreError("DR_DATABASE_PRESNAPSHOT_LOCAL_MISMATCH")
        self.verify_encrypted_gzip(local_path, secrets["DB_BACKUP_ENCRYPTION_KEY"])
        return {
            "path": str(local_path), "remote_path": remote_path,
            "sha256": digest, "size_bytes": size,
            "integrity": "OPENSSL_GZIP_PASS",
        }

    def set_request_dir(self, path: Path) -> None:
        self._active_request_dir = path

    def verify_encrypted_gzip(self, path: Path, key: str) -> None:
        secret_dir = _create_local_secret_dir()
        try:
            key_file = secret_dir / "backup.key"
            _write_private_file(key_file, key.encode())
            decrypt = subprocess.Popen(
                ["openssl", "enc", "-d", "-aes-256-cbc", "-salt", "-pbkdf2", "-in", str(path), "-pass", f"file:{key_file}"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=self.child_env,
            )
            assert decrypt.stdout is not None
            gzip = subprocess.run(["gzip", "-t"], stdin=decrypt.stdout, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, check=False, env=self.child_env)
            decrypt.stdout.close()
            decrypt_code = decrypt.wait()
            if gzip.returncode or decrypt_code:
                raise DemoRestoreError("ENCRYPTED_GZIP_INTEGRITY_CHECK_FAILED")
        except OSError as exc:
            raise DemoRestoreError("ENCRYPTED_GZIP_VALIDATOR_UNAVAILABLE") from exc
        finally:
            shutil.rmtree(secret_dir, ignore_errors=True)

    def stage_selected(self, backup: Path, status: Path, restore_source: Path, request_id: str) -> str:
        remote_dir = f"/home/ubuntu/db_backups/demo-restore/{request_id}"
        script = f'''set -euo pipefail
install -d -m 0700 "{remote_dir}"
chown ubuntu:ubuntu "{remote_dir}"
test ! -e "{remote_dir}/{backup.name}"
test ! -e "{remote_dir}/{status.name}"
test ! -e "{remote_dir}/db_restore.sh"
printf 'STAGE_DIR_READY:{request_id}\\n'
'''
        output = self._require_remote_success("dr-db", script, "SELECTED_BACKUP_STAGE_PREPARATION_FAILED")
        if output != f"STAGE_DIR_READY:{request_id}":
            raise DemoRestoreError("SELECTED_BACKUP_STAGE_PREPARATION_FAILED")
        for source, name in ((backup, backup.name), (status, status.name), (restore_source, "db_restore.sh")):
            result = self._run(["scp", "-F", str(self.ssh_config), "--", str(source), f"dr-db:{remote_dir}/{name}"])
            if result.returncode:
                raise DemoRestoreError("SELECTED_BACKUP_UPLOAD_FAILED")
        chmod = f'''set -euo pipefail
chmod 0600 "{remote_dir}/{backup.name}" "{remote_dir}/{status.name}"
chmod 0700 "{remote_dir}/db_restore.sh"
printf 'SELECTED_BACKUP_STAGED:{request_id}\\n'
'''
        output = self._require_remote_success("dr-db", chmod, "SELECTED_BACKUP_STAGE_VERIFICATION_FAILED")
        if output != f"SELECTED_BACKUP_STAGED:{request_id}":
            raise DemoRestoreError("SELECTED_BACKUP_STAGE_VERIFICATION_FAILED")
        return f"{remote_dir}/{backup.name}"

    def restore(self, *, staged_backup: str, request_id: str, checksum: str,
                sidecar_checksum: str,
                snapshot: dict, secrets: dict[str, str], overwrite_authorization: dict) -> dict:
        remote_dir = f"/home/ubuntu/db_backups/demo-restore/{request_id}"
        status = staged_backup.removesuffix(".sql.gz.enc") + ".master_status"
        script_path = f"{remote_dir}/db_restore.sh"
        authorization_id = str((overwrite_authorization or {}).get("authorization_id") or "")
        if not UUID_RE.fullmatch(authorization_id):
            raise DemoRestoreError("EXISTING_DR_OVERWRITE_AUTHORIZATION_INVALID")
        values = {
            "DUMP_RESTORE_EXEC_ENABLED": "true",
            "DEMO_DUMP_RESTORE_MODE": "true",
            "DEMO_DUMP_REQUEST_ID": request_id,
            "DEMO_DUMP_CHATOPS_AUTHORIZATION_REQUEST_ID": request_id,
            "DEMO_DUMP_CHATOPS_AUTHORIZATION_ID": authorization_id,
            "DEMO_DUMP_CHATOPS_AUTHORIZATION_SCOPE": "REPLACE_EXISTING_AWS_DR_HOSPITAL_DB",
            "DEMO_DUMP_EXPECTED_DB_INSTANCE_ID": DB_INSTANCE_ID,
            "DEMO_DUMP_EXPECTED_DB_PRIVATE_IP": DB_PRIVATE_IP,
            "DEMO_DUMP_PRESNAPSHOT_FILE": snapshot["remote_path"],
            "DEMO_DUMP_PRESNAPSHOT_SHA256": snapshot["sha256"],
            "DB_BACKUP_FILE": staged_backup,
            "DB_BACKUP_ID": Path(staged_backup).name,
            "DB_BACKUP_EXPECTED_SHA256": checksum,
            "DEMO_DUMP_MASTER_STATUS_EXPECTED_SHA256": sidecar_checksum,
            "BACKUP_DIR": remote_dir,
            "TARGET_DB": "hospital_db",
            **secrets,
        }
        exports = "\n".join(f"export {name}={_shell_quote(value)}" for name, value in values.items())
        remote = "set +x\nset -euo pipefail\n" + exports + f"\nexec bash {_shell_quote(script_path)}\n"
        result = self._ssh_script("dr-db", remote)
        if result.returncode:
            # db_restore.sh emits only a sanitized, allowlisted reason marker.
            # Preserve that reason in the protected receipt instead of losing
            # it behind a generic SSH failure; never forward arbitrary stderr.
            failure_codes = re.findall(
                r"^DEMO_DB_RESTORE=BLOCKED reason=([A-Z0-9_]{1,96})$",
                result.stderr or "",
                re.M,
            )
            if len(failure_codes) == 1 and SAFE_CODE_RE.fullmatch(failure_codes[0]):
                raise DemoRestoreError(failure_codes[0])
            raise DemoRestoreError("RESTORE_COMMAND_FAILED_OR_RESULT_UNCERTAIN")
        proofs = re.findall(r"^REPLICA_FENCE\|(NONE|STOPPED)\|(NONE|PERSISTED_SKIP_REPLICA_START)$", result.stdout, re.M)
        if len(proofs) != 1:
            raise DemoRestoreError("REPLICA_FENCE_PROOF_MISSING_OR_AMBIGUOUS")
        state, persistence = proofs[0]
        if (state, persistence) not in {
            ("NONE", "NONE"),
            ("STOPPED", "PERSISTED_SKIP_REPLICA_START"),
        }:
            raise DemoRestoreError("REPLICA_FENCE_PROOF_INVALID")
        return {
            "channel_state": state,
            "restart_protection": persistence,
            "verified_at_utc": _utc_now(),
        }

    def verify_database(self, secrets: dict[str, str], request_id: str) -> dict:
        script = _remote_secret_prefix(secrets) + f'''set -euo pipefail
umask 077
tmp="$(mktemp -d /dev/shm/hospital-dr-db-verify.XXXXXX)"
trap 'rm -f "$tmp/mysql.cnf"; rmdir "$tmp" 2>/dev/null || true' EXIT
escaped="$(printf '%s' "$MYSQL_ROOT_PASS" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')"
printf '[client]\\nuser=root\\npassword="%s"\\n' "$escaped" >"$tmp/mysql.cnf"
chmod 0600 "$tmp/mysql.cnf"
version="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e 'SELECT VERSION()')"
mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names hospital_db -e 'SELECT 1' >/dev/null
db_state="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e \
  "SELECT CONCAT(LOWER(@@server_uuid),'|',@@server_id,'|',@@hostname,'|',@@port,'|',@@global.read_only,'|',@@global.super_read_only,'|',COALESCE((SELECT CASE WHEN UPPER(variable_value) IN ('ON','1') THEN 'ON' ELSE 'OFF' END FROM performance_schema.persisted_variables WHERE LOWER(variable_name)='read_only' LIMIT 1),'MISSING'),'|',COALESCE((SELECT CASE WHEN UPPER(variable_value) IN ('ON','1') THEN 'ON' ELSE 'OFF' END FROM performance_schema.persisted_variables WHERE LOWER(variable_name)='super_read_only' LIMIT 1),'MISSING'))")"
tables="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e \
  "SELECT table_name FROM information_schema.tables WHERE table_schema='hospital_db' AND table_type='BASE TABLE' ORDER BY table_name")"
mysql_pid_file="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names -e 'SELECT @@pid_file')"
service_pid="$(systemctl show --property=MainPID --value mysql.service)"
[[ -n "$version" && -n "$tables" && -n "$db_state" ]]
[[ "$mysql_pid_file" =~ ^/[A-Za-z0-9_./-]+$ && -f "$mysql_pid_file" && ! -L "$mysql_pid_file" ]]
[[ "$service_pid" =~ ^[1-9][0-9]*$ && "$(cat -- "$mysql_pid_file")" == "$service_pid" ]]
'''
        script += 'startup_proof="$(MYSQL_EXPECTED_PID="$service_pid" python3 - <<\'PY_STARTUP\'\n'
        script += _MYSQL_STARTUP_PROBE
        script += '\nPY_STARTUP\n)"\n'
        script += f'''printf 'DB_VERSION_OK:{request_id}\\n'
printf 'STANDBY:%s\\n' "$db_state"
printf '%s\\n' "$startup_proof"
while IFS= read -r table; do
  [[ "$table" =~ ^[A-Za-z][A-Za-z0-9_]*$ ]] || exit 41
  count="$(mysql --defaults-extra-file="$tmp/mysql.cnf" --batch --skip-column-names hospital_db -e "SELECT COUNT(*) FROM \`$table\`")"
  [[ "$count" =~ ^[0-9]+$ ]] || exit 42
  printf 'TABLE:%s:%s\\n' "$table" "$count"
done <<< "$tables"
'''
        output = self._require_remote_success("dr-db", script, "POST_RESTORE_DATABASE_VERIFICATION_FAILED")
        lines = output.splitlines()
        if len(lines) < 4 or lines[0] != f"DB_VERSION_OK:{request_id}":
            raise DemoRestoreError("POST_RESTORE_DATABASE_RESPONSE_INVALID")
        standby_match = re.fullmatch(
            r"STANDBY:(?P<server_uuid>[0-9a-f-]{36})\|(?P<server_id>[0-9]+)\|(?P<hostname>[A-Za-z0-9_.-]+)\|3306\|"
            r"(?P<read_only>[01])\|(?P<super_read_only>[01])\|"
            r"(?P<persisted_read_only>ON|OFF|MISSING)\|(?P<persisted_super_read_only>ON|OFF|MISSING)",
            lines[1] if len(lines) > 1 else "",
        )
        startup_match = re.fullmatch(
            r"STARTUP\|(VERIFIED|UNVERIFIED)\|"
            r"(ON|OFF|MISSING|CONFLICT|INVALID)\|"
            r"(ON|OFF|MISSING|CONFLICT|INVALID)\|([1-9][0-9]*)",
            lines[2] if len(lines) > 2 else "",
        )
        if (
            not standby_match or not UUID_RE.fullmatch(standby_match.group("server_uuid"))
            or not startup_match
        ):
            raise DemoRestoreError("POST_RESTORE_READ_ONLY_STANDBY_NOT_VERIFIED")
        persistence_source = _persistent_read_only_source(
            runtime_read_only=standby_match.group("read_only"),
            runtime_super_read_only=standby_match.group("super_read_only"),
            persisted_read_only=standby_match.group("persisted_read_only"),
            persisted_super_read_only=standby_match.group("persisted_super_read_only"),
            startup_read_only=startup_match.group(2),
            startup_super_read_only=startup_match.group(3),
            startup_source_verified=startup_match.group(1) == "VERIFIED",
        )
        if persistence_source is None:
            raise DemoRestoreError("POST_RESTORE_READ_ONLY_STANDBY_NOT_VERIFIED")
        if int(standby_match.group("server_id")) != 20:
            raise DemoRestoreError("POST_RESTORE_DB_SERVER_ID_MISMATCH")
        table_counts: dict[str, int] = {}
        for line in lines[3:]:
            match = re.fullmatch(r"TABLE:([A-Za-z][A-Za-z0-9_]*):([0-9]+)", line)
            if not match:
                raise DemoRestoreError("POST_RESTORE_DATABASE_RESPONSE_INVALID")
            table_counts[match.group(1).lower()] = int(match.group(2))
        if set(table_counts) != CORE_TABLES:
            raise DemoRestoreError("POST_RESTORE_SIX_TABLE_CONTRACT_MISMATCH")
        return {
            "mysql_responded": True,
            "core_tables": sorted(CORE_TABLES),
            "row_counts": table_counts,
            "database_identity": {
                "server_uuid": standby_match.group("server_uuid"),
                "server_id": int(standby_match.group("server_id")),
                "hostname": standby_match.group("hostname"),
                "port": 3306,
            },
            "read_only_standby": {
                "read_only": standby_match.group("read_only") == "1",
                "super_read_only": standby_match.group("super_read_only") == "1",
                "persisted_read_only": standby_match.group("persisted_read_only"),
                "persisted_super_read_only": standby_match.group("persisted_super_read_only"),
                "startup_read_only": startup_match.group(2),
                "startup_super_read_only": startup_match.group(3),
                "startup_source_verified": startup_match.group(1) == "VERIFIED",
                "persistence_source": persistence_source,
            },
        }


def _shell_quote(value: str) -> str:
    import shlex
    return shlex.quote(str(value))


def _remote_secret_prefix(secrets: Mapping[str, str]) -> str:
    return "set +x\nset -euo pipefail\n" + "\n".join(
        f"{name}={_shell_quote(value)}" for name, value in secrets.items()
    ) + "\n"


def _write_private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _create_local_secret_dir() -> Path:
    try:
        result = subprocess.run(
            ["findmnt", "-n", "-o", "FSTYPE", "--target", "/dev/shm"],
            text=True, capture_output=True, check=False,
        )
        if result.returncode or result.stdout.strip() != "tmpfs":
            raise DemoRestoreError("SECRET_TMPFS_UNAVAILABLE")
        return Path(tempfile.mkdtemp(prefix="hospital-dr-demo-check.", dir="/dev/shm"))
    except OSError as exc:
        raise DemoRestoreError("SECRET_TMPFS_UNAVAILABLE") from exc


def _sha256(path: Path) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise DemoRestoreError("BACKUP_ARTIFACT_INVALID")
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise DemoRestoreError("BACKUP_ARTIFACT_UNREADABLE") from exc
    if size <= 0:
        raise DemoRestoreError("BACKUP_ARTIFACT_EMPTY")
    return digest.hexdigest(), size


def _read_secrets(env: Mapping[str, str]) -> dict[str, str]:
    directory = Path(env.get("DEMO_DUMP_SECRET_DIR", ""))
    try:
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise DemoRestoreError("SECRET_FILE_PERMISSIONS_INVALID")
        result = {}
        for name, filename in (("MYSQL_ROOT_PASS", "mysql_root_pass"), ("DB_BACKUP_ENCRYPTION_KEY", "backup_key")):
            path = directory / filename
            item = path.lstat()
            if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o600:
                raise DemoRestoreError("SECRET_FILE_PERMISSIONS_INVALID")
            value = path.read_text(encoding="utf-8")
            if not value:
                raise DemoRestoreError("DATABASE_SECRET_UNAVAILABLE")
            result[name] = value
        return result
    except DemoRestoreError:
        raise
    except OSError as exc:
        raise DemoRestoreError("DATABASE_SECRET_UNAVAILABLE") from exc


def _validate_approval(args: argparse.Namespace, env: Mapping[str, str]) -> dict:
    backup = Path(env["DUMP_BACKUP_DIR"]) / args.backup_id
    fallback = bool(getattr(args, "failover_fallback", False))
    if fallback and (
        str(env.get("DR_FAILOVER_REQUEST_ID") or "") != args.request_id
        or str(env.get("DR_DUMP_FALLBACK_REQUEST_ID") or "") != args.request_id
        or env.get("DR_DUMP_FAILOVER_FALLBACK") != "1"
    ):
        raise DemoRestoreError("FAILOVER_FALLBACK_REQUEST_BINDING_INVALID")
    try:
        result = _validate_chatops_approval(
            request_id=args.request_id, backup_path=backup,
            expected_sha256=args.expected_sha256, environment=env,
            now=datetime.now(timezone.utc),
            allowed_request_origins=("GENERAL", "EMERGENCY", "CLOUD_SLACK_DR_TRIGGER"),
            require_existing_dr_overwrite_authorization=True,
            allow_conditional_failover_fallback=fallback,
        )
    except Exception as exc:
        code = str(exc)
        if SAFE_CODE_RE.fullmatch(code):
            raise DemoRestoreError(code) from exc
        raise DemoRestoreError("CHATOPS_APPROVAL_NOT_CURRENT") from exc
    if result.get("approval_required") != 2 or result.get("approval_count") != 2:
        raise DemoRestoreError("CURRENT_TWO_ADMIN_APPROVAL_REQUIRED")
    return result


def _validate_approval_unchanged(args: argparse.Namespace, env: Mapping[str, str], initial: dict) -> None:
    current = _validate_approval(args, env)
    if (
        current.get("execution_id") != initial.get("execution_id")
        or current.get("approver_ids") != initial.get("approver_ids")
        or current.get("approval_required") != 2
        or current.get("approval_count") != 2
        or current.get("request_origin") != initial.get("request_origin")
        or current.get("request_type") != initial.get("request_type")
        or current.get("request_source") != initial.get("request_source")
        or current.get("slack_client_key") != initial.get("slack_client_key")
        or current.get("recovery_plan") != initial.get("recovery_plan")
        or current.get("dump_restore_mode", "MANIFEST_VERIFIED")
        != initial.get("dump_restore_mode", "MANIFEST_VERIFIED")
        or current.get("expected_rpo") != initial.get("expected_rpo")
        or current.get("backup_sidecar_checksum") != initial.get("backup_sidecar_checksum")
        or current.get("overwrite_authorization") != initial.get("overwrite_authorization")
    ):
        raise DemoRestoreError("CHATOPS_APPROVAL_CHANGED_DURING_RESTORE")


def execute_restore(
    args: argparse.Namespace,
    *,
    environment: Mapping[str, str] | None = None,
    operations: SystemOperations | None = None,
) -> dict:
    env = dict(environment if environment is not None else os.environ)
    request_id, backup_id, checksum = validate_cli_identity(args)
    failover_fallback = bool(getattr(args, "failover_fallback", False))
    if failover_fallback:
        if getattr(args, "continue_failover", False):
            raise DemoRestoreError("FAILOVER_FALLBACK_CONTINUATION_NOT_ALLOWED")
        if (
            env.get("DR_FAILOVER_RECOVERY_MODE") != "AUTO"
            or env.get("DR_FAILOVER_REQUEST_ID") != request_id
            or env.get("DR_DUMP_FALLBACK_REQUEST_ID") != request_id
            or env.get("DR_DUMP_FAILOVER_FALLBACK") != "1"
            or env.get("DR_FAILOVER_DUMP_BACKUP_ID") != backup_id
            or str(env.get("DR_FAILOVER_DUMP_SHA256") or "").lower() != checksum
            or not re.fullmatch(r"[0-9a-f]{64}", str(env.get("DR_FAILOVER_DUMP_SIDECAR_SHA256") or ""))
            or not UUID_RE.fullmatch(str(env.get("DR_FAILOVER_DUMP_AUTHORIZATION_ID") or ""))
        ):
            raise DemoRestoreError("FAILOVER_FALLBACK_PLAN_BINDING_INVALID")
    validate_execution_gates(env, request_id=request_id)
    for name in ("CHATOPS_STATE_DB", "SLACK_ADMIN_USER_IDS", "DUMP_BACKUP_DIR", "SSH_KEY"):
        if not str(env.get(name, "")).strip():
            raise DemoRestoreError(f"{name.upper()}_UNAVAILABLE")
    backup_dir = Path(env["DUMP_BACKUP_DIR"])
    backup = backup_dir / backup_id
    if backup.is_symlink() or not backup.is_file():
        raise DemoRestoreError("SELECTED_BACKUP_UNAVAILABLE")
    try:
        selected = validate_backup_pair(backup, checksum, allow_legacy_manual=True)
    except Exception as exc:
        code = getattr(exc, "code", str(exc))
        if not SAFE_CODE_RE.fullmatch(str(code)):
            code = "BACKUP_CHECKSUM_OR_PAIR_INVALID"
        raise DemoRestoreError(str(code)) from exc
    if Path(selected["backup_path"]).name != backup_id or selected["sha256"] != checksum:
        raise DemoRestoreError("SELECTED_BACKUP_IDENTITY_MISMATCH")
    try:
        status_text = Path(selected["status_path"]).read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise DemoRestoreError("MASTER_STATUS_UNAVAILABLE") from exc
    timestamp_match = re.search(r"^\s*BackupTimestamp\s*:\s*(\S+)\s*$", status_text, re.I | re.M)
    expected_stamp = backup_id.removeprefix("db_backup_").removesuffix(".sql.gz.enc")
    if timestamp_match and timestamp_match.group(1) != expected_stamp:
        raise DemoRestoreError("MASTER_STATUS_BACKUP_ID_MISMATCH")
    sidecar_sha256, _ = _sha256(Path(selected["status_path"]))
    if selected["sidecar_sha256"] != sidecar_sha256:
        raise DemoRestoreError("MASTER_STATUS_CHECKSUM_MISMATCH")
    if failover_fallback and sidecar_sha256 != str(env["DR_FAILOVER_DUMP_SIDECAR_SHA256"]).lower():
        raise DemoRestoreError("MASTER_STATUS_CHECKSUM_MISMATCH")

    state_dir = Path(env.get("DEMO_DUMP_RESTORE_STATE_DIR", str(Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "demo-dump-restores")))
    request_dir = _private_request_dir(state_dir, request_id)
    log_path = request_dir / "execution.log"
    receipt_path = request_dir / "result.json"
    now = _utc_now()
    receipt = {
        "request_id": request_id,
        "backup_id": backup_id,
        "expected_sha256": checksum,
        "sidecar_sha256": sidecar_sha256,
        "manifest_sha256": selected["manifest_sha256"],
        "manifest_object_key": selected["manifest_object_key"],
        "manifest_status": selected["manifest_status"],
        "restore_mode": selected["restore_mode"],
        "expected_rpo": selected.get("expected_rpo"),
        "data_reference_at": selected.get("data_reference_at"),
        "data_reference_time_status": selected.get("data_reference_time_status", "UNVERIFIED"),
        "recovery_mode": "DUMP_FALLBACK" if failover_fallback else "DUMP_RESTORE",
        "master_status": {
            "file": selected["master_status_file"],
            "position": int(selected["master_status_position"]),
        },
        "target": {
            "instance_id": DB_INSTANCE_ID,
            "private_ip": DB_PRIVATE_IP,
            "port": 3306,
            "database": "hospital_db",
        },
        "status": "EXECUTING",
        "phase": "INITIALIZED",
        "phase_started_at_utc": now,
        "started_at_utc": now,
        "stages": {},
        "apps_fenced": False,
        "apps_fence_state": "NOT_STARTED",
        "db_instance_start": {
            "status": "NOT_STARTED", "started_by_request": False,
            "web_gateway_started_by_request": False,
        },
        "presnapshot": None,
        "restore_attempted": False,
        "dns_changed": False,
        "dr_active_recorded": False,
        "failure_code": None,
        "automatic_db_rollback": False,
    }
    _write_private_json(receipt_path, receipt)
    _append_log(log_path, "EXECUTION_STARTED")
    active_ops = operations or SystemOperations(env, backup_dir)
    if hasattr(active_ops, "set_request_dir"):
        active_ops.set_request_dir(request_dir)
    phase = "INITIALIZED"
    restore_attempted = False
    db_start_stage_entered = False

    def advance(name: str) -> None:
        nonlocal phase
        phase = name
        timestamp = _utc_now()
        receipt["phase"] = name
        receipt["phase_started_at_utc"] = timestamp
        receipt["stages"][name] = {"status": "STARTED", "started_at_utc": timestamp}
        _write_private_json(receipt_path, receipt)
        _append_log(log_path, f"{name}_STARTED")
        print(f"DEMO_DUMP_RESTORE request_id={request_id} phase={name} result=STARTED", flush=True)

    def complete(name: str) -> None:
        stage = receipt["stages"].setdefault(name, {})
        stage["status"] = "COMPLETE"
        stage["completed_at_utc"] = _utc_now()
        _write_private_json(receipt_path, receipt)
        _append_log(log_path, f"{name}_COMPLETE")
        print(f"DEMO_DUMP_RESTORE request_id={request_id} phase={name} result=COMPLETE", flush=True)

    try:
        with active_ops.locks():
            approval = _validate_approval(args, env) if isinstance(active_ops, SystemOperations) else active_ops.validate_approval(args, env)
            if (
                approval.get("dump_restore_mode", "MANIFEST_VERIFIED") != selected["restore_mode"]
                or approval.get("backup_sidecar_checksum", sidecar_sha256) != sidecar_sha256
                or (
                    selected["restore_mode"] == "LEGACY_MANUAL"
                    and approval.get("expected_rpo") != {"status": "NOT_MEASURED", "seconds": None}
                )
            ):
                raise DemoRestoreError("SELECTED_DUMP_REQUEST_BINDING_MISMATCH")
            if failover_fallback:
                plan = approval.get("recovery_plan")
                candidate = plan.get("dump") if isinstance(plan, dict) else None
                authorization = approval.get("overwrite_authorization")
                actual_master_status = {
                    "file": selected["master_status_file"],
                    "position": int(selected["master_status_position"]),
                }
                if (
                    not isinstance(candidate, dict)
                    or candidate.get("backup_id") != backup_id
                    or str(candidate.get("sha256") or "").lower() != checksum
                    or str(candidate.get("sidecar_sha256") or "").lower() != sidecar_sha256
                    or candidate.get("master_status") != actual_master_status
                    or not isinstance(authorization, dict)
                    or authorization.get("authorization_id") != env.get("DR_FAILOVER_DUMP_AUTHORIZATION_ID")
                    or authorization.get("request_id") != request_id
                ):
                    raise DemoRestoreError("FAILOVER_FALLBACK_APPROVAL_BINDING_INVALID")
            receipt.update({
                "request_origin": approval.get("request_origin"),
                "request_type": approval.get("request_type"),
                "request_source": approval.get("request_source"),
                "slack_client_key": approval.get("slack_client_key"),
                "production_action_verified": approval.get("production_action_verified") is True,
            })
            if failover_fallback:
                receipt["recovery_plan"] = approval["recovery_plan"]
            overwrite_authorization = approval.get("overwrite_authorization")
            if not isinstance(overwrite_authorization, dict):
                raise DemoRestoreError("EXISTING_DR_OVERWRITE_AUTHORIZATION_INVALID")
            receipt["overwrite_authorization"] = {
                "request_id": overwrite_authorization.get("request_id"),
                "authorization_id": overwrite_authorization.get("authorization_id"),
                "status": overwrite_authorization.get("status"),
                "scope": overwrite_authorization.get("scope"),
                "target": overwrite_authorization.get("target"),
                "backup_id": overwrite_authorization.get("backup_id"),
                "sha256": overwrite_authorization.get("sha256"),
                "approved_at": overwrite_authorization.get("approved_at"),
                "execution_id": overwrite_authorization.get("execution_id"),
            }
            if failover_fallback:
                receipt["overwrite_authorization"].update({
                    key: overwrite_authorization.get(key) for key in (
                        "grant_kind", "sidecar_sha256", "master_status", "data_timestamp",
                        "expected_rpo", "request_type", "request_origin", "request_source",
                        "slack_client_key", "approval_required", "approval_count", "approver_ids",
                    )
                })
                receipt["master_status"] = dict(candidate["master_status"])
            receipt["approval_evidence"] = {
                "approval_required": approval.get("approval_required"),
                "approval_count": approval.get("approval_count"),
                "execution_id": approval.get("execution_id"),
                "approver_ids": approval.get("approver_ids", []),
            }
            _write_private_json(receipt_path, receipt)
            if selected["restore_mode"] == "LEGACY_MANUAL":
                _append_log(log_path, "LEGACY_MANUAL_RPO_NOT_MEASURED_REQUEST_BOUND")
            if isinstance(active_ops, SystemOperations):
                active_ops.verify_source_writer_fence()
                _append_log(log_path, "SOURCE_WRITE_FENCE_VERIFIED")
            advance("TARGET_IDENTITY")
            targets = active_ops.validate_targets()
            receipt["aws_targets"] = targets
            receipt["phase"] = phase
            _write_private_json(receipt_path, receipt)
            complete(phase)

            advance("DB_ONLY_INSTANCE_START")
            db_start_stage_entered = True
            receipt["db_instance_start"] = {
                "status": "START_OR_STATE_VERIFICATION_IN_PROGRESS",
                "started_by_request": None,
                "request_id": request_id,
            }
            _write_private_json(receipt_path, receipt)
            _validate_approval_unchanged(args, env, approval) if isinstance(active_ops, SystemOperations) else active_ops.validate_approval_unchanged(args, env, approval)
            start_result = active_ops.start_database_target(targets)
            if not isinstance(start_result, dict) or not isinstance(start_result.get("targets"), dict):
                raise DemoRestoreError("DR_DATABASE_START_RESULT_INVALID")
            targets = start_result["targets"]
            if (
                targets.get("db", {}).get("state") != "running"
                or targets.get("web", {}).get("state") != "running"
                or targets.get("doc", {}).get("state") not in {"stopped", "running"}
            ):
                raise DemoRestoreError("DR_DATABASE_START_RESULT_UNSAFE")
            receipt["aws_targets"] = targets
            receipt["db_instance_start"] = {
                "status": "RUNNING", "started_by_request": bool(start_result.get("started_by_request")),
                "web_gateway_started_by_request": bool(start_result.get("web_started_by_request")),
                "completed_at_utc": _utc_now(),
            }
            _write_private_json(receipt_path, receipt)
            complete(phase)

            advance("SSM_TRANSPORT")
            active_ops.prepare_ssh(targets)
            complete(phase)

            advance("APPLICATION_FENCE")
            active_ops.fence_apps(targets)
            receipt["apps_fenced"] = True
            receipt["apps_fence_state"] = "VERIFIED"
            _write_private_json(receipt_path, receipt)
            complete(phase)

            secrets = _read_secrets(env) if isinstance(active_ops, SystemOperations) else active_ops.read_secrets(env)
            advance("PRESNAPSHOT_PREFLIGHT")
            preflight = active_ops.database_preflight(secrets, request_id)
            local_free = shutil.disk_usage(request_dir).free
            # Reserve twice the reported logical DB size plus 64 MiB; fail
            # conservatively before creating a snapshot if either side is tight.
            required = int(preflight["database_bytes"]) * 2 + 64 * 1024 * 1024
            if int(preflight["remote_free_bytes"]) < required or local_free < required:
                raise DemoRestoreError("PRESNAPSHOT_DISK_SPACE_INSUFFICIENT")
            if (
                not _valid_preflight_read_only_standby(preflight.get("read_only_standby"))
                or not isinstance(preflight.get("identity"), dict)
            ):
                raise DemoRestoreError("DR_DATABASE_NOT_PERSISTENT_READ_ONLY_STANDBY")
            receipt["database_preflight"] = {
                "identity": preflight["identity"],
                "read_only_standby": preflight["read_only_standby"],
                "remote_sessions": int(preflight["remote_sessions"]),
                "completed_at_utc": _utc_now(),
            }
            _write_private_json(receipt_path, receipt)
            complete(phase)

            advance("PRESNAPSHOT")
            snapshot = active_ops.create_snapshot(secrets, request_id)
            if not re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("sha256", ""))) or int(snapshot.get("size_bytes", 0)) <= 0:
                raise DemoRestoreError("PRESNAPSHOT_VERIFICATION_FAILED")
            receipt["presnapshot"] = {
                "local_path": snapshot["path"],
                "remote_path": snapshot["remote_path"],
                "sha256": snapshot["sha256"],
                "size_bytes": int(snapshot["size_bytes"]),
                "integrity": snapshot["integrity"],
                "completed_at_utc": _utc_now(),
            }
            _write_private_json(receipt_path, receipt)
            complete(phase)

            advance("SELECTED_DUMP_REVALIDATION")
            if isinstance(active_ops, SystemOperations):
                active_ops.verify_encrypted_gzip(backup, secrets["DB_BACKUP_ENCRYPTION_KEY"])
            else:
                active_ops.validate_selected_dump(backup, checksum, secrets)
            selected_sha, _ = _sha256(backup)
            if selected_sha != checksum:
                raise DemoRestoreError("SELECTED_BACKUP_CHECKSUM_MISMATCH")
            complete(phase)

            status_path = Path(selected["status_path"])
            advance("SELECTED_DUMP_STAGE")
            staged_backup = active_ops.stage_selected(backup, status_path, REPO_ROOT / "automation/ansible/roles/db_recovery/files/db_restore.sh", request_id)
            complete(phase)

            advance("FINAL_FENCE_AND_AUTHORIZATION_CHECK")
            final_targets = active_ops.validate_targets()
            if final_targets != targets:
                raise DemoRestoreError("AWS_DR_INSTANCE_IDENTITY_CHANGED")
            active_ops.verify_apps_fenced()
            active_ops.verify_no_application_db_sessions(secrets, request_id)
            _validate_approval_unchanged(args, env, approval) if isinstance(active_ops, SystemOperations) else active_ops.validate_approval_unchanged(args, env, approval)
            complete(phase)

            advance("RESTORE_ATTEMPTED")
            restore_attempted = True
            receipt["restore_attempted"] = True
            receipt["overwrite_approval_request_id"] = request_id
            receipt["overwrite_authorized_at_utc"] = _utc_now()
            _write_private_json(receipt_path, receipt)
            _append_log(log_path, "RESTORE_COMMAND_SUBMITTED")
            restore_kwargs = {
                "staged_backup": staged_backup,
                "request_id": request_id,
                "checksum": checksum,
                "sidecar_checksum": sidecar_sha256,
                "snapshot": snapshot,
                "secrets": secrets,
            }
            if isinstance(active_ops, SystemOperations):
                restore_kwargs["overwrite_authorization"] = approval.get("overwrite_authorization")
            restore_result = active_ops.restore(**restore_kwargs)
            if isinstance(active_ops, SystemOperations):
                if not isinstance(restore_result, dict):
                    raise DemoRestoreError("REPLICA_FENCE_PROOF_MISSING_OR_AMBIGUOUS")
                receipt["replication_fence"] = restore_result
                if failover_fallback and restore_result.get("channel_state") not in {"NONE", "STOPPED"}:
                    raise DemoRestoreError("REPLICA_FENCE_PROOF_INVALID")
                _write_private_json(receipt_path, receipt)
            complete(phase)

            advance("POST_RESTORE_DB_VERIFICATION")
            verification = active_ops.verify_database(secrets, request_id)
            verified_read_only = verification.get("read_only_standby")
            if (
                verification.get("mysql_responded") is not True
                or set(verification.get("core_tables", [])) != CORE_TABLES
                or set(verification.get("row_counts", {})) != CORE_TABLES
                or not _valid_preflight_read_only_standby(verified_read_only)
                or verification.get("database_identity") != preflight.get("identity")
            ):
                raise DemoRestoreError("POST_RESTORE_DATABASE_VERIFICATION_FAILED")
            receipt["database_verification"] = verification
            complete(phase)
            receipt["apps_fenced"] = True
            receipt["dump_restore_status"] = "PASS"
            receipt["dump_failover_status"] = "NOT_STARTED"
            receipt["status"] = "DB_RESTORED_NOT_FAILOVER_COMPLETE"
            receipt["phase"] = "DB_RESTORED_NOT_FAILOVER_COMPLETE"
            receipt["completed_at_utc"] = _utc_now()
            receipt["failure_code"] = None
            receipt["operator_intervention_required"] = False
            _write_private_json(receipt_path, receipt)
            _append_log(log_path, "DB_RESTORED_NOT_FAILOVER_COMPLETE")
            return receipt
    except Exception as exc:
        raw_code = exc.code if isinstance(exc, DemoRestoreError) else "UNEXPECTED_EXECUTION_ERROR"
        code = raw_code if SAFE_CODE_RE.fullmatch(raw_code) else "UNEXPECTED_EXECUTION_ERROR"
        status = "PARTIAL_FAILURE" if restore_attempted or db_start_stage_entered or phase == "APPLICATION_FENCE" else "FAILED"
        receipt["status"] = status
        receipt["dump_restore_status"] = "PARTIAL_FAILURE" if restore_attempted else "FAILED"
        receipt["dump_failover_status"] = "NOT_STARTED"
        receipt["phase"] = phase
        receipt["failure_code"] = code
        if phase in receipt.get("stages", {}):
            receipt["stages"][phase]["status"] = "FAILED_OR_UNCERTAIN"
            receipt["stages"][phase]["failure_code"] = code
            receipt["stages"][phase]["completed_at_utc"] = _utc_now()
        receipt["apps_fenced"] = bool(receipt.get("apps_fenced"))
        if phase == "APPLICATION_FENCE":
            receipt["apps_fence_state"] = "PARTIAL_OR_UNKNOWN"
        receipt["completed_at_utc"] = _utc_now()
        receipt["operator_intervention_required"] = status == "PARTIAL_FAILURE" or receipt["apps_fenced"]
        receipt["automatic_db_rollback"] = False
        receipt["dns_changed"] = False
        receipt["dr_active_recorded"] = False
        try:
            _write_private_json(receipt_path, receipt)
            _append_log(log_path, f"{status}_{code}")
        except Exception:
            pass
        print(f"DEMO_DUMP_RESTORE request_id={request_id} phase={phase} result={status} code={code}", flush=True)
        return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--backup-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--continue-failover", action="store_true")
    parser.add_argument("--resume-failover-only", action="store_true")
    parser.add_argument("--failover-fallback", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--validate-cli-only", action="store_true", help=argparse.SUPPRESS)
    return parser


def _read_final_dr_state(env: Mapping[str, str]) -> str:
    state_file = Path(
        env.get("DR_STATE_FILE")
        or (Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "dr_state")
    )
    try:
        metadata = state_file.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_size > 128
        ):
            return "UNKNOWN"
        value = state_file.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return "UNKNOWN"
    allowed = {"IDLE", "FAILOVER_EXECUTING", "DR_ACTIVE", "FAILED", "PARTIAL_FAILURE"}
    return value if value in allowed else "UNKNOWN"


def _emit_safe_environment_start_summary(output: str) -> bool:
    allowed = (
        "[FAILOVER LAUNCH]", "[RPO WARNING]", "[DB RECOVERY]", "[DB PROMOTION",
        "[DR START]", "[EC2 START]", "[CONNECTIVITY]", "[START BLOCKED]",
        "[START ERROR]", "[APPLICATION ERROR]", "[APPLICATION VALIDATION ERROR]",
        "[DNS]", "[DNS ERROR]", "[DR STATE]", "[DR STARTED]",
        "[FAILOVER BLOCKED]", "[AWS VALIDATION ERROR]", "[VALIDATION]",
    )
    complete = False
    for line in output.splitlines():
        if line.startswith(
            "[DR STARTED] Web, EMR, and DB Health checks passed and Cloudflare DNS points to the approved DR Web."
        ):
            complete = True
        if line.startswith(allowed):
            print(line[:1000], flush=True)
    return complete


def continue_failover_after_dump_restore(
    args: argparse.Namespace,
    receipt: dict,
    *,
    environment: Mapping[str, str] | None = None,
    resume_only: bool = False,
) -> tuple[dict, int]:
    """Continue an already-verified Dump through the existing DR start path."""
    env = dict(environment if environment is not None else os.environ)
    request_id, backup_id, checksum = validate_cli_identity(args)
    state_dir = Path(env.get(
        "DEMO_DUMP_RESTORE_STATE_DIR",
        str(Path(env.get("DR_STATE_DIR", "/var/lib/hospital-dr")) / "demo-dump-restores"),
    ))
    receipt_path = state_dir / request_id / "result.json"
    log_path = state_dir / request_id / "execution.log"

    def blocked(code: str, *, preserve_receipt: bool = False) -> tuple[dict, int]:
        if preserve_receipt:
            receipt.setdefault("request_id", request_id)
            receipt["dump_restore_status"] = "PASS"
            receipt["dump_failover_status"] = "BLOCKED"
            receipt["failure_code"] = code
            receipt["failover_pipeline"] = {"status": "BLOCKED", "failure_code": code}
        else:
            receipt["failover_pipeline"] = {"status": "BLOCKED", "failure_code": code}
            receipt["dump_restore_status"] = "PASS"
            receipt["dump_failover_status"] = "BLOCKED"
            _write_private_json(receipt_path, receipt)
        if log_path.is_file() and not log_path.is_symlink():
            _append_log(log_path, f"DR_ENVIRONMENT_START_BLOCKED_{code}")
        print(f"DR_ENVIRONMENT_START=BLOCKED request_id={request_id} code={code}", flush=True)
        return receipt, 10

    if resume_only:
        database = env.get("CHATOPS_STATE_DB", "/var/lib/hospital-dr/chatops_state.sqlite3")
        gate = REPO_ROOT / "operations/failover/chatops_launch_gate.py"
        if gate.is_symlink() or not gate.is_file() or not os.access(gate, os.R_OK):
            return blocked("DUMP_FOLLOWUP_APPROVAL_GATE_UNAVAILABLE", preserve_receipt=True)
        gate_args = [
            sys.executable, str(gate), "--database", database, "--request-id", request_id,
            "--dump-restore-followup", "--dump-followup-resume",
            "--backup-id", backup_id, "--sha256", checksum, "--dump-receipt", str(receipt_path),
        ]
        try:
            gate_result = subprocess.run(
                gate_args, cwd=str(REPO_ROOT), env=env, text=True,
                capture_output=True, check=False, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return blocked("DUMP_FOLLOWUP_APPROVAL_RECHECK_FAILED", preserve_receipt=True)
        if gate_result.returncode != 0:
            match = re.search(r"FAILOVER_LAUNCH=BLOCKED reason=([A-Z0-9_]+)", gate_result.stdout)
            return blocked(
                match.group(1) if match else "DUMP_FOLLOWUP_APPROVAL_RECHECK_FAILED",
                preserve_receipt=True,
            )
        try:
            receipt = _read_existing_private_json(receipt_path)
        except DemoRestoreError as exc:
            return blocked(exc.code, preserve_receipt=True)
    else:
        try:
            current_approval = _validate_approval(args, env)
        except DemoRestoreError as exc:
            return blocked(exc.code)
        prior_approval = receipt.get("approval_evidence") or {}
        prior_authorization = receipt.get("overwrite_authorization") or {}
        current_authorization = current_approval.get("overwrite_authorization") or {}
        if (
            current_approval.get("approval_count") != 2
            or current_approval.get("approval_required") != 2
            or current_approval.get("execution_id") != prior_approval.get("execution_id")
            or current_approval.get("approver_ids") != prior_approval.get("approver_ids")
            or current_authorization.get("authorization_id") != prior_authorization.get("authorization_id")
            or current_authorization.get("backup_id") != backup_id
            or str(current_authorization.get("sha256") or "").lower() != checksum
        ):
            return blocked("APPROVAL_CHANGED_AFTER_RESTORE")
        try:
            validate_dump_restore_receipt(
                receipt_path, request_id=request_id, backup_id=backup_id, expected_sha256=checksum,
            )
        except Exception:
            return blocked("RESTORE_RECEIPT_NOT_VALID_FOR_PROMOTION")

    pre_state = _read_final_dr_state(env)
    if pre_state not in {"IDLE", "FAILED"}:
        if resume_only:
            return blocked(f"DR_STATE_NOT_READY_{pre_state}", preserve_receipt=True)
        receipt["failover_pipeline"] = {"status": "BLOCKED", "failure_code": "DR_STATE_NOT_READY", "pre_state": pre_state}
        _write_private_json(receipt_path, receipt)
        _append_log(log_path, "FULL_FAILOVER_BLOCKED_DR_STATE_NOT_READY")
        print(f"FULL_FAILOVER=BLOCKED request_id={request_id} code=DR_STATE_NOT_READY", flush=True)
        return receipt, 10

    runner = REPO_ROOT / "operations/finops/dr_environment_control.sh"
    if runner.is_symlink() or not runner.is_file() or not os.access(runner, os.R_OK | os.X_OK):
        return blocked("EXISTING_DR_ENVIRONMENT_START_UNAVAILABLE", preserve_receipt=resume_only)
    child_env = dict(env)
    child_env.update({
        "DR_FAILOVER_REQUEST_ID": request_id,
        "DR_FAILOVER_RECOVERY_MODE": "APPROVED_DUMP",
        "DR_FAILOVER_DUMP_BACKUP_ID": backup_id,
        "DR_FAILOVER_DUMP_SHA256": checksum,
    })
    if resume_only:
        child_env["DR_FAILOVER_DUMP_FOLLOWUP_RESUME"] = "1"
    else:
        child_env.pop("DR_FAILOVER_DUMP_FOLLOWUP_RESUME", None)
    started_at = _utc_now()
    _append_log(log_path, "DR_ENVIRONMENT_START_STARTED")
    try:
        timeout_seconds = max(1.0, float(env.get("CHATOPS_EXECUTION_TIMEOUT_SECONDS", "3600")))
        process = subprocess.run(
            ["bash", str(runner), "start"], cwd=str(REPO_ROOT), env=child_env,
            text=True, capture_output=True, check=False, timeout=timeout_seconds,
        )
        completion_marker = _emit_safe_environment_start_summary(
            process.stdout + "\n" + process.stderr
        )
        return_code = int(process.returncode)
    except subprocess.TimeoutExpired:
        completion_marker = False
        return_code = 124
    except OSError:
        completion_marker = False
        return_code = 127

    final_state = _read_final_dr_state(env)
    succeeded = return_code == 0 and final_state == "DR_ACTIVE" and completion_marker
    receipt["failover_pipeline"] = {
        "request_id": request_id,
        "recovery_mode": "APPROVED_DUMP",
        "status": "SUCCEEDED" if succeeded else "PARTIAL_FAILURE",
        "execution_path": "DR_ENVIRONMENT_START",
        "backup_id": backup_id,
        "sha256": checksum,
        "started_at_utc": started_at,
        "return_code": return_code,
        "final_dr_state": final_state,
        "completion_marker_verified": completion_marker,
        "completed_at_utc": _utc_now(),
    }
    receipt["phase"] = "FAILOVER_COMPLETE" if succeeded else "DR_ENVIRONMENT_START"
    receipt["completed_at_utc"] = _utc_now()
    receipt["status"] = "FAILOVER_COMPLETE" if succeeded else "PARTIAL_FAILURE"
    receipt["dump_restore_status"] = "PASS"
    receipt["dump_failover_status"] = "PASS" if succeeded else "PARTIAL_FAILURE"
    receipt["dump_failover_resume_attempted"] = bool(resume_only)
    receipt["failure_code"] = None if succeeded else "DR_ENVIRONMENT_START_FAILED_AFTER_DUMP_RESTORE"
    receipt["operator_intervention_required"] = not succeeded
    receipt["dns_changed"] = True if succeeded else "UNKNOWN"
    receipt["dr_active_recorded"] = bool(succeeded and final_state == "DR_ACTIVE")
    receipt["automatic_db_rollback"] = False
    receipt.setdefault("stages", {})["DR_ENVIRONMENT_START"] = {
        "status": "COMPLETE" if succeeded else "FAILED_OR_UNCERTAIN",
        "started_at_utc": started_at,
        "completed_at_utc": _utc_now(),
    }
    _write_private_json(receipt_path, receipt)
    _append_log(log_path, "DR_ENVIRONMENT_START_COMPLETE" if succeeded else "PARTIAL_FAILURE_DR_ENVIRONMENT_START")
    print(
        f"DR_ENVIRONMENT_START request_id={request_id} status={receipt['status']} "
        f"dr_state={final_state} recovery_mode=APPROVED_DUMP",
        flush=True,
    )
    return receipt, 0 if succeeded else 2


def exit_code_for_status(status: str) -> int:
    # Exit 0 is reserved for a complete Failover. A DB-only restore must not be
    # mistaken for overall success by the current generic ChatOps executor.
    if status == "DB_RESTORED_NOT_FAILOVER_COMPLETE":
        return 10
    if status == "FAILOVER_COMPLETE":
        return 0
    if status == "PARTIAL_FAILURE":
        return 2
    return 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.validate_cli_only:
        try:
            validate_cli_identity(args)
        except DemoRestoreError as exc:
            print(f"DEMO_DUMP_RESTORE=BLOCKED reason={exc.code}", file=sys.stderr)
            return 1
        return 0
    if args.resume_failover_only:
        try:
            validate_cli_identity(args)
        except DemoRestoreError as exc:
            print(f"DEMO_DUMP_RESTORE=BLOCKED reason={exc.code}", file=sys.stderr)
            return 1
        receipt, continuation_code = continue_failover_after_dump_restore(
            args, {}, resume_only=True,
        )
        print(
            "DEMO_DUMP_RESTORE "
            f"request_id={receipt.get('request_id', args.request_id)} "
            f"DUMP_RESTORE={receipt.get('dump_restore_status', 'PASS')} "
            f"DUMP_FAILOVER={receipt.get('dump_failover_status', 'BLOCKED')} "
            f"failure_code={receipt.get('failure_code') or 'NONE'}",
            flush=True,
        )
        return continuation_code
    try:
        receipt = execute_restore(args)
    except DemoRestoreError as exc:
        print(f"DEMO_DUMP_RESTORE=BLOCKED reason={exc.code}", file=sys.stderr)
        return 1
    if args.continue_failover and receipt.get("status") == "DB_RESTORED_NOT_FAILOVER_COMPLETE":
        receipt, continuation_code = continue_failover_after_dump_restore(args, receipt)
        pipeline_failure = (receipt.get("failover_pipeline") or {}).get("failure_code")
        print(
            "DEMO_DUMP_RESTORE "
            f"request_id={receipt['request_id']} status={receipt['status']} "
            f"failure_code={receipt.get('failure_code') or pipeline_failure or 'NONE'}",
            flush=True,
        )
        return continuation_code
    print(
        "DEMO_DUMP_RESTORE "
        f"request_id={receipt['request_id']} status={receipt['status']} "
        f"failure_code={receipt.get('failure_code') or 'NONE'}",
        flush=True,
    )
    if args.failover_fallback and receipt.get("status") == "DB_RESTORED_NOT_FAILOVER_COMPLETE":
        return 0
    return exit_code_for_status(receipt["status"])


if __name__ == "__main__":
    raise SystemExit(main())
