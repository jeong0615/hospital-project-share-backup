#!/usr/bin/env python3
"""Read-only proof that one Dump-cutover app host remains fenced before DNS."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Callable


CUTOVER_ROOT = Path("/var/lib/hospital-dr/db-endpoint-cutovers")
APP_CONTRACT = {
    "web": ("hospital-dr-web", "dr-web", "IP_REDACTED"),
    "emr": ("hospital-dr-emr", "dr-doc", "IP_REDACTED"),
}
SAFE_TIMERS = {
    "apt-daily.timer", "apt-daily-upgrade.timer", "fstrim.timer",
    "logrotate.timer", "man-db.timer", "motd-news.timer",
    "systemd-tmpfiles-clean.timer", "ua-timer.timer",
}
SAFE_CRON_JOBS = {
    "apt-compat", "dpkg", "e2scrub_all", "logrotate", "man-db", "passwd", "sysstat",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class AppFenceError(RuntimeError):
    """Non-secret preflight failure code."""


def _read_private_regular(path: Path, *, owner_uid: int) -> str:
    if path.is_symlink() or not path.is_file():
        raise AppFenceError("APP_CUTOVER_RECEIPT_MISSING")
    metadata = path.stat()
    if metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise AppFenceError("APP_CUTOVER_RECEIPT_PERMISSIONS_INVALID")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AppFenceError("APP_CUTOVER_RECEIPT_UNREADABLE") from exc


def _parse_env(text: str, keys: tuple[str, ...]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in keys:
            if key in values or not value:
                raise AppFenceError("APP_DB_CONFIG_INVALID")
            values[key] = value
    if set(values) != set(keys):
        raise AppFenceError("APP_DB_CONFIG_INVALID")
    return values


def validate_app_fence(
    *,
    kind: str,
    cutover_id: str,
    isolated_private_ip: str,
    root: Path = CUTOVER_ROOT,
    current_env_path: Path | None = None,
    owner_uid: int = 0,
    snapshot_text: str | None = None,
    current_env_text: str | None = None,
    container_metadata_text: str | None = None,
    current_container: str | None = None,
    rollback_container: str | None = None,
    pm2_service_state: str = "inactive",
    pm2_processes_text: str = "[]",
    listener_output: str = "",
    timers_text: str = "",
    active_services_text: str = "",
    running_containers_text: str = "",
    cron_entries: tuple[str, ...] = (),
    fence_service_state: str = "inactive",
    fence_probe_output: str = "",
) -> dict:
    if kind not in APP_CONTRACT:
        raise AppFenceError("APP_KIND_INVALID")
    try:
        normalized = str(uuid.UUID(cutover_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AppFenceError("CUTOVER_ID_INVALID") from exc
    if normalized != cutover_id.lower():
        raise AppFenceError("CUTOVER_ID_INVALID")

    container_name, _inventory_host, source_ip = APP_CONTRACT[kind]
    directory = root / normalized
    if snapshot_text is None:
        snapshot_text = _read_private_regular(directory / "app.env.before", owner_uid=owner_uid)
    if container_metadata_text is None:
        container_metadata_text = _read_private_regular(directory / "container.json", owner_uid=owner_uid)
    if current_env_text is None:
        if current_env_path is None:
            raise AppFenceError("APP_DB_CONFIG_UNAVAILABLE")
        current_env_text = _read_private_regular(current_env_path, owner_uid=owner_uid)
    try:
        metadata = json.loads(container_metadata_text)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AppFenceError("APP_CUTOVER_RECEIPT_INVALID") from exc
    if not isinstance(metadata, dict):
        raise AppFenceError("APP_CUTOVER_RECEIPT_INVALID")

    before = _parse_env(snapshot_text, ("DB_HOST", "DB_PORT", "DB_NAME"))
    current = _parse_env(
        current_env_text, ("DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME")
    )
    expected_rollback = f"{container_name}-dbcutover-{normalized.replace('-', '')}"
    original_id = str(metadata.get("container_id", ""))
    image_id = str(metadata.get("image_id", ""))
    if (
        metadata.get("container") != container_name
        or metadata.get("rollback_container") != expected_rollback
        or metadata.get("was_running") is not True
        or not HEX64.fullmatch(original_id)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
        or before != {"DB_HOST": "IP_REDACTED", "DB_PORT": "3306", "DB_NAME": "hospital_db"}
        or current["DB_HOST"] != isolated_private_ip
        or current["DB_PORT"] != "3307"
        or current["DB_USER"] != "hospital_dr_service"
        or current["DB_NAME"] != "hospital_db"
    ):
        raise AppFenceError("APP_CUTOVER_RECEIPT_MISMATCH")

    try:
        current_data = (current_container or "").split("|")
        rollback_data = (rollback_container or "").split("|")
        pm2_rows = json.loads(pm2_processes_text)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AppFenceError("APP_RUNTIME_STATE_INVALID") from exc
    if (
        len(current_data) != 4
        or not HEX64.fullmatch(current_data[0])
        or current_data[1] != "false"
        or current_data[2] != normalized
        or current_data[3] not in {"unless-stopped", "no"}
        or len(rollback_data) != 2
        or rollback_data != [original_id, "false"]
    ):
        raise AppFenceError("APP_CONTAINER_NOT_FENCED")
    if current_data[3] == "no" and (
        fence_service_state != "active"
        or fence_probe_output.strip() != "DUMP_READONLY_EXTERNAL_FENCE=PASS ports=80,443 interface=non-loopback"
    ):
        raise AppFenceError("APP_RESTART_DISABLED_WITHOUT_EXTERNAL_FENCE")
    if pm2_service_state not in {"inactive", "failed", "unknown", "not-found"}:
        raise AppFenceError("LEGACY_APP_SERVICE_ACTIVE")
    if not isinstance(pm2_rows, list):
        raise AppFenceError("LEGACY_APP_PROCESS_STATE_INVALID")
    if any(
        row.get("name") in {"hospital-web", "hospital-emr"}
        and row.get("pm2_env", {}).get("status") == "online"
        for row in pm2_rows if isinstance(row, dict)
    ):
        raise AppFenceError("LEGACY_APP_PROCESS_ACTIVE")
    if listener_output.strip():
        raise AppFenceError("HOST_APP_PORT_STILL_LISTENING")
    if running_containers_text.strip():
        raise AppFenceError("UNAPPROVED_APP_CONTAINER_RUNNING")
    for line in active_services_text.splitlines():
        unit = line.split()[0].lower() if line.split() else ""
        if unit == "hospital-dr-dump-readonly-fence.service":
            continue
        if any(token in unit for token in ("hospital", "emr", "pm2", "docker-compose", "app-start")):
            raise AppFenceError("UNAPPROVED_APP_SERVICE_ACTIVE")

    for line in timers_text.splitlines():
        fields = line.split()
        if not fields:
            continue
        timer = next((field for field in reversed(fields) if field.endswith(".timer")), "")
        if timer not in SAFE_TIMERS:
            raise AppFenceError("UNAPPROVED_APP_SYSTEMD_TIMER_PRESENT")
    if any(line.strip() and not line.lstrip().startswith("#") for line in cron_entries):
        raise AppFenceError("UNAPPROVED_APP_CRON_JOB_PRESENT")

    return {
        "host": "dr-web" if kind == "web" else "dr-doc",
        "source_ip": source_ip,
        "container_id": current_data[0],
        "cutover_id": normalized,
        "db_host": isolated_private_ip,
        "db_port": 3307,
        "stopped": True,
        "restart_policy": current_data[3],
        "external_fence": current_data[3] == "no",
        "listener_absent": True,
        "app_health_checked": False,
    }


def _run(command: list[str], *, runner: Callable = subprocess.run) -> subprocess.CompletedProcess:
    try:
        result = runner(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise AppFenceError("APP_RUNTIME_INSPECTION_UNAVAILABLE") from exc
    if result.returncode != 0:
        raise AppFenceError("APP_RUNTIME_INSPECTION_UNAVAILABLE")
    return result


def _system_snapshot(*, runner: Callable = subprocess.run) -> tuple[str, str, str, tuple[str, ...]]:
    service = runner(
        ["systemctl", "is-active", "pm2-ubuntu.service"],
        capture_output=True,
        text=True,
        check=False,
    )
    if service.returncode not in (0, 3, 4):
        raise AppFenceError("LEGACY_APP_SERVICE_STATE_UNAVAILABLE")
    state = service.stdout.strip() or "unknown"
    pm2 = runner(
        [
            "runuser", "-u", "ubuntu", "--", "/bin/bash", "-c",
            "if ! command -v pm2 >/dev/null 2>&1; then echo '[]'; else pm2 jlist; fi",
        ],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "HOME": "/home/ubuntu"},
    )
    if pm2.returncode != 0:
        raise AppFenceError("LEGACY_APP_PROCESS_STATE_UNAVAILABLE")
    listeners = _run(["ss", "-lntH", "sport = :3000"], runner=runner).stdout
    active_services = _run(
        ["systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "--no-pager"],
        runner=runner,
    ).stdout
    containers = _run(["docker", "ps", "-q"], runner=runner).stdout
    timers = _run(
        ["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"], runner=runner
    ).stdout
    crons = []
    for user in ("root", "ubuntu"):
        result = runner(["crontab", "-l", "-u", user], capture_output=True, text=True, check=False)
        if result.returncode not in (0, 1):
            raise AppFenceError("APP_BACKGROUND_JOB_INVENTORY_UNAVAILABLE")
        crons.extend(result.stdout.splitlines())
    for directory in (
        Path("/etc/cron.d"), Path("/etc/cron.hourly"), Path("/etc/cron.daily"),
        Path("/etc/cron.weekly"), Path("/etc/cron.monthly"),
    ):
        try:
            entries = list(directory.iterdir()) if directory.is_dir() else []
        except OSError as exc:
            raise AppFenceError("APP_BACKGROUND_JOB_INVENTORY_UNAVAILABLE") from exc
        for entry in entries:
            if entry.name == ".placeholder":
                continue
            if entry.is_symlink() or not entry.is_file() or entry.name not in SAFE_CRON_JOBS:
                raise AppFenceError("UNAPPROVED_APP_SYSTEM_CRON_JOB_PRESENT")
    spool = Path("/var/spool/cron/crontabs")
    try:
        spool_entries = list(spool.iterdir()) if spool.is_dir() else []
    except OSError as exc:
        raise AppFenceError("APP_BACKGROUND_JOB_INVENTORY_UNAVAILABLE") from exc
    if spool_entries:
        raise AppFenceError("UNAPPROVED_APP_CRON_JOB_PRESENT")
    return state, pm2.stdout, listeners, timers, active_services, containers, tuple(crons)


def inspect_app_host(
    *,
    kind: str,
    cutover_id: str,
    isolated_private_ip: str,
    root: Path = CUTOVER_ROOT,
    runner: Callable = subprocess.run,
    owner_uid: int = 0,
) -> dict:
    if kind not in APP_CONTRACT:
        raise AppFenceError("APP_KIND_INVALID")
    container_name = APP_CONTRACT[kind][0]
    normalized = str(uuid.UUID(cutover_id))
    directory = root / normalized
    current_env_path = Path(
        "/etc/hospital-dr/hospital-dr-web.env" if kind == "web"
        else "/etc/hospital-dr/hospital-dr-emr.env"
    )
    current = _run(
        ["docker", "inspect", "--format", "{{.Id}}|{{.State.Running}}|{{index .Config.Labels \"hospital-dr.db-cutover-id\"}}|{{.HostConfig.RestartPolicy.Name}}", container_name],
        runner=runner,
    ).stdout.strip()
    metadata = json.loads(_read_private_regular(directory / "container.json", owner_uid=owner_uid))
    rollback_name = str(metadata.get("rollback_container", ""))
    rollback = _run(
        ["docker", "inspect", "--format", "{{.Id}}|{{.State.Running}}", rollback_name],
        runner=runner,
    ).stdout.strip()
    state, pm2_rows, listeners, timers, active_services, containers, crons = _system_snapshot(runner=runner)
    fence_state = "inactive"
    fence_probe = ""
    if current.split("|")[3:4] == ["no"]:
        fence_state = _run(
            ["systemctl", "is-active", "hospital-dr-dump-readonly-fence.service"], runner=runner
        ).stdout.strip()
        fence_probe = _run(
            ["/usr/local/sbin/hospital-dr-dump-external-fence", "verify"], runner=runner
        ).stdout.strip()
    result = validate_app_fence(
        kind=kind,
        cutover_id=cutover_id,
        isolated_private_ip=isolated_private_ip,
        root=root,
        current_env_path=current_env_path,
        owner_uid=owner_uid,
        current_container=current,
        rollback_container=rollback,
        pm2_service_state=state,
        pm2_processes_text=pm2_rows,
        listener_output=listeners,
        timers_text=timers,
        active_services_text=active_services,
        running_containers_text=containers,
        cron_entries=crons,
        fence_service_state=fence_state,
        fence_probe_output=fence_probe,
    )
    return result


def validate_active_readonly_app(
    *,
    kind: str,
    cutover_id: str,
    isolated_private_ip: str,
    db_server_uuid: str,
    root: Path = CUTOVER_ROOT,
    current_env_path: Path | None = None,
    owner_uid: int = 0,
    snapshot_text: str | None = None,
    current_env_text: str | None = None,
    container_metadata_text: str | None = None,
    active_container_text: str = "",
    listener_output: str = "",
    current_container_text: str = "",
    rollback_container: str = "",
    pm2_service_state: str = "inactive",
    pm2_processes_text: str = "[]",
    active_services_text: str = "",
    timers_text: str = "",
    cron_entries: tuple[str, ...] = (),
    fence_service_state: str = "active",
    fence_probe_output: str = "DUMP_READONLY_EXTERNAL_FENCE=PASS ports=80,443 interface=non-loopback",
    expected_fence_probe: str = "DUMP_READONLY_EXTERNAL_FENCE=PASS ports=80,443 interface=non-loopback",
) -> dict:
    """Validate an app running only behind the persistent external traffic fence."""
    if kind not in APP_CONTRACT:
        raise AppFenceError("APP_KIND_INVALID")
    normalized = str(uuid.UUID(cutover_id))
    if normalized != cutover_id.lower():
        raise AppFenceError("CUTOVER_ID_INVALID")
    container_name, expected_host, source_ip = APP_CONTRACT[kind]
    directory = root / normalized
    if snapshot_text is None:
        snapshot_text = _read_private_regular(directory / "app.env.before", owner_uid=owner_uid)
    if container_metadata_text is None:
        container_metadata_text = _read_private_regular(directory / "container.json", owner_uid=owner_uid)
    if current_env_text is None:
        if current_env_path is None:
            raise AppFenceError("APP_DB_CONFIG_UNAVAILABLE")
        current_env_text = _read_private_regular(current_env_path, owner_uid=owner_uid)
    try:
        metadata = json.loads(container_metadata_text)
        container = current_container_text.split("|", 5)
        rollback = rollback_container.split("|")
        pm2_rows = json.loads(pm2_processes_text)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AppFenceError("APP_RUNTIME_STATE_INVALID") from exc
    before = _parse_env(snapshot_text, ("DB_HOST", "DB_PORT", "DB_NAME"))
    current = _parse_env(current_env_text, ("DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME"))
    expected_rollback = f"{container_name}-dbcutover-{normalized.replace('-', '')}"
    expected_expiry_timer = f"hospital-dr-dump-expire-{normalized.replace('-', '')}.timer"
    if (
        not isinstance(metadata, dict)
        or metadata.get("container") != container_name
        or metadata.get("rollback_container") != expected_rollback
        or metadata.get("was_running") is not True
        or not HEX64.fullmatch(str(metadata.get("container_id", "")))
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(metadata.get("image_id", "")))
        or before != {"DB_HOST": "IP_REDACTED", "DB_PORT": "3306", "DB_NAME": "hospital_db"}
        or current["DB_HOST"] != isolated_private_ip
        or current["DB_PORT"] != "3307"
        or current["DB_USER"] != "hospital_dr_service"
        or current["DB_NAME"] != "hospital_db"
    ):
        raise AppFenceError("APP_CUTOVER_RECEIPT_MISMATCH")
    if (
        len(container) != 6
        or not HEX64.fullmatch(container[0])
        or container[1] != "true"
        or container[2] != normalized
        or container[3] != "no"
        or container[4] != "healthy"
        or container[0] == metadata["container_id"]
    ):
        raise AppFenceError("APP_CONTAINER_ACTIVE_STATE_INVALID")
    try:
        bindings = json.loads(container[5])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AppFenceError("APP_CONTAINER_PORT_BINDING_INVALID") from exc
    expected_bindings = {"3000/tcp": [{"HostIp": "IP_REDACTED", "HostPort": "3000"}]}
    if bindings != expected_bindings or active_container_text.splitlines() != [container_name]:
        raise AppFenceError("APP_CONTAINER_EXTERNALLY_PUBLISHED")
    if len(rollback) != 2 or rollback != [metadata["container_id"], "false"]:
        raise AppFenceError("APP_ROLLBACK_CONTAINER_NOT_PRESERVED")
    if fence_service_state != "active" or fence_probe_output.strip() != expected_fence_probe:
        raise AppFenceError("EXTERNAL_TRAFFIC_FENCE_NOT_ACTIVE")
    if pm2_service_state not in {"inactive", "failed", "unknown", "not-found"}:
        raise AppFenceError("LEGACY_APP_SERVICE_ACTIVE")
    if not isinstance(pm2_rows, list) or any(
        row.get("name") in {"hospital-web", "hospital-emr"}
        and row.get("pm2_env", {}).get("status") == "online"
        for row in pm2_rows if isinstance(row, dict)
    ):
        raise AppFenceError("LEGACY_APP_PROCESS_ACTIVE")
    if not _loopback_listener_only(listener_output):
        raise AppFenceError("APP_LOOPBACK_LISTENER_CONTRACT_INVALID")
    for line in active_services_text.splitlines():
        unit = line.split()[0].lower() if line.split() else ""
        if unit == "hospital-dr-dump-readonly-fence.service" or unit.startswith("hospital-dr-dump-service-fence@"):
            continue
        if any(token in unit for token in ("hospital", "emr", "pm2", "docker-compose", "app-start")):
            raise AppFenceError("UNAPPROVED_APP_SERVICE_ACTIVE")
    for line in timers_text.splitlines():
        fields = line.split()
        if not fields:
            continue
        timer = next((field for field in reversed(fields) if field.endswith(".timer")), "")
        if timer not in SAFE_TIMERS and timer != expected_expiry_timer:
            raise AppFenceError("UNAPPROVED_APP_SYSTEMD_TIMER_PRESENT")
    if any(line.strip() and not line.lstrip().startswith("#") for line in cron_entries):
        raise AppFenceError("UNAPPROVED_APP_CRON_JOB_PRESENT")
    return {
        "host": expected_host,
        "source_ip": source_ip,
        "cutover_id": normalized,
        "db_host": isolated_private_ip,
        "db_port": 3307,
        "db_server_uuid": db_server_uuid,
        "health_endpoint": "/__hospital_dr/health",
        "external_fence": True,
        "container_running": True,
        "restart_policy": "no",
        "select_only_probe": True,
        "status": "PASS",
        "application_health_checked": False,
    }


def _loopback_listener_only(output: str) -> bool:
    lines = [line.split() for line in output.splitlines() if line.strip()]
    if not lines:
        return False
    for fields in lines:
        # ss -lntH: State Recv-Q Send-Q Local Address:Port Peer Address:Port
        if len(fields) < 5 or fields[0] != "LISTEN":
            return False
        local = fields[3]
        if local not in {"IP_REDACTED:3000", "[::1]:3000"}:
            return False
    return True


def inspect_active_readonly_app_host(
    *,
    kind: str,
    cutover_id: str,
    isolated_private_ip: str,
    db_server_uuid: str,
    runner: Callable = subprocess.run,
    owner_uid: int = 0,
) -> dict:
    if kind not in APP_CONTRACT:
        raise AppFenceError("APP_KIND_INVALID")
    container_name = APP_CONTRACT[kind][0]
    normalized = str(uuid.UUID(cutover_id))
    current_env_path = Path(
        "/etc/hospital-dr/hospital-dr-web.env" if kind == "web"
        else "/etc/hospital-dr/hospital-dr-emr.env"
    )
    current = _run(
        [
            "docker", "inspect", "--format",
            "{{.Id}}|{{.State.Running}}|{{index .Config.Labels \"hospital-dr.db-cutover-id\"}}|{{.HostConfig.RestartPolicy.Name}}|{{.State.Health.Status}}|{{json .HostConfig.PortBindings}}",
            container_name,
        ],
        runner=runner,
    ).stdout.strip()
    metadata_text = _read_private_regular(
        CUTOVER_ROOT / normalized / "container.json", owner_uid=owner_uid
    )
    metadata = json.loads(metadata_text)
    rollback_name = str(metadata.get("rollback_container", ""))
    rollback = _run(
        ["docker", "inspect", "--format", "{{.Id}}|{{.State.Running}}", rollback_name],
        runner=runner,
    ).stdout.strip()
    active_names = _run(
        ["docker", "ps", "--format", "{{.Names}}"], runner=runner
    ).stdout
    state, pm2_rows, listeners, timers, active_services, _containers, crons = _system_snapshot(runner=runner)
    fence_state = _run(
        ["systemctl", "is-active", "hospital-dr-dump-readonly-fence.service"], runner=runner
    ).stdout.strip()
    fence_probe = _run(
        ["/usr/local/sbin/hospital-dr-dump-external-fence", "verify"], runner=runner
    ).stdout.strip()
    return validate_active_readonly_app(
        kind=kind,
        cutover_id=cutover_id,
        isolated_private_ip=isolated_private_ip,
        db_server_uuid=db_server_uuid,
        current_env_path=current_env_path,
        owner_uid=owner_uid,
        active_container_text=active_names,
        listener_output=listeners,
        current_container_text=current,
        rollback_container=rollback,
        pm2_service_state=state,
        pm2_processes_text=pm2_rows,
        active_services_text=active_services,
        timers_text=timers,
        cron_entries=crons,
        fence_service_state=fence_state,
        fence_probe_output=fence_probe,
    )


def inspect_service_open_app_host(
    *, kind: str, cutover_id: str, isolated_private_ip: str,
    cloudflare_ipv4_cidrs: tuple[str, ...], network_mode: str,
    expect_stopped: bool = False,
    root: Path = CUTOVER_ROOT,
    runner: Callable = subprocess.run, owner_uid: int = 0,
) -> dict:
    """Validate a live app behind the exact prepared or durable Dump fence."""
    if kind not in APP_CONTRACT or network_mode not in {"prepared", "service", "strict"}:
        raise AppFenceError("APP_KIND_INVALID")
    normalized = str(uuid.UUID(cutover_id))
    if normalized != cutover_id.lower():
        raise AppFenceError("CUTOVER_ID_INVALID")
    container_name = APP_CONTRACT[kind][0]
    current = _run(
        [
            "docker", "inspect", "--format",
            "{{.Id}}|{{.State.Running}}|{{index .Config.Labels \"hospital-dr.db-cutover-id\"}}|{{.HostConfig.RestartPolicy.Name}}|{{.State.Health.Status}}|{{json .HostConfig.PortBindings}}",
            container_name,
        ],
        runner=runner,
    ).stdout.strip()
    metadata = json.loads(_read_private_regular(root / normalized / "container.json", owner_uid=owner_uid))
    rollback_name = str(metadata.get("rollback_container", ""))
    rollback = _run(
        ["docker", "inspect", "--format", "{{.Id}}|{{.State.Running}}", rollback_name], runner=runner
    ).stdout.strip()
    active_names = _run(["docker", "ps", "--format", "{{.Names}}"], runner=runner).stdout
    state, pm2_rows, listeners, timers, active_services, _containers, crons = _system_snapshot(runner=runner)
    unit = (
        "hospital-dr-dump-readonly-fence.service" if network_mode in {"prepared", "strict"}
        else f"hospital-dr-dump-service-fence@{normalized.replace('-', '')}-{kind}.service"
    )
    fence_state = _run(["systemctl", "is-active", unit], runner=runner).stdout.strip()
    if network_mode == "strict":
        fence_probe = _run(["/usr/local/sbin/hospital-dr-dump-external-fence", "verify"], runner=runner).stdout.strip()
        expected_marker = "DUMP_READONLY_EXTERNAL_FENCE=PASS ports=80,443 interface=non-loopback"
        service_instance = f"hospital-dr-dump-service-fence@{normalized.replace('-', '')}-{kind}.service"
        service_state = runner(["systemctl", "is-active", service_instance], capture_output=True, text=True, check=False)
        service_enabled = runner(["systemctl", "show", "--property=UnitFileState", "--value", service_instance], capture_output=True, text=True, check=False)
        auth_path = Path(f"/var/lib/hospital-dr-dump-service-fence/{normalized.replace('-', '')}-{kind}.json")
        auth_exists = auth_path.exists() or auth_path.is_symlink()
        if service_state.returncode == 0 and service_state.stdout.strip() == "active":
            raise AppFenceError("SERVICE_FENCE_UNIT_STILL_ACTIVE")
        if service_enabled.returncode != 0 or service_enabled.stdout.strip() == "enabled" or auth_exists:
            raise AppFenceError("SERVICE_FENCE_BOOT_AUTHORIZATION_REMAINS")
    else:
        command = [
            "/usr/local/sbin/hospital-dr-dump-external-fence",
            "verify-service" if network_mode == "service" else "verify-prepared",
            "--role", kind, "--cutover-id", normalized,
        ] + [f"--cloudflare-ipv4-cidr={cidr}" for cidr in cloudflare_ipv4_cidrs]
        fence_probe = _run(command, runner=runner).stdout.strip()
        expected_marker = (
            f"DUMP_SERVICE_FENCE=PASS role={kind} cutover_id={normalized}"
            if network_mode == "service"
            else f"DUMP_PUBLIC_READINESS_FENCE=PASS role={kind} cutover_id={normalized}"
        )
    if expect_stopped:
        _validate_service_open_stopped_app(
            kind=kind, cutover_id=normalized, isolated_private_ip=isolated_private_ip,
            root=root, current_container=current,
            active_container_text=active_names, rollback_container=rollback,
            listener_output=listeners, fence_service_state=fence_state,
            fence_probe_output=fence_probe, expected_fence_probe=expected_marker,
            pm2_service_state=state, pm2_processes_text=pm2_rows,
            active_services_text=active_services, timers_text=timers,
            cron_entries=crons, owner_uid=owner_uid,
        )
        return {
            "host": "dr-web" if kind == "web" else "dr-doc",
            "cutover_id": normalized,
            "stopped": True,
            "external_fence": True,
            "status": "PASS",
        }
    result = validate_active_readonly_app(
        kind=kind, cutover_id=normalized, isolated_private_ip=isolated_private_ip,
        db_server_uuid="",
        current_env_path=Path(
            "/etc/hospital-dr/hospital-dr-web.env" if kind == "web"
            else "/etc/hospital-dr/hospital-dr-emr.env"
        ),
        owner_uid=owner_uid, active_container_text=active_names,
        listener_output=listeners, current_container_text=current,
        rollback_container=rollback, pm2_service_state=state,
        pm2_processes_text=pm2_rows, active_services_text=active_services,
        timers_text=timers, cron_entries=crons, fence_service_state=fence_state,
        fence_probe_output=fence_probe, expected_fence_probe=expected_marker,
    )
    result.update(select_only_probe=False, database_identity_probe_required=True)
    return result


def _validate_service_open_stopped_app(
    *, kind: str, cutover_id: str, isolated_private_ip: str,
    root: Path, current_container: str,
    active_container_text: str, rollback_container: str, listener_output: str,
    fence_service_state: str, fence_probe_output: str,
    expected_fence_probe: str, pm2_service_state: str,
    pm2_processes_text: str, active_services_text: str,
    timers_text: str, cron_entries: tuple[str, ...], owner_uid: int,
) -> None:
    """Require the exact cutover app to be stopped behind its owned fence."""
    container, _host, _source = APP_CONTRACT[kind]
    fields = current_container.split("|", 5)
    rollback = rollback_container.split("|")
    normalized = str(uuid.UUID(cutover_id))
    expected_rollback = f"{container}-dbcutover-{normalized.replace('-', '')}"
    metadata_text = _read_private_regular(root / normalized / "container.json", owner_uid=owner_uid)
    current_env_path = Path(
        "/etc/hospital-dr/hospital-dr-web.env" if kind == "web"
        else "/etc/hospital-dr/hospital-dr-emr.env"
    )
    snapshot_text = _read_private_regular(root / normalized / "app.env.before", owner_uid=owner_uid)
    current_env_text = _read_private_regular(current_env_path, owner_uid=owner_uid)
    try:
        metadata = json.loads(metadata_text)
        bindings = json.loads(fields[5]) if len(fields) == 6 else None
        pm2_rows = json.loads(pm2_processes_text)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AppFenceError("APP_RUNTIME_STATE_INVALID") from exc
    before = _parse_env(snapshot_text, ("DB_HOST", "DB_PORT", "DB_NAME"))
    current = _parse_env(current_env_text, ("DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME"))
    if (
        not isinstance(metadata, dict)
        or metadata.get("container") != container
        or metadata.get("rollback_container") != expected_rollback
        or metadata.get("was_running") is not True
        or not HEX64.fullmatch(str(metadata.get("container_id", "")))
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(metadata.get("image_id", "")))
        or len(fields) != 6 or not HEX64.fullmatch(fields[0])
        or fields[1] != "false" or fields[2] != normalized
        or fields[3] != "no" or fields[4] not in {"healthy", "none"}
        or fields[0] == metadata["container_id"]
        or bindings != {"3000/tcp": [{"HostIp": "IP_REDACTED", "HostPort": "3000"}]}
        or active_container_text.splitlines()
        or len(rollback) != 2 or rollback != [metadata["container_id"], "false"]
        or before != {"DB_HOST": "IP_REDACTED", "DB_PORT": "3306", "DB_NAME": "hospital_db"}
        or current["DB_HOST"] != isolated_private_ip or current["DB_PORT"] != "3307"
        or current["DB_USER"] != "hospital_dr_service" or current["DB_NAME"] != "hospital_db"
    ):
        raise AppFenceError("APP_CONTAINER_NOT_SAFELY_STOPPED")
    if fence_service_state != "active" or fence_probe_output.strip() != expected_fence_probe:
        raise AppFenceError("EXTERNAL_TRAFFIC_FENCE_NOT_ACTIVE")
    if listener_output.strip():
        raise AppFenceError("HOST_APP_PORT_STILL_LISTENING")
    if pm2_service_state not in {"inactive", "failed", "unknown", "not-found"}:
        raise AppFenceError("LEGACY_APP_SERVICE_ACTIVE")
    if not isinstance(pm2_rows, list) or any(
        row.get("name") in {"hospital-web", "hospital-emr"}
        and row.get("pm2_env", {}).get("status") == "online"
        for row in pm2_rows if isinstance(row, dict)
    ):
        raise AppFenceError("LEGACY_APP_PROCESS_ACTIVE")
    for line in active_services_text.splitlines():
        unit = line.split()[0].lower() if line.split() else ""
        if unit in {"hospital-dr-dump-readonly-fence.service"} or unit.startswith("hospital-dr-dump-service-fence@"):
            continue
        if any(token in unit for token in ("hospital", "emr", "pm2", "docker-compose", "app-start")):
            raise AppFenceError("UNAPPROVED_APP_SERVICE_ACTIVE")
    expected_expiry = f"hospital-dr-dump-expire-{normalized.replace('-', '')}.timer"
    for line in timers_text.splitlines():
        fields = line.split()
        timer = next((field for field in reversed(fields) if field.endswith(".timer")), "")
        if timer and timer not in SAFE_TIMERS and timer != expected_expiry:
            raise AppFenceError("UNAPPROVED_APP_SYSTEMD_TIMER_PRESENT")
    if any(line.strip() and not line.lstrip().startswith("#") for line in cron_entries):
        raise AppFenceError("UNAPPROVED_APP_CRON_JOB_PRESENT")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=tuple(APP_CONTRACT), required=True)
    parser.add_argument("--cutover-id", required=True)
    parser.add_argument("--isolated-private-ip", required=True)
    parser.add_argument("--mode", choices=("stopped", "readonly-active", "service-open"), default="stopped")
    parser.add_argument("--db-server-uuid", default="")
    parser.add_argument("--network-mode", choices=("prepared", "service"), default="prepared")
    parser.add_argument("--expect-stopped", action="store_true")
    parser.add_argument("--cloudflare-ipv4-cidr", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.mode == "readonly-active":
            result = inspect_active_readonly_app_host(
                kind=args.kind,
                cutover_id=args.cutover_id,
                isolated_private_ip=args.isolated_private_ip,
                db_server_uuid=args.db_server_uuid,
            )
        elif args.mode == "service-open":
            result = inspect_service_open_app_host(
                kind=args.kind, cutover_id=args.cutover_id,
                isolated_private_ip=args.isolated_private_ip,
                cloudflare_ipv4_cidrs=tuple(args.cloudflare_ipv4_cidr),
                network_mode=args.network_mode,
                expect_stopped=args.expect_stopped,
            )
        else:
            result = inspect_app_host(
                kind=args.kind,
                cutover_id=args.cutover_id,
                isolated_private_ip=args.isolated_private_ip,
            )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    except AppFenceError as exc:
        print(f"DUMP_APP_FENCE=BLOCKED reason={exc}", file=sys.stderr, flush=True)
        return 1
    except (OSError, ValueError, TypeError):
        print("DUMP_APP_FENCE=BLOCKED reason=APP_RUNTIME_STATE_INVALID", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
