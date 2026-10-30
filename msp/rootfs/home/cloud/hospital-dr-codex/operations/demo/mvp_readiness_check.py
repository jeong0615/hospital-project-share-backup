#!/usr/bin/env python3
"""Read-only, fail-closed readiness summary for the Hospital DR MVP.

The default mode reads local configuration/evidence only.  Optional live
queries are explicitly enabled with ``--live-chatops``, ``--live-zabbix`` or
``--live-wazuh``; those paths perform status/GET/JSON-RPC reads only.  This
command never starts or stops services, changes Zabbix, invokes a DR workflow,
connects to a database, changes DNS, or writes an evidence file.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
for _relative in ("operations/preflight", "operations/chatops", "operations/zabbix"):
    sys.path.insert(0, str(ROOT / _relative))

from final_live_e2e_preflight import parse_env_file  # noqa: E402
from production_dr_policy import (  # noqa: E402
    DB_HEALTH_ITEM_KEY,
    DOC_FAIL_ITEM_KEY,
    FAILOVER_STABILITY_SECONDS,
    HEALTH_SAMPLE_FRESHNESS_SECONDS,
    HEALTH_SAMPLE_INTERVAL_SECONDS,
    MAINTENANCE_ITEM_KEY,
    MONITORING_MAINTENANCE_HOSTS,
    WEB_FAIL_ITEM_KEY,
)
from rpo_evidence import collect as collect_rpo_evidence  # noqa: E402
from rto_timeline import calculate_run  # noqa: E402


STATUSES = {"PASS", "BLOCKED", "DISABLED", "UNVERIFIED"}
DEFAULT_ENV_FILE = Path("/home/cloud/hospital-dr-secrets/dr.env")
DEFAULT_CHATOPS_UNIT = Path("/etc/systemd/system/hospital-dr-chatops.service")
DEFAULT_STATE_DIR = Path("/var/lib/hospital-dr")
WAZUH_REQUIRED = (
    "WAZUH_API_URL",
    "WAZUH_API_USER",
    "WAZUH_API_PASSWORD",
    "WAZUH_INDEXER_URL",
    "WAZUH_INDEXER_USER",
    "WAZUH_INDEXER_PASSWORD",
    "WAZUH_FAILBACK_REQUIRED_AGENTS",
)


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    reason: str

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unsupported readiness status: {self.status}")


def _truth(value: str | None) -> bool | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    return None


def _load_values(env_file: Path, environ: dict[str, str] | None = None) -> dict[str, str]:
    """Reuse the existing non-evaluating dotenv parser; never expose values."""

    values = parse_env_file(env_file)
    values.update(os.environ if environ is None else environ)
    return values


def _read_only_chatops_live(
    unit_path: Path,
    *,
    runner: Callable[..., Any] = subprocess.run,
    timeout: float = 3.0,
) -> Check:
    """Check systemd and GET the existing loopback-only informational page."""

    try:
        unit = unit_path.read_text(encoding="utf-8")
    except OSError:
        return Check("chatops_service_http", "UNVERIFIED", "systemd unit is not readable")
    match = re.search(r"--bind\s+([^\s]+)", unit)
    if not match:
        return Check("chatops_service_http", "UNVERIFIED", "service bind address is not declared")
    bind = match.group(1)
    try:
        host_port = bind.rsplit(":", 1)
        host, port = host_port[0].strip("[]"), int(host_port[1])
        if not ipaddress.ip_address(host).is_loopback:
            return Check("chatops_service_http", "BLOCKED", "ChatOps bind is not loopback-only")
    except (ValueError, IndexError):
        return Check("chatops_service_http", "UNVERIFIED", "service bind address could not be validated")

    try:
        active = runner(
            ["systemctl", "is-active", "--quiet", "hospital-dr-chatops.service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return Check("chatops_service_http", "UNVERIFIED", "systemd status could not be queried")
    if getattr(active, "returncode", 1) != 0:
        return Check("chatops_service_http", "BLOCKED", "hospital-dr-chatops.service is not active")

    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        if response.status == 200:
            return Check("chatops_service_http", "PASS", "service active; loopback GET / returned HTTP 200")
        return Check("chatops_service_http", "BLOCKED", f"loopback GET / returned HTTP {response.status}")
    except (OSError, http.client.HTTPException, TimeoutError):
        return Check("chatops_service_http", "BLOCKED", "active service did not answer loopback GET /")
    finally:
        connection.close()


def _zabbix_snapshot_check(state: dict[str, Any], actions: list[dict[str, Any]]) -> Check:
    """Evaluate an existing read-only Zabbix snapshot using its policy helper."""

    from configure_production_dr_triggers import _aggregate_conditions_match_policy
    from production_dr_policy import maintenance_state_observation, monitoring_path_observation

    trigger = state.get("aggregate")
    if not isinstance(trigger, dict):
        return Check("zabbix_production_trigger", "BLOCKED", "Production aggregate trigger is missing or ambiguous")

    path_item = state.get("monitoring_path_item")
    path_key = str((path_item or {}).get("key_") or "")
    zabbix_host = (state.get("hosts") or {}).get("Zabbix server") or {}
    zabbix_hostid = str(zabbix_host.get("hostid") or "")
    # Check expression policy separately from the live enabled/disabled bit.
    policy_matches = bool(
        path_key
        and _aggregate_conditions_match_policy(
            trigger,
            state.get("items") or [],
            path_key,
            maintenance_host_ids={
                name: str((state.get("hosts") or {}).get(name, {}).get("hostid") or "")
                for name in MONITORING_MAINTENANCE_HOSTS
            },
            expected_status=None,
        )
    )
    enabled = str(trigger.get("status", "")) == "0"
    expected_delays = {
        WEB_FAIL_ITEM_KEY: "1m",
        DOC_FAIL_ITEM_KEY: "1m",
        DB_HEALTH_ITEM_KEY: f"{HEALTH_SAMPLE_INTERVAL_SECONDS}s",
    }
    items = {str(item.get("key_", "")): item for item in state.get("items") or []}
    item_state_issue = ""
    now = time.time()
    for key, delay in expected_delays.items():
        item = items.get(key)
        if item is None:
            item_state_issue = "required Web/EMR/DB health item is missing"
            break
        if str(item.get("status", "")) != "0" or str(item.get("state", "")) != "0":
            item_state_issue = "required health item is disabled or unsupported"
            break
        if str(item.get("delay", "")) != delay:
            item_state_issue = "health item sampling interval differs from policy"
            break
        try:
            age = now - int(item.get("lastclock"))
        except (TypeError, ValueError):
            item_state_issue = "health item sample time is unavailable"
            break
        if age < 0 or age > HEALTH_SAMPLE_FRESHNESS_SECONDS:
            item_state_issue = "health item sample is stale or has an invalid clock"
            break
    action_rows = [item for item in actions if item.get("name") == "Cloud_Slack_DR_Trigger"]
    action_enabled = (
        len(action_rows) == 1
        and str(action_rows[0].get("status", "")) == "0"
        and str(action_rows[0].get("eventsource", "")) == "0"
    )
    trigger_value = str(trigger.get("value", "?"))
    value_text = {"0": "OK", "1": "PROBLEM"}.get(trigger_value, "UNKNOWN")
    if not enabled:
        path_note = "Monitoring Path=UNVERIFIED" if path_item is None else "Monitoring Path sample is not evaluated while trigger is disabled"
        return Check(
            "zabbix_production_trigger",
            "DISABLED",
            f"trigger disabled; live value={value_text}; policy={'AND/300s' if policy_matches else 'MISMATCH'}; {path_note}",
        )
    if path_item is None or not path_key or not zabbix_hostid:
        return Check("zabbix_production_trigger", "BLOCKED", "enabled trigger has no independently configured Monitoring Path witness")
    path_healthy, path_reason = monitoring_path_observation(
        path_item,
        expected_key=path_key,
        expected_hostid=zabbix_hostid,
        now_epoch=now,
    )
    if not path_healthy:
        return Check("zabbix_production_trigger", "BLOCKED", f"Monitoring Path witness is not healthy: {path_reason}")
    for host_name in MONITORING_MAINTENANCE_HOSTS:
        host = (state.get("hosts") or {}).get(host_name) or {}
        clear, reason = maintenance_state_observation(
            (state.get("maintenance_items") or {}).get(host_name),
            expected_hostid=str(host.get("hostid") or ""),
            now_epoch=now,
        )
        if not clear:
            status = "BLOCKED" if reason == "host_in_maintenance_or_state_unknown" else "UNVERIFIED"
            return Check(
                "zabbix_production_trigger",
                status,
                f"Maintenance state is not verified for {host_name}: {reason}",
            )
    if not policy_matches:
        return Check("zabbix_production_trigger", "BLOCKED", f"enabled trigger violates the Web AND EMR AND DB 300s contract; value={value_text}")
    if item_state_issue:
        status = "UNVERIFIED" if "unavailable" in item_state_issue else "BLOCKED"
        return Check("zabbix_production_trigger", status, item_state_issue)
    if not action_enabled:
        return Check("zabbix_production_trigger", "BLOCKED", "Production Action is missing, ambiguous or disabled")
    return Check("zabbix_production_trigger", "PASS", f"AND/300s policy and enabled trigger-event Action 3 verified; live value={value_text}")


def _live_zabbix_check(env_file: Path) -> Check:
    """Use existing Zabbix client/configurator read methods only."""

    try:
        from configure_chatops import ZabbixClient, load_settings
        from configure_production_dr_triggers import ProductionTriggerConfigurator

        settings = load_settings(str(env_file) if env_file.is_file() else None)
        client = ZabbixClient(settings)
        client.authenticate()
        state = ProductionTriggerConfigurator(client).inspect()
        zabbix_host = (state.get("hosts") or {}).get("Zabbix server") or {}
        path_key = str(state.get("monitoring_path_key") or "")
        if not path_key and isinstance(state.get("monitoring_path_item"), dict):
            path_key = str(state["monitoring_path_item"].get("key_") or "")
        query_keys = [WEB_FAIL_ITEM_KEY, DOC_FAIL_ITEM_KEY, DB_HEALTH_ITEM_KEY]
        if path_key:
            query_keys.append(path_key)
        fresh_items = client.call(
            "item.get",
            {
                "output": ["itemid", "hostid", "name", "key_", "type", "value_type", "delay", "status", "state", "lastclock", "lastvalue"],
                "hostids": [str(zabbix_host.get("hostid", ""))],
                "filter": {"key_": query_keys},
                "selectTags": "extend",
            },
        ) or []
        host_ids = {
            name: str((state.get("hosts") or {}).get(name, {}).get("hostid") or "")
            for name in MONITORING_MAINTENANCE_HOSTS
        }
        maintenance_rows = client.call(
            "item.get",
            {
                "output": ["itemid", "hostid", "name", "key_", "type", "value_type", "delay", "status", "state", "lastclock", "lastvalue"],
                "hostids": list(host_ids.values()),
                "filter": {"key_": [MAINTENANCE_ITEM_KEY]},
            },
        ) or []
        fresh_items.extend(maintenance_rows)
        state["items"] = fresh_items
        state["maintenance_items"] = {
            name: next(
                (item for item in maintenance_rows if str(item.get("hostid") or "") == host_id),
                None,
            )
            for name, host_id in host_ids.items()
        }
        state["monitoring_path_item"] = next(
            (item for item in fresh_items if str(item.get("key_") or "") == path_key),
            None,
        )
        state["monitoring_path_key"] = path_key or None
        actions = client.call(
            "action.get",
            {
                "output": ["actionid", "name", "status", "eventsource"],
                "filter": {"name": ["Cloud_Slack_DR_Trigger"]},
            },
        ) or []
        return _zabbix_snapshot_check(state, actions)
    except Exception:
        # Do not print API errors, response bodies, or authentication details.
        return Check("zabbix_production_trigger", "UNVERIFIED", "read-only Zabbix API query failed or was not configured")


def _wazuh_live_check(values: dict[str, str]) -> Check:
    try:
        from wazuh_failback_gate import evaluate_failback_security
        from wazuh_live_provider import build_wazuh_provider

        required_agents = tuple(
            value.strip()
            for value in values.get("WAZUH_FAILBACK_REQUIRED_AGENTS", "").split(",")
            if value.strip()
        )
        provider = build_wazuh_provider(values)
        if provider is None or not required_agents:
            return Check("wazuh_failback_security", "BLOCKED", "required Wazuh provider or agent configuration is missing")
        result = evaluate_failback_security(provider.snapshot(), required_agents=required_agents)
        status = str(result.get("status", "UNKNOWN"))
        if status == "READY":
            return Check("wazuh_failback_security", "PASS", "existing failback security gate returned READY")
        if status == "BLOCKED":
            return Check("wazuh_failback_security", "BLOCKED", "existing Wazuh security gate blocks Failback")
        return Check("wazuh_failback_security", "UNVERIFIED", "Wazuh data is unavailable, incomplete or stale")
    except Exception:
        return Check("wazuh_failback_security", "UNVERIFIED", "read-only Wazuh query failed")


def _chatops_state_check(state_db: Path) -> Check:
    """Read approval status counts using SQLite's read-only URI mode."""

    if not state_db.is_file():
        return Check("chatops_active_requests", "UNVERIFIED", "ChatOps state database is unavailable")
    try:
        uri = state_db.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2) as connection:
            tables = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if "approval_requests" not in tables:
                return Check("chatops_active_requests", "UNVERIFIED", "approval_requests table is unavailable")
            rows = connection.execute(
                "SELECT status, COUNT(*) FROM approval_requests GROUP BY status"
            ).fetchall()
        counts = {str(status): int(count) for status, count in rows}
    except (OSError, sqlite3.Error, ValueError):
        return Check("chatops_active_requests", "UNVERIFIED", "ChatOps state database could not be read-only queried")
    active = sum(counts.get(status, 0) for status in ("PENDING", "PARTIALLY_APPROVED", "EXECUTING"))
    if active:
        return Check("chatops_active_requests", "BLOCKED", f"active approval/execution requests={active}")
    return Check("chatops_active_requests", "PASS", "no PENDING, PARTIALLY_APPROVED or EXECUTING requests")


def _chatops_lock_check(lock_path: Path, *, live: bool) -> Check:
    if not live:
        return Check("chatops_execution_lock", "UNVERIFIED", "lock-holder state is not queried in offline mode")
    if not lock_path.exists():
        return Check("chatops_execution_lock", "PASS", "execution lock file is absent")
    try:
        result = subprocess.run(
            ["fuser", str(lock_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return Check("chatops_execution_lock", "UNVERIFIED", "lock holder could not be queried")
    if result.returncode == 0:
        return Check("chatops_execution_lock", "BLOCKED", "execution lock has an active holder")
    if result.returncode == 1:
        return Check("chatops_execution_lock", "PASS", "execution lock has no active holder")
    return Check("chatops_execution_lock", "UNVERIFIED", "lock holder could not be verified")


def _unit_environment_value(unit_path: Path, key: str) -> str:
    try:
        lines = unit_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    prefix = f"Environment={key}="
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):].strip().strip('"')
    return ""


def _runbook_policy_check(root: Path) -> Check:
    path = root / "operations/demo/MVP_RUNBOOK.md"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return Check("mvp_runbook_policy", "UNVERIFIED", "existing MVP Runbook is unavailable")
    canonical_lines = [line for line in lines if "Canonical" in line and "Web" in line]
    canonical_correct = any(
        re.search(r"Web\s+AND\s+(?:EMR(?:/Doc)?|Doc)\s+AND\s+DB", line, re.IGNORECASE)
        and re.search(r"300\s*(?:s|초|seconds)", line, re.IGNORECASE)
        for line in canonical_lines
    )
    canonical_conflict = any(
        re.search(r"Web\s+OR\s+(?:EMR|Doc)\b", line, re.IGNORECASE)
        for line in canonical_lines
    )
    stale_current_or_claim = any(
        re.search(r"(?:current|현재).*aggregate.*Web\s+OR", line, re.IGNORECASE)
        for line in lines
    )
    if canonical_conflict or stale_current_or_claim:
        return Check("mvp_runbook_policy", "BLOCKED", "Runbook attributes an OR aggregate to current Canonical policy")
    if not canonical_correct:
        return Check("mvp_runbook_policy", "UNVERIFIED", "Runbook does not state the Canonical Web AND EMR/Doc AND DB 300s contract")

    trigger_lines = [line for line in lines if "Trigger 24712" in line]
    trigger_disabled_legacy = any(
        ("disabled" in line.lower() or "비활성" in line)
        and "OR" in line
        and ("legacy" in line.lower() or "구형" in line)
        for line in trigger_lines
    )
    monitoring_path_unavailable = any(
        "Monitoring Path" in line
        and any(token in line.lower() for token in ("unavailable", "not configured", "없", "확인 불가"))
        for line in lines
    )
    if not trigger_disabled_legacy or not monitoring_path_unavailable:
        return Check(
            "mvp_runbook_policy",
            "UNVERIFIED",
            "Runbook must separately record the last-reported Trigger 24712 state and missing independent Monitoring Path",
        )
    return Check(
        "mvp_runbook_policy",
        "PASS",
        "Runbook separates Canonical AND/300s policy from the last-reported disabled legacy Trigger and unavailable Monitoring Path",
    )


def _runbook_production_trigger_check(root: Path) -> Check:
    """Report the documented last-known trigger state without claiming a live read."""
    path = root / "operations/demo/MVP_RUNBOOK.md"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return Check("zabbix_production_trigger", "UNVERIFIED", "live trigger/action state not queried; Runbook unavailable")
    for line in lines:
        if "Trigger 24712" in line and ("disabled" in line.lower() or "비활성" in line):
            return Check(
                "zabbix_production_trigger",
                "BLOCKED",
                "last reported Trigger 24712 state is disabled; live Zabbix state was not rechecked by this offline check",
            )
    return Check(
        "zabbix_production_trigger",
        "UNVERIFIED",
        f"live trigger/action state not queried; source contract is AND/{FAILOVER_STABILITY_SECONDS}s",
    )


def _dump_gate_check(values: dict[str, str]) -> Check:
    enabled = _truth(values.get("DUMP_RESTORE_EXEC_ENABLED"))
    if enabled is None:
        return Check("dump_execution_gate", "UNVERIFIED", "DUMP_RESTORE_EXEC_ENABLED was not found in selected local configuration")
    if not enabled:
        return Check("dump_execution_gate", "DISABLED", "Dump execution is explicitly disabled")
    executor = values.get("DUMP_RESTORE_EXECUTOR", "").strip()
    if not executor:
        return Check("dump_execution_gate", "BLOCKED", "Dump gate is enabled but no executor is configured")
    path = Path(executor)
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        return Check("dump_execution_gate", "BLOCKED", "configured Dump executor is not a safe executable file")
    return Check("dump_execution_gate", "PASS", "gate and executable path are configured; run authorization is not tested")


def _wazuh_config_check(values: dict[str, str], *, live: bool) -> Check:
    missing = [name for name in WAZUH_REQUIRED if not values.get(name, "").strip()]
    if missing:
        return Check("wazuh_failback_security", "BLOCKED", "required security configuration missing: " + ",".join(missing))
    if not live:
        return Check("wazuh_failback_security", "UNVERIFIED", "configuration exists; live Wazuh state was not queried")
    return _wazuh_live_check(values)


def _nr_check(values: dict[str, str]) -> Check:
    enabled = _truth(values.get("DB_NR_ENABLED"))
    if enabled is False:
        return Check("nr_replication", "DISABLED", "DB_NR_ENABLED=false; replication is not an active data path")
    if enabled is True:
        return Check("nr_replication", "UNVERIFIED", "NR is configured enabled; live replica status was not queried")
    return Check("nr_replication", "UNVERIFIED", "DB_NR_ENABLED is absent or invalid in selected local configuration")


def _rto_rpo_check(timeline_path: Path, rpo_path: Path | None, nr_enabled: str) -> Check:
    measured_rto = 0
    try:
        if timeline_path.is_file():
            document = json.loads(timeline_path.read_text(encoding="utf-8"))
            runs = document.get("runs") if isinstance(document, dict) else None
            if isinstance(runs, list):
                for run in runs:
                    if not isinstance(run, dict) or run.get("synthetic") is True or run.get("dry_run") is True:
                        continue
                    run_id = str(run.get("run_id", "")).lower()
                    if run_id.startswith(("test-", "synthetic-", "dry-run-")):
                        continue
                    result = calculate_run(run)
                    if result.get("total_rto_seconds") is not None:
                        measured_rto += 1
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return Check("rto_rpo_evidence", "UNVERIFIED", "RTO timeline is missing or invalid")

    measured_rpo = False
    if rpo_path is not None and rpo_path.is_file():
        try:
            rpo = collect_rpo_evidence(rpo_path, nr_enabled=nr_enabled)
            measured_rpo = rpo.get("rpo_status") == "MEASURED" and rpo.get("rpo_value_status") == "MEASURED"
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            measured_rpo = False
    if measured_rto and measured_rpo:
        return Check("rto_rpo_evidence", "PASS", f"existing evidence parser found measured RTO runs={measured_rto} and an RPO record")
    reasons = []
    reasons.append(f"measured RTO runs={measured_rto}")
    reasons.append("RPO measured" if measured_rpo else "RPO NOT_MEASURED/unknown")
    return Check("rto_rpo_evidence", "UNVERIFIED", "; ".join(reasons))


def collect_readiness(
    *,
    root: Path = ROOT,
    values: dict[str, str] | None = None,
    env_file: Path = DEFAULT_ENV_FILE,
    timeline_path: Path | None = None,
    rpo_path: Path | None = None,
    live_chatops: bool = False,
    live_zabbix: bool = False,
    live_wazuh: bool = False,
    zabbix_env_file: Path | None = None,
    chatops_check: Callable[[Path], Check] = _read_only_chatops_live,
    zabbix_check: Callable[[Path], Check] = _live_zabbix_check,
    wazuh_check: Callable[[dict[str, str]], Check] = _wazuh_live_check,
) -> dict[str, Any]:
    """Collect a readiness snapshot; no live call occurs unless opted in."""

    selected = dict(values) if values is not None else _load_values(env_file)
    source_unit_path = root / "operations/chatops/systemd/hospital-dr-chatops.service"
    runtime_unit_path = Path(
        selected.get(
            "CHATOPS_SYSTEMD_UNIT",
            "/etc/systemd/system/hospital-dr-chatops.service" if live_chatops else str(source_unit_path),
        )
    )
    selected_zabbix_env = zabbix_env_file
    if selected_zabbix_env is None:
        configured_zabbix_env = (
            selected.get("ZABBIX_ENV_FILE")
            or selected.get("NETWORK_DR_HEALTH_ZABBIX_ENV_FILE")
            or _unit_environment_value(runtime_unit_path if live_zabbix else source_unit_path, "NETWORK_DR_HEALTH_ZABBIX_ENV_FILE")
        )
        selected_zabbix_env = Path(configured_zabbix_env) if configured_zabbix_env else env_file
    app_path = root / "operations/chatops/app.py"
    core_path = root / "operations/chatops/chatops_core.py"
    try:
        unit_text = source_unit_path.read_text(encoding="utf-8")
        app_text = app_path.read_text(encoding="utf-8")
        core_text = core_path.read_text(encoding="utf-8")
        static_ok = "--bind IP_REDACTED:5000" in unit_text and "@app.get(\"/\")" in core_text and "create_app(" in app_text
    except OSError:
        static_ok = False
    checks = [
        Check(
            "chatops_runtime_contract",
            "PASS" if static_ok else "UNVERIFIED",
            "source unit, loopback bind and informational GET route found" if static_ok else "ChatOps source/runtime contract could not be confirmed",
        ),
        chatops_check(runtime_unit_path) if live_chatops else Check("chatops_service_http", "UNVERIFIED", "live service/HTTP state not queried in offline mode"),
        _chatops_state_check(Path(selected.get("CHATOPS_STATE_DB", str(DEFAULT_STATE_DIR / "chatops_state.sqlite3")))),
        _chatops_lock_check(
            Path(selected.get("CHATOPS_EXECUTION_LOCK_FILE", str(DEFAULT_STATE_DIR / "chatops.pipeline.lock"))),
            live=live_chatops,
        ),
        _dump_gate_check(selected),
        _wazuh_config_check(selected, live=live_wazuh) if not live_wazuh else wazuh_check(selected),
        _nr_check(selected),
    ]

    if live_zabbix:
        checks.append(zabbix_check(selected_zabbix_env))
    else:
        checks.append(_runbook_production_trigger_check(root))
    if not live_zabbix:
        checks.append(
            Check(
                "zabbix_monitoring_path",
                "BLOCKED",
                "no site-verified Monitoring Path endpoint or live fresh probe sample is available",
            )
        )
    checks.append(_runbook_policy_check(root))

    state_dir = Path(selected.get("DR_STATE_DIR", str(DEFAULT_STATE_DIR)))
    timeline = timeline_path or Path(selected.get("DR_RTO_TIMELINE_FILE", str(state_dir / "rto_timeline.json")))
    checks.append(_rto_rpo_check(timeline, rpo_path, selected.get("DB_NR_ENABLED", "false")))

    statuses = {check.status for check in checks}
    if "BLOCKED" in statuses:
        overall = "BLOCKED"
    elif "UNVERIFIED" in statuses:
        overall = "UNVERIFIED"
    elif "DISABLED" in statuses:
        overall = "DISABLED"
    else:
        overall = "PASS"
    return {
        "overall": overall,
        "ready": overall == "PASS",
        "checks": [asdict(check) for check in checks],
    }


def render_text(result: dict[str, Any]) -> str:
    lines = [f"MVP_READINESS={result['overall']}"]
    lines.extend(
        f"{check['status']:<10} {check['name']}: {check['reason']}"
        for check in result["checks"]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--env-file", type=Path, default=Path(os.environ.get("DR_SECRET_FILE", DEFAULT_ENV_FILE)))
    parser.add_argument("--timeline", type=Path)
    parser.add_argument("--rpo-evidence", type=Path)
    parser.add_argument("--zabbix-env-file", type=Path, help="explicit existing Zabbix read-only API environment file")
    parser.add_argument("--live-chatops", action="store_true", help="query systemd and loopback GET /")
    parser.add_argument("--live-zabbix", action="store_true", help="query existing Zabbix API read-only objects")
    parser.add_argument("--live-wazuh", action="store_true", help="query the existing read-only Wazuh provider")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    values = _load_values(args.env_file)
    result = collect_readiness(
        root=args.root,
        values=values,
        env_file=args.env_file,
        timeline_path=args.timeline,
        rpo_path=args.rpo_evidence,
        live_chatops=args.live_chatops,
        live_zabbix=args.live_zabbix,
        live_wazuh=args.live_wazuh,
        zabbix_env_file=args.zabbix_env_file,
    )
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) if args.format == "json" else render_text(result))
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
