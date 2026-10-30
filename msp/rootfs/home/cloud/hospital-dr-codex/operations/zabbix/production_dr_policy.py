"""Pure Production DR policy and Zabbix object contract."""

from __future__ import annotations

import ipaddress
import time
from typing import Any


FAILOVER_STABILITY_SECONDS = 0
FAILOVER_STABILITY_WINDOW = "60s"
HEALTH_SAMPLE_INTERVAL_SECONDS = 60
HEALTH_SAMPLE_FRESHNESS_SECONDS = 90
FAILOVER_REQUIRED_FAILED_SAMPLES = 1
ZABBIX_SERVER_HOST = "Zabbix server"
MONITORING_MAINTENANCE_HOSTS = (
    "web_server",
    "DB_Server",
    "Doc_Server",
    ZABBIX_SERVER_HOST,
)
MAINTENANCE_ITEM_KEY = "zabbix[host,,maintenance]"
MAINTENANCE_ITEM_NAME = "Hospital DR host maintenance state"
ONPREM_WEB_IP = "IP_REDACTED"
ONPREM_DB_IP = "IP_REDACTED"
ONPREM_EMR_IP = "IP_REDACTED"
WEB_SCENARIO_NAME = "Hospital DR Web Core"
DOC_SCENARIO_NAME = "Hospital DR Doc Core"
WEB_FAIL_ITEM_KEY = f"web.test.fail[{WEB_SCENARIO_NAME}]"
DOC_FAIL_ITEM_KEY = f"web.test.fail[{DOC_SCENARIO_NAME}]"
DB_HEALTH_ITEM_KEY = f"net.tcp.service[tcp,{ONPREM_DB_IP},3306]"
SNMP_AVAILABILITY_ITEM_KEY = "zabbix[host,snmp,available]"
ONPREM_SNMP_HOSTS = (
    "Cisco-2800-Series",
    "Catalyst-2950-Series",
    "Catalyst-3560-Series",
    "Catalyst-3550-Series",
)
MONITORING_PATH_ITEM_NAME = "Hospital DR Independent Monitoring Path TCP witness"
MONITORING_PATH_TAG = ("DR_Monitoring_Path", "independent")
PRODUCTION_TRIGGER_DESCRIPTION = "Hospital DR: On-Prem core services sustained failure"
PRODUCTION_TRIGGER_TAGS = (
    ("DR_Escalate", "1"),
    ("DR_Policy", "production"),
    ("DR_Scope", "Hospital-Core"),
    ("DR_Type", "Failover"),
)


def web_scenario_spec(
    name: str,
    step_name: str,
    url: str,
    *,
    status_codes: str = "200",
) -> dict[str, Any]:
    """Return the source-backed HTTP health scenario contract."""

    return {
        "name": name,
        "delay": "1m",
        "steps": [
            {
                "name": step_name,
                "url": url,
                "status_codes": status_codes,
                "no": 1,
                "timeout": "5s",
                "follow_redirects": 1,
            }
        ],
        "tags": [
            {"tag": "DR_Policy", "value": "production"},
            {"tag": "DR_Scope", "value": "Hospital-Core"},
        ],
    }


WEB_SCENARIO = web_scenario_spec(
    WEB_SCENARIO_NAME,
    "Web /health",
    f"http://{ONPREM_WEB_IP}/health",
)
DOC_SCENARIO = web_scenario_spec(
    DOC_SCENARIO_NAME,
    "Doc /__hospital_dr/health",
    f"http://{ONPREM_EMR_IP}/__hospital_dr/health",
    status_codes="204",
)


def monitoring_path_item_key(address: str, port: int | str) -> str:
    """Build a probe key from an explicitly supplied literal IP and TCP port.

    Syntax validation cannot establish that the endpoint is an independently
    managed Monitoring Path witness. That classification requires site review.
    """

    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError as exc:
        raise ValueError("Monitoring Path endpoint must be a literal IP address") from exc
    try:
        tcp_port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("Monitoring Path TCP port must be an integer") from exc
    if isinstance(port, bool) or not 1 <= tcp_port <= 65535:
        raise ValueError("Monitoring Path TCP port must be between 1 and 65535")
    service_addresses = {
        ipaddress.ip_address(ONPREM_WEB_IP),
        ipaddress.ip_address(ONPREM_DB_IP),
        ipaddress.ip_address(ONPREM_EMR_IP),
    }
    if ip in service_addresses:
        raise ValueError("Monitoring Path witness must be distinct from Web, EMR, and DB probes")
    return f"net.tcp.service[tcp,{ip.compressed},{tcp_port}]"


def monitoring_path_observation(
    item: dict[str, Any] | None,
    *,
    expected_key: str,
    expected_hostid: str,
    now_epoch: float | None = None,
) -> tuple[bool, str]:
    """Fail closed unless the configured probe is enabled, supported and fresh."""

    if item is None:
        return False, "monitoring_path_item_missing"
    if not expected_key or not str(expected_hostid).strip():
        return False, "monitoring_path_expected_identity_missing"
    if str(item.get("key_") or "").strip() != expected_key:
        return False, "monitoring_path_target_mismatch"
    if str(item.get("hostid") or "").strip() != str(expected_hostid):
        return False, "monitoring_path_host_mismatch"
    if (
        str(item.get("type") or "").strip() != "3"
        or str(item.get("value_type") or "").strip() != "3"
        or str(item.get("delay") or "").strip() not in {"60s", "1m"}
    ):
        return False, "monitoring_path_item_contract_invalid"
    if str(item.get("status") or "").strip() != "0" or str(item.get("state") or "").strip() != "0":
        return False, "monitoring_path_item_disabled_or_unsupported"
    if not any(
        isinstance(tag, dict)
        and str(tag.get("tag") or "").strip() == MONITORING_PATH_TAG[0]
        and str(tag.get("value") or "").strip() == MONITORING_PATH_TAG[1]
        for tag in item.get("tags") or []
    ):
        return False, "monitoring_path_item_not_owned"
    if str(item.get("lastvalue") or "").strip() != "1":
        return False, "monitoring_path_probe_not_healthy"
    try:
        observed_at = int(item.get("lastclock"))
        current = time.time() if now_epoch is None else float(now_epoch)
    except (TypeError, ValueError, OverflowError):
        return False, "monitoring_path_observation_missing"
    age = current - observed_at
    if age < 0 or age > HEALTH_SAMPLE_FRESHNESS_SECONDS:
        return False, "monitoring_path_observation_stale"
    return True, "healthy"


def maintenance_state_observation(
    item: dict[str, Any] | None,
    *,
    expected_hostid: str,
    now_epoch: float | None = None,
) -> tuple[bool, str]:
    """Require a fresh Zabbix internal check confirming this host is not in maintenance."""

    if item is None:
        return False, "maintenance_state_item_missing"
    if not str(expected_hostid).strip():
        return False, "maintenance_state_expected_host_missing"
    if str(item.get("hostid") or "").strip() != str(expected_hostid):
        return False, "maintenance_state_host_mismatch"
    if str(item.get("key_") or "").strip() != MAINTENANCE_ITEM_KEY:
        return False, "maintenance_state_key_mismatch"
    if str(item.get("name") or "").strip() != MAINTENANCE_ITEM_NAME:
        return False, "maintenance_state_item_not_owned"
    if (
        str(item.get("type") or "").strip() != "5"
        or str(item.get("value_type") or "").strip() != "3"
        or str(item.get("delay") or "").strip() not in {"60s", "1m"}
    ):
        return False, "maintenance_state_item_contract_invalid"
    if str(item.get("status") or "").strip() != "0" or str(item.get("state") or "").strip() != "0":
        return False, "maintenance_state_item_disabled_or_unsupported"
    if str(item.get("lastvalue") or "").strip() != "0":
        return False, "host_in_maintenance_or_state_unknown"
    try:
        observed_at = int(item.get("lastclock"))
        current = time.time() if now_epoch is None else float(now_epoch)
    except (TypeError, ValueError, OverflowError):
        return False, "maintenance_state_observation_missing"
    age = current - observed_at
    if age < 0 or age > HEALTH_SAMPLE_FRESHNESS_SECONDS:
        return False, "maintenance_state_observation_stale"
    return True, "not_in_maintenance"


def failover_expression(
    host: str = ZABBIX_SERVER_HOST,
) -> str:
    """Alert on any fresh failure among the existing On-Prem probes.

    Web/EMR fail items use 1 for failure. DB TCP and SNMP availability use 0.
    Probes collect every 60 seconds; the freshness clause prevents a stale or
    unsupported item from being mistaken for a current failure.
    """
    fresh = f"{HEALTH_SAMPLE_FRESHNESS_SECONDS}s"
    failures = [
        (host, WEB_FAIL_ITEM_KEY, "1"),
        (host, DOC_FAIL_ITEM_KEY, "1"),
        (host, DB_HEALTH_ITEM_KEY, "0"),
        *((snmp_host, SNMP_AVAILABILITY_ITEM_KEY, "0") for snmp_host in ONPREM_SNMP_HOSTS),
    ]
    branches = []
    for target_host, item_key, failed_value in failures:
        item = f"/{target_host}/{item_key}"
        branches.append(f"(last({item})={failed_value} and nodata({item},{fresh})=0)")
    return "(" + " or ".join(branches) + ")"


def production_trigger_tags() -> list[dict[str, str]]:
    return [{"tag": tag, "value": value} for tag, value in PRODUCTION_TRIGGER_TAGS]


def evaluate_failover_policy(
    *,
    web_failed: bool,
    doc_failed: bool,
    db_failed: bool,
    snmp_failed: bool = False,
    duration_seconds: float,
    monitoring_path_last_value: Any,
    monitoring_path_lastclock: Any,
    now_epoch: float | None = None,
    health_samples_fresh: bool = False,
    maintenance: bool,
    broad_test_mode: bool,
    test_marker: bool = False,
    maintenance_host_states: dict[str, Any] | None = None,
    maintenance_samples_fresh: bool = False,
) -> bool:
    """Evaluate any fresh monitored failure while preserving explicit test guards."""
    del (
        duration_seconds,
        monitoring_path_last_value,
        monitoring_path_lastclock,
        now_epoch,
        maintenance,
        maintenance_host_states,
        maintenance_samples_fresh,
    )
    return bool(
        any(value is True for value in (web_failed, doc_failed, db_failed, snmp_failed))
        and health_samples_fresh is True
        and broad_test_mode is False
        and test_marker is False
    )


def policy_matrix() -> list[dict[str, str]]:
    """Return the concise operator-facing production policy matrix."""

    return [
        {"situation": "Server reboot", "general_alert": "O", "failover": "X", "failback": "X"},
        {"situation": "Agent disconnect", "general_alert": "O", "failover": "X", "failback": "X"},
        {"situation": "WireGuard/monitoring path disconnect", "general_alert": "O", "failover": "X", "failback": "X"},
        {"situation": "CPU/RAM/Disk warning", "general_alert": "O", "failover": "X", "failback": "X"},
        {"situation": "Temporary service outage", "general_alert": "O", "failover": "X", "failback": "X"},
        {"situation": "Any fresh On-Prem Web/EMR/DB/SNMP health failure", "general_alert": "O", "failover": "O", "failback": "X"},
        {"situation": "Unknown or stale On-Prem health observation", "general_alert": "O", "failover": "X", "failback": "X"},
        {"situation": "Failover execution complete", "general_alert": "O", "failover": "-", "failback": "X"},
        {"situation": "Temporary On-Prem recovery", "general_alert": "O", "failover": "X", "failback": "X"},
        {"situation": "DR_ACTIVE + all fresh On-Prem health probes normal", "general_alert": "O", "failover": "X", "failback": "O"},
        {"situation": "Stale Recovery", "general_alert": "O", "failover": "X", "failback": "X"},
        {"situation": "CPU/RAM/Disk/FIM/SCA/Vulnerability/general Wazuh alert", "general_alert": "O", "failover": "X", "failback": "X"},
    ]
