"""Normalize ordinary Zabbix alerts without granting DR approval authority.

The alert bridge is a monitoring-notification path only. Failover candidates
must arrive over the separately authenticated ``Cloud_Slack_DR_Trigger``
operation; a host name, Problem status, or event tag in an ordinary alert is
not sufficient authority to create an approval request.
"""

import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone


DEMO_FAILOVER_HOST_PROFILES = {
    "web_server": "web",
    "doc_server": "web",
    "emr_server": "web",
    "db_server": "db",
    "cisco_2800_series": "snmp",
    "catalyst_2950_series": "snmp",
    "catalyst_3560_series": "snmp",
    "catalyst_3550_series": "snmp",
    "zabbix_server": "db_tcp",
}
DB_TCP_ITEM_KEY = "net.tcp.service[tcp,IP_REDACTED,3306]"
NON_DR_METRIC_MARKERS = (
    "cpu",
    "processor",
    "ram",
    "memory",
    "disk",
    "filesystem",
    "file system",
    "storage",
    "swap",
    "load average",
    "load_average",
    "loadavg",
    "performance",
    "threshold",
    "backup",
    "s3",
    "clock",
    "time sync",
    "time_sync",
    "ntp",
    "wazuh",
    "fim",
    "sca",
    "vulnerability",
    "ssh",
    "secure shell",
    "login",
    "security",
    "informational",
)
# Compatibility name for callers/tests that imported the earlier constant.
NON_HEALTH_MARKERS = NON_DR_METRIC_MARKERS


def _first_value(*values):
    for value in values:
        if value is not None and str(value).strip():
            return value
    return ""


def _text(value, limit=300):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _as_bool(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _normalise_host(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _is_db_tcp_item(item):
    normalized = re.sub(r"\s+", "", str(item or "").lower())
    return normalized == DB_TCP_ITEM_KEY


def _non_dr_metric(alert):
    signal = " ".join(
        (alert.event, alert.trigger_description, alert.item, alert.value)
    ).lower()
    return any(marker in signal for marker in NON_DR_METRIC_MARKERS)


def demo_failover_candidate(alert):
    """Ordinary Alert payloads are never authenticated Production DR actions."""

    if alert.status not in {"PROBLEM", "ACTIVE"}:
        return False, "not a problem event"
    return False, "PRODUCTION_ACTION_REQUIRED"


def demo_failback_candidate(alert):
    """Return ``(eligible, reason)`` for an immediate Recovery candidate.

    Recovery candidates use the same core-host and non-DR metric contract as
    Failover, but the lifecycle ``DR_ACTIVE`` check is performed by the
    caller against persistent state.  Zabbix's current recovery status values
    are accepted without inventing a second trigger or stability window.
    """

    if alert.status not in {"OK", "RECOVERY", "RESOLVED"}:
        return False, "not a recovery event"
    profile = DEMO_FAILOVER_HOST_PROFILES.get(_normalise_host(alert.host))
    if profile is None:
        return False, "host is outside the Demo Freeze core-host set"
    if profile == "db_tcp" and not _is_db_tcp_item(alert.item):
        return False, "Zabbix server event is not the dedicated DB TCP check"
    if _non_dr_metric(alert):
        return False, "NON_DR_METRIC"
    return True, "CORE_HOST_RECOVERY"


def _onprem_targets_snapshot(app):
    provider = app.config.get("NETWORK_DR_HEALTH_PROVIDER")
    provider_object = getattr(provider, "__self__", None)
    if provider_object is None and hasattr(provider, "onprem_targets_snapshot"):
        provider_object = provider
    snapshot_method = getattr(provider_object, "onprem_targets_snapshot", None)
    if not callable(snapshot_method):
        return {"status": "UNKNOWN", "reason": "Zabbix On-Prem health provider unavailable"}
    try:
        snapshot = snapshot_method()
    except Exception:
        return {"status": "UNKNOWN", "reason": "Zabbix On-Prem health query failed"}
    if not isinstance(snapshot, dict):
        return {"status": "UNKNOWN", "reason": "Zabbix On-Prem health response invalid"}
    return snapshot


def _zabbix_recheck_lock(app):
    from chatops_core import acquire_pipeline_file_lock

    lock_path = str(app.config["CHATOPS_EXECUTION_LOCK_FILE"]) + ".zabbix-recheck"
    return acquire_pipeline_file_lock(lock_path)


def poll_failover_condition(app):
    """Recheck the existing signed production event against fresh Zabbix probes."""
    from chatops_core import read_persistent_dr_state, release_pipeline_file_lock

    lock = _zabbix_recheck_lock(app)
    if lock is None:
        return {"status": "SKIPPED", "reason": "RECHECK_ALREADY_RUNNING"}
    try:
        dr_state = read_persistent_dr_state(app.config["DR_STATE_FILE"])
        if not dr_state or dr_state in {"DR_ACTIVE", "FAILOVER_EXECUTING", "FAILBACK_EXECUTING"}:
            return {"status": "SKIPPED", "reason": "DR_STATE_NOT_FAILOVER_ELIGIBLE"}
        store = app.extensions["approval_store"]
        if store.find_active("failover"):
            return {"status": "SKIPPED", "reason": "FAILOVER_REQUEST_ALREADY_ACTIVE"}
        snapshot = _onprem_targets_snapshot(app)
        if snapshot.get("status") != "PROBLEM":
            return {"status": snapshot.get("status") or "UNKNOWN", "reason": snapshot.get("reason") or "NO_FRESH_PROBE_FAILURE"}
        provider = app.config.get("NETWORK_DR_HEALTH_PROVIDER")
        provider_object = getattr(provider, "__self__", None)
        if provider_object is None and hasattr(provider, "current_production_problem"):
            provider_object = provider
        get_problem = getattr(provider_object, "current_production_problem", None)
        event = get_problem() if callable(get_problem) else None
        if not isinstance(event, dict):
            return {"status": "UNKNOWN", "reason": "OPEN_PRODUCTION_ZABBIX_EVENT_UNAVAILABLE"}
        event_id = str(event.get("event_id") or "")
        trigger_id = str(event.get("trigger_id") or "")
        try:
            event_clock = int(event.get("event_clock"))
        except (TypeError, ValueError, OverflowError):
            return {"status": "UNKNOWN", "reason": "OPEN_PRODUCTION_ZABBIX_EVENT_INVALID"}
        if not re.fullmatch(r"[1-9][0-9]*", event_id) or trigger_id != "24712":
            return {"status": "UNKNOWN", "reason": "OPEN_PRODUCTION_ZABBIX_EVENT_INVALID"}
        secret = str(app.config.get("ZABBIX_PRODUCTION_ACTION_HMAC_KEY") or "")
        if len(secret.encode("utf-8")) < 32:
            return {"status": "BLOCKED", "reason": "PRODUCTION_ACTION_HMAC_UNAVAILABLE"}
        event_tags_json = json.dumps(event.get("tags") or [], ensure_ascii=True, separators=(",", ":"))
        observed_at = datetime.fromtimestamp(event_clock, timezone.utc).isoformat().replace("+00:00", "Z")
        payload = {
            "source": "zabbix_production_action",
            "action_name": "Cloud_Slack_DR_Trigger",
            "action": "failover",
            "incident_id": event_id,
            "event_id": event_id,
            "trigger_id": trigger_id,
            "event_source": "0",
            "summary": str(event.get("summary") or "On-Prem monitored health failure"),
            "host": "Zabbix server",
            "status": "PROBLEM",
            "event_tags_json": event_tags_json,
            "incident_at": observed_at,
            "test_mode": False,
            "event_age_seconds": str(max(0, time.time() - event_clock)),
        }
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        signature_timestamp = str(int(time.time()))
        signature = hmac.new(
            secret.encode("utf-8"),
            signature_timestamp.encode("ascii") + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        request = urllib.request.Request(
            str(app.config.get("ZABBIX_CHATOPS_REQUEST_URL") or "http://IP_REDACTED:5000/chatops/request"),
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-ChatOps-Zabbix-Timestamp": signature_timestamp,
                "X-ChatOps-Zabbix-Signature": "v1=" + signature,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                return {"status": "SKIPPED", "reason": "CHATOPS_STATE_CHANGED"}
            raise ZabbixProcessingError("Signed Zabbix recheck delivery failed") from exc
        except (OSError, TimeoutError, ValueError) as exc:
            raise ZabbixProcessingError("Signed Zabbix recheck delivery failed") from exc
        return {
            "status": "REQUESTED",
            "request_id": str(result.get("request_id") or ""),
            "event_id": event_id,
        }
    finally:
        release_pipeline_file_lock(lock)


def poll_failback_condition(app):
    """Create a Failback approval when DR is active and one server is normal.

    The existing expiry worker calls this on its 60-second recheck cadence. An
    expired approval may be recreated while the same fresh normal condition
    remains; a cancelled, failed, or completed request is not automatically
    reissued.
    """
    from chatops_core import create_approval_request, read_persistent_dr_state, release_pipeline_file_lock

    lock = _zabbix_recheck_lock(app)
    if lock is None:
        return {"status": "SKIPPED", "reason": "RECHECK_ALREADY_RUNNING"}
    try:
        if read_persistent_dr_state(app.config["DR_STATE_FILE"]) != "DR_ACTIVE":
            return {"status": "SKIPPED", "reason": "DR_NOT_ACTIVE"}
        store = app.extensions["approval_store"]
        if store.find_active("failback"):
            return {"status": "SKIPPED", "reason": "FAILBACK_REQUEST_ALREADY_ACTIVE"}
        prior = [
            state for state in store.list_with_messages()
            if state.get("action") == "failback"
        ]
        latest = prior[-1] if prior else None
        if latest is not None and latest.get("status") not in {"EXPIRED", "SUCCEEDED"}:
            return {"status": "SKIPPED", "reason": "PRIOR_REQUEST_NOT_EXPIRED"}
        snapshot = _onprem_targets_snapshot(app)
        probes = snapshot.get("probes") if isinstance(snapshot.get("probes"), dict) else {}
        normal_servers = {
            name: probe
            for name, probe in probes.items()
            if name in {"Hospital DR Web Core", "Hospital DR Doc Core", "Hospital DR DB Core"}
            and isinstance(probe, dict)
            and probe.get("status") == "READY"
        }
        if not normal_servers:
            return {"status": snapshot.get("status") or "UNKNOWN", "reason": snapshot.get("reason") or "NO_ONPREM_SERVER_NORMAL"}
        incident = {
            "incident_id": "zabbix-onprem-server-recovery",
            "summary": "At least one monitored On-Prem server is normal; Failback approval requested.",
            "observed_at": snapshot.get("checked_at") or "-",
            "incident_at": snapshot.get("checked_at") or "-",
            "source": "zabbix",
            "request_origin": "ZABBIX_ANY_SERVER_NORMAL",
            "rule_id": "24712",
            "severity": "INFO",
            "host": ", ".join(normal_servers),
            "failback_mode": "ANY_SERVER_NORMAL",
            "failback_reason": "AT_LEAST_ONE_FRESH_ONPREM_SERVER_PROBE_NORMAL",
            "network_status": snapshot.get("status") or "UNKNOWN",
            "network_reason": "At least one On-Prem server probe is normal; full readiness is checked during approval and execution.",
            "network_source": "ZABBIX_ONPREM_HEALTH",
            "network_devices": probes,
            "network_checked_at": snapshot.get("checked_at") or "-",
            "event_age_seconds": 0,
        }
        state, reused = create_approval_request(app, "failback", incident)
        return {
            "status": "REQUESTED",
            "request_id": state.get("request_id"),
            "reused": reused,
        }
    finally:
        release_pipeline_file_lock(lock)


@dataclass(frozen=True)
class ZabbixAlert:
    incident_id: str
    trigger_id: str
    host: str
    severity: str
    status: str
    value: str
    event: str
    timestamp: str
    item: str
    trigger_description: str
    dr_escalate: bool

    def incident(self):
        incident = {
            "incident_id": self.incident_id,
            "summary": _text(f"Zabbix {self.severity}: {self.host} - {self.event}", 300),
            "observed_at": self.timestamp or "-",
            "source": "zabbix",
            "rule_id": self.trigger_id or "-",
            "severity": self.severity,
            "host": self.host,
        }
        if self.timestamp and self.timestamp != "-":
            incident["incident_at"] = self.timestamp
        return incident


class ZabbixProcessingError(RuntimeError):
    """Raised when the alert was not durably processed and Zabbix must retry."""

    status_code = 502


def parse_zabbix_alert(payload):
    """Parse the Media Type payload while treating all fields as optional."""
    if not isinstance(payload, dict):
        raise ValueError("Zabbix alert must be a JSON object")

    event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    host = _text(_first_value(payload.get("host"), payload.get("Host"), payload.get("hostname"), event.get("host")), 120)
    severity = _text(_first_value(payload.get("severity"), payload.get("Severity"), event.get("severity"), "UNKNOWN"), 20).upper()
    status = _text(_first_value(payload.get("status"), payload.get("Status"), payload.get("event_status"), event.get("status"), "UNKNOWN"), 30).upper()
    value = _text(_first_value(payload.get("value"), payload.get("Value"), event.get("value")), 80)
    trigger_id = _text(_first_value(payload.get("trigger_id"), payload.get("TriggerID"), payload.get("triggerid"), event.get("trigger_id")), 80)
    event_text = _text(
        _first_value(
            payload.get("event_description"),
            payload.get("trigger_description"),
            payload.get("TriggerDescription"),
            payload.get("message"),
            payload.get("Message"),
            payload.get("subject"),
            payload.get("Subject"),
            event.get("description"),
            "Zabbix infrastructure event",
        ),
        500,
    )
    timestamp = _text(_first_value(payload.get("timestamp"), payload.get("Timestamp"), event.get("timestamp")), 80)
    item = _text(_first_value(payload.get("item"), payload.get("Item"), event.get("item")), 160)
    supplied_id = _first_value(
        payload.get("event_id"),
        payload.get("EventID"),
        payload.get("eventid"),
        event.get("id"),
    )
    if supplied_id:
        incident_id = _text(supplied_id, 160)
    else:
        fingerprint = {
            "host": host,
            "trigger_id": trigger_id,
            "status": status,
            "value": value,
            "event": event_text,
            "timestamp": timestamp,
        }
        incident_id = "zabbix-" + hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True, ensure_ascii=True).encode("utf-8")
        ).hexdigest()[:24]
    return ZabbixAlert(
        incident_id=incident_id,
        trigger_id=trigger_id,
        host=host or "unknown",
        severity=severity or "UNKNOWN",
        status=status or "UNKNOWN",
        value=value or "-",
        event=event_text,
        timestamp=timestamp or "-",
        item=item or "-",
        trigger_description=event_text,
        dr_escalate=_as_bool(_first_value(payload.get("dr_escalate"), payload.get("DR_Escalate"), event.get("dr_escalate"))),
    )


def render_zabbix_alert(alert):
    lines = [
        "*[ZABBIX INFRASTRUCTURE ALERT]*",
        f"Host: `{alert.host}`",
        f"Severity: *{alert.severity}*",
        f"Status: *{alert.status}*",
        f"Event: {alert.event}",
        f"Trigger ID: `{alert.trigger_id or '-'}`",
        f"Value: `{alert.value}`",
        f"Time: `{alert.timestamp}`",
    ]
    if alert.item != "-":
        lines.append(f"Item: `{alert.item}`")
    lines.extend(("", "Infrastructure monitoring alert; approval controls remain separate."))
    text = "\n".join(lines)
    return text, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]


def process_zabbix_alert(app, payload):
    alert = parse_zabbix_alert(payload)
    audit = app.extensions["chatops_audit"]
    if audit.has_alert_incident("zabbix", alert.incident_id, alert.status):
        print(f"[ZABBIX] duplicate alert ignored incident={alert.incident_id}", flush=True)
        return {
            "incident_id": alert.incident_id,
            "alert_sent": False,
            "duplicate": True,
            "dr_escalated": False,
            "request_id": None,
        }

    alert_client = app.extensions["wazuh_alert_client"]
    if not getattr(alert_client, "available", False):
        raise ZabbixProcessingError("ChatOps alert delivery is not configured")

    text, blocks = render_zabbix_alert(alert)
    try:
        message_result = alert_client.post_message(text, blocks)
    except Exception as exc:
        raise ZabbixProcessingError("ChatOps alert delivery failed") from exc

    request_id = None
    failback_request_id = None
    reused = False
    failover_candidate, failover_reason = demo_failover_candidate(alert)

    failback_candidate, failback_reason = demo_failback_candidate(alert)
    failback_dr_active = None
    if failback_candidate:
        try:
            from chatops_core import (
                _record_rto,
                create_approval_request,
                read_persistent_dr_state,
            )

            failback_dr_active = (
                read_persistent_dr_state(app.config["DR_STATE_FILE"]) == "DR_ACTIVE"
            )
            if not failback_dr_active:
                failback_candidate = False
                failback_reason = "DR_NOT_ACTIVE"
            else:
                incident = alert.incident()
                incident["failback_mode"] = "ANY_SERVER_NORMAL"
                incident["failback_reason"] = "ELIGIBLE_ONPREM_SERVER_RECOVERY_EVENT"
                incident["recovered_target"] = alert.host
                incident["network_status"] = "UNKNOWN"
                incident["network_reason"] = (
                    "One On-Prem target recovery event was received; overall network health is rechecked during approval."
                )
                incident["network_source"] = "ZABBIX_RECOVERY_EVENT"
                incident["network_devices"] = {
                    alert.host: {"status": "READY", "source": "ZABBIX_RECOVERY_EVENT"}
                }
                incident["network_checked_at"] = alert.timestamp or "-"
                _record_rto(incident, "slack_alert_at")
                state, reused = create_approval_request(app, "failback", incident)
                failback_request_id = state["request_id"]
                request_id = failback_request_id
        except Exception as exc:
            raise ZabbixProcessingError("Failback request delivery failed") from exc

    if alert.status in {"OK", "RECOVERY", "RESOLVED"}:
        active_text = (
            str(failback_dr_active).lower()
            if failback_dr_active is not None
            else "UNKNOWN"
        )
        print(
            "[ZABBIX] recovery received "
            f"incident={alert.incident_id} host={alert.host} "
            f"failback_candidate={failback_candidate} reason={failback_reason} "
            f"dr_active={active_text} "
            f"failback_requested={bool(failback_request_id)}",
            flush=True,
        )

    try:
        registered = audit.register_alert_message_data(
            {
                "incident_id": alert.incident_id,
                "source": "zabbix",
                "event": "zabbix_infrastructure_alert",
                "rule_id": alert.trigger_id,
                "host": alert.host,
                "severity": alert.severity,
                "status": alert.status,
                "timestamp": alert.timestamp,
                "summary": alert.event,
            },
            message_result,
            dr_escalated=False,
        )
        if registered is None:
            raise ZabbixProcessingError("ChatOps alert message result was incomplete")
    except Exception as exc:
        # A successful Slack post without a successful duplicate registry is
        # not a successful ingestion contract; allow Zabbix to retry.
        raise ZabbixProcessingError("ChatOps alert result could not be recorded") from exc

    print(
        "[ZABBIX] alert received "
        f"incident={alert.incident_id} trigger={alert.trigger_id or '-'} host={alert.host} "
        f"severity={alert.severity} alert_sent=True "
        f"failover_candidate={failover_candidate} reason={failover_reason} "
        "dr_escalated=False "
        f"failback_requested={bool(failback_request_id)}",
        flush=True,
    )
    return {
        "incident_id": alert.incident_id,
        "trigger_id": alert.trigger_id,
        "severity": alert.severity,
        "alert_sent": True,
        "alert_error": None,
        "duplicate": False,
        "dr_escalated": False,
        "request_id": request_id,
        "reused": reused,
        "escalation_error": None,
        "failover_candidate": failover_candidate,
        "failover_reason": failover_reason,
        "failback_candidate": failback_candidate,
        "failback_reason": failback_reason,
        "failback_requested": bool(failback_request_id),
    }
