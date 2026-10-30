"""Normalize Zabbix alerts and route them to the ChatOps Alert client."""

import hashlib
import json
import re
from dataclasses import dataclass


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
        return {
            "incident_id": self.incident_id,
            "summary": _text(f"Zabbix {self.severity}: {self.host} - {self.event}", 300),
            "observed_at": self.timestamp or "-",
            "source": "zabbix",
            "rule_id": self.trigger_id or "-",
            "severity": self.severity,
            "host": self.host,
        }


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
        "[ZABBIX INFRASTRUCTURE ALERT]",
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
    if audit.has_alert_incident("zabbix", alert.incident_id):
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
    reused = False
    if alert.dr_escalate:
        try:
            from chatops_core import create_approval_request

            state, reused = create_approval_request(app, "failover", alert.incident())
            request_id = state["request_id"]
        except Exception as exc:
            # Do not register the Slack alert until escalation, when requested,
            # has also succeeded. The next Zabbix retry must be allowed through.
            raise ZabbixProcessingError("DR escalation delivery failed") from exc

    try:
        registered = audit.register_alert_message_data(
            {
                "incident_id": alert.incident_id,
                "source": "zabbix",
                "event": "zabbix_infrastructure_alert",
                "rule_id": alert.trigger_id,
                "host": alert.host,
                "severity": alert.severity,
                "timestamp": alert.timestamp,
                "summary": alert.event,
            },
            message_result,
            dr_escalated=bool(request_id),
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
        f"severity={alert.severity} alert_sent=True dr_escalated={bool(request_id)}",
        flush=True,
    )
    return {
        "incident_id": alert.incident_id,
        "trigger_id": alert.trigger_id,
        "severity": alert.severity,
        "alert_sent": True,
        "alert_error": None,
        "duplicate": False,
        "dr_escalated": bool(request_id),
        "request_id": request_id,
        "reused": reused,
        "escalation_error": None,
    }
