"""Normalize Wazuh alerts and optionally escalate high-impact events to DR."""

import hashlib
import json
import re
from dataclasses import dataclass


DESTRUCTIVE_TERMS = (
    "ransomware",
    "wiper",
    "destructive malware",
    "mass deletion",
    "file encryption",
    "encrypt files",
    "data destruction",
)
IMPORTANT_HOST_TERMS = ("db", "database", "mysql", "web", "doc", "emr", "hospital")


def _first_value(*values):
    for value in values:
        if value is not None and str(value).strip():
            return value
    return ""


def _text(value, limit=300):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    value = re.sub(r"\s+", " ", str(value or "")).strip()
    return value[:limit]


def _mrkdwn(value, limit=300):
    return _text(value, limit).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _severity(level):
    try:
        numeric_level = int(level)
    except (TypeError, ValueError):
        return "LOW"
    if numeric_level >= 13:
        return "CRITICAL"
    if numeric_level >= 10:
        return "HIGH"
    if numeric_level >= 7:
        return "MEDIUM"
    return "LOW"


def _mitre_values(rule):
    mitre = rule.get("mitre") or {}
    entries = mitre if isinstance(mitre, list) else [mitre]
    values = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        identifier = _first_value(entry.get("id"), entry.get("technique_id"))
        name = _first_value(entry.get("name"), entry.get("technique"))
        if identifier or name:
            values.append(_text(" / ".join(filter(None, (identifier, name))), 120))
    return tuple(values)


@dataclass(frozen=True)
class WazuhAlert:
    timestamp: str
    rule_id: str
    rule_level: int
    rule_description: str
    severity: str
    agent_id: str
    agent_name: str
    agent_ip: str
    decoder: str
    source_ip: str
    destination_ip: str
    location: str
    mitre: tuple
    groups: tuple
    event_summary: str
    incident_id: str

    def incident(self):
        return {
            "incident_id": self.incident_id,
            "summary": _text(
                f"Wazuh {self.severity}: {self.agent_name or self.agent_id or 'unknown host'} - "
                f"{self.rule_description or self.event_summary or 'security event'}",
                300,
            ),
            "observed_at": self.timestamp or "-",
            "source": "wazuh",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "host": self.agent_name or self.agent_id or "unknown",
            "groups": list(self.groups),
            "location": self.location,
            "decoder": self.decoder,
        }


def parse_wazuh_alert(payload):
    """Parse a Wazuh JSON object; fields not present in an alert are optional."""
    if not isinstance(payload, dict):
        raise ValueError("Wazuh alert must be a JSON object")

    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
    decoder = payload.get("decoder") if isinstance(payload.get("decoder"), dict) else {}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    level_value = _first_value(rule.get("level"), payload.get("level"), 0)
    try:
        rule_level = int(level_value)
    except (TypeError, ValueError):
        rule_level = 0

    rule_id = _text(_first_value(rule.get("id"), payload.get("rule_id"), "unknown"), 80)
    description = _text(_first_value(rule.get("description"), payload.get("description")), 300)
    full_log = _text(_first_value(payload.get("full_log"), payload.get("log")), 500)
    event_summary = description or full_log or "Wazuh security event"
    timestamp = _text(_first_value(payload.get("timestamp"), payload.get("@timestamp")), 80)
    agent_id = _text(_first_value(agent.get("id"), payload.get("agent_id")), 80)
    agent_name = _text(_first_value(agent.get("name"), payload.get("agent_name")), 120)
    agent_ip = _text(_first_value(agent.get("ip"), payload.get("agent_ip")), 80)
    decoder_name = _text(_first_value(decoder.get("name"), payload.get("decoder_name")), 120)
    source_ip = _text(
        _first_value(data.get("srcip"), data.get("src_ip"), payload.get("srcip"), payload.get("src_ip")),
        80,
    )
    destination_ip = _text(
        _first_value(data.get("dstip"), data.get("dst_ip"), payload.get("dstip"), payload.get("dst_ip")),
        80,
    )
    location = _text(_first_value(payload.get("location"), data.get("location")), 160)
    groups = rule.get("groups") or payload.get("groups") or []
    if not isinstance(groups, list):
        groups = [groups]
    groups = tuple(_text(item, 80) for item in groups if str(item).strip())
    mitre = _mitre_values(rule)

    supplied_id = _first_value(payload.get("id"), payload.get("event_id"), data.get("event_id"))
    if supplied_id:
        incident_id = _text(supplied_id, 160)
    else:
        fingerprint = {
            "timestamp": timestamp,
            "rule_id": rule_id,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "description": description,
            "full_log": full_log,
            "source_ip": source_ip,
        }
        incident_id = "wazuh-" + hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True, ensure_ascii=True).encode("utf-8")
        ).hexdigest()[:24]

    return WazuhAlert(
        timestamp=timestamp,
        rule_id=rule_id,
        rule_level=rule_level,
        rule_description=description,
        severity=_severity(rule_level),
        agent_id=agent_id,
        agent_name=agent_name,
        agent_ip=agent_ip,
        decoder=decoder_name,
        source_ip=source_ip,
        destination_ip=destination_ip,
        location=location,
        mitre=mitre,
        groups=groups,
        event_summary=event_summary,
        incident_id=incident_id,
    )


def should_escalate_to_dr(alert, destructive_terms=DESTRUCTIVE_TERMS, important_host_terms=IMPORTANT_HOST_TERMS):
    """Escalate only critical destructive events affecting an important service."""
    if alert.severity != "CRITICAL":
        return False
    searchable = " ".join(
        (
            alert.rule_description,
            alert.event_summary,
            " ".join(alert.groups),
            alert.agent_name,
            alert.location,
        )
    ).lower()
    normalized = re.sub(r"[^a-z0-9]+", " ", searchable)
    destructive = any(
        re.sub(r"[^a-z0-9]+", " ", term.lower()).strip() in normalized
        for term in destructive_terms
    )
    host_tokens = set(normalized.split())
    important_host = any(term.lower() in host_tokens for term in important_host_terms)
    return destructive and important_host


def render_wazuh_alert(alert):
    """Return concise Slack text/blocks without forwarding the raw alert payload."""
    lines = [
        "[WAZUH SECURITY ALERT]",
        f"Severity: *{_mrkdwn(alert.severity, 20)}*",
        f"Host: `{_mrkdwn(alert.agent_name or alert.agent_id or 'unknown', 120)}`",
        f"Rule ID: `{_mrkdwn(alert.rule_id, 80)}`",
        f"Event: {_mrkdwn(alert.rule_description or alert.event_summary, 300)}",
        f"Source: Wazuh / {_mrkdwn(alert.decoder or alert.location or 'unknown', 120)}",
        f"Time: `{_mrkdwn(alert.timestamp or '-', 80)}`",
    ]
    if alert.agent_ip:
        lines.append(f"Agent IP: `{_mrkdwn(alert.agent_ip, 80)}`")
    if alert.source_ip or alert.destination_ip:
        lines.append(
            f"Network: `{_mrkdwn(alert.source_ip or '-', 80)}` -> `{_mrkdwn(alert.destination_ip or '-', 80)}`"
        )
    if alert.mitre:
        lines.append(f"MITRE: {_mrkdwn(', '.join(alert.mitre), 240)}")
    lines.extend(
        (
            "",
            f"Details: {_mrkdwn(alert.event_summary, 500)}",
            "Security monitoring alert; this message is separate from DR approval control.",
        )
    )
    text = "\n".join(lines)
    return text, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]


def process_wazuh_alert(app, payload):
    """Send the alert and reuse the existing failover request engine when needed."""
    alert = parse_wazuh_alert(payload)
    alert_client = app.extensions["wazuh_alert_client"]
    alert_sent = False
    alert_error = None
    message_result = None
    if getattr(alert_client, "available", False):
        text, blocks = render_wazuh_alert(alert)
        try:
            message_result = alert_client.post_message(text, blocks)
            alert_sent = True
        except Exception as exc:
            alert_error = type(exc).__name__
    else:
        alert_error = "not_configured"

    correlation = {"status": "NOT_CONFIGURED", "incident_id": None, "alert_sent": False}
    correlation_incident = None
    correlation_path = app.config.get("WAZUH_CORRELATION_STATE_FILE")
    if correlation_path:
        try:
            from wazuh_correlation import CorrelationState, render_security_incident

            window = app.config.get("WAZUH_CORRELATION_WINDOW_SECONDS", 900)
            new_incidents = CorrelationState(correlation_path, window_seconds=window).record(payload)
            correlation = {
                "status": "NO_INCIDENT" if not new_incidents else "INCIDENT",
                "incident_id": new_incidents[0]["incident_id"] if new_incidents else None,
                "alert_sent": False,
            }
            if new_incidents:
                correlation_incident = new_incidents[0]
                security_client = app.extensions.get("wazuh_security_client")
                if app.config.get("WAZUH_SECURITY_SLACK_DRY_RUN"):
                    correlation["dry_run"] = True
                    correlation["payload_ready"] = True
                elif getattr(security_client, "available", False):
                    security_text = render_security_incident(correlation_incident)
                    try:
                        security_result = security_client.post_message(security_text, [])
                        correlation["alert_sent"] = True
                        correlation["slack_channel_id"] = security_result.get("channel")
                        correlation["slack_message_ts"] = security_result.get("ts")
                        app.extensions["chatops_audit"].register_alert_message_data(
                            {
                                "incident_id": correlation_incident["incident_id"],
                                "source": "wazuh-correlation",
                                "event": "security_incident_high",
                                "rule_id": ",".join(correlation_incident["source_rules"]),
                                "host": correlation_incident["agent"],
                                "severity": correlation_incident["severity"],
                                "timestamp": correlation_incident["last_seen"],
                                "summary": correlation_incident["scenario"],
                            },
                            security_result,
                        )
                    except Exception as exc:
                        correlation["alert_error"] = type(exc).__name__
                else:
                    correlation["alert_error"] = "security_channel_not_configured"
        except (OSError, ValueError, TypeError) as exc:
            correlation = {"status": "ERROR", "incident_id": None, "alert_sent": False, "error": type(exc).__name__}

    request_id = None
    reused = False
    escalation_error = None
    escalation_block_reason = None
    if should_escalate_to_dr(alert):
        try:
            # Delayed import keeps the parser independent from the approval engine at import time.
            from chatops_core import FailoverRequestBlocked, create_approval_request

            incident = alert.incident()
            incident.update(
                {
                    "request_type": "SECURITY_DR_ESCALATION",
                    "security_escalation": True,
                    "precheck_status": "WARNING",
                    "precheck_reason": "Wazuh destructive Critical event requires operator pre-check.",
                }
            )
            state, reused = create_approval_request(app, "failover", incident)
            request_id = state["request_id"]
        except FailoverRequestBlocked as exc:
            escalation_block_reason = exc.code
        except Exception as exc:
            escalation_error = type(exc).__name__

    if alert_sent and message_result:
        try:
            app.extensions["chatops_audit"].register_alert_message(
                alert, message_result, dr_escalated=bool(request_id)
            )
        except Exception as exc:
            print(f"[AUDIT WARN] Alert message registration failed: {type(exc).__name__}", flush=True)

    print(
        "[WAZUH] alert received "
        f"incident={alert.incident_id} rule={alert.rule_id} host={alert.agent_name or alert.agent_id or 'unknown'} "
        f"severity={alert.severity} alert_sent={alert_sent} dr_escalated={bool(request_id)} "
        f"dr_escalation_block_reason={escalation_block_reason or '-'}",
        flush=True,
    )
    return {
        "incident_id": alert.incident_id,
        "severity": alert.severity,
        "rule_id": alert.rule_id,
        "alert_sent": alert_sent,
        "alert_error": alert_error,
        "dr_escalated": bool(request_id),
        "request_id": request_id,
        "reused": reused,
        "escalation_error": escalation_error,
        "escalation_block_reason": escalation_block_reason,
        "security_correlation": correlation,
    }
