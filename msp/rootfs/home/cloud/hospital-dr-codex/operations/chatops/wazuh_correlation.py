"""Deterministic Wazuh signal correlation for the Hospital DR security plane.

The module deliberately remains small and explainable.  It does not execute
active response, change an endpoint, or create a DR approval by itself.  It
normalizes a bounded stream of Wazuh events and raises a high-severity
security incident only when two independent signal classes occur on the same
agent inside the configured correlation window.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone


DEFAULT_WINDOW_SECONDS = 15 * 60
DEFAULT_MAX_EVENTS = 256

AUTH_GROUPS = {
    "authentication_failed",
    "authentication_failure",
    "invalid_login",
    "sshd",
}
FIM_GROUPS = {"syscheck", "syscheck_entry_added", "syscheck_file"}
SCA_GROUPS = {"sca"}
VULNERABILITY_GROUPS = {"vulnerability-detector", "vulnerability_detection", "vulnerability"}
AUTH_RULE_IDS = {"2501", "5710", "5711", "5712"}


def _text(value, limit=500):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return " ".join(str(value or "").split())[:limit]


def _timestamp(value, fallback=None):
    """Return a UTC epoch for common Wazuh timestamp spellings."""
    if isinstance(value, (int, float)):
        return float(value)
    raw = str(value or "").strip()
    if raw:
        candidate = raw.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
                try:
                    return datetime.strptime(raw, fmt).timestamp()
                except ValueError:
                    continue
    return time.time() if fallback is None else float(fallback)


def _iso(epoch):
    return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat().replace("+00:00", "Z")


def _groups(payload):
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    groups = rule.get("groups") or payload.get("groups") or []
    if not isinstance(groups, list):
        groups = [groups]
    return {str(item).strip().lower() for item in groups if str(item).strip()}


def normalize_signal(payload, now=None):
    """Keep only non-sensitive fields needed for deterministic correlation."""
    if not isinstance(payload, dict):
        raise ValueError("Wazuh signal must be a JSON object")
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    rule_id = _text(rule.get("id") or payload.get("rule_id") or "unknown", 80)
    description = _text(rule.get("description") or payload.get("description") or payload.get("full_log"), 300)
    agent_id = _text(agent.get("id") or payload.get("agent_id"), 80)
    agent_name = _text(agent.get("name") or payload.get("agent_name") or agent_id or "unknown", 120)
    event_id = _text(payload.get("id") or payload.get("event_id") or data.get("event_id"), 160)
    observed_at = _timestamp(payload.get("timestamp") or payload.get("@timestamp"), now)
    groups = _groups(payload)
    searchable = " ".join(
        (
            description,
            _text(payload.get("location"), 160),
            _text(payload.get("full_log"), 300),
            " ".join(sorted(groups)),
        )
    ).lower()
    categories = set()
    if rule_id in AUTH_RULE_IDS or groups.intersection(AUTH_GROUPS) or any(
        term in searchable for term in ("authentication failure", "invalid user", "login attempt")
    ):
        categories.add("authentication")
    if groups.intersection(FIM_GROUPS) or any(
        term in searchable for term in ("file integrity", "file modified", "file added", "file deleted", "syscheck")
    ):
        categories.add("fim")
    if groups.intersection(SCA_GROUPS) or "sca" in searchable or "cis ubuntu" in searchable:
        categories.add("sca")
    if groups.intersection(VULNERABILITY_GROUPS) or any(
        term in searchable for term in ("cve-", "vulnerability", "vulnerable package")
    ):
        categories.add("vulnerability")
    app_change = "fim" in categories and any(
        term in searchable for term in ("/etc/nginx", "/etc/apache", "/etc/mysql", "hospital", "application", "config")
    )
    if app_change:
        categories.add("application_config")
    return {
        "event_id": event_id or "wazuh-" + hashlib.sha256(
            f"{agent_name}|{rule_id}|{observed_at}|{description}".encode()
        ).hexdigest()[:24],
        "agent_id": agent_id,
        "agent_name": agent_name,
        "rule_id": rule_id,
        "description": description or "Wazuh security event",
        "groups": sorted(groups),
        "categories": sorted(categories),
        "observed_at": _iso(observed_at),
        "observed_epoch": observed_at,
    }


def _correlation_pair(categories):
    categories = set(categories)
    if {"authentication", "fim"}.issubset(categories):
        return "AUTH_AND_FIM"
    if {"authentication", "vulnerability"}.issubset(categories):
        return "AUTH_AND_VULNERABILITY"
    if {"authentication", "application_config"}.issubset(categories):
        return "AUTH_AND_APPLICATION_CONFIG"
    return ""


def correlate_signals(signals, window_seconds=DEFAULT_WINDOW_SECONDS, now=None):
    """Return explainable HIGH incidents from a normalized or raw signal list."""
    normalized = []
    for item in signals or []:
        try:
            normalized.append(item if "observed_epoch" in item else normalize_signal(item, now=now))
        except (TypeError, ValueError):
            continue
    if not normalized:
        return []
    current = time.time() if now is None else float(now)
    cutoff = current - max(1, int(window_seconds))
    by_agent = {}
    for signal in normalized:
        if float(signal.get("observed_epoch", 0)) >= cutoff:
            by_agent.setdefault(signal.get("agent_name") or signal.get("agent_id") or "unknown", []).append(signal)
    incidents = []
    for agent, events in by_agent.items():
        events.sort(key=lambda item: float(item.get("observed_epoch", 0)))
        for index, first in enumerate(events):
            window = [
                item
                for item in events[index:]
                if float(item.get("observed_epoch", 0)) - float(first.get("observed_epoch", 0)) <= window_seconds
            ]
            categories = {category for item in window for category in item.get("categories", [])}
            scenario = _correlation_pair(categories)
            if not scenario:
                continue
            source_events = [item for item in window if item.get("categories")]
            first_seen = min(float(item["observed_epoch"]) for item in source_events)
            last_seen = max(float(item["observed_epoch"]) for item in source_events)
            source_rules = sorted({str(item.get("rule_id", "unknown")) for item in source_events})
            evidence = [
                {
                    "event_id": item["event_id"],
                    "rule_id": item["rule_id"],
                    "description": item["description"],
                    "categories": item["categories"],
                    "observed_at": item["observed_at"],
                }
                for item in source_events[-8:]
            ]
            fingerprint = f"{agent}|{scenario}|{','.join(source_rules)}|{int(first_seen // max(1, int(window_seconds)))}"
            incident_id = "security-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:24]
            incident = {
                "incident_id": incident_id,
                "agent": agent,
                "scenario": scenario,
                "severity": "HIGH",
                "source_rules": source_rules,
                "first_seen": _iso(first_seen),
                "last_seen": _iso(last_seen),
                "evidence": evidence,
            }
            if not any(existing["incident_id"] == incident_id for existing in incidents):
                incidents.append(incident)
    return incidents


class CorrelationState:
    """Small atomic JSON state file; raw Wazuh payloads never enter it."""

    def __init__(self, path, window_seconds=DEFAULT_WINDOW_SECONDS, max_events=DEFAULT_MAX_EVENTS):
        self.path = path
        self.window_seconds = max(1, int(window_seconds))
        self.max_events = max(16, int(max_events))

    def _read(self):
        try:
            with open(self.path, "r", encoding="utf-8") as stream:
                value = json.load(stream)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def record(self, payload, now=None):
        current = time.time() if now is None else float(now)
        state = self._read()
        signals = state.get("signals") if isinstance(state.get("signals"), list) else []
        signals.append(normalize_signal(payload, now=current))
        cutoff = current - self.window_seconds
        signals = [item for item in signals if float(item.get("observed_epoch", 0)) >= cutoff][-self.max_events :]
        incidents = correlate_signals(signals, self.window_seconds, now=current)
        emitted = state.get("emitted") if isinstance(state.get("emitted"), dict) else {}
        retained_emitted = {}
        for incident_id, emitted_at in emitted.items():
            try:
                if current - float(emitted_at) <= self.window_seconds * 4:
                    retained_emitted[str(incident_id)] = float(emitted_at)
            except (TypeError, ValueError):
                continue
        emitted = dict(list(retained_emitted.items())[-self.max_events :])
        new_incidents = [item for item in incidents if item["incident_id"] not in emitted]
        for item in new_incidents:
            emitted[item["incident_id"]] = current
        updated = {"version": 1, "signals": signals, "emitted": emitted}
        self._write(updated)
        return new_incidents

    def _write(self, value):
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".wazuh-correlation-", dir=parent, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=True, separators=(",", ":"))
                stream.write("\n")
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def render_security_incident(incident):
    """Render a safe Slack message without forwarding raw logs."""
    rules = ", ".join(str(item) for item in incident.get("source_rules", [])) or "-"
    return (
        "[WAZUH SECURITY INCIDENT]\n"
        f"Severity: *{_text(incident.get('severity'), 20)}*\n"
        f"Incident: `{_text(incident.get('incident_id'), 80)}`\n"
        f"Host: `{_text(incident.get('agent'), 120)}`\n"
        f"Scenario: `{_text(incident.get('scenario'), 80)}`\n"
        f"Source rules: `{_text(rules, 160)}`\n"
        f"First seen: `{_text(incident.get('first_seen'), 80)}`\n"
        "This is a correlated security signal; DR execution remains separately approval-gated."
    )
