"""Security readiness checks used before a Failback approval can proceed."""

import re
from datetime import datetime, timezone


READY = "READY"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"

DESTRUCTIVE_TERMS = (
    "ransomware",
    "wiper",
    "destructive malware",
    "mass deletion",
    "file encryption",
    "encrypt files",
    "data destruction",
)
ACTIVE_INCIDENT_STATUSES = {"active", "open", "unresolved", "investigating", "ongoing"}
ONLINE_AGENT_STATUSES = {"active", "online", "ok", "normal", "available"}


def _normalized(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _parse_timestamp(value):
    if isinstance(value, (int, float)):
        return float(value)
    if not value:
        return None
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return None


def _severity_is_critical(incident):
    severity = str(incident.get("severity", "")).upper()
    if severity == "CRITICAL":
        return True
    try:
        return int(incident.get("level", incident.get("rule_level", 0))) >= 13
    except (TypeError, ValueError):
        return False


def _event_severity(incident):
    severity = str(incident.get("severity", "")).strip().upper()
    if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return severity
    try:
        level = int(incident.get("level", incident.get("rule_level")))
    except (TypeError, ValueError):
        return None
    if level >= 13:
        return "CRITICAL"
    if level >= 10:
        return "HIGH"
    if level >= 7:
        return "MEDIUM"
    return "LOW"


def evaluate_failback_risk(snapshot=None, now=None, max_age_seconds=900):
    """Summarize recent Wazuh severity for Slack; this is informational only.

    Missing query data, timestamps, or severity is UNKNOWN. Events outside the
    configured recent window are ignored so an old alert cannot look current.
    """
    current_time = datetime.now(timezone.utc).timestamp() if now is None else float(now)
    checked_at = datetime.fromtimestamp(current_time, timezone.utc).isoformat().replace("+00:00", "Z")

    def result(level, observed_at="-", reason=""):
        return {
            "risk_level": level,
            "risk_observed_at": observed_at,
            "risk_checked_at": checked_at,
            "risk_reason": reason,
        }

    if not isinstance(snapshot, dict) or snapshot.get("query_ok") is not True:
        return result("UNKNOWN", reason="Wazuh query is unavailable.")
    incidents = snapshot.get("incidents")
    if not isinstance(incidents, list):
        return result("UNKNOWN", reason="Wazuh event data is incomplete.")
    try:
        window = int(max_age_seconds)
    except (TypeError, ValueError):
        return result("UNKNOWN", reason="Wazuh freshness window is invalid.")
    if window <= 0:
        return result("UNKNOWN", reason="Wazuh freshness window is invalid.")

    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    recent = []
    for incident in incidents:
        if not isinstance(incident, dict):
            return result("UNKNOWN", reason="Wazuh event data is incomplete.")
        observed = incident.get("observed_at") or incident.get("timestamp") or incident.get("@timestamp")
        observed_epoch = _parse_timestamp(observed)
        if observed_epoch is None:
            return result("UNKNOWN", reason="A Wazuh event has no valid observation time.")
        age = current_time - observed_epoch
        if age < 0:
            return result("UNKNOWN", reason="A Wazuh event timestamp is in the future.")
        if age > window:
            continue
        severity = _event_severity(incident)
        if severity is None:
            return result("UNKNOWN", reason="A recent Wazuh event has no valid severity.")
        recent.append((rank[severity], observed_epoch, severity))

    if not recent:
        return result("NORMAL", reason="No Wazuh events were observed in the recent window.")
    _, observed_epoch, severity = max(recent)
    observed_at = datetime.fromtimestamp(observed_epoch, timezone.utc).isoformat().replace("+00:00", "Z")
    return result(severity, observed_at, reason="Based on the most severe recent Wazuh event.")


def _is_destructive(incident):
    searchable = _normalized(
        " ".join(
            str(incident.get(key, ""))
            for key in ("category", "description", "summary", "rule_description", "groups", "mitre")
        )
    )
    return any(_normalized(term) in searchable for term in DESTRUCTIVE_TERMS)


def _is_active(incident):
    status = str(incident.get("status", "")).lower().strip()
    return status in ACTIVE_INCIDENT_STATUSES or incident.get("resolved") is False


def _incident_host_matches(incident, required_agents):
    if not required_agents:
        return True
    values = {
        _normalized(incident.get("agent_id")),
        _normalized(incident.get("agent_name")),
        _normalized(incident.get("host")),
    }
    return bool(values.intersection({_normalized(item) for item in required_agents}))


def _result(status, reason, agents="-", critical_incident="-"):
    return {
        "status": status,
        "reason": reason,
        "agents": agents,
        "critical_incident": critical_incident,
    }


def evaluate_failback_security(snapshot=None, required_agents=None, now=None, stale_after=300):
    """Return READY/BLOCKED/UNKNOWN from a complete Wazuh state snapshot.

    A snapshot must explicitly confirm a successful query and include both the
    agent list and the incident list. Missing or stale security data is never
    treated as READY.
    """
    if not isinstance(snapshot, dict) or snapshot.get("query_ok") is not True:
        return _result(UNKNOWN, "Wazuh state is unavailable or the query failed.")
    agents = snapshot.get("agents")
    incidents = snapshot.get("incidents")
    if not isinstance(agents, list) or not isinstance(incidents, list):
        return _result(UNKNOWN, "Wazuh state is incomplete; agents and incidents are required.")
    required_agents = tuple(required_agents or ())
    if not required_agents:
        return _result(UNKNOWN, "The required On-Premise Wazuh agents are not configured.")

    current_time = datetime.now(timezone.utc).timestamp() if now is None else float(now)
    agent_by_identity = {}
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        for identity in (agent.get("id"), agent.get("name")):
            identity = _normalized(identity)
            if identity:
                agent_by_identity[identity] = agent

    for required in required_agents:
        agent = agent_by_identity.get(_normalized(required))
        if not agent:
            return _result(UNKNOWN, f"Required Wazuh agent is missing: {required}.", agents="INCOMPLETE")
        status = str(agent.get("status", "")).lower().strip()
        last_seen = _parse_timestamp(agent.get("last_seen"))
        if status not in ONLINE_AGENT_STATUSES or last_seen is None:
            return _result(UNKNOWN, f"Required Wazuh agent is offline or stale: {required}.", agents="STALE")
        if current_time - last_seen > stale_after:
            return _result(UNKNOWN, f"Required Wazuh agent is stale: {required}.", agents="STALE")

    for incident in incidents:
        if not isinstance(incident, dict):
            return _result(UNKNOWN, "Wazuh incident data contains an invalid entry.", agents="OK")
        if (
            _is_active(incident)
            and _severity_is_critical(incident)
            and _is_destructive(incident)
            and _incident_host_matches(incident, required_agents)
        ):
            incident_id = incident.get("id") or incident.get("incident_id") or "unresolved-critical-event"
            return _result(
                BLOCKED,
                "An unresolved destructive Critical incident affects an important On-Premise service.",
                agents="OK",
                critical_incident=str(incident_id)[:160],
            )

    return _result(READY, "No unresolved destructive Critical incident was found.", agents="OK", critical_incident="None")
