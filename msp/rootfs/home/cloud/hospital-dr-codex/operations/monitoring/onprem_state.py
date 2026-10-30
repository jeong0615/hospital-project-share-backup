"""Conservative On-Prem monitoring state classification.

Network probes cannot distinguish a powered-off host from a broken path.  This
module therefore requires an explicit power-state input before returning
``POWERED_OFF`` and never turns one unavailable host into a global WireGuard
failure.  A live host is enough to report a partial live path; a global path
failure requires an independent, explicit common-path signal.
"""

from __future__ import annotations

from typing import Any


STATES = (
    "LIVE",
    "POWERED_OFF",
    "AGENT_UNAVAILABLE",
    "SERVICE_UNHEALTHY",
    "NETWORK_PATH_BLOCKED",
    "UNKNOWN",
    "NOT_TESTED",
)

POWER_STATE_ALIASES = {
    "off": "POWERED_OFF",
    "stopped": "POWERED_OFF",
    "powered_off": "POWERED_OFF",
    "powered-off": "POWERED_OFF",
    "on": "LIVE",
    "running": "LIVE",
    "live": "LIVE",
}


def normalize_power_state(value: str | None) -> str:
    """Normalize an optional operator-owned power-state contract."""

    token = str(value or "").strip().lower().replace(" ", "_")
    return POWER_STATE_ALIASES.get(token, "UNKNOWN")


def classify_host(
    *,
    power_state: str | None = None,
    agent_reachable: bool | None = None,
    service_healthy: bool | None = None,
    path_blocked: bool = False,
) -> dict[str, Any]:
    """Return a host state without conflating power and network failure.

    ``service_healthy`` is deliberately separate from runtime reachability:
    for example, a Web process can be live while its DB dependency returns an
    HTTP 5xx response.
    """

    explicit_power = normalize_power_state(power_state)
    if explicit_power == "POWERED_OFF":
        return {"state": "POWERED_OFF", "display": "POWERED_OFF / NOT TESTED LIVE"}
    if path_blocked:
        return {"state": "NETWORK_PATH_BLOCKED", "display": "NETWORK PATH BLOCKED"}
    if agent_reachable is True:
        result = {"state": "LIVE", "display": "LIVE"}
        if service_healthy is False:
            result["service_state"] = "SERVICE_UNHEALTHY"
            result["service_display"] = "SERVICE DEGRADED / DEPENDENCY CHECK FAILED"
        elif service_healthy is True:
            result["service_state"] = "LIVE"
            result["service_display"] = "SERVICE HEALTHY"
        else:
            result["service_state"] = "NOT_TESTED"
            result["service_display"] = "SERVICE NOT TESTED"
        return result
    if explicit_power == "LIVE":
        return {"state": "AGENT_UNAVAILABLE", "display": "AGENT UNAVAILABLE"}
    if agent_reachable is False:
        return {
            "state": "UNKNOWN",
            "display": "POWERED_OFF_OR_NOT_AVAILABLE",
            "reason": "No trusted power-state source; network probe failed",
        }
    return {"state": "NOT_TESTED", "display": "NOT TESTED LIVE"}


def classify_global_path(host_states: dict[str, dict[str, Any]], *, common_path_failure: bool = False) -> dict[str, str]:
    """Classify the shared path only from independent evidence.

    A live Web host plus powered-off/unavailable peers is ``PASS_PARTIAL_LIVE``
    rather than ``WG_PATH_BLOCKED``.  ``NETWORK_PATH_BLOCKED`` is returned only
    when an explicit common-path signal is supplied.
    """

    if common_path_failure:
        return {"state": "NETWORK_PATH_BLOCKED", "display": "NETWORK PATH BLOCKED"}
    if any(item.get("state") == "LIVE" for item in host_states.values()):
        return {"state": "PASS_PARTIAL_LIVE", "display": "PASS_PARTIAL_LIVE"}
    if host_states and all(item.get("state") == "POWERED_OFF" for item in host_states.values()):
        return {"state": "NOT_TESTED", "display": "POWERED_OFF_HOSTS / PATH NOT TESTED"}
    return {"state": "UNKNOWN", "display": "COMMON PATH NOT CONFIRMED"}
