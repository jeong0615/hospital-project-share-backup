"""Read-only Wazuh API and Indexer provider for Failback security checks."""

import requests

from wazuh_alerts import parse_wazuh_alert


class WazuhLiveProvider:
    def __init__(
        self,
        api_url,
        api_user,
        api_password,
        indexer_url,
        indexer_user,
        indexer_password,
        ca_cert=True,
        lookback_minutes=15,
        timeout=10,
        session=None,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_user = api_user
        self.api_password = api_password
        self.indexer_url = indexer_url.rstrip("/")
        self.indexer_user = indexer_user
        self.indexer_password = indexer_password
        self.ca_cert = ca_cert if ca_cert is not None else True
        self.lookback_minutes = int(lookback_minutes)
        self.timeout = timeout
        self.session = session or requests.Session()

    def _api_token(self):
        response = self.session.post(
            f"{self.api_url}/security/user/authenticate?raw=true",
            auth=(self.api_user, self.api_password),
            verify=self.ca_cert,
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json() if "application/json" in response.headers.get("content-type", "") else None
        if isinstance(data, dict):
            token = (data.get("data") or {}).get("token") or data.get("token")
        else:
            token = response.text.strip()
        if not token:
            raise RuntimeError("Wazuh API authentication returned no token")
        return token

    def _agents(self, token):
        response = self.session.get(
            f"{self.api_url}/agents",
            params={"select": "id,name,ip,status,lastKeepAlive"},
            headers={"Authorization": f"Bearer {token}"},
            verify=self.ca_cert,
            timeout=self.timeout,
        )
        response.raise_for_status()
        items = (response.json().get("data") or {}).get("affected_items") or []
        agents = []
        for item in items:
            if not isinstance(item, dict):
                continue
            agents.append(
                {
                    "id": item.get("id", ""),
                    "name": item.get("name", ""),
                    "ip": item.get("ip", ""),
                    "status": item.get("status", ""),
                    "last_seen": item.get("lastKeepAlive", item.get("last_seen")),
                }
            )
        return agents

    def _alerts(self):
        response = self.session.get(
            f"{self.indexer_url}/wazuh-alerts-*/_search",
            auth=(self.indexer_user, self.indexer_password),
            params={"size": 100},
            json={
                "query": {
                    "range": {
                        "timestamp": {"gte": f"now-{self.lookback_minutes}m"}
                    }
                },
                "sort": [{"timestamp": {"order": "desc"}}],
            },
            verify=self.ca_cert,
            timeout=self.timeout,
        )
        response.raise_for_status()
        hit_data = response.json().get("hits")
        if not isinstance(hit_data, dict):
            raise RuntimeError("Wazuh Indexer response is incomplete")
        hits = hit_data.get("hits")
        if not isinstance(hits, list):
            raise RuntimeError("Wazuh Indexer event results are incomplete")
        total = hit_data.get("total")
        if isinstance(total, dict):
            total_count = total.get("value")
            relation = total.get("relation", "eq")
        else:
            total_count = total
            relation = "eq"
        if (
            isinstance(total_count, bool)
            or not isinstance(total_count, int)
            or relation != "eq"
            or total_count > len(hits)
        ):
            raise RuntimeError("Wazuh Indexer event results are incomplete")
        incidents = []
        for hit in hits:
            payload = hit.get("_source") if isinstance(hit, dict) else None
            if not isinstance(payload, dict):
                raise RuntimeError("Wazuh Indexer event result is incomplete")
            alert = parse_wazuh_alert(payload)
            incident = alert.incident()
            event_data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            resolved = payload.get("resolved", event_data.get("resolved"))
            status = payload.get("status", event_data.get("status"))
            if status is None:
                status = "resolved" if resolved is True else "active"
            incident.update(
                {
                    "status": status,
                    "agent_id": alert.agent_id,
                    "agent_name": alert.agent_name,
                    "description": alert.rule_description,
                    "groups": list(alert.groups),
                    "level": alert.rule_level,
                }
            )
            if resolved is not None:
                incident["resolved"] = resolved
            # Only recent security events are exposed to the gate. The gate's
            # destructive/important-host policy remains the single decision point.
            incidents.append(incident)
        return incidents

    def snapshot(self):
        try:
            token = self._api_token()
            return {
                "query_ok": True,
                "agents": self._agents(token),
                "incidents": self._alerts(),
                "lookback_minutes": self.lookback_minutes,
            }
        except Exception:
            return {"query_ok": False, "agents": [], "incidents": []}


def build_wazuh_provider(values):
    """Build a provider only when all read-only credentials are configured."""
    required = (
        "WAZUH_API_URL",
        "WAZUH_API_USER",
        "WAZUH_API_PASSWORD",
        "WAZUH_INDEXER_URL",
        "WAZUH_INDEXER_USER",
        "WAZUH_INDEXER_PASSWORD",
    )
    if any(not values.get(key) for key in required):
        return None
    return WazuhLiveProvider(
        api_url=values["WAZUH_API_URL"],
        api_user=values["WAZUH_API_USER"],
        api_password=values["WAZUH_API_PASSWORD"],
        indexer_url=values["WAZUH_INDEXER_URL"],
        indexer_user=values["WAZUH_INDEXER_USER"],
        indexer_password=values["WAZUH_INDEXER_PASSWORD"],
        ca_cert=values.get("WAZUH_CA_CERT") or True,
        lookback_minutes=values.get("WAZUH_SECURITY_LOOKBACK_MINUTES", 15),
    )
