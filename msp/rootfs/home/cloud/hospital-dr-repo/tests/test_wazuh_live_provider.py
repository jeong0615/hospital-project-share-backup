import json
import sys
import time
import unittest
from pathlib import Path


CHATOPS_DIR = Path(__file__).resolve().parents[1] / "operations" / "chatops"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "wazuh"
sys.path.insert(0, str(CHATOPS_DIR))

from wazuh_live_provider import WazuhLiveProvider, build_wazuh_provider


class FakeResponse:
    def __init__(self, payload, text="", headers=None, error=None):
        self.payload = payload
        self.text = text
        self.headers = headers or {"content-type": "application/json"}
        self.error = error

    def raise_for_status(self):
        if self.error:
            raise RuntimeError(self.error)

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, alert_payload):
        self.alert_payload = alert_payload
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return FakeResponse({"data": {"token": "<SET_IN_SECRET_STORE>"}})

    def get(self, url, **kwargs):
        self.calls.append(("get", url, kwargs))
        if url.endswith("/agents"):
            return FakeResponse(
                {
                    "data": {
                        "affected_items": [
                            {
                                "id": "001",
                                "name": "DB_Server",
                                "ip": "IP_REDACTED",
                                "status": "active",
                                "lastKeepAlive": time.time(),
                            }
                        ]
                    }
                }
            )
        return FakeResponse({"hits": {"hits": [{"_source": self.alert_payload}]}})


class WazuhLiveProviderTest(unittest.TestCase):
    def setUp(self):
        payload = json.loads((FIXTURE_DIR / "critical-ransomware-db.json").read_text(encoding="utf-8"))
        self.session = FakeSession(payload)
        self.provider = WazuhLiveProvider(
            api_url="https://IP_REDACTED:55000",
            api_user="readonly-api",
            api_password="runtime-api-password",
            indexer_url="https://IP_REDACTED:9200",
            indexer_user="readonly-indexer",
            indexer_password="runtime-indexer-password",
            ca_cert="/tmp/wazuh-root-ca.pem",
            session=self.session,
        )

    def test_snapshot_reads_agents_and_recent_alerts(self):
        snapshot = self.provider.snapshot()

        self.assertTrue(snapshot["query_ok"])
        self.assertEqual(snapshot["agents"][0]["name"], "DB_Server")
        self.assertEqual(snapshot["incidents"][0]["status"], "active")
        self.assertEqual(snapshot["incidents"][0]["severity"], "CRITICAL")
        self.assertNotIn("internal-detail-should-not-be-forwarded", snapshot["incidents"][0])
        self.assertEqual(self.session.calls[0][2]["verify"], "/tmp/wazuh-root-ca.pem")

    def test_api_or_indexer_failure_returns_unknown_input(self):
        failing = FakeSession({})
        failing.post = lambda url, **kwargs: FakeResponse({}, error="unavailable")
        provider = WazuhLiveProvider(
            "https://api",
            "user",
            "password",
            "https://indexer",
            "user",
            "password",
            session=failing,
        )

        self.assertEqual(provider.snapshot(), {"query_ok": False, "agents": [], "incidents": []})

    def test_resolved_event_status_is_preserved(self):
        self.session.alert_payload["status"] = "resolved"
        self.session.alert_payload["resolved"] = True

        snapshot = self.provider.snapshot()

        self.assertEqual(snapshot["incidents"][0]["status"], "resolved")
        self.assertTrue(snapshot["incidents"][0]["resolved"])

    def test_builder_requires_all_runtime_credentials(self):
        self.assertIsNone(build_wazuh_provider({"WAZUH_API_URL": "https://api"}))
        provider = build_wazuh_provider(
            {
                "WAZUH_API_URL": "https://api",
                "WAZUH_API_USER": "api-user",
                "WAZUH_API_PASSWORD": "api-password",
                "WAZUH_INDEXER_URL": "https://indexer",
                "WAZUH_INDEXER_USER": "indexer-user",
                "WAZUH_INDEXER_PASSWORD": "indexer-password",
            }
        )
        self.assertIsNotNone(provider)


if __name__ == "__main__":
    unittest.main()
