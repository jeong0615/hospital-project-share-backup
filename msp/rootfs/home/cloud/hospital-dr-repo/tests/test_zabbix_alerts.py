import json
import sys
import tempfile
import unittest
from pathlib import Path


CHATOPS_DIR = Path(__file__).resolve().parents[1] / "operations" / "chatops"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "zabbix"
sys.path.insert(0, str(CHATOPS_DIR))

from chatops_core import cleanup_old_slack_messages, create_app
from zabbix_alerts import parse_zabbix_alert, render_zabbix_alert


class FakeSlackClient:
    def __init__(self, channel_id):
        self.channel_id = channel_id
        self.posts = []

    @property
    def available(self):
        return True

    def post_message(self, text, blocks):
        self.posts.append({"text": text, "blocks": blocks})
        return {"ok": True, "channel": self.channel_id, "ts": f"3000.{len(self.posts)}"}

    def delete_message(self, channel_id, message_ts):
        return {"ok": True}


class ZabbixAlertFlowTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        state_db = str(Path(self.temp_dir.name) / "state.sqlite3")
        self.failover = FakeSlackClient("C_FAILOVER")
        self.failback = FakeSlackClient("C_FAILBACK")
        self.alert = FakeSlackClient("C_ALERT")
        self.app = create_app(
            default_state_db=state_db,
            default_secret_file=str(Path(self.temp_dir.name) / "missing.env"),
            default_script_root="/nonexistent/mock-only",
            test_config={
                "TESTING": True,
                "CHATOPS_STATE_DB": state_db,
                "SLACK_CLIENTS": {"failover": self.failover, "failback": self.failback},
                "SLACK_ALERT_CLIENT": self.alert,
                "ADMIN_USER_IDS": {"U_ADMIN_1", "U_ADMIN_2"},
                "VERIFY_SLACK_SIGNATURE": False,
                "PIPELINE_LAUNCHER": lambda request_id, action, approver: None,
            },
        )
        self.client = self.app.test_client()
        self.fixture = json.loads((FIXTURE_DIR / "infrastructure.json").read_text(encoding="utf-8"))

    def tearDown(self):
        self.temp_dir.cleanup()

    def post_alert(self, payload=None, remote_addr="IP_REDACTED"):
        return self.client.post(
            "/zabbix/alert",
            json=payload or self.fixture,
            environ_base={"REMOTE_ADDR": remote_addr},
        )

    def test_normal_alert_uses_alert_client_without_approval_controls(self):
        response = self.post_alert()
        result = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(result["alert_sent"])
        self.assertFalse(result["dr_escalated"])
        self.assertFalse(result["duplicate"])
        self.assertEqual(len(self.alert.posts), 1)
        self.assertEqual(len(self.failover.posts), 0)
        self.assertNotIn("actions", self.alert.posts[0]["blocks"][0])
        self.assertIn("ZABBIX INFRASTRUCTURE ALERT", self.alert.posts[0]["text"])

    def test_explicit_dr_escalation_reuses_failover_engine(self):
        payload = dict(self.fixture)
        payload["EventID"] = "zbx-event-dr-1"
        payload["DR_Escalate"] = "1"
        response = self.post_alert(payload)
        result = response.get_json()

        self.assertTrue(result["dr_escalated"])
        self.assertIsNotNone(result["request_id"])
        self.assertEqual(len(self.alert.posts), 1)
        self.assertEqual(len(self.failover.posts), 1)
        state = self.app.extensions["approval_store"].get(result["request_id"])
        self.assertEqual(state["action"], "failover")
        self.assertEqual(state["incidents"][0]["source"], "zabbix")

    def test_duplicate_event_is_not_sent_twice(self):
        first = self.post_alert().get_json()
        second = self.post_alert().get_json()

        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(len(self.alert.posts), 1)

    def test_alert_uses_existing_cleanup_registry(self):
        self.post_alert()
        result = cleanup_old_slack_messages(self.app, now=10**10)

        self.assertEqual(result["deleted"], 1)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(len(self.app.extensions["chatops_audit"].candidates(now=10**10, ttl_seconds=0)), 0)

    def test_external_zabbix_request_is_rejected(self):
        response = self.post_alert(remote_addr="IP_REDACTED")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.alert.posts), 0)

    def test_optional_fields_are_safe(self):
        alert = parse_zabbix_alert({"Host": "Web_Server", "Message": "test"})
        text, blocks = render_zabbix_alert(alert)

        self.assertEqual(alert.host, "Web_Server")
        self.assertEqual(alert.severity, "UNKNOWN")
        self.assertTrue(alert.incident_id.startswith("zabbix-"))
        self.assertIn("UNKNOWN", text)
        self.assertEqual(blocks[0]["type"], "section")


if __name__ == "__main__":
    unittest.main()
