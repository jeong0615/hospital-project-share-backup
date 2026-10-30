import json
import sys
import tempfile
import unittest
from pathlib import Path


CHATOPS_DIR = Path(__file__).resolve().parents[1] / "operations" / "chatops"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "wazuh"
sys.path.insert(0, str(CHATOPS_DIR))

from chatops_core import create_app
from wazuh_alerts import parse_wazuh_alert, render_wazuh_alert, should_escalate_to_dr


class FakeSlackClient:
    def __init__(self):
        self.channel_id = "C_WAZUH_TEST"
        self.posts = []
        self.updates = []

    @property
    def available(self):
        return True

    def post_message(self, text, blocks):
        self.posts.append({"text": text, "blocks": blocks})
        return {"ok": True, "channel": self.channel_id, "ts": f"2000.{len(self.posts)}"}

    def update_message(self, channel_id, message_ts, text, blocks):
        self.updates.append(
            {"channel": channel_id, "ts": message_ts, "text": text, "blocks": blocks}
        )
        return {"ok": True}


def load_fixture(name):
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


class WazuhAlertFlowTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        state_db = str(Path(self.temp_dir.name) / "state.sqlite3")
        self.failover_slack = FakeSlackClient()
        self.failback_slack = FakeSlackClient()
        self.alert_slack = FakeSlackClient()
        self.app = create_app(
            default_state_db=state_db,
            default_secret_file=str(Path(self.temp_dir.name) / "missing.env"),
            default_script_root="/nonexistent/mock-only",
            test_config={
                "TESTING": True,
                "CHATOPS_STATE_DB": state_db,
                "SLACK_CLIENTS": {
                    "failover": self.failover_slack,
                    "failback": self.failback_slack,
                },
                "SLACK_ALERT_CLIENT": self.alert_slack,
                "ADMIN_USER_IDS": {"U_ADMIN_1", "U_ADMIN_2"},
                "VERIFY_SLACK_SIGNATURE": False,
                "PIPELINE_LAUNCHER": lambda request_id, action, approver: None,
            },
        )
        self.client = self.app.test_client()
        self.store = self.app.extensions["approval_store"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def post_alert(self, fixture):
        return self.client.post(
            "/wazuh/alert",
            json=load_fixture(fixture),
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )

    def test_low_and_high_ssh_alert_without_dr_escalation(self):
        low = self.post_alert("low.json")
        high = self.post_alert("high-ssh.json")

        self.assertEqual(low.status_code, 200)
        self.assertFalse(low.get_json()["dr_escalated"])
        self.assertEqual(low.get_json()["severity"], "LOW")
        self.assertFalse(high.get_json()["dr_escalated"])
        self.assertEqual(high.get_json()["severity"], "HIGH")
        self.assertEqual(len(self.alert_slack.posts), 2)
        self.assertEqual(len(self.failover_slack.posts), 0)

    def test_critical_ransomware_on_db_escalates_to_existing_failover(self):
        response = self.post_alert("critical-ransomware-db.json")

        result = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(result["alert_sent"])
        self.assertTrue(result["dr_escalated"])
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(len(self.alert_slack.posts), 1)
        self.assertEqual(len(self.failover_slack.posts), 1)
        state = self.store.get(result["request_id"])
        self.assertEqual(state["action"], "failover")
        self.assertEqual(state["incidents"][0]["source"], "wazuh")
        self.assertNotIn("internal-detail-should-not-be-forwarded", self.alert_slack.posts[0]["text"])

    def test_critical_event_without_dr_impact_stays_alert_only(self):
        response = self.post_alert("critical-workstation.json")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["dr_escalated"])
        self.assertEqual(len(self.alert_slack.posts), 1)
        self.assertEqual(len(self.failover_slack.posts), 0)

    def test_optional_fields_do_not_break_parser(self):
        alert = parse_wazuh_alert(load_fixture("optional-fields.json"))

        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.agent_name, "EMR_Server")
        self.assertEqual(alert.source_ip, "")
        self.assertFalse(should_escalate_to_dr(alert))
        text, blocks = render_wazuh_alert(alert)
        self.assertIn("CRITICAL", text)
        self.assertEqual(blocks[0]["type"], "section")

    def test_new_wazuh_incident_merges_and_keeps_existing_approver(self):
        first = self.post_alert("critical-ransomware-db.json").get_json()
        self.assertTrue(first["dr_escalated"])
        result, state = self.store.approve(first["request_id"], "failover", "U_ADMIN_1")
        self.assertEqual(result, "pending")

        second_payload = load_fixture("critical-ransomware-db.json")
        second_payload["id"] = "wazuh-event-critical-db-2"
        second_payload["rule"]["description"] = "Ransomware-like file encryption detected again"
        second = self.client.post(
            "/wazuh/alert",
            json=second_payload,
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        ).get_json()

        self.assertTrue(second["dr_escalated"])
        self.assertTrue(second["reused"])
        self.assertEqual(second["request_id"], first["request_id"])
        state = self.store.get(first["request_id"])
        self.assertEqual(state["approvers"], ["U_ADMIN_1"])
        self.assertEqual(len(state["incidents"]), 2)
        self.assertEqual(len(self.failover_slack.posts), 1)
        self.assertEqual(len(self.failover_slack.updates), 1)

    def test_wazuh_escalation_only_creates_failover_not_failback(self):
        failback = self.client.post(
            "/chatops/request",
            json={"action": "failback", "incident_id": "recovery-1"},
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        ).get_json()
        wazuh = self.post_alert("critical-ransomware-db.json").get_json()

        self.assertNotEqual(wazuh["request_id"], failback["request_id"])
        self.assertEqual(self.store.get(failback["request_id"])["action"], "failback")
        self.assertEqual(self.store.get(wazuh["request_id"])["action"], "failover")


if __name__ == "__main__":
    unittest.main()
