import json
import sys
import tempfile
import time
import unittest
from pathlib import Path


CHATOPS_DIR = Path(__file__).resolve().parents[1] / "operations" / "chatops"
sys.path.insert(0, str(CHATOPS_DIR))

from chatops_core import button_value, create_app
from wazuh_failback_gate import BLOCKED, READY, UNKNOWN, evaluate_failback_security


class FakeSlackClient:
    def __init__(self):
        self.channel_id = "C_GATE_TEST"
        self.posts = []
        self.updates = []

    @property
    def available(self):
        return True

    def post_message(self, text, blocks):
        self.posts.append({"text": text, "blocks": blocks})
        return {"ok": True, "channel": self.channel_id, "ts": f"3000.{len(self.posts)}"}

    def update_message(self, channel_id, message_ts, text, blocks):
        self.updates.append({"channel": channel_id, "ts": message_ts, "text": text, "blocks": blocks})
        return {"ok": True}


def healthy_snapshot():
    last_seen = time.time()
    return {
        "query_ok": True,
        "agents": [
            {"id": "001", "name": "DB_Server", "status": "active", "last_seen": last_seen},
            {"id": "002", "name": "Web_Server", "status": "active", "last_seen": last_seen},
            {"id": "003", "name": "EMR_Server", "status": "active", "last_seen": last_seen},
        ],
        "incidents": [],
    }


def blocked_snapshot():
    snapshot = healthy_snapshot()
    snapshot["incidents"] = [
        {
            "id": "security-incident-1",
            "severity": "CRITICAL",
            "status": "active",
            "category": "ransomware",
            "agent_name": "DB_Server",
        }
    ]
    return snapshot


class FailbackSecurityGateTest(unittest.TestCase):
    def test_ready_blocked_and_unknown_decisions(self):
        required = ("DB_Server", "Web_Server", "EMR_Server")
        self.assertEqual(evaluate_failback_security(healthy_snapshot(), required), {"status": READY, "reason": "No unresolved destructive Critical incident was found.", "agents": "OK", "critical_incident": "None"})
        self.assertEqual(evaluate_failback_security(blocked_snapshot(), required)["status"], BLOCKED)
        offline = healthy_snapshot()
        offline["agents"][0]["status"] = "offline"
        self.assertEqual(evaluate_failback_security(offline, required)["status"], UNKNOWN)
        self.assertEqual(evaluate_failback_security({"query_ok": False}, required)["status"], UNKNOWN)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        state_db = str(Path(self.temp_dir.name) / "state.sqlite3")
        self.failover_slack = FakeSlackClient()
        self.failback_slack = FakeSlackClient()
        self.executions = []
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
                "ADMIN_USER_IDS": {"U_ADMIN_1", "U_ADMIN_2"},
                "WAZUH_FAILBACK_REQUIRED_AGENTS": ("DB_Server", "Web_Server", "EMR_Server"),
                "WAZUH_FAILBACK_SECURITY_SNAPSHOT": healthy_snapshot(),
                "VERIFY_SLACK_SIGNATURE": False,
                "PIPELINE_LAUNCHER": lambda request_id, action, approver: self.executions.append(
                    (request_id, action, approver)
                ),
            },
        )
        self.client = self.app.test_client()
        self.store = self.app.extensions["approval_store"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_failback(self):
        response = self.client.post(
            "/chatops/request",
            json={"action": "failback", "incident_id": "recovery-1", "summary": "On-Prem recovery"},
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["request_id"]

    def interact(self, request_id, operation, user_id):
        payload = {
            "actions": [{"value": button_value(request_id, "failback", operation)}],
            "user": {"id": user_id},
            "channel": {"id": "C_GATE_TEST"},
            "container": {"message_ts": "3000.1", "channel_id": "C_GATE_TEST"},
        }
        return self.client.post("/slack/failback/action", data={"payload": json.dumps(payload)})

    def test_blocked_gate_removes_partial_approval_and_never_executes(self):
        request_id = self.create_failback()
        self.interact(request_id, "approve", "U_ADMIN_1")
        self.assertEqual(self.store.get(request_id)["approvers"], ["U_ADMIN_1"])

        self.app.config["WAZUH_FAILBACK_SECURITY_SNAPSHOT"] = blocked_snapshot()
        response = self.interact(request_id, "approve", "U_ADMIN_2")

        self.assertEqual(response.status_code, 200)
        self.assertIn("BLOCKED", response.get_json()["text"])
        state = self.store.get(request_id)
        self.assertEqual(state["status"], "PENDING")
        self.assertEqual(state["approvers"], [])
        self.assertEqual(self.executions, [])

    def test_unknown_gate_has_no_approve_button_and_ready_still_requires_two(self):
        self.app.config["WAZUH_FAILBACK_SECURITY_SNAPSHOT"] = {"query_ok": False}
        blocked_request = self.create_failback()
        actions = self.failback_slack.posts[-1]["blocks"][-1]["elements"]
        self.assertEqual([item["action_id"] for item in actions], ["hospital_dr_cancel"])

        self.app.config["WAZUH_FAILBACK_SECURITY_SNAPSHOT"] = healthy_snapshot()
        # A new request merges into the active one and refreshes the security gate.
        self.client.post(
            "/chatops/request",
            json={"action": "failback", "incident_id": "recovery-2"},
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        self.interact(blocked_request, "approve", "U_ADMIN_1")
        self.assertEqual(self.store.get(blocked_request)["status"], "PARTIALLY_APPROVED")
        self.assertEqual(self.executions, [])

        self.interact(blocked_request, "approve", "U_ADMIN_2")
        self.assertEqual(self.store.get(blocked_request)["status"], "EXECUTING")
        self.assertEqual(self.executions[0][1], "failback")

    def test_failover_is_not_gated_by_failback_security_state(self):
        self.app.config["WAZUH_FAILBACK_SECURITY_SNAPSHOT"] = blocked_snapshot()
        response = self.client.post(
            "/chatops/request",
            json={"action": "failover", "incident_id": "incident-1"},
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.store.get(response.get_json()["request_id"])["action"], "failover")


if __name__ == "__main__":
    unittest.main()
