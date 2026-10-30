import json
import sys
import tempfile
import unittest
from pathlib import Path


CHATOPS_DIR = Path(__file__).resolve().parents[1] / "operations" / "chatops"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "wazuh"
sys.path.insert(0, str(CHATOPS_DIR))

from chatops_core import SlackApiError, cleanup_old_slack_messages, create_app


class CleanupSlackClient:
    def __init__(self, channel_id="C_CLEANUP"):
        self.channel_id = channel_id
        self.posts = []
        self.updates = []
        self.deletes = []
        self.fail_delete = False

    @property
    def available(self):
        return True

    def post_message(self, text, blocks):
        result = {"ok": True, "channel": self.channel_id, "ts": f"3000.{len(self.posts) + 1}"}
        self.posts.append(result)
        return result

    def update_message(self, channel_id, message_ts, text, blocks):
        self.updates.append({"channel": channel_id, "ts": message_ts})
        return {"ok": True}

    def delete_message(self, channel_id, message_ts):
        if self.fail_delete:
            raise SlackApiError("chat.delete", "ratelimited")
        self.deletes.append({"channel": channel_id, "ts": message_ts})
        return {"ok": True}


class ChatOpsCleanupTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_db = str(Path(self.temp_dir.name) / "state.sqlite3")
        self.failover = CleanupSlackClient()
        self.failback = CleanupSlackClient("C_FAILBACK")
        self.alert = CleanupSlackClient("C_ALERT")
        self.app = create_app(
            default_state_db=self.state_db,
            default_secret_file=str(Path(self.temp_dir.name) / "missing.env"),
            default_script_root="/nonexistent/mock-only",
            test_config={
                "TESTING": True,
                "CHATOPS_STATE_DB": self.state_db,
                "CHATOPS_AUDIT_FILE": str(Path(self.temp_dir.name) / "audit" / "chatops_audit.jsonl"),
                "CHATOPS_SLACK_CLEANUP_TTL_SECONDS": 0,
                "SLACK_CLIENTS": {"failover": self.failover, "failback": self.failback},
                "SLACK_ALERT_CLIENT": self.alert,
                "ADMIN_USER_IDS": {"U_ADMIN_1", "U_ADMIN_2"},
                "VERIFY_SLACK_SIGNATURE": False,
                "PIPELINE_LAUNCHER": lambda request_id, action, approver: None,
            },
        )
        self.http = self.app.test_client()
        self.store = self.app.extensions["approval_store"]
        self.audit = self.app.extensions["chatops_audit"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_request(self, action="failover", incident_id="cleanup-request"):
        response = self.http.post(
            "/chatops/request",
            json={"action": action, "incident_id": incident_id, "summary": incident_id},
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        self.assertEqual(response.status_code, 200)
        return self.store.get(response.get_json()["request_id"])

    def audit_records(self):
        path = Path(self.app.config["CHATOPS_AUDIT_FILE"])
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    def test_terminal_request_is_audited_then_deleted_once(self):
        state = self.create_request()
        state = self.store.finish(state["request_id"], succeeded=True)

        result = cleanup_old_slack_messages(self.app, now=state["created_at"] + 1)
        self.assertEqual(result["deleted"], 1)
        self.assertEqual(len(self.failover.deletes), 1)
        records = self.audit_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["request_id"], state["request_id"])
        self.assertEqual(records[0]["status"], "SUCCEEDED")
        self.assertEqual(records[0]["delete_result"], "deleted")
        self.assertNotIn("password", json.dumps(records[0]).lower())

        duplicate = cleanup_old_slack_messages(self.app, now=state["created_at"] + 2)
        self.assertEqual(duplicate["deleted"], 0)
        self.assertEqual(len(self.failover.deletes), 1)
        self.assertEqual(len(self.audit_records()), 1)

    def test_active_requests_are_protected(self):
        states = []
        for request_id, status, approvers in (
            ("pending-request", "PENDING", []),
            ("partial-request", "PARTIALLY_APPROVED", ["U_ADMIN_1"]),
            ("executing-request", "EXECUTING", ["U_ADMIN_1", "U_ADMIN_2"]),
        ):
            with self.store._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO approval_requests (
                        request_id, action, status, incidents, approvers,
                        created_at, first_approved_at, expires_at, slack_channel_id,
                        slack_message_ts, finished_at, cancelled_by, result
                    ) VALUES (?, 'failover', ?, ?, ?, 100, NULL, 999999, 'C_CLEANUP', ?, NULL, NULL, NULL)
                    """,
                    (
                        request_id,
                        status,
                        json.dumps([{"incident_id": request_id, "summary": request_id}]),
                        json.dumps(approvers),
                        f"5000.{len(states) + 1}",
                    ),
                )
            state = self.store.get(request_id)
            self.audit.register_request_message(state)
            states.append(state)

        result = cleanup_old_slack_messages(self.app, now=101)
        self.assertEqual(result["candidates"], 0)
        self.assertEqual(self.failover.deletes, [])
        self.assertEqual(self.store.get(states[0]["request_id"])["status"], "PENDING")
        self.assertEqual(self.store.get(states[1]["request_id"])["status"], "PARTIALLY_APPROVED")
        self.assertEqual(self.store.get(states[2]["request_id"])["status"], "EXECUTING")

    def test_cancelled_and_expired_requests_are_cleaned(self):
        cancelled = self.create_request(incident_id="cancelled")
        result, cancelled = self.store.cancel(
            cancelled["request_id"], "failover", cancelled_by="U_ADMIN_1"
        )
        self.assertEqual(result, "cancelled")
        self.assertEqual(cancelled["cancelled_by"], "U_ADMIN_1")

        expired, _ = self.store.create_or_merge(
            "failback", {"incident_id": "expired", "summary": "expired"}, now=100
        )
        self.store.attach_slack_message(expired["request_id"], "C_FAILBACK", "4000.1")
        self.audit.register_request_message(self.store.get(expired["request_id"]))
        expired = self.store.expire_due(now=1300)[0]

        result = cleanup_old_slack_messages(self.app, now=10**10)
        self.assertEqual(result["deleted"], 2)
        records = {record["request_id"]: record for record in self.audit_records()}
        self.assertEqual(records[cancelled["request_id"]]["status"], "CANCELLED")
        self.assertEqual(records[cancelled["request_id"]]["cancelled_by"], "U_ADMIN_1")
        self.assertEqual(records[expired["request_id"]]["status"], "EXPIRED")

    def test_delete_failure_is_fail_open_and_audit_is_not_duplicated(self):
        state = self.create_request()
        state = self.store.finish(state["request_id"], succeeded=False)
        self.failover.fail_delete = True

        failed = cleanup_old_slack_messages(self.app, now=state["created_at"] + 1)
        self.assertEqual(failed["failed"], 1)
        self.assertEqual(len(self.audit_records()), 1)
        self.assertEqual(self.store.get(state["request_id"])["status"], "FAILED")

        self.failover.fail_delete = False
        retried = cleanup_old_slack_messages(self.app, now=state["created_at"] + 2)
        self.assertEqual(retried["deleted"], 1)
        self.assertEqual(len(self.audit_records()), 1)

    def test_alert_is_tracked_separately_from_approval_requests(self):
        fixture = json.loads((FIXTURE_DIR / "low.json").read_text(encoding="utf-8"))
        response = self.http.post(
            "/wazuh/alert", json=fixture, environ_base={"REMOTE_ADDR": "IP_REDACTED"}
        )
        self.assertEqual(response.status_code, 200)
        result = cleanup_old_slack_messages(self.app, now=10**10)
        self.assertEqual(result["deleted"], 1)
        self.assertEqual(len(self.alert.deletes), 1)
        record = self.audit_records()[0]
        self.assertEqual(record["kind"], "alert")
        self.assertEqual(record["source"], "wazuh")
        self.assertFalse(record["dr_escalated"])
        self.assertNotIn("internal-detail-should-not-be-forwarded", json.dumps(record))


if __name__ == "__main__":
    unittest.main()
