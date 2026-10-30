import hashlib
import hmac
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode


CHATOPS_DIR = Path(__file__).resolve().parents[1] / "operations" / "chatops"
sys.path.insert(0, str(CHATOPS_DIR))

from chatops_core import (
    ApprovalStore,
    button_value,
    create_app,
    expire_pending_requests,
    SlackApiError,
    valid_slack_signature,
)


class FakeSlackClient:
    def __init__(self):
        self.channel_id = "C_TEST"
        self.posts = []
        self.updates = []
        self.fail_updates = False

    @property
    def available(self):
        return True

    def post_message(self, text, blocks):
        self.posts.append({"text": text, "blocks": blocks})
        return {"ok": True, "channel": self.channel_id, "ts": f"1000.{len(self.posts)}"}

    def update_message(self, channel_id, message_ts, text, blocks):
        if self.fail_updates:
            raise SlackApiError("chat.update", "cant_update_message")
        self.updates.append(
            {"channel": channel_id, "ts": message_ts, "text": text, "blocks": blocks}
        )
        return {"ok": True}


def has_actions(blocks):
    return any(block.get("type") == "actions" for block in blocks)


def action_styles(blocks):
    for block in blocks:
        if block.get("type") == "actions":
            return [element.get("style") for element in block.get("elements", [])]
    return []


class ChatOpsApprovalFlowTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.fake_slack = FakeSlackClient()
        self.executions = []
        state_db = str(Path(self.temp_dir.name) / "state.sqlite3")
        self.app = create_app(
            default_state_db=state_db,
            default_secret_file=str(Path(self.temp_dir.name) / "missing.env"),
            default_script_root="/nonexistent/mock-only",
            test_config={
                "TESTING": True,
                "CHATOPS_STATE_DB": state_db,
                "SLACK_CLIENT": self.fake_slack,
                "ADMIN_USER_IDS": {"U_ADMIN_1", "U_ADMIN_2", "U_ADMIN_3"},
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

    def create_request(self, action, incident_id):
        response = self.client.post(
            "/chatops/request",
            json={"action": action, "incident_id": incident_id, "summary": incident_id},
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def interact(self, request_id, action, operation, user_id):
        payload = {
            "actions": [{"value": button_value(request_id, action, operation)}],
            "user": {"id": user_id},
            "channel": {"id": "C_TEST"},
            "container": {"message_ts": "1000.1", "channel_id": "C_TEST"},
            "response_url": "https://example.invalid/mock-response",
        }
        return self.client.post("/slack/action", data={"payload": json.dumps(payload)})

    def test_two_person_approval_duplicate_and_incident_merge(self):
        created = self.create_request("failover", "incident-1")
        request_id = created["request_id"]
        self.assertFalse(created["reused"])
        self.assertEqual(len(self.fake_slack.posts), 1)
        self.assertEqual(action_styles(self.fake_slack.posts[0]["blocks"]), ["primary", "danger"])
        initial_text = self.fake_slack.posts[0]["blocks"][0]["text"]["text"]
        self.assertIn("🚨 [CRITICAL] On-Premise Network Failure Detected", initial_text)
        self.assertIn("온프레미스 네트워크 장애가 감지되었습니다.", initial_text)
        self.assertIn("Cloud DR 환경으로 Failover를 진행하시겠습니까?", initial_text)
        self.assertIn("승인 상태: *0/2*", initial_text)
        self.assertEqual(
            [item["action_id"] for item in self.fake_slack.posts[0]["blocks"][-1]["elements"]],
            ["hospital_dr_approve", "hospital_dr_cancel"],
        )

        response = self.interact(request_id, "failover", "approve", "U_ADMIN_1")
        self.assertEqual(response.status_code, 200)
        state = self.store.get(request_id)
        self.assertEqual(state["status"], "PARTIALLY_APPROVED")
        self.assertEqual(state["approvers"], ["U_ADMIN_1"])
        self.assertAlmostEqual(state["expires_at"] - state["first_approved_at"], 3600, delta=1)
        self.assertIn("승인 상태: *1/2*", self.fake_slack.updates[-1]["blocks"][0]["text"]["text"])
        self.assertEqual(action_styles(self.fake_slack.updates[-1]["blocks"]), ["primary", "danger"])
        reloaded_store = ApprovalStore(self.app.config["CHATOPS_STATE_DB"])
        self.assertEqual(reloaded_store.get(request_id)["approvers"], ["U_ADMIN_1"])

        duplicate = self.interact(request_id, "failover", "approve", "U_ADMIN_1")
        self.assertIn("이미 승인된 요청입니다", duplicate.get_json()["text"])
        self.assertEqual(self.store.get(request_id)["approvers"], ["U_ADMIN_1"])

        merged = self.create_request("failover", "incident-2")
        self.assertTrue(merged["reused"])
        self.assertEqual(merged["request_id"], request_id)
        state = self.store.get(request_id)
        self.assertEqual(state["approvers"], ["U_ADMIN_1"])
        self.assertEqual(len(state["incidents"]), 2)
        self.assertEqual(len(self.fake_slack.posts), 1)

        approved = self.interact(request_id, "failover", "approve", "U_ADMIN_2")
        self.assertEqual(approved.status_code, 200)
        state = self.store.get(request_id)
        self.assertEqual(state["status"], "EXECUTING")
        self.assertEqual(state["approvers"], ["U_ADMIN_1", "U_ADMIN_2"])
        self.assertEqual(self.executions, [(request_id, "failover", "U_ADMIN_2")])
        self.assertFalse(has_actions(self.fake_slack.updates[-1]["blocks"]))
        self.assertIn("승인 상태: *2/2*", self.fake_slack.updates[-1]["blocks"][0]["text"]["text"])
        self.assertIn("상태: *실행 중*", self.fake_slack.updates[-1]["blocks"][0]["text"]["text"])

        cancel = self.interact(request_id, "failover", "cancel", "U_ADMIN_3")
        self.assertIn("실행 중인 요청은 취소", cancel.get_json()["text"])
        self.assertEqual(self.store.get(request_id)["status"], "EXECUTING")

    def test_stale_message_is_replaced_without_losing_request_state(self):
        created = self.create_request("failback", "stale-message-1")
        request_id = created["request_id"]
        self.fake_slack.fail_updates = True

        merged = self.create_request("failback", "stale-message-2")
        self.assertTrue(merged["reused"])
        self.assertEqual(merged["request_id"], request_id)
        self.assertEqual(len(self.fake_slack.posts), 2)
        state = self.store.get(request_id)
        self.assertEqual(state["status"], "PENDING")
        self.assertEqual(state["slack_message_ts"], "1000.2")

    def test_single_admin_cancel_discards_approvals_and_new_request_is_fresh(self):
        created = self.create_request("failback", "recovery-1")
        request_id = created["request_id"]
        initial_text = self.fake_slack.posts[-1]["blocks"][0]["text"]["text"]
        self.assertIn("🔄 [RECOVERY] On-Premise Service Recovery Confirmed", initial_text)
        self.assertIn("온프레미스 서비스 복구가 확인되었습니다.", initial_text)
        self.assertIn("Cloud DR 환경에서 On-Premise 환경으로 Failback을 진행하시겠습니까?", initial_text)
        self.assertIn("승인 상태: *0/2*", initial_text)
        self.interact(request_id, "failback", "approve", "U_ADMIN_1")
        cancelled = self.interact(request_id, "failback", "cancel", "U_ADMIN_2")
        self.assertEqual(cancelled.status_code, 200)
        state = self.store.get(request_id)
        self.assertEqual(state["status"], "CANCELLED")
        self.assertEqual(state["approvers"], [])
        self.assertFalse(has_actions(self.fake_slack.updates[-1]["blocks"]))

        replacement = self.create_request("failback", "recovery-2")
        self.assertNotEqual(replacement["request_id"], request_id)
        self.assertEqual(self.store.get(replacement["request_id"])["approvers"], [])

    def test_failover_and_failback_approvals_are_independent(self):
        failover = self.create_request("failover", "incident-a")
        failback = self.create_request("failback", "incident-b")
        self.interact(failover["request_id"], "failover", "approve", "U_ADMIN_1")
        self.assertEqual(self.store.get(failover["request_id"])["approvers"], ["U_ADMIN_1"])
        self.assertEqual(self.store.get(failback["request_id"])["approvers"], [])

    def test_failover_and_failback_use_separate_clients_and_signing_secrets(self):
        failover_slack = FakeSlackClient()
        failback_slack = FakeSlackClient()
        state_db = str(Path(self.temp_dir.name) / "separate-apps.sqlite3")
        app = create_app(
            default_state_db=state_db,
            default_secret_file=str(Path(self.temp_dir.name) / "missing.env"),
            default_script_root="/nonexistent/mock-only",
            test_config={
                "TESTING": True,
                "CHATOPS_STATE_DB": state_db,
                "SLACK_CLIENTS": {"failover": failover_slack, "failback": failback_slack},
                "SLACK_SIGNING_SECRETS": {
                    "failover": "failover-signing-secret",
                    "failback": "failback-signing-secret",
                },
                "ADMIN_USER_IDS": {"U_ADMIN_1", "U_ADMIN_2"},
                "VERIFY_SLACK_SIGNATURE": True,
                "PIPELINE_LAUNCHER": lambda request_id, action, approver: None,
            },
        )
        client = app.test_client()

        failover_response = client.post(
            "/chatops/request",
            json={"action": "failover", "incident_id": "separate-failover"},
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        failback_response = client.post(
            "/chatops/request",
            json={"action": "failback", "incident_id": "separate-failback"},
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        self.assertEqual(failover_response.status_code, 200)
        self.assertEqual(failback_response.status_code, 200)
        self.assertEqual(len(failover_slack.posts), 1)
        self.assertEqual(len(failback_slack.posts), 1)

        failover_id = failover_response.get_json()["request_id"]
        payload = {
            "actions": [{"value": button_value(failover_id, "failover", "approve")}],
            "user": {"id": "U_ADMIN_1"},
            "channel": {"id": "C_TEST"},
            "container": {"message_ts": "1000.1", "channel_id": "C_TEST"},
        }
        body = urlencode({"payload": json.dumps(payload, separators=(",", ":"))}).encode()

        def signed(secret):
            timestamp = str(int(time.time()))
            base = b"v0:" + timestamp.encode("ascii") + b":" + body
            signature = "v0=" + hmac.new(
                secret.encode(), base, hashlib.sha256
            ).hexdigest()
            return timestamp, signature

        wrong_timestamp, wrong_signature = signed("failback-signing-secret")
        wrong = client.post(
            "/slack/failover/action",
            data=body,
            content_type="application/x-www-form-urlencoded",
            headers={
                "X-Slack-Request-Timestamp": wrong_timestamp,
                "X-Slack-Signature": wrong_signature,
            },
        )
        self.assertEqual(wrong.status_code, 401)

        timestamp, signature = signed("failover-signing-secret")
        correct = client.post(
            "/slack/failover/action",
            data=body,
            content_type="application/x-www-form-urlencoded",
            headers={
                "X-Slack-Request-Timestamp": timestamp,
                "X-Slack-Signature": signature,
            },
        )
        self.assertEqual(correct.status_code, 200)

    def test_one_registered_admin_can_validate_one_of_two_without_execution(self):
        fake_slack = FakeSlackClient()
        state_db = str(Path(self.temp_dir.name) / "single-admin.sqlite3")
        app = create_app(
            default_state_db=state_db,
            default_secret_file=str(Path(self.temp_dir.name) / "missing.env"),
            default_script_root="/nonexistent/mock-only",
            test_config={
                "TESTING": True,
                "CHATOPS_STATE_DB": state_db,
                "SLACK_CLIENT": fake_slack,
                "ADMIN_USER_IDS": {"U_ADMIN_1"},
                "VERIFY_SLACK_SIGNATURE": False,
                "PIPELINE_LAUNCHER": lambda request_id, action, approver: self.fail(
                    "one administrator must not execute the workflow"
                ),
            },
        )
        client = app.test_client()
        response = client.post(
            "/chatops/request",
            json={"action": "failover", "incident_id": "single-admin"},
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        self.assertEqual(response.status_code, 200)
        request_id = response.get_json()["request_id"]
        payload = {
            "actions": [{"value": button_value(request_id, "failover", "approve")}],
            "user": {"id": "U_ADMIN_1"},
            "channel": {"id": "C_TEST"},
            "container": {"message_ts": "1000.1", "channel_id": "C_TEST"},
        }
        first = client.post("/slack/action", data={"payload": json.dumps(payload)})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(app.extensions["approval_store"].get(request_id)["status"], "PARTIALLY_APPROVED")

    def test_expiry_windows_and_message_cleanup(self):
        store = ApprovalStore(
            str(Path(self.temp_dir.name) / "expiry.sqlite3"), initial_ttl=1200, approved_ttl=3600
        )
        store.create_or_merge("failover", {"incident_id": "i1", "summary": "i1"}, now=1000)
        self.assertEqual(store.expire_due(now=2199), [])
        expired = store.expire_due(now=2200)
        self.assertEqual(expired[0]["status"], "EXPIRED")

        partial, _ = store.create_or_merge(
            "failover", {"incident_id": "i2", "summary": "i2"}, now=3000
        )
        result, partial = store.approve(partial["request_id"], "failover", "U_ADMIN_1", now=3010)
        self.assertEqual(result, "pending")
        self.assertEqual(partial["expires_at"], 6610)
        self.assertEqual(store.expire_due(now=6609), [])
        self.assertEqual(store.expire_due(now=6610)[0]["status"], "EXPIRED")

        app_state = self.create_request("failover", "incident-expire")
        request_state = self.store.get(app_state["request_id"])
        expired_messages = expire_pending_requests(self.app, now=request_state["expires_at"])
        self.assertEqual(len(expired_messages), 1)
        self.assertEqual(self.store.get(app_state["request_id"])["status"], "EXPIRED")
        self.assertFalse(has_actions(self.fake_slack.updates[-1]["blocks"]))

    def test_slack_signature_and_replay_window(self):
        import hashlib
        import hmac

        secret = "<SET_IN_SECRET_STORE>"
        body = b"payload=%7B%7D"
        timestamp = "10000"
        base = b"v0:" + timestamp.encode("ascii") + b":" + body
        signature = "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
        self.assertTrue(valid_slack_signature(secret, body, timestamp, signature, now=10010))
        self.assertFalse(valid_slack_signature(secret, body, timestamp, signature, now=10301))


if __name__ == "__main__":
    unittest.main()
