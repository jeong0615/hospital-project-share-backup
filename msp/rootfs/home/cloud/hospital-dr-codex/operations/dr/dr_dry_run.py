#!/usr/bin/env python3
"""Run a no-Slack, no-AWS DR approval and RTO contract dry-run.

This exercises the real ChatOps request/approval construction with in-memory
Slack clients.  It intentionally does not call Zabbix, Slack, AWS, DNS, or a
workflow executor.  The separate controlled Zabbix runner remains the test
for the live Zabbix Action path.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHATOPS_DIR = ROOT / "operations" / "chatops"
DB_DIR = ROOT / "operations" / "db"
ZABBIX_DIR = ROOT / "operations" / "zabbix"
ZABBIX_DRY_RUN_HMAC_KEY = "dry-run-only-zabbix-action-key-32-bytes-minimum"
sys.path.insert(0, str(CHATOPS_DIR))
sys.path.insert(0, str(ZABBIX_DIR))

from chatops_core import create_app  # noqa: E402
from production_dr_policy import evaluate_failover_policy  # noqa: E402
from rto_timeline import metric_values, synthetic_run  # noqa: E402


class DryRunSlackClient:
    def __init__(self, channel_id: str):
        self.channel_id = channel_id
        self.posts: list[dict[str, object]] = []

    @property
    def available(self) -> bool:
        return True

    def post_message(self, text, blocks):
        self.posts.append({"text": text, "blocks": blocks})
        return {"ok": True, "channel": self.channel_id, "ts": f"dry-run.{len(self.posts)}"}

    def update_message(self, channel_id, message_ts, text, blocks):
        return {"ok": True, "channel": channel_id, "ts": message_ts}

    def delete_message(self, channel_id, message_ts):
        return {"ok": True}


def _stability_contract_passes() -> bool:
    helper = DB_DIR / "failback_stability.sh"
    command = (
        f"source {helper!s}; "
        "failback_stability_validate_config 300 2 && "
        "! failback_stability_is_satisfied 100 399 300 && "
        "failback_stability_is_satisfied 100 400 300"
    )
    result = subprocess.run(["bash", "-c", command], cwd=ROOT, check=False)
    return result.returncode == 0


def run() -> int:
    with tempfile.TemporaryDirectory(prefix="hospital-dr-dry-run-") as temporary:
        temp = Path(temporary)
        state_db = temp / "chatops.sqlite3"
        timeline = temp / "rto_timeline.json"
        dr_state_file = temp / "dr_state"
        # Failback is intentionally expected to be rejected from IDLE. This is
        # an isolated fixture; it is not an operational DR state assertion.
        dr_state_file.write_text("IDLE\n", encoding="utf-8")
        environment = {
            "DR_RTO_TIMELINE_FILE": str(timeline),
            "DR_STATE_FILE": str(dr_state_file),
        }
        import os

        os.environ.update(environment)
        failover = DryRunSlackClient("C_DRY_FAILOVER")
        failback_client = DryRunSlackClient("C_DRY_FAILBACK")
        alert = DryRunSlackClient("C_DRY_ALERT")
        app = create_app(
            default_state_db=str(state_db),
            default_secret_file=str(temp / "missing.env"),
            default_script_root=str(ROOT / "operations"),
            test_config={
                "TESTING": True,
                "CHATOPS_STATE_DB": str(state_db),
                "SLACK_CLIENTS": {"failover": failover, "failback": failback_client},
                "SLACK_ALERT_CLIENT": alert,
                "ADMIN_USER_IDS": {"U_DRY_1", "U_DRY_2"},
                "VERIFY_SLACK_SIGNATURE": False,
                "ZABBIX_PRODUCTION_ACTION_HMAC_KEY": ZABBIX_DRY_RUN_HMAC_KEY,
                "PIPELINE_LAUNCHER": lambda request_id, action, approver: None,
            },
        )
        client = app.test_client()
        event_id = "dry-run-event-1"
        incident_at = "2026-09-19T00:00:00Z"
        problem = client.post(
            "/zabbix/alert",
            json={
                "EventID": event_id,
                "Host": "DB_Server",
                "Status": "PROBLEM",
                "Value": "0",
                "Severity": "HIGH",
                "Message": "MySQL TCP 3306 unavailable (controlled dry-run problem)",
                "Item": "net.tcp.service[tcp,IP_REDACTED,3306]",
                "Timestamp": incident_at,
            },
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        problem_result = problem.get_json() or {}
        problem_pass = (
            problem.status_code == 200
            and problem_result.get("alert_sent") is True
            and problem_result.get("dr_escalated") is False
            and not failover.posts
        )

        aggregate_payload = {
            "source": "zabbix_production_action",
            "action_name": "Cloud_Slack_DR_Trigger",
            "action": "failover",
            "incident_id": "1001001",
            "event_id": "1001001",
            "trigger_id": "2002001",
            "event_source": "0",
            "summary": "controlled dry-run production aggregate event",
            "host": "Zabbix server",
            "status": "PROBLEM",
            "event_tags_json": json.dumps(
                [
                    {"tag": "DR_Escalate", "value": "1"},
                    {"tag": "DR_Policy", "value": "production"},
                    {"tag": "DR_Scope", "value": "Hospital-Core"},
                    {"tag": "DR_Type", "value": "Failover"},
                ],
                separators=(",", ":"),
            ),
            "incident_at": incident_at,
            "test_mode": False,
            "event_age_seconds": "0",
        }
        aggregate_body = json.dumps(aggregate_payload, separators=(",", ":")).encode("utf-8")
        signature_timestamp = str(int(time.time()))
        signature = hmac.new(
            ZABBIX_DRY_RUN_HMAC_KEY.encode("utf-8"),
            signature_timestamp.encode("ascii") + b"." + aggregate_body,
            hashlib.sha256,
        ).hexdigest()
        aggregate_response = client.post(
            "/chatops/request",
            data=aggregate_body,
            content_type="application/json",
            headers={
                "X-ChatOps-Zabbix-Timestamp": signature_timestamp,
                "X-ChatOps-Zabbix-Signature": "v1=" + signature,
            },
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        aggregate_result = aggregate_response.get_json() or {}
        aggregate_approval_pass = (
            aggregate_response.status_code == 200
            and aggregate_result.get("action") == "failover"
            and aggregate_result.get("status") == "PENDING"
            and len(failover.posts) == 1
        )

        recovery = client.post(
            "/zabbix/alert",
            json={
                "EventID": event_id,
                "Host": "DB_Server",
                "Status": "RESOLVED",
                "Value": "0",
                "Severity": "HIGH",
                "Message": "MySQL TCP 3306 recovered (controlled dry-run recovery)",
                "Item": "net.tcp.service[tcp,IP_REDACTED,3306]",
                "Timestamp": incident_at,
            },
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        recovery_pass = recovery.status_code == 200 and recovery.get_json().get("alert_sent") is True

        failback_response = client.post(
            "/chatops/request",
            json={
                "source": "zabbix",
                "action": "failback",
                "incident_id": "dry-run-recovery-1",
                "summary": "controlled dry-run recovery",
                "host": "DB_Server",
                "event_age_seconds": "0",
                "incident_at": incident_at,
                "test_mode": True,
                "stability_verified": True,
                "stability_seconds": 300,
            },
            environ_base={"REMOTE_ADDR": "IP_REDACTED"},
        )
        failback_result = failback_response.get_json() or {}
        failback_guard_pass = (
            failback_response.status_code == 409
            and failback_result.get("code") == "FAILBACK_REQUIRES_DR_ACTIVE"
            and failback_result.get("dr_state") == "IDLE"
            and "request_id" not in failback_result
            and not failback_client.posts
        )
        failback_network_gate_skipped = (
            failback_guard_pass
            and failback_result.get("code") == "FAILBACK_REQUIRES_DR_ACTIVE"
        )

        # This pure policy check verifies fail-closed behavior when there is no
        # independent Monitoring Path signal. It does not query or simulate
        # operational monitoring data.
        production_monitoring_path_blocked = not evaluate_failover_policy(
            web_failed=True,
            doc_failed=True,
            db_failed=True,
            duration_seconds=300,
            monitoring_path_last_value=None,
            monitoring_path_lastclock=None,
            health_samples_fresh=True,
            maintenance=False,
            broad_test_mode=False,
        )

        timeline_result = synthetic_run(timeline, "dry-run-rto")
        timeline_metrics = metric_values(timeline_result)
        dashboard_paths = (
            ROOT / "monitoring/grafana/provisioning/dashboards/json/hospital-dr-automation.json",
            ROOT / "monitoring/grafana/provisioning/dashboards/json/hospital-dr-rto.json",
        )
        dashboards = [json.loads(path.read_text(encoding="utf-8")) for path in dashboard_paths]
        required_rto_keys = (
            "dr.rto.seconds",
            "dr.rto.target_seconds",
            "dr.rto.result",
            "dr.rto.detection_seconds",
            "dr.rto.approval_creation_seconds",
            "dr.rto.approval_seconds",
            "dr.rto.approval_to_start_seconds",
            "dr.rto.execution_seconds",
        )
        rto_targets = [
            target
            for dashboard in dashboards
            for panel in dashboard.get("panels", [])
            if panel.get("title") in {"RTO Seconds / Target 1h", "Current / Latest RTO"}
            for target in panel.get("targets", [])
        ]
        zabbix_uid = "PA67C5EADE9207728"
        grafana_pass = (
            all(key in timeline_metrics for key in required_rto_keys)
            and len(rto_targets) == 2
            and all(
                target.get("datasource", {}).get("uid") == zabbix_uid
                and target.get("host", {}).get("filter") == "Hospital_DR_Automation"
                and target.get("item", {}).get("filter") == "DR total RTO seconds"
                for target in rto_targets
            )
            and "RPO STATUS: NR NOT READY" in json.dumps(dashboards, ensure_ascii=True)
        )
        stability_pass = _stability_contract_passes()

        results = {
            "PROBLEM_EVENT": "PASS" if problem_pass else "FAIL",
            "GENERAL_ALERT": "PASS" if len(alert.posts) >= 2 else "FAIL",
            "FAILOVER_APPROVAL": "PASS" if aggregate_approval_pass else "FAIL",
            "FAILOVER_EXECUTION": "SKIPPED_DRY_RUN",
            "RECOVERY_EVENT": "PASS" if recovery_pass else "FAIL",
            "NETWORK_DR_HEALTH": "UNVERIFIED",
            "NETWORK_DR_HEALTH_REASON": "no live Zabbix snapshot; dry-run does not assert operational monitoring health",
            "PRODUCTION_MONITORING_PATH": "BLOCKED"
            if production_monitoring_path_blocked
            else "FAIL",
            "PRODUCTION_MONITORING_PATH_REASON": "independent signal is unavailable; production escalation remains fail-closed",
            "FAILBACK_NETWORK_GATE": "SKIPPED_DR_STATE_NOT_ACTIVE"
            if failback_network_gate_skipped
            else "FAIL",
            "FAILBACK_NETWORK_GATE_REASON": "IDLE state rejected before network and Wazuh checks",
            "RECOVERY_STABILITY_GUARD": "PASS" if stability_pass else "FAIL",
            "FAILBACK_APPROVAL": "BLOCKED_EXPECTED" if failback_guard_pass else "FAIL",
            "FAILBACK_APPROVAL_GUARD": "PASS" if failback_guard_pass else "FAIL",
            "FAILBACK_REJECTION_CODE": str(failback_result.get("code") or "UNKNOWN"),
            "FAILBACK_APPROVAL_REASON": "DR_ACTIVE required; no approval request was created",
            "RTO_METRICS": "PASS"
            if timeline_result["total_rto_seconds"] == 600.0
            and timeline_metrics.get("dr.rto.seconds") == 600.0
            and timeline_metrics.get("dr.rto.result") == 1
            else "FAIL",
            "GRAFANA_RTO_DATA": "PASS" if grafana_pass else "FAIL",
            "FAILBACK_EXECUTION": "SKIPPED_DRY_RUN",
            "DR_DRY_RUN_RESULT": "PASS",
            "RTO": timeline_result,
        }
        contract_checks = (
            problem_pass,
            len(alert.posts) >= 2,
            aggregate_approval_pass,
            recovery_pass,
            production_monitoring_path_blocked,
            failback_network_gate_skipped,
            failback_guard_pass,
            stability_pass,
            timeline_result["total_rto_seconds"] == 600.0,
            timeline_metrics.get("dr.rto.seconds") == 600.0,
            timeline_metrics.get("dr.rto.result") == 1,
            grafana_pass,
        )
        if not all(contract_checks):
            results["DR_DRY_RUN_RESULT"] = "FAIL"
        for key in (
            "PROBLEM_EVENT",
            "GENERAL_ALERT",
            "FAILOVER_APPROVAL",
            "FAILOVER_EXECUTION",
            "RECOVERY_EVENT",
            "NETWORK_DR_HEALTH",
            "NETWORK_DR_HEALTH_REASON",
            "PRODUCTION_MONITORING_PATH",
            "PRODUCTION_MONITORING_PATH_REASON",
            "FAILBACK_NETWORK_GATE",
            "FAILBACK_NETWORK_GATE_REASON",
            "RECOVERY_STABILITY_GUARD",
            "FAILBACK_APPROVAL",
            "FAILBACK_APPROVAL_GUARD",
            "FAILBACK_REJECTION_CODE",
            "FAILBACK_APPROVAL_REASON",
            "FAILBACK_EXECUTION",
            "RTO_METRICS",
            "GRAFANA_RTO_DATA",
            "DR_DRY_RUN_RESULT",
        ):
            print(f"{key}={results[key]}")
        print("RTO_JSON=" + json.dumps(timeline_result, ensure_ascii=True, sort_keys=True))
        return 0 if results["DR_DRY_RUN_RESULT"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(run())
