import fcntl
import hashlib
import hmac
import json
import logging
import os
import queue
import sqlite3
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, request

from chatops_audit import ChatOpsAudit, request_audit_payload


ACTIVE_STATUSES = ("PENDING", "PARTIALLY_APPROVED", "EXECUTING")
APPROVAL_STATUSES = ("PENDING", "PARTIALLY_APPROVED")
TERMINAL_STATUSES = ("SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED")
REQUIRED_APPROVALS = 2
INITIAL_APPROVAL_TTL_SECONDS = 20 * 60
FIRST_APPROVAL_TTL_SECONDS = 60 * 60
DEFAULT_EXECUTION_TIMEOUT_SECONDS = 60 * 60
DEFAULT_EXECUTION_HEARTBEAT_SECONDS = 15
DEFAULT_EXECUTION_LEASE_SECONDS = 60


def utc_timestamp():
    return time.time()


def format_timestamp(value):
    if value is None:
        return "-"
    return datetime.fromtimestamp(value, timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def load_env_file(path):
    values = {}
    if not path or not os.path.isfile(path):
        return values
    with open(path, "r", encoding="utf-8") as stream:
        for raw_line in stream:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if key:
                values[key] = value
    return values


class ApprovalStore:
    def __init__(
        self,
        path,
        initial_ttl=INITIAL_APPROVAL_TTL_SECONDS,
        approved_ttl=FIRST_APPROVAL_TTL_SECONDS,
        execution_timeout=DEFAULT_EXECUTION_TIMEOUT_SECONDS,
        execution_lease_seconds=DEFAULT_EXECUTION_LEASE_SECONDS,
    ):
        self.path = path
        self.initial_ttl = initial_ttl
        self.approved_ttl = approved_ttl
        self.execution_timeout = max(1.0, float(execution_timeout))
        self.execution_lease_seconds = max(1.0, float(execution_lease_seconds))
        self.lock = threading.RLock()
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self.lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_requests (
                    request_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    incidents TEXT NOT NULL,
                    approvers TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    first_approved_at REAL,
                    expires_at REAL NOT NULL,
                    slack_channel_id TEXT,
                    slack_message_ts TEXT,
                    finished_at REAL,
                    cancelled_by TEXT,
                    result TEXT,
                    execution_started_at REAL,
                    execution_heartbeat_at REAL,
                    execution_lease_until REAL,
                    execution_id TEXT
                )
                """
            )
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(approval_requests)")
            }
            for name, definition in (
                ("finished_at", "REAL"),
                ("cancelled_by", "TEXT"),
                ("result", "TEXT"),
                ("execution_started_at", "REAL"),
                ("execution_heartbeat_at", "REAL"),
                ("execution_lease_until", "REAL"),
                ("execution_id", "TEXT"),
            ):
                if name not in columns:
                    connection.execute(f"ALTER TABLE approval_requests ADD COLUMN {name} {definition}")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_active ON approval_requests(action, status, created_at)"
            )
        os.chmod(self.path, 0o600)

    @staticmethod
    def _decode(row):
        if row is None:
            return None
        result = dict(row)
        result["incidents"] = json.loads(result["incidents"])
        result["approvers"] = json.loads(result["approvers"])
        return result

    @staticmethod
    def _read(connection, request_id):
        return connection.execute(
            "SELECT * FROM approval_requests WHERE request_id = ?", (request_id,)
        ).fetchone()

    def get(self, request_id):
        with self.lock, self._connect() as connection:
            return self._decode(self._read(connection, request_id))

    def list_with_messages(self):
        with self.lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM approval_requests WHERE slack_channel_id IS NOT NULL "
                "AND slack_message_ts IS NOT NULL ORDER BY created_at ASC"
            ).fetchall()
            return [self._decode(row) for row in rows]

    def _recover_stale_executions_locked(self, connection, now):
        rows = connection.execute(
            """
            SELECT request_id, created_at, execution_started_at,
                   execution_heartbeat_at, execution_lease_until
            FROM approval_requests
            WHERE status = 'EXECUTING'
            """
        ).fetchall()
        stale_ids = []
        for row in rows:
            lease_until = row["execution_lease_until"]
            started_at = row["execution_started_at"] or row["execution_heartbeat_at"] or row["created_at"]
            stale = lease_until is not None and lease_until <= now
            if lease_until is None:
                stale = started_at + self.execution_timeout <= now
            if stale:
                stale_ids.append(row["request_id"])
        if stale_ids:
            connection.executemany(
                """
                UPDATE approval_requests
                SET status = 'FAILED', finished_at = ?, result = 'stale_execution_recovered',
                    execution_lease_until = NULL
                WHERE request_id = ? AND status = 'EXECUTING'
                """,
                [(now, request_id) for request_id in stale_ids],
            )
        return stale_ids

    def recover_stale_executions(self, now=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            stale_ids = self._recover_stale_executions_locked(connection, now)
            states = [self._decode(self._read(connection, request_id)) for request_id in stale_ids]
            connection.commit()
            return states

    def find_active(self, action):
        now = utc_timestamp()
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            row = connection.execute(
                """
                SELECT * FROM approval_requests
                WHERE action = ? AND status IN (?, ?, ?)
                ORDER BY created_at DESC LIMIT 1
                """,
                (action, *ACTIVE_STATUSES),
            ).fetchone()
            connection.commit()
            return self._decode(row)

    def _expire_due_locked(self, connection, now):
        rows = connection.execute(
            """
            SELECT request_id FROM approval_requests
            WHERE status IN (?, ?) AND expires_at <= ?
            """,
            (*APPROVAL_STATUSES, now),
        ).fetchall()
        expired_ids = [row["request_id"] for row in rows]
        if expired_ids:
            connection.executemany(
                "UPDATE approval_requests SET status = 'EXPIRED', finished_at = ?, result = 'expired' "
                "WHERE request_id = ?",
                [(now, request_id) for request_id in expired_ids],
            )
        return expired_ids

    def expire_due(self, now=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            expired_ids = self._expire_due_locked(connection, now)
            states = [self._decode(self._read(connection, request_id)) for request_id in expired_ids]
            connection.commit()
            return states

    def create_or_merge(self, action, incident, now=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            self._expire_due_locked(connection, now)
            row = connection.execute(
                """
                SELECT * FROM approval_requests
                WHERE action = ? AND status IN (?, ?, ?)
                ORDER BY created_at DESC LIMIT 1
                """,
                (action, *ACTIVE_STATUSES),
            ).fetchone()
            if row is not None:
                state = self._decode(row)
                incident_ids = {item.get("incident_id") for item in state["incidents"]}
                if incident.get("incident_id") not in incident_ids:
                    state["incidents"].append(incident)
                    connection.execute(
                        "UPDATE approval_requests SET incidents = ? WHERE request_id = ?",
                        (json.dumps(state["incidents"], ensure_ascii=True), state["request_id"]),
                    )
                connection.commit()
                return self.get(state["request_id"]), True

            request_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO approval_requests (
                    request_id, action, status, incidents, approvers,
                    created_at, first_approved_at, expires_at,
                    slack_channel_id, slack_message_ts,
                    execution_started_at, execution_heartbeat_at,
                    execution_lease_until, execution_id
                ) VALUES (?, ?, 'PENDING', ?, '[]', ?, NULL, ?, NULL, NULL, NULL, NULL, NULL, NULL)
                """,
                (
                    request_id,
                    action,
                    json.dumps([incident], ensure_ascii=True),
                    now,
                    now + self.initial_ttl,
                ),
            )
            connection.commit()
            return self.get(request_id), False

    def attach_slack_message(self, request_id, channel_id, message_ts):
        with self.lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE approval_requests
                SET slack_channel_id = ?, slack_message_ts = ?
                WHERE request_id = ?
                """,
                (channel_id, message_ts, request_id),
            )
            connection.commit()
        return self.get(request_id)

    def clear_slack_message(self, request_id):
        with self.lock, self._connect() as connection:
            connection.execute(
                "UPDATE approval_requests SET slack_message_ts = NULL WHERE request_id = ?",
                (request_id,),
            )
            connection.commit()
        return self.get(request_id)

    def refresh_failback_security(self, request_id, security):
        """Persist the latest gate result and discard stale partial approvals when blocked."""
        now = utc_timestamp()
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._read(connection, request_id)
            if row is None:
                connection.commit()
                return None
            state = self._decode(row)
            if state["action"] != "failback" or not state["incidents"]:
                connection.commit()
                return state
            incidents = state["incidents"]
            latest = dict(incidents[-1])
            latest.update(
                {
                    "security_status": security.get("status", "UNKNOWN"),
                    "security_reason": security.get("reason", "Security readiness was not evaluated."),
                    "security_agents": security.get("agents", "-"),
                    "security_critical_incident": security.get("critical_incident", "-"),
                }
            )
            incidents[-1] = latest
            values = [json.dumps(incidents, ensure_ascii=True)]
            update = "UPDATE approval_requests SET incidents = ?"
            if security.get("status") in ("BLOCKED", "UNKNOWN") and state["status"] in APPROVAL_STATUSES:
                update += ", status = 'PENDING', approvers = '[]', first_approved_at = NULL, expires_at = ?"
                values.append(now + self.initial_ttl)
            update += " WHERE request_id = ?"
            values.append(request_id)
            connection.execute(update, values)
            connection.commit()
        return self.get(request_id)

    def approve(self, request_id, action, user_id, now=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            self._expire_due_locked(connection, now)
            row = self._read(connection, request_id)
            if row is None:
                connection.commit()
                return "missing", None
            state = self._decode(row)
            if state["action"] != action:
                connection.commit()
                return "action_mismatch", state
            if state["status"] == "EXECUTING":
                connection.commit()
                return "executing", state
            if state["status"] in TERMINAL_STATUSES:
                connection.commit()
                return "closed", state
            if user_id in state["approvers"]:
                connection.commit()
                return "duplicate", state

            approvers = state["approvers"] + [user_id]
            first_approved_at = state["first_approved_at"]
            expires_at = state["expires_at"]
            if first_approved_at is None:
                first_approved_at = now
                expires_at = now + self.approved_ttl
            status = "EXECUTING" if len(approvers) >= REQUIRED_APPROVALS else "PARTIALLY_APPROVED"
            execution_started_at = state.get("execution_started_at")
            execution_heartbeat_at = state.get("execution_heartbeat_at")
            execution_lease_until = state.get("execution_lease_until")
            execution_id = state.get("execution_id")
            if status == "EXECUTING":
                execution_started_at = now
                execution_heartbeat_at = now
                execution_lease_until = now + self.execution_lease_seconds
                execution_id = str(uuid.uuid4())
            connection.execute(
                """
                UPDATE approval_requests
                SET status = ?, approvers = ?, first_approved_at = ?, expires_at = ?,
                    execution_started_at = ?, execution_heartbeat_at = ?,
                    execution_lease_until = ?, execution_id = ?
                WHERE request_id = ?
                """,
                (
                    status,
                    json.dumps(approvers, ensure_ascii=True),
                    first_approved_at,
                    expires_at,
                    execution_started_at,
                    execution_heartbeat_at,
                    execution_lease_until,
                    execution_id,
                    request_id,
                ),
            )
            connection.commit()
            return ("approved" if status == "EXECUTING" else "pending"), self.get(request_id)

    def cancel(self, request_id, action, now=None, cancelled_by=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_stale_executions_locked(connection, now)
            self._expire_due_locked(connection, now)
            row = self._read(connection, request_id)
            if row is None:
                connection.commit()
                return "missing", None
            state = self._decode(row)
            if state["action"] != action:
                connection.commit()
                return "action_mismatch", state
            if state["status"] == "EXECUTING":
                connection.commit()
                return "executing", state
            if state["status"] in TERMINAL_STATUSES:
                connection.commit()
                return "closed", state
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'CANCELLED', approvers = '[]', expires_at = ?,
                    finished_at = ?, cancelled_by = ?, result = 'cancelled',
                    execution_lease_until = NULL
                WHERE request_id = ?
                """,
                (now, now, cancelled_by, request_id),
            )
            connection.commit()
            return "cancelled", self.get(request_id)

    def heartbeat(self, request_id, now=None):
        now = utc_timestamp() if now is None else now
        with self.lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE approval_requests
                SET execution_heartbeat_at = ?, execution_lease_until = ?
                WHERE request_id = ? AND status = 'EXECUTING'
                """,
                (now, now + self.execution_lease_seconds, request_id),
            )
            connection.commit()
            return cursor.rowcount == 1

    def finish(self, request_id, succeeded, result=None):
        status = "SUCCEEDED" if succeeded else "FAILED"
        finished_at = utc_timestamp()
        result = result or ("success" if succeeded else "failed")
        with self.lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE approval_requests
                SET status = ?, finished_at = ?, result = ?, execution_lease_until = NULL
                WHERE request_id = ? AND status IN ('PENDING', 'PARTIALLY_APPROVED', 'EXECUTING')
                """,
                (status, finished_at, result, request_id),
            )
            connection.commit()
        return self.get(request_id)


class SlackApiError(RuntimeError):
    def __init__(self, method, error):
        self.method = method
        self.error = error
        super().__init__(f"Slack API {method} failed: {error}")


class SlackClient:
    def __init__(self, token, channel_id):
        self.token = token
        self.channel_id = channel_id

    @property
    def available(self):
        return bool(self.token and self.channel_id)

    def _call(self, method, payload):
        response = requests.post(
            f"https://slack.com/api/{method}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        if not data.get("ok"):
            raise SlackApiError(method, data.get("error", "unknown_error"))
        return data

    def post_message(self, text, blocks):
        return self._call(
            "chat.postMessage",
            {"channel": self.channel_id, "text": text, "blocks": blocks},
        )

    def update_message(self, channel_id, message_ts, text, blocks):
        return self._call(
            "chat.update",
            {"channel": channel_id, "ts": message_ts, "text": text, "blocks": blocks},
        )

    def delete_message(self, channel_id, message_ts):
        return self._call(
            "chat.delete",
            {"channel": channel_id, "ts": message_ts},
        )


def action_label(action):
    return "DR FAILOVER" if action == "failover" else "WEB+DOC+DB FAILBACK"


def status_label(status):
    return {
        "PENDING": "PENDING / 승인 대기",
        "PARTIALLY_APPROVED": "PENDING / 추가 승인 대기",
        "EXECUTING": "EXECUTING / 실행 중",
        "SUCCEEDED": "SUCCEEDED / 완료",
        "FAILED": "FAILED / 실패",
        "CANCELLED": "CANCELLED / 취소",
        "EXPIRED": "EXPIRED / 만료",
    }.get(status, status)


def safe_mrkdwn(value, limit=300):
    text = str(value or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text[:limit]


def button_value(request_id, action, operation):
    return json.dumps(
        {"request_id": request_id, "action": action, "operation": operation},
        separators=(",", ":"),
    )


def valid_slack_signature(signing_secret, raw_body, timestamp, signature, now=None):
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        request_time = int(timestamp)
    except (TypeError, ValueError):
        return False
    current_time = int(utc_timestamp() if now is None else now)
    if abs(current_time - request_time) > 300:
        return False
    base = b"v0:" + str(request_time).encode("ascii") + b":" + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def failback_security_from_state(state):
    if state.get("action") != "failback":
        return "READY", "", "-", "-"
    for incident in reversed(state.get("incidents") or []):
        if "security_status" in incident:
            return (
                incident.get("security_status") or "UNKNOWN",
                incident.get("security_reason") or "Security readiness was not evaluated.",
                incident.get("security_agents") or "-",
                incident.get("security_critical_incident") or "-",
            )
    return "UNKNOWN", "Security readiness was not evaluated.", "-", "-"


def evaluate_current_failback_security(app):
    """Evaluate the configured Wazuh snapshot/provider without failing open."""
    try:
        from wazuh_failback_gate import evaluate_failback_security

        provider = app.config.get("WAZUH_SECURITY_STATE_PROVIDER")
        snapshot = provider() if callable(provider) else app.config.get("WAZUH_FAILBACK_SECURITY_SNAPSHOT")
        required_agents = app.config.get("WAZUH_FAILBACK_REQUIRED_AGENTS", ())
        if isinstance(required_agents, str):
            required_agents = tuple(item.strip() for item in required_agents.split(",") if item.strip())
        return evaluate_failback_security(snapshot, required_agents=required_agents)
    except Exception:
        return {
            "status": "UNKNOWN",
            "reason": "Wazuh security state could not be evaluated.",
            "agents": "UNKNOWN",
            "critical_incident": "-",
        }


def request_ui_copy(action):
    if action == "failover":
        return (
            "🚨 [CRITICAL] On-Premise Network Failure Detected",
            "온프레미스 네트워크 장애가 감지되었습니다.",
            "Cloud DR 환경으로 Failover를 진행하시겠습니까?",
        )
    return (
        "🔄 [RECOVERY] On-Premise Service Recovery Confirmed",
        "온프레미스 서비스 복구가 확인되었습니다.",
        "Cloud DR 환경에서 On-Premise 환경으로 Failback을 진행하시겠습니까?",
    )


def ui_status_label(status):
    return {
        "PENDING": "승인 대기",
        "PARTIALLY_APPROVED": "추가 승인 대기",
        "EXECUTING": "실행 중",
        "SUCCEEDED": "완료",
        "FAILED": "실패",
        "CANCELLED": "취소",
        "EXPIRED": "만료",
    }.get(status, status)


def render_request_message(state, detail=None):
    title, description, prompt = request_ui_copy(state["action"])
    approvers = " ".join(f"<@{user_id}>" for user_id in state["approvers"])
    lines = [
        f"*{safe_mrkdwn(title, 160)}*",
        "",
        safe_mrkdwn(description, 300),
        safe_mrkdwn(prompt, 300),
        "",
        f"승인 상태: *{len(state['approvers'])}/{REQUIRED_APPROVALS}*",
    ]
    if approvers:
        lines.append(f"승인자: {approvers}")
    lines.append(f"요청 ID: `{safe_mrkdwn(state['request_id'], 120)}`")
    if state["status"] not in APPROVAL_STATUSES:
        lines.append(f"상태: *{ui_status_label(state['status'])}*")
    if state["action"] == "failback":
        security_status, security_reason, agents, critical_incident = failback_security_from_state(state)
        lines.extend(
            (
                f"보안 상태: *{safe_mrkdwn(security_status, 20)}*",
                f"Wazuh Agent: *{safe_mrkdwn(agents, 40)}*",
                f"Critical 보안 이벤트: *{safe_mrkdwn(critical_incident, 160)}*",
            )
        )
        if security_status != "READY":
            lines.append(f"사유: {safe_mrkdwn(security_reason, 240)}")
    if detail:
        lines.extend(("", f"처리 결과: {safe_mrkdwn(detail, 400)}"))

    text = "\n".join(lines)

    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    if state["status"] in APPROVAL_STATUSES:
        security_ready = state["action"] != "failback" or failback_security_from_state(state)[0] == "READY"
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            "※ 서로 다른 관리자 2명의 승인이 완료되어야 실행됩니다. 승인 대기 중 관리자 1명이 취소할 수 있습니다."
                            if security_ready
                            else "※ Wazuh 보안 상태가 READY가 될 때까지 Failback 승인이 차단됩니다. 관리자 1명은 취소할 수 있습니다."
                        ),
                    }
                ],
            }
        )
        elements = []
        if security_ready:
            elements.append(
                {
                    "type": "button",
                    "action_id": "hospital_dr_approve",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "value": button_value(state["request_id"], state["action"], "approve"),
                }
            )
        elements.append(
            {
                "type": "button",
                "action_id": "hospital_dr_cancel",
                "text": {"type": "plain_text", "text": "Cancel"},
                "style": "danger",
                "value": button_value(state["request_id"], state["action"], "cancel"),
                "confirm": {
                    "title": {"type": "plain_text", "text": "요청을 취소하시겠습니까?"},
                    "text": {"type": "mrkdwn", "text": "현재 승인과 요청이 모두 취소됩니다."},
                    "confirm": {"type": "plain_text", "text": "취소"},
                    "deny": {"type": "plain_text", "text": "대기"},
                },
            }
        )
        blocks.append(
            {
                "type": "actions",
                "elements": elements,
            }
        )
    return title, blocks


def command_for_action(action, script_root):
    if action == "failover":
        return ["bash", os.path.join(script_root, "full_failover.sh")]
    if action == "failback":
        return ["bash", os.path.join(script_root, "web_db_failback.sh")]
    return None


def should_suppress_log_line(line):
    noisy_patterns = (
        "CryptographyDeprecationWarning",
        "algorithms.TripleDES",
        "The authenticity of host",
        "ED25519 key fingerprint is",
        "This host key is known by the following other names/addresses",
        "Are you sure you want to continue connecting",
        "Warning: Permanently added",
    )
    return any(pattern in line for pattern in noisy_patterns) or "known_hosts:" in line


REPLACEABLE_MESSAGE_ERRORS = frozenset({"cant_update_message", "message_not_found"})


def register_request_message(app, state):
    try:
        app.extensions["chatops_audit"].register_request_message(state)
    except Exception as exc:
        # Audit failures must never stop an approval or DR workflow.
        print(f"[AUDIT WARN] Request message registration failed: {type(exc).__name__}", flush=True)


def deliver_slack_message(app, state, text, blocks):
    """Update the tracked message, replacing only stale/unowned messages."""
    if not state:
        raise RuntimeError("approval request state is missing")
    store = app.extensions["approval_store"]
    client = app.extensions["slack_clients"][state["action"]]
    if not client.available:
        raise RuntimeError(f"SLACK_{state['action'].upper()}_BOT_TOKEN and SLACK_CHANNEL_ID are required")

    if state.get("slack_message_ts") and state.get("slack_channel_id"):
        try:
            client.update_message(state["slack_channel_id"], state["slack_message_ts"], text, blocks)
            register_request_message(app, state)
            return state
        except SlackApiError as exc:
            if exc.error not in REPLACEABLE_MESSAGE_ERRORS:
                raise
            print(
                f"[SLACK WARN] Replacing stale request message action={state['action']} error={exc.error}",
                flush=True,
            )
            state = store.clear_slack_message(state["request_id"])

    result = client.post_message(text, blocks)
    state = store.attach_slack_message(
        state["request_id"], result.get("channel") or client.channel_id, result["ts"]
    )
    register_request_message(app, state)
    return state


def update_slack_message(app, state, detail=None):
    if not state or not state.get("slack_channel_id") or not state.get("slack_message_ts"):
        return False
    text, blocks = render_request_message(state, detail)
    try:
        deliver_slack_message(app, state, text, blocks)
        return True
    except SlackApiError as exc:
        print(
            f"[SLACK ERROR] Request message update failed method={exc.method} error={exc.error}",
            flush=True,
        )
        return False
    except Exception as exc:
        print(f"[SLACK ERROR] Request message update failed: {type(exc).__name__}", flush=True)
        return False


def expire_pending_requests(app, now=None):
    expired = app.extensions["approval_store"].expire_due(now=now)
    for state in expired:
        update_slack_message(app, state, "Approval window expired. A new incident will require a new request. / 승인 시간이 만료되었습니다.")
    return expired


def cleanup_old_slack_messages(app, now=None):
    """Audit and delete old terminal ChatOps messages without affecting DR state."""
    audit = app.extensions["chatops_audit"]
    store = app.extensions["approval_store"]
    # Refresh status before selecting candidates so a failed Slack update cannot
    # leave a terminal request stuck with an old ACTIVE registry status.
    for state in store.list_with_messages():
        register_request_message(app, state)
    candidates = audit.candidates(
        now=now,
        ttl_seconds=app.config["CHATOPS_SLACK_CLEANUP_TTL_SECONDS"],
    )
    deleted = 0
    skipped = 0
    failed = 0
    for row in candidates:
        client = None
        audit_payload = row.get("payload")
        if row["kind"] == "request":
            state = store.get(row.get("request_id"))
            if not state or state.get("status") not in TERMINAL_STATUSES:
                skipped += 1
                continue
            state = dict(state)
            state["slack_channel_id"] = row["channel_id"]
            state["slack_message_ts"] = row["message_ts"]
            audit_payload = request_audit_payload(state)
            client = app.extensions["slack_clients"].get(state.get("action"))
        elif row["kind"] == "alert":
            client = app.extensions.get("wazuh_alert_client")
        if client is None or not getattr(client, "available", False):
            skipped += 1
            continue
        try:
            prepared = audit.prepare_delete(row["message_key"], now=now, payload=audit_payload)
            if prepared is None:
                skipped += 1
                continue
            client.delete_message(prepared["channel_id"], prepared["message_ts"])
        except SlackApiError as exc:
            if exc.error == "message_not_found":
                audit.mark_deleted(row["message_key"], now=now)
                deleted += 1
                continue
            audit.mark_delete_failed(row["message_key"], exc.error, now=now)
            failed += 1
            print(
                f"[SLACK CLEANUP] Delete failed key={row['message_key']} error={exc.error}",
                flush=True,
            )
            continue
        except Exception as exc:
            audit.mark_delete_failed(row["message_key"], type(exc).__name__, now=now)
            failed += 1
            print(
                f"[SLACK CLEANUP] Delete failed key={row['message_key']} error={type(exc).__name__}",
                flush=True,
            )
            continue
        audit.mark_deleted(row["message_key"], now=now)
        deleted += 1
        print(f"[SLACK CLEANUP] Deleted key={row['message_key']}", flush=True)
    return {"candidates": len(candidates), "deleted": deleted, "skipped": skipped, "failed": failed}


def create_approval_request(app, action, incident):
    """Create or update an approval request and deliver its control message."""
    store = app.extensions["approval_store"]
    slack_client = app.extensions["slack_clients"][action]
    if not slack_client.available:
        raise RuntimeError(f"SLACK_{action.upper()}_BOT_TOKEN and SLACK_CHANNEL_ID are required")

    expire_pending_requests(app)
    state, reused = store.create_or_merge(action, incident)
    if action == "failback" and "security_status" in incident:
        state = store.refresh_failback_security(
            state["request_id"],
            {
                "status": incident.get("security_status"),
                "reason": incident.get("security_reason"),
                "agents": incident.get("security_agents"),
                "critical_incident": incident.get("security_critical_incident"),
            },
        )
    text, blocks = render_request_message(state)
    state = deliver_slack_message(app, state, text, blocks)
    return state, reused


def acquire_pipeline_file_lock(path):
    """Acquire a non-blocking lock shared by every ChatOps worker process."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    lock_handle = open(path, "a+", encoding="utf-8")
    os.chmod(path, 0o600)
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_handle.close()
        return None
    return lock_handle


def release_pipeline_file_lock(lock_handle):
    if lock_handle is None:
        return
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    finally:
        lock_handle.close()


def terminate_pipeline(process):
    """Stop the whole workflow process group after a total timeout."""
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
        process.wait(timeout=5)


def run_pipeline(app, request_id, action, final_approver, response_url):
    pipeline_lock = app.extensions["pipeline_lock"]
    store = app.extensions["approval_store"]
    label = action_label(action)
    command = command_for_action(action, app.config["DR_SCRIPT_ROOT"])
    file_lock = None
    thread_lock_held = False

    if command is None:
        state = store.finish(request_id, False, result="unknown_action")
        update_slack_message(app, state, "Unknown workflow action. / 알 수 없는 실행 작업입니다.")
        return

    if not pipeline_lock.acquire(blocking=False):
        state = store.finish(request_id, False, result="in_process_lock_unavailable")
        update_slack_message(app, state, "Another DR workflow is already running. / 다른 DR 작업이 실행 중입니다.")
        return
    thread_lock_held = True

    try:
        try:
            file_lock = acquire_pipeline_file_lock(app.config["CHATOPS_EXECUTION_LOCK_FILE"])
        except OSError as exc:
            print(f"[{label}] Pipeline lock could not be opened: {type(exc).__name__}", flush=True)
        if file_lock is None:
            state = store.finish(request_id, False, result="cross_process_lock_unavailable")
            update_slack_message(app, state, "Another DR workflow is already running. / 다른 DR 작업이 실행 중입니다.")
            return

        if not store.heartbeat(request_id):
            state = store.finish(request_id, False, result="execution_lease_lost")
            update_slack_message(app, state, "Execution lease was lost; a new approval is required. / 실행 lease가 만료되어 새 승인이 필요합니다.")
            return

        print(f"[{label}] Executing request {request_id} after final approval by <@{final_approver}>.", flush=True)
        child_env = os.environ.copy()
        child_env.setdefault("ANSIBLE_HOST_KEY_CHECKING", "False")
        child_env.setdefault("ANSIBLE_DEPRECATION_WARNINGS", "False")
        child_env.setdefault("PYTHONWARNINGS", "ignore")
        child_env.setdefault("ANSIBLE_LOCAL_TEMP", "/tmp/ansible-local")
        child_env.setdefault("ANSIBLE_REMOTE_TEMP", "/tmp/ansible-remote")
        child_env.setdefault("ANSIBLE_SSH_CONTROL_PATH_DIR", "/tmp/ansible-cp")

        process = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            env=child_env,
            start_new_session=True,
        )
        output_queue = queue.Queue()

        def stream_output():
            try:
                for raw_line in process.stdout or ():
                    output_queue.put(("line", raw_line))
            finally:
                output_queue.put(("eof", None))

        reader = threading.Thread(target=stream_output, daemon=True, name=f"chatops-output-{request_id}")
        reader.start()
        timeout_seconds = max(1.0, float(app.config["CHATOPS_EXECUTION_TIMEOUT_SECONDS"]))
        heartbeat_seconds = max(1.0, float(app.config["CHATOPS_EXECUTION_HEARTBEAT_SECONDS"]))
        deadline = time.monotonic() + timeout_seconds
        next_heartbeat = time.monotonic() + heartbeat_seconds
        output_eof = False
        timed_out = False

        while process.poll() is None or not output_eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                print(f"[{label}] Execution total timeout reached for request {request_id}.", flush=True)
                terminate_pipeline(process)
                break
            wait_seconds = min(remaining, max(0.1, next_heartbeat - time.monotonic()))
            try:
                kind, value = output_queue.get(timeout=wait_seconds)
            except queue.Empty:
                if time.monotonic() >= next_heartbeat:
                    store.heartbeat(request_id)
                    next_heartbeat = time.monotonic() + heartbeat_seconds
                continue
            if kind == "eof":
                output_eof = True
                continue
            line = value.rstrip("\n")
            if not should_suppress_log_line(line):
                print(line, flush=True)
            if time.monotonic() >= next_heartbeat:
                store.heartbeat(request_id)
                next_heartbeat = time.monotonic() + heartbeat_seconds

        reader.join(timeout=1)
        if process.stdout is not None:
            process.stdout.close()

        if timed_out:
            return_code = process.returncode if process.returncode is not None else -signal.SIGTERM
            result = "timeout"
            succeeded = False
        else:
            return_code = process.wait()
            result = "success" if return_code == 0 else "failed"
            succeeded = return_code == 0
        state = store.finish(request_id, succeeded, result=result)
        detail = (
            f"Exit code: {return_code}\n"
            + ("Execution total timeout was reached.\n" if timed_out else "")
            + "Detailed workflow output remains in the MSP execution log. / "
            "상세 실행 로그는 MSP 실행 로그에서 확인하세요."
        )
        if not update_slack_message(app, state, detail) and response_url:
            try:
                requests.post(
                    response_url,
                    json={"replace_original": False, "text": f"{label} finished with exit code {return_code}."},
                    timeout=10,
                )
            except Exception:
                pass
    except Exception as exc:
        state = store.finish(request_id, False, result="execution_error")
        update_slack_message(app, state, f"Execution error: {type(exc).__name__}")
        print(f"[{label}] Pipeline error for request {request_id}: {type(exc).__name__}", flush=True)
    finally:
        release_pipeline_file_lock(file_lock)
        if thread_lock_held:
            pipeline_lock.release()


def launch_pipeline(app, request_id, action, final_approver, response_url):
    test_launcher = app.config.get("PIPELINE_LAUNCHER")
    if test_launcher is not None:
        test_launcher(request_id, action, final_approver)
        return
    threading.Thread(
        target=run_pipeline,
        args=(app, request_id, action, final_approver, response_url),
        daemon=True,
    ).start()


def parse_interaction(payload, store):
    action_item = (payload.get("actions") or [{}])[0]
    raw_value = action_item.get("value", "")
    try:
        value = json.loads(raw_value)
        request_id = value.get("request_id")
        action = value.get("action")
        operation = value.get("operation")
    except (TypeError, json.JSONDecodeError):
        legacy_actions = {"run_restore": "failover", "run_failback": "failback"}
        action = legacy_actions.get(raw_value)
        operation = "approve"
        active = store.find_active(action) if action else None
        request_id = active["request_id"] if active else None
    return request_id, action, operation


def ephemeral(text):
    return jsonify({"response_type": "ephemeral", "replace_original": False, "text": text})


def create_app(default_state_db, default_secret_file, default_script_root, test_config=None):
    app = Flask(__name__)
    app.config.update(
        CHATOPS_STATE_DB=os.environ.get("CHATOPS_STATE_DB", default_state_db),
        DR_SECRET_FILE=os.environ.get("DR_SECRET_FILE", default_secret_file),
        DR_SCRIPT_ROOT=os.environ.get("DR_SCRIPT_ROOT", default_script_root),
        CHATOPS_EXECUTION_TIMEOUT_SECONDS=float(
            os.environ.get("CHATOPS_EXECUTION_TIMEOUT_SECONDS", str(DEFAULT_EXECUTION_TIMEOUT_SECONDS))
        ),
        CHATOPS_EXECUTION_HEARTBEAT_SECONDS=float(
            os.environ.get("CHATOPS_EXECUTION_HEARTBEAT_SECONDS", str(DEFAULT_EXECUTION_HEARTBEAT_SECONDS))
        ),
        CHATOPS_EXECUTION_LEASE_SECONDS=float(
            os.environ.get("CHATOPS_EXECUTION_LEASE_SECONDS", str(DEFAULT_EXECUTION_LEASE_SECONDS))
        ),
        CHATOPS_EXECUTION_LOCK_FILE=os.environ.get("CHATOPS_EXECUTION_LOCK_FILE", ""),
        EXPIRY_INTERVAL_SECONDS=int(os.environ.get("CHATOPS_EXPIRY_INTERVAL_SECONDS", "15")),
        CHATOPS_SLACK_CLEANUP_TTL_SECONDS=int(
            os.environ.get("CHATOPS_SLACK_CLEANUP_TTL_SECONDS", "86400")
        ),
        CHATOPS_SLACK_CLEANUP_INTERVAL_SECONDS=int(
            os.environ.get("CHATOPS_SLACK_CLEANUP_INTERVAL_SECONDS", "300")
        ),
        CHATOPS_AUDIT_FILE=os.environ.get(
            "CHATOPS_AUDIT_FILE",
            os.path.join(
                os.path.dirname(
                    os.path.abspath(os.environ.get("CHATOPS_STATE_DB", default_state_db))
                ),
                "audit",
                "chatops_audit.jsonl",
            ),
        ),
        VERIFY_SLACK_SIGNATURE=True,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("CHATOPS_EXECUTION_LOCK_FILE"):
        app.config["CHATOPS_EXECUTION_LOCK_FILE"] = os.path.join(
            os.path.dirname(os.path.abspath(app.config["CHATOPS_STATE_DB"])),
            "pipeline.lock",
        )

    file_values = load_env_file(app.config["DR_SECRET_FILE"])

    def configured_value(name):
        return file_values.get(name, "")

    if app.config.get("WAZUH_FAILBACK_REQUIRED_AGENTS") is None:
        app.config["WAZUH_FAILBACK_REQUIRED_AGENTS"] = tuple(
            item.strip()
            for item in configured_value("WAZUH_FAILBACK_REQUIRED_AGENTS").split(",")
            if item.strip()
        )
    if app.config.get("WAZUH_SECURITY_STATE_PROVIDER") is None:
        try:
            from wazuh_live_provider import build_wazuh_provider

            live_provider = build_wazuh_provider(file_values)
            if live_provider is not None:
                app.config["WAZUH_SECURITY_STATE_PROVIDER"] = live_provider.snapshot
        except Exception:
            # A missing or incomplete live provider must remain UNKNOWN.
            pass
    channel_id = configured_value("SLACK_CHANNEL_ID")
    alert_channel_id = configured_value("SLACK_ALERT_CHANNEL_ID") or channel_id
    raw_admin_ids = configured_value("SLACK_ADMIN_USER_IDS")
    token_by_action = {
        "failover": configured_value("SLACK_FAILOVER_BOT_TOKEN"),
        "failback": configured_value("SLACK_FAILBACK_BOT_TOKEN"),
    }
    signing_secret_by_action = {
        "failover": configured_value("SLACK_FAILOVER_SIGNING_SECRET"),
        "failback": configured_value("SLACK_FAILBACK_SIGNING_SECRET"),
    }
    configured_signing_secrets = app.config.get("SLACK_SIGNING_SECRETS")
    if configured_signing_secrets is not None:
        signing_secret_by_action.update(configured_signing_secrets)
    configured_admin_ids = app.config.get("ADMIN_USER_IDS")
    if configured_admin_ids is None:
        admin_ids = {item.strip() for item in raw_admin_ids.split(",") if item.strip()}
    elif isinstance(configured_admin_ids, str):
        admin_ids = {item.strip() for item in configured_admin_ids.split(",") if item.strip()}
    else:
        admin_ids = set(configured_admin_ids)

    store = ApprovalStore(
        app.config["CHATOPS_STATE_DB"],
        initial_ttl=app.config.get("INITIAL_APPROVAL_TTL_SECONDS", INITIAL_APPROVAL_TTL_SECONDS),
        approved_ttl=app.config.get("FIRST_APPROVAL_TTL_SECONDS", FIRST_APPROVAL_TTL_SECONDS),
        execution_timeout=app.config["CHATOPS_EXECUTION_TIMEOUT_SECONDS"],
        execution_lease_seconds=app.config["CHATOPS_EXECUTION_LEASE_SECONDS"],
    )
    store.recover_stale_executions()
    audit = ChatOpsAudit(app.config["CHATOPS_STATE_DB"], app.config["CHATOPS_AUDIT_FILE"])
    audit.backfill_requests(store)
    configured_clients = app.config.get("SLACK_CLIENTS")
    if configured_clients is None and app.config.get("SLACK_CLIENT") is not None:
        configured_clients = {
            "failover": app.config["SLACK_CLIENT"],
            "failback": app.config["SLACK_CLIENT"],
        }
    slack_clients = configured_clients or {
        action: SlackClient(token, channel_id) for action, token in token_by_action.items()
    }
    alert_client = app.config.get("SLACK_ALERT_CLIENT") or SlackClient(
        configured_value("SLACK_ALERT_BOT_TOKEN"), alert_channel_id
    )
    app.extensions["approval_store"] = store
    app.extensions["chatops_audit"] = audit
    app.extensions["slack_clients"] = slack_clients
    app.extensions["wazuh_alert_client"] = alert_client
    app.extensions["admin_user_ids"] = admin_ids
    app.extensions["slack_signing_secrets"] = signing_secret_by_action
    app.extensions["pipeline_lock"] = threading.Lock()
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.get("/")
    def index():
        return "<h1>Hospital DR Orchestration Console (Persistent Two-Approval Mode)</h1>"

    @app.post("/chatops/request")
    def create_request():
        if request.remote_addr not in ("IP_REDACTED", "::1") and not app.config.get("ALLOW_REMOTE_REQUEST_CREATION", False):
            return jsonify({"error": "request creation is restricted to MSP localhost"}), 403
        if not admin_ids:
            return jsonify({
                "error": "SLACK_ADMIN_USER_IDS must contain at least one administrator; two distinct administrators are required to execute"
            }), 503

        payload = request.get_json(silent=True) or {}
        action = payload.get("action")
        if action not in ("failover", "failback"):
            return jsonify({"error": "action must be failover or failback"}), 400
        incident = {
            "incident_id": str(payload.get("incident_id") or uuid.uuid4()),
            "summary": safe_mrkdwn(payload.get("summary") or f"{action} request", 300),
            "observed_at": payload.get("observed_at") or format_timestamp(utc_timestamp()),
        }
        if action == "failback":
            security = evaluate_current_failback_security(app)
            incident.update(
                {
                    "security_status": security["status"],
                    "security_reason": security["reason"],
                    "security_agents": security["agents"],
                    "security_critical_incident": security["critical_incident"],
                }
            )
        try:
            state, reused = create_approval_request(app, action, incident)
        except SlackApiError as exc:
            print(
                f"[SLACK ERROR] Approval request delivery failed method={exc.method} error={exc.error}",
                flush=True,
            )
            return jsonify({"error": "Slack approval request delivery failed"}), 502
        except Exception as exc:
            print(f"[SLACK ERROR] Approval request delivery failed: {type(exc).__name__}", flush=True)
            return jsonify({"error": "Slack approval request delivery failed"}), 502
        return jsonify(
            {
                "request_id": state["request_id"],
                "action": state["action"],
                "status": state["status"],
                "incident_count": len(state["incidents"]),
                "reused": reused,
            }
        )

    @app.post("/wazuh/alert")
    def wazuh_alert():
        if request.remote_addr not in ("IP_REDACTED", "::1"):
            return jsonify({"error": "Wazuh alert ingestion is restricted to MSP localhost"}), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Wazuh alert must be a JSON object"}), 400
        try:
            from wazuh_alerts import process_wazuh_alert

            return jsonify(process_wazuh_alert(app, payload))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/zabbix/alert")
    def zabbix_alert():
        if request.remote_addr not in ("IP_REDACTED", "::1"):
            return jsonify({"error": "Zabbix alert ingestion is restricted to MSP localhost"}), 403
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Zabbix alert must be a JSON object"}), 400
        try:
            from zabbix_alerts import ZabbixProcessingError, process_zabbix_alert

            return jsonify(process_zabbix_alert(app, payload))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except ZabbixProcessingError as exc:
            print(f"[ZABBIX ERROR] Alert processing failed: {type(exc).__name__}", flush=True)
            return jsonify({"ok": False, "error": str(exc)}), exc.status_code
        except Exception as exc:
            print(f"[ZABBIX ERROR] Alert processing failed: {type(exc).__name__}", flush=True)
            return jsonify({"ok": False, "error": "Zabbix alert processing failed"}), 502

    def handle_slack_action(expected_action=None):
        raw_body = request.get_data(cache=True)
        try:
            payload = json.loads(request.form.get("payload", "{}"))
        except json.JSONDecodeError:
            return jsonify({"error": "invalid Slack payload"}), 400

        request_id, action, operation = parse_interaction(payload, store)
        if expected_action and action != expected_action:
            return jsonify({"error": "Slack action does not match this endpoint"}), 400
        if action not in ("failover", "failback"):
            return ephemeral("요청 작업을 식별할 수 없습니다.")
        signing_secret = signing_secret_by_action[action]
        if app.config["VERIFY_SLACK_SIGNATURE"]:
            if not signing_secret:
                return jsonify({
                    "error": f"SLACK_{action.upper()}_SIGNING_SECRET is not configured"
                }), 503
            if not valid_slack_signature(
                signing_secret,
                raw_body,
                request.headers.get("X-Slack-Request-Timestamp"),
                request.headers.get("X-Slack-Signature"),
            ):
                return jsonify({"error": "invalid Slack signature"}), 401

        user_id = (payload.get("user") or {}).get("id", "")
        response_url = payload.get("response_url", "")
        if not request_id or operation not in ("approve", "cancel"):
            return ephemeral("요청을 찾을 수 없거나 이미 만료되었습니다. 새 승인 요청을 생성해 주세요.")
        if not admin_ids:
            return ephemeral("관리자 승인 목록이 설정되지 않았습니다. SLACK_ADMIN_USER_IDS를 확인해 주세요.")
        if user_id not in admin_ids:
            return ephemeral("이 작업은 등록된 관리자만 승인하거나 취소할 수 있습니다.")

        container = payload.get("container") or {}
        channel_id = (payload.get("channel") or {}).get("id") or container.get("channel_id")
        message_ts = container.get("message_ts") or (payload.get("message") or {}).get("ts")
        state = store.get(request_id)
        if state and message_ts and channel_id and not state.get("slack_message_ts"):
            state = store.attach_slack_message(request_id, channel_id, message_ts)

        if operation == "cancel":
            result, state = store.cancel(request_id, action, cancelled_by=user_id)
            if result == "cancelled":
                update_slack_message(app, state, f"Cancelled by <@{user_id}>. All approvals were discarded. / <@{user_id}> 요청 취소, 기존 승인 폐기")
                return "", 200
            if result == "executing":
                return ephemeral("이미 실행 중인 요청은 취소할 수 없습니다.")
            if state and state["status"] == "EXPIRED":
                update_slack_message(app, state)
            return ephemeral("이미 종료되었거나 만료된 요청입니다.")

        if action == "failback":
            security = evaluate_current_failback_security(app)
            state = store.refresh_failback_security(request_id, security)
            if security["status"] != "READY":
                update_slack_message(app, state, f"Security Status: {security['status']}. Failback approval remains blocked.")
                return ephemeral(
                    f"Failback Security Gate: {security['status']}. {security['reason']}"
                )

        result, state = store.approve(request_id, action, user_id)
        if result == "duplicate":
            return ephemeral(
                f"이미 승인된 요청입니다. 현재 승인: {len(state['approvers'])}/{REQUIRED_APPROVALS}"
            )
        if result == "pending":
            update_slack_message(app, state)
            return "", 200
        if result == "approved":
            update_slack_message(app, state, "Two-person approval completed. Workflow execution started. / 2인 승인 완료, 실행 시작")
            try:
                launch_pipeline(app, request_id, action, user_id, response_url)
            except Exception as exc:
                state = store.finish(request_id, False, result="launch_error")
                update_slack_message(app, state, "Workflow launch failed; a new approval is required. / 실행 시작에 실패해 새 승인이 필요합니다.")
                print(f"[CHATOPS ERROR] Pipeline launch failed: {type(exc).__name__}", flush=True)
                return ephemeral("실행 시작에 실패했습니다. 새 승인 요청을 생성해 주세요.")
            return "", 200
        if result == "executing":
            return ephemeral("이미 실행 중인 요청입니다.")
        if state and state["status"] == "EXPIRED":
            update_slack_message(app, state)
        return ephemeral("이미 종료되었거나 만료된 요청입니다. 새 요청을 생성해 주세요.")

    @app.post("/slack/action")
    def slack_action():
        return handle_slack_action()

    @app.post("/slack/failover/action")
    def slack_failover_action():
        return handle_slack_action(expected_action="failover")

    @app.post("/slack/failback/action")
    def slack_failback_action():
        return handle_slack_action(expected_action="failback")

    return app


def start_expiry_worker(app):
    def worker():
        while True:
            try:
                expire_pending_requests(app)
            except Exception as exc:
                print(f"[EXPIRY ERROR] Approval expiry check failed: {type(exc).__name__}", flush=True)
            time.sleep(app.config["EXPIRY_INTERVAL_SECONDS"])

    threading.Thread(target=worker, daemon=True, name="chatops-expiry-worker").start()


def start_cleanup_worker(app):
    def worker():
        while True:
            try:
                cleanup_old_slack_messages(app)
            except Exception as exc:
                print(f"[CLEANUP ERROR] Slack retention check failed: {type(exc).__name__}", flush=True)
            time.sleep(app.config["CHATOPS_SLACK_CLEANUP_INTERVAL_SECONDS"])

    threading.Thread(target=worker, daemon=True, name="chatops-cleanup-worker").start()
