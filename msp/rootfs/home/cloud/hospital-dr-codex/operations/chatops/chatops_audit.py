"""Durable audit and retention tracking for ChatOps Slack messages."""

import json
import os
import sqlite3
import tempfile
import threading
import time


TERMINAL_STATUSES = (
    "SUCCEEDED", "DB_RESTORED_NOT_FAILOVER_COMPLETE", "FAILED",
    "PARTIAL_FAILURE", "CANCELLED", "EXPIRED",
)


def _safe_incident(incident):
    if not isinstance(incident, dict):
        return {"summary": str(incident)[:300]}
    allowed = (
        "incident_id",
        "summary",
        "observed_at",
        "source",
        "rule_id",
        "severity",
        "host",
        "security_status",
        "security_reason",
        "security_agents",
        "security_critical_incident",
        "request_type",
        "request_origin",
        "reason_code",
        "reason_text",
        "requested_by",
        "requested_at",
        "expires_at",
        "precheck_status",
        "precheck_reason",
        "backup_id",
        "backup_filename",
        "backup_timestamp",
        "backup_timestamp_source",
        "backup_checksum",
        "expected_rpo",
    )
    return {
        key: str(incident[key])[:500]
        for key in allowed
        if key in incident and incident[key] is not None
    }


def request_audit_payload(state):
    incidents = [_safe_incident(item) for item in state.get("incidents", [])]
    status = state.get("status", "UNKNOWN")
    finished_at = state.get("finished_at")
    return {
        "kind": "request",
        "incident_id": incidents[0].get("incident_id", "-") if incidents else "-",
        "incident_ids": [item.get("incident_id", "-") for item in incidents],
        "request_id": state.get("request_id"),
        "action": state.get("action"),
        "request_type": (incidents[-1].get("request_type") if incidents else None),
        "request_origin": (incidents[-1].get("request_origin") if incidents else None),
        "event": "chatops_approval_request",
        "source": "chatops",
        "incidents": incidents,
        "created_at": state.get("created_at"),
        "expires_at": state.get("expires_at"),
        "approval_required": state.get("approval_required", 2),
        "approval_mode_expires_at": state.get("approval_mode_expires_at"),
        "first_approved_at": state.get("first_approved_at"),
        "approval_times": [
            value
            for value in (state.get("first_approved_at"), state.get("execution_started_at"))
            if value is not None
        ],
        "execution_started_at": state.get("execution_started_at"),
        "execution_id": state.get("execution_id"),
        "completed_at": finished_at if status in (
            "SUCCEEDED", "DB_RESTORED_NOT_FAILOVER_COMPLETE", "FAILED", "PARTIAL_FAILURE"
        ) else None,
        "cancelled_at": finished_at if status == "CANCELLED" else None,
        "expired_at": finished_at if status == "EXPIRED" else None,
        "approvers": list(state.get("approvers", [])),
        "cancelled_by": state.get("cancelled_by"),
        "status": status,
        "result": state.get("result"),
        "rto_seconds": state.get("rto_seconds"),
        "slack_channel_id": state.get("slack_channel_id"),
        "slack_message_ts": state.get("slack_message_ts"),
    }


class ChatOpsAudit:
    def __init__(self, state_db, audit_file):
        self.state_db = state_db
        self.audit_file = audit_file
        self.lock = threading.RLock()
        audit_dir = os.path.dirname(os.path.abspath(audit_file))
        os.makedirs(audit_dir, mode=0o700, exist_ok=True)
        os.chmod(audit_dir, 0o700)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.state_db, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self.lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS chatops_message_registry (
                    message_key TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    request_id TEXT,
                    action TEXT,
                    channel_id TEXT NOT NULL,
                    message_ts TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    audit_written_at REAL,
                    delete_attempted_at REAL,
                    deleted_at REAL,
                    delete_error TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_chatops_cleanup "
                "ON chatops_message_registry(deleted_at, created_at)"
            )
        if os.path.exists(self.audit_file):
            os.chmod(self.audit_file, 0o600)

    @staticmethod
    def _decode(row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _upsert_message(self, key, kind, request_id, action, channel_id, message_ts, created_at, status, payload):
        if not channel_id or not message_ts:
            return None
        with self.lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO chatops_message_registry (
                    message_key, kind, request_id, action, channel_id, message_ts,
                    created_at, status, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(message_key) DO UPDATE SET
                    kind = excluded.kind,
                    request_id = excluded.request_id,
                    action = excluded.action,
                    channel_id = excluded.channel_id,
                    message_ts = excluded.message_ts,
                    status = excluded.status,
                    payload = excluded.payload
                """,
                (
                    key,
                    kind,
                    request_id,
                    action,
                    channel_id,
                    message_ts,
                    created_at,
                    status,
                    json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
                ),
            )
            connection.commit()
            return self._decode(
                connection.execute(
                    "SELECT * FROM chatops_message_registry WHERE message_key = ?", (key,)
                ).fetchone()
            )

    def register_request_message(self, state):
        payload = request_audit_payload(state)
        return self._upsert_message(
            f"request:{state['request_id']}",
            "request",
            state["request_id"],
            state.get("action"),
            state.get("slack_channel_id"),
            state.get("slack_message_ts"),
            state.get("created_at", time.time()),
            state.get("status", "UNKNOWN"),
            payload,
        )

    def register_alert_message(self, alert, result, dr_escalated):
        return self.register_alert_message_data(
            {
                "incident_id": alert.incident_id,
                "source": "wazuh",
                "event": "wazuh_security_alert",
                "rule_id": alert.rule_id,
                "host": alert.agent_name or alert.agent_id or "unknown",
                "severity": alert.severity,
                "timestamp": alert.timestamp or "-",
                "summary": str(alert.event_summary)[:500],
            },
            result,
            dr_escalated,
        )

    def register_alert_message_data(self, alert, result, dr_escalated=False):
        """Register a normalized monitoring alert without storing raw payloads."""
        channel_id = result.get("channel")
        message_ts = result.get("ts")
        if not channel_id or not message_ts:
            return None
        payload = {
            "kind": "alert",
            "incident_id": str(alert.get("incident_id") or "unknown")[:160],
            "source": str(alert.get("source") or "unknown")[:40],
            "event": str(alert.get("event") or "monitoring_alert")[:80],
            "rule_id": str(alert.get("rule_id") or "-")[:80],
            "host": str(alert.get("host") or "unknown")[:120],
            "severity": str(alert.get("severity") or "UNKNOWN")[:20],
            "status": str(alert.get("status") or "UNKNOWN")[:30],
            "timestamp": str(alert.get("timestamp") or "-")[:80],
            "summary": str(alert.get("summary") or "monitoring event")[:500],
            "dr_escalated": bool(dr_escalated),
            "slack_channel_id": channel_id,
            "slack_message_ts": message_ts,
        }
        return self._upsert_message(
            f"alert:{channel_id}:{message_ts}",
            "alert",
            None,
            None,
            channel_id,
            message_ts,
            time.time(),
            "ALERT",
            payload,
        )

    def has_alert_incident(self, source, incident_id, status=None):
        """Return whether this source/id/lifecycle alert is already registered.

        Zabbix recovery operations may reuse the original problem EventID while
        changing the status to RESOLVED.  Duplicate suppression must therefore
        be scoped to the alert lifecycle status, otherwise a successful problem
        notification suppresses the required recovery notification.  Registry
        rows written before status was persisted remain compatible: they still
        suppress repeated problem alerts, but do not suppress a recovery alert.
        """
        if not incident_id:
            return False
        requested_status = str(status or "").strip().upper()
        recovery_statuses = {"OK", "RESOLVED", "RECOVERY"}
        with self.lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM chatops_message_registry WHERE kind = 'alert'"
            ).fetchall()
        for row in rows:
            try:
                payload = json.loads(row[0])
            except (TypeError, json.JSONDecodeError):
                continue
            if payload.get("source") != source or payload.get("incident_id") != str(incident_id):
                continue
            recorded_status = str(payload.get("status") or "").strip().upper()
            if recorded_status:
                if not requested_status or recorded_status == requested_status:
                    return True
                continue
            # Legacy rows did not retain lifecycle status.  Preserve their
            # problem duplicate behavior while allowing the first recovery
            # notification for the same original EventID.
            if not requested_status or requested_status not in recovery_statuses:
                return True
        return False

    def backfill_requests(self, approval_store):
        for state in approval_store.list_with_messages():
            if state.get("slack_channel_id") and state.get("slack_message_ts"):
                self.register_request_message(state)

    def record_event(self, event, payload=None, now=None):
        """Append a redacted lifecycle event to the existing JSONL audit log."""
        record = {
            "event": str(event)[:120],
            "timestamp": time.time() if now is None else float(now),
        }
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key in {
                    "channel_id",
                    "message_ts",
                    "status",
                    "reason",
                    "request_id",
                    "request_type",
                    "request_origin",
                    "approval_required",
                    "approval_mode_expires_at",
                    "mode",
                    "approvers",
                    "incident_ids",
                    "cancelled_by",
                    "result",
                    "failure_phase",
                    "failure_code",
                    "automatic_rollback_allowed",
                    "operator_intervention_required",
                    "executor_started",
                    "superseded_by_request_id",
                    "error_type",
                }:
                    if key in {"approvers", "incident_ids"}:
                        values = value if isinstance(value, (list, tuple)) else [value]
                        record[key] = [str(item)[:160] for item in values[:50]]
                    elif key in {
                        "automatic_rollback_allowed",
                        "operator_intervention_required",
                        "executor_started",
                    }:
                        record[key] = bool(value)
                    else:
                        record[key] = str(value)[:500]
        with self.lock:
            self._append_audit(record)
        return record

    def latest_event_of(self, events):
        """Read the newest matching event without exposing unrelated audit data."""
        wanted = set(events or ())
        if not wanted or not os.path.exists(self.audit_file):
            return None
        latest = None
        try:
            with self.lock, open(self.audit_file, "r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("event") in wanted:
                        latest = record
        except OSError:
            return None
        return latest

    def candidates(self, now=None, ttl_seconds=86400):
        now = time.time() if now is None else now
        cutoff = now - max(0, int(ttl_seconds))
        terminal_placeholders = ", ".join("?" for _ in TERMINAL_STATUSES)
        with self.lock, self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM chatops_message_registry
                WHERE deleted_at IS NULL AND created_at <= ?
                  AND (kind = 'alert' OR (kind = 'request' AND status IN ({terminal_placeholders})))
                ORDER BY created_at ASC
                """,
                (cutoff, *TERMINAL_STATUSES),
            ).fetchall()
            return [self._decode(row) for row in rows]

    def prepare_delete(self, message_key, now=None, payload=None):
        now = time.time() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM chatops_message_registry WHERE message_key = ?", (message_key,)
            ).fetchone()
            if row is None or row["deleted_at"] is not None:
                connection.commit()
                return None
            decoded = self._decode(row)
            if row["audit_written_at"] is None:
                audit_payload = dict(payload or decoded["payload"])
                audit_payload.update(
                    {
                        "audit_key": message_key,
                        "cleanup_started_at": now,
                        "deleted_at": None,
                    }
                )
                if not self._audit_key_exists(message_key):
                    self._append_audit(audit_payload)
                connection.execute(
                    "UPDATE chatops_message_registry SET audit_written_at = ? WHERE message_key = ?",
                    (now, message_key),
                )
            connection.execute(
                "UPDATE chatops_message_registry SET delete_attempted_at = ?, delete_error = NULL "
                "WHERE message_key = ?",
                (now, message_key),
            )
            connection.commit()
            return self._decode(
                connection.execute(
                    "SELECT * FROM chatops_message_registry WHERE message_key = ?", (message_key,)
                ).fetchone()
            )

    def mark_deleted(self, message_key, now=None):
        now = time.time() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute(
                "UPDATE chatops_message_registry SET deleted_at = ?, delete_error = NULL WHERE message_key = ?",
                (now, message_key),
            )
            connection.commit()
        self._update_audit(message_key, {"deleted_at": now, "delete_result": "deleted"})

    def mark_delete_failed(self, message_key, error, now=None):
        now = time.time() if now is None else now
        with self.lock, self._connect() as connection:
            connection.execute(
                "UPDATE chatops_message_registry SET delete_attempted_at = ?, delete_error = ? "
                "WHERE message_key = ?",
                (now, str(error)[:240], message_key),
            )
            connection.commit()

    def _audit_key_exists(self, message_key):
        if not os.path.exists(self.audit_file):
            return False
        try:
            with open(self.audit_file, "r", encoding="utf-8") as stream:
                return any(json.loads(line).get("audit_key") == message_key for line in stream if line.strip())
        except (OSError, json.JSONDecodeError):
            return False

    def _append_audit(self, payload):
        parent = os.path.dirname(os.path.abspath(self.audit_file))
        fd, temporary = tempfile.mkstemp(prefix=".chatops-audit-", dir=parent, text=True)
        try:
            if os.path.exists(self.audit_file):
                with open(self.audit_file, "rb") as source, os.fdopen(fd, "wb") as target:
                    target.write(source.read())
                    target.write((json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n").encode())
            else:
                with os.fdopen(fd, "w", encoding="utf-8") as target:
                    target.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.audit_file)
            os.chmod(self.audit_file, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _update_audit(self, message_key, updates):
        if not os.path.exists(self.audit_file):
            return
        parent = os.path.dirname(os.path.abspath(self.audit_file))
        fd, temporary = tempfile.mkstemp(prefix=".chatops-audit-", dir=parent, text=True)
        found = False
        try:
            with open(self.audit_file, "r", encoding="utf-8") as source, os.fdopen(
                fd, "w", encoding="utf-8"
            ) as target:
                for line in source:
                    if line.strip():
                        record = json.loads(line)
                        if record.get("audit_key") == message_key:
                            record.update(updates)
                            found = True
                        target.write(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")
            if found:
                os.chmod(temporary, 0o600)
                os.replace(temporary, self.audit_file)
                os.chmod(self.audit_file, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
