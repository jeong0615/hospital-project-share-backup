#!/usr/bin/env python3
"""Reconcile the Zabbix-to-ChatOps configuration through the Zabbix API.

The command is intentionally small and policy driven.  It discovers media,
actions, the recipient user, and the failover recipient group by name instead
of relying on IDs from one installation.  ``--check`` never mutates Zabbix;
``--apply`` writes a redacted pre-change export before making only the
required API changes.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shlex
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
MEDIA_SCRIPT = REPO_ROOT / "operations" / "chatops" / "zabbix_media_type.js"
MEDIA_PARAM_NAMES = (
    "EventID",
    "TriggerID",
    "Host",
    "Severity",
    "Status",
    "Value",
    "Subject",
    "Message",
    "Item",
    "Timestamp",
    "DR_Escalate",
    "URL",
)
SCRIPT_EXEC_PARAMS = "__zabbix__\n{ALERT.SUBJECT}\n{ALERT.MESSAGE}\n"
TARGET_MEDIA_NAMES = ("Slack DR Trigger", "Slack Failback", "ChatOps_Alert")
TARGET_ACTION_NAMES = ("Cloud_Slack_DR_Trigger", "ChatOps_Alert_Automation")
REDACTED = "<redacted>"

# Action 3 uses an explicit, structured message so the shell media helper can
# carry the real Event ID, host, and EVENT.AGE into ChatOps.  The age is used
# as a fail-closed freshness guard for production approval requests; Action 9
# remains the button-free general Alert path.
DR_APPROVAL_SUBJECT = "[DR][{EVENT.STATUS}] {EVENT.NAME}"
DR_APPROVAL_MESSAGE = (
    "Action name: {ACTION.NAME}\n"
    "Event ID: {EVENT.ID}\n"
    "Trigger ID: {TRIGGER.ID}\n"
    "Event source: {EVENT.SOURCE}\n"
    "Host: {HOST.NAME}\n"
    "Status: {EVENT.STATUS}\n"
    "Severity: {EVENT.SEVERITY}\n"
    "Value: {EVENT.VALUE}\n"
    "Event age: {EVENT.AGE}\n"
    "Event tags JSON: {EVENT.TAGSJSON}\n"
    "Time: {EVENT.DATE} {EVENT.TIME}"
)


class ConfigurationError(RuntimeError):
    """Raised when the required configuration cannot be reconciled safely."""


class ZabbixAPIError(RuntimeError):
    """Raised for a failed Zabbix JSON-RPC request without exposing secrets."""


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _same(value: Any, expected: Any) -> bool:
    return _text(value) == _text(expected)


def _normalise_script(value: Any) -> str:
    return _text(value).replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")


def _copy(value: Any) -> Any:
    return copy.deepcopy(value)


def _writable_user_medias(medias: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Strip read-only identifiers before passing media to user.update."""

    return [
        {key: _copy(value) for key, value in media.items() if key not in {"mediaid", "userid"}}
        for media in medias
    ]


def _read_env_file(path: Path) -> dict[str, str]:
    """Read simple KEY=value files without expanding or printing values."""

    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigurationError(f"Cannot read environment file: {path}") from exc
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        raw_value = raw_value.strip()
        try:
            parsed = shlex.split(raw_value, comments=False, posix=True)
        except ValueError as exc:
            raise ConfigurationError(f"Malformed value in environment file: {path}") from exc
        values[key] = parsed[0] if parsed else ""
    return values


def _config_value(values: dict[str, str], *names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, values.get(name, ""))
        if value.strip():
            return value.strip()
    return default


@dataclass(frozen=True)
class Settings:
    api_url: str
    api_user: str
    api_password: str
    api_token: str
    recipient_username: str
    failover_group: str
    alert_url: str
    failover_sendto: str
    failback_sendto: str
    alert_sendto: str
    auto_failback_enabled: bool = False


def load_settings(env_file: str | None = None) -> Settings:
    selected = env_file or os.environ.get("ZABBIX_ENV_FILE") or os.environ.get("DR_SECRET_FILE")
    values: dict[str, str] = {}
    if selected:
        values.update(_read_env_file(Path(selected)))

    api_url = _config_value(values, "ZABBIX_API_URL", "ZABBIX_URL")
    if api_url and not api_url.rstrip("/").endswith("api_jsonrpc.php"):
        api_url = api_url.rstrip("/") + "/api_jsonrpc.php"
    api_token = _config_value(values, "ZABBIX_API_TOKEN", "ZABBIX_TOKEN")
    api_user = _config_value(values, "ZABBIX_API_USER", "ZABBIX_USER")
    api_password = _config_value(values, "ZABBIX_API_PASSWORD", "ZABBIX_PASSWORD")
    if not api_url:
        raise ConfigurationError("ZABBIX_API_URL or ZABBIX_URL is required")
    if not api_token and not (api_user and api_password):
        raise ConfigurationError("Zabbix API token or username/password is required")
    return Settings(
        api_url=api_url,
        api_user=api_user,
        api_password=api_password,
        api_token=api_token,
        recipient_username=_config_value(values, "ZABBIX_RECIPIENT_USERNAME", default="Admin"),
        failover_group=_config_value(
            values, "ZABBIX_FAILOVER_RECIPIENT_GROUP", default="Zabbix administrators"
        ),
        alert_url=_config_value(
            values,
            "ZABBIX_CHATOPS_ALERT_URL",
            default="http://IP_REDACTED:5001/zabbix/alert",
        ),
        failover_sendto=_config_value(values, "ZABBIX_FAILOVER_SENDTO", default="slack"),
        failback_sendto=_config_value(values, "ZABBIX_FAILBACK_SENDTO", default="slack"),
        alert_sendto=_config_value(values, "ZABBIX_ALERT_SENDTO", default="chatops"),
        auto_failback_enabled=_config_value(
            values, "ZABBIX_AUTO_FAILBACK_ENABLED", default="false"
        ).lower() in {"1", "true", "yes", "on"},
    )


class ZabbixClient:
    """Minimal standard-library JSON-RPC client for Zabbix 6+ APIs."""

    def __init__(self, settings: Settings, opener: Any = urllib.request.urlopen):
        self.settings = settings
        self._opener = opener
        self._request_id = 0
        self.auth: str | None = settings.api_token or None

    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        include_auth: bool = True,
    ) -> Any:
        self._request_id += 1
        body: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._request_id,
        }
        if include_auth and self.auth is not None:
            body["auth"] = self.auth
        request = urllib.request.Request(
            self.settings.api_url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json-rpc"},
            method="POST",
        )
        try:
            with self._opener(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise ZabbixAPIError(f"Zabbix API request failed: {method}") from exc
        if "error" in payload:
            error = payload.get("error") or {}
            message = _text(error.get("message")) or "unknown API error"
            raise ZabbixAPIError(f"Zabbix API rejected {method}: {message}")
        return payload.get("result")

    def authenticate(self) -> str:
        version = self.call("apiinfo.version", include_auth=False)
        if self.auth is None:
            self.auth = self.call(
                "user.login",
                {"user": self.settings.api_user, "password": "<SET_IN_SECRET_STORE>"},
            )
        return _text(version)


def _unique_by_name(items: Iterable[dict[str, Any]], name: str, label: str) -> dict[str, Any] | None:
    matches = [item for item in items if _text(item.get("name")) == name]
    if len(matches) > 1:
        raise ConfigurationError(f"Multiple {label} objects have the name {name!r}")
    return matches[0] if matches else None


def _filter_signature(filter_value: dict[str, Any] | None) -> tuple[Any, ...]:
    filter_value = filter_value or {}
    conditions = []
    for condition in filter_value.get("conditions") or []:
        conditions.append(
            (
                _text(condition.get("conditiontype")),
                _text(condition.get("operator")),
                _text(condition.get("value")),
                _text(condition.get("value2")),
            )
        )
    return (
        _text(filter_value.get("evaltype")),
        "",
        _text(filter_value.get("formula")),
        tuple(sorted(conditions)),
    )


def _production_dr_action_filter() -> dict[str, Any]:
    """Return the fail-closed Production Action 3 event filter.

    The complete trigger tag contract is required; ``DR_Escalate=1`` alone is
    not an approval authority. All tag-value conditions and the final
    maintenance-suppression exclusion must match (Zabbix 6 evaltype 1 = AND;
    operator 11 means "No").
    """
    conditions = [
        {
            "conditiontype": "26",
            "operator": "0",
            "value": value,
            "value2": tag,
        }
        for tag, value in (
            ("DR_Escalate", "1"),
            ("DR_Policy", "production"),
            ("DR_Scope", "Hospital-Core"),
            ("DR_Type", "Failover"),
        )
    ]
    conditions.append({"conditiontype": "16", "operator": "11"})
    return {
        "evaltype": "1",
        "conditions": conditions,
    }


def _operation_media(operation: dict[str, Any]) -> str:
    return _text((operation.get("opmessage") or {}).get("mediatypeid"))


def _operation_recipients(operation: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    groups = tuple(sorted(_text(item.get("usrgrpid")) for item in operation.get("opmessage_grp") or []))
    users = tuple(sorted(_text(item.get("userid")) for item in operation.get("opmessage_usr") or []))
    return groups, users


def _operation_for_update(operation: dict[str, Any]) -> dict[str, Any]:
    """Keep only operation fields accepted by action.update."""

    allowed = (
        "operationtype",
        "esc_period",
        "esc_step_from",
        "esc_step_to",
        "evaltype",
        "opconditions",
        "opmessage",
        "opmessage_grp",
        "opmessage_usr",
    )
    result = {key: _copy(operation[key]) for key in allowed if key in operation}
    result.pop("actionid", None)
    return result


def _recovery_operation_for_update(operation: dict[str, Any]) -> dict[str, Any]:
    """Keep only fields accepted by Zabbix action.update recovery operations."""
    result = _operation_for_update(operation)
    # Zabbix 6 returns these defaults on recovery operations but rejects them
    # when they are sent back in action.update.
    result.pop("evaltype", None)
    result.pop("opconditions", None)
    return result


def _set_operation_target(
    operation: dict[str, Any],
    media_id: str,
    recipient_kind: str,
    recipient_id: str,
) -> dict[str, Any]:
    result = _operation_for_update(operation)
    message = _copy(result.get("opmessage") or {})
    message["mediatypeid"] = media_id
    result["opmessage"] = message
    if recipient_kind == "group":
        result["opmessage_grp"] = [{"usrgrpid": recipient_id}]
        result["opmessage_usr"] = []
    else:
        result["opmessage_grp"] = []
        result["opmessage_usr"] = [{"userid": recipient_id}]
    return result


def _set_dr_approval_message(
    operation: dict[str, Any], phase: str, plan: "Plan"
) -> dict[str, Any]:
    """Reconcile Action 3's structured event message without changing its target."""
    result = _operation_for_update(operation)
    opmessage = _copy(result.get("opmessage") or {})
    desired = {
        "default_msg": "0",
        "subject": DR_APPROVAL_SUBJECT,
        "message": DR_APPROVAL_MESSAGE,
    }
    if any(opmessage.get(key) != value for key, value in desired.items()):
        opmessage.update(desired)
        result["opmessage"] = opmessage
        plan.changes.append(f"update Cloud_Slack_DR_Trigger {phase} event metadata")
    return result


def _new_operation(
    media_id: str,
    recipient_kind: str,
    recipient_id: str,
    default_msg: str,
) -> dict[str, Any]:
    operation: dict[str, Any] = {
        "operationtype": "0",
        "esc_step_from": "1",
        "esc_step_to": "1",
        "opmessage": {"default_msg": default_msg, "mediatypeid": media_id},
        "opconditions": [],
    }
    if recipient_kind == "group":
        operation["opmessage_grp"] = [{"usrgrpid": recipient_id}]
        operation["opmessage_usr"] = []
    else:
        operation["opmessage_grp"] = []
        operation["opmessage_usr"] = [{"userid": recipient_id}]
    return operation


@dataclass
class Plan:
    changes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    media_creates: list[dict[str, Any]] = field(default_factory=list)
    media_updates: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    user_media: list[dict[str, Any]] | None = None
    action_creates: list[dict[str, Any]] = field(default_factory=list)
    action_updates: list[tuple[str, dict[str, Any]]] = field(default_factory=list)


class ChatOpsConfigurator:
    """Build and apply the small, named ChatOps policy."""

    def __init__(self, api: Any, settings: Settings, media_script: Path = MEDIA_SCRIPT):
        self.api = api
        self.settings = settings
        try:
            self.media_script = media_script.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"Cannot read media type script: {media_script}") from exc

    def inspect(self) -> dict[str, Any]:
        media: dict[str, dict[str, Any] | None] = {}
        for name in TARGET_MEDIA_NAMES:
            result = self.api.call(
                "mediatype.get",
                {
                    "output": "extend",
                    "filter": {"name": name},
                    "selectParameters": "extend",
                },
            )
            media[name] = _unique_by_name(result or [], name, "media type")

        actions: dict[str, dict[str, Any] | None] = {}
        for name in TARGET_ACTION_NAMES:
            result = self.api.call(
                "action.get",
                {
                    "output": "extend",
                    "filter": {"name": name},
                    "selectFilter": "extend",
                    "selectOperations": "extend",
                    "selectRecoveryOperations": "extend",
                    "selectUpdateOperations": "extend",
                },
            )
            actions[name] = _unique_by_name(result or [], name, "action")

        users = self.api.call(
            "user.get",
            {
                "output": "extend",
                "filter": {"username": self.settings.recipient_username},
                "selectMedias": "extend",
            },
        )
        user_matches = [
            item
            for item in users or []
            if _text(item.get("username")) == self.settings.recipient_username
        ]
        if len(user_matches) > 1:
            raise ConfigurationError(
                f"Multiple users have the username {self.settings.recipient_username!r}"
            )
        user = user_matches[0] if user_matches else None

        groups = self.api.call(
            "usergroup.get",
            {"output": "extend", "filter": {"name": self.settings.failover_group}},
        )
        group = _unique_by_name(groups or [], self.settings.failover_group, "user group")
        return {"media": media, "actions": actions, "user": user, "group": group}

    def _media_spec(self) -> dict[str, dict[str, Any]]:
        params = [
            {"name": name, "value": value}
            for name, value in (
                ("EventID", "{EVENT.ID}"),
                ("TriggerID", "{TRIGGER.ID}"),
                ("Host", "{HOST.NAME}"),
                ("Severity", "{EVENT.SEVERITY}"),
                ("Status", "{EVENT.STATUS}"),
                ("Value", "{EVENT.VALUE}"),
                ("Subject", "{ALERT.SUBJECT}"),
                ("Message", "{ALERT.MESSAGE}"),
                ("Item", "{ITEM.NAME1}"),
                ("Timestamp", "{EVENT.DATE} {EVENT.TIME}"),
                ("DR_Escalate", "0"),
                ("URL", self.settings.alert_url),
            )
        ]
        return {
            "Slack DR Trigger": {
                "name": "Slack DR Trigger",
                "type": "1",
                "status": "0",
                "exec_path": "send_slack.sh",
                "exec_params": SCRIPT_EXEC_PARAMS,
            },
            "Slack Failback": {
                "name": "Slack Failback",
                "type": "1",
                "status": "0",
                "exec_path": "send_failback.sh",
                "exec_params": SCRIPT_EXEC_PARAMS,
            },
            "ChatOps_Alert": {
                "name": "ChatOps_Alert",
                "type": "4",
                "status": "0",
                "script": self.media_script,
                "parameters": params,
            },
        }

    def _media_differences(self, current: dict[str, Any], desired: dict[str, Any]) -> list[str]:
        fields = ("name", "type", "status", "exec_path", "exec_params", "script", "parameters")
        differences = []
        for field_name in fields:
            current_value = current.get(field_name)
            desired_value = desired[field_name] if field_name in desired else None
            if field_name == "script":
                differs = _normalise_script(current_value) != _normalise_script(desired_value)
            else:
                differs = field_name in desired and current_value != desired_value
            if differs:
                differences.append(field_name)
        return differences

    def _ensure_operations(
        self,
        action: dict[str, Any],
        phase: str,
        media_id: str,
        recipient_kind: str,
        recipient_id: str,
        default_msg: str,
        plan: Plan,
    ) -> list[dict[str, Any]]:
        operations = [_operation_for_update(item) for item in action.get(phase) or []]
        matches = [index for index, item in enumerate(operations) if _operation_media(item) == media_id]
        if len(matches) > 1:
            plan.errors.append(
                f"{action.get('name', 'action')} has duplicate {phase} operations for media {media_id}"
            )
            return operations

        if len(matches) == 1:
            index = matches[0]
            current = operations[index]
            expected_recipient = (
                ((recipient_id,), ()) if recipient_kind == "group" else ((), (recipient_id,))
            )
            if _operation_recipients(current) != expected_recipient:
                operations[index] = _set_operation_target(
                    current, media_id, recipient_kind, recipient_id
                )
                plan.changes.append(
                    f"update {action['name']} {phase} recipient for media {media_id}"
                )
            return operations

        if len(operations) == 1:
            operations[0] = _set_operation_target(
                operations[0], media_id, recipient_kind, recipient_id
            )
            plan.changes.append(f"bind {action['name']} {phase} to media {media_id}")
            return operations

        if not operations:
            operations.append(_new_operation(media_id, recipient_kind, recipient_id, default_msg))
            plan.changes.append(f"create {action['name']} {phase} operation for media {media_id}")
            return operations

        plan.errors.append(
            f"{action.get('name', 'action')} has multiple unrelated {phase} operations; manual review required"
        )
        return operations

    def _action_plan(
        self,
        action: dict[str, Any] | None,
        name: str,
        media_ids: tuple[str, str] | None,
        user_id: str | None,
        group_id: str | None,
        plan: Plan,
    ) -> None:
        if action is None:
            if media_ids is None or user_id is None or (name == "Cloud_Slack_DR_Trigger" and group_id is None):
                plan.changes.append(f"create action {name} after named dependencies exist")
                return
            if name == "Cloud_Slack_DR_Trigger":
                action_filter = _production_dr_action_filter()
                problem = _new_operation(media_ids[0], "group", group_id, "1")
                problem["esc_step_to"] = "0"
                recovery_operations = []
            else:
                action_filter = {"evaltype": "0", "conditions": []}
                problem = _new_operation(media_ids[2 - 2], "user", user_id, "0")
                recovery_operations = [_new_operation(media_ids[1 - 1], "user", user_id, "0")]
            plan.action_creates.append(
                {
                    "name": name,
                    "eventsource": "0",
                    "status": "0",
                    "esc_period": "60s" if name == "Cloud_Slack_DR_Trigger" else "1h",
                    "filter": action_filter,
                    "operations": [problem],
                    "recovery_operations": recovery_operations,
                }
            )
            plan.changes.append(f"create action {name}")
            return

        if name == "Cloud_Slack_DR_Trigger" and _text(action.get("eventsource")) != "0":
            plan.errors.append(
                "Cloud_Slack_DR_Trigger must be a trigger-event Action (eventsource=0); manual review required"
            )
            return

        expected_filter = (
            _production_dr_action_filter()
            if name == "Cloud_Slack_DR_Trigger"
            else {"evaltype": "0", "eval_formula": "", "formula": "", "conditions": []}
        )
        if _filter_signature(action.get("filter")) != _filter_signature(expected_filter):
            plan.changes.append(f"update {name} event filter")
            action_update = {"filter": expected_filter}
        else:
            action_update = {}

        if name == "Cloud_Slack_DR_Trigger":
            if _text(action.get("status")) != "0":
                action_update["status"] = "0"
                plan.changes.append("enable Cloud_Slack_DR_Trigger after preserving its signed two-admin request path")
            if _text(action.get("esc_period")) != "60s":
                action_update["esc_period"] = "60s"
                plan.changes.append("set Cloud_Slack_DR_Trigger recheck/escalation interval to 60 seconds")

        if media_ids is None or user_id is None or (name == "Cloud_Slack_DR_Trigger" and group_id is None):
            if media_ids is None:
                plan.changes.append(f"bind {name} after named media types exist")
            if user_id is None:
                plan.errors.append(f"recipient user {self.settings.recipient_username!r} is missing")
            if name == "Cloud_Slack_DR_Trigger" and group_id is None:
                plan.errors.append(f"recipient group {self.settings.failover_group!r} is missing")
            return

        if name == "Cloud_Slack_DR_Trigger":
            operations = self._ensure_operations(
                action, "operations", media_ids[0], "group", group_id, "1", plan
            )
            if len(operations) == 1:
                operations[0] = _set_dr_approval_message(operations[0], "Problem", plan)
                if _text(operations[0].get("esc_step_from")) != "1" or _text(operations[0].get("esc_step_to")) != "0":
                    operations[0]["esc_step_from"] = "1"
                    operations[0]["esc_step_to"] = "0"
                    plan.changes.append("repeat the same signed operation every 60 seconds while the problem persists")
            if self.settings.auto_failback_enabled:
                recovery_operations = self._ensure_operations(
                    action, "recovery_operations", media_ids[1], "user", user_id, "0", plan
                )
                if len(recovery_operations) == 1:
                    recovery_operations[0] = _set_dr_approval_message(
                        recovery_operations[0], "Recovery", plan
                    )
            else:
                recovery_operations = []
                if action.get("recovery_operations"):
                    plan.changes.append(
                        "remove automatic Cloud_Slack_DR_Trigger recovery operation; use manual Failback request"
                    )
        else:
            # The action-specific tuple for Action 9 is (ChatOps_Alert,
            # ChatOps_Alert); keeping both references explicit avoids IDs in
            # this policy and makes the desired routing obvious.
            operations = self._ensure_operations(
                action, "operations", media_ids[0], "user", user_id, "0", plan
            )
            recovery_operations = self._ensure_operations(
                action, "recovery_operations", media_ids[0], "user", user_id, "0", plan
            )

        recovery_operations = [
            _recovery_operation_for_update(item) for item in recovery_operations
        ]

        current_operations = [_operation_for_update(item) for item in action.get("operations") or []]
        current_recovery = [
            _recovery_operation_for_update(item)
            for item in action.get("recovery_operations") or []
        ]
        if operations != current_operations:
            action_update["operations"] = operations
        if recovery_operations != current_recovery:
            action_update["recovery_operations"] = recovery_operations
        if action_update:
            plan.action_updates.append((_text(action.get("actionid")), action_update))

    def build_plan(self, state: dict[str, Any]) -> Plan:
        plan = Plan()
        desired_media = self._media_spec()
        media_by_name = state["media"]
        for name, desired in desired_media.items():
            current = media_by_name.get(name)
            if current is None:
                plan.media_creates.append(desired)
                plan.changes.append(f"create media type {name}")
            else:
                differences = self._media_differences(current, desired)
                if differences:
                    fields = {field_name: _copy(desired[field_name]) for field_name in differences}
                    plan.media_updates.append((_text(current.get("mediatypeid")), fields))
                    plan.changes.append(f"update media type {name}: {', '.join(differences)}")

        user = state.get("user")
        group = state.get("group")
        if user is None:
            plan.errors.append(f"recipient user {self.settings.recipient_username!r} is missing")
        if group is None:
            plan.errors.append(f"recipient group {self.settings.failover_group!r} is missing")

        media_ids = {
            name: _text(item.get("mediatypeid"))
            for name, item in media_by_name.items()
            if item is not None and item.get("mediatypeid") is not None
        }
        target_media_ids = (media_ids.get("Slack DR Trigger"), media_ids.get("Slack Failback"), media_ids.get("ChatOps_Alert"))
        if user is not None and all(target_media_ids):
            existing_medias = [_copy(item) for item in user.get("medias") or []]
            proposed_medias = _copy(existing_medias)
            media_specs = (
                (target_media_ids[0], self.settings.failover_sendto),
                (target_media_ids[1], self.settings.failback_sendto),
                (target_media_ids[2], self.settings.alert_sendto),
            )
            for media_id, sendto in media_specs:
                matches = [item for item in proposed_medias if _text(item.get("mediatypeid")) == media_id]
                if len(matches) > 1:
                    plan.errors.append(f"user {self.settings.recipient_username!r} has duplicate media {media_id}")
                    continue
                if not matches:
                    proposed_medias.append(
                        {
                            "mediatypeid": media_id,
                            "sendto": sendto,
                            "active": "0",
                            "severity": "63",
                            "period": "1-7,00:00-24:00",
                        }
                    )
                    plan.changes.append(f"add media {media_id} to user {self.settings.recipient_username}")
                    continue
                current = matches[0]
                expected = {
                    "sendto": sendto,
                    "active": "0",
                    "severity": "63",
                    "period": "1-7,00:00-24:00",
                }
                if any(not _same(current.get(key), value) for key, value in expected.items()):
                    for key, value in expected.items():
                        current[key] = value
                    plan.changes.append(f"update user media {media_id} for {self.settings.recipient_username}")
            if proposed_medias != existing_medias:
                plan.user_media = proposed_medias
        elif user is not None:
            plan.changes.append("bind user media after named media types exist")

        actions = state["actions"]
        action3_ids = (media_ids.get("Slack DR Trigger"), media_ids.get("Slack Failback"))
        action9_ids = (media_ids.get("ChatOps_Alert"), media_ids.get("ChatOps_Alert"))
        user_id = _text(user.get("userid")) if user is not None else None
        group_id = _text(group.get("usrgrpid")) if group is not None else None
        self._action_plan(
            actions.get("Cloud_Slack_DR_Trigger"),
            "Cloud_Slack_DR_Trigger",
            action3_ids if all(action3_ids) else None,
            user_id,
            group_id,
            plan,
        )
        self._action_plan(
            actions.get("ChatOps_Alert_Automation"),
            "ChatOps_Alert_Automation",
            action9_ids if all(action9_ids) else None,
            user_id,
            group_id,
            plan,
        )
        return plan

    def apply_plan(self, plan: Plan) -> None:
        if plan.errors:
            raise ConfigurationError("; ".join(plan.errors))
        for spec in plan.media_creates:
            self.api.call("mediatype.create", spec)
        for media_id, fields in plan.media_updates:
            self.api.call("mediatype.update", {"mediatypeid": media_id, **fields})

        state = self.inspect()
        refreshed_plan = self.build_plan(state)
        if refreshed_plan.errors:
            raise ConfigurationError("; ".join(refreshed_plan.errors))
        if refreshed_plan.user_media is not None:
            user_id = _text(state["user"].get("userid"))
            self.api.call(
                "user.update",
                {"userid": user_id, "medias": _writable_user_medias(refreshed_plan.user_media)},
            )

        state = self.inspect()
        refreshed_plan = self.build_plan(state)
        if refreshed_plan.errors:
            raise ConfigurationError("; ".join(refreshed_plan.errors))
        for payload in refreshed_plan.action_creates:
            self.api.call("action.create", payload)
        for action_id, payload in refreshed_plan.action_updates:
            self.api.call("action.update", {"actionid": action_id, **payload})

    def reconcile(self, apply: bool = False) -> Plan:
        state = self.inspect()
        plan = self.build_plan(state)
        if apply and plan.changes:
            self.apply_plan(plan)
            final = self.build_plan(self.inspect())
            if final.errors or final.changes:
                details = "; ".join(final.errors + final.changes)
                raise ConfigurationError(f"Post-apply verification failed: {details}")
        return plan

    def snapshot(self, api_version: str = "") -> dict[str, Any]:
        state = self.inspect()
        return {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "zabbix_api_version": api_version,
            "media_types": [_redact(state["media"][name]) for name in TARGET_MEDIA_NAMES if state["media"][name]],
            "actions": [_redact(state["actions"][name]) for name in TARGET_ACTION_NAMES if state["actions"][name]],
            "user": _redact(state["user"]),
            "user_group": _redact(state["group"]),
        }


def _redact(value: Any, parent_key: str = "") -> Any:
    secret_key = re.compile(
        r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key)",
        re.IGNORECASE,
    )
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key_text = _text(key)
            if secret_key.search(key_text):
                result[key] = REDACTED
            elif key_text.lower() == "value" and secret_key.search(parent_key):
                result[key] = REDACTED
            else:
                result[key] = _redact(item, key_text)
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, dict) and secret_key.search(_text(item.get("name"))):
                item_copy = _copy(item)
                if "value" in item_copy:
                    item_copy["value"] = REDACTED
                result.append(_redact(item_copy, parent_key))
            else:
                result.append(_redact(item, parent_key))
        return result
    return value


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _backup_before_apply(
    configurator: ChatOpsConfigurator,
    api_version: str,
    directory: Path,
) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"zabbix-chatops-pre-apply-{timestamp}.json"
    _write_json_atomic(path, configurator.snapshot(api_version))
    return path


def _print_plan(plan: Plan) -> None:
    for item in plan.changes:
        print(f"DRIFT: {item}")
    for item in plan.errors:
        print(f"BLOCKED: {item}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="read-only compliance check (default)")
    mode.add_argument("--apply", action="store_true", help="apply only the required API changes")
    parser.add_argument("--export", type=Path, help="write a redacted read-only configuration export")
    parser.add_argument(
        "--env-file",
        help="external environment file containing Zabbix API settings; values are never printed",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=Path("/var/lib/hospital-dr/zabbix-config-backups"),
        help="external directory for --apply pre-change exports",
    )
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args.env_file)
        client = ZabbixClient(settings)
        version = client.authenticate()
        configurator = ChatOpsConfigurator(client, settings)

        if args.export:
            _write_json_atomic(args.export, configurator.snapshot(version))
            print(f"EXPORT PASS: {args.export}")
            return 0

        backup = None
        if args.apply:
            backup = _backup_before_apply(configurator, version, args.backup_dir)
            print(f"BACKUP PASS: {backup}")
        plan = configurator.reconcile(apply=args.apply)
        _print_plan(plan)
        if plan.errors:
            print("APPLY BLOCKED" if args.apply else "CHECK BLOCKED")
            return 1
        if args.apply:
            print("APPLY PASS: desired Zabbix ChatOps configuration verified")
            return 0
        if plan.changes:
            print("CHECK DRIFT: no changes were made; rerun with --apply after review")
            return 2
        print("CHECK PASS: desired Zabbix ChatOps configuration is present")
        return 0
    except (ConfigurationError, ZabbixAPIError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
