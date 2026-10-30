#!/usr/bin/env python3
"""Reconcile the existing Production Zabbix DR health trigger.

The existing HTTP, DB TCP, and SNMP probes sample every 60 seconds. Any one
fresh failed probe raises the tagged Production trigger. ``--check`` is
read-only; ``--apply`` updates and enables only the existing trigger after a
redacted pre-change snapshot, then verifies the live readback. It does not
send Slack messages or change the two-admin ChatOps approval policy.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "operations" / "zabbix"))

from configure_chatops import (  # noqa: E402
    ConfigurationError,
    ZabbixClient,
    ZabbixAPIError,
    _copy,
    _redact,
    _text,
    _write_json_atomic,
    load_settings,
)
from production_dr_policy import (  # noqa: E402
    DB_HEALTH_ITEM_KEY,
    DOC_FAIL_ITEM_KEY,
    DOC_SCENARIO,
    FAILOVER_REQUIRED_FAILED_SAMPLES,
    FAILOVER_STABILITY_SECONDS,
    FAILOVER_STABILITY_WINDOW,
    HEALTH_SAMPLE_INTERVAL_SECONDS,
    HEALTH_SAMPLE_FRESHNESS_SECONDS,
    MAINTENANCE_ITEM_KEY,
    MAINTENANCE_ITEM_NAME,
    MONITORING_MAINTENANCE_HOSTS,
    MONITORING_PATH_ITEM_NAME,
    MONITORING_PATH_TAG,
    ONPREM_SNMP_HOSTS,
    PRODUCTION_TRIGGER_DESCRIPTION,
    PRODUCTION_TRIGGER_TAGS,
    SNMP_AVAILABILITY_ITEM_KEY,
    WEB_FAIL_ITEM_KEY,
    WEB_SCENARIO,
    ZABBIX_SERVER_HOST,
    failover_expression,
    maintenance_state_observation,
    monitoring_path_item_key,
    monitoring_path_observation,
    production_trigger_tags,
)


TARGET_HOSTS = ("web_server", "DB_Server", "Doc_Server")
AGENT_UNAVAILABLE_DESCRIPTION = "Linux: Zabbix agent is not available"
DB_ITEM_NAME = "Hospital DR DB Core TCP health"
MONITORING_PATH_HISTORY = "7d"
AGGREGATE_STATUS_ENABLED = "0"
AGGREGATE_PRIORITY = "4"  # High; Action 3 still requires the explicit tag.
EXPECTED_PRODUCTION_TRIGGER_ID = "24712"
EXPECTED_PRODUCTION_ACTION_ID = "3"


def _one(rows: list[dict[str, Any]], field: str, value: str, label: str) -> dict[str, Any] | None:
    matches = [row for row in rows if _text(row.get(field)) == value]
    if len(matches) > 1:
        raise ConfigurationError(f"Multiple {label} objects match {field}={value!r}")
    return matches[0] if matches else None


def _tag_pairs(tags: list[dict[str, Any]] | None) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((_text(tag.get("tag")), _text(tag.get("value"))) for tag in tags or []))


def _has_tag(tags: list[dict[str, Any]] | None, name: str, value: str) -> bool:
    return (name, value) in _tag_pairs(tags)


def _scenario_payload(hostid: str, spec: dict[str, Any]) -> dict[str, Any]:
    payload = _copy(spec)
    payload["hostid"] = hostid
    return payload


def _scenario_signature(scenario: dict[str, Any]) -> tuple[Any, ...]:
    steps = []
    for step in scenario.get("steps") or []:
        steps.append(
            (
                _text(step.get("name")),
                _text(step.get("url")),
                _text(step.get("status_codes")),
                _text(step.get("no")),
                _text(step.get("timeout")),
                _text(step.get("follow_redirects")),
            )
        )
    return (
        _text(scenario.get("hostid")),
        _text(scenario.get("name")),
        _text(scenario.get("delay")),
        _text(scenario.get("attempts")),
        tuple(steps),
        _tag_pairs(scenario.get("tags")),
    )


def _expected_scenario_signature(hostid: str, spec: dict[str, Any]) -> tuple[Any, ...]:
    return _scenario_signature(_scenario_payload(hostid, spec))


def _item_signature(item: dict[str, Any]) -> tuple[str, ...]:
    return (
        _text(item.get("key_")),
        _text(item.get("type")),
        _text(item.get("value_type")),
        _text(item.get("delay")),
        _text(item.get("status")),
    )


def _health_probe_rows(items: list[dict[str, Any]], hosts: dict[str, dict[str, Any]]) -> list[tuple[dict[str, Any], str]] | None:
    """Resolve each existing health item to its failed value; fail closed on ambiguity."""
    zabbix_id = _text(hosts[ZABBIX_SERVER_HOST].get("hostid"))
    expected = [
        (zabbix_id, WEB_FAIL_ITEM_KEY, "1"),
        (zabbix_id, DOC_FAIL_ITEM_KEY, "1"),
        (zabbix_id, DB_HEALTH_ITEM_KEY, "0"),
    ]
    expected.extend(
        (_text(hosts[name].get("hostid")), SNMP_AVAILABILITY_ITEM_KEY, "0")
        for name in ONPREM_SNMP_HOSTS
    )
    rows: list[tuple[dict[str, Any], str]] = []
    for hostid, key, failed_value in expected:
        matches = [
            item for item in items
            if _text(item.get("hostid")) == hostid and _text(item.get("key_")) == key
        ]
        if len(matches) != 1 or not _text(matches[0].get("itemid")):
            return None
        rows.append((matches[0], failed_value))
    return rows


def _aggregate_conditions_match_policy(
    trigger: dict[str, Any],
    items: list[dict[str, Any]],
    hosts: dict[str, dict[str, Any]],
    *,
    expected_status: str | None = AGGREGATE_STATUS_ENABLED,
) -> bool:
    """Compare the any-one-fresh-probe policy using stable item/function IDs."""
    probes = _health_probe_rows(items, hosts)
    if probes is None:
        return False
    fresh = f"$,{HEALTH_SAMPLE_FRESHNESS_SECONDS}s"
    expected: dict[tuple[str, str, str], tuple[str, str]] = {}
    for item, failed_value in probes:
        itemid = _text(item.get("itemid"))
        expected[(itemid, "last", "$")] = ("=", failed_value)
        expected[(itemid, "nodata", fresh)] = ("=", "0")
    functions = trigger.get("functions") or []
    actual = {
        (_text(row.get("itemid")), _text(row.get("function")), _text(row.get("parameter")))
        for row in functions
    }
    if actual != set(expected):
        return False
    predicates = {
        _text(row.get("functionid")): expected[
            (_text(row.get("itemid")), _text(row.get("function")), _text(row.get("parameter")))
        ]
        for row in functions
        if _text(row.get("functionid"))
    }
    expression = _text(trigger.get("expression"))
    actual_predicates = {
        function_id: (operator, value)
        for function_id, operator, value in re.findall(
            r"\{([^{}]+)\}\s*(>=|<=|=|>|<)\s*(-?\d+)", expression
        )
    }
    operators = re.findall(r"\b(and|or)\b", expression.lower())
    remainder = re.sub(r"\{[^{}]+\}\s*(?:>=|<=|=|>|<)\s*-?\d+", "", expression)
    remainder = re.sub(r"\b(?:and|or)\b", "", remainder, flags=re.IGNORECASE)
    return bool(
        len(predicates) == len(expected)
        and actual_predicates == predicates
        and operators.count("and") == len(probes)
        and operators.count("or") == len(probes) - 1
        and not re.sub(r"[\s()]", "", remainder)
        and _text(trigger.get("recovery_expression")) == ""
        and _text(trigger.get("priority")) == AGGREGATE_PRIORITY
        and (expected_status is None or _text(trigger.get("status")) == expected_status)
        and _tag_pairs(trigger.get("tags")) == _tag_pairs(production_trigger_tags())
    )

def _dependency_ids(trigger: dict[str, Any] | None) -> set[str]:
    return {
        _text(item.get("triggerid"))
        for item in (trigger or {}).get("dependencies") or []
        if _text(item.get("triggerid"))
    }


def _main_agent_interface_id(host: dict[str, Any]) -> str:
    interfaces = [
        item
        for item in host.get("interfaces") or []
        if _text(item.get("type")) == "1" and _text(item.get("main")) == "1"
    ]
    if len(interfaces) != 1:
        raise ConfigurationError(
            f"expected one main Agent interface on {host.get('name', '<unknown>')}"
        )
    return _text(interfaces[0].get("interfaceid"))


def _trigger_signature(trigger: dict[str, Any]) -> tuple[Any, ...]:
    return (
        _text(trigger.get("expression")),
        _text(trigger.get("recovery_expression")),
        _text(trigger.get("priority")),
        _text(trigger.get("status")),
        _tag_pairs(trigger.get("tags")),
    )


@dataclass
class Plan:
    changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ProductionTriggerConfigurator:
    def __init__(
        self,
        api: Any,
        *,
        monitoring_path_ip: str | None = None,
        monitoring_path_port: int | str | None = None,
    ):
        self.api = api
        if (monitoring_path_ip is None) != (monitoring_path_port is None):
            raise ConfigurationError("Monitoring Path IP and port must be supplied together")
        self.monitoring_path_ip = monitoring_path_ip
        self.monitoring_path_port = monitoring_path_port
        try:
            self.monitoring_path_key = (
                monitoring_path_item_key(monitoring_path_ip, monitoring_path_port)
                if monitoring_path_ip is not None
                else None
            )
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc

    def _hosts(self) -> dict[str, dict[str, Any]]:
        names = (*TARGET_HOSTS, *ONPREM_SNMP_HOSTS, ZABBIX_SERVER_HOST)
        rows = self.api.call(
            "host.get",
            {
                "output": ["hostid", "host", "name", "status"],
                "filter": {"name": list(names)},
                "selectInterfaces": ["interfaceid", "type", "main"],
            },
        ) or []
        result: dict[str, dict[str, Any]] = {}
        for name in names:
            result[name] = _one(rows, "name", name, "host")
        return result

    def inspect(self) -> dict[str, Any]:
        hosts = self._hosts()
        zabbix = hosts.get(ZABBIX_SERVER_HOST)
        missing = [
            name
            for name in (*TARGET_HOSTS, ZABBIX_SERVER_HOST)
            if hosts.get(name) is None
        ]
        if missing:
            raise ConfigurationError("missing required Zabbix host(s): " + ", ".join(missing))
        zabbix_id = _text(zabbix["hostid"])

        scenarios = self.api.call(
            "httptest.get",
            {
                "output": "extend",
                "hostids": [zabbix_id],
                "selectSteps": "extend",
                "selectTags": "extend",
            },
        ) or []
        scenario_by_name: dict[str, dict[str, Any] | None] = {}
        for name in (WEB_SCENARIO["name"], DOC_SCENARIO["name"]):
            scenario_by_name[name] = _one(scenarios, "name", name, "web scenario")

        health_host_ids = [
            zabbix_id,
            *(_text(hosts[name]["hostid"]) for name in ONPREM_SNMP_HOSTS),
        ]
        items = self.api.call(
            "item.get",
            {
                "output": ["itemid", "hostid", "name", "key_", "type", "value_type", "delay", "status", "state", "lastclock", "lastvalue"],
                "hostids": health_host_ids,
                "webitems": True,
                "selectTags": "extend",
            },
        ) or []
        host_ids = [_text(hosts[name]["hostid"]) for name in MONITORING_MAINTENANCE_HOSTS]
        maintenance_items = self.api.call(
            "item.get",
            {
                "output": ["itemid", "hostid", "name", "key_", "type", "value_type", "delay", "status", "state", "lastclock", "lastvalue"],
                "hostids": host_ids,
                "filter": {"key_": [MAINTENANCE_ITEM_KEY]},
            },
        ) or []
        existing_item_ids = {_text(item.get("itemid")) for item in items}
        items.extend(
            item for item in maintenance_items
            if _text(item.get("itemid")) not in existing_item_ids
        )

        tagged_path_items = [
            item
            for item in items
            if _has_tag(item.get("tags"), MONITORING_PATH_TAG[0], MONITORING_PATH_TAG[1])
        ]
        monitoring_path_error = ""
        if len(tagged_path_items) > 1:
            monitoring_path_item = None
            monitoring_path_error = "multiple Monitoring Path witness items are configured"
        elif tagged_path_items:
            monitoring_path_item = tagged_path_items[0]
            if (
                self.monitoring_path_key is not None
                and _text(monitoring_path_item.get("key_")) != self.monitoring_path_key
            ):
                monitoring_path_error = "configured Monitoring Path witness does not match the explicit endpoint"
        elif self.monitoring_path_key is not None:
            monitoring_path_item = _one(
                items, "key_", self.monitoring_path_key, "Monitoring Path item"
            )
            if (
                monitoring_path_item is not None
                and _text(monitoring_path_item.get("name")) != MONITORING_PATH_ITEM_NAME
            ):
                monitoring_path_error = "Monitoring Path key collides with an item not owned by this policy"
        else:
            monitoring_path_item = None
            monitoring_path_error = "Monitoring Path IP/port are not configured"

        maintenance_items_by_host: dict[str, dict[str, Any] | None] = {}
        for name in MONITORING_MAINTENANCE_HOSTS:
            expected_hostid = _text(hosts[name]["hostid"])
            matches = [
                item for item in items
                if _text(item.get("hostid")) == expected_hostid
                and _text(item.get("key_")) == MAINTENANCE_ITEM_KEY
            ]
            if len(matches) > 1:
                raise ConfigurationError(f"Multiple maintenance-state items found on {name}")
            maintenance_items_by_host[name] = matches[0] if matches else None

        triggers = self.api.call(
            "trigger.get",
            {
                "output": [
                    "triggerid",
                    "hostid",
                    "description",
                    "expression",
                    "recovery_expression",
                    "priority",
                    "status",
                    "value",
                    "state",
                ],
                "hostids": [zabbix_id],
                "selectTags": "extend",
                "selectDependencies": "extend",
                "selectFunctions": "extend",
            },
        ) or []
        aggregate = _one(triggers, "description", PRODUCTION_TRIGGER_DESCRIPTION, "production trigger")

        agent_triggers: dict[str, dict[str, Any] | None] = {}
        for name in TARGET_HOSTS:
            host = hosts[name]
            rows = self.api.call(
                "trigger.get",
                {
                    "output": ["triggerid", "hostid", "description", "expression", "priority", "status", "value", "state"],
                    "hostids": [_text(host["hostid"])],
                    "filter": {"description": [AGENT_UNAVAILABLE_DESCRIPTION]},
                    "selectTags": "extend",
                    "selectDependencies": "extend",
                },
            ) or []
            agent_triggers[name] = _one(rows, "description", AGENT_UNAVAILABLE_DESCRIPTION, "Agent availability trigger")

        all_escalations = self.api.call(
            "trigger.get",
            {
                "output": ["triggerid", "hostid", "description"],
                "selectTags": "extend",
            },
        ) or []
        return {
            "hosts": hosts,
            "health_host_ids": health_host_ids,
            "scenarios": scenario_by_name,
            "items": items,
            "monitoring_path_item": monitoring_path_item,
            "monitoring_path_key": self.monitoring_path_key,
            "monitoring_path_error": monitoring_path_error,
            "maintenance_items": maintenance_items_by_host,
            "observed_at_epoch": datetime.now(timezone.utc).timestamp(),
            "aggregate": aggregate,
            "agent_triggers": agent_triggers,
            "all_escalations": [
                row for row in all_escalations if _has_tag(row.get("tags"), "DR_Escalate", "1")
            ],
        }

    def build_plan(self, state: dict[str, Any]) -> Plan:
        plan = Plan()
        hosts = state["hosts"]
        zabbix_id = _text(hosts[ZABBIX_SERVER_HOST]["hostid"])
        for spec in (WEB_SCENARIO, DOC_SCENARIO):
            current = state["scenarios"].get(spec["name"])
            expected = _expected_scenario_signature(zabbix_id, spec)
            if current is None:
                plan.errors.append(f"existing health scenario is missing: {spec['name']}")
            elif _scenario_signature(current) != expected:
                plan.changes.append(f"update owned web scenario {spec['name']}")

        items = state["items"]
        items_by_host_key = {
            (_text(item.get("hostid")), _text(item.get("key_"))): item
            for item in items
        }
        expected_delays = {
            WEB_FAIL_ITEM_KEY: _text(WEB_SCENARIO["delay"]),
            DOC_FAIL_ITEM_KEY: _text(DOC_SCENARIO["delay"]),
            DB_HEALTH_ITEM_KEY: f"{HEALTH_SAMPLE_INTERVAL_SECONDS}s",
        }
        for key, expected_delay in expected_delays.items():
            item = items_by_host_key.get((zabbix_id, key))
            if item is None:
                plan.errors.append(f"existing health item is unavailable: {key}")
                continue
            if _text(item.get("delay")) != expected_delay:
                plan.errors.append(f"health item {key} must sample every {expected_delay}")
            if _text(item.get("status")) != "0" or _text(item.get("state")) != "0":
                plan.errors.append(f"health item {key} is disabled or unsupported")

        probes = _health_probe_rows(items, hosts)
        if probes is None:
            plan.errors.append("one or more existing On-Prem health probes are missing or ambiguous")
        else:
            now = float(state.get("observed_at_epoch") or 0)
            for item, _failed_value in probes:
                key = _text(item.get("key_"))
                if _text(item.get("status")) != "0" or _text(item.get("state")) != "0":
                    plan.errors.append(f"health probe is disabled or unsupported: {key}")
                    continue
                if _text(item.get("delay")) not in {"60s", "1m"}:
                    plan.errors.append(f"health probe must sample every 60 seconds: {key}")
                    continue
                try:
                    age = now - int(item.get("lastclock"))
                    value = str(item.get("lastvalue") or "").strip()
                except (TypeError, ValueError, OverflowError):
                    plan.errors.append(f"health probe has no current observation: {key}")
                    continue
                if age < 0 or age > HEALTH_SAMPLE_FRESHNESS_SECONDS:
                    plan.errors.append(f"health probe observation is stale: {key}")
                if value not in {"0", "1"}:
                    plan.errors.append(f"health probe observation is unknown: {key}")

        aggregate = state["aggregate"]
        if aggregate is None:
            plan.errors.append("existing production trigger is missing; refusing to create a new trigger")
        elif not _aggregate_conditions_match_policy(aggregate, items, hosts):
            plan.changes.append(f"update and enable production trigger {PRODUCTION_TRIGGER_DESCRIPTION}")

        if aggregate is not None and _dependency_ids(aggregate):
            plan.changes.append(
                "remove existing production trigger dependencies so a single probe failure is not suppressed"
            )

        aggregate_id = _text(aggregate.get("triggerid")) if aggregate else ""
        for row in state["all_escalations"]:
            trigger_id = _text(row.get("triggerid"))
            description = _text(row.get("description"))
            if trigger_id == aggregate_id or description == PRODUCTION_TRIGGER_DESCRIPTION:
                continue
            plan.errors.append(
                f"unexpected DR_Escalate=1 trigger {trigger_id} ({description}); manual review required"
            )
        return plan

    @staticmethod
    def _scenario_update_payload(hostid: str, current: dict[str, Any] | None, spec: dict[str, Any]) -> dict[str, Any]:
        payload = _scenario_payload(hostid, spec)
        if current is not None:
            # Zabbix 6.0 rejects hostid on httptest.update (the scenario's
            # owning host is immutable through this API operation).
            payload.pop("hostid", None)
            payload = {"httptestid": _text(current["httptestid"]), **payload}
        return payload

    @staticmethod
    def _db_item_payload(hostid: str, interfaceid: str, current: dict[str, Any] | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "hostid": hostid,
            "name": DB_ITEM_NAME,
            "key_": DB_HEALTH_ITEM_KEY,
            "type": 3,
            "value_type": 3,
            "interfaceid": interfaceid,
            "delay": f"{HEALTH_SAMPLE_INTERVAL_SECONDS}s",
            "history": "7d",
            "trends": "30d",
            "status": 0,
            "tags": [
                {"tag": "DR_Policy", "value": "production"},
                {"tag": "DR_Scope", "value": "Hospital-Core"},
            ],
        }
        if current is not None:
            return {"itemid": _text(current["itemid"]), **payload}
        return payload

    @staticmethod
    def _monitoring_path_item_payload(
        hostid: str, interfaceid: str, key: str, current: dict[str, Any] | None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "hostid": hostid,
            "name": MONITORING_PATH_ITEM_NAME,
            "key_": key,
            "type": 3,
            "value_type": 3,
            "interfaceid": interfaceid,
            "delay": f"{HEALTH_SAMPLE_INTERVAL_SECONDS}s",
            "history": MONITORING_PATH_HISTORY,
            "trends": "30d",
            "status": 0,
            "tags": [{"tag": MONITORING_PATH_TAG[0], "value": MONITORING_PATH_TAG[1]}],
        }
        if current is not None:
            return {"itemid": _text(current["itemid"]), **payload}
        return payload

    @staticmethod
    def _maintenance_item_payload(hostid: str, current: dict[str, Any] | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "hostid": hostid,
            "name": MAINTENANCE_ITEM_NAME,
            "key_": MAINTENANCE_ITEM_KEY,
            "type": 5,
            "value_type": 3,
            "delay": f"{HEALTH_SAMPLE_INTERVAL_SECONDS}s",
            "history": "7d",
            "trends": "30d",
            "status": 0,
        }
        if current is not None:
            return {"itemid": _text(current["itemid"]), **payload}
        return payload

    def _prepare_maintenance_items(self, state: dict[str, Any]) -> bool:
        changed = False
        for host_name in MONITORING_MAINTENANCE_HOSTS:
            hostid = _text(state["hosts"][host_name]["hostid"])
            current = (state.get("maintenance_items") or {}).get(host_name)
            if current is not None and _text(current.get("name")) != MAINTENANCE_ITEM_NAME:
                raise ConfigurationError(f"maintenance-state key collides with a non-owned item on {host_name}")
            if current is not None and (
                _text(current.get("type")) != "5"
                or _text(current.get("value_type")) != "3"
            ):
                raise ConfigurationError(f"maintenance-state item type is incompatible on {host_name}")
            needs_update = current is not None and (
                _text(current.get("delay")) != f"{HEALTH_SAMPLE_INTERVAL_SECONDS}s"
                or _text(current.get("status")) != "0"
            )
            if current is None or needs_update:
                self.api.call(
                    "item.update" if current is not None else "item.create",
                    self._maintenance_item_payload(hostid, current),
                )
                changed = True
        return changed

    def _assert_live_production_gates_disabled(self) -> None:
        """Keep isolated monitor-item preparation from changing live escalation."""

        triggers = self.api.call(
            "trigger.get",
            {
                "output": ["triggerid", "description", "status"],
                "triggerids": [EXPECTED_PRODUCTION_TRIGGER_ID],
            },
        ) or []
        actions = self.api.call(
            "action.get",
            {
                "output": ["actionid", "name", "eventsource", "status"],
                "actionids": [EXPECTED_PRODUCTION_ACTION_ID],
            },
        ) or []
        if (
            len(triggers) != 1
            or _text(triggers[0].get("triggerid")) != EXPECTED_PRODUCTION_TRIGGER_ID
            or _text(triggers[0].get("description")) != PRODUCTION_TRIGGER_DESCRIPTION
            or _text(triggers[0].get("status")) != "1"
        ):
            raise ConfigurationError("Trigger 24712 identity/status is not verified disabled; maintenance item write refused")
        if (
            len(actions) != 1
            or _text(actions[0].get("actionid")) != EXPECTED_PRODUCTION_ACTION_ID
            or _text(actions[0].get("name")) != "Cloud_Slack_DR_Trigger"
            or _text(actions[0].get("eventsource")) != "0"
            or _text(actions[0].get("status")) != "1"
        ):
            raise ConfigurationError("Action 3 identity/status is not verified disabled; maintenance item write refused")

    def prepare_maintenance_items_only(self, state: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Prepare only owned maintenance-state items while live escalation is disabled.

        This isolated operation never writes a trigger, action, scenario, or
        Monitoring Path endpoint. Fresh samples are still required before the
        production trigger can be reconciled.
        """

        self._assert_live_production_gates_disabled()
        changed = self._prepare_maintenance_items(state)
        readback = self.inspect()
        items = readback.get("maintenance_items") or {}
        for host_name in MONITORING_MAINTENANCE_HOSTS:
            item = items.get(host_name)
            if (
                item is None
                or _text(item.get("hostid")) != _text(readback["hosts"][host_name].get("hostid"))
                or _text(item.get("name")) != MAINTENANCE_ITEM_NAME
                or _text(item.get("key_")) != MAINTENANCE_ITEM_KEY
                or _text(item.get("type")) != "5"
                or _text(item.get("value_type")) != "3"
                or _text(item.get("delay")) != f"{HEALTH_SAMPLE_INTERVAL_SECONDS}s"
                or _text(item.get("status")) != "0"
            ):
                raise ConfigurationError(f"maintenance-state item readback failed on {host_name}")
        self._assert_live_production_gates_disabled()
        return readback, changed

    def prepare_health_scenarios_only(self, state: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Reconcile only existing owned health scenarios under disabled gates."""

        self._assert_live_production_gates_disabled()
        zabbix_id = _text(state["hosts"][ZABBIX_SERVER_HOST]["hostid"])
        changed = False
        for spec in (WEB_SCENARIO, DOC_SCENARIO):
            current = (state.get("scenarios") or {}).get(spec["name"])
            if current is None:
                raise ConfigurationError(f"owned health scenario is missing: {spec['name']}; creation refused")
            if _scenario_signature(current) != _expected_scenario_signature(zabbix_id, spec):
                self.api.call(
                    "httptest.update",
                    self._scenario_update_payload(zabbix_id, current, spec),
                )
                changed = True
        readback = self.inspect()
        for spec in (WEB_SCENARIO, DOC_SCENARIO):
            current = (readback.get("scenarios") or {}).get(spec["name"])
            if current is None or _scenario_signature(current) != _expected_scenario_signature(
                _text(readback["hosts"][ZABBIX_SERVER_HOST]["hostid"]), spec
            ):
                raise ConfigurationError(f"owned health scenario readback failed: {spec['name']}")
        self._assert_live_production_gates_disabled()
        return readback, changed

    def prepare_monitoring_path(self) -> tuple[dict[str, Any], bool]:
        """Prepare explicit path and host-maintenance witness items only.

        It intentionally does not change a trigger. After preparation, Zabbix
        must collect fresh successful path and normal-maintenance samples
        before ``--apply`` can proceed.
        """

        if self.monitoring_path_key is None:
            raise ConfigurationError("explicit Monitoring Path IP/port are required")
        state = self.inspect()
        if state.get("monitoring_path_error"):
            raise ConfigurationError(state["monitoring_path_error"])
        zabbix = state["hosts"][ZABBIX_SERVER_HOST]
        hostid = _text(zabbix["hostid"])
        current = _one(state["items"], "key_", self.monitoring_path_key, "Monitoring Path item")
        if current is not None:
            if _text(current.get("name")) != MONITORING_PATH_ITEM_NAME:
                raise ConfigurationError("Monitoring Path key collides with a non-owned item")
            if _text(current.get("hostid")) != hostid:
                raise ConfigurationError("Monitoring Path item is not on the Zabbix server host")
            if _text(current.get("type")) != "3" or _text(current.get("value_type")) != "3":
                raise ConfigurationError("Monitoring Path item has an incompatible type; manual review required")
        needs_update = current is not None and (
            _item_signature(current)
            != (
                self.monitoring_path_key,
                "3",
                "3",
                f"{HEALTH_SAMPLE_INTERVAL_SECONDS}s",
                "0",
            )
            or not _has_tag(current.get("tags"), MONITORING_PATH_TAG[0], MONITORING_PATH_TAG[1])
        )
        changed = current is None or needs_update
        if changed:
            interfaceid = _main_agent_interface_id(zabbix)
            payload = self._monitoring_path_item_payload(
                hostid, interfaceid, self.monitoring_path_key, current
            )
            self.api.call("item.update" if current is not None else "item.create", payload)
        readback = self.inspect()
        changed = self._prepare_maintenance_items(readback) or changed
        return self.inspect(), changed

    def _apply_scenarios(self, state: dict[str, Any]) -> None:
        zabbix_id = _text(state["hosts"][ZABBIX_SERVER_HOST]["hostid"])
        for spec in (WEB_SCENARIO, DOC_SCENARIO):
            current = state["scenarios"].get(spec["name"])
            if current is None:
                self.api.call("httptest.create", _scenario_payload(zabbix_id, spec))
            elif _scenario_signature(current) != _expected_scenario_signature(zabbix_id, spec):
                self.api.call("httptest.update", self._scenario_update_payload(zabbix_id, current, spec))

    def _apply_db_item(self, state: dict[str, Any]) -> None:
        zabbix_host = state["hosts"][ZABBIX_SERVER_HOST]
        zabbix_id = _text(zabbix_host["hostid"])
        interfaceid = _main_agent_interface_id(zabbix_host)
        items = {_text(item.get("key_")): item for item in state["items"]}
        current = items.get(DB_HEALTH_ITEM_KEY)
        if current is None:
            self.api.call("item.create", self._db_item_payload(zabbix_id, interfaceid, None))
        elif _item_signature(current) != (
            DB_HEALTH_ITEM_KEY,
            "3",
            "3",
            f"{HEALTH_SAMPLE_INTERVAL_SECONDS}s",
            "0",
        ):
            self.api.call("item.update", self._db_item_payload(zabbix_id, interfaceid, current))

    def _apply_aggregate(self, state: dict[str, Any]) -> None:
        aggregate = state.get("aggregate")
        if aggregate is None:
            raise ConfigurationError("existing production trigger is missing; trigger creation refused")
        probes = _health_probe_rows(state["items"], state["hosts"])
        if probes is None:
            raise ConfigurationError("existing On-Prem health probes are missing or ambiguous")
        now = float(state.get("observed_at_epoch") or 0)
        for item, _failed_value in probes:
            if _text(item.get("status")) != "0" or _text(item.get("state")) != "0":
                raise ConfigurationError(f"health probe is disabled or unsupported: {_text(item.get('key_'))}")
            if _text(item.get("delay")) not in {"60s", "1m"}:
                raise ConfigurationError(f"health probe is not configured for 60-second checks: {_text(item.get('key_'))}")
            try:
                age = now - int(item.get("lastclock"))
                value = str(item.get("lastvalue") or "").strip()
            except (TypeError, ValueError, OverflowError) as exc:
                raise ConfigurationError(f"health probe has no current observation: {_text(item.get('key_'))}") from exc
            if age < 0 or age > HEALTH_SAMPLE_FRESHNESS_SECONDS or value not in {"0", "1"}:
                raise ConfigurationError(f"health probe is stale or unknown: {_text(item.get('key_'))}")
        expression = failover_expression(ZABBIX_SERVER_HOST)
        payload = {
            "description": PRODUCTION_TRIGGER_DESCRIPTION,
            "expression": expression,
            "recovery_expression": "",
            "priority": int(AGGREGATE_PRIORITY),
            "status": int(AGGREGATE_STATUS_ENABLED),
            "tags": production_trigger_tags(),
        }
        if not _aggregate_conditions_match_policy(aggregate, state["items"], state["hosts"]):
            self.api.call("trigger.update", {"triggerid": _text(aggregate["triggerid"]), **payload})

    def _remove_dependencies(self, state: dict[str, Any]) -> None:
        aggregate = state["aggregate"]
        if aggregate is None:
            raise ConfigurationError("production trigger was not present after apply")
        if _dependency_ids(aggregate):
            self.api.call(
                "trigger.deleteDependencies",
                [{"triggerid": _text(aggregate["triggerid"])}],
            )

    def apply(self) -> None:
        state = self.inspect()
        self._apply_scenarios(state)
        state = self.inspect()
        self._apply_db_item(state)
        state = self.inspect()
        self._apply_aggregate(state)
        state = self.inspect()
        self._remove_dependencies(state)

    def snapshot(self, state: dict[str, Any], api_version: str) -> dict[str, Any]:
        return {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "zabbix_api_version": api_version,
            "policy": {
                "trigger": PRODUCTION_TRIGGER_DESCRIPTION,
                "stability_seconds": FAILOVER_STABILITY_SECONDS,
                "stability_window": FAILOVER_STABILITY_WINDOW,
                "health_sample_interval_seconds": HEALTH_SAMPLE_INTERVAL_SECONDS,
                "health_sample_freshness_seconds": HEALTH_SAMPLE_FRESHNESS_SECONDS,
                "web_scenario": WEB_SCENARIO,
                "doc_scenario": DOC_SCENARIO,
                "db_item_key": DB_HEALTH_ITEM_KEY,
                "monitoring_path_gate": {
                    "configured_key": state.get("monitoring_path_key"),
                    "error": state.get("monitoring_path_error") or None,
                    "freshness_seconds": HEALTH_SAMPLE_FRESHNESS_SECONDS,
                },
                "maintenance_gate": {
                    "item_key": MAINTENANCE_ITEM_KEY,
                    "hosts": list(MONITORING_MAINTENANCE_HOSTS),
                    "normal_value": "0",
                    "freshness_seconds": HEALTH_SAMPLE_FRESHNESS_SECONDS,
                },
            },
            "hosts": _redact(state["hosts"]),
            "scenarios": _redact(state["scenarios"]),
            "aggregate": _redact(state["aggregate"]),
            "monitoring_path_item": _redact(state.get("monitoring_path_item")),
            "maintenance_state_items": _redact(state.get("maintenance_items")),
            "agent_triggers": _redact(state["agent_triggers"]),
            "escalation_triggers": _redact(state["all_escalations"]),
        }

    def reconcile(self, *, apply: bool = False) -> tuple[Plan, dict[str, Any]]:
        state = self.inspect()
        plan = self.build_plan(state)
        if apply:
            if plan.errors:
                raise ConfigurationError("; ".join(plan.errors))
            if plan.changes:
                self.apply()
            final_state = self.inspect()
            final_plan = self.build_plan(final_state)
            if final_plan.errors or final_plan.changes:
                detail = "; ".join(final_plan.errors + final_plan.changes)
                raise ConfigurationError(f"post-apply verification failed: {detail}")
            return final_plan, final_state
        return plan, state


def _print_plan(plan: Plan) -> None:
    for change in plan.changes:
        print(f"DRIFT: {change}")
    for warning in plan.warnings:
        print(f"WARN: {warning}")
    for error in plan.errors:
        print(f"BLOCKED: {error}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="read-only compliance check (default)")
    mode.add_argument("--apply", action="store_true", help="apply only owned Zabbix changes")
    mode.add_argument(
        "--prepare-monitoring-path",
        action="store_true",
        help="prepare only an explicit Monitoring Path TCP witness and host-maintenance state items",
    )
    mode.add_argument(
        "--prepare-maintenance-items",
        action="store_true",
        help="prepare only host-maintenance items while Trigger 24712 and Action 3 are verified disabled",
    )
    mode.add_argument(
        "--prepare-health-scenarios",
        action="store_true",
        help="reconcile only existing owned health scenarios while Trigger 24712 and Action 3 are verified disabled",
    )
    parser.add_argument("--monitoring-path-ip", help="site-verified independent path witness IP (literal only)")
    parser.add_argument("--monitoring-path-port", help="site-verified TCP witness port")
    parser.add_argument("--env-file", help="external file containing Zabbix API settings")
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=Path("/var/lib/hospital-dr/zabbix-config-backups"),
        help="external directory for the redacted pre-apply snapshot",
    )
    args = parser.parse_args(argv)
    try:
        if args.prepare_monitoring_path and (
            not args.monitoring_path_ip or not args.monitoring_path_port
        ):
            raise ConfigurationError(
                "--prepare-monitoring-path requires an explicit site-verified IP and TCP port"
            )
        settings = load_settings(args.env_file)
        client = ZabbixClient(settings)
        version = client.authenticate()
        configurator = ProductionTriggerConfigurator(
            client,
            monitoring_path_ip=args.monitoring_path_ip,
            monitoring_path_port=args.monitoring_path_port,
        )
        state = configurator.inspect()
        if args.prepare_monitoring_path:
            backup = args.backup_dir / (
                "zabbix-monitoring-path-pre-apply-"
                + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                + ".json"
            )
            _write_json_atomic(backup, configurator.snapshot(state, version))
            print(f"BACKUP PASS: {backup}")
            prepared_state, changed = configurator.prepare_monitoring_path()
            print("MONITORING_PATH_ITEM=PREPARED" if changed else "MONITORING_PATH_ITEM=UNCHANGED")
            path_item = prepared_state.get("monitoring_path_item")
            key = prepared_state.get("monitoring_path_key") or ""
            healthy, reason = monitoring_path_observation(
                path_item,
                expected_key=key,
                expected_hostid=_text(prepared_state["hosts"][ZABBIX_SERVER_HOST]["hostid"]),
                now_epoch=prepared_state.get("observed_at_epoch"),
            )
            print("MONITORING_PATH_SAMPLE=PASS" if healthy else f"MONITORING_PATH_SAMPLE=WAITING reason={reason}")
            for host_name in MONITORING_MAINTENANCE_HOSTS:
                clear, maintenance_reason = maintenance_state_observation(
                    (prepared_state.get("maintenance_items") or {}).get(host_name),
                    expected_hostid=_text(prepared_state["hosts"][host_name]["hostid"]),
                    now_epoch=prepared_state.get("observed_at_epoch"),
                )
                print(
                    f"MAINTENANCE_STATE[{host_name}]="
                    + ("PASS" if clear else f"WAITING reason={maintenance_reason}")
                )
            print("No trigger or Action was changed.")
            return 0
        if args.prepare_maintenance_items:
            backup = args.backup_dir / (
                "zabbix-maintenance-items-pre-apply-"
                + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                + ".json"
            )
            _write_json_atomic(backup, configurator.snapshot(state, version))
            print(f"BACKUP PASS: {backup}")
            prepared_state, changed = configurator.prepare_maintenance_items_only(state)
            print("MAINTENANCE_ITEMS=PREPARED" if changed else "MAINTENANCE_ITEMS=UNCHANGED")
            for host_name in MONITORING_MAINTENANCE_HOSTS:
                clear, reason = maintenance_state_observation(
                    (prepared_state.get("maintenance_items") or {}).get(host_name),
                    expected_hostid=_text(prepared_state["hosts"][host_name]["hostid"]),
                    now_epoch=prepared_state.get("observed_at_epoch"),
                )
                print(
                    f"MAINTENANCE_STATE[{host_name}]="
                    + ("PASS" if clear else f"WAITING reason={reason}")
                )
            print("No scenario, trigger, Action, or Monitoring Path item was changed.")
            return 0
        if args.prepare_health_scenarios:
            backup = args.backup_dir / (
                "zabbix-health-scenarios-pre-apply-"
                + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                + ".json"
            )
            _write_json_atomic(backup, configurator.snapshot(state, version))
            print(f"BACKUP PASS: {backup}")
            prepared_state, changed = configurator.prepare_health_scenarios_only(state)
            print("HEALTH_SCENARIOS=PREPARED" if changed else "HEALTH_SCENARIOS=UNCHANGED")
            for spec in (WEB_SCENARIO, DOC_SCENARIO):
                scenario = (prepared_state.get("scenarios") or {}).get(spec["name"]) or {}
                print(f"HEALTH_SCENARIO[{spec['name']}]=CONFIGURED status={_text(scenario.get('status'))}")
            print("No trigger, Action, Maintenance Item, or Monitoring Path item was changed.")
            print("Endpoint response health remains unverified until a fresh successful sample is observed.")
            return 0
        if args.apply:
            backup = args.backup_dir / (
                "zabbix-production-dr-pre-apply-"
                + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                + ".json"
            )
            _write_json_atomic(backup, configurator.snapshot(state, version))
            print(f"BACKUP PASS: {backup}")
            plan, _ = configurator.reconcile(apply=True)
        else:
            plan, _ = configurator.reconcile(apply=False)
        _print_plan(plan)
        if plan.errors:
            print("APPLY BLOCKED" if args.apply else "CHECK BLOCKED")
            return 1
        if args.apply:
            print("APPLY PASS: production DR trigger policy verified")
            return 0
        if plan.changes:
            print("CHECK DRIFT: no changes were made; rerun with --apply after review")
            return 2
        print("CHECK PASS: production DR trigger policy is present")
        return 0
    except (ConfigurationError, ZabbixAPIError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
