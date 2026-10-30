#!/usr/bin/env python3
"""Optional, explicitly enabled registration of AWS DR Active-Agent hosts.

The command only owns hosts tagged ``environment=aws`` and ``dr=true``.  It
does not alter existing On-Prem hosts, actions, media types, or DR approval
conditions.  Continuous AWS server monitoring is currently retired, so
``--apply`` is fail-closed unless ``AWS_ZABBIX_MONITORING_ENABLED=true`` is
explicitly supplied in the process environment or external env file.  Use
``operations/zabbix/retire_decommissioned_monitoring.py`` to remove the
retired hosts safely.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "operations" / "zabbix"))
from configure_chatops import ZabbixClient, _read_env_file, _text, load_settings  # noqa: E402


GROUP_NAME = "AWS DR"
TEMPLATE_CANDIDATES = ("Linux by Zabbix agent active", "Linux by Zabbix agent")
HOSTS = {
    "aws-dr-web": {"name": "aws-dr-web", "ip": "AWS_PUBLIC_IP_REDACTED", "role": "web"},
    "aws-dr-emr": {"name": "aws-dr-emr", "ip": "AWS_PUBLIC_IP_REDACTED", "role": "emr"},
    "aws-dr-db": {"name": "aws-dr-db", "ip": "AWS_PUBLIC_IP_REDACTED", "role": "db"},
}


def _api(client: ZabbixClient, method: str, params: dict[str, Any]) -> Any:
    return client.call(method, params)


def _one(rows: list[dict[str, Any]], field: str, value: str) -> dict[str, Any] | None:
    matches = [row for row in rows if _text(row.get(field)) == value]
    if len(matches) > 1:
        raise RuntimeError(f"multiple Zabbix objects match {field}={value}")
    return matches[0] if matches else None


def discover(client: ZabbixClient) -> dict[str, Any]:
    groups = _api(client, "hostgroup.get", {"output": ["groupid", "name"], "filter": {"name": [GROUP_NAME]}})
    templates = _api(client, "template.get", {"output": ["templateid", "host", "name"], "filter": {"name": list(TEMPLATE_CANDIDATES)}})
    hosts = _api(
        client,
        "host.get",
        {
            "output": ["hostid", "host", "name", "status"],
            "filter": {"host": list(HOSTS)},
            "selectGroups": ["groupid", "name"],
            "selectParentTemplates": ["templateid", "name"],
            "selectInterfaces": ["interfaceid", "ip", "port", "type", "main"],
            "selectTags": "extend",
        },
    )
    return {
        "group": _one(groups, "name", GROUP_NAME),
        "templates": templates or [],
        "hosts": hosts or [],
    }


def _template(discovered: dict[str, Any]) -> dict[str, Any]:
    for name in TEMPLATE_CANDIDATES:
        found = _one(discovered["templates"], "name", name)
        if found:
            return found
    raise RuntimeError("a supported Linux active-agent template is not present")


def _desired_items(role: str) -> list[dict[str, Any]]:
    result = [{"key_": "hospital.dr.health", "name": "AWS DR service health"}]
    if role in {"web", "emr"}:
        result.extend(
            [
                {"key_": "hospital.dr.docker.health", "name": "AWS DR Docker health"},
                {"key_": "hospital.dr.docker.restarts", "name": "AWS DR Docker restart count"},
            ]
        )
    return result


def _ensure_agent_interface(
    client: ZabbixClient,
    hostid: str,
    private_ip: str,
    *,
    apply: bool,
) -> dict[str, Any]:
    """Keep the displayed Agent interface accurate even for active checks.

    Active checks do not use the passive interface for transport, but keeping
    the real private address prevents misleading UI/API state and preserves a
    safe future passive-check contract without opening a listener.
    """

    interfaces = _api(
        client,
        "hostinterface.get",
        {
            "output": ["interfaceid", "ip", "dns", "port", "type", "main", "useip"],
            "hostids": [hostid],
        },
    )
    agent_interfaces = [item for item in interfaces or [] if _text(item.get("type")) == "1"]
    if len(agent_interfaces) > 1:
        raise RuntimeError(f"multiple Agent interfaces found for hostid={hostid}")
    desired = {"ip": private_ip, "dns": "", "port": "10050", "useip": 1, "main": 1}
    if not agent_interfaces:
        if not apply:
            return {"status": "WOULD_CREATE", "ip": private_ip}
        _api(
            client,
            "hostinterface.create",
            {"hostid": hostid, "type": 1, **desired},
        )
        return {"status": "CREATED", "ip": private_ip}

    interface = agent_interfaces[0]
    drift = any(_text(interface.get(key)) != str(value) for key, value in desired.items())
    if not drift:
        return {"status": "EXISTS", "interfaceid": interface["interfaceid"], "ip": private_ip}
    if not apply:
        return {"status": "WOULD_UPDATE", "interfaceid": interface["interfaceid"], "ip": private_ip}
    _api(client, "hostinterface.update", {"interfaceid": interface["interfaceid"], **desired})
    return {"status": "UPDATED", "interfaceid": interface["interfaceid"], "ip": private_ip}


def _ensure_active_items_and_triggers(
    client: ZabbixClient,
    hostid: str,
    technical_name: str,
    role: str,
    *,
    apply: bool,
) -> dict[str, Any]:
    existing_items = _api(
        client,
        "item.get",
        {"output": ["itemid", "key_", "name"], "hostids": [hostid], "filter": {"key_": [item["key_"] for item in _desired_items(role)]}},
    )
    item_by_key = {_text(item.get("key_")): item for item in existing_items or []}
    status = []
    for desired in _desired_items(role):
        key = desired["key_"]
        if key in item_by_key:
            item_id = item_by_key[key]["itemid"]
            item_status = "EXISTS"
        elif not apply:
            item_id = "<would-create>"
            item_status = "WOULD_CREATE"
        else:
            item_id = _api(
                client,
                "item.create",
                {
                    "hostid": hostid,
                    "name": desired["name"],
                    "key_": key,
                    "type": 7,
                    "value_type": 3,
                    "delay": "60s",
                    "history": "7d",
                    "trends": "30d",
                    "status": 0,
                    "tags": [{"tag": "environment", "value": "aws"}, {"tag": "dr", "value": "true"}],
                },
            )["itemids"][0]
            item_status = "CREATED"
        status.append({"key": key, "status": item_status, "itemid": item_id})

    existing_triggers = _api(
        client,
        "trigger.get",
        {"output": ["triggerid", "description", "expression"], "hostids": [hostid]},
    )
    trigger_by_description = {_text(item.get("description")): item for item in existing_triggers or []}
    trigger_description = "AWS DR service health is unhealthy"
    if trigger_description in trigger_by_description:
        trigger_status = "EXISTS"
    elif not apply:
        trigger_status = "WOULD_CREATE"
    else:
        _api(
            client,
            "trigger.create",
            {
                "description": trigger_description,
                "expression": f"last(/{technical_name}/hospital.dr.health)=0",
                "priority": 2,
                "status": 0,
                "tags": [
                    {"tag": "environment", "value": "aws"},
                    {"tag": "dr", "value": "true"},
                    {"tag": "dr_escalate", "value": "0"},
                ],
            },
        )
        trigger_status = "CREATED"
    return {"items": status, "health_trigger": trigger_status}


def reconcile(client: ZabbixClient, *, apply: bool) -> dict[str, Any]:
    discovered = discover(client)
    group = discovered["group"]
    template = _template(discovered)
    if not group and apply:
        group_id = _api(client, "hostgroup.create", {"name": GROUP_NAME})["groupids"][0]
        group = {"groupid": group_id, "name": GROUP_NAME}
    if not group:
        group = {"groupid": "<would-create>", "name": GROUP_NAME}
    result = {"mode": "apply" if apply else "check", "group": GROUP_NAME, "template": template["name"], "hosts": []}
    for technical_name, spec in HOSTS.items():
        existing = _one(discovered["hosts"], "host", technical_name)
        if existing:
            interface_result = _ensure_agent_interface(
                client, existing["hostid"], HOSTS[technical_name]["ip"], apply=apply
            )
            item_result = _ensure_active_items_and_triggers(
                client, existing["hostid"], technical_name, spec["role"], apply=apply
            )
            result["hosts"].append(
                {
                    "host": technical_name,
                    "status": "EXISTS",
                    "hostid": existing["hostid"],
                    "interface": interface_result,
                    **item_result,
                }
            )
            continue
        if not apply:
            result["hosts"].append({"host": technical_name, "status": "WOULD_CREATE"})
            continue
        host_id = _api(
            client,
            "host.create",
            {
                "host": technical_name,
                "name": spec["name"],
                "groups": [{"groupid": group["groupid"]}],
                "templates": [{"templateid": template["templateid"]}],
                "interfaces": [{"type": 1, "main": 1, "useip": 1, "ip": spec["ip"], "dns": "", "port": "10050"}],
                "tags": [
                    {"tag": "environment", "value": "aws"},
                    {"tag": "dr", "value": "true"},
                    {"tag": "role", "value": spec["role"]},
                    {"tag": "dr_escalate", "value": "0"},
                ],
            },
        )["hostids"][0]
        item_result = _ensure_active_items_and_triggers(
            client, host_id, technical_name, spec["role"], apply=True
        )
        result["hosts"].append(
            {
                "host": technical_name,
                "status": "CREATED",
                "hostid": host_id,
                "interface": {"status": "CREATED", "ip": spec["ip"]},
                **item_result,
            }
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default=os.environ.get("ZABBIX_ENV_FILE") or os.environ.get("DR_SECRET_FILE"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--check", action="store_true", help="read-only discovery (the default)")
    args = parser.parse_args(argv)
    try:
        values = _read_env_file(Path(args.env_file)) if args.env_file else {}
        enabled = _text(
            os.environ.get(
                "AWS_ZABBIX_MONITORING_ENABLED",
                values.get("AWS_ZABBIX_MONITORING_ENABLED", "false"),
            )
        ).lower() == "true"
        if args.apply and not enabled:
            print(
                json.dumps(
                    {
                        "mode": "apply",
                        "status": "DISABLED_BY_DESIGN",
                        "reason": "AWS_ZABBIX_MONITORING_RETIRED",
                    },
                    sort_keys=True,
                )
            )
            return 2
        settings = load_settings(args.env_file)
        client = ZabbixClient(settings)
        version = client.authenticate()
        result = reconcile(client, apply=args.apply)
        result["zabbix_version"] = version
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(json.dumps({"status": "BLOCKED", "error": type(exc).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
