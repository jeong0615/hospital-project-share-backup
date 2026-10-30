#!/usr/bin/env python3
"""Safely retire the obsolete ChatOps test host and AWS Zabbix hosts.

This command owns only two exact, decommissioned object sets:

* ``DR-CHATOPS-TEST`` and its ``DR TEST:`` triggers; and
* ``aws-dr-web``, ``aws-dr-emr``, and ``aws-dr-db`` when they are tagged
  ``environment=aws`` and ``dr=true`` and belong to ``AWS DR``.

``--check`` is read-only.  ``--apply`` requires an explicit target and
``--confirm``.  No Slack, AWS, Grafana, Wazuh, On-Prem, or production DR
objects are touched.  The script intentionally does not delete the empty
``AWS DR`` host group because that is harmless metadata and may be reused by a
future, separately reviewed monitoring design.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "operations" / "zabbix"))

from configure_chatops import (  # noqa: E402
    ConfigurationError,
    ZabbixClient,
    _text,
    load_settings,
)


TEST_HOST = "DR-CHATOPS-TEST"
TEST_TRIGGER_PREFIX = "DR TEST:"
AWS_GROUP = "AWS DR"
AWS_HOSTS = ("aws-dr-web", "aws-dr-emr", "aws-dr-db")


def _tag_value(tags: list[dict[str, Any]] | None, name: str) -> str:
    values = {_text(item.get("value")) for item in tags or [] if _text(item.get("tag")) == name}
    if len(values) > 1:
        raise ConfigurationError(f"multiple values found for tag {name!r}")
    return next(iter(values), "")


def _group_names(groups: list[dict[str, Any]] | None) -> set[str]:
    return {_text(item.get("name")) for item in groups or []}


def discover_test_host(api: Any) -> dict[str, Any]:
    rows = api.call(
        "host.get",
        {
            "output": ["hostid", "host", "name", "status"],
            "filter": {"name": [TEST_HOST]},
            "selectGroups": ["groupid", "name"],
            "selectTags": "extend",
        },
    ) or []
    if len(rows) > 1:
        raise ConfigurationError(f"multiple hosts named {TEST_HOST!r}")
    if not rows:
        return {"status": "ABSENT", "host": TEST_HOST, "triggers": []}
    host = rows[0]
    triggers = api.call(
        "trigger.get",
        {
            "output": ["triggerid", "hostid", "description", "status"],
            "hostids": [_text(host["hostid"])],
            "selectTags": "extend",
        },
    ) or []
    unsafe = [
        _text(row.get("description"))
        for row in triggers
        if not _text(row.get("description")).startswith(TEST_TRIGGER_PREFIX)
    ]
    return {
        "status": "READY_TO_RETIRE" if not unsafe else "BLOCKED",
        "host": TEST_HOST,
        "hostid": _text(host.get("hostid")),
        "groups": sorted(_group_names(host.get("groups"))),
        "trigger_count": len(triggers),
        "unsafe_triggers": unsafe,
    }


def discover_aws_hosts(api: Any) -> dict[str, Any]:
    rows = api.call(
        "host.get",
        {
            "output": ["hostid", "host", "name", "status"],
            "filter": {"host": list(AWS_HOSTS)},
            "selectGroups": ["groupid", "name"],
            "selectTags": "extend",
        },
    ) or []
    by_name: dict[str, list[dict[str, Any]]] = {name: [] for name in AWS_HOSTS}
    for row in rows:
        name = _text(row.get("host"))
        if name in by_name:
            by_name[name].append(row)
    result: dict[str, Any] = {"group": AWS_GROUP, "hosts": []}
    for name in AWS_HOSTS:
        matches = by_name[name]
        if len(matches) > 1:
            raise ConfigurationError(f"multiple hosts named {name!r}")
        if not matches:
            result["hosts"].append({"host": name, "status": "ABSENT"})
            continue
        row = matches[0]
        groups = _group_names(row.get("groups"))
        valid = (
            AWS_GROUP in groups
            and _tag_value(row.get("tags"), "environment") == "aws"
            and _tag_value(row.get("tags"), "dr") == "true"
        )
        result["hosts"].append(
            {
                "host": name,
                "hostid": _text(row.get("hostid")),
                "status": "READY_TO_RETIRE" if valid else "BLOCKED",
                "groups": sorted(groups),
                "tag_environment": _tag_value(row.get("tags"), "environment"),
                "tag_dr": _tag_value(row.get("tags"), "dr"),
            }
        )
    return result


def _assert_retirable_test(discovery: dict[str, Any]) -> None:
    if discovery["status"] == "ABSENT":
        return
    if discovery["status"] != "READY_TO_RETIRE":
        raise ConfigurationError(
            f"{TEST_HOST} is not a test-only host; unsafe triggers={discovery.get('unsafe_triggers', [])}"
        )


def _assert_retirable_aws(discovery: dict[str, Any]) -> None:
    blocked = [row["host"] for row in discovery["hosts"] if row["status"] == "BLOCKED"]
    if blocked:
        raise ConfigurationError("AWS host safety contract failed: " + ", ".join(blocked))


def apply_test_host(api: Any, discovery: dict[str, Any]) -> None:
    _assert_retirable_test(discovery)
    if discovery["status"] == "ABSENT":
        return
    api.call("host.delete", [discovery["hostid"]])


def apply_aws_hosts(api: Any, discovery: dict[str, Any]) -> None:
    _assert_retirable_aws(discovery)
    ids = [row["hostid"] for row in discovery["hosts"] if row["status"] == "READY_TO_RETIRE"]
    if ids:
        api.call("host.delete", ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", help="external file containing Zabbix API settings")
    parser.add_argument("--check", action="store_true", help="read-only inspection (default)")
    parser.add_argument("--apply", action="store_true", help="delete only the selected exact object set")
    parser.add_argument("--target", choices=("chatops-test", "aws-zabbix"), required=True)
    parser.add_argument("--confirm", action="store_true", help="required with --apply")
    args = parser.parse_args(argv)
    if args.apply and not args.confirm:
        parser.error("--apply requires --confirm")
    if not args.apply:
        args.check = True
    try:
        settings = load_settings(args.env_file)
        client = ZabbixClient(settings)
        version = client.authenticate()
        if args.target == "chatops-test":
            discovery = discover_test_host(client)
            if args.apply:
                apply_test_host(client, discovery)
                discovery = discover_test_host(client)
        else:
            discovery = discover_aws_hosts(client)
            if args.apply:
                apply_aws_hosts(client, discovery)
                discovery = discover_aws_hosts(client)
        if args.apply and args.target == "chatops-test" and discovery["status"] != "ABSENT":
            raise ConfigurationError("post-delete verification failed for DR-CHATOPS-TEST")
        if args.apply and args.target == "aws-zabbix":
            remaining = [row["host"] for row in discovery["hosts"] if row["status"] != "ABSENT"]
            if remaining:
                raise ConfigurationError("post-delete verification failed: " + ", ".join(remaining))
        print(json.dumps({"target": args.target, "mode": "apply" if args.apply else "check", "zabbix_version": version, "result": discovery}, sort_keys=True))
        return 0
    except (ConfigurationError, OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"status": "BLOCKED", "error": type(exc).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
