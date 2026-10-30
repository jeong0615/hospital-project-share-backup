#!/usr/bin/env python3
"""Fail-closed identity and lifecycle planner for the three existing DR EC2s."""

from __future__ import annotations

import json
import sys


EXPECTED_INSTANCES = {
    "Hospital-Real-Web-Server": ("AWS_RESOURCE_ID_REDACTED", "AWS_PUBLIC_IP_REDACTED"),
    "Hospital-DR-Doc-Server": ("AWS_RESOURCE_ID_REDACTED", "AWS_PUBLIC_IP_REDACTED"),
    "Hospital-DR-DB-Server": ("AWS_RESOURCE_ID_REDACTED", "AWS_PUBLIC_IP_REDACTED"),
}

START_ACTIONS = {
    "running": "none",
    "stopped": "start",
    "pending": "wait-running",
    "stopping": "wait-stopped-then-replan",
}


def plan_instances(response: dict, *, require_running: bool = False) -> list[dict[str, str]]:
    """Validate exact IDs/roles/private IPs and classify states without mutation."""
    instances = [
        instance
        for reservation in response.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]
    by_name: dict[str, list[dict]] = {}
    for instance in instances:
        tags = {tag.get("Key"): tag.get("Value") for tag in instance.get("Tags", [])}
        name = tags.get("Name")
        if name in EXPECTED_INSTANCES:
            by_name.setdefault(name, []).append(instance)

    if set(by_name) != set(EXPECTED_INSTANCES):
        raise ValueError("expected exactly the approved Web, Doc, and DB instances")

    rows: list[dict[str, str]] = []
    for name, (expected_id, expected_ip) in EXPECTED_INSTANCES.items():
        matches = by_name[name]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one instance with role {name}")
        instance = matches[0]
        if instance.get("InstanceId") != expected_id:
            raise ValueError(f"instance ID mismatch for role {name}")
        if instance.get("PrivateIpAddress") != expected_ip:
            raise ValueError(f"private IP mismatch for role {name}")
        state = instance.get("State", {}).get("Name")
        if state not in START_ACTIONS:
            raise ValueError(f"unsafe or unsupported EC2 state for role {name}: {state or 'unknown'}")
        if require_running and state != "running":
            raise ValueError(f"role {name} is not running after the start/wait phase")
        rows.append(
            {
                "role": name,
                "instance_id": expected_id,
                "private_ip": expected_ip,
                "state": state,
                "action": START_ACTIONS[state],
            }
        )
    return rows


def main() -> int:
    require_running = "--require-running" in sys.argv[1:]
    role = ""
    if "--role" in sys.argv[1:]:
        try:
            role_index = sys.argv.index("--role") + 1
            role = sys.argv[role_index]
        except (IndexError, ValueError):
            print("[EC2 START PLAN ERROR] missing role value", file=sys.stderr)
            return 1
        if role not in EXPECTED_INSTANCES:
            print("[EC2 START PLAN ERROR] unknown role filter", file=sys.stderr)
            return 1
    try:
        response = json.load(sys.stdin)
        rows = plan_instances(response, require_running=require_running)
        if role:
            rows = [row for row in rows if row["role"] == role]
            if len(rows) != 1:
                raise ValueError("requested role did not resolve to exactly one approved instance")
    except (json.JSONDecodeError, TypeError, ValueError, KeyError) as error:
        print(f"[EC2 START PLAN ERROR] {error}", file=sys.stderr)
        return 1
    for row in rows:
        print("\t".join(row[key] for key in ("role", "instance_id", "state", "action")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
