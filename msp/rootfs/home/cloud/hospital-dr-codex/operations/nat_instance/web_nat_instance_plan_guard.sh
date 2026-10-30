#!/usr/bin/env bash
set -euo pipefail

# Validate a saved Terraform plan before a Web NAT migration or BLACKHOLE
# recovery apply. The plan may contain only the approved private default-route
# update and the single Web NAT forwarding ingress addition. This guard does
# not run Terraform apply and does not mutate AWS.

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 PLAN_FILE [--allow-none-egress]" >&2
  exit 2
fi
PLAN_FILE="$1"
ALLOW_NONE_EGRESS=0
if [ "${2:-}" = "--allow-none-egress" ]; then
  ALLOW_NONE_EGRESS=1
elif [ "$#" -eq 2 ]; then
  echo "NAT INSTANCE PLAN ERROR: unknown option: $2" >&2
  exit 2
fi
if [ ! -r "$PLAN_FILE" ]; then
  echo "NAT INSTANCE PLAN ERROR: plan file is unreadable: $PLAN_FILE" >&2
  exit 2
fi
if ! command -v terraform >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  echo "NAT INSTANCE PLAN ERROR: terraform and python3 are required." >&2
  exit 2
fi

tmp_plan_json="$(mktemp)"
trap 'rm -f "$tmp_plan_json"' EXIT
if ! terraform show -json "$PLAN_FILE" > "$tmp_plan_json"; then
  echo "NAT INSTANCE PLAN ERROR: terraform could not read the saved plan." >&2
  exit 2
fi

ALLOW_NONE_EGRESS="$ALLOW_NONE_EGRESS" python3 - "$tmp_plan_json" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    plan = json.load(stream)
changes = []
for change in plan.get("resource_changes", []):
    actions = change.get("change", {}).get("actions", [])
    if actions != ["no-op"]:
        changes.append((change.get("address", ""), actions))

route_addresses = {
    # The indexed address is the current count-based resource address. Keep
    # the legacy unindexed spelling for older saved fixtures/state layouts.
    "aws_route.private_internet[0]",
    "aws_route.private_internet",
}
allowed_addresses = route_addresses | {"aws_security_group.web_sg"}
protected_addresses = {
    "aws_nat_gateway.nat_gw",
    "aws_eip.nat_eip",
    "aws_instance.hospital_real_web",
    "aws_instance.doc_server",
    "aws_instance.db_server",
    "aws_eip.web_eip",
}
unexpected = [
    (address, actions) for address, actions in changes if address not in allowed_addresses
]
route_changes = [
    (address, actions) for address, actions in changes if address in route_addresses
]

if unexpected:
    print("NAT INSTANCE PLAN ERROR: unexpected resource changes:", file=sys.stderr)
    for address, actions in unexpected:
        kind = "protected" if address in protected_addresses else "unexpected"
        print(f"- {address}: {','.join(actions)} ({kind})", file=sys.stderr)
    raise SystemExit(1)
if not route_changes:
    print("NAT INSTANCE PLAN ERROR: no private default-route change is present.", file=sys.stderr)
    raise SystemExit(1)

if len(route_changes) != 1:
    print("NAT INSTANCE PLAN ERROR: more than one private default-route change is present.", file=sys.stderr)
    raise SystemExit(1)

address, actions = route_changes[0]
route_change = next(
    change for change in plan.get("resource_changes", [])
    if change.get("address", "") == address
)
change = route_change.get("change", {})
before = change.get("before") or {}
after = change.get("after") or {}
allow_none_egress = os.environ.get("ALLOW_NONE_EGRESS") == "1"

if actions == ["update"]:
    if before.get("nat_gateway_id") != "AWS_RESOURCE_ID_REDACTED" \
        or before.get("network_interface_id") not in (None, "") \
        or after.get("network_interface_id") != "AWS_RESOURCE_ID_REDACTED" \
        or after.get("nat_gateway_id") not in (None, "") \
        or before.get("route_table_id") != "AWS_RESOURCE_ID_REDACTED" \
        or after.get("route_table_id") != "AWS_RESOURCE_ID_REDACTED" \
        or before.get("destination_cidr_block") != "AWS_PUBLIC_IP_REDACTED/0" \
        or after.get("destination_cidr_block") != "AWS_PUBLIC_IP_REDACTED/0":
        print("NAT INSTANCE PLAN ERROR: route is not the approved BLACKHOLE recovery update.", file=sys.stderr)
        raise SystemExit(1)
    for field in set(before) | set(after):
        if field in {"nat_gateway_id", "network_interface_id"}:
            continue
        if before.get(field) != after.get(field):
            print(f"NAT INSTANCE PLAN ERROR: route field changed unexpectedly: {field}", file=sys.stderr)
            raise SystemExit(1)
    route_mode = "WEB_NAT_INSTANCE"
elif actions == ["delete"] and allow_none_egress:
    if before.get("network_interface_id") != "AWS_RESOURCE_ID_REDACTED" \
        or before.get("route_table_id") != "AWS_RESOURCE_ID_REDACTED" \
        or before.get("destination_cidr_block") != "AWS_PUBLIC_IP_REDACTED/0":
        print("NAT INSTANCE PLAN ERROR: no-egress rollback is not from the approved Web route.", file=sys.stderr)
        raise SystemExit(1)
    route_mode = "NONE_EGRESS_ROLLBACK"
else:
    print("NAT INSTANCE PLAN ERROR: route action is not an approved migration action.", file=sys.stderr)
    raise SystemExit(1)


def canonical(value):
    if isinstance(value, dict):
        return tuple(sorted((key, canonical(item)) for key, item in value.items()))
    if isinstance(value, list):
        return tuple(sorted((canonical(item) for item in value), key=repr))
    return value


def rules(value):
    if value in (None, []):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    print("NAT INSTANCE PLAN ERROR: Web security-group ingress shape is invalid.", file=sys.stderr)
    raise SystemExit(1)


def rule_matches(rule, protocol, port, cidr):
    if not isinstance(rule, dict):
        return False
    return (
        str(rule.get("protocol", "")).lower() == protocol
        and str(rule.get("from_port", "")) == str(port)
        and str(rule.get("to_port", "")) == str(port)
        and cidr in (rule.get("cidr_blocks") or [])
    )


def is_approved_nat_ingress(rule):
    if not isinstance(rule, dict):
        return False
    if rule.get("description") != "Private-subnet traffic forwarded by the opt-in Web NAT Instance":
        return False
    if str(rule.get("protocol", "")) != "-1":
        return False
    if str(rule.get("from_port", "")) != "0" or str(rule.get("to_port", "")) != "0":
        return False
    if sorted(rule.get("cidr_blocks") or []) != [
        "IP_REDACTED/24",
        "IP_REDACTED/24",
        "IP_REDACTED/24",
    ]:
        return False
    for key in ("ipv6_cidr_blocks", "prefix_list_ids", "security_groups"):
        if rule.get(key) not in (None, []):
            return False
    return rule.get("self") in (None, False)


sg_changes = [
    change for change in plan.get("resource_changes", [])
    if change.get("address", "") == "aws_security_group.web_sg"
    and change.get("change", {}).get("actions", []) != ["no-op"]
]
if sg_changes:
    if len(sg_changes) != 1 or sg_changes[0].get("change", {}).get("actions") != ["update"]:
        print("NAT INSTANCE PLAN ERROR: Web security-group action is not an in-place update.", file=sys.stderr)
        raise SystemExit(1)
    sg_change = sg_changes[0].get("change", {})
    sg_before = sg_change.get("before") or {}
    sg_after = sg_change.get("after") or {}
    if sg_before.get("vpc_id") != "AWS_RESOURCE_ID_REDACTED" \
        or sg_after.get("vpc_id") != "AWS_RESOURCE_ID_REDACTED":
        print("NAT INSTANCE PLAN ERROR: Web security group is outside the approved VPC.", file=sys.stderr)
        raise SystemExit(1)
    for field in set(sg_before) | set(sg_after):
        if field == "ingress":
            continue
        if canonical(sg_before.get(field)) != canonical(sg_after.get(field)):
            print(f"NAT INSTANCE PLAN ERROR: Web security-group field changed unexpectedly: {field}", file=sys.stderr)
            raise SystemExit(1)

    before_rules = rules(sg_before.get("ingress"))
    after_rules = rules(sg_after.get("ingress"))
    remaining = {}
    for rule in before_rules:
        remaining[canonical(rule)] = remaining.get(canonical(rule), 0) + 1
    additions = []
    for rule in after_rules:
        key = canonical(rule)
        if remaining.get(key, 0):
            remaining[key] -= 1
        else:
            additions.append(rule)
    if any(count for count in remaining.values()):
        print("NAT INSTANCE PLAN ERROR: an existing Web security-group ingress rule was removed or changed.", file=sys.stderr)
        raise SystemExit(1)
    if len(additions) != 1 or not is_approved_nat_ingress(additions[0]):
        print("NAT INSTANCE PLAN ERROR: Web security-group change is not the approved NAT ingress addition.", file=sys.stderr)
        raise SystemExit(1)
    protected_rules = (
        ("udp", 51820, "IP_REDACTED/32"),
        ("udp", 51821, "IP_REDACTED/32"),
        ("tcp", 3306, "IP_REDACTED/32"),
    )
    for protocol, port, cidr in protected_rules:
        if not any(rule_matches(rule, protocol, port, cidr) for rule in before_rules) \
            or not any(rule_matches(rule, protocol, port, cidr) for rule in after_rules):
            print(
                f"NAT INSTANCE PLAN ERROR: protected {protocol}/{port} rule for {cidr} is missing or changed.",
                file=sys.stderr,
            )
            raise SystemExit(1)
    web_sg_mode = "APPROVED_NAT_INGRESS_ONLY"
else:
    web_sg_mode = "NO_SG_CHANGE"

print(f"NAT_INSTANCE_PLAN=PASS")
print(f"ROUTE_RESOURCE={address}")
print(f"ROUTE_ACTIONS={','.join(actions)}")
print(f"ROUTE_MODE={route_mode}")
print(f"WEB_SG_MODE={web_sg_mode}")
print("NAT_GATEWAY_CREATE_PLANNED=NO")
print("NAT_GATEWAY_RECREATE_PLANNED=NO")
print("NAT_GATEWAY_DESTROY=NO")
print("NAT_EIP_DESTROY=NO")
print("NAT_EIP_ALLOCATION_CHANGE=NO")
print("EC2_REPLACEMENT=NO")
print("WEB_EIP_REPLACEMENT=NO")
PY
