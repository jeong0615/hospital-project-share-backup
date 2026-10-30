#!/usr/bin/env bash
set -euo pipefail

# Read-only classifier for a Terraform plan rendered with:
#   terraform show -json <plan-file> > /path/to/plan.json
#
# This command never runs apply and never mutates Terraform state.  It reports
# known operator-owned drift separately so a future reconcile cannot silently
# replace a key pair or change the Web management CIDR.

usage() {
  cat >&2 <<'EOF'
Usage: terraform_drift_check.sh --plan-json PATH

PATH must be the JSON output of `terraform show -json` for a read-only plan.
EOF
}

PLAN_JSON=""
case "${1:-}" in
  --plan-json)
    PLAN_JSON="${2:-}"
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [ -z "$PLAN_JSON" ] || [ ! -f "$PLAN_JSON" ] || [ ! -r "$PLAN_JSON" ]; then
  echo "[TF DRIFT] plan JSON is missing or unreadable: ${PLAN_JSON:-<unset>}" >&2
  exit 2
fi

result="$({
  PLAN_JSON="$PLAN_JSON" python3 - <<'PY'
import json
import os
import sys

path = os.environ["PLAN_JSON"]
try:
    with open(path, encoding="utf-8") as handle:
        plan = json.load(handle)
except (OSError, ValueError) as error:
    print(f"[TF DRIFT] invalid plan JSON: {error}", file=sys.stderr)
    raise SystemExit(2)

changes = []
for resource in plan.get("resource_changes", []):
    change = resource.get("change", {})
    actions = change.get("actions", [])
    if actions != ["no-op"]:
        changes.append(resource)

oidc_state_drift = False
key_pair_mismatch = False
management_cidr_needs_input = False
destructive = []

for resource in changes:
    address = resource.get("address", "")
    change = resource.get("change", {})
    actions = change.get("actions", [])
    before = change.get("before") or {}
    after = change.get("after") or {}

    if address == "aws_iam_role.github_actions_ecr_push":
        oidc_state_drift = True

    if address == "aws_key_pair.dr_key" and "delete" in actions and "create" in actions:
        key_pair_mismatch = True

    if address == "aws_security_group.web_sg":
        before_ingress = before.get("ingress", [])
        after_ingress = after.get("ingress", [])
        if before_ingress != after_ingress:
            management_cidr_needs_input = True

    if "delete" in actions:
        destructive.append(address)

print(f"TERRAFORM_DRIFT_COUNT={len(changes)}")
print(f"OIDC_STATE_DRIFT={'true' if oidc_state_drift else 'false'}")
print(f"KEY_PAIR_MISMATCH={'true' if key_pair_mismatch else 'false'}")
print(f"MANAGEMENT_CIDR_NEEDS_INPUT={'true' if management_cidr_needs_input else 'false'}")
print(f"DESTRUCTIVE_CHANGE_COUNT={len(destructive)}")
for address in destructive:
    print(f"[TF DRIFT] destructive action requires explicit review: {address}")

if oidc_state_drift:
    print("[TF DRIFT] OIDC state/config mismatch requires a planned state reconciliation.")
if key_pair_mismatch:
    print("[TF DRIFT] KEY_PAIR_MISMATCH: owner confirmation is required; no replacement is authorized.")
if management_cidr_needs_input:
    print("[TF DRIFT] MANAGEMENT_CIDR_NEEDS_INPUT: CIDR owner confirmation is required; no SG update is authorized.")

raise SystemExit(1 if changes else 0)
PY
})" || drift_rc=$?
drift_rc="${drift_rc:-0}"
printf '%s\n' "$result"

if [ "$drift_rc" -eq 0 ]; then
  echo "TERRAFORM_DRIFT_CHECK_READY=true"
else
  echo "TERRAFORM_DRIFT_CHECK_READY=false"
fi
exit "$drift_rc"
