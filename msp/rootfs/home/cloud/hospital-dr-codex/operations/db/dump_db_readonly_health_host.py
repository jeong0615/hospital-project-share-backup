#!/usr/bin/env python3
"""Remote isolated-DB controls for Dump read-only app health validation."""

from __future__ import annotations

import argparse
import json
import sys

try:
    from .isolated_db_service_host import (
        RestoreError,
        record_readonly_health_receipt,
        relock_readonly_health_accounts,
        revoke_readonly_health_receipt,
        unlock_readonly_health_accounts,
        verify_existing_readonly_health_state,
        verify_readonly_health_preconditions,
    )
except ImportError:  # pragma: no cover - deployed as a standalone remote script
    from isolated_db_service_host import (
        RestoreError,
        record_readonly_health_receipt,
        relock_readonly_health_accounts,
        revoke_readonly_health_receipt,
        unlock_readonly_health_accounts,
        verify_existing_readonly_health_state,
        verify_readonly_health_preconditions,
    )


def _common(parser):
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--private-ip", required=True)
    parser.add_argument("--data-volume-id", required=True)
    parser.add_argument("--stage-volume-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--backup-id", required=True)
    parser.add_argument("--promotion-id", required=True)
    parser.add_argument("--cutover-id", required=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight")
    _common(preflight)
    public_ready = sub.add_parser("verify-public-readiness")
    _common(public_ready)
    unlock = sub.add_parser("unlock-readonly-health")
    _common(unlock)
    lock = sub.add_parser("lock-readonly-health")
    for name in ("instance-id", "private-ip", "data-volume-id", "stage-volume-id", "promotion-id", "cutover-id"):
        lock.add_argument(f"--{name}", required=True)
    revoke = sub.add_parser("revoke-readonly-health-receipt")
    revoke.add_argument("--promotion-id", required=True)
    revoke.add_argument("--cutover-id", required=True)
    record = sub.add_parser("record-readonly-health")
    _common(record)
    record.add_argument("--expected-db-server-uuid", required=True)
    record.add_argument("--apps-json", required=True)
    args = parser.parse_args(argv)
    base = {
        "expected_instance_id": args.instance_id,
        "expected_private_ip": args.private_ip,
        "expected_data_volume_id": args.data_volume_id,
        "expected_stage_volume_id": args.stage_volume_id,
    }
    try:
        if args.command in {"preflight", "unlock-readonly-health", "verify-public-readiness"}:
            values = {
                **base,
                "expected_sha256": args.expected_sha256,
                "expected_backup_id": args.backup_id,
                "promotion_id": args.promotion_id,
                "cutover_id": args.cutover_id,
            }
            result = (
                verify_readonly_health_preconditions(**values)
                if args.command == "preflight"
                else (
                    verify_existing_readonly_health_state(**values)
                    if args.command == "verify-public-readiness"
                    else unlock_readonly_health_accounts(**values)
                )
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
            return 0
        if args.command == "lock-readonly-health":
            result = relock_readonly_health_accounts(
                **base, promotion_id=args.promotion_id, cutover_id=args.cutover_id
            )
            print("DUMP_READONLY_DB_ACCOUNTS=LOCKED_VERIFIED", flush=True)
            return 0
        if args.command == "revoke-readonly-health-receipt":
            revoke_readonly_health_receipt(
                promotion_id=args.promotion_id, cutover_id=args.cutover_id
            )
            print("DUMP_READONLY_HEALTH_RECEIPT=REVOKED", flush=True)
            return 0
        try:
            apps = json.loads(args.apps_json)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RestoreError("READONLY_HEALTH_APP_RECEIPT_INVALID") from exc
        result = record_readonly_health_receipt(
            **base,
            expected_sha256=args.expected_sha256,
            expected_backup_id=args.backup_id,
            promotion_id=args.promotion_id,
            cutover_id=args.cutover_id,
            expected_db_server_uuid=args.expected_db_server_uuid,
            apps=apps,
        )
        print(
            "DUMP_READONLY_HEALTH_RECEIPT=APPS_READONLY_HEALTH_VERIFIED_NOT_DNS_AUTHORIZED "
            "dns_authorized=false application_writes_allowed=false",
            flush=True,
        )
        return 0
    except RestoreError as exc:
        print(f"DUMP_READONLY_HEALTH=BLOCKED reason={exc.code}", file=sys.stderr, flush=True)
        return 1
    except (OSError, ValueError, TypeError):
        print("DUMP_READONLY_HEALTH=BLOCKED reason=READONLY_HEALTH_CHECK_UNAVAILABLE", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
