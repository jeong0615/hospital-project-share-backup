#!/usr/bin/env python3
"""Approved ChatOps adapter for the isolated synthetic AWS MySQL demo."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from operations.failover.chatops_launch_gate import (  # noqa: E402
    LaunchGateError,
    validate_synthetic_demo_launch,
)
from operations.demo import aws_mysql_data_roundtrip as mysql_demo  # noqa: E402


def _emit_blocked(phase: str, reason: str) -> int:
    safe_reason = reason if re.fullmatch(r"[a-z0-9_]{1,96}", reason or "") else "unexpected_error"
    print(f"SYNTHETIC_MYSQL_DEMO=BLOCKED phase={phase} reason={safe_reason}", flush=True)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--request-id", required=True)
    args = parser.parse_args(argv)

    try:
        validate_synthetic_demo_launch(args.database, args.request_id)
    except LaunchGateError as exc:
        return _emit_blocked("GATE", exc.reason)
    except Exception:
        return _emit_blocked("GATE", "unexpected_error")

    try:
        result = mysql_demo._run_demo(reset_existing=True)
    except mysql_demo.MySQLDemoError as exc:
        return _emit_blocked("RUNNER", exc.code)
    except mysql_demo.common.DemoError as exc:
        return _emit_blocked("RUNNER", exc.code)
    except Exception:
        return _emit_blocked("RUNNER", "unexpected_error")

    if not (
        result.get("AWS_MYSQL_FAILOVER") == "PASS"
        and result.get("AWS_MYSQL_FAILBACK") == "PASS"
        and result.get("DATA_A_B") == "PASS"
        and result.get("AWS_INSTANCE_FINAL_STATE") == "stopped"
        and result.get("AWS_TARGET") == mysql_demo.INSTANCE_ID
    ):
        return _emit_blocked("RUNNER", "result_contract_invalid")

    print("SYNTHETIC_MYSQL_DEMO=PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
