#!/usr/bin/env python3
"""Validate the explicit, short-lived opt-in for a live DNS-write test."""

from __future__ import annotations

import sys
from datetime import datetime, timezone


MAX_WINDOW_SECONDS = 4 * 60 * 60


def live_dns_test_window_status(
    enabled: str, expires_at: str, *, now: datetime | None = None
) -> str:
    """Return ACTIVE, INACTIVE, or INVALID; never infer permission from it."""
    if enabled != "true":
        return "INACTIVE"
    if not expires_at or expires_at != expires_at.strip():
        return "INVALID"
    try:
        deadline = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if deadline.tzinfo is None or deadline.utcoffset() is None:
            return "INVALID"
        now_utc = now or datetime.now(timezone.utc)
        if now_utc.tzinfo is None or now_utc.utcoffset() is None:
            return "INVALID"
        remaining = (deadline.astimezone(timezone.utc) - now_utc.astimezone(timezone.utc)).total_seconds()
    except (OverflowError, TypeError, ValueError):
        return "INVALID"
    if not 0 < remaining <= MAX_WINDOW_SECONDS:
        return "INVALID"
    return "ACTIVE"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("Usage: validate_live_dns_test_window.py <true|false> <expiry>", file=sys.stderr)
        return 2
    status = live_dns_test_window_status(argv[1], argv[2])
    print(status)
    return 0 if status != "INVALID" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
