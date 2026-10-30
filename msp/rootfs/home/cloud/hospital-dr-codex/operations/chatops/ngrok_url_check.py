#!/usr/bin/env python3
"""Report and remember the ngrok public URL without exposing credentials.

The ngrok agent API is local and unauthenticated by design.  ``--record`` is
used by the systemd unit after startup: it initializes the expected URL and
logs a warning when a later restart receives a different URL.  ``--check`` is
the operator/health-check form and returns non-zero for an unavailable,
uninitialized, or changed URL.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_API_URL = "http://IP_REDACTED:4040/api/tunnels"
DEFAULT_STATE_FILE = "/var/lib/hospital-dr/ngrok_public_url"
PUBLIC_URL_RE = re.compile(r"^https?://[^/\s]+$")


def fetch_public_urls(api_url: str = DEFAULT_API_URL, opener: Any = urllib.request.urlopen) -> list[str]:
    request = urllib.request.Request(api_url, headers={"Accept": "application/json"})
    try:
        with opener(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("ngrok local API is unavailable") from exc
    urls = []
    for tunnel in payload.get("tunnels", []) if isinstance(payload, dict) else []:
        if not isinstance(tunnel, dict):
            continue
        url = str(tunnel.get("public_url", "")).strip()
        if url and PUBLIC_URL_RE.fullmatch(url):
            urls.append(url)
    if not urls:
        raise RuntimeError("ngrok has no public tunnel URL")
    return sorted(set(urls))


def read_expected(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuntimeError("ngrok URL state is unreadable") from exc
    return value or None


def write_expected(path: Path, url: str) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o750)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"{url}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o640)
    finally:
        temporary.unlink(missing_ok=True)


def check_url(urls: list[str], expected: str | None) -> tuple[bool, str]:
    if len(urls) != 1:
        return False, "ngrok exposes more than one public tunnel; callback URL is ambiguous"
    current = urls[0]
    if expected is None:
        return False, f"ngrok URL baseline is not initialized: {current}"
    if current != expected:
        return False, f"ngrok public URL changed: expected {expected}, current {current}"
    return True, f"ngrok public URL unchanged: {current}"


def fetch_with_retry(api_url: str, wait_seconds: int) -> list[str]:
    deadline = time.monotonic() + max(0, wait_seconds)
    while True:
        try:
            return fetch_public_urls(api_url)
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(min(1, max(0, deadline - time.monotonic())))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--record", action="store_true", help="initialize the URL baseline after agent startup")
    mode.add_argument("--check", action="store_true", help="fail if the URL is unavailable or changed")
    parser.add_argument("--api-url", default=os.environ.get("NGROK_API_URL", DEFAULT_API_URL))
    parser.add_argument(
        "--state-file",
        default=os.environ.get("NGROK_URL_STATE_FILE", DEFAULT_STATE_FILE),
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=0,
        help="wait for the local agent API (defaults to 30 seconds for --record)",
    )
    args = parser.parse_args(argv)
    record = args.record or not args.check
    path = Path(args.state_file)
    try:
        wait_seconds = args.wait_seconds if args.wait_seconds > 0 else (30 if record else 0)
        urls = fetch_with_retry(args.api_url, wait_seconds)
        expected = read_expected(path)
        if record and expected is None:
            if len(urls) != 1:
                raise RuntimeError("cannot initialize an ambiguous ngrok URL baseline")
            write_expected(path, urls[0])
            print(f"ngrok public URL baseline recorded: {urls[0]}")
            return 0

        ok, message = check_url(urls, expected)
        if ok:
            print(f"INFO: {message}")
            return 0
        if record:
            print(f"WARNING: {message}; Slack Interactivity URL may require operator update", file=sys.stderr)
            return 0
        print(f"ERROR: {message}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        if record:
            print(f"WARNING: {exc}; current Slack callback URL could not be verified", file=sys.stderr)
            return 0
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
