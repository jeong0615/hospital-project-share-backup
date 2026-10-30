#!/usr/bin/env python3
"""Forward one Wazuh alert file to the local ChatOps security endpoint.

This is intended for an explicitly installed Wazuh custom integration.  It
does not contain credentials, does not execute active response, and never
prints the alert body.  Installation into the external Wazuh named volume is
an operational step and is deliberately not performed by this repository
helper.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests


def load_alert(path):
    with open(path, "r", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError("Wazuh alert payload must be a JSON object")
    return payload


def forward(path, endpoint, timeout=5):
    payload = load_alert(path)
    response = requests.post(endpoint, json=payload, timeout=timeout)
    if not 200 <= response.status_code < 300:
        raise RuntimeError(f"ChatOps returned HTTP {response.status_code}")
    return response.status_code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("alert_file")
    parser.add_argument(
        "--endpoint",
        default=os.environ.get("WAZUH_CHATOPS_ENDPOINT", "http://AWS_PUBLIC_IP_REDACTED:5000/wazuh/alert"),
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        forward(args.alert_file, args.endpoint, args.timeout)
    except (OSError, ValueError, requests.RequestException, RuntimeError) as exc:
        print(f"wazuh-chatops integration failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
