#!/usr/bin/env python3
"""Synthetic-only HTTPS source-IP echo endpoint. No request/access logging."""
from __future__ import annotations

import argparse
import ipaddress
import json
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PATH = "/v1/source-ip"


def _config(source_file: Path) -> str:
    value = source_file.read_text(encoding="ascii").strip()
    if value == "DISABLED":
        raise ValueError("SOURCE_DISABLED")
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global:
        raise ValueError("SOURCE_INVALID")
    return str(address)


def _tls_check(domain: str, certificate: Path, private_key: Path) -> tuple[bool, bool]:
    host = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-checkhost", domain],
        capture_output=True, text=True, timeout=5, check=False,
    )
    expiry = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-checkend", "604800"],
        capture_output=True, text=True, timeout=5, check=False,
    )
    start = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-startdate"],
        capture_output=True, text=True, timeout=5, check=False,
    )
    key_pub = subprocess.run(
        ["openssl", "pkey", "-passin", "pass:", "-in", str(private_key), "-pubout", "-outform", "DER"],
        capture_output=True, timeout=5, check=False,
    )
    # Compare canonical public-key DER without exposing any material.
    cert_result = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
        capture_output=True, timeout=5, check=False,
    )
    cert_der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input=cert_result.stdout,
        capture_output=True, timeout=5, check=False,
    )
    matched = (
        cert_result.returncode == 0 and cert_der.returncode == 0 and key_pub.returncode == 0
        and cert_der.stdout == key_pub.stdout
    )
    not_before_valid = False
    if start.returncode == 0:
        try:
            not_before_valid = ssl.cert_time_to_seconds(start.stdout.strip().removeprefix("notBefore=")) <= time.time()
        except (OverflowError, ValueError):
            not_before_valid = False
    return host.returncode == 0 and expiry.returncode == 0 and not_before_valid, matched


class Handler(BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        expected_host = self.server.probe_domain
        allowed_source = self.server.allowed_source
        if self.path != PATH or self.headers.get("Host", "").lower() not in {expected_host, f"{expected_host}:443"}:
            self._empty(404)
            return
        if self.client_address[0] != allowed_source:
            self._empty(403)
            return
        body = json.dumps({"source_ipv4": self.client_address[0]}, separators=(",", ":")).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self._empty(405)

    do_PUT = do_POST
    do_DELETE = do_POST


def self_check(domain: str, source_file: Path, certificate: Path, private_key: Path, expected_source: str) -> dict[str, object]:
    try:
        source = _config(source_file)
    except (OSError, ValueError):
        source = None
    try:
        hostname_valid, key_matches = _tls_check(domain, certificate, private_key)
    except (OSError, subprocess.SubprocessError):
        hostname_valid, key_matches = False, False
    try:
        key_mode = private_key.stat().st_mode & 0o777 == 0o640
        cert_mode = certificate.stat().st_mode & 0o777 == 0o640
        source_mode = source_file.stat().st_mode & 0o777 == 0o400
    except OSError:
        key_mode = cert_mode = source_mode = False
    return {
        "source_allowlist_configured": source is not None,
        "source_allowlist_matches_expected": source == expected_source,
        "certificate_hostname_and_expiry_valid": hostname_valid,
        "certificate_private_key_match": key_matches,
        "certificate_permissions_valid": cert_mode and key_mode and source_mode,
    }


def serve(domain: str, source_file: Path, certificate: Path, private_key: Path) -> None:
    allowed = _config(source_file)
    hostname_valid, key_matches = _tls_check(domain, certificate, private_key)
    if not hostname_valid or not key_matches:
        raise ValueError("TLS_CONFIGURATION_INVALID")
    server = ThreadingHTTPServer(("IP_REDACTED", 443), Handler)
    server.probe_domain = domain.lower()
    server.allowed_source = allowed
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(private_key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--serve", action="store_true")
    mode.add_argument("--self-check", action="store_true")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--allowed-source-file", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--expected-source", required=False, default="")
    args = parser.parse_args(argv)
    if args.self_check:
        report = self_check(args.domain, args.allowed_source_file, args.certificate, args.private_key, args.expected_source)
        print(json.dumps(report, sort_keys=True))
        return 0 if all(report.values()) else 1
    try:
        serve(args.domain, args.allowed_source_file, args.certificate, args.private_key)
    except Exception as exc:  # Keep key/cert paths and exception details out of logs.
        print(type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
