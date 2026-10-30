#!/usr/bin/env python3
"""Manage the Dump-only HTTP(S) ingress fence using nftables.

The default mode is a strict deny.  The optional prepared mode permits only
Cloudflare IPv4 -> Web:443 or the fixed Web private IP -> EMR:80, and keeps a
final drop for every other non-loopback HTTP(S) packet.  DNS and DB state are
outside this helper's scope.
"""

from __future__ import annotations

import argparse
import ipaddress
import subprocess
import sys
import uuid
from typing import Callable


TABLE = "hospital_dr_dump_readonly"
CHAIN = "input"
RULE_MARKER = "hospital-dr-dump-readonly-fence"
EXPECTED_RULE = (
    'iifname != "lo" tcp dport { 80, 443 } drop '
    f'comment "{RULE_MARKER}"'
)
PREPARED_MARKER_PREFIX = "hospital-dr-dump-readiness"
SERVICE_MARKER_PREFIX = "hospital-dr-dump-service"
SERVICE_AUTH_ROOT = "/var/lib/hospital-dr-dump-service-fence"
WEB_PRIVATE_IP = "IP_REDACTED"
STRICT_DROP_RULE = EXPECTED_RULE


class FenceError(RuntimeError):
    """A stable, non-secret firewall-fence error."""


def _run(command: list[str], *, runner: Callable = subprocess.run, input_text: str | None = None):
    try:
        return runner(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise FenceError("NFTABLES_UNAVAILABLE") from exc


def _validate_table(text: str) -> None:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or lines[0] != f"table inet {TABLE} {{" or lines[-1] != "}":
        raise FenceError("EXTERNAL_FENCE_TABLE_MISMATCH")
    chain_lines = [line for line in lines if line == f"chain {CHAIN} {{"]
    hook_lines = [line for line in lines if line.startswith("type filter hook ")]
    rules = [line for line in lines if RULE_MARKER in line]
    allowed = {
        f"table inet {TABLE} {{",
        f"chain {CHAIN} {{",
        "type filter hook input priority -300; policy accept;",
        "type filter hook input priority raw; policy accept;",
        EXPECTED_RULE,
        "}",
    }
    if (
        len(chain_lines) != 1
        or len(hook_lines) != 1
        or hook_lines[0] not in {
            "type filter hook input priority -300; policy accept;",
            "type filter hook input priority raw; policy accept;",
        }
        or len(rules) != 1
        or rules[0] != EXPECTED_RULE
        or any(line not in allowed for line in lines)
    ):
        raise FenceError("EXTERNAL_FENCE_TABLE_MISMATCH")


def _canonical_cutover_id(value: str) -> str:
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise FenceError("CUTOVER_ID_INVALID") from exc
    if canonical != value.lower():
        raise FenceError("CUTOVER_ID_INVALID")
    return canonical


def validate_cloudflare_ipv4_cidrs(values: list[str]) -> tuple[str, ...]:
    if not values:
        raise FenceError("CLOUDFLARE_IPV4_RANGES_REQUIRED")
    networks = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise FenceError("CLOUDFLARE_IPV4_RANGE_INVALID") from exc
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or network.prefixlen < 8
            or network.network_address.is_private
            or network.network_address.is_loopback
            or network.network_address.is_link_local
            or network.network_address.is_multicast
            or network.network_address.is_reserved
        ):
            raise FenceError("CLOUDFLARE_IPV4_RANGE_UNSAFE")
        networks.append(str(network))
    if len(set(networks)) != len(networks):
        raise FenceError("CLOUDFLARE_IPV4_RANGE_DUPLICATE")
    return tuple(sorted(networks, key=lambda item: (ipaddress.ip_network(item).network_address, ipaddress.ip_network(item).prefixlen)))


def _prepared_rules(*, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str]) -> list[str]:
    if role not in {"web", "emr"}:
        raise FenceError("APP_ROLE_INVALID")
    operation_id = _canonical_cutover_id(cutover_id)
    cidrs = validate_cloudflare_ipv4_cidrs(cloudflare_ipv4_cidrs)
    rules = []
    if role == "web":
        rules.extend(
            f'iifname != "lo" ip saddr {cidr} tcp dport 443 accept '
            f'comment "{PREPARED_MARKER_PREFIX}:{operation_id}:web-cloudflare"'
            for cidr in cidrs
        )
    else:
        rules.append(
            f'iifname != "lo" ip saddr {WEB_PRIVATE_IP} tcp dport 80 accept '
            f'comment "{PREPARED_MARKER_PREFIX}:{operation_id}:web-to-emr"'
        )
    rules.append(
        f'iifname != "lo" tcp dport {{ 80, 443 }} drop '
        f'comment "{PREPARED_MARKER_PREFIX}:{operation_id}:drop-other-http"'
    )
    return rules


def _expected_table_lines(rules: list[str]) -> set[str]:
    return {
        f"table inet {TABLE} {{",
        f"chain {CHAIN} {{",
        "type filter hook input priority -300; policy accept;",
        *rules,
        "}",
    }


def _service_rules(*, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str]) -> list[str]:
    """The durable service policy is the same narrow ingress, with its own owner marker."""
    operation_id = _canonical_cutover_id(cutover_id)
    cidrs = validate_cloudflare_ipv4_cidrs(cloudflare_ipv4_cidrs)
    if role not in {"web", "emr"}:
        raise FenceError("APP_ROLE_INVALID")
    rules = []
    if role == "web":
        rules.extend(
            f'iifname != "lo" ip saddr {cidr} tcp dport 443 accept '
            f'comment "{SERVICE_MARKER_PREFIX}:{operation_id}:web-cloudflare"'
            for cidr in cidrs
        )
    else:
        rules.append(
            f'iifname != "lo" ip saddr {WEB_PRIVATE_IP} tcp dport 80 accept '
            f'comment "{SERVICE_MARKER_PREFIX}:{operation_id}:web-to-emr"'
        )
    rules.append(
        f'iifname != "lo" tcp dport {{ 80, 443 }} drop '
        f'comment "{SERVICE_MARKER_PREFIX}:{operation_id}:drop-other-http"'
    )
    return rules


def validate_service_authorization(
    record: object, *, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str]
) -> None:
    """Validate the root-created durable authorization consumed by systemd at boot."""
    normalized = _canonical_cutover_id(cutover_id)
    cidrs = list(validate_cloudflare_ipv4_cidrs(cloudflare_ipv4_cidrs))
    if not isinstance(record, dict) or record != {
        "status": "DUMP_SERVICE_FENCE_ACTIVE",
        "role": role,
        "cutover_id": normalized,
        "cloudflare_ipv4_cidrs": cidrs,
    }:
        raise FenceError("SERVICE_FENCE_AUTHORIZATION_INVALID")


def _read_service_authorization(
    path: str, *, owner_uid: int, role: str, cutover_id: str,
    cloudflare_ipv4_cidrs: list[str],
) -> None:
    import json
    import os
    import stat
    from pathlib import Path

    auth_path = Path(path)
    try:
        metadata = auth_path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < 2
            or metadata.st_size > 16384
        ):
            raise FenceError("SERVICE_FENCE_AUTHORIZATION_INVALID")
        record = json.loads(auth_path.read_text(encoding="utf-8"))
    except FenceError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise FenceError("SERVICE_FENCE_AUTHORIZATION_UNAVAILABLE") from exc
    validate_service_authorization(
        record, role=role, cutover_id=cutover_id,
        cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
    )


def _validate_prepared_table(
    text: str, *, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str]
) -> None:
    lines = {line.strip() for line in text.splitlines() if line.strip()}
    expected = _expected_table_lines(
        _prepared_rules(role=role, cutover_id=cutover_id, cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs)
    )
    if lines != expected:
        raise FenceError("PREPARED_EXTERNAL_FENCE_MISMATCH")


def _validate_service_table(
    text: str, *, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str]
) -> None:
    lines = {line.strip() for line in text.splitlines() if line.strip()}
    expected = _expected_table_lines(
        _service_rules(role=role, cutover_id=cutover_id, cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs)
    )
    if lines != expected:
        raise FenceError("SERVICE_EXTERNAL_FENCE_MISMATCH")


def _replace_owned_chain(rules: list[str], *, runner: Callable) -> None:
    """Atomically replace only our validated chain contents."""
    listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
    if listed.returncode != 0:
        raise FenceError("EXTERNAL_FENCE_NOT_INSTALLED")
    lines = {line.strip() for line in listed.stdout.splitlines() if line.strip()}
    header = {
        f"table inet {TABLE} {{",
        f"chain {CHAIN} {{",
        "}",
    }
    hook_lines = {
        "type filter hook input priority -300; policy accept;",
        "type filter hook input priority raw; policy accept;",
    }
    hook = lines & hook_lines
    current_rules = lines - header - hook
    # Keep the ownership check deliberately narrow: no other nft table or
    # arbitrary rule can be flushed by this helper.
    owned = current_rules == {STRICT_DROP_RULE} or (
        bool(current_rules)
        and all(
            (PREPARED_MARKER_PREFIX in line or SERVICE_MARKER_PREFIX in line)
            and ("accept" in line or "drop" in line)
            for line in current_rules
        )
    )
    if not header.issubset(lines) or len(hook) != 1 or not owned:
        raise FenceError("EXTERNAL_FENCE_TABLE_MISMATCH")
    script = [f"flush chain inet {TABLE} {CHAIN}"]
    script.extend(f"add rule inet {TABLE} {CHAIN} {rule}" for rule in rules)
    result = _run(["nft", "-f", "-"], runner=runner, input_text="\n".join(script) + "\n")
    if result.returncode != 0:
        raise FenceError("EXTERNAL_FENCE_UPDATE_FAILED")


def ensure_prepared_fence(
    *, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str], runner: Callable = subprocess.run
) -> None:
    """Open only the Dump maintenance/probe transport after strict-fence proof."""
    verify_fence(runner=runner)
    rules = _prepared_rules(
        role=role, cutover_id=cutover_id, cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs
    )
    try:
        _replace_owned_chain(rules, runner=runner)
        listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
        if listed.returncode != 0:
            raise FenceError("PREPARED_EXTERNAL_FENCE_VERIFY_FAILED")
        _validate_prepared_table(
            listed.stdout,
            role=role,
            cutover_id=cutover_id,
            cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
        )
    except FenceError:
        # If our transition partially failed, make a best-effort strict re-fence.
        try:
            _replace_owned_chain([STRICT_DROP_RULE], runner=runner)
            listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
            if listed.returncode != 0:
                raise FenceError("EXTERNAL_FENCE_RESTORE_FAILED")
            _validate_table(listed.stdout)
        except FenceError as rollback_error:
            raise FenceError("EXTERNAL_FENCE_RESTORE_FAILED") from rollback_error
        raise


def verify_prepared_fence(
    *, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str], runner: Callable = subprocess.run
) -> None:
    listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
    if listed.returncode != 0:
        raise FenceError("EXTERNAL_FENCE_NOT_INSTALLED")
    _validate_prepared_table(
        listed.stdout,
        role=role,
        cutover_id=cutover_id,
        cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
    )


def ensure_service_fence(
    *, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str],
    authorization_file: str, runner: Callable = subprocess.run,
    owner_uid: int = 0,
) -> None:
    """Install only the authorized Cloudflare/Web-to-EMR policy for service lifetime."""
    _read_service_authorization(
        authorization_file, owner_uid=owner_uid, role=role, cutover_id=cutover_id,
        cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
    )
    current = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
    if current.returncode != 0:
        raise FenceError("EXTERNAL_FENCE_NOT_INSTALLED")
    try:
        _validate_table(current.stdout)
    except FenceError:
        try:
            _validate_prepared_table(
                current.stdout, role=role, cutover_id=cutover_id,
                cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
            )
        except FenceError:
            _validate_service_table(
                current.stdout, role=role, cutover_id=cutover_id,
                cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
            )
    _replace_owned_chain(
        _service_rules(role=role, cutover_id=cutover_id, cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs),
        runner=runner,
    )
    listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
    if listed.returncode != 0:
        raise FenceError("SERVICE_EXTERNAL_FENCE_VERIFY_FAILED")
    _validate_service_table(
        listed.stdout, role=role, cutover_id=cutover_id,
        cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
    )


def verify_service_fence(
    *, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str],
    authorization_file: str, runner: Callable = subprocess.run,
    owner_uid: int = 0,
) -> None:
    _read_service_authorization(
        authorization_file, owner_uid=owner_uid, role=role, cutover_id=cutover_id,
        cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
    )
    listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
    if listed.returncode != 0:
        raise FenceError("EXTERNAL_FENCE_NOT_INSTALLED")
    _validate_service_table(
        listed.stdout, role=role, cutover_id=cutover_id,
        cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
    )


def ensure_authorized_service_fence(
    *, authorization_file: str, runner: Callable = subprocess.run, owner_uid: int = 0,
) -> None:
    """Boot-time entry point; rule scope is read only from the root-owned authorization."""
    import json
    import os
    import stat
    from pathlib import Path

    path = Path(authorization_file)
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < 2 or metadata.st_size > 16384
        ):
            raise FenceError("SERVICE_FENCE_AUTHORIZATION_INVALID")
        record = json.loads(path.read_text(encoding="utf-8"))
    except FenceError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise FenceError("SERVICE_FENCE_AUTHORIZATION_UNAVAILABLE") from exc
    if not isinstance(record, dict):
        raise FenceError("SERVICE_FENCE_AUTHORIZATION_INVALID")
    ensure_service_fence(
        role=record.get("role"), cutover_id=record.get("cutover_id"),
        cloudflare_ipv4_cidrs=record.get("cloudflare_ipv4_cidrs"),
        authorization_file=authorization_file, runner=runner, owner_uid=owner_uid,
    )


def restore_strict_fence(*, runner: Callable = subprocess.run) -> None:
    """Return a recognized strict/prepared table to deny-all HTTP(S)."""
    _replace_owned_chain([STRICT_DROP_RULE], runner=runner)
    verify_fence(runner=runner)


def restore_operation_strict_fence(
    *, role: str, cutover_id: str, cloudflare_ipv4_cidrs: list[str],
    runner: Callable = subprocess.run,
) -> None:
    """Close only the prepared/service fence belonging to this operation."""
    listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
    if listed.returncode != 0:
        raise FenceError("EXTERNAL_FENCE_NOT_INSTALLED")
    try:
        _validate_prepared_table(
            listed.stdout, role=role, cutover_id=cutover_id,
            cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
        )
    except FenceError:
        _validate_service_table(
            listed.stdout, role=role, cutover_id=cutover_id,
            cloudflare_ipv4_cidrs=cloudflare_ipv4_cidrs,
        )
    _replace_owned_chain([STRICT_DROP_RULE], runner=runner)
    verify_fence(runner=runner)


def ensure_fence(*, runner: Callable = subprocess.run) -> None:
    listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
    if listed.returncode == 0:
        try:
            _validate_table(listed.stdout)
        except FenceError:
            _replace_owned_chain([STRICT_DROP_RULE], runner=runner)
            listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
            if listed.returncode != 0:
                raise FenceError("EXTERNAL_FENCE_RESTORE_FAILED")
            _validate_table(listed.stdout)
        return

    # Only create a new, dedicated table. Never flush or alter another table.
    script = "\n".join((
        f"add table inet {TABLE}",
        f"add chain inet {TABLE} {CHAIN} {{ type filter hook input priority -300; policy accept; }}",
        f"add rule inet {TABLE} {CHAIN} {EXPECTED_RULE}",
        "",
    ))
    created = _run(["nft", "-f", "-"], runner=runner, input_text=script)
    if created.returncode != 0:
        # A concurrent or pre-existing table is not overwritten; verify only
        # the exact expected contract after a failed create.
        listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
        if listed.returncode != 0:
            raise FenceError("EXTERNAL_FENCE_INSTALL_FAILED")
    listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
    if listed.returncode != 0:
        raise FenceError("EXTERNAL_FENCE_VERIFY_FAILED")
    _validate_table(listed.stdout)


def verify_fence(*, runner: Callable = subprocess.run) -> None:
    """Read-only verification; unlike ensure, this never mutates nftables."""
    listed = _run(["nft", "list", "table", "inet", TABLE], runner=runner)
    if listed.returncode != 0:
        raise FenceError("EXTERNAL_FENCE_NOT_INSTALLED")
    _validate_table(listed.stdout)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("ensure", "verify", "prepare", "verify-prepared", "ensure-service", "verify-service", "ensure-service-authorized", "restore-strict", "restore-operation-strict"))
    parser.add_argument("--role", choices=("web", "emr"))
    parser.add_argument("--cutover-id")
    parser.add_argument("--cloudflare-ipv4-cidr", action="append", default=[])
    parser.add_argument("--authorization-file")
    args = parser.parse_args(argv)
    try:
        if args.command == "ensure":
            ensure_fence()
            print("DUMP_READONLY_EXTERNAL_FENCE=PASS ports=80,443 interface=non-loopback", flush=True)
        elif args.command == "verify":
            verify_fence()
            print("DUMP_READONLY_EXTERNAL_FENCE=PASS ports=80,443 interface=non-loopback", flush=True)
        elif args.command == "restore-strict":
            restore_strict_fence()
            print("DUMP_READONLY_EXTERNAL_FENCE=PASS ports=80,443 interface=non-loopback", flush=True)
        elif args.command == "restore-operation-strict":
            if not args.role or not args.cutover_id:
                raise FenceError("PREPARED_FENCE_ARGUMENTS_REQUIRED")
            restore_operation_strict_fence(
                role=args.role, cutover_id=args.cutover_id,
                cloudflare_ipv4_cidrs=args.cloudflare_ipv4_cidr,
            )
            print("DUMP_SERVICE_FENCE=PASS strict=true", flush=True)
        elif args.command == "ensure-service-authorized":
            if not args.authorization_file:
                raise FenceError("SERVICE_FENCE_ARGUMENTS_REQUIRED")
            ensure_authorized_service_fence(authorization_file=args.authorization_file)
            print("DUMP_SERVICE_FENCE=PASS authorized_scope=verified", flush=True)
        elif args.command in {"ensure-service", "verify-service"}:
            if not args.role or not args.cutover_id or not args.authorization_file:
                raise FenceError("SERVICE_FENCE_ARGUMENTS_REQUIRED")
            kwargs = {
                "role": args.role,
                "cutover_id": args.cutover_id,
                "cloudflare_ipv4_cidrs": args.cloudflare_ipv4_cidr,
                "authorization_file": args.authorization_file,
            }
            if args.command == "ensure-service":
                ensure_service_fence(**kwargs)
            else:
                verify_service_fence(**kwargs)
            print(
                f"DUMP_SERVICE_FENCE=PASS role={args.role} cutover_id={_canonical_cutover_id(args.cutover_id)}",
                flush=True,
            )
        else:
            if not args.role or not args.cutover_id:
                raise FenceError("PREPARED_FENCE_ARGUMENTS_REQUIRED")
            kwargs = {
                "role": args.role,
                "cutover_id": args.cutover_id,
                "cloudflare_ipv4_cidrs": args.cloudflare_ipv4_cidr,
            }
            if args.command == "prepare":
                ensure_prepared_fence(**kwargs)
            else:
                verify_prepared_fence(**kwargs)
            print(
                f"DUMP_PUBLIC_READINESS_FENCE=PASS role={args.role} cutover_id={_canonical_cutover_id(args.cutover_id)}",
                flush=True,
            )
        return 0
    except FenceError as exc:
        print(f"DUMP_READONLY_EXTERNAL_FENCE=BLOCKED reason={exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
