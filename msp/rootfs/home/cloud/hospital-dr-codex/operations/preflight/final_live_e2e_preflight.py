#!/usr/bin/env python3
"""Read-only final live DR E2E preflight and demo-readiness checker.

This checker is deliberately preparation-only.  It never starts EC2, creates
NAT, changes routes/SG/DNS, calls Slack, changes Terraform state, or starts a
DR workflow.  External secret values are loaded only in memory and are never
included in output or JSON evidence.

The existing ``operations/runtime/final_dr_preflight.sh`` remains the lower
level legacy gate.  This command adds a single machine-readable view for the
live test window and classifies expected standby state separately from real
blockers.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "operations" / "monitoring"))
sys.path.insert(0, str(ROOT / "operations" / "zabbix"))

from onprem_state import classify_global_path, classify_host, normalize_power_state  # noqa: E402
from production_dr_policy import (  # noqa: E402
    DOC_SCENARIO,
    ONPREM_DB_IP,
    ONPREM_EMR_IP,
    ONPREM_WEB_IP,
    WEB_SCENARIO,
)

DEFAULT_SECRET_FILE = Path("/home/cloud/hospital-dr-secrets/dr.env")
DEFAULT_REGION = "ap-northeast-2"
DEFAULT_INSTANCE_IDS = {
    "web": "AWS_RESOURCE_ID_REDACTED",
    "emr": "AWS_RESOURCE_ID_REDACTED",
    "db": "AWS_RESOURCE_ID_REDACTED",
}
EXPECTED_INSTANCES = {
    "AWS_RESOURCE_ID_REDACTED": {"role": "web", "private_ip": "AWS_PUBLIC_IP_REDACTED"},
    "AWS_RESOURCE_ID_REDACTED": {"role": "emr", "private_ip": "AWS_PUBLIC_IP_REDACTED"},
    "AWS_RESOURCE_ID_REDACTED": {"role": "db", "private_ip": "AWS_PUBLIC_IP_REDACTED"},
}
REQUIRED_FILES = (
    "operations/runtime/final_dr_preflight.sh",
    "operations/failover/full_failover.sh",
    "operations/failover/full_failback.sh",
    "operations/failover/failback.sh",
    "operations/db/zabbix_failback_guard.sh",
    "operations/chatops/rto_timeline.py",
    "docs/runbooks/FINAL_DR_INTEGRATION_AND_DEEP_FREEZE.md",
)
DEFAULT_FIXED_CHATOPS_BASE_URL = "https://chatops.hospital-web.pp.ua"
DEFAULT_ZABBIX_ALERTSCRIPTS_DIR = "/usr/lib/zabbix/alertscripts"
DEFAULT_ZABBIX_COMPOSE_FILE = "/home/cloud/zabbix/docker-compose.yml"
ACTIVE_APPROVAL_STATUSES = ("PENDING", "PARTIALLY_APPROVED", "EXECUTING")
SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ONPREM_DEFAULTS = {
    "web": {"ip": ONPREM_WEB_IP, "health_url": WEB_SCENARIO["steps"][0]["url"]},
    "emr": {"ip": ONPREM_EMR_IP, "health_url": DOC_SCENARIO["steps"][0]["url"]},
    "db": {"ip": ONPREM_DB_IP, "health_url": ""},
}


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    blocker: str | None = None
    category: str = "general"


def assess_readiness(
    checks: Iterable[Check],
    *,
    root: Path = ROOT,
    git_commit: str = "",
    warnings: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the safe-to-start/demo decision from classified checks.

    This pure function is intentionally small so tests can prove that
    expected ``SUSPENDED_EXPECTED`` and ``NR_NOT_READY`` states do not get
    silently converted into a safe live-test result.
    """

    check_list = list(checks)
    blockers = sorted({item.blocker for item in check_list if item.status == "BLOCKED" and item.blocker})
    team_dependencies = sorted(
        {
            item.blocker
            for item in check_list
            if item.status == "BLOCKED"
            and item.blocker
            and (
                item.blocker.startswith("BLOCKED_")
                or item.blocker.startswith("DIRECT_NR")
                or item.blocker.startswith("ONPREM_")
                or item.blocker.startswith("AWS_")
                or item.blocker.startswith("WAZUH_")
            )
        }
    )
    evidence_ready = all(
        (root / path).is_file()
        for path in (
            "operations/chatops/rto_timeline.py",
            "operations/preflight/rpo_evidence.py",
            "docs/runbooks/FINAL_DR_INTEGRATION_AND_DEEP_FREEZE.md",
        )
    )
    def category_ready(category: str) -> bool:
        return not any(item.category == category and item.status == "BLOCKED" for item in check_list)

    static_monitoring_files = all(
        (root / path).is_file()
        for path in (
            "operations/aws/apply_endpoint_security.sh",
            "monitoring/grafana/provisioning/dashboards/json/hospital-aws-dr-security.json",
            "operations/security/aws_cloudtrail_collector.py",
        )
    )
    static_security_files = all(
        (root / path).is_file()
        for path in (
            "monitoring/wazuh/feature-contract.yml",
            "operations/security/aws_cloudtrail_collector.py",
            "operations/chatops/wazuh_correlation.py",
        )
    )
    approval_check = next((item for item in check_list if item.name == "slack_two_person"), None)
    readiness = {
        "code_ready": category_ready("repo"),
        "monitoring_config_ready": static_monitoring_files,
        "security_config_ready": static_security_files,
        "aws_config_ready": category_ready("aws"),
        "network_ready": category_ready("network"),
        "direct_nr_ready": category_ready("nr"),
        "two_approvers_ready": bool(approval_check and approval_check.status == "PASS"),
        "evidence_ready": evidence_ready,
    }
    return {
        "schema_version": 1,
        "timestamp": utc_now(),
        "git_commit": git_commit,
        "safe_to_start_live_e2e": not blockers,
        "demo_ready": not blockers and evidence_ready,
        "checks": {item.name: asdict(item) for item in check_list},
        "blockers": blockers,
        "warnings": sorted(set(warnings)),
        "team_dependencies": team_dependencies,
        "environment_limitations": sorted(
            f"{item.name}:{item.detail}"
            for item in check_list
            if item.status == "DISABLED"
        ),
        "evidence_ready": evidence_ready,
        "readiness": readiness,
        "aws_cost_change": "NONE_READ_ONLY_PREFLIGHT",
        "aws_instances_started": False,
        "aws_new_resources": False,
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse simple dotenv assignments without executing shell code."""

    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not SECRET_NAME_RE.fullmatch(key):
            continue
        value = raw_value.strip()
        try:
            tokens = shlex.split(value, comments=True, posix=True)
            value = tokens[0] if tokens else ""
        except ValueError:
            # A malformed external file is reported by the permission/source
            # check; do not attempt to execute or print its contents.
            continue
        values[key] = value
    return values


def merged_values(env_file: Path, auxiliary_files: Iterable[Path] = ()) -> dict[str, str]:
    values: dict[str, str] = {}
    for auxiliary in auxiliary_files:
        values.update(parse_env_file(auxiliary))
    values.update(parse_env_file(env_file))
    for key, value in os.environ.items():
        if SECRET_NAME_RE.fullmatch(key):
            values[key] = value
    return values


def safe_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname or "?"
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or "/"
        return f"{parsed.scheme}://{host}{port}{path}"
    except ValueError:
        return "<invalid-url>"


def command_result(command: list[str], *, timeout: int = 15, env: dict[str, str] | None = None) -> tuple[int, str]:
    """Run a read-only command and return only stdout, never stderr."""

    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return result.returncode, result.stdout.strip()


def http_probe(
    url: str,
    *,
    auth: tuple[str, str] | None = None,
    ca_file: str = "",
    insecure: bool = False,
) -> tuple[bool, str]:
    if not url:
        return False, "URL_NOT_CONFIGURED"
    request = urllib.request.Request(url, method="GET")
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode("utf-8")).decode("ascii")
        request.add_header("Authorization", f"Basic {token}")
    context: ssl.SSLContext | None = None
    if urllib.parse.urlsplit(url).scheme == "https":
        try:
            context = ssl._create_unverified_context() if insecure else ssl.create_default_context(cafile=ca_file or None)
        except (OSError, ssl.SSLError):
            return False, "TLS_CONTEXT_ERROR"
    try:
        with urllib.request.urlopen(request, timeout=8, context=context) as response:
            return 200 <= response.status < 400, f"HTTP_{response.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP_{exc.code}"
    except (OSError, urllib.error.URLError, ssl.SSLError):
        return False, "UNREACHABLE"


def tcp_probe(host: str, port: int, *, timeout: float = 3.0) -> tuple[bool, str]:
    if not host:
        return False, "HOST_NOT_CONFIGURED"
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, "TCP_CONNECT_PASS"
    except (OSError, ValueError):
        return False, "TCP_CONNECT_BLOCKED"


def _is_true(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _is_false(value: str) -> bool:
    return str(value).strip().lower() in {"0", "false", "no", "off", "disabled"}


def configured_indexer_url(values: dict[str, str]) -> str:
    """Return the controller override or the existing Grafana runtime URL."""

    return values.get("WAZUH_CONTROLLER_INDEXER_URL", "") or values.get("WAZUH_INDEXER_URL", "")


def _unique_csv(value: str) -> list[str]:
    return sorted({part.strip() for part in str(value or "").split(",") if part.strip()})


def _safe_status(status: str) -> str:
    return status.upper().replace(" ", "_")


class FinalLivePreflight:
    def __init__(
        self,
        *,
        root: Path = ROOT,
        values: dict[str, str] | None = None,
        runner: Callable[..., tuple[int, str]] = command_result,
        http: Callable[..., tuple[bool, str]] = http_probe,
        tcp: Callable[..., tuple[bool, str]] = tcp_probe,
        include_legacy: bool = True,
    ) -> None:
        self.root = root
        self.values = values or {}
        self.runner = runner
        self.http = http
        self.tcp = tcp
        self.include_legacy = include_legacy
        self.checks: list[Check] = []
        self.warnings: list[str] = []
        self.blockers: list[str] = []
        self.onprem_state: dict[str, Any] = {}

    def value(self, name: str, default: str = "") -> str:
        return self.values.get(name, default)

    def add(
        self,
        name: str,
        status: str,
        detail: str,
        *,
        blocker: str | None = None,
        category: str = "general",
    ) -> None:
        normalized = _safe_status(status)
        self.checks.append(Check(name, normalized, detail, blocker, category))
        if normalized == "BLOCKED" and blocker:
            self.blockers.append(blocker)

    def check_local_repo(self) -> None:
        branch_rc, branch = self.runner(["git", "-C", str(self.root), "branch", "--show-current"])
        self.add("repository", "PASS" if branch_rc == 0 and branch else "BLOCKED", "canonical repository detected", blocker="CANONICAL_REPOSITORY_UNAVAILABLE", category="repo")
        self.add("branch", "PASS" if branch == "main" else "BLOCKED", "main" if branch == "main" else "branch is not main", blocker=None if branch == "main" else "GIT_BRANCH_NOT_MAIN", category="repo")

        _, status = self.runner(["git", "-C", str(self.root), "status", "--porcelain"])
        self.add("git_clean", "PASS" if not status else "BLOCKED", "working tree clean" if not status else "working tree has changes", blocker=None if not status else "GIT_WORKTREE_DIRTY", category="repo")
        _, head = self.runner(["git", "-C", str(self.root), "rev-parse", "HEAD"])
        _, origin = self.runner(["git", "-C", str(self.root), "rev-parse", "origin/main"])
        self.git_head = head.strip()
        self.add("origin_sync", "PASS" if head and head == origin else "BLOCKED", "HEAD matches origin/main" if head == origin else "HEAD and origin/main differ", blocker=None if head == origin else "GIT_HEAD_ORIGIN_MISMATCH", category="repo")
        self.add("git_head", "PASS" if re.fullmatch(r"[0-9a-f]{40}", head or "") else "BLOCKED", "current immutable commit recorded" if head else "HEAD unavailable", blocker=None if head else "GIT_HEAD_UNAVAILABLE", category="repo")
        image_tag = self.value("DR_IMAGE_TAG", head)
        self.add(
            "immutable_image_tag",
            "PASS" if image_tag == head and re.fullmatch(r"[0-9a-f]{40}", image_tag or "") else "BLOCKED",
            "DR_IMAGE_TAG matches current HEAD" if image_tag == head else "DR_IMAGE_TAG must match current HEAD",
            blocker=None if image_tag == head else "IMAGE_TAG_NOT_CURRENT_HEAD",
            category="repo",
        )

        secret_file = Path(self.value("DR_SECRET_FILE", str(DEFAULT_SECRET_FILE)))
        if not secret_file.is_file() or not os.access(secret_file, os.R_OK):
            self.add("secret_file", "BLOCKED", "external secret file is not readable", blocker="SECRET_FILE_UNREADABLE", category="repo")
        else:
            mode = secret_file.stat().st_mode & 0o777
            self.add("secret_file_permission", "PASS" if mode in {0o600, 0o640} else "BLOCKED", f"external secret file mode={mode:03o}", blocker=None if mode in {0o600, 0o640} else "SECRET_FILE_PERMISSION", category="repo")

        for relative in REQUIRED_FILES:
            path = self.root / relative
            self.add(f"required:{relative}", "PASS" if path.is_file() else "BLOCKED", "present" if path.is_file() else "missing", blocker=None if path.is_file() else "REQUIRED_FILE_MISSING", category="repo")

        configured_broad = self.value("ZABBIX_DR_BROAD_TEST_MODE", self.value("BROAD_TEST_MODE"))
        broad = configured_broad or "false"
        broad_detail = "OFF (explicit)" if configured_broad else "OFF (fail-closed application default)"
        self.add("broad_test_mode", "PASS" if _is_false(broad) else "BLOCKED", broad_detail if _is_false(broad) else "must be OFF", blocker=None if _is_false(broad) else "BROAD_TEST_MODE_NOT_OFF", category="safety")
        nr = self.value("DB_NR_ENABLED")
        self.add("db_nr_enabled", "PASS" if _is_false(nr) else "BLOCKED", "false" if _is_false(nr) else "must remain false during preparation", blocker=None if _is_false(nr) else "DB_NR_ENABLED_NOT_FALSE", category="safety")

    def check_clock_sync(self) -> None:
        """Verify the controller clock without changing time configuration."""

        rc, output = self.runner(
            ["timedatectl", "show", "--property=NTPSynchronized", "--property=NTP"]
        )
        properties = {}
        for line in output.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                properties[key.strip()] = value.strip().lower()
        if not properties:
            # Keep compatibility with older timedatectl versions that emit
            # values only when --value is used.
            values = [line.strip().lower() for line in output.splitlines()]
            properties = {
                "NTPSynchronized": values[0] if values else "",
                "NTP": values[1] if len(values) > 1 else "",
            }
        synchronized = rc == 0 and properties.get("NTPSynchronized") == "yes"
        unit_rc, _ = self.runner(["systemctl", "is-active", "systemd-timesyncd.service"])
        chrony_rc, _ = self.runner(["systemctl", "is-active", "chrony.service"])
        daemon_ok = properties.get("NTP") == "yes" and (unit_rc == 0 or chrony_rc == 0)
        self.add(
            "clock_sync_msp",
            "PASS" if synchronized and daemon_ok else "BLOCKED",
            "MSP clock synchronized by an active time-sync service"
            if synchronized and daemon_ok
            else "MSP clock synchronization is not proven",
            blocker=None if synchronized and daemon_ok else "MSP_CLOCK_NOT_SYNCHRONIZED",
            category="evidence",
        )

    def check_runtime_drift(self) -> None:
        """Run the existing manifest comparison; it is strictly read-only."""

        helper = self.root / "operations/runtime/runtime_drift_check.sh"
        if not helper.is_file():
            self.add(
                "runtime_drift",
                "BLOCKED",
                "runtime drift checker is missing",
                blocker="RUNTIME_DRIFT_CHECKER_MISSING",
                category="repo",
            )
            return
        rc, _ = self.runner(["bash", str(helper), "--check"], timeout=90)
        self.add(
            "runtime_drift",
            "PASS" if rc == 0 else "BLOCKED",
            "canonical and installed runtime manifests match"
            if rc == 0
            else "canonical and installed runtime manifests differ",
            blocker=None if rc == 0 else "RUNTIME_DRIFT_DETECTED",
            category="repo",
        )

    def check_egress_workflow_contract(self) -> None:
        """Prevent a live run from silently recreating or deleting retired NAT."""

        candidates = (
            self.root / "operations/failover/full_failover.sh",
            self.root / "operations/db/db_failback_to_onprem.sh",
            self.root / "operations/failover/full_failback.sh",
        )
        references = []
        for path in candidates:
            try:
                source = path.read_text(encoding="utf-8")
                if "nat_enable.sh" in source or "nat_disable.sh" in source:
                    references.append(str(path.relative_to(self.root)))
            except OSError:
                references.append(f"{path.relative_to(self.root)}:unreadable")
        for path in candidates[:2]:
            try:
                if "web_nat_instance_status.sh" not in path.read_text(encoding="utf-8"):
                    references.append(f"{path.relative_to(self.root)}:missing-web-nat-status-guard")
            except OSError:
                pass
        if references:
            self.add(
                "egress_workflow",
                "BLOCKED",
                "live workflow egress contract is unsafe: " + ", ".join(references),
                blocker="FAILOVER_EGRESS_MODE_UNRECONCILED",
                category="aws",
            )
        else:
            self.add(
                "egress_workflow",
                "PASS",
                "live workflow uses Web NAT Instance status guards and no NAT lifecycle mutation",
                category="aws",
            )

    def check_zabbix_failback_runtime(self) -> None:
        """Check the actual Zabbix alertscript installation, without installing it.

        The MSP deployment runs Zabbix in Docker.  In that deployment the
        host does not have /usr/lib/zabbix/alertscripts; the compose bind
        mounts are the effective runtime contract.  Validate that contract
        when present, while retaining the direct-host check for other
        environments.
        """

        runtime_dir = Path(
            self.value("ZABBIX_ALERTSCRIPTS_DIR", DEFAULT_ZABBIX_ALERTSCRIPTS_DIR)
        )
        compose_file = Path(
            self.value("ZABBIX_COMPOSE_FILE", DEFAULT_ZABBIX_COMPOSE_FILE)
        )
        if not runtime_dir.is_dir() and compose_file.is_file():
            compose = compose_file.read_text(encoding="utf-8", errors="replace")
            wrapper = Path(
                self.value("ZABBIX_HOST_FAILBACK_WRAPPER", "/home/cloud/send_failback.sh")
            )
            guard = self.root / "operations/db/zabbix_failback_guard.sh"
            expected_wrapper_mount = (
                f"{wrapper}:/usr/lib/zabbix/alertscripts/send_failback.sh:ro"
            )
            expected_guard_mount = (
                f"{guard}:/usr/lib/zabbix/alertscripts/zabbix_failback_guard.sh:ro"
            )
            wrapper_valid = (
                wrapper.is_file()
                and bool(wrapper.stat().st_mode & 0o111)
                and f"exec bash {self.root}/operations/chatops/send_failback.sh \"$@\""
                in wrapper.read_text(encoding="utf-8", errors="replace")
            )
            guard_valid = guard.is_file() and bool(guard.stat().st_mode & 0o111)
            if expected_wrapper_mount in compose and expected_guard_mount in compose and wrapper_valid and guard_valid:
                for path in (wrapper, guard):
                    rc, _ = self.runner(["bash", "-n", str(path)])
                    if rc != 0:
                        self.add(
                            "zabbix_failback_runtime",
                            "BLOCKED",
                            f"Zabbix Docker alertscript has invalid shell syntax: {path}",
                            blocker="ZABBIX_FAILBACK_RUNTIME_NOT_READY",
                            category="chatops",
                        )
                        return
                self.add(
                    "zabbix_failback_runtime",
                    "PASS",
                    "Zabbix Docker compose bind mounts provide the canonical Failback sender and guard",
                    category="chatops",
                )
                return

        pairs = (
            (self.root / "operations/chatops/send_failback.sh", runtime_dir / "send_failback.sh"),
            (self.root / "operations/db/zabbix_failback_guard.sh", runtime_dir / "zabbix_failback_guard.sh"),
        )
        missing: list[str] = []
        drifted: list[str] = []
        invalid: list[str] = []
        for source, installed in pairs:
            if not installed.is_file():
                missing.append(installed.name)
                continue
            try:
                same_content = source.read_bytes() == installed.read_bytes()
            except OSError:
                same_content = False
            if not same_content:
                drifted.append(installed.name)
            mode = installed.stat().st_mode & 0o777
            if not mode & 0o111:
                invalid.append(installed.name)
            rc, _ = self.runner(["bash", "-n", str(installed)])
            if rc != 0:
                invalid.append(installed.name)
        if missing or drifted or invalid:
            detail_parts = []
            if missing:
                detail_parts.append("missing=" + ",".join(sorted(set(missing))))
            if drifted:
                detail_parts.append("drifted=" + ",".join(sorted(set(drifted))))
            if invalid:
                detail_parts.append("invalid=" + ",".join(sorted(set(invalid))))
            self.add(
                "zabbix_failback_runtime",
                "BLOCKED",
                "Zabbix Failback alertscript runtime is not ready: " + "; ".join(detail_parts),
                blocker="ZABBIX_FAILBACK_RUNTIME_NOT_READY",
                category="chatops",
            )
            return
        self.add(
            "zabbix_failback_runtime",
            "PASS",
            f"installed scripts match canonical source in {runtime_dir}",
            category="chatops",
        )

    def check_chatops_runtime_state(self) -> None:
        """Read active approval rows and lock holders without changing state."""

        state_db = Path(
            self.value("CHATOPS_STATE_DB", "/var/lib/hospital-dr/chatops_state.sqlite3")
        )
        if not state_db.is_file():
            self.add(
                "chatops_state",
                "BLOCKED",
                "ChatOps state database is unavailable",
                blocker="CHATOPS_STATE_UNAVAILABLE",
                category="chatops",
            )
        else:
            try:
                connection = sqlite3.connect(f"file:{state_db}?mode=ro", uri=True)
                statuses = {
                    str(status): int(count)
                    for status, count in connection.execute(
                        "SELECT status, COUNT(*) FROM approval_requests GROUP BY status"
                    )
                }
                active = sum(statuses.get(status, 0) for status in ACTIVE_APPROVAL_STATUSES)
                console_ready = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM emergency_console WHERE status = 'READY'"
                    ).fetchone()[0]
                )
                connection.close()
                if active:
                    self.add(
                        "chatops_state",
                        "BLOCKED",
                        f"active ChatOps requests={active}",
                        blocker="CHATOPS_ACTIVE_REQUESTS",
                        category="chatops",
                    )
                elif console_ready < 1:
                    self.add(
                        "chatops_state",
                        "BLOCKED",
                        "Emergency Console is not recorded READY",
                        blocker="EMERGENCY_CONSOLE_NOT_READY",
                        category="chatops",
                    )
                else:
                    self.add(
                        "chatops_state",
                        "PASS",
                        "no pending/partially-approved/executing request; Emergency Console READY",
                        category="chatops",
                    )
            except (OSError, sqlite3.Error, ValueError, TypeError):
                self.add(
                    "chatops_state",
                    "BLOCKED",
                    "ChatOps state database could not be read read-only",
                    blocker="CHATOPS_STATE_UNREADABLE",
                    category="chatops",
                )

        lock_file = Path(self.value("DR_WORKFLOW_LOCK_FILE", "/var/lib/hospital-dr/workflow.lock"))
        if not lock_file.exists():
            self.add("chatops_execution_lock", "PASS", "workflow lock is absent/free", category="chatops")
            return
        rc, _ = self.runner(["fuser", str(lock_file)])
        if rc == 0:
            self.add(
                "chatops_execution_lock",
                "BLOCKED",
                "workflow lock has an active holder",
                blocker="CHATOPS_EXECUTION_LOCK_HELD",
                category="chatops",
            )
        elif rc == 1:
            self.add("chatops_execution_lock", "PASS", "workflow lock has no active holder", category="chatops")
        else:
            self.add(
                "chatops_execution_lock",
                "BLOCKED",
                "workflow lock holder could not be verified",
                blocker="CHATOPS_EXECUTION_LOCK_UNVERIFIED",
                category="chatops",
            )

    def check_fixed_slack_endpoint(self) -> None:
        """Check the fixed callback hostname; GET 405 is expected for POST-only routes."""

        base_url = self.value(
            "SLACK_FIXED_ENDPOINT_BASE_URL", DEFAULT_FIXED_CHATOPS_BASE_URL
        ).rstrip("/")
        ok, detail = self.http(f"{base_url}/slack/action")
        endpoint_ok = ok or detail == "HTTP_405"
        self.add(
            "slack_fixed_endpoint",
            "PASS" if endpoint_ok else "BLOCKED",
            f"fixed Slack endpoint {safe_url(base_url + '/slack/action')} reachable ({detail})"
            if endpoint_ok
            else f"fixed Slack endpoint {safe_url(base_url + '/slack/action')} unavailable ({detail})",
            blocker=None if endpoint_ok else "SLACK_FIXED_ENDPOINT_UNAVAILABLE",
            category="slack",
        )

    def _repository_name(self) -> str:
        _, remote = self.runner(["git", "-C", str(self.root), "config", "--get", "remote.origin.url"])
        remote = remote.removesuffix(".git")
        for prefix in ("git@github.com:", "https://github.com/", "ssh://git@github.com/"):
            if remote.startswith(prefix):
                return remote[len(prefix):]
        return ""

    def check_ci(self) -> None:
        repo = self._repository_name()
        if not repo or not self.git_head:
            self.add("github_actions", "BLOCKED", "repository or HEAD unavailable", blocker="GITHUB_ACTIONS_UNRESOLVED", category="repo")
            return
        if shutil.which("gh") is None:
            self.add("github_actions", "BLOCKED", "gh CLI unavailable", blocker="GITHUB_CLI_UNAVAILABLE", category="repo")
            return
        rc, output = self.runner(["gh", "run", "list", "--repo", repo, "--limit", "50", "--json", "databaseId,status,conclusion,headSha,createdAt"])
        try:
            rows = json.loads(output) if rc == 0 else []
        except json.JSONDecodeError:
            rows = []
        matches = [row for row in rows if row.get("headSha") == self.git_head]
        matches.sort(key=lambda row: str(row.get("createdAt", "")), reverse=True)
        latest = matches[0] if matches else {}
        ok = latest.get("status") == "completed" and latest.get("conclusion") == "success"
        self.add("github_actions", "PASS" if ok else "BLOCKED", f"run={latest.get('databaseId', 'none')}" if ok else "current HEAD has no successful run", blocker=None if ok else "GITHUB_ACTIONS_NOT_GREEN", category="repo")

    def _service_or_endpoint(
        self,
        name: str,
        url: str,
        unit: str,
        container_patterns: Iterable[str],
        process_patterns: Iterable[str] = (),
    ) -> None:
        if url:
            ok, detail = self.http(url)
            if ok:
                self.add(name, "PASS", f"endpoint={safe_url(url)} {detail}", category="msp")
                return
        rc, _ = self.runner(["systemctl", "is-active", "--quiet", unit])
        if rc == 0:
            self.add(name, "PASS", f"systemd={unit}", category="msp")
            return
        rc, output = self.runner(["docker", "ps", "--format", "{{.Names}}"])
        names = set(output.splitlines()) if rc == 0 else set()
        matched = any(any(pattern in candidate for pattern in container_patterns) for candidate in names)
        if not matched:
            matched = any(
                self.runner(["pgrep", "-f", pattern])[0] == 0
                for pattern in process_patterns
            )
        self.add(name, "PASS" if matched else "BLOCKED", "container/process detected" if matched else "service health unavailable", blocker=None if matched else f"{name.upper()}_UNAVAILABLE", category="msp")

    def check_msp(self) -> None:
        self._service_or_endpoint("chatops", self.value("CHATOPS_HEALTH_URL", "http://AWS_PUBLIC_IP_REDACTED:5000/"), "hospital-dr-chatops.service", ("chatops",))
        self._service_or_endpoint("grafana", self.value("GRAFANA_HEALTH_URL", "http://AWS_PUBLIC_IP_REDACTED:3001/api/health"), "grafana-server.service", ("grafana",))

        # Grafana's datasource URL is often container-internal.  The
        # controller-side URL is explicit and defaults to the local published
        # API endpoint instead of guessing a Docker hostname.
        zabbix_url = self.value("ZABBIX_CONTROLLER_API_URL", "http://IP_REDACTED/api_jsonrpc.php")
        body = json.dumps({"jsonrpc": "2.0", "method": "apiinfo.version", "params": {}, "id": 1}).encode("utf-8")
        try:
            request = urllib.request.Request(zabbix_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(request, timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8"))
            ok = bool(payload.get("result"))
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
            ok = False
        self.add("zabbix_msp", "PASS" if ok else "BLOCKED", "Zabbix API version query passed" if ok else "Zabbix API unavailable", blocker=None if ok else "ZABBIX_MSP_UNAVAILABLE", category="msp")

        # Grafana/Wazuh runtime commonly exposes the read-only Indexer URL as
        # WAZUH_INDEXER_URL.  Prefer the explicit controller override when it
        # exists, but accept the existing runtime contract as a fallback so a
        # valid local Indexer is not misclassified as missing.
        indexer_url = configured_indexer_url(self.values)
        indexer_user = self.value("WAZUH_INDEXER_USER")
        indexer_password = self.value("WAZUH_INDEXER_PASSWORD")
        if indexer_url and indexer_user and indexer_password:
            ok, detail = self.http(
                f"{indexer_url.rstrip('/')}/_cluster/health",
                auth=(indexer_user, indexer_password),
                ca_file=self.value("WAZUH_CA_CERT"),
                insecure=_is_true(self.value("WAZUH_INDEXER_TLS_SKIP_VERIFY")),
            )
            self.add("wazuh_indexer", "PASS" if ok else "BLOCKED", detail if ok else "Indexer health unavailable", blocker=None if ok else "WAZUH_INDEXER_UNAVAILABLE", category="msp")
        else:
            self.add("wazuh_indexer", "BLOCKED", "external Indexer contract is incomplete", blocker="WAZUH_INDEXER_CONTRACT_MISSING", category="msp")

        wazuh_api = self.value("WAZUH_API_URL")
        if wazuh_api and self.value("WAZUH_API_USER") and self.value("WAZUH_API_PASSWORD"):
            ok, detail = self.http(wazuh_api, auth=(self.value("WAZUH_API_USER"), self.value("WAZUH_API_PASSWORD")), ca_file=self.value("WAZUH_CA_CERT"))
            self.add("wazuh_manager", "PASS" if ok else "BLOCKED", detail if ok else "Manager API unavailable", blocker=None if ok else "WAZUH_MANAGER_UNAVAILABLE", category="msp")
        else:
            self._service_or_endpoint(
                "wazuh_manager",
                "",
                "wazuh-manager.service",
                ("wazuh.manager", "wazuh-manager"),
                (r"[w]azuh-(analysisd|remoted|authd|db)",),
            )

        correlation_state = Path(self.value("WAZUH_CORRELATION_STATE_FILE", "/var/lib/hospital-dr/wazuh_correlation.json"))
        correlation_code = self.root / "operations/chatops/wazuh_correlation.py"
        ok = correlation_code.is_file() and (correlation_state.is_file() or self._check_pass("chatops"))
        self.add("xdr_runtime", "PASS" if ok else "BLOCKED", "correlation code and runtime path available" if ok else "correlation runtime unavailable", blocker=None if ok else "XDR_RUNTIME_UNAVAILABLE", category="msp")

        state_dir = Path(self.value("DR_STATE_DIR", "/var/lib/hospital-dr"))
        self.add("persistent_state", "PASS" if state_dir.is_dir() and os.access(state_dir, os.R_OK | os.W_OK) else "BLOCKED", "state directory readable/writable" if state_dir.is_dir() and os.access(state_dir, os.R_OK | os.W_OK) else "state directory unavailable", blocker=None if state_dir.is_dir() and os.access(state_dir, os.R_OK | os.W_OK) else "PERSISTENT_STATE_UNAVAILABLE", category="msp")

    def _check_pass(self, name: str) -> bool:
        return any(item.name == name and item.status == "PASS" for item in self.checks)

    def check_onprem_path(self) -> None:
        # These are the already-owned production probe contracts from the
        # Zabbix DR policy.  Environment values may override them, but missing
        # dotenv entries must not collapse all hosts into a synthetic WG
        # failure.
        specs = {
            "web": {
                "ip": self.value("ONPREM_WEB_IP", ONPREM_DEFAULTS["web"]["ip"]),
                "health_url": self.value("ONPREM_WEB_HEALTH_URL", ONPREM_DEFAULTS["web"]["health_url"]),
                "power_state": self.value("ONPREM_WEB_POWER_STATE", self.value("ONPREM_WEB_STATE")),
            },
            "emr": {
                "ip": self.value("ONPREM_EMR_IP", ONPREM_DEFAULTS["emr"]["ip"]),
                "health_url": self.value("ONPREM_DOC_HEALTH_URL", ONPREM_DEFAULTS["emr"]["health_url"]),
                "power_state": self.value("ONPREM_EMR_POWER_STATE", self.value("ONPREM_DOC_POWER_STATE", self.value("ONPREM_DOC_STATE"))),
            },
            "db": {
                "ip": self.value("ONPREM_DB_HOST", self.value("ONPREM_DB_IP", ONPREM_DEFAULTS["db"]["ip"])),
                "health_url": "",
                "power_state": self.value("ONPREM_DB_POWER_STATE", self.value("ONPREM_DB_STATE")),
            },
        }
        raw: dict[str, dict[str, Any]] = {}
        for name, spec in specs.items():
            explicit_power = normalize_power_state(spec["power_state"])
            if explicit_power == "POWERED_OFF":
                raw[name] = {
                    "agent_ok": None,
                    "service_ok": None,
                    "agent_detail": "not probed; operator power-state contract is POWERED_OFF",
                    "service_detail": "not tested while host is POWERED_OFF",
                }
                continue
            agent_ok, agent_detail = self.tcp(spec["ip"], 10050)
            if name == "db":
                service_ok, service_detail = self.tcp(
                    spec["ip"], int(self.value("ONPREM_DB_PORT", "3306"))
                )
            else:
                service_ok, service_detail = self.http(spec["health_url"])
            raw[name] = {
                "agent_ok": agent_ok,
                "service_ok": service_ok,
                "agent_detail": agent_detail,
                "service_detail": service_detail,
            }

        for name, spec in specs.items():
            probe = raw[name]
            state = classify_host(
                power_state=spec["power_state"],
                agent_reachable=probe["agent_ok"],
                service_healthy=probe["service_ok"],
            )
            service_detail = probe["service_detail"]
            # Web can be reachable while its DB/Doc dependency returns 5xx.
            # Keep that distinction visible instead of calling the Web process
            # or the WG path down.
            if name == "web" and probe["agent_ok"] and not probe["service_ok"]:
                service_detail = "DEGRADED_DB_OR_DOC_DEPENDENCY: " + service_detail
            self.onprem_state[name] = {
                "ip": spec["ip"],
                "power_state_input": "configured" if spec["power_state"] else "not_configured",
                "state": state["state"],
                "display": state["display"],
                "agent": probe["agent_detail"],
                "service": service_detail,
                "service_state": state.get("service_state", "NOT_TESTED"),
            }

            if state["state"] == "POWERED_OFF":
                check_status, blocker = "EXPECTED", None
                detail = "POWERED_OFF / NOT TESTED LIVE"
            elif state["state"] == "LIVE":
                check_status, blocker = "PASS", None
                detail = f"LIVE; agent={probe['agent_detail']}"
            elif state["state"] == "UNKNOWN":
                check_status, blocker = "BLOCKED", f"ONPREM_{name.upper()}_NOT_RUNNING_OR_UNCONFIRMED"
                detail = "POWERED_OFF_OR_NOT_AVAILABLE; no trusted power-state source"
            elif state["state"] == "AGENT_UNAVAILABLE":
                check_status, blocker = "BLOCKED", f"ONPREM_{name.upper()}_AGENT_UNAVAILABLE"
                detail = "host expected live but Zabbix Agent is unavailable"
            else:
                check_status, blocker = "BLOCKED", f"ONPREM_{name.upper()}_PATH_BLOCKED"
                detail = state["display"]
            self.add(f"onprem_{name}_state", check_status, detail, blocker=blocker, category="network")

            if probe["service_ok"] is True:
                self.add(f"onprem_{name}_service", "PASS", probe["service_detail"], category="network")
            elif state["state"] == "POWERED_OFF":
                self.add(f"onprem_{name}_service", "EXPECTED", "not tested while POWERED_OFF", category="network")
            elif name == "web" and probe["agent_ok"]:
                self.add(f"onprem_{name}_service", "WARN", service_detail, category="network")
            else:
                self.add(
                    f"onprem_{name}_service",
                    "BLOCKED",
                    probe["service_detail"],
                    blocker=f"ONPREM_{name.upper()}_SERVICE_NOT_READY",
                    category="network",
                )

        global_state = classify_global_path(
            self.onprem_state,
            common_path_failure=_is_true(self.value("ONPREM_COMMON_PATH_FAILURE")),
        )
        self.onprem_state["global"] = global_state
        if global_state["state"] == "NETWORK_PATH_BLOCKED":
            self.add("onprem_wg_global", "BLOCKED", global_state["display"], blocker="ONPREM_COMMON_PATH_FAILURE", category="network")
        elif global_state["state"] == "PASS_PARTIAL_LIVE":
            self.add("onprem_wg_global", "PASS", "Web is live; inactive peers are not treated as global WG failure", category="network")
        else:
            self.add("onprem_wg_global", "WARN", global_state["display"], category="network")
        self.add(
            "onprem_health_path",
            "PASS" if global_state["state"] == "PASS_PARTIAL_LIVE" else "WARN",
            "host-level states are classified independently; no global WG failure inferred",
            category="network",
        )
        self.add(
            "onprem_zabbix_agent_path",
            "PASS" if global_state["state"] == "PASS_PARTIAL_LIVE" else "WARN",
            global_state["display"],
            category="network",
        )

        wazuh_external_path_enabled = _is_true(
            self.value("AWS_WAZUH_EXTERNAL_PATH_ENABLED", "false")
        )
        manager_host = self.value("WAZUH_MANAGER_HOST")
        if not wazuh_external_path_enabled:
            self.add(
                "onprem_wazuh_path",
                "DISABLED",
                "TCP/1514 and TCP/1515 are not required: AWS external Wazuh path is disabled by design",
                category="network",
            )
        elif manager_host:
            for port in (1514, 1515):
                ok, detail = self.tcp(manager_host, port)
                self.add(f"onprem_wazuh_{port}", "PASS" if ok else "BLOCKED", detail, blocker=None if ok else f"ONPREM_WAZUH_{port}_BLOCKED", category="network")
        else:
            self.add(
                "onprem_wazuh_path",
                "BLOCKED",
                "WAZUH_MANAGER_HOST is not configured while the external Wazuh path is enabled",
                blocker="BLOCKED_TEAM_DEPENDENCY_WAZUH_PATH",
                category="network",
            )

    def check_aws(self) -> None:
        if shutil.which("aws") is None:
            self.add("aws_credentials", "BLOCKED", "AWS CLI unavailable", blocker="AWS_CLI_UNAVAILABLE", category="aws")
            return
        rc, identity = self.runner(["aws", "sts", "get-caller-identity", "--query", "Arn", "--output", "text"])
        if rc != 0 or not identity:
            self.add("aws_credentials", "BLOCKED", "read-only AWS identity unavailable", blocker="AWS_CREDENTIALS_UNAVAILABLE", category="aws")
            return
        self.add("aws_credentials", "PASS", "read-only AWS identity available", category="aws")
        image_tag = self.value("DR_IMAGE_TAG", self.git_head)
        for name, default_repository in (("web", "hospital-dr-web"), ("emr", "hospital-dr-emr")):
            repository = self.value(f"ECR_{name.upper()}_REPOSITORY", default_repository)
            image_rc, image_output = self.runner([
                "aws", "ecr", "describe-images", "--region", self.value("AWS_REGION", DEFAULT_REGION),
                "--repository-name", repository, "--image-ids", f"imageTag={image_tag}",
                "--query", "imageDetails[0].imageDigest", "--output", "text",
            ])
            image_ok = bool(re.fullmatch(r"sha256:[0-9a-fA-F]{64}", image_output.strip())) if image_rc == 0 else False
            self.add(
                f"ecr_{name}",
                "PASS" if image_ok else "BLOCKED",
                f"immutable {name} image exists" if image_ok else f"immutable {name} image for current HEAD is unavailable",
                blocker=None if image_ok else f"ECR_IMAGE_MISSING_{name.upper()}",
                category="aws",
            )
        ids = list(DEFAULT_INSTANCE_IDS.values())
        rc, output = self.runner(["aws", "ec2", "describe-instances", "--region", self.value("AWS_REGION", DEFAULT_REGION), "--instance-ids", *ids, "--output", "json"])
        try:
            instances = [item for reservation in json.loads(output).get("Reservations", []) for item in reservation.get("Instances", [])] if rc == 0 else []
        except (ValueError, TypeError, json.JSONDecodeError):
            instances = []
        by_id = {item.get("InstanceId"): item for item in instances}
        mapping_ok = True
        stopped = True
        for instance_id, expected in EXPECTED_INSTANCES.items():
            item = by_id.get(instance_id)
            mapping_ok = mapping_ok and bool(item) and item.get("PrivateIpAddress") == expected["private_ip"]
            stopped = stopped and bool(item) and item.get("State", {}).get("Name") == "stopped"
        if not mapping_ok:
            self.add("aws_instance_mapping", "BLOCKED", "expected instance/IP mapping is not stable", blocker="AWS_INSTANCE_MAPPING_MISMATCH", category="aws")
        elif stopped:
            self.add("aws_state", "PASS", "SUSPENDED_EXPECTED", category="aws")
        else:
            self.add("aws_state", "PASS", "live state requires SSM/agent checks", category="aws")

        rc, output = self.runner(["aws", "ssm", "describe-instance-information", "--region", self.value("AWS_REGION", DEFAULT_REGION), "--filters", f"Key=InstanceIds,Values={','.join(ids)}", "--output", "json"])
        try:
            information = json.loads(output).get("InstanceInformationList", []) if rc == 0 else []
        except (ValueError, TypeError, json.JSONDecodeError):
            information = []
        online = {item.get("InstanceId") for item in information if item.get("PingStatus") == "Online"}
        if stopped:
            self.add("aws_ssm", "PASS", "not required while EC2 is SUSPENDED_EXPECTED", category="aws")
        else:
            self.add("aws_ssm", "PASS" if set(ids).issubset(online) else "BLOCKED", "all three Online" if set(ids).issubset(online) else "one or more instances not Online in SSM", blocker=None if set(ids).issubset(online) else "AWS_SSM_NOT_ONLINE", category="aws")

        eip_rc, eip_output = self.runner(["aws", "ec2", "describe-addresses", "--region", self.value("AWS_REGION", DEFAULT_REGION), "--public-ips", "AWS_PUBLIC_IP_REDACTED", "AWS_PUBLIC_IP_REDACTED", "--output", "json"])
        try:
            ips = {item.get("PublicIp") for item in json.loads(eip_output).get("Addresses", [])} if eip_rc == 0 else set()
        except (ValueError, TypeError, json.JSONDecodeError):
            ips = set()
        self.add("aws_eips", "PASS" if {"AWS_PUBLIC_IP_REDACTED", "AWS_PUBLIC_IP_REDACTED"}.issubset(ips) else "BLOCKED", "fixed EIPs present" if {"AWS_PUBLIC_IP_REDACTED", "AWS_PUBLIC_IP_REDACTED"}.issubset(ips) else "fixed EIP missing", blocker=None if {"AWS_PUBLIC_IP_REDACTED", "AWS_PUBLIC_IP_REDACTED"}.issubset(ips) else "FIXED_EIP_MISSING", category="aws")

        # Cost/safety invariant for the frozen standby state.  These are
        # read-only checks; the checker never removes a gateway or route.
        nat_rc, nat_output = self.runner([
            "aws", "ec2", "describe-nat-gateways", "--region", self.value("AWS_REGION", DEFAULT_REGION),
            "--filter", "Name=state,Values=pending,available,active,deleting", "--output", "json",
        ])
        try:
            nat_gateways = json.loads(nat_output).get("NatGateways", []) if nat_rc == 0 else []
        except (ValueError, TypeError, json.JSONDecodeError):
            nat_gateways = []
        if nat_rc == 0:
            self.add(
                "aws_nat_gateways",
                "PASS" if not nat_gateways else "BLOCKED",
                "no active/pending/deleting NAT Gateway" if not nat_gateways else "unexpected NAT Gateway exists",
                blocker=None if not nat_gateways else "AWS_NAT_GATEWAY_PRESENT",
                category="aws",
            )
        else:
            self.add("aws_nat_gateways", "BLOCKED", "NAT Gateway state is unreadable", blocker="AWS_NAT_STATE_UNREADABLE", category="aws")

        vpc_ids = sorted({item.get("VpcId") for item in by_id.values() if item.get("VpcId")})
        if vpc_ids:
            route_rc, route_output = self.runner([
                "aws", "ec2", "describe-route-tables", "--region", self.value("AWS_REGION", DEFAULT_REGION),
                "--filters", f"Name=vpc-id,Values={','.join(vpc_ids)}", "--output", "json",
            ])
            try:
                route_tables = json.loads(route_output).get("RouteTables", []) if route_rc == 0 else []
            except (ValueError, TypeError, json.JSONDecodeError):
                route_tables = []
            nat_routes = [
                route
                for table in route_tables
                for route in table.get("Routes", [])
                if route.get("DestinationCidrBlock") == "AWS_PUBLIC_IP_REDACTED/0" and route.get("NatGatewayId")
            ]
            if route_rc == 0:
                self.add(
                    "aws_private_nat_route",
                    "PASS" if not nat_routes else "BLOCKED",
                    "no private default route through NAT" if not nat_routes else "private default route points to NAT",
                    blocker=None if not nat_routes else "AWS_PRIVATE_NAT_ROUTE_PRESENT",
                    category="aws",
                )
            else:
                self.add("aws_private_nat_route", "BLOCKED", "route-table state is unreadable", blocker="AWS_ROUTE_STATE_UNREADABLE", category="aws")

        self.add(
            "aws_zabbix_monitoring",
            "DISABLED",
            "continuous AWS Zabbix server monitoring retired; AWS DR hosts are not part of the active dashboard",
            category="aws",
        )
        aws_agent_scripts = (self.root / "operations/aws/apply_endpoint_security.sh").is_file() and (self.root / "operations/aws/aws_endpoint_security_bootstrap.sh").is_file()
        self.add("aws_endpoint_contract", "PASS" if aws_agent_scripts else "BLOCKED", "SSM endpoint-security bootstrap present" if aws_agent_scripts else "AWS endpoint bootstrap missing", blocker=None if aws_agent_scripts else "AWS_ENDPOINT_CONTRACT_MISSING", category="aws")
        zabbix_enabled = _is_true(self.value("AWS_ZABBIX_EXTERNAL_PATH_ENABLED", "false"))
        wazuh_enabled = _is_true(self.value("AWS_WAZUH_EXTERNAL_PATH_ENABLED", "false"))
        zabbix_configured = bool(self.value("AWS_ZABBIX_ACTIVE_SERVER"))
        wazuh_configured = bool(self.value("AWS_WAZUH_MANAGER"))
        self.add(
            "aws_zabbix_external_path",
            "PASS" if zabbix_enabled and zabbix_configured else "BLOCKED" if zabbix_enabled else "DISABLED",
            "AWS Zabbix external path explicitly enabled" if zabbix_enabled and zabbix_configured else "AWS Zabbix endpoint is required when the path is enabled" if zabbix_enabled else "disabled by design: MSP is behind uncontrolled upstream NAT",
            blocker=None if (not zabbix_enabled or zabbix_configured) else "AWS_ZABBIX_ENDPOINT_MISSING",
            category="aws",
        )
        self.add(
            "aws_wazuh_external_path",
            "PASS" if wazuh_enabled and wazuh_configured else "BLOCKED" if wazuh_enabled else "DISABLED",
            "AWS Wazuh external path explicitly enabled" if wazuh_enabled and wazuh_configured else "AWS Wazuh endpoint is required when the path is enabled" if wazuh_enabled else "disabled by design: MSP is behind uncontrolled upstream NAT",
            blocker=None if (not wazuh_enabled or wazuh_configured) else "AWS_WAZUH_ENDPOINT_MISSING",
            category="aws",
        )
        self.add(
            "aws_agent_endpoint_values",
            "PASS" if (zabbix_configured and wazuh_configured) else "DISABLED" if not zabbix_enabled and not wazuh_enabled else "BLOCKED",
            "endpoint inputs preserved for future controlled environment; active use disabled" if not zabbix_enabled and not wazuh_enabled else "external AWS agent endpoints configured" if zabbix_configured and wazuh_configured else "enabled endpoint input is missing",
            blocker=None if ((not zabbix_enabled and not wazuh_enabled) or (zabbix_configured and wazuh_configured)) else "AWS_AGENT_ENDPOINT_VALUES_MISSING",
            category="aws",
        )
        dashboard = self.root / "monitoring/grafana/provisioning/dashboards/json/hospital-aws-dr-security.json"
        self.add("aws_grafana_contract", "PASS" if dashboard.is_file() else "BLOCKED", "AWS dashboard provisioning present" if dashboard.is_file() else "AWS dashboard missing", blocker=None if dashboard.is_file() else "AWS_GRAFANA_CONTRACT_MISSING", category="aws")

    def check_external_ingress(self) -> None:
        # The current MSP is behind an uncontrolled upstream NAT. These ports
        # are intentionally not part of the current architecture; retaining
        # them as live blockers would misclassify a disabled-by-design path.
        paths = (
            ("msp_zabbix_ingress", 10051, "AWS_ZABBIX_EXTERNAL_PATH_ENABLED"),
            ("msp_wazuh_ingress", 1514, "AWS_WAZUH_EXTERNAL_PATH_ENABLED"),
            ("msp_wazuh_enrollment", 1515, "AWS_WAZUH_EXTERNAL_PATH_ENABLED"),
        )
        for name, port, flag in paths:
            if not _is_true(self.value(flag, "false")):
                self.add(name, "DISABLED", f"TCP/{port} not required: AWS external Agent path disabled by design", category="network")
            else:
                self.add(name, "BLOCKED", f"external source-path test requires live AWS source on TCP/{port}", blocker=f"BLOCKED_EXTERNAL_TCP_{port}", category="network")

    def check_direct_nr(self) -> None:
        scripts = all((self.root / path).is_file() for path in ("operations/db/db_nr_source_setup.sh", "operations/db/db_backup.sh", "operations/db/db_failback_to_onprem.sh"))
        self.add("direct_nr_scripts", "PASS" if scripts else "BLOCKED", "NR scripts present" if scripts else "NR scripts incomplete", blocker=None if scripts else "DIRECT_NR_SCRIPTS_MISSING", category="nr")
        pair_paths = self.value("DB_BACKUP_SEARCH_PATHS", "/home/cloud/db_backups:/var/lib/hospital-dr/db_backups").split(":")
        pair_found = False
        for directory in pair_paths:
            root = Path(directory)
            if not root.is_dir():
                continue
            for dump in root.glob("db_backup_*.sql.gz.enc"):
                status = dump.with_name(dump.name.removesuffix(".sql.gz.enc") + ".master_status")
                if status.is_file() and dump.stat().st_size > 0 and status.stat().st_size > 0:
                    pair_found = True
                    break
        if not pair_found and self.value("S3_BACKUP_BUCKET"):
            s3_args = [
                "aws", "s3api", "list-objects-v2", "--region", self.value("AWS_REGION", DEFAULT_REGION),
                "--bucket", self.value("S3_BACKUP_BUCKET"),
                "--prefix", f"{self.value('S3_BACKUP_PREFIX', 'mysql/hospital_db').rstrip('/')}/",
                "--query", "Contents[].{Key:Key,Size:Size}", "--output", "json",
            ]
            if self.value("S3_BACKUP_AWS_PROFILE"):
                s3_args.extend(["--profile", self.value("S3_BACKUP_AWS_PROFILE")])
            s3_rc, s3_output = self.runner(s3_args, timeout=30)
            try:
                objects = json.loads(s3_output) if s3_rc == 0 else []
            except (ValueError, TypeError, json.JSONDecodeError):
                objects = []
            names: set[str] = set()
            for item in objects:
                if not isinstance(item, dict) or not item.get("Key"):
                    continue
                try:
                    size = int(item.get("Size") or 0)
                except (TypeError, ValueError):
                    continue
                if size > 0:
                    names.add(str(item["Key"]))
            pair_found = any(
                name.endswith(".sql.gz.enc")
                and name.removesuffix(".sql.gz.enc") + ".master_status" in names
                for name in names
            )
        self.add("direct_nr_backup_pair", "PASS" if pair_found else "BLOCKED", "encrypted dump and master_status pair found" if pair_found else "complete local pair not found", blocker=None if pair_found else "DIRECT_NR_BACKUP_PAIR_MISSING", category="nr")
        key = self.value("DB_BACKUP_ENCRYPTION_KEY")
        self.add("direct_nr_backup_key", "PASS" if key else "BLOCKED", "backup encryption key is present in external environment" if key else "backup encryption key is not available", blocker=None if key else "DB_BACKUP_ENCRYPTION_KEY_MISSING", category="nr")
        if _is_false(self.value("DB_NR_ENABLED")):
            self.add("direct_nr_live", "BLOCKED", "DB_NR_ENABLED=false; pfSense/source path and NR validation remain team-gated", blocker="DIRECT_NR_BLOCKED_TEAM_PFSENSE", category="nr")
        else:
            self.add("direct_nr_live", "PASS", "NR flag enabled; live evidence still required", category="nr")

    def check_slack(self) -> None:
        required = (
            "SLACK_CHANNEL_ID",
            "SLACK_ALERT_CHANNEL_ID",
            "SLACK_FAILOVER_BOT_TOKEN",
            "SLACK_FAILBACK_BOT_TOKEN",
            "SLACK_EMERGENCY_CHANNEL_ID",
            "SLACK_EMERGENCY_BOT_TOKEN",
            "SLACK_EMERGENCY_SIGNING_SECRET",
        )
        missing = [name for name in required if not self.value(name)]
        channels_separate = bool(self.value("SLACK_CHANNEL_ID")) and bool(self.value("SLACK_ALERT_CHANNEL_ID")) and self.value("SLACK_CHANNEL_ID") != self.value("SLACK_ALERT_CHANNEL_ID")
        if missing:
            self.add("slack_channels_tokens", "BLOCKED", "required Slack contract is incomplete", blocker="SLACK_CONTRACT_MISSING", category="slack")
        elif not channels_separate:
            self.add("slack_channels_tokens", "BLOCKED", "approval and general alert channels must be separate", blocker="SLACK_CHANNELS_NOT_SEPARATED", category="slack")
        else:
            self.add("slack_channels_tokens", "PASS", "channel/token contract present; no message sent", category="slack")
        approvers = _unique_csv(self.value("SLACK_ADMIN_USER_IDS"))
        self.add("slack_two_person", "PASS" if len(approvers) >= 2 else "BLOCKED", f"distinct_approvers={len(approvers)}" if len(approvers) >= 2 else "distinct approver count is below two", blocker=None if len(approvers) >= 2 else "BLOCKED_SECOND_APPROVER", category="slack")

    def _zabbix_api_read(self, method: str, params: dict[str, Any]) -> Any:
        """Read Zabbix configuration without emitting credentials."""

        api_url = self.value("ZABBIX_CONTROLLER_API_URL", "http://IP_REDACTED/api_jsonrpc.php")
        request_id = 0

        def call(request_method: str, request_params: dict[str, Any], auth: str | None = None) -> Any:
            nonlocal request_id
            request_id += 1
            body: dict[str, Any] = {
                "jsonrpc": "2.0",
                "method": request_method,
                "params": request_params,
                "id": request_id,
            }
            if auth:
                body["auth"] = auth
            request = urllib.request.Request(
                api_url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json-rpc"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if payload.get("error"):
                raise ValueError("Zabbix API error")
            return payload.get("result")

        token = self.value("ZABBIX_API_TOKEN")
        if token:
            auth = token
        else:
            auth = call(
                "user.login",
                {"user": self.value("ZABBIX_API_USER"), "password": self.value("ZABBIX_API_PASSWORD")},
            )
        return call(method, params, auth=auth)

    def check_snmp(self) -> None:
        targets_file = self.value("SNMP_TARGETS_FILE")
        names = _unique_csv(self.value("SNMP_HOST_NAMES"))
        if targets_file and Path(targets_file).is_file():
            self.add("snmp_config", "PASS", "SNMP target contract file exists; live polling remains a separate path", category="snmp")
        elif names:
            self.add("snmp_config", "PASS", f"configured_hosts={len(names)}; live polling remains a separate path", category="snmp")
        else:
            expected = (
                "Cisco-2800-Series",
                "Catalyst-2950-Series",
                "Catalyst-3560-Series",
                "Catalyst-3550-Series",
            )
            try:
                hosts: list[dict[str, Any]] = []
                for host_name in expected:
                    rows = self._zabbix_api_read(
                        "host.get",
                        {
                            "output": ["hostid", "host"],
                            "filter": {"host": host_name},
                            "selectInterfaces": ["type", "available", "ip", "port"],
                        },
                    )
                    if rows:
                        hosts.append(rows[0])
                available = [
                    host
                    for host in hosts
                    if any(
                        str(interface.get("type")) == "2" and str(interface.get("available")) == "1"
                        for interface in host.get("interfaces", [])
                    )
                ]
                if len(hosts) == len(expected) and len(available) == len(expected):
                    self.add("snmp_config", "PASS", "four configured Zabbix SNMP hosts available=1", category="snmp")
                else:
                    self.add(
                        "snmp_config",
                        "BLOCKED",
                        f"Zabbix SNMP hosts available={len(available)}/{len(expected)}",
                        blocker="BLOCKED_PHYSICAL_PATH_SNMP",
                        category="snmp",
                    )
            except (OSError, ValueError, TypeError, urllib.error.URLError, json.JSONDecodeError):
                self.add("snmp_config", "BLOCKED", "physical SNMP path/target owner is not available", blocker="BLOCKED_PHYSICAL_PATH_SNMP", category="snmp")

    def check_legacy_gate(self) -> None:
        script = self.root / "operations/runtime/final_dr_preflight.sh"
        if not self.include_legacy or not script.is_file():
            return
        rc, output = self.runner([str(script)], timeout=90, env={**os.environ, **self.values})
        match = re.search(r"FINAL_DR_READY=(true|false)", output)
        if rc == 0 and match and match.group(1) == "true":
            self.add("legacy_final_dr_gate", "PASS", "existing final_dr_preflight.sh passed", category="legacy")
        else:
            self.add("legacy_final_dr_gate", "WARN", "existing lower-level gate is not fully green; detailed blockers are reported by this checker", category="legacy")

    def run(self) -> dict[str, Any]:
        self.git_head = ""
        self.check_local_repo()
        self.check_clock_sync()
        self.check_runtime_drift()
        self.check_egress_workflow_contract()
        self.check_zabbix_failback_runtime()
        self.check_ci()
        self.check_msp()
        self.check_chatops_runtime_state()
        self.check_onprem_path()
        self.check_aws()
        self.check_external_ingress()
        self.check_direct_nr()
        self.check_slack()
        self.check_fixed_slack_endpoint()
        self.check_snmp()
        self.check_legacy_gate()
        result = assess_readiness(self.checks, root=self.root, git_commit=self.git_head, warnings=self.warnings)
        result["onprem_state"] = self.onprem_state
        return result


def render_summary(result: dict[str, Any]) -> str:
    labels = {
        "repository": "Repository",
        "github_actions": "GitHub Actions",
        "zabbix_msp": "Zabbix MSP",
        "wazuh_manager": "Wazuh Manager",
        "wazuh_indexer": "Wazuh Indexer",
        "grafana": "Grafana",
        "chatops": "ChatOps",
        "clock_sync_msp": "MSP Clock Sync",
        "runtime_drift": "Runtime Drift",
        "egress_workflow": "Egress Workflow",
        "zabbix_failback_runtime": "Zabbix Failback Runtime",
        "chatops_state": "ChatOps State",
        "chatops_execution_lock": "ChatOps Execution Lock",
        "onprem_health_path": "On-Prem Health",
        "onprem_zabbix_agent_path": "On-Prem Zabbix/WG",
        "onprem_wg_global": "On-Prem WG Global",
        "onprem_web_state": "On-Prem Web State",
        "onprem_emr_state": "On-Prem EMR State",
        "onprem_db_state": "On-Prem DB State",
        "aws_state": "AWS State",
        "aws_ssm": "AWS SSM",
        "ecr_web": "ECR Web",
        "ecr_emr": "ECR EMR",
        "aws_nat_gateways": "AWS NAT Gateways",
        "aws_private_nat_route": "AWS Private NAT Route",
        "aws_eips": "AWS Preserved EIPs",
        "aws_zabbix_monitoring": "AWS Zabbix Monitoring",
        "aws_endpoint_contract": "AWS Wazuh Config",
        "aws_zabbix_external_path": "AWS Zabbix External Path",
        "aws_wazuh_external_path": "AWS Wazuh External Path",
        "aws_agent_endpoint_values": "AWS Agent Endpoint Contract",
        "msp_zabbix_ingress": "MSP Zabbix Ingress",
        "msp_wazuh_ingress": "MSP Wazuh Ingress",
        "direct_nr_live": "Direct NR",
        "slack_two_person": "Slack 2/2",
        "slack_fixed_endpoint": "Slack Fixed Endpoint",
        "snmp_config": "SNMP Live",
    }
    lines = ["FINAL LIVE E2E PREFLIGHT", "========================", ""]
    for key, label in labels.items():
        check = result["checks"].get(key)
        if not check:
            continue
        status = check["status"]
        if key == "aws_state" and status == "PASS" and "SUSPENDED_EXPECTED" in check["detail"]:
            status = "SUSPENDED_EXPECTED"
        lines.append(f"{label:<22} {status}")
    lines.extend(
        [
            "",
            f"SAFE_TO_START_LIVE_E2E={str(result['safe_to_start_live_e2e']).lower()}",
            f"DEMO_READY={str(result['demo_ready']).lower()}",
            "",
            "READINESS:",
        ]
    )
    lines.extend(
        f"{key.upper()}={str(value).upper()}"
        for key, value in result.get("readiness", {}).items()
    )
    onprem = result.get("onprem_state", {})
    if onprem:
        lines.extend(
            [
                "",
                "ONPREM_STATE:",
                f"WEB={onprem.get('web', {}).get('display', 'UNKNOWN')}",
                f"EMR={onprem.get('emr', {}).get('display', 'UNKNOWN')}",
                f"DB={onprem.get('db', {}).get('display', 'UNKNOWN')}",
                f"GLOBAL={onprem.get('global', {}).get('display', 'UNKNOWN')}",
            ]
        )
    lines.extend(
        [
            "",
            "BLOCKERS:",
        ]
    )
    lines.extend(f"- {item}" for item in result["blockers"] or ["NONE"])
    lines.append("TEAM_DEPENDENCIES:")
    lines.extend(f"- {item}" for item in result["team_dependencies"] or ["NONE"])
    lines.append("ENVIRONMENT_LIMITATIONS:")
    lines.extend(f"- {item}" for item in result.get("environment_limitations", []) or ["NONE"])
    return "\n".join(lines)


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=True, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o640)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=Path(os.environ.get("DR_SECRET_FILE", DEFAULT_SECRET_FILE)))
    parser.add_argument("--aux-env-file", type=Path, action="append", default=[], help="Optional existing runtime env source (for example Grafana's Indexer credentials)")
    parser.add_argument("--json-output", type=Path, default=ROOT / "artifacts/preflight/final-live-e2e-preflight.json")
    parser.add_argument("--no-legacy-shell", action="store_true", help="Skip the existing final_dr_preflight.sh sub-gate")
    args = parser.parse_args(argv)
    values = merged_values(args.env_file, args.aux_env_file)
    checker = FinalLivePreflight(values=values, include_legacy=not args.no_legacy_shell)
    result = checker.run()
    write_json(args.json_output, result)
    print(render_summary(result))
    print(f"JSON_OUTPUT={args.json_output}")
    return 0 if result["safe_to_start_live_e2e"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
