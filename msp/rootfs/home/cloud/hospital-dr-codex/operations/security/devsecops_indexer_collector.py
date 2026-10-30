#!/usr/bin/env python3
"""Persist GitHub Actions and derived Wazuh incidents in the Wazuh Indexer.

The collector deliberately reuses the existing MSP Wazuh Indexer.  GitHub
Actions emits a secret-free JSON summary in its job log; this process reads
that summary through ``gh`` and stores one normalized document per run.  It
also derives deterministic incidents from real indexed Wazuh alerts without
writing raw alert payloads to the custom incident index.

No AWS, DR, active-response, Slack, or endpoint operation is performed.
Indexer TLS verification is enabled by default.  A local operator may use
``--insecure`` explicitly for a diagnostic run only.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from urllib.parse import quote, urlsplit

import requests


CHATOPS_DIR = Path(__file__).resolve().parents[1] / "chatops"
if str(CHATOPS_DIR) not in sys.path:
    sys.path.insert(0, str(CHATOPS_DIR))

from wazuh_correlation import correlate_signals  # noqa: E402


DEVSECOPS_INDEX = "hospital-devsecops-executions"
SECURITY_INCIDENTS_INDEX = "hospital-security-incidents"
SUMMARY_BEGIN = "DEVSECOPS_SUMMARY_JSON_BEGIN"
SUMMARY_END = "DEVSECOPS_SUMMARY_JSON_END"
SHA256_RE = re.compile(r"digest:\s+(sha256:[0-9a-f]{64})", re.IGNORECASE)
_TEMP_CA_FILES: list[str] = []


def _cleanup_temp_cas():
    for path in _TEMP_CA_FILES:
        try:
            os.unlink(path)
        except OSError:
            pass


atexit.register(_cleanup_temp_cas)


def _strip_ansi(value):
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value))


def _gh_json(repository, endpoint):
    command = ["gh", "api", f"repos/{repository}/{endpoint}"]
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"GitHub API unavailable: {type(exc).__name__}") from exc
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("GitHub API returned invalid JSON") from exc


def _gh_log(repository, run_id):
    command = ["gh", "run", "view", str(run_id), "--repo", repository, "--log"]
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"GitHub run log unavailable: {type(exc).__name__}") from exc
    return completed.stdout


def latest_completed_run(repository, branch="main", limit=20):
    payload = _gh_json(
        repository,
        f"actions/runs?branch={quote(branch, safe='')}&per_page={max(1, min(int(limit), 100))}",
    )
    runs = payload.get("workflow_runs") if isinstance(payload, dict) else []
    completed = [item for item in runs or [] if item.get("status") == "completed"]
    if not completed:
        raise RuntimeError("No completed GitHub Actions run was found")
    return sorted(completed, key=lambda item: item.get("updated_at", ""), reverse=True)[0]


def _job_result(jobs, *fragments):
    matches = [
        job
        for job in jobs
        if all(fragment.lower() in str(job.get("name", "")).lower() for fragment in fragments)
    ]
    if not matches:
        return "NOT_REPORTED"
    if any(job.get("conclusion") == "success" for job in matches):
        return "PASS"
    if any(job.get("conclusion") in {"failure", "cancelled", "timed_out"} for job in matches):
        return "FAIL"
    return "NOT_REPORTED"


def _job_name(line):
    return _strip_ansi(line.split("\t", 1)[0]).strip().lower()


def _log_payload(line):
    value = _strip_ansi(line.split("\t", 3)[-1]).rstrip("\r")
    # `gh run view --log` prefixes each emitted line with an ISO timestamp.
    # Remove only that transport prefix; the JSON content remains unchanged.
    return re.sub(r"^\ufeff?\d{4}-\d{2}-\d{2}T[^ ]+Z\s*", "", value)


def extract_security_summaries(log_text):
    """Extract the explicit JSON blocks emitted by the CI workflow."""
    summaries = {}
    active = None
    chunks = []
    for raw_line in str(log_text or "").splitlines():
        line = _strip_ansi(raw_line)
        if SUMMARY_BEGIN in line:
            job = _job_name(raw_line)
            active = "emr" if "emr" in job else "web" if "web" in job else None
            chunks = []
            continue
        if SUMMARY_END in line:
            if active:
                text = "\n".join(chunks)
                start, end = text.find("{"), text.rfind("}")
                if start >= 0 and end > start:
                    try:
                        value = json.loads(text[start : end + 1])
                    except json.JSONDecodeError:
                        value = None
                    if isinstance(value, dict):
                        summaries[active] = value
            active = None
            chunks = []
            continue
        if active:
            chunks.append(_log_payload(raw_line))
    return summaries


def extract_ecr_digests(log_text):
    digests = {}
    for raw_line in str(log_text or "").splitlines():
        match = SHA256_RE.search(_strip_ansi(raw_line))
        if not match:
            continue
        job = _job_name(raw_line)
        if "web" in job:
            digests["web"] = match.group(1)
        elif "emr" in job:
            digests["emr"] = match.group(1)
    return digests


def _sum_summary_counts(summaries, scope, severity):
    values = []
    for summary in summaries.values():
        trivy = summary.get("trivy") if isinstance(summary, dict) else None
        for report in (trivy or {}).values():
            if isinstance(report, dict) and isinstance(report.get(severity), int):
                values.append(report[severity])
    return sum(values) if values else None


def build_devsecops_document(run, jobs, log_text, repository):
    summaries = extract_security_summaries(log_text)
    digests = extract_ecr_digests(log_text)
    checks = {
        "unittest": _job_result(jobs, "python unittest"),
        "gitleaks": _job_result(jobs, "secret scan"),
        "trivy": _job_result(jobs, "build and scan"),
        "docker_scan": _job_result(jobs, "build and scan"),
        "terraform": _job_result(jobs, "terraform format"),
        "ansible": _job_result(jobs, "ansible playbook"),
        "ecr_push": _job_result(jobs, "push gated"),
    }
    return {
        "schema_version": 1,
        "source": "github-actions",
        "event_type": "github_actions_devsecops",
        "timestamp": run.get("updated_at") or run.get("created_at"),
        "run_id": str(run.get("id", "")),
        "run_number": run.get("run_number"),
        "repository": repository,
        "branch": run.get("head_branch"),
        "workflow": run.get("name") or "Quality Gate and Docker Security Scan",
        "run_url": run.get("html_url"),
        "commit_sha": run.get("head_sha"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "checks": checks,
        "unittest": checks["unittest"],
        "gitleaks": checks["gitleaks"],
        "trivy": checks["trivy"],
        "docker_scan": checks["docker_scan"],
        "terraform": checks["terraform"],
        "ansible": checks["ansible"],
        "ecr_push": checks["ecr_push"],
        "trivy_high": _sum_summary_counts(summaries, "", "high"),
        "trivy_critical": _sum_summary_counts(summaries, "", "critical"),
        "trivy_summary_available": bool(summaries),
        "web_image_digest": digests.get("web")
        or (summaries.get("web", {}).get("ecr_image_digest") if summaries.get("web") else None),
        "emr_image_digest": digests.get("emr")
        or (summaries.get("emr", {}).get("ecr_image_digest") if summaries.get("emr") else None),
        "security_summary_sources": sorted(summaries),
        "collector_schema": "hospital-devsecops/v1",
    }


def _extract_ca(source):
    text = Path(source).read_text(encoding="utf-8")
    match = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        text,
        re.DOTALL,
    )
    if not match:
        raise ValueError("Indexer CA source does not contain a certificate")
    certificate = "\n".join(line.strip() for line in match.group(0).splitlines())
    handle = tempfile.NamedTemporaryFile("w", prefix="devsecops-indexer-ca-", suffix=".pem", delete=False)
    handle.write(certificate + "\n")
    handle.close()
    os.chmod(handle.name, 0o600)
    _TEMP_CA_FILES.append(handle.name)
    return handle.name


def _read_credential_source(source):
    """Read existing operational Indexer credentials without logging values."""
    text = Path(source).read_text(encoding="utf-8")
    values = {}
    for line in text.splitlines():
        match = re.match(r"^\s*(?:-\s*)?(INDEXER_USERNAME|INDEXER_PASSWORD)=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2).strip().strip('"').strip("'")
    return values.get("INDEXER_USERNAME", ""), values.get("INDEXER_PASSWORD", "")


class IndexerWriter:
    def __init__(
        self,
        url,
        user,
        password,
        ca_cert="",
        ca_source="",
        credential_source="",
        connect_ip="",
        host_header="",
        insecure=False,
        timeout=15,
    ):
        if credential_source:
            source_user, source_password = _read_credential_source(credential_source)
            user = user or source_user
            password = password or source_password
        if not url or not user or not password:
            raise ValueError("Indexer URL and credentials are required")
        if insecure:
            self.verify = False
        elif ca_cert:
            if not os.path.isfile(ca_cert):
                raise ValueError("Indexer CA certificate is not readable")
            self.verify = ca_cert
        elif ca_source:
            self.verify = _extract_ca(ca_source)
        else:
            raise ValueError("Indexer CA certificate source is required")
        self.url = url.rstrip("/")
        self.auth = (user, password)
        self.connect_ip = connect_ip
        self.host_header = host_header
        self.timeout = timeout

    @contextmanager
    def _network_context(self):
        """Keep TLS SNI/verification on the service hostname when using a host port.

        The MSP host exposes the container's TLS listener on loopback while the
        certificate is issued to ``wazuh.indexer``.  This process-local resolver
        override avoids changing /etc/hosts or disabling certificate validation.
        """
        if not self.connect_ip:
            yield
            return
        target = (urlsplit(self.url).hostname or "").lower()
        original = socket.getaddrinfo

        def resolve(host, port, *args, **kwargs):
            if str(host).lower() == target:
                host = self.connect_ip
            return original(host, port, *args, **kwargs)

        socket.getaddrinfo = resolve
        try:
            yield
        finally:
            socket.getaddrinfo = original

    def _request_raw(self, method, path, **kwargs):
        headers = dict(kwargs.pop("headers", {}) or {})
        if self.host_header:
            headers.setdefault("Host", self.host_header)
        if headers:
            kwargs["headers"] = headers
        with self._network_context():
            return requests.request(
                method,
                f"{self.url}/{path.lstrip('/')}",
                auth=self.auth,
                verify=self.verify,
                timeout=self.timeout,
                **kwargs,
            )

    def _request(self, method, path, **kwargs):
        response = self._request_raw(method, path, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(f"Indexer HTTP {response.status_code}")
        return response

    def ensure_index(self, name, mappings):
        response = self._request_raw("GET", quote(name, safe=""))
        if response.status_code == 200:
            return "EXISTS"
        if response.status_code != 404:
            raise RuntimeError(f"Indexer index check HTTP {response.status_code}")
        self._request("PUT", quote(name, safe=""), json={"mappings": {"properties": mappings}})
        return "CREATED"

    def index_document(self, name, document_id, document):
        self._request(
            "PUT",
            f"{quote(name, safe='')}/_doc/{quote(str(document_id), safe='')}",
            params={"refresh": "wait_for"},
            json=document,
        )

    def search_alerts(self, lookback_minutes, limit=2000):
        query = {
            "size": max(1, min(int(limit), 5000)),
            "sort": [{"timestamp": {"order": "asc"}}],
            "_source": [
                "id",
                "timestamp",
                "@timestamp",
                "agent",
                "rule",
                "data",
                "location",
                "full_log",
            ],
            "query": {"range": {"timestamp": {"gte": f"now-{int(lookback_minutes)}m"}}},
        }
        response = self._request("POST", "wazuh-alerts-*/_search", json=query)
        hits = response.json().get("hits", {}).get("hits", [])
        return [item.get("_source", {}) for item in hits if isinstance(item, dict)]


DEVSECOPS_MAPPING = {
    "timestamp": {"type": "date"},
    "run_id": {"type": "keyword"},
    "run_number": {"type": "integer"},
    "repository": {"type": "keyword"},
    "branch": {"type": "keyword"},
    "workflow": {"type": "keyword"},
    "commit_sha": {"type": "keyword"},
    "status": {"type": "keyword"},
    "conclusion": {"type": "keyword"},
    "checks": {"type": "object", "enabled": True},
    "trivy_high": {"type": "integer"},
    "trivy_critical": {"type": "integer"},
    "trivy_summary_available": {"type": "boolean"},
    "web_image_digest": {"type": "keyword"},
    "emr_image_digest": {"type": "keyword"},
    "security_summary_sources": {"type": "keyword"},
    "collector_schema": {"type": "keyword"},
    "unittest": {"type": "keyword"},
    "gitleaks": {"type": "keyword"},
    "trivy": {"type": "keyword"},
    "docker_scan": {"type": "keyword"},
    "terraform": {"type": "keyword"},
    "ansible": {"type": "keyword"},
    "ecr_push": {"type": "keyword"},
}

INCIDENT_MAPPING = {
    "timestamp": {"type": "date"},
    "incident_id": {"type": "keyword"},
    "agent": {"type": "keyword"},
    "scenario": {"type": "keyword"},
    "severity": {"type": "keyword"},
    "source_rules": {"type": "keyword"},
    "first_seen": {"type": "date"},
    "last_seen": {"type": "date"},
    "evidence": {"type": "object", "enabled": False},
    "source": {"type": "keyword"},
    "synthetic": {"type": "boolean"},
}


def build_incident_document(incident):
    return {
        "timestamp": incident["last_seen"],
        "incident_id": incident["incident_id"],
        "agent": incident["agent"],
        "scenario": incident["scenario"],
        "severity": incident["severity"],
        "source_rules": incident["source_rules"],
        "first_seen": incident["first_seen"],
        "last_seen": incident["last_seen"],
        "evidence": incident["evidence"],
        "source": "wazuh-indexer-correlation",
        "synthetic": False,
    }


def collect(args):
    run = latest_completed_run(args.repository, args.branch, args.run_limit)
    jobs_payload = _gh_json(args.repository, f"actions/runs/{run['id']}/jobs?per_page=100")
    jobs = jobs_payload.get("jobs", []) if isinstance(jobs_payload, dict) else []
    log_text = _gh_log(args.repository, run["id"])
    document = build_devsecops_document(run, jobs, log_text, args.repository)
    result = {
        "devsecops": "DRY_RUN" if args.dry_run else "NOT_WRITTEN",
        "run_id": document["run_id"],
        "commit_sha": document["commit_sha"],
        "trivy_summary_available": document["trivy_summary_available"],
        "security_summary_sources": document["security_summary_sources"],
        "xdr_incidents": 0,
    }
    if args.dry_run:
        return result

    writer = IndexerWriter(
        args.indexer_url,
        args.indexer_user,
        args.indexer_password,
        ca_cert=args.ca_cert,
        ca_source=args.ca_source,
        credential_source=args.credential_source,
        connect_ip=args.connect_ip,
        host_header=args.host_header,
        insecure=args.insecure,
    )
    writer.ensure_index(args.devsecops_index, DEVSECOPS_MAPPING)
    writer.index_document(args.devsecops_index, document["run_id"], document)
    result["devsecops"] = "PASS"

    writer.ensure_index(args.incidents_index, INCIDENT_MAPPING)
    alerts = writer.search_alerts(args.lookback_minutes, args.max_alerts)
    incidents = correlate_signals(alerts, window_seconds=args.correlation_window_seconds)
    for incident in incidents:
        writer.index_document(
            args.incidents_index,
            incident["incident_id"],
            build_incident_document(incident),
        )
    result["xdr_incidents"] = len(incidents)
    result["xdr"] = "PASS" if incidents else "NO_CORRELATED_INCIDENTS"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--branch", default=os.environ.get("DEVSECOPS_BRANCH", "main"))
    parser.add_argument("--run-limit", type=int, default=20)
    parser.add_argument("--indexer-url", default=os.environ.get("DEVSECOPS_INDEXER_URL") or os.environ.get("WAZUH_INDEXER_URL", ""))
    parser.add_argument(
        "--indexer-user",
        default=os.environ.get("DEVSECOPS_INDEXER_USER")
        or ("" if os.environ.get("DEVSECOPS_INDEXER_CREDENTIAL_SOURCE") else os.environ.get("WAZUH_INDEXER_USER", "")),
    )
    parser.add_argument(
        "--indexer-password",
        default=os.environ.get("DEVSECOPS_INDEXER_PASSWORD")
        or ("" if os.environ.get("DEVSECOPS_INDEXER_CREDENTIAL_SOURCE") else os.environ.get("WAZUH_INDEXER_PASSWORD", "")),
    )
    parser.add_argument("--ca-cert", default=os.environ.get("DEVSECOPS_INDEXER_CA_CERT", ""))
    parser.add_argument("--ca-source", default=os.environ.get("DEVSECOPS_INDEXER_CA_SOURCE", ""))
    parser.add_argument("--credential-source", default=os.environ.get("DEVSECOPS_INDEXER_CREDENTIAL_SOURCE", ""))
    parser.add_argument("--connect-ip", default=os.environ.get("DEVSECOPS_INDEXER_CONNECT_IP", ""))
    parser.add_argument("--host-header", default=os.environ.get("DEVSECOPS_INDEXER_HOST_HEADER", ""))
    parser.add_argument("--devsecops-index", default=os.environ.get("DEVSECOPS_INDEX", DEVSECOPS_INDEX))
    parser.add_argument("--incidents-index", default=os.environ.get("WAZUH_INCIDENTS_INDEX", SECURITY_INCIDENTS_INDEX))
    parser.add_argument("--lookback-minutes", type=int, default=int(os.environ.get("WAZUH_SECURITY_LOOKBACK_MINUTES", "43200")))
    parser.add_argument("--max-alerts", type=int, default=2000)
    parser.add_argument("--correlation-window-seconds", type=int, default=int(os.environ.get("WAZUH_CORRELATION_WINDOW_SECONDS", "900")))
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if not args.repository:
        parser.error("--repository or GITHUB_REPOSITORY is required")
    try:
        result = collect(args)
    except (OSError, ValueError, RuntimeError, requests.RequestException) as exc:
        print(json.dumps({"status": "FAIL", "error": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
