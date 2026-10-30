#!/usr/bin/env python3
"""Build a secret-free, machine-readable DevSecOps scan summary."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def _report_counts(path, source):
    result = {
        "critical": 0,
        "high": 0,
        "fixable": 0,
        "unfixed": 0,
        "findings": [],
        "unique_cves": [],
    }
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return result
    for scan in document.get("Results", []) or []:
        for finding in scan.get("Vulnerabilities", []) or []:
            severity = str(finding.get("Severity", "")).upper()
            if severity not in {"CRITICAL", "HIGH"}:
                continue
            result[severity.lower()] += 1
            fixed_version = str(finding.get("FixedVersion") or "")
            vulnerability_id = str(finding.get("VulnerabilityID") or "")
            result["findings"].append(
                {
                    "source": source,
                    "target": str(scan.get("Target") or ""),
                    "severity": severity,
                    "vulnerability_id": vulnerability_id,
                    "package": str(finding.get("PkgName") or ""),
                    "installed_version": str(finding.get("InstalledVersion") or ""),
                    "fixed_version": fixed_version,
                    "upstream_status": str(finding.get("Status") or ""),
                    "classification": "FIX_AVAILABLE" if fixed_version else "NO_FIXED_VERSION",
                }
            )
            if fixed_version:
                result["fixable"] += 1
            else:
                result["unfixed"] += 1
    result["unique_cves"] = sorted(
        {item["vulnerability_id"] for item in result["findings"] if item["vulnerability_id"]}
    )
    return result


def build_summary(args):
    os_counts = _report_counts(args.os_report, "OS_PACKAGE")
    library_counts = _report_counts(args.library_report, "APPLICATION_LIBRARY")
    build = str(args.build).lower()
    health = str(args.health).lower()
    npm_exit = int(args.npm_exit)
    gate = "PASS"
    if build != "success" or health != "success" or npm_exit != 0:
        gate = "FAIL"
    if library_counts["critical"] or library_counts["high"] or os_counts["fixable"]:
        gate = "FAIL"
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repository": args.repository,
        "run_id": args.run_id,
        "commit_sha": args.commit_sha,
        "image": args.image,
        "ecr_repository": args.ecr_repository,
        "build": build,
        "health": health,
        "npm_audit_exit": npm_exit,
        "trivy": {"os": os_counts, "library": library_counts},
        "security_gate": gate,
        "ecr_push": str(args.ecr_push).upper(),
        "ecr_image_digest": str(args.ecr_image_digest or ""),
        "wazuh_event_type": "github_actions_devsecops",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os-report", required=True)
    parser.add_argument("--library-report", required=True)
    parser.add_argument("--build", default="unknown")
    parser.add_argument("--health", default="unknown")
    parser.add_argument("--npm-exit", default="1")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "unknown"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "unknown"))
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--image", default="unknown")
    parser.add_argument("--ecr-repository", default="unknown")
    parser.add_argument("--ecr-push", default="PENDING")
    parser.add_argument("--ecr-image-digest", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_summary(args), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
