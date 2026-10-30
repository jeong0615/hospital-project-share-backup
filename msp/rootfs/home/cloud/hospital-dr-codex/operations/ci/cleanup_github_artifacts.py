#!/usr/bin/env python3
"""Safely reclaim expired/superseded GitHub Actions artifacts.

The default is a read-only report.  Deletion requires an explicit flag.  All
expired artifacts may be removed because GitHub has already marked them
unavailable.  Non-expired cleanup is limited to CI image/summary artifacts
belonging to runs outside the protected recent-run window; source, SARIF, and
unrelated artifacts are never selected by this helper.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys


PRUNABLE_PREFIXES = ("gated-image-", "docker-security-", "devsecops-")


def _gh_json_lines(endpoint):
    command = ["gh", "api", "--paginate", "--jq", ".artifacts[]", endpoint]
    try:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"GitHub API unavailable: {type(exc).__name__}") from exc
    values = []
    for line in completed.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            values.append(item)
    return values


def _gh_runs(repository):
    endpoint = f"repos/{repository}/actions/runs?branch=main&per_page=100"
    command = ["gh", "api", "--paginate", "--jq", ".workflow_runs[]", endpoint]
    try:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"GitHub run API unavailable: {type(exc).__name__}") from exc
    runs = []
    for line in completed.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            runs.append(item)
    return runs


def _delete(repository, artifact_id):
    command = ["gh", "api", "-X", "DELETE", f"repos/{repository}/actions/artifacts/{artifact_id}"]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        # A concurrent retention pass or GitHub expiry can remove the item
        # between listing and deletion. Treat that as already complete.
        if "404" in (exc.stderr or "") or "Not Found" in (exc.stderr or ""):
            return False
        raise RuntimeError(f"Artifact deletion failed: {type(exc).__name__}") from exc
    except OSError as exc:
        raise RuntimeError(f"Artifact deletion failed: {type(exc).__name__}") from exc
    return True


def select_artifacts(artifacts, runs, keep_runs, delete_expired, prune_superseded):
    completed_runs = [
        item
        for item in runs
        if item.get("status") == "completed"
    ]
    protected = {
        str(item.get("id"))
        for item in sorted(
            completed_runs,
            key=lambda value: value.get("updated_at", ""),
            reverse=True,
        )[: max(0, int(keep_runs))]
    }
    selected = []
    for artifact in artifacts:
        expired = bool(artifact.get("expired"))
        if expired and delete_expired:
            selected.append((artifact, "expired"))
            continue
        if not prune_superseded or expired:
            continue
        run = artifact.get("workflow_run") or {}
        run_id = str(run.get("id", ""))
        name = str(artifact.get("name", ""))
        if run_id not in protected and name.startswith(PRUNABLE_PREFIXES):
            selected.append((artifact, "superseded"))
    return selected


def cleanup(args):
    artifacts = _gh_json_lines(f"repos/{args.repository}/actions/artifacts?per_page=100")
    runs = _gh_runs(args.repository) if args.prune_superseded else []
    selected = select_artifacts(
        artifacts,
        runs,
        args.keep_runs,
        args.delete_expired,
        args.prune_superseded,
    )
    selected_bytes = sum(int(item.get("size_in_bytes") or 0) for item, _ in selected)
    deleted = 0
    if args.delete:
        for artifact, _reason in selected:
            if _delete(args.repository, artifact["id"]):
                deleted += 1
    return {
        "repository": args.repository,
        "artifact_count": len(artifacts),
        "candidate_count": len(selected),
        "candidate_bytes": selected_bytes,
        "deleted_count": deleted,
        "mode": "delete" if args.delete else "report",
        "keep_runs": args.keep_runs,
        "expired_policy": "delete" if args.delete_expired else "report_only",
        "superseded_policy": "delete" if args.prune_superseded and args.delete else "report_only",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--keep-runs", type=int, default=20)
    parser.add_argument("--delete-expired", action="store_true")
    parser.add_argument("--prune-superseded", action="store_true")
    parser.add_argument("--delete", action="store_true", help="Actually delete selected artifacts")
    args = parser.parse_args(argv)
    if args.delete and not (args.delete_expired or args.prune_superseded):
        parser.error("--delete requires --delete-expired or --prune-superseded")
    try:
        print(json.dumps(cleanup(args), sort_keys=True))
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "error": type(exc).__name__}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
