#!/usr/bin/env python3
"""Persist AWS CloudTrail Event History security signals in the existing Wazuh Indexer.

The collector uses the account's CloudTrail Event History read API instead of
creating a trail, S3 bucket, Kinesis stream, Security Hub, or another paid
service.  It stores normalized, non-secret fields in a separate index so the
existing Wazuh alert index and deterministic XDR incident index are untouched.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "operations" / "security"))
from devsecops_indexer_collector import IndexerWriter  # noqa: E402


AWS_INDEX = "hospital-aws-cloud-events"
STATE_FILE = "/var/lib/hospital-dr/aws-cloudtrail-collector.json"

HIGH_RISK_EVENTS = {
    "AttachRolePolicy",
    "CreateAccessKey",
    "CreateLoginProfile",
    "CreatePolicyVersion",
    "CreateRole",
    "DeleteTrail",
    "PutRolePolicy",
    "PutUserPolicy",
    "PutEventSelectors",
    "PutBucketPolicy",
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "RevokeSecurityGroupEgress",
    "ModifyInstanceAttribute",
    "ModifyInstanceMetadataOptions",
    "RunInstances",
    "TerminateInstances",
    "StopInstances",
    "StartInstances",
}
AUTH_EVENTS = {"ConsoleLogin", "GetFederationToken", "AssumeRole", "AssumeRoleWithSAML"}

MAPPING = {
    "timestamp": {"type": "date"},
    "event_time": {"type": "date"},
    "event_id": {"type": "keyword"},
    "event_name": {"type": "keyword"},
    "event_source": {"type": "keyword"},
    "aws_region": {"type": "keyword"},
    # CloudTrail uses values such as ``AWS Internal`` for service calls, so an
    # Elasticsearch IP mapping would reject legitimate events.
    "source_ip": {"type": "keyword"},
    "user": {"type": "keyword"},
    "user_identity_type": {"type": "keyword"},
    "read_only": {"type": "boolean"},
    "category": {"type": "keyword"},
    "severity": {"type": "keyword"},
    "resources": {"type": "keyword"},
    "resource_count": {"type": "integer"},
    "environment": {"type": "keyword"},
    "source": {"type": "keyword"},
    "security_relevant": {"type": "boolean"},
}


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("CloudTrailEvent")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return event


def safe_cloudtrail_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return an allowlisted CloudTrail event without credential-bearing data.

    STS responses can embed SecretAccessKey and SessionToken under
    ``responseElements.credentials``.  Never return CloudTrailEvent itself or
    copy arbitrary nested fields: this function is the boundary between the
    AWS response and callers that may log, inspect, or persist an event.
    """

    payload = _event_payload(event)
    identity = payload.get("userIdentity") if isinstance(payload.get("userIdentity"), dict) else {}
    resources = payload.get("resources") if isinstance(payload.get("resources"), list) else []
    safe_resources = []
    for resource in resources[:20]:
        if isinstance(resource, dict):
            value = resource.get("ARN") or resource.get("resourceName") or resource.get("ResourceName")
        else:
            value = resource
        if isinstance(value, (str, int)):
            safe_resources.append(str(value)[:300])

    def text(value: Any, fallback: str, limit: int = 300) -> str:
        return str(value)[:limit] if isinstance(value, (str, int)) else fallback

    event_time = _parse_time(text(payload.get("eventTime") or event.get("EventTime"), ""))
    return {
        "eventID": text(event.get("EventId") or payload.get("eventID"), ""),
        "eventTime": _iso(event_time),
        "eventName": text(payload.get("eventName") or event.get("EventName"), "unknown", 120),
        "eventSource": text(payload.get("eventSource") or event.get("EventSource"), "unknown", 160),
        "awsRegion": text(payload.get("awsRegion") or event.get("AwsRegion"), "unknown", 80),
        "sourceIPAddress": text(payload.get("sourceIPAddress"), "AWS_PUBLIC_IP_REDACTED", 120),
        "userIdentity": {
            "type": text(identity.get("type"), "unknown", 80),
            "arn": text(identity.get("arn") or identity.get("userName") or identity.get("principalId"), "unknown"),
        },
        "readOnly": payload.get("readOnly") is True or str(payload.get("readOnly", "")).lower() == "true",
        "errorCode": text(payload.get("errorCode"), "", 160),
        "resources": safe_resources,
    }


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Reduce a CloudTrail event to fields safe for the monitoring index."""

    payload = safe_cloudtrail_event(event)
    event_name = payload["eventName"]
    event_source = payload["eventSource"]
    event_time = _parse_time(payload["eventTime"])
    identity = payload["userIdentity"]
    user = identity["arn"]
    resource_names = payload["resources"]
    error_code = payload["errorCode"]
    read_only = payload["readOnly"]
    if event_name in AUTH_EVENTS:
        category = "authentication"
    elif event_name in HIGH_RISK_EVENTS:
        category = "configuration_or_control_plane"
    elif event_source.startswith("ec2."):
        category = "ec2"
    elif event_source.startswith("iam."):
        category = "iam"
    else:
        category = "aws_api"
    severity = "HIGH" if event_name in HIGH_RISK_EVENTS or error_code else "INFO"
    event_id = payload["eventID"]
    if not event_id:
        event_id = f"{event_name}-{event_time.timestamp()}-{user}"
    return {
        "timestamp": _iso(event_time),
        "event_time": _iso(event_time),
        "event_id": event_id,
        "event_name": event_name,
        "event_source": event_source,
        "aws_region": payload["awsRegion"],
        "source_ip": payload["sourceIPAddress"],
        "user": str(user)[:300],
        "user_identity_type": identity["type"],
        "read_only": read_only,
        "category": category,
        "severity": severity,
        "resources": resource_names,
        "resource_count": len(resource_names),
        "environment": "aws",
        "source": "cloudtrail-event-history",
        "security_relevant": bool(event_name in HIGH_RISK_EVENTS or event_name in AUTH_EVENTS or error_code),
    }


def lookup_events(
    region: str,
    start_time: datetime,
    end_time: datetime,
    *,
    max_results: int = 50,
    aws_profile: str = "",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, Any]]:
    command = [
        "aws",
        "cloudtrail",
        "lookup-events",
        "--region",
        region,
        "--start-time",
        _iso(start_time),
        "--end-time",
        _iso(end_time),
        "--max-results",
        str(max(1, min(max_results, 50))),
        "--output",
        "json",
    ]
    if aws_profile:
        command[2:2] = ["--profile", aws_profile]
    result = runner(command, check=True, capture_output=True, text=True, timeout=30)
    payload = json.loads(result.stdout or "{}")
    events = payload.get("Events") if isinstance(payload, dict) else []
    # Do not let raw CloudTrailEvent blobs (including STS credentials) escape
    # this function, even if a future caller logs its return value directly.
    return [safe_cloudtrail_event(item) for item in events if isinstance(item, dict)]


def _read_state(path: Path) -> datetime | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return _parse_time(value.get("last_event_time")) if value.get("last_event_time") else None
    except (OSError, ValueError, TypeError):
        return None


def _write_state(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".aws-cloudtrail-", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def collect(
    *,
    region: str,
    lookback_minutes: int,
    state_file: str,
    max_results: int,
    aws_profile: str,
    dry_run: bool,
    writer: Any = None,
    lookup: Callable[..., list[dict[str, Any]]] = lookup_events,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    state_path = Path(state_file)
    previous = _read_state(state_path)
    start = previous - timedelta(minutes=2) if previous else now - timedelta(minutes=max(1, lookback_minutes))
    events = lookup(region, start, now, max_results=max_results, aws_profile=aws_profile)
    documents = [normalize_event(event) for event in events]
    documents.sort(key=lambda item: item["event_time"])
    result: dict[str, Any] = {
        "status": "DRY_RUN" if dry_run else "NOT_WRITTEN",
        "index": AWS_INDEX,
        "events": len(documents),
        "security_relevant": sum(1 for item in documents if item["security_relevant"]),
        "high": sum(1 for item in documents if item["severity"] == "HIGH"),
    }
    if dry_run or not documents:
        if not dry_run and not documents:
            result["status"] = "NO_EVENTS"
        return result
    if writer is None:
        raise ValueError("writer is required when dry_run is false")
    writer.ensure_index(AWS_INDEX, MAPPING)
    for document in documents:
        writer.index_document(AWS_INDEX, document["event_id"], document)
    _write_state(state_path, {"version": 1, "last_event_time": documents[-1]["event_time"]})
    result["status"] = "PASS"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "ap-northeast-2"))
    parser.add_argument("--lookback-minutes", type=int, default=int(os.environ.get("AWS_CLOUDTRAIL_LOOKBACK_MINUTES", "60")))
    parser.add_argument("--max-results", type=int, default=50)
    parser.add_argument("--state-file", default=os.environ.get("AWS_CLOUDTRAIL_STATE_FILE", STATE_FILE))
    parser.add_argument("--aws-profile", default=os.environ.get("AWS_PROFILE", ""))
    parser.add_argument("--indexer-url", default=os.environ.get("AWS_INDEXER_URL") or os.environ.get("WAZUH_INDEXER_URL", ""))
    # Do not silently reuse Grafana's read-only identity for writes.  A
    # dedicated external writer identity or the existing operational source is
    # required; absent that, the collector fails closed.
    parser.add_argument("--indexer-user", default=os.environ.get("AWS_INDEXER_WRITE_USER", ""))
    parser.add_argument("--indexer-password", default=os.environ.get("AWS_INDEXER_WRITE_PASSWORD", ""))
    parser.add_argument("--ca-cert", default=os.environ.get("AWS_INDEXER_CA_CERT", ""))
    parser.add_argument("--ca-source", default=os.environ.get("AWS_INDEXER_CA_SOURCE") or os.environ.get("DEVSECOPS_INDEXER_CA_SOURCE", ""))
    parser.add_argument("--credential-source", default=os.environ.get("AWS_INDEXER_CREDENTIAL_SOURCE") or os.environ.get("DEVSECOPS_INDEXER_CREDENTIAL_SOURCE", ""))
    parser.add_argument("--connect-ip", default=os.environ.get("AWS_INDEXER_CONNECT_IP", "AWS_PUBLIC_IP_REDACTED"))
    parser.add_argument("--host-header", default=os.environ.get("AWS_INDEXER_HOST_HEADER", "wazuh.indexer"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        writer = None
        if not args.dry_run:
            writer = IndexerWriter(
                args.indexer_url,
                args.indexer_user,
                args.indexer_password,
                ca_cert=args.ca_cert,
                ca_source=args.ca_source,
                credential_source=args.credential_source,
                connect_ip=args.connect_ip,
                host_header=args.host_header,
            )
        print(json.dumps(collect(
            region=args.region,
            lookback_minutes=args.lookback_minutes,
            state_file=args.state_file,
            max_results=args.max_results,
            aws_profile=args.aws_profile,
            dry_run=args.dry_run,
            writer=writer,
        ), sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        message = str(exc)
        safe_error = message if message.startswith("Indexer HTTP ") else type(exc).__name__
        print(json.dumps({"status": "FAIL", "error": safe_error}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
