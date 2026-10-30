#!/usr/bin/env python3
"""Read-only Wazuh Manager/Indexer evidence and capability check.

The checker is intentionally external-secret friendly: credentials are read
from arguments/environment but never included in output.  It is useful both
for operator preflight and for CI/static contract tests; it never writes to
Wazuh, OpenSearch, Slack, or an endpoint.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests


CAPABILITY_RULES = {
    "authentication": {"2501", "5710", "5711", "5712"},
    # Wazuh 4.8 emits the common syscheck events as 5501/5502 in this
    # deployment.  Keep the group check as well because custom rules may use
    # a different rule id.
    "fim": {"5501", "5502"},
    "sca": set(),
    "syscollector": set(),
    "vulnerability": set(),
}


def _search(url, auth, verify, lookback):
    query = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": f"now-{int(lookback)}m"}}},
        "aggs": {
            "agents": {"terms": {"field": "agent.name", "size": 50}},
            "rules": {"terms": {"field": "rule.id", "size": 100}},
            "groups": {"terms": {"field": "rule.groups", "size": 100}},
        },
    }
    response = requests.post(
        f"{url.rstrip('/')}/wazuh-alerts-*/_search",
        auth=auth,
        verify=verify,
        json=query,
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def _capabilities(data):
    aggregations = data.get("aggregations") or {}
    rules = {str(item.get("key")) for item in (aggregations.get("rules", {}).get("buckets") or [])}
    groups = {str(item.get("key")).lower() for item in (aggregations.get("groups", {}).get("buckets") or [])}
    return {
        "authentication": bool(rules.intersection(CAPABILITY_RULES["authentication"]) or groups.intersection({"authentication_failed", "authentication_failure", "invalid_login", "sshd"})),
        "fim": bool(
            rules.intersection(CAPABILITY_RULES["fim"])
            or groups.intersection({"syscheck", "syscheck_entry_added", "syscheck_file"})
        ),
        "sca": bool(groups.intersection({"sca"}) or rules.intersection({"19004", "19005", "19007", "19008", "19009"})),
        "syscollector": bool(groups.intersection({"syscollector", "ossec"}) or rules.intersection({"533"})),
        "vulnerability": bool(groups.intersection({"vulnerability", "vulnerability-detector", "vulnerability_detection"})),
    }


def check_pipeline(url, user, password, ca_cert=True, lookback=1440):
    result = {
        "manager": "UNKNOWN",
        "indexer": "FAIL",
        "alerts_index": "wazuh-alerts-*",
        "ingestion": "FAIL",
        "document_count": 0,
        "agents": {},
        "rule_levels": {},
        "capabilities": {key: False for key in CAPABILITY_RULES},
    }
    try:
        health = requests.get(
            f"{url.rstrip('/')}/_cluster/health",
            auth=(user, password),
            verify=ca_cert,
            timeout=15,
        )
        health.raise_for_status()
        result["indexer"] = "PASS" if health.json().get("status") in {"green", "yellow"} else "FAIL"
        data = _search(url, (user, password), ca_cert, lookback)
        hits = data.get("hits", {}).get("total", 0)
        result["document_count"] = hits.get("value", 0) if isinstance(hits, dict) else int(hits or 0)
        result["ingestion"] = "PASS" if result["document_count"] > 0 else "NO_DATA"
        aggs = data.get("aggregations") or {}
        result["agents"] = {
            str(item.get("key")): int(item.get("doc_count", 0))
            for item in aggs.get("agents", {}).get("buckets", [])
        }
        result["rule_levels"] = {
            str(item.get("key")): int(item.get("doc_count", 0))
            for item in aggs.get("rules", {}).get("buckets", [])
        }
        result["capabilities"] = _capabilities(data)
        result["manager"] = "PASS" if result["document_count"] else "UNKNOWN"
    except (OSError, ValueError, requests.RequestException, json.JSONDecodeError) as exc:
        result["error"] = type(exc).__name__
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("WAZUH_INDEXER_URL", ""))
    parser.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", ""))
    parser.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASSWORD", ""))
    parser.add_argument("--ca-cert", default=os.environ.get("WAZUH_CA_CERT", ""))
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Allow local operator checks without a CA file; never changes runtime TLS settings",
    )
    parser.add_argument("--lookback-minutes", type=int, default=1440)
    args = parser.parse_args(argv)
    if not args.url or not args.user or not args.password:
        parser.error("--url, --user and --password (or matching environment variables) are required")
    verify = False if args.insecure else (args.ca_cert or True)
    if args.ca_cert and not os.path.exists(args.ca_cert):
        parser.error(f"CA certificate is not readable: {args.ca_cert}")
    if verify is False:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    print(json.dumps(check_pipeline(args.url, args.user, args.password, verify, args.lookback_minutes), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
