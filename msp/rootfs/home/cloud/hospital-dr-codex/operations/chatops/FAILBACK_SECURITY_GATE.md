# Failback Security Readiness Gate

The Wazuh gate is a safety check for Failback. The ordinary Zabbix Alert
bridge creates an immediate Failback candidate only for an eligible
Web/EMR/DB/SNMP Recovery while `DR_ACTIVE` is present; it does not wait for a
300-second stability window or require every service to recover first. The
existing Network/SNMP and Wazuh checks are evaluated again when an approval is
pressed, and a non-ready result still blocks execution. The existing Slack
two-person approval flow remains the only path to execution.

## State contract

The current implementation accepts a mock snapshot through
`WAZUH_FAILBACK_SECURITY_SNAPSHOT`. When all read-only Wazuh API and Indexer
settings are present, the ChatOps app automatically uses the live provider
through `WAZUH_SECURITY_STATE_PROVIDER`. Both providers supply the same shape
without changing the decision function.

```json
{
  "query_ok": true,
  "agents": [
    {"id": "001", "name": "DB_Server", "status": "active", "last_seen": 1757040000}
  ],
  "incidents": []
}
```

`WAZUH_FAILBACK_REQUIRED_AGENTS` must list every important On-Premise agent.
Missing, offline, stale, or unconfigured agents result in `UNKNOWN`.

The live provider requires `WAZUH_API_URL`, `WAZUH_API_USER`,
`WAZUH_API_PASSWORD`, `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, and
`WAZUH_INDEXER_PASSWORD`. Use a Wazuh read-only API/Indexer identity and mount
the Wazuh CA through `WAZUH_CA_CERT`; do not use the Wazuh administrator
identity in ChatOps.

## Decisions

- `READY`: all required agents are online and fresh, the query succeeded, and
  no unresolved destructive Critical incident affects an important service.
- `BLOCKED`: an unresolved ransomware, wiper, destructive malware, mass
  deletion, file encryption, or data destruction event affects an important
  service.
- `UNKNOWN`: the Wazuh query failed, data is incomplete, required agents are
  missing/stale/offline, or required agent configuration is absent.

`UNKNOWN` never fails open to `READY`.

## ChatOps behavior

Failback approval evaluates both gates and displays only short, non-sensitive
summaries. An immediate Recovery candidate is visible as a 0/2 request; the
approval callback re-evaluates both gates immediately. A non-`READY` result
cannot enter the executor and clears partial approvals. `READY` still
requires two distinct administrators.

The current default without a live Wazuh provider is `UNKNOWN`, which is
intentional until the required Agent state is connected.
