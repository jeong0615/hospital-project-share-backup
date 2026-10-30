# Wazuh to ChatOps Alert

## Current boundary

The repository contains Grafana Wazuh Indexer datasource configuration, but no
existing Wazuh custom integration, webhook receiver, or Alert sender was found.
This change adds a local JSON receiver without installing or connecting a
Wazuh Agent.

`POST /wazuh/alert` is accepted only from MSP localhost. It parses a Wazuh
alert, sends a concise message through the Alert-only Slack client, and can
reuse the existing Failover approval engine when the escalation policy matches.
The raw alert and full log are never forwarded to Slack or stored in the
approval incident.

## Environment

The Alert app is deliberately separate from Failover and Failback:

```text
SLACK_ALERT_BOT_TOKEN=
SLACK_ALERT_CHANNEL_ID=
```

`SLACK_ALERT_CHANNEL_ID` falls back to `SLACK_CHANNEL_ID` when it is empty.
Do not reuse a control Bot token for Alert messages. The token belongs in the
external secret file loaded by `DR_SECRET_FILE`; it must not be committed.

## Severity and escalation

Wazuh levels map as follows:

```text
0-6   LOW
7-9   MEDIUM
10-12 HIGH
13-15 CRITICAL
```

All severities produce a ChatOps Alert when the Alert client is configured.
DR escalation requires all of these conditions:

- severity is `CRITICAL`
- the rule/summary/groups contain a destructive signal such as ransomware,
  wiper, mass deletion, or file encryption
- the event identifies an important service host such as DB, MySQL, Web, Doc,
  or EMR

The escalated incident is submitted as `action=failover` through the existing
`request_id` approval store. It never creates a second approval engine and it
never creates a Failback request.

## Local mock example

```bash
curl -fsS -X POST http://IP_REDACTED:5000/wazuh/alert \
  -H 'Content-Type: application/json' \
  --data @tests/fixtures/wazuh/critical-ransomware-db.json
```

The endpoint is intentionally local-only until a Wazuh Manager integration is
configured. A future Wazuh custom integration may forward its JSON to this
endpoint after the Agent/Manager network path is approved.

## Live Failback provider

The ChatOps app automatically enables the read-only live provider when all
Wazuh API and Indexer variables in `.env.example` are present. It uses the API
for Agent status/keepalive and the Indexer for recent `wazuh-alerts-*` events.
The default lookback is 15 minutes. API or Indexer failure returns
`query_ok=false`, which the Failback gate maps to `UNKNOWN`.
If an alert contains `status` or `resolved`, those fields are preserved;
otherwise a recent alert is conservatively considered active until it leaves
the lookback window.

The current MSP Compose exposes the Manager Agent channels on TCP 1514 and
1515, and the API on TCP 55000. These ports must be reachable from the
approved On-Premise to MSP WireGuard path only; do not expose them to the
public Internet. Indexer/API credentials must be read-only identities and
must be stored outside Git.
