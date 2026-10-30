# Reproducible Zabbix ChatOps configuration

`configure_chatops.py` reconciles the named Zabbix media types, actions, and
DR recipient through the Zabbix JSON-RPC API. It never writes PostgreSQL and
does not store API credentials or Slack secrets in the repository.

The policy is:

```text
ChatOps_Alert_Automation
  Problem   -> ChatOps_Alert
  Recovery  -> ChatOps_Alert

Cloud_Slack_DR_Trigger
  Problem   -> Slack DR Trigger -> authenticated ChatOps Failover request
  Recovery  -> no automatic Failback request
```

The ordinary Alert path is notification-only: it cannot create Failover
approvals. Failover requests must use the separate Production Action and pass
a signed event contract. Recovery notifications retain the existing
immediate Failback candidate path only while persistent `DR_ACTIVE` is set;
Network/SNMP and Wazuh checks are re-evaluated at approval time. A Recovery
outside `DR_ACTIVE` remains rejected. The existing two-person gate, duplicate
merge behavior, and separate Broad Test Mode path are preserved; Broad Test
Mode cannot create production Failover approvals.

The script resolves media, action, user, and group IDs by their exact names.
Existing unrelated user media are preserved. Duplicate target media or
ambiguous operations stop the run for manual review rather than deleting or
merging live configuration.

## Production Failover escalation policy

`operations/zabbix/configure_production_dr_triggers.py` owns the Production
candidate that feeds `Cloud_Slack_DR_Trigger`. Its service-failure expression
now requires all three signals from the Zabbix server host:

- Web: `http://IP_REDACTED/health`, `web.test.fail` failure value `1`.
- Doc/EMR: `http://IP_REDACTED/__hospital_dr/health`, HTTP 204,
  `web.test.fail` failure value `1`. This dedicated endpoint runs only a
  non-identifying `SELECT 1`; do not use the patient API for monitoring.
- DB: `net.tcp.service[tcp,IP_REDACTED,3306]`, failure value `0`.

Each probe is configured at 60-second intervals. The expression requires at
least six failed samples in the rolling `5m` window, all observed Web/EMR
values to remain failed (`min(...)=1`), all observed DB values to remain failed
(`max(...)=0`), and each item to have data within 90 seconds. Zabbix sampling
and window boundaries may add delay; the 300-second persistence condition is
not shortened. Agent/SNMP availability is not a substitute for any service
health condition.

The Production expression also requires a separately configured TCP witness
on the `Zabbix server` host: the latest `net.tcp.service[tcp,<IP>,<PORT>]`
sample must be `1` and no older than 90 seconds. The reconciler does not
invent an address or port. The school must identify a dedicated, independently
managed Monitoring Path witness; a TCP check proves only that Zabbix Server
can connect to that endpoint, not that the endpoint is independent or that all
On-Prem writers are fenced. Zabbix simple checks are run by the Zabbix
server/proxy, without requiring a Zabbix agent on the target. See the
[Zabbix 6.0 simple-check reference](https://www.zabbix.com/documentation/6.0/en/manual/config/items/itemtypes/simple_checks).

The Production expression also requires a fresh normal-maintenance value
(`0`) from the Zabbix internal key `zabbix[host,,maintenance]` on each of
`web_server`, `DB_Server`, `Doc_Server`, and `Zabbix server`. Values `1`
(maintenance with data collection), `2` (maintenance without data collection),
missing, stale, disabled, or unsupported samples cannot satisfy the
expression. See the
[Zabbix 6.0 internal-check reference](https://www.zabbix.com/documentation/6.0/en/manual/config/items/itemtypes/internal).
Production test mode remains a separate signed test Action and is rejected by
the ChatOps Production event contract; `test_mode` must be exactly false.
Action 3's existing `Problem is suppressed = No` condition remains an
additional suppression guard, not a substitute for these explicit host
maintenance-state samples.

Two narrowly scoped preparation modes are available while the current
Production Trigger 24712 and Action 3 are both verified disabled:

```bash
python3 operations/zabbix/configure_production_dr_triggers.py \
  --prepare-health-scenarios --env-file /path/to/external/zabbix.env \
  --backup-dir /var/lib/hospital-dr/zabbix-config-backups

python3 operations/zabbix/configure_production_dr_triggers.py \
  --prepare-maintenance-items --env-file /path/to/external/zabbix.env \
  --backup-dir /var/lib/hospital-dr/zabbix-config-backups
```

The first updates only the two existing owned Web scenarios; the second
creates or updates only the four owned internal maintenance-state items. Both
write a protected pre-change snapshot, refuse to write if either production
gate is enabled or has the wrong identity, and verify the gates remain
disabled. Neither changes a trigger, Action, or Monitoring Path item. The Doc
scenario uses `/__hospital_dr/health` and expects HTTP 204; this prevents the
monitor from polling `/api/patients`. Configuration readback is not proof that
the deployed On-Prem endpoint responds successfully.

Until the site witness IP/port are confirmed and a recent successful sample
is visible, `--check` and `--apply` remain blocked. Once confirmed (and only
under a separately approved maintenance change), the path item can be prepared
without touching any trigger:

```bash
python3 operations/zabbix/configure_production_dr_triggers.py \
  --prepare-monitoring-path \
  --monitoring-path-ip '<SITE_VERIFIED_WITNESS_IP>' \
  --monitoring-path-port '<SITE_VERIFIED_TCP_PORT>' \
  --env-file /path/to/external/zabbix.env \
  --backup-dir /var/lib/hospital-dr/zabbix-config-backups
```

Wait for the TCP witness and all four maintenance-state items to produce fresh
samples, then run `--check` with the same explicit IP/port. The checker
requires the TCP item on the Zabbix server host, type `Simple check`, numeric
unsigned, enabled, supported, tagged as the owned witness, value `1`, and fresh
within 90 seconds. Every maintenance item must be type `Zabbix internal`,
enabled, supported, value `0`, and fresh within 90 seconds. Missing, stale,
disabled, unsupported, down, duplicate, or mismatched items block. The
Production trigger reconciler itself writes trigger status `Disabled`; it does
not activate Production escalation. The scoped health-scenario and
maintenance-item preparations may be applied independently, but the live
Production Trigger remains blocked until the site-verified Monitoring Path
endpoint and fresh healthy sample exist.

After a separate approval and site review, a Production policy apply uses the
same explicit endpoint and the normal redacted pre-change snapshot. Review the
snapshot and `--check` output before applying. If a later live review finds an
unsafe trigger state, immediately set only that Production trigger's status
to Disabled in Zabbix and verify the readback; do not restore the former OR
expression. Keep Action 3 and Trigger 24712 disabled until an independent
Monitoring Path is site-verified and a separate activation approval exists.

| Situation | General Alert | Failover approval | Failback approval |
| --- | ---: | ---: | ---: |
| Reboot, Agent disconnect, WG/path disconnect | O | X | X |
| CPU/RAM/Disk warning or temporary service outage | O | X | X |
| Individual Problem delivered only by `ChatOps_Alert_Automation` | O | X | X |
| Verified Production aggregate Problem after all policy gates | O | O | X |
| Agent disconnect without a failed health branch, or Wazuh disconnect | O | X | X |
| Failover completion | O | - | X |
| Temporary On-Prem recovery | O | X | X |
| `DR_ACTIVE` plus one eligible health Recovery | O | X | O |
| Stale Recovery event | O | X | X |

Failback has an additional read-only Network/SNMP and Wazuh safety check at
approval time. It is not a request-creation delay: one eligible Recovery is
enough to create the 0/2 candidate while `DR_ACTIVE` is set. A device marked
unavailable or stale can still block approval; unrelated SNMP warnings and
unsupported OIDs do not. The gate is evaluated again before an approval is
accepted, and a regression resets any partial approvals.

Action 3 requires all four Production event tags and `Problem is suppressed =
No`. Its message carries the actual `{ACTION.NAME}`, `{EVENT.SOURCE}`, Event ID,
Trigger ID, status, host,
event age, and `{EVENT.TAGSJSON}`. `send_slack.sh` signs the exact request body with
`ZABBIX_PRODUCTION_ACTION_HMAC_KEY`; ChatOps verifies the signature, request
freshness, source/action identity, numeric event IDs, host, PROBLEM status,
and required tag values before creating an approval. The same high-entropy
key must be configured outside Git in both ChatOps and the Zabbix
alert-script runtime. Missing or invalid configuration fails closed. The
Action's suppression condition and distinct Broad Test Mode source prevent
suppressed and broad-test events from entering this production path. Recovery
operations on this production action are removed by default; the ordinary
Alert bridge retains the existing immediate Failback candidate behavior.
Retired test objects are not silently normalized by
the production reconciler; they must be removed with the exact decommissioning
utility before a stray escalation tag can be accepted. The production
reconciliation is idempotent, has `--check` and `--apply`, never deletes
objects, and writes a redacted external pre-change snapshot before an apply:

```bash
python3 operations/zabbix/configure_production_dr_triggers.py \
  --check \
  --monitoring-path-ip '<SITE_VERIFIED_WITNESS_IP>' \
  --monitoring-path-port '<SITE_VERIFIED_TCP_PORT>' \
  --env-file /path/to/external/zabbix.env

python3 operations/zabbix/configure_production_dr_triggers.py \
  --apply \
  --monitoring-path-ip '<SITE_VERIFIED_WITNESS_IP>' \
  --monitoring-path-port '<SITE_VERIFIED_TCP_PORT>' \
  --env-file /path/to/external/zabbix.env \
  --backup-dir /var/lib/hospital-dr/zabbix-config-backups
```

Action 3 still requires all four Production event tags and
`Problem is suppressed = No`; the separate Broad Test Mode source and ChatOps
test-mode checks remain unchanged. A Monitoring Path source must be verified
before the service expression can be tagged and applied. The reconciler
continues to fail closed for missing, disabled, unsupported, stale, or
unexpected objects and never performs AWS or Slack execution. The source change
does not update the live Zabbix server; an authorized school-side check and
review are required before any API apply.

Use an external environment file or exported variables. The current MSP API
credential file is outside this repository; for example:

```bash
python3 operations/zabbix/configure_chatops.py \
  --check \
  --env-file /home/cloud/hospital-dr-ansible/roles/web_deploy/files/.env
```

The file must provide `ZABBIX_URL` (or `ZABBIX_API_URL`) and either
`ZABBIX_USER`/`ZABBIX_PASSWORD` or an API token. Optional names are
`ZABBIX_RECIPIENT_USERNAME`, `ZABBIX_FAILOVER_RECIPIENT_GROUP`,
`ZABBIX_CHATOPS_ALERT_URL`, and `ZABBIX_AUTO_FAILBACK_ENABLED`. The last
variable defaults to `false` for Demo Freeze; set it to `true` only if the
legacy Zabbix Recovery-to-Failback operation is intentionally re-enabled.
Secret values are read only in memory and are never printed.

Review drift without changing Zabbix:

```bash
python3 operations/zabbix/configure_chatops.py --check --env-file /path/to/external/zabbix.env
```

Apply only the required changes. A redacted, mode-0600 pre-change export is
written outside Git before the API mutation:

```bash
python3 operations/zabbix/configure_chatops.py \
  --apply \
  --env-file /path/to/external/zabbix.env \
  --backup-dir /var/lib/hospital-dr/zabbix-config-backups
```

Create a standalone redacted export when needed:

```bash
python3 operations/zabbix/configure_chatops.py \
  --export /var/lib/hospital-dr/zabbix-config-backups/chatops-live.json \
  --env-file /path/to/external/zabbix.env
```

`--check` returns 0 when compliant, 2 when drift is found, and 1 when the
configuration is blocked or the API cannot be reached. `--apply` verifies the
result with a fresh readback.

## Broad approval-path test mode

The broad test action is separate from `Cloud_Slack_DR_Trigger` and is off by
default. No persistent ChatOps test server is provisioned anymore. If a
controlled test window is explicitly opened, the action matches only the
named existing hosts and routes a Problem to the existing Failover approval
engine and a Recovery to the existing Failback approval engine. The test
action uses the existing shell media path with a test marker; it does not
bypass two-person approval.

Inspect without changing Zabbix:

```bash
python3 operations/zabbix/configure_broad_test_mode.py \
  --check --env-file /path/to/external/zabbix.env
```

Enable only for a controlled test window:

```bash
python3 operations/zabbix/configure_broad_test_mode.py \
  --enable --env-file /path/to/external/zabbix.env \
  --backup-dir /var/lib/hospital-dr/zabbix-config-backups
```

Disable it after the test; the production `DR_Escalate=1` action is not
changed:

```bash
python3 operations/zabbix/configure_broad_test_mode.py \
  --disable --env-file /path/to/external/zabbix.env \
  --backup-dir /var/lib/hospital-dr/zabbix-config-backups
```

Test-mode Recovery messages include the Zabbix event age. Events older than
`ZABBIX_TEST_MODE_MAX_EVENT_AGE_SECONDS` are rejected before a new Failback
approval request is created, preventing stale historical Problems from
creating a test request.

Do not create temporary trapper items, triggers, or containers in production
Zabbix. If a live validation is explicitly scheduled, use a real monitored
host whose impact is understood and restore the action to disabled state after
the window. A host stop/start verifies only the triggers and actions actually
attached to that host; it does not bypass the normal two-person approval,
Failback stability, stale-event, or duplicate-request guards.

For an additional host, include its exact visible host name in the enabled
broad test action without editing the secret file:

```bash
python3 operations/zabbix/configure_broad_test_mode.py \
  --enable \
  --host 'EXACT SNMP HOST NAME' \
  --env-file /home/cloud/hospital-dr-ansible/roles/web_deploy/files/.env
```
