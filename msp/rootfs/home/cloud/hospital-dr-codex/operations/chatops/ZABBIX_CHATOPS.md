# Zabbix to ChatOps Alert bridge

## Current Routing

The old Zabbix `Slack_Alert` Media Type is a separate monitoring path:

```text
Zabbix Slack_Alert -> params.URL -> Slack Incoming Webhook -> channel
```

It does not use `SLACK_ALERT_BOT_TOKEN`, `/zabbix/alert`, the SQLite registry,
or the ChatOps 24-hour audit/cleanup process. It is not the Failover or
Failback control path and must not be removed before the replacement is
verified.

The target monitoring path is:

```text
Zabbix -> /zabbix/alert -> ChatOps Alert Bot -> #dr-alerts
Wazuh -> /wazuh/alert -> ChatOps Alert Bot -> #dr-alerts
```

The control paths remain separate:

```text
Slack_DR_Trigger -> ChatOps Failover -> two-person approval
Slack Failback    -> ChatOps Failback -> two-person approval
```

The Demo Freeze Recovery path is immediate: an eligible Web/EMR HTTP, DB
TCP/MySQL, or required SNMP availability Recovery creates a Failback 0/2
request only when persistent `DR_ACTIVE` is present.  It does not wait for a
`FAILBACK_STABILITY_SECONDS` window or require every service to recover first.
The existing Network/SNMP and Wazuh checks are re-evaluated when an
administrator presses Approve, so a premature candidate can be cancelled or
expire without entering the executor.  The legacy
`zabbix_failback_guard.sh`/`failback_stability.sh` files remain available for
older deployments but are not invoked by the current sender.

Set `ONPREM_WEB_HEALTH_URL`, `ONPREM_DOC_HEALTH_URL`, and `ONPREM_DB_HOST` in
the external runtime environment.  Configure the existing read-only Zabbix
API identity through `NETWORK_DR_HEALTH_ZABBIX_ENV_FILE` or the
`NETWORK_DR_HEALTH_ZABBIX_*` variables.  The guard has no documentation-address
fallback; missing probe configuration or missing/stale Network/SNMP data fails
closed. Unrelated SNMP warnings (Fan2, an unused interface, unsupported OID,
or CPU/RAM warning) are not part of this gate.

Failover events carry a correlation ID into the runtime RTO timeline
at `/var/lib/hospital-dr/rto_timeline.json`. The reported RTO is detection-based:
it starts at the Zabbix Problem event timestamp (not the unobserved physical
fault onset) and ends after verified service recovery. Alert delivery,
approval-request creation, first/final approval, workflow start, and successful
service recovery are recorded with UTC ISO-8601 timestamps; missing source
timestamps are left absent and incomplete runs remain `NOT_MEASURED`. The
project targets are RTO 3600 seconds (1 hour) and RPO 900 seconds (15 minutes).
When `zabbix_sender` is available, the workflow publishes the measured
timeline to the existing `Hospital_DR_Automation` trapper contract:
`dr.rto.seconds`, `dr.rto.target_seconds`, `dr.rto.result`,
`dr.rto.detection_seconds`, `dr.rto.approval_creation_seconds`,
`dr.rto.approval_seconds`, `dr.rto.approval_to_start_seconds`, and
`dr.rto.execution_seconds`. Raw stage timestamps use `dr.<stage>`; missing
stages are omitted rather than published as zero.

RPO remains `NOT_MEASURED` unless read-only replication evidence identifies the
actual recoverable data point. Backup-file creation time alone is not used to
claim an RPO value.

The Zabbix script media types use the current shared request engine:

```text
Slack DR Trigger -> /usr/lib/zabbix/alertscripts/send_slack.sh
Slack Failback   -> /usr/lib/zabbix/alertscripts/send_failback.sh
```

Their Zabbix 6 script parameters are three newline-delimited values:

```text
__zabbix__
{ALERT.SUBJECT}
{ALERT.MESSAGE}
```

Broad TEST MODE uses the same three parameters. Its alert message contains
the event ID, host, and event age fields; the shell helper extracts those
fields because separate non-`ALERT.*` macros may be passed literally by the
Zabbix 6 custom-script runner.

The marker distinguishes a real Zabbix invocation from the two-argument
manual helper form. Zabbix custom scripts receive configured parameters as
command-line arguments; they must not depend on inherited environment
variables. When an event ID is not explicitly supplied, the helper derives a
stable non-secret digest from the alert subject and message for duplicate
suppression.

## Bridge Behavior

`POST /zabbix/alert` accepts a normalized Zabbix event and sends a
button-free monitoring alert through the existing `SLACK_ALERT_BOT_TOKEN`
client. It reuses the existing SQLite message registry and audit/cleanup
process. Duplicate `source`/`EventID`/lifecycle-status deliveries are
suppressed by the registry. Zabbix recovery operations may reuse the original
problem EventID, so PROBLEM and RESOLVED notifications are tracked separately.

The ordinary `ChatOps_Alert_Automation` path is notification-only:

```text
Action 9 -> ChatOps_Alert media -> /zabbix/alert -> general Slack alert
```

It does not create Failover approvals. Agent availability events, individual
core-host Problems, generic events, and an untrusted `DR_Escalate=1` payload
remain ordinary alerts.

Production Failover approvals use the separate Action 3 path:

```text
Cloud_Slack_DR_Trigger
  -> Slack DR Trigger / send_slack.sh
  -> signed /chatops/request
  -> existing two-person Failover approval
```

The Action must match all four event tags (`DR_Escalate=1`,
`DR_Policy=production`, `DR_Scope=Hospital-Core`, `DR_Type=Failover`) and
Zabbix must report the event as unsuppressed. The sender includes the actual
`{ACTION.NAME}` value, event source (`{EVENT.SOURCE}=0` for trigger events),
event ID, trigger ID, status, host,
age, and `EVENT.TAGSJSON`; ChatOps accepts the
Failover only with a valid HMAC from this dedicated sender and a valid
PROBLEM-event contract. The shared `ZABBIX_PRODUCTION_ACTION_HMAC_KEY` must be
configured outside Git in both the ChatOps secret file and the Zabbix
alert-script environment. If it is absent or invalid, production Action
requests fail closed. Broad test-mode messages use a distinct source and
cannot create production approvals.

The production trigger itself remains the existing OR aggregate reconciled
by `operations/zabbix/configure_production_dr_triggers.py`; this change does
not alter its branches or duration. Because its current OR policy has no
independent monitoring-path health gate, a path outage that makes a health
probe fail can still produce a tagged aggregate event. That residual
false-positive risk remains a separate Production DR policy issue. Automatic
Recovery-to-Failback remains separate and unchanged.

`zabbix_media_type.js` is the payload template for the Zabbix JavaScript Media
Type. It does not contain a Slack token. Its `params.URL` must eventually
point to an internal-only bridge path.

## Docker-to-Host Constraint

ChatOps remains bound to `IP_REDACTED:5000`. The Zabbix server is defined in
`/home/cloud/zabbix/docker-compose.yml` as a normal Compose service; it does
not use `network_mode: host` or a configured `extra_hosts` entry. A container's
`IP_REDACTED` is therefore not the MSP host loopback. Adding only
`host.docker.internal` would also be insufficient while ChatOps listens only
on loopback.

Recommended minimum-change path:

1. Read-only inspect the running Zabbix container and its actual bridge
   gateway/subnet.
2. Run `zabbix_host_proxy.py` as a host-side reverse proxy bound only to
   `IP_REDACTED:5001`. It allows only source `IP_REDACTED` and forwards to
   `IP_REDACTED:5000/zabbix/alert`.
3. Keep ChatOps on loopback and do not publish port 5000 or the proxy port on
   the MSP/Internet-facing interface.
4. Point the Zabbix Media Type `params.URL` to
   `http://IP_REDACTED:5001/zabbix/alert` only
   after the local and container-origin tests pass.

Changing Zabbix to host networking or containerizing ChatOps would affect more
of the existing deployment and is not the first choice.

The confirmed current network is:

```text
network: zabbix_default
subnet: AWS_PUBLIC_IP_REDACTED/16
gateway: IP_REDACTED
zabbix-server: IP_REDACTED
```

The proxy is implemented by `zabbix_host_proxy.py` and the systemd unit
`systemd/hospital-dr-zabbix-proxy.service`:

```text
IP_REDACTED:5001 (source IP_REDACTED only)
    -> IP_REDACTED:5000/zabbix/alert
```

On the MSP host, direct access to the proxy is expected to return `403` because
the host is not the allow-listed Zabbix container source. The actual
Zabbix-container request must return `2xx`; that test requires Docker socket
access and must be run with read-only `sudo docker exec` if the regular user is
not a member of the Docker group.

## Activation and Rollback

Before activation:

1. Confirm the running `zabbix-server` container and Docker network with
   read-only `sudo docker inspect`.
2. Start ChatOps, then start the proxy unit and verify that it binds only to
   `IP_REDACTED:5001`.
3. Verify the proxy from the Zabbix container to `/zabbix/alert`.
4. Send a non-DR test and verify one ChatOps Alert message with no buttons.
5. Send an explicit escalation test with the Failover executor mocked.
6. Confirm audit/cleanup registration and no duplicate messages.
7. Disable the old `Slack_Alert` Media Type only after the replacement passes;
   retain its configuration for immediate rollback.

The Zabbix Media Type URL is then:

```text
http://IP_REDACTED:5001/zabbix/alert
```

Do not put Slack tokens or Webhook values in this repository.
