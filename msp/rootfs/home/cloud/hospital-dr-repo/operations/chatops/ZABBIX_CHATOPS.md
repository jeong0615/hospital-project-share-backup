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
process. Duplicate `EventID` values are suppressed by the registry.

Only an explicit `DR_Escalate=1` from an existing Zabbix DR Action can reuse
the existing Failover request engine. Normal Zabbix alerts never create
approval requests. Alert and approval messages remain separate.

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
