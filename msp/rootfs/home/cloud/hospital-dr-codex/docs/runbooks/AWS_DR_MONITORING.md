# AWS DR monitoring and security contract

This extension reuses the existing MSP Zabbix, Wazuh 4.8, Wazuh Indexer, and
Grafana runtime. It does not create a VPN, Kubernetes cluster, managed
OpenSearch service, Security Hub, GuardDuty, or a second Wazuh manager.

## Endpoint-agent path (disabled in the current environment)

`operations/aws/apply_endpoint_security.sh` and
`aws_endpoint_security_bootstrap.sh` retain the reusable SSM bootstrap for a
future network with a controlled inbound edge. The current MSP is behind an
uncontrolled upstream NAT and has no public inbound IPv4 address. The current
runtime therefore sets both external-agent flags to `false`:

```text
AWS_ZABBIX_EXTERNAL_PATH_ENABLED=false
AWS_WAZUH_EXTERNAL_PATH_ENABLED=false
CONFIG_AVAILABLE=YES
LIVE_PATH_ENABLED=NO
LIVE_PATH_REASON=MSP_BEHIND_UNCONTROLLED_UPSTREAM_NAT
```

The scripts exit before requiring endpoint values when the path is disabled.
They remain idempotent and keep the Zabbix agent in active mode with
`ListenIP=IP_REDACTED` when explicitly enabled in a suitable future network;
this repository does not open an AWS inbound agent port.

The Web and EMR hosts additionally stream Docker lifecycle events to
`/var/log/hospital-dr/docker-events.json`. The Wazuh agent reads that file; the
Docker socket is never mounted into a monitoring container. MySQL data files
are not placed under real-time FIM.

The controller requires the non-secret external inputs
`AWS_ZABBIX_ACTIVE_SERVER` and `AWS_WAZUH_MANAGER` only when the
corresponding external path flags are explicitly enabled. The current
operating mode does not require, validate, or use an MSP Agent inbound
endpoint. No TCP 10051/1514/1515 port-forward is expected or required.

## Dedicated AWS DR WireGuard path (disabled by default)

The Direct NR replacement path is a separate, opt-in tunnel and must not reuse
the existing On-Premise-to-MSP `wg0` interface or the retired `10.250.x.x`
address space. Its contract is:

```text
AWS Web gateway:  wg-aws-dr / AWS_PUBLIC_IP_REDACTED/24 / AWS_PUBLIC_IP_REDACTED:51821
On-Prem DB:      wg-aws-dr / AWS_PUBLIC_IP_REDACTED/32 / outbound client
AWS DB target:   AWS_PUBLIC_IP_REDACTED/32
Feature flag:    AWS_DR_WG_ENABLED=false
```

Terraform prepares the Web security-group UDP/51821 rule, the private route
`IP_REDACTED/24 -> Web ENI`, and the routed source-preserving path only when
`aws_dr_wg_enabled` is explicitly true. The optional resources have fail-closed
preconditions for the approved VPC, Web address, and private route table.
The Terraform switch is passed as `TF_VAR_aws_dr_wg_enabled`; the operator
environment example keeps both this and `AWS_DR_WG_ENABLED` false.
The Web instance already has source/destination checking disabled for its
gateway role. No MASQUERADE rule is part of the contract, so the expected
MySQL source address at the On-Prem DB is `IP_REDACTED`.

The explicit Ansible playbook is
`automation/ansible/aws_dr_wireguard.yml`; it is not included by `site.yml`.
It reads key files from paths outside Git, changes only `wg-aws-dr`, and is
fail-closed when runtime key material is absent. The read-only checker is:

```bash
AWS_DR_WG_ENABLED=false operations/aws/aws_dr_wireguard_status.sh
```

Before a reviewed cutover, the client configuration can be rendered without
starting the interface or touching the legacy route. This is an explicit
preparation-only path; it requires the existing out-of-band private key to be
mode `0600` and never bypasses the live cutover guard:

```bash
PYTHONNOUSERSITE=1 ansible-playbook \
  -i /tmp/aws-dr-wg-live.ini \
  automation/ansible/aws_dr_wireguard_prepare.yml \
  --limit onprem_db_wg \
  -e ansible_python_interpreter=/usr/bin/python3 \
  --check --diff

PYTHONNOUSERSITE=1 ansible-playbook \
  -i /tmp/aws-dr-wg-live.ini \
  automation/ansible/aws_dr_wireguard_prepare.yml \
  --limit onprem_db_wg \
  -e ansible_python_interpreter=/usr/bin/python3
```

The preparation playbook only creates or updates
`/etc/wireguard/wg-aws-dr.conf` with mode `0600`. It does not install
packages, start or enable `wg-aws-dr`, remove the `wg-aws-hub` route, change
AWS, or change MySQL. The normal `aws_dr_wireguard.yml` remains the separate
live path and continues to fail closed while the legacy interface or route is
active.

The live path is not enabled by this repository change. A future live window
must apply the reviewed Terraform plan first, configure both endpoints with
out-of-band keys, verify `nc -vz AWS_PUBLIC_IP_REDACTED 3306` from the AWS DB, and only
then consider the separate NR configuration. Existing MSP WireGuard, legacy
AWS WireGuard, NAT, and MySQL grants remain outside this contract.

### On-Prem path diagnosis and reversible cutover gate

Before applying the On-Prem client, verify that the MSP can reach the current
On-Prem management/DB address. The read-only diagnostic is:

```bash
/home/cloud/hospital-dr-codex/operations/aws/aws_dr_wireguard_path_preflight.sh
```

It reports the route to `IP_REDACTED`, the `IP_REDACTED` gateway, TCP/22,
and TCP/3306 without changing a route, interface, firewall, AWS resource, or
WireGuard service. A route through `IP_REDACTED` is the pfSense/LAN path; it is
not evidence that the legacy AWS tunnel is healthy. If the gateway itself is
unreachable, the exact fault remains in the MSP LAN/pfSense/On-Prem segment
until a host with network privileges can inspect the next hop.

The new client must not be started while the legacy `wg-aws-hub` interface or
its `IP_REDACTED/32` route is active. The Ansible client role checks both and
fails closed; it never stops the legacy tunnel automatically. After the
management path is healthy, a separately reviewed cutover window may use:

```bash
# On the On-Prem DB host: execute only after the cutover window is approved.
sudo systemctl stop wg-quick@wg-aws-hub.service
ip route show IP_REDACTED/32

# From the Ansible runtime, with the temporary inventory and Python 3 path.
PYTHONNOUSERSITE=1 ansible-playbook \
  -i /tmp/aws-dr-wg-live.ini \
  automation/ansible/aws_dr_wireguard.yml \
  --limit onprem_db_wg \
  -e ansible_python_interpreter=/usr/bin/python3 \
  -e aws_dr_wg_enabled=true

# On the On-Prem DB host: verify only the dedicated interface and route.
sudo wg show wg-aws-dr
ip route get IP_REDACTED
```

If the dedicated path fails, roll back by stopping only the new interface and
starting the legacy service again. Do not add a competing manual route:

```bash
sudo systemctl stop wg-quick@wg-aws-dr.service || true
sudo systemctl start wg-quick@wg-aws-hub.service
sudo wg show wg-aws-hub
ip route get IP_REDACTED
```

This cutover is not performed by the diagnostic or by the repository change.
MySQL replication configuration and `DB_NR_ENABLED` remain outside this gate.

## AWS server monitoring status

Continuous AWS server-agent monitoring is retired from the current operating
scope. The `aws-dr-web`, `aws-dr-emr`, and `aws-dr-db` Zabbix hosts are not
part of the active Grafana dashboard, and the old registration helper is
fail-closed unless a future environment explicitly sets
`AWS_ZABBIX_MONITORING_ENABLED=true`.

When the MSP Zabbix API is available, remove the exact retired objects with
the read-only check followed by the explicit cleanup command:

```bash
python3 operations/zabbix/retire_decommissioned_monitoring.py \
  --target chatops-test --check --env-file /path/to/zabbix.env
python3 operations/zabbix/retire_decommissioned_monitoring.py \
  --target chatops-test --apply --confirm --env-file /path/to/zabbix.env

python3 operations/zabbix/retire_decommissioned_monitoring.py \
  --target aws-zabbix --check --env-file /path/to/zabbix.env
python3 operations/zabbix/retire_decommissioned_monitoring.py \
  --target aws-zabbix --apply --confirm --env-file /path/to/zabbix.env
```

The cleanup utility deletes only the exact test host or AWS hosts with the
expected ownership tags. It never deletes the `AWS DR` group, production
hosts, AWS instances, CloudTrail data, Wazuh data, or DR approval objects.
The local `services/docker-compose.dr-test.yml` definition is retired; any
already-running container must be removed by the Docker operator on the host
where that compose project was deployed.

## AWS CloudTrail security

`operations/security/aws_cloudtrail_collector.py` reads the account's
CloudTrail Event History with `cloudtrail:LookupEvents` and writes normalized
documents to the existing Wazuh Indexer index
`hospital-aws-cloud-events`. It stores event metadata, not raw CloudTrail
session material or credentials. The systemd timer is an optional operational
installation; it uses the existing AWS credential chain and Wazuh Indexer
credential source.

The collector is intentionally not a CloudTrail trail creator. A durable S3
trail or a paid security service requires a separate cost and retention review.
The collector must use an external write-capable Indexer identity supplied as
`AWS_INDEXER_WRITE_USER`/`AWS_INDEXER_WRITE_PASSWORD` or the existing
operational credential source; Grafana's read-only identity is rejected.
The canonical least-privilege role contract is
`monitoring/wazuh/aws-cloudtrail-writer-role.json`; the runtime identity is
`aws_cloudtrail_writer`, and its external mode-0600 secret file is
`/home/cloud/hospital-dr-secrets/aws-indexer-writer.env`.

## Readiness states

`CONFIG_READY` means the repository contract, dashboards, and collectors pass
validation. `DISABLED_BY_DESIGN` means the current MSP topology cannot provide
a controlled inbound Agent path and the path is intentionally not part of the
operating architecture. It is not a live blocker and is not converted into a
synthetic endpoint-agent PASS. AWS instances in the normal stopped DR standby
state are displayed as `STANDBY`, not as an outage.

## Live validation record

The 2026-09-29 controlled validation established that the observed
`IP_REDACTED` address is not a controllable MSP inbound edge. It is not
used as an AWS Agent endpoint. The AWS endpoint-agent paths are now explicitly
disabled in the current runtime. CloudTrail Event History produced real
documents in `hospital-aws-cloud-events`, and Grafana
CloudTrail/category/high-risk/XDR queries returned real frames. The three EC2
instances remain stopped, no NAT or private route is retained, and both EIPs
are preserved.
