# Final DR Integration Runbook and Deep Freeze Plan

This runbook is for the final Hospital DR test window. Do not run the live
integration steps while the environment is frozen.

## Scope and Rules

- AWS region: `ap-northeast-2`
- NR mode: MySQL position-based replication
- Direct NR candidate endpoint: `AWS_PUBLIC_IP_REDACTED:3306` through the dedicated
  `wg-aws-dr` path (`AWS_PUBLIC_IP_REDACTED/24`, AWS Web gateway `AWS_PUBLIC_IP_REDACTED`).
- `AWS_PUBLIC_IP_REDACTED:3306` is the retired public/NAT-era path and is not an
  acceptance endpoint for the current Direct NR design.
- The preserved `AWS_PUBLIC_IP_REDACTED` EIP must not be released before the WG/NR
  acceptance decision, but it is not the current Direct NR source endpoint.
- The existing MSP WireGuard is only the On-Premise <-> MSP monitoring tunnel.
- A separate, optional AWS DR WireGuard path is reserved for On-Premise DB <->
  AWS DR Web gateway traffic; it uses `wg-aws-dr` and `AWS_PUBLIC_IP_REDACTED/24` and is
  disabled by default. It never reuses `wg0` or the retired `10.250.x.x` range.
- Do not use `full_failback.sh` alone for the final test. It skips DB and Doc
  failback unless the matching environment variables are set.
- Judge success by service responses and matching data, not by log lines alone.
- Never print secret values, dump contents, tokens, or private keys.
- The current AWS baseline has no NAT Gateway.  Live failover/failback uses the
  approved Web NAT Instance status guard and must not invoke NAT Gateway
  create/delete lifecycle commands.  A status guard failure is a hard stop;
  do not allow the workflow to recreate a NAT Gateway during the final window.

The canonical repository is the tracked source of truth. The operational
Terraform directory keeps its existing state and generated artifacts, while
ChatOps keeps its separate persistent runtime. Commands below use explicit
paths where an operational directory is required.

## Final Demo Freeze Operating Checklist

This is the operator-facing freeze checklist for the day before and the day
of the presentation. It adds no runtime feature and does not replace the
existing preflight, approval, workflow, or rollback contracts below. If a
check cannot be evidenced, treat it as a hard stop; do not make the result
look green by weakening a gate.

### Freeze rules and decision

Before the freeze, record the current commit, preflight JSON, owners, and
known blockers. After the freeze, only the following are allowed:

- a blocker bug fix that does not change the DR design or approval policy;
- a fixed endpoint or other reviewed operational setting correction; and
- documentation or evidence correction that preserves the source records.

The following are prohibited after freeze: new ChatOps or security features,
Terraform topology changes, network redesign, Kubernetes, Prometheus, a new
replication method, a new tunnel, or a change from two-person approval.

The live demonstration cannot start unless the final preflight reports both
`SAFE_TO_START_LIVE_E2E=true` and `DEMO_READY=true`, and every hard-stop item
below is clear. `DB_NR_ENABLED=false` and
`DUMP_RESTORE_EXEC_ENABLED=false` remain the safe preparation defaults until
their separately approved acceptance gates pass.

### T-1 day checklist

Run from the MSP controller. These checks are read-only except for fetching
the current Git remote references; they do not start AWS or send Slack.

```bash
cd /home/cloud/hospital-dr-codex
git fetch --quiet origin main
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
test -z "$(git status --porcelain)"
git rev-parse HEAD

# The command uses the external secret source but never prints its values.
test -r /home/cloud/hospital-dr-secrets/dr.env
test "$(stat -c '%a' /home/cloud/hospital-dr-secrets/dr.env)" = 600

ZABBIX_CONTROLLER_API_URL=http://IP_REDACTED/api_jsonrpc.php \
WAZUH_CONTROLLER_INDEXER_URL=https://IP_REDACTED:9200 \
WAZUH_INDEXER_TLS_SKIP_VERIFY=true \
PYTHONNOUSERSITE=1 python3 operations/preflight/final_live_e2e_preflight.py \
  --no-legacy-shell \
  --env-file /home/cloud/hospital-dr-secrets/dr.env \
  --aux-env-file /home/cloud/grafana/.env \
  --json-output /tmp/final-live-e2e-preflight-t1.json
```

Record the following T-1 evidence without exposing secret values:

- Git `HEAD`, `origin/main`, clean worktree, and the matching GREEN CI run;
- readable `dr.env` with mode `0600`, required credential names present, and
  no secret backup or residue files;
- fixed Cloudflare DNS/TLS and all three POST-only callback routes;
- Zabbix Server/Proxy, alert scripts, Failback runtime, and recovery-action
  documentation;
- Wazuh Manager/Indexer, destructive-event escalation contract, and the
  AWS external 1514/1515 path recorded as `DISABLED_BY_DESIGN`;
- Grafana provisioning and datasource health, without replacing its runtime
  database;
- complete local dump/`.master_status` pair, checksum/metadata result, and
  read-only S3 pair visibility;
- AWS cost status: the three DR EC2 states, no NAT Gateway recreation, EIP
  preservation, and no unexpected paid resource; and
- physical network, pfSense, On-Prem Web/Doc/DB, SNMP, clock, and owner
  availability for Demo Day.

Use the existing read-only checks for the final details:

```bash
bash operations/runtime/final_dr_preflight.sh
bash operations/aws/aws_dr_wireguard_path_preflight.sh
operations/nat/nat_status.sh
```

For fixed Slack, a POST-only handler returning `405` to a GET is expected;
DNS, TLS, and application reachability must still succeed. Do not remove the
working ngrok path until the fixed hostname has passed and all three Slack
Apps have been manually switched and tested.

### Demo Day power-on order

Do not skip forward in this sequence. Each stage records its result before
the next stage begins.

1. **Physical network:** power and link state, upstream switch, router, and
   pfSense WAN/LAN/gateway status. Confirm the MSP-to-On-Prem path before
   touching DR state.
2. **pfSense:** verify interfaces, routes, ARP, firewall policy, and the
   existing MSP WireGuard path read-only. Do not create an AWS inbound rule or
   change the legacy tunnel during this preparation stage.
3. **On-Prem Web/DB/Doc:** power on the required hosts, verify clock sync,
   service health, Web/Doc/DB ports, and the four SNMP devices. Do not call
   the AWS DR workflow while any required On-Prem health gate is red.
4. **MSP services:** confirm ChatOps, Zabbix Proxy, Grafana, Wazuh, and the
   local evidence/backup paths are active. Start only an inactive approved
   service; do not perform an unreviewed restart.
5. **Zabbix/Wazuh/Grafana/ChatOps:** run the read-only contracts, verify the
   Alert and approval routes, Emergency Console, audit/state DB, free locks,
   and no pending or executing request.
6. **AWS start:** only after steps 1–5 pass, start the three existing DR EC2
   instances through the approved wrapper, without changing DNS first:

   ```bash
   SKIP_DNS=true \
     /home/cloud/hospital-dr-terraform/dr_project_resume.sh
   ```

   This is an explicit Demo Day power-on action, not a preflight command. It
   must not provision EC2, create a NAT Gateway, release an EIP, or change the
   Terraform topology.
7. **Route health:** verify Web `source_dest_check=false`, Web ENI target,
   `IP_REDACTED/0` and `IP_REDACTED/24` routes are `active`, and no route is
   `blackhole` after Web is running. Confirm the Web NAT Instance status guard.
8. **WireGuard:** run the dedicated `wg-aws-dr` pre-cutover check, then use
   only the approved live cutover procedure. Keep `wg-aws-hub` as rollback
   until the new handshake, route, and DB port test pass.
9. **MySQL NR:** use a fresh dump and matching File/Pos only after the
   two-person approval/pre-check gate. Verify IO/SQL threads, lag/errors,
   read-only state, and test transaction evidence.
10. **Final preflight:** rerun the integrated checker and archive the JSON
    with the same `RUN_ID`/`INCIDENT_ID` plan. Only then may the approved
    Failover demonstration begin.

### Hard-stop matrix

Stop the demonstration and preserve evidence if any condition is true:

| Condition | Required result |
| --- | --- |
| Fixed Slack endpoint | `PASS` for DNS/TLS/application reachability and all three routes |
| On-Prem Web/Doc/DB | Required service health `PASS` |
| SNMP | All required DR network devices live and fresh |
| WireGuard | `WG_PRE_CUTOVER_READY=YES` or, after cutover, handshake/route pass |
| Native Replication | `NR_PRECHECK_READY=YES`; during live run IO/SQL healthy |
| Lock/request state | No stale execution lock and no `PENDING`, `PARTIALLY_APPROVED`, or `EXECUTING` request |
| Clock | MSP, Zabbix, On-Prem, and AWS clocks synchronized and evidence timestamps trustworthy |
| AWS route | No `blackhole` route after Web starts; wrong target/VPC is configuration error |
| Approval | Two distinct administrators, valid TTL, no duplicate/superseded request |

Do not bypass a hard stop by manually invoking a workflow, opening a broad
firewall rule, recreating NAT, hiding a Wazuh state, or treating an old
`NOT_MEASURED` record as a successful run.

### Live evidence capture checklist

Use one unique `RUN_ID` and the exact correlated `INCIDENT_ID`. Capture the
source timestamp, not the time a screenshot was taken.

- [ ] T-1/final preflight JSON and Git/CI identity
- [ ] Zabbix Problem/Recovery, ordinary Alert bridge, and Failover/Failback
  candidate evidence
- [ ] General ChatOps Alert and Failover request, including 0/2, 1/2, and 2/2
- [ ] first/second approver identities and approval timestamps
- [ ] execution start, Terraform/Ansible stage results, and workflow audit
- [ ] AWS Web/EMR/DB health, route state, Web NAT Instance, and security state
- [ ] WireGuard interface, handshake, route, and AWS DB to `AWS_PUBLIC_IP_REDACTED:3306`
- [ ] MySQL source/replica File/Pos, IO/SQL state, lag/errors, and test
  INSERT/UPDATE/DELETE evidence
- [ ] Grafana RTO/RPO panels, Zabbix, Wazuh, AWS Cloud Security, and XDR
- [ ] Failback request, Recovery event, Network/SNMP/Wazuh gate,
  0/2 → 1/2 → 2/2
- [ ] final cleanup status: DNS, `DR_STATE`, locks, requests, routes, WG,
  replica, EC2, EIP, and cost resources

Create the presentation bundle only from these real records:

```bash
python3 operations/preflight/rto_rpo_evidence_collector.py \
  --run-id "$RUN_ID" \
  --incident-id "$INCIDENT_ID" \
  --timeline "${DR_RTO_TIMELINE_FILE:-/var/lib/hospital-dr/rto_timeline.json}" \
  --state-db "${CHATOPS_STATE_DB:-/var/lib/hospital-dr/chatops_state.sqlite3}" \
  --audit "${CHATOPS_AUDIT_FILE:-/var/lib/hospital-dr/audit/chatops_audit.jsonl}" \
  --db-nr-enabled "${DB_NR_ENABLED:-false}" \
  --output-root "${DR_EVIDENCE_ROOT:-/var/lib/hospital-dr/evidence}"
```

Missing stages remain `NOT_MEASURED`; with `DB_NR_ENABLED=false`, RPO remains
`NOT_MEASURABLE`. Never fill an absent timestamp with the current time.

### Rollback index

Use the existing detailed procedures rather than inventing a new command at
the incident console:

- [Phase 3 WireGuard rollback command sequence](#phase-3-wireguard-rollback-command-sequence)
- [Failure rollback matrix](#failure-rollback-matrix)
- [Failover abort conditions](#failover-abort-conditions)
- [Failback Live Runbook](#14-failback-live-runbook)
- [RTO and RPO Evidence Capture](#15-rto-and-rpo-evidence-capture)

The universal rule is: stop at the failed stage, preserve logs/audit/status,
keep the known healthy side active, and require a fresh reviewed request before
retrying. Do not reset replication, reuse old File/Pos, recreate NAT, or run a
second workflow in parallel.

### Post-demo cleanup

Cleanup starts only after the approved Failback result or an explicitly
documented aborted demonstration. Preserve the evidence bundle first.

1. Confirm DNS/traffic is back on the approved On-Prem endpoint and
   `DR_STATE=IDLE`; do not clear state by editing the database.
2. Resolve or expire requests through the normal ChatOps flow. Verify no
   `PENDING`, partial approval, execution lock, or duplicate Emergency Console
   remains. Validate ownership before any stale-lock action.
3. If `wg-aws-dr` was used, stop only the dedicated new interface after the
   legacy path is verified; keep the MSP `wg0`/`wg-aws-hub` monitoring fallback
   intact unless the approved rollback says otherwise.
4. Leave the MySQL evidence and replica status recorded. Do not run
   `RESET REPLICA`, delete the source dump, or change `DB_NR_ENABLED` until
   the DB owner signs off.
5. Return the environment through the approved suspend path and verify all
   three AWS EC2 instances are stopped:

   ```bash
   SKIP_DNS=true \
     /home/cloud/hospital-dr-terraform/post_demo_suspend.sh
   SKIP_DNS=true \
     /home/cloud/hospital-dr-terraform/dr_environment_control.sh stop
   ```

   The FinOps/environment wrappers do not manage NAT. Run
   `operations/nat/nat_status.sh` for verification only; do not recreate or
   release NAT/EIP resources as part of cleanup.
6. Verify no temporary route, SG, EIP, ENI, backup, or other paid resource was
   created. Preserve the approved EIPs and the Direct NR/WG dependency EIP.
7. Remove the temporary ngrok path only after the fixed Cloudflare hostname
   and all three Slack Apps have been tested successfully. Otherwise leave
   ngrok available for recovery.
8. Confirm test flags are back to safe values: broad test mode `OFF`,
   `DB_NR_ENABLED=false` unless the separately approved NR acceptance is
   complete, and `DUMP_RESTORE_EXEC_ENABLED=false`.
9. Archive the final preflight, RTO/RPO bundle, screenshots, audit reference,
   cleanup output, and the final Git/CI identity.

The cleanup is complete only when AWS is suspended, `DR_STATE` is idle, locks
and requests are clear, no temporary endpoint is unintentionally active, and
the evidence directory is immutable/preserved.

## 0. Final Read-only Readiness Gate

Before assembling the two-person test window, run the canonical checker:

```bash
cd /home/cloud/hospital-dr-codex
bash operations/runtime/final_dr_preflight.sh
```

The checker only reads local state, service/process status, Cloudflare record
metadata, SSM-backed token availability, AWS resource state, ECR metadata, and
backup metadata. It does not start AWS resources, change DNS, send callbacks,
prepare state, or execute either DR workflow. `FINAL_DR_READY=false` with
`BLOCKED:` codes is the expected result until all external prerequisites are
complete; do not treat a nonzero exit as permission to bypass a blocker.

When a reviewed read-only Terraform plan is available, include it explicitly:

```bash
DR_TERRAFORM_PLAN_JSON=/path/to/terraform-show-plan.json \
  bash operations/runtime/final_dr_preflight.sh
```

The final window may start only after the blocking codes are resolved. Terraform
OIDC state drift, key-pair mismatch, and management-CIDR ownership remain
operator-review warnings; the checker never reconciles them automatically.

### On-Prem monitoring state classification

The preflight and Grafana infrastructure dashboard classify host state and
shared-path state independently. The current observed snapshot is:

- Web: `LIVE` / Zabbix Agent reachable / WireGuard path live; its HTTP health
  may separately report a database or Doc dependency degradation.
- Doc/EMR: `POWERED_OFF / NOT TESTED LIVE`.
- DB: `POWERED_OFF / NOT TESTED LIVE`.
- Shared On-Prem path: `PASS_PARTIAL_LIVE` because the Web path is live.

An unavailable Doc/DB host is not evidence of a WireGuard failure. The checker
returns `POWERED_OFF_OR_NOT_AVAILABLE` when no trusted power-state source is
available, and only an independent common-path signal can produce
`NETWORK_PATH_BLOCKED`. Doc/DB not running remains a live-test prerequisite,
not a network diagnosis.

### Final audit commands (read-only)

Run these checks before the two-person window. They do not start EC2, change
routes, send Slack messages, or alter Zabbix/Cloudflare state.

```bash
cd /home/cloud/hospital-dr-codex

# MSP/controller clock. Run the same three read-only commands on On-Prem
# Web/Doc/DB and on each AWS host through the approved management path.
date -Is
timedatectl show --property=Timezone --property=NTPSynchronized --property=NTP
systemctl is-active systemd-timesyncd.service chrony.service chronyd.service || true

# Zabbix API/action contracts. The URL override avoids a Docker-internal
# hostname; the env file path is used as a secret source and its values are
# never printed.
ZABBIX_API_URL=http://IP_REDACTED/api_jsonrpc.php \
  python3 operations/zabbix/configure_chatops.py --check \
  --env-file /home/cloud/grafana/.env
ZABBIX_API_URL=http://IP_REDACTED/api_jsonrpc.php \
  python3 operations/zabbix/configure_production_dr_triggers.py --check \
  --env-file /home/cloud/grafana/.env

# The actual Zabbix Server alertscript installation, not only the repository.
sudo test -x /usr/lib/zabbix/alertscripts/send_failback.sh
sudo test -x /usr/lib/zabbix/alertscripts/zabbix_failback_guard.sh
sudo cmp operations/chatops/send_failback.sh \
  /usr/lib/zabbix/alertscripts/send_failback.sh
sudo cmp operations/db/zabbix_failback_guard.sh \
  /usr/lib/zabbix/alertscripts/zabbix_failback_guard.sh
sudo bash -n /usr/lib/zabbix/alertscripts/send_failback.sh
sudo bash -n /usr/lib/zabbix/alertscripts/zabbix_failback_guard.sh

# Runtime drift is read-only and excludes secrets/state/audit files.
bash operations/runtime/runtime_drift_check.sh --check

# Fixed Slack callback routes. GET 405 is expected for POST-only handlers;
# DNS/TLS failure is a blocker. ngrok is not a production substitute.
for path in /slack/failover/action /slack/failback/action /slack/action; do
  curl -ksS -o /dev/null -w "%{http_code} %{url_effective}\\n" \
    --connect-timeout 5 --max-time 10 "https://chatops.hospital-web.pp.ua${path}"
done

# Dedicated WG path diagnostic; it is read-only and must not perform cutover.
bash operations/aws/aws_dr_wireguard_path_preflight.sh
```

The audit must also record `fuser /var/lib/hospital-dr/workflow.lock` (no
holder), no active `PENDING/PARTIALLY_APPROVED/EXECUTING` rows in the ChatOps
state DB, and one `READY` Emergency Console row. Do not delete stale-looking
locks or rows without validating the owning process/state first.

## Phase 2.5 freeze and Phase 3 entry contract

Phase 2.5 is an audit and procedure-freeze stage. It does not start or stop
AWS, change a route, stop either WireGuard peer, or change MySQL replication.
The Phase 3 window is not allowed to begin until every gate below is explicit:

```text
FIXED_SLACK_ENDPOINT=PASS
ONPREM_WEB=PASS
SNMP_LIVE=PASS
ZABBIX_FAILBACK_RUNTIME=PASS
RUNTIME_DRIFT=PASS
EGRESS_WORKFLOW=PASS
WG_PRE_CUTOVER_READY=YES
NR_PRECHECK_READY=YES
NO_STALE_EXECUTION_LOCK=true
NO_ACTIVE_PENDING_REQUEST=true
GIT_PHASE3_REQUIRED_CHANGES_REVIEWED=true
```

The current frozen AWS observation is also important: the private route table
targets the approved Web instance/ENI for both `AWS_PUBLIC_IP_REDACTED/0` and
`AWS_PUBLIC_IP_REDACTED/24`, while Web, DB, and EMR are stopped. AWS therefore reports
those instance-targeted routes as `blackhole`; this is
`EXPECTED_WHILE_WEB_STOPPED`, not evidence to recreate a NAT Gateway. After
Web is started in the live window, either route remaining `blackhole`, or a
different target/VPC/route table, is `CONFIGURATION_ERROR` and the window must
stop.

Any future Terraform plan for the approved Web NAT/WireGuard topology must
pass the explicit feature values below. Do not rely on defaults and do not
apply the plan during Phase 2.5:

```text
private_egress_mode=web_nat_instance
aws_web_nat_instance_enabled=true
enable_nat_gateway=false
aws_dr_wg_enabled=true
```

The final live path uses the three already-provisioned EC2 instances. It must
not call `infra/terraform/run_demo.sh`,
`operations/finops/dr_environment_control.sh provision`,
`operations/nat/nat_enable.sh`, or `operations/nat/nat_disable.sh`. Those are
provisioning/manual lifecycle paths and are `MUST_NOT_USE` during Phase 3;
the live workflow may only run the read-only Web NAT Instance status guard.
If the three-instance set is incomplete, the live workflow must fail closed
and the window must be rescheduled rather than entering reprovisioning.

### Phase 3 operator sequence (not executed by this audit)

1. Run the final read-only preflight, record the run ID, verify two distinct
   approvers, and confirm no execution lock or pending request exists.
2. Start Web, DB, and EMR with the approved lifecycle command. Confirm SSM,
   service health, Web `source_dest_check=false`, the approved EIP, and that
   both private routes are `active` before continuing.
3. Run the Web NAT Instance status guard and verify Web forwarding/NAT and
   `wg-aws-dr` without restarting the legacy MSP tunnel.
4. From the On-Prem DB host, record the legacy `wg-aws-hub` handshake and
   `IP_REDACTED/32` route. Verify the dedicated key/config without starting
   it yet.
5. In the approved cutover window, stop only `wg-aws-hub`, verify its route is
   gone, then apply the explicit `wg-aws-dr` client playbook. The client role
   fails closed if the legacy interface or route is still present.
6. Verify the new handshake, `AWS_PUBLIC_IP_REDACTED <-> AWS_PUBLIC_IP_REDACTED`, the AWS DB route,
   and `nc -vz -w 5 AWS_PUBLIC_IP_REDACTED 3306` from the AWS DB. Do not continue if any
   gate fails.
7. Take a fresh source dump and capture its checksum and the same source
   `File/Pos`. Never reuse legacy coordinates. Restore the dump to the DR DB,
   configure position-based replication with source host `IP_REDACTED`, and
   start it only after the two-person approval and pre-check pass.
8. Accept NR only with `Replica_IO_Running=Yes`, `Replica_SQL_Running=Yes`,
   acceptable lag, no IO/SQL error, matching coordinates, and unique
   INSERT/UPDATE/DELETE evidence. Keep the replica read-only.
9. Run the existing approved Failover/Failback flows, capture RTO/RPO evidence,
   and set `DB_NR_ENABLED=true` only after all acceptance criteria pass.

For any failed NR attempt, preserve `SHOW MASTER STATUS`, replica status,
source/relay/exec coordinates, `Last_IO_Error`, `Last_SQL_Error`, logs, and
the run ID. Do not run `RESET REPLICA`, do not reuse an old position, and do
not retry blindly.

### Phase 3 WireGuard rollback command sequence

Rollback is operator-controlled and is only used after the new path has
actually been started. It does not create a NAT Gateway or add a competing
manual route:

```bash
# On the On-Prem DB host.
sudo systemctl stop wg-quick@wg-aws-dr.service || true
ip route show IP_REDACTED/32
sudo systemctl start wg-quick@wg-aws-hub.service
sudo wg show wg-aws-hub
ip route get IP_REDACTED

# From the approved management path, verify the original DB endpoint before
# any retry. Preserve the failure evidence if it is still unreachable.
nc -vz -w 5 IP_REDACTED 3306
```

If MySQL configuration has already started and fails, stop at the failure,
preserve the coordinates and errors above, leave `DB_NR_ENABLED=false`, and
obtain a fresh reviewed dump/position before any later attempt. Do not combine
WireGuard rollback with a replication reset.

## 1. Preflight Without Starting AWS

These checks do not start EC2 or NAT resources.

```bash
cd /home/cloud/hospital-dr-terraform
terraform fmt -check
terraform validate

for script in \
  full_failover.sh full_failback.sh web_db_failback.sh \
  db_failback_to_onprem.sh doc_failback_sync.sh run_demo.sh \
  failback.sh dr_environment_control.sh; do
  bash -n "$script"
done

ANSIBLE_CONFIG=/home/cloud/hospital-dr-ansible/ansible.cfg \
ansible-playbook \
  -i /home/cloud/hospital-dr-ansible/inventory.ini \
  /home/cloud/hospital-dr-ansible/site.yml \
  --syntax-check

operations/nat/nat_status.sh
aws ec2 describe-nat-gateways \
  --region ap-northeast-2 \
  --filter Name=state,Values=available,pending,deleting \
  --query 'NatGateways[].{id:NatGatewayId,state:State}' \
  --output table
```

Inject the Cloudflare token into the Terraform process only. Do not echo it.

```bash
CLOUDFLARE_API_TOKEN="$(aws ssm get-parameter \
  --name /hospital-dr/cloudflare/api-token \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text)" \
terraform plan -refresh=true -no-color
```

The expected frozen state is three stopped EC2 instances, no NAT Gateway, and
the preserved NAT EIP still present. The plan must report `No changes`.

### Secret and configuration checklist

This prints only `SET` or `MISSING`, never a value.

```bash
set +u
source /home/cloud/hospital-dr-secrets/dr.env
set -u

for name in \
  CF_API_TOKEN CLOUDFLARE_API_TOKEN \
  MYSQL_ROOT_PASS DB_REPL_PASSWORD DB_BACKUP_ENCRYPTION_KEY \
  WEB_DB_PASSWORD DOC_DB_PASSWORD \
  ONPREM_DB_ROOT_PASS ONPREM_DOC_DB_PASSWORD \
  DB_NR_ENABLED DB_REPL_MODE DB_SOURCE_HOST DB_SOURCE_PORT \
  DB_SOURCE_LOG_FILE DB_SOURCE_LOG_POS ONPREM_DOC_SSH; do
  if [ -n "${!name:-}" ]; then
    printf 'SET %s\n' "$name"
  else
    printf 'MISSING %s\n' "$name"
  fi
done
```

For the final NR test, these non-secret values must be explicit:

```text
DB_NR_ENABLED=true
DB_REPL_MODE=position
DB_SOURCE_HOST=IP_REDACTED
DB_SOURCE_PORT=3306
DB_SOURCE_LOG_FILE=<current source binlog file>
DB_SOURCE_LOG_POS=<current source binlog position>
```

`DB_REPL_PASSWORD` must be loaded from `dr.env`, never placed in a command
line.  Set `DB_SOURCE_HOST=IP_REDACTED` only after the controlled
`wg-aws-dr` cutover and route/handshake checks have passed.  The existing
legacy script defaults are not proof that the WG path is live.

## 2. On-Premise and pfSense Gate

Before the AWS test window:

1. Confirm that the on-premise DB listens on TCP 3306 on the dedicated WG
   address or the local DB listener used by the routed path.
2. Confirm the On-Prem peer has `wg-aws-dr` at `AWS_PUBLIC_IP_REDACTED/32`, the AWS Web
   gateway has `IP_REDACTED/24`, and the peer handshake is fresh.
3. Confirm the AWS DB route to `AWS_PUBLIC_IP_REDACTED/32` uses the dedicated WG path and
   does not collide with `wg-aws-hub`.
4. Confirm the MySQL `repl` account is allowed from the *observed routed
   source*; do not assume the retired `IP_REDACTED` source.
5. Record `SHOW MASTER STATUS\G` immediately before the NR test.
6. Confirm the MSP management path separately from the AWS DB/WG path.

After the AWS DR DB is running, the first live network gate is:

```bash
nc -vz -w 5 IP_REDACTED 3306
```

If it fails, stop. Do not open the AWS Security Group to `AWS_PUBLIC_IP_REDACTED/0`.
Check the `wg-aws-dr` route, handshake, peer firewall, and MySQL listener.

## 3. Practical Test Order

The conceptual gate is `WG path -> fresh dump/position -> NR -> Failover ->
service/data test -> Failback`.
The current topology has a practical constraint: private DR DB SSH is reached
through the DR Web bastion. Therefore the bastion must be available before an
Ansible-based NR check can run.

Use this operational order:

1. Complete the on-premise and pfSense gate.
2. Start the approved AWS test window and complete the dedicated WG cutover
   gate before any replication command.
3. Create the fresh dump/position pair and run the NR TCP/status gates before
   declaring the database path ready.
4. Run the full failover workflow and verify Web, EMR, and DB health.
5. Generate unique test data and verify it on the promoted DR DB.
6. Run the complete DB/Doc/Web failback workflow.
7. Verify the same data on the on-premise DB and services.
8. Restore DNS, stop EC2, verify the Web NAT Instance final state, and verify
   Terraform has no unapproved drift. Do not invoke a NAT Gateway lifecycle
   command as cleanup.

This keeps NR as a failover acceptance gate without pretending that an
unreachable private DB can be checked through Ansible before its bastion is
started.

## 4. Failover and NR Acceptance

### Current P0 execution rule (2026-10-18)

The historical direct-shell example and its static `DB_NR_ENABLED=true` /
source-coordinate exports are **not a valid current production procedure**.
Do not source `dr.env` and invoke `full_failover.sh` manually. Production
Failover may start only from the current Slack ChatOps request after two
distinct authorized administrators approve that same request. The server-side
launch guard re-reads the request and its recovery/RPO evidence before it
starts the canonical executor. Emergency entry uses the same executor and
does not bypass fencing or data gates.

After the network owner confirms restoration, collect evidence in this order;
these checks do not themselves authorize a transition:

1. Run the existing read-only DB check:
   `bash /home/cloud/hospital-dr-codex/operations/finops/dr_environment_control.sh --check-onprem-only`.
   It checks the reachable DB identity and its runtime/persistent read-only
   state. It does **not** prove that Web/EMR writers are stopped or isolated.
2. Obtain fresh, request-bound Web and EMR writer-isolation evidence from
   verified host identities and pinned SSH host keys, or from an independently
   readable network/hypervisor fence. Evidence must identify each target,
   result, and capture time and satisfy the verifier's request binding/TTL.
   SSH failure, a DB session listing, or an operator-entered environment value
   is not a PASS. Recheck the DB fence immediately before promotion.
3. For Position NR, record the live source UUID/server ID, `binlog_format=ROW`,
   GTID mode/state and current source File/Position, then verify the AWS replica source
   identity, IO/SQL state, lag and read/executed coordinates against that
   source position. Do not use historical coordinates, manually enable NR,
   reset/reseed replication, or treat a stopped channel as ready. The existing
   readiness selector performs these checks in the approved execution path.
4. Bind the recovery candidate and RPO evidence to the same Slack request.
   RPO is usable only when the recovered-data cutoff is trusted, authenticated,
   request-matched, and no more than 900 seconds old. Dump completion time,
   S3 upload time, a standalone MySQL observation, or an `UNVERIFIED` manifest
   leaves RPO `NOT_MEASURED` and blocks execution. A Dump fallback additionally
   requires one exact Manifest-backed Dump/sidecar set, verified hashes and
   coordinates, and the existing pre-restore AWS DB preservation/approval
   gates. Legacy sidecar-only backups are not candidates.
5. Only after the field evidence and a recoverable candidate exist should the
   operator create a fresh Slack request explicitly describing the selected
   recovery plan and evidence. Two-person approval is then performed in Slack;
   ChatOps alone launches `infra/terraform/full_failover.sh`, which delegates
   to `operations/failover/full_failover.sh`. Never run that child separately.

**Ansible path contract (2026-10-18):** the executor now reads
`aws_web_nat_instance.yml` and `ansible.cfg` only from canonical
`DR_ANSIBLE_SOURCE_DIR=/home/cloud/hospital-dr-codex/automation/ansible`, with
realpath checks against the repository's canonical files. `DR_ANSIBLE_DIR` at
`/home/cloud/hospital-dr-ansible` remains the operational inventory location;
its external `ansible.cfg` is not consumed by this NAT path. Focused contract
tests and `ansible-playbook --syntax-check` passed without contacting hosts.
No Ansible apply, Failover, or service restart was performed. Other Ansible
workflows using the external config are outside this path fix.

The current `full_failover.sh` starts only the approved existing three-EC2
set; if the set is incomplete, it blocks instead of invoking `run_demo.sh` or
silently provisioning infrastructure. Do not use the historical paragraph
below as an execution instruction.

NR is accepted only when:

- DR DB reaches the **field-verified current On-Prem source endpoint** through
  the approved route. Do not assume the historical `IP_REDACTED:3306` is live
  until route and source identity are read back;
- the approved request selects Position mode; do not turn NR on by manually
  exporting a static environment value;
- `Replica_IO_Running=Yes` and `Replica_SQL_Running=Yes` (or legacy
  `Slave_*` equivalents) are reported;
- the live readiness contract's reported lag requirement is met (currently
  zero reported lag);
- source file/position and replica read/executed coordinates match or are
  beyond the same live source coordinate; and
- a unique source test row is visible on the DR replica before promotion,
  only when a separate DB-owner-approved test write is in scope. Do not add a
  source write merely to satisfy this checklist without that approval.

Ansible success alone is not proof of replication. Query the actual row.

## 5. Service and Data Verification

Verify the user-facing routes after failover readiness:

```bash
curl -fsS https://hospital-web.pp.ua/health
curl -fsS https://hospital-web.pp.ua/emr/
curl -fsS https://emr.hospital-web.pp.ua/
```

Create two uniquely identifiable records through the real applications:

- one Web account using a timestamped test login;
- one Doc/EMR patient record marked as test data.

Record only non-sensitive identifiers. Verify them directly on the promoted
DR DB and in both application views. The test fails if HTTP succeeds but the
expected row is missing or Web and EMR show different database states.

## 6. Complete Failback Path

Use this wrapper for the final test. It enables both DB and Doc failback,
requires explicit overwrite/sync confirmations, returns DNS, cleans temporary
NAT resources, and can stop EC2 after the data workflow succeeds.

```bash
cd /home/cloud/hospital-dr-terraform
source /home/cloud/hospital-dr-secrets/dr.env

export ONPREM_DOC_SSH=<on-premise-doc-user-and-reachable-address>
export ONPREM_DOC_PATH=/home/hoseo/hospital_emr
export ONPREM_DOC_PORT=5000
export ONPREM_DB_HOST=IP_REDACTED
export ONPREM_DB_PORT=3306
export DB_FAILBACK_CONFIRM=OVERWRITE_ONPREM_DB
export DOC_FAILBACK_CONFIRM=SYNC_DOC_TO_ONPREM
export RUN_DB_FAILBACK=true
export RUN_DOC_FAILBACK=true
export CLEANUP_NAT_AFTER_FAILBACK=false
export STOP_DR_EC2_AFTER_FAILBACK=true

./web_db_failback.sh
```

The wrapper invokes:

1. `db_failback_to_onprem.sh`: exports the promoted DR DB and restores it to
   the on-premise DB after TCP and authentication gates;
2. `doc_failback_sync.sh`: transfers the DR Doc archive, restores the
   on-premise Doc path, and checks the local service;
3. `failback.sh`: returns Web and EMR DNS to the on-premise target and checks
   on-premise health;
4. the Web NAT Instance status guard: verifies the approved egress without
   creating, deleting, or retargeting a NAT Gateway; NAT lifecycle commands
   remain explicit operator-only actions outside the live workflow; and
5. `dr_environment_control.sh stop` through the explicit stop flag.

Do not use `full_failback.sh` alone. Its default environment intentionally
skips DB and Doc failback.

## 7. On-Premise Data Acceptance

After the wrapper completes:

1. Query both unique test identifiers on the on-premise DB.
2. Confirm the Web account works on the on-premise service.
3. Confirm the Doc/EMR patient record is displayed on port 5000.
4. Confirm the on-premise service is listening on the expected port.
5. Confirm Cloudflare resolves to the on-premise target and health endpoints
   respond.
6. If a row is missing, stop and preserve the DR dump/logs. Do not run a
   second overwrite blindly.

The script row counts are secondary evidence. Unique identifiers and actual
application responses are the acceptance evidence.

## 8. Cost Cleanup and Final State

After data acceptance, verify cleanup without starting resources:

```bash
cd /home/cloud/hospital-dr-terraform
operations/nat/nat_status.sh

aws ec2 describe-nat-gateways \
  --region ap-northeast-2 \
  --filter Name=state,Values=available,pending,deleting \
  --query 'NatGateways[].{id:NatGatewayId,state:State}' \
  --output table

aws ec2 describe-instances \
  --region ap-northeast-2 \
  --filters \
    Name=tag:Name,Values=Hospital-Real-Web-Server,Hospital-DR-Doc-Server,Hospital-DR-DB-Server \
  --query 'Reservations[].Instances[].{name:Tags[?Key==`Name`]|[0].Value,state:State.Name}' \
  --output table

aws ec2 describe-addresses \
  --region ap-northeast-2 \
  --filters Name=tag:Name,Values=Hospital-DR-NAT-EIP \
  --query 'Addresses[].{ip:PublicIp,association:AssociationId,preserve:Tags[?Key==`Preserve`]|[0].Value}' \
  --output table
```

Expected result:

- no available, pending, or deleting NAT Gateway;
- all three DR EC2 instances stopped;
- NAT EIP `AWS_PUBLIC_IP_REDACTED` remains allocated with `Preserve=true`;
- Cloudflare is back on the on-premise target; and
- a full Terraform plan reports `No changes`.

Also perform the residual-state audit before closing the window:

```bash
fuser /var/lib/hospital-dr/workflow.lock || true
fuser /var/lib/hospital-dr/failover.lock || true
fuser /var/lib/hospital-dr/failback.lock || true
```

Read the ChatOps SQLite database in read-only mode and confirm there are no
`PENDING`, `PARTIALLY_APPROVED`, or `EXECUTING` requests, no duplicate
Emergency Console rows, and no unreviewed stale approval. Confirm
`BROAD_TEST_MODE=OFF`, `DB_NR_ENABLED` is set to the intended post-test value,
only the intended WireGuard interface/route remains active, the AWS replica is
not left stopped or writable unexpectedly, and no temporary ngrok callback is
being presented as the production endpoint.

## 9. AdministratorAccess Removal Preparation

Do not detach `AdministratorAccess` before the complete live integration test.
The current four custom policies and AdministratorAccess remain attached to
`terraform-admin`.

After the integration test and before detaching:

1. Record attached policies and a clean Terraform plan.
2. Simulate the exact APIs used by Terraform and lifecycle scripts: STS,
   EC2/VPC/subnet/route/SG/EIP/NAT, Lambda, EventBridge, CloudWatch Logs, IAM
   role/profile and policy management, restricted `iam:PassRole`, SSM read,
   and KMS decrypt through SSM.
3. Confirm `iam:PassRole` is limited to the cost-guard role.
4. Run a read-only Terraform plan using only the four custom policies.
5. In an approved window, detach only the AWS managed AdministratorAccess
   policy.
6. Immediately repeat identity, plan, NAT status, ECR/OIDC, SSM, Lambda,
   EventBridge, and non-destructive Terraform checks.
7. Keep a documented break-glass recovery identity outside daily automation.

AdminAccess removal is not complete until a full Failover/Failback also works
with the reduced policy set active.

## 10. Deep Freeze Decision Matrix

Do not delete resources during preparation. Back up source, state,
configuration, and test evidence first.

### Preserve for rebuild

- Terraform code and verified state backup;
- Ansible roles, inventory template, and recovery scripts;
- GitHub private Repo, Actions workflow, OIDC provider, and ECR repositories;
- VPC, subnets, routes, SG definitions, IAM policies/roles, S3 backup, and
  SSM parameter;
- encrypted dumps and `.master_status` files;
- Dockerfiles, immutable image tags/digests, and this Runbook; and
- Cloudflare record identifiers and pfSense change records.

### Delete only after explicit plan review

- EC2 instances and attached EBS volumes, if the rebuild procedure is proven;
- obsolete NAT Gateway resources or private default routes, only after a
  reviewed read-only inventory confirms they exist;
- Web EIP, if the final DNS design no longer needs a stable origin address;
- NAT EIP, only after recording that deletion changes the pfSense allowlist.

Deleting the preserved NAT EIP saves its idle public IPv4 cost but invalidates
the fixed `IP_REDACTED/32` rule. Treat it as a deliberate design decision.

## 11. Rebuild One Week Before Demonstration

1. Restore verified Terraform code/state and configure minimum AWS permissions.
2. Run `terraform init`, `fmt`, `validate`, and a reviewed `plan`.
3. Apply VPC, subnets, routes, SGs, IAM roles, S3/SSM, ECR, and EC2.
4. Use the approved Web NAT Instance opt-in path only when package/ECR
   outbound is required.  Do not recreate a NAT Gateway or attach the
   preserved NAT EIP as part of the final test.
5. Run Ansible for Web, Doc/EMR, and DB. Pull immutable ECR tags or digests;
   do not build on the failover path.
6. Restore the encrypted dump if required, then configure and verify Position
   NR using a consistent source coordinate.
7. Confirm Web/EMR/DB health and Cloudflare DNS/SSL behavior.
8. Rehearse Failover and the complete `web_db_failback.sh` path.
9. Delete temporary NAT, stop EC2, re-run the plan, and record the result.

The rebuild is complete only when service responses, database rows, DNS state,
and cost cleanup all agree.

## 12. Final Live E2E Preparation Gate

Run this read-only checker immediately before assembling the live test window.
It writes only an ignored, non-secret JSON evidence file.  It never starts
AWS, changes DNS, sends Slack, changes Terraform state, or invokes a DR
workflow.

```bash
cd /home/cloud/hospital-dr-codex
python3 operations/preflight/final_live_e2e_preflight.py \
  --aux-env-file /home/cloud/grafana/.env \
  --json-output artifacts/preflight/final-live-e2e-preflight.json
```

When the Grafana environment uses Docker-internal hostnames, provide the
controller-side published endpoints explicitly.  The optional local TLS
override below affects only this read-only probe; it does not change Grafana
or Wazuh TLS settings.

```bash
ZABBIX_CONTROLLER_API_URL=http://IP_REDACTED/api_jsonrpc.php \
WAZUH_CONTROLLER_INDEXER_URL=https://IP_REDACTED:9200 \
WAZUH_INDEXER_TLS_SKIP_VERIFY=true \
python3 operations/preflight/final_live_e2e_preflight.py \
  --aux-env-file /home/cloud/grafana/.env \
  --json-output artifacts/preflight/final-live-e2e-preflight.json
```

The command returns non-zero while a blocker remains.  `AWS_STATE=
SUSPENDED_EXPECTED` is not itself a blocker.  The live window must not start
until the summary contains:

```text
SAFE_TO_START_LIVE_E2E=true
DEMO_READY=true
```

The JSON contains check status, blocker codes, team dependencies, commit, UTC
timestamp, and explicit preparation safety fields
(`aws_cost_change=NONE_READ_ONLY_PREFLIGHT`, `aws_instances_started=false`,
`aws_new_resources=false`).  It must never contain a token, password, private
key, certificate key, or raw database evidence.

The lower-level `operations/runtime/final_dr_preflight.sh` is called as a
read-only sub-gate.  Its non-green result is shown as a warning here while the
integrated checker reports the actionable blockers.

## 13. Failover Live Runbook

Only run this section in the approved two-person test window.  A direct shell
invocation before the Slack 2/2 gate is not an accepted test path.

### Pre-failover

| Action | Expected | Pass condition | Evidence |
|---|---|---|---|
| Run final preflight | Full summary | `SAFE_TO_START_LIVE_E2E=true` | JSON file and terminal output |
| Confirm owners | Network, DB, ChatOps, two approvers present | All checklist owners acknowledged | Team checklist |
| Record AWS standby | Three EC2 stopped, no NAT, EIPs preserved | `SUSPENDED_EXPECTED` | AWS read-only output |
| Record DNS baseline | Web and EMR on the on-premise Tunnel/CNAME baseline | Full record metadata matches | Cloudflare GET output |
| Record service baseline | On-premise Web, Doc/EMR, DB healthy | All configured probes pass | Health output |
| Verify NR | Position mode and live IO/SQL status | IO/SQL both `Yes`, no errors | RPO evidence JSON |
| Verify monitoring | Zabbix, Wazuh, Grafana ready | No unresolved required gate | Dashboard/screenshots |

The operator must reserve a unique, non-secret `RUN_ID` before the live run
and ensure that the reviewed incident/ChatOps correlation carries it.  If the
existing Zabbix/ChatOps path generated the run ID from the incident ID, use
that exact recorded value.  Do not call the timeline helper for
`incident_at` before an incident occurs: the incident and Zabbix timestamps
must come from the real event/audit source.  If a manual record is required,
pass the timestamp copied from that source with `--at`; never let the helper
use the current time as a substitute.

### Incident, approval, and execution

1. Use the previously reviewed, non-destructive incident scenario.  Do not
   drop data, reset replication, or stop an unrelated production service.
2. Zabbix creates the Problem and normal Alert.  The production DR action must
   create the Failover approval request.  ChatOps records detection, alert,
   and approval-request timestamps for the same correlation ID.
3. Two distinct administrators approve in Slack.  ChatOps records first and
   second approval timestamps.  No execution is possible at 0/2 or 1/2.
4. After 2/2, the existing ChatOps pipeline launches
   `operations/failover/full_failover.sh`.  Do not run it separately in
   parallel.
5. Record Terraform and Ansible completion only after each real stage returns
   successfully:

```bash
python3 operations/chatops/rto_timeline.py record --run-id "$RUN_ID" --stage terraform_completed_at
python3 operations/chatops/rto_timeline.py record --run-id "$RUN_ID" --stage ansible_completed_at
```

6. The existing workflow records automation start and service recovery.  It
   records DNS/traffic recovery only when DNS was actually changed; a
   `SKIP_DNS=true` rehearsal must not claim traffic recovery.
7. Validate Web, EMR, DB, HTTPS, Docker health, Zabbix, Wazuh, Grafana, and
   the unique read-only/test evidence before declaring success.

### Failover abort conditions

- preflight false or required owner absent;
- NR IO/SQL unhealthy, source coordinates inconsistent, or DB connectivity
  fails;
- missing second approver or approval TTL expiry;
- Terraform/Ansible critical failure;
- Web, EMR, or DB health failure;
- Cloudflare update or post-cutover health failure; or
- any unexpected data mutation.

On abort, keep the known healthy side active, preserve logs/evidence, and let
the existing DNS transaction helper roll back from its fresh snapshot when a
DNS change has already occurred.  Never leave a failed DNS state in place.

## 14. Failback Live Runbook

Failback candidates are created only while `DR_STATE=DR_ACTIVE` and when the
ordinary Zabbix Alert bridge receives one eligible Web/EMR/DB/SNMP Recovery.
There is no additional 300-second request-creation window. Network/SNMP and
Wazuh safety checks are re-evaluated when administrators approve, and the
existing two-person gate remains required.

| Action | Expected | Pass condition | Abort condition |
|---|---|---|---|
| Confirm on-premise Web/Doc/DB | Recovery event and current health evidence | Eligible Recovery received while DR_ACTIVE | DR state inactive or recovery is not an owned health signal |
| Export promoted DB | Read-only validation before export | Dump and checksum/evidence recorded | Export or consistency failure |
| Restore on-premise DB | Explicit approved overwrite | Schema and unique test records match | Import/data mismatch |
| Sync Doc/EMR | Approved one-way DR-to-on-prem sync | Service health and data match | Sync or health failure |
| Request Failback | ChatOps 0/2 | Existing stale/duplicate/DR-active guards pass | Guard rejects or stale event |
| Approve Failback | Two distinct administrators | 2/2 and execution starts | Missing/duplicate/expired approval |
| Restore DNS | Snapshot-backed A-to-original-CNAME | External HTTPS returns on-premise | DNS/health failure |
| Cleanup | Remove temporary NAT and stop EC2 | No NAT, all DR EC2 stopped, EIPs preserved | Cleanup partial failure |

Use the existing complete wrapper, not `full_failback.sh` with DB/Doc steps
silently skipped:

```bash
export RUN_DB_FAILBACK=true
export RUN_DOC_FAILBACK=true
export CLEANUP_NAT_AFTER_FAILBACK=false
export STOP_DR_EC2_AFTER_FAILBACK=true
# The ChatOps Failback 2/2 gate launches the approved workflow.
```

The wrapper must not be started until the two-person approval is complete.
If import, stability, or on-premise health fails, do not change DNS and do not
repeat an overwrite blindly.  If post-failback public health fails, restore
the complete DNS snapshot and preserve the failure evidence.

### Failure rollback matrix

Rollback is operator-controlled and evidence-preserving. No branch below
creates a replacement NAT Gateway or silently retries a destructive step.

| Failure point | Immediate action | Safe rollback/stop condition |
|---|---|---|
| Slack/ChatOps | Keep the request state and audit record; do not create a second request | Cancel/expire only after checking the request ID and execution lock |
| Zabbix Action | Stop at the approval boundary | Use the reviewed read-only configuration snapshot; do not send a manual execution call |
| Terraform plan/apply | Treat any unapproved resource as fail-closed | Do not apply; for an already changed route, use the reviewed route-only rollback plan and never recreate NAT automatically |
| Ansible/service stage | Stop the workflow and preserve logs | Remove only project-owned changes after network route rollback; do not flush Docker/WireGuard chains |
| AWS service health | Keep the known healthy side active | Do not change DNS until all required service probes pass |
| `wg-aws-dr` cutover | Keep `wg-aws-hub` untouched until the new path is proven | `wg-aws-dr` down, restore the legacy route, restart only the legacy peer under the approved operator runbook, then verify connectivity |
| MySQL NR | Do not reset or re-seed replication blindly | Stop, preserve `SHOW MASTER STATUS`, replica status, and logs; leave `DB_NR_ENABLED` unchanged unless acceptance is complete |
| Failback | Do not repeat DB overwrite or Doc sync | Restore the DNS snapshot if changed, keep failure evidence, verify `DR_STATE`/lock, and require a fresh two-person request |

For the dedicated WG cutover, the reversible sequence is explicitly:

```text
legacy wg-aws-hub stop (only in the approved live window)
-> verify the legacy IP_REDACTED route is absent
-> start wg-aws-dr and verify handshake/route/3306
-> on failure: stop wg-aws-dr
-> restore wg-aws-hub and its AWS_PUBLIC_IP_REDACTED route
-> verify the original path
```

This sequence is documentation for the live window only; it was not executed
by the readiness audit.

## 15. RTO and RPO Evidence Capture

`operations/chatops/rto_timeline.py` is the atomic, controller-side RTO
collector.  It accepts the following real stages without manufacturing
missing values:

| Evidence stage | Source |
|---|---|
| `incident_at` | Zabbix event |
| `zabbix_detected_at` | ChatOps/Zabbix correlation |
| `slack_alert_at` | General Alert delivery |
| `failover_approval_created_at` | ChatOps approval request |
| `first_approval_at`, `second_approval_at` | Slack approval actions |
| `failover_started_at`, `automation_started_at` | Approved workflow |
| `terraform_started_at`, `terraform_completed_at` | Real Terraform stage timing |
| `ansible_started_at`, `ansible_completed_at` | Real Ansible stage timing |
| `service_recovered_at` | Service health PASS |
| `dns_traffic_recovered_at` | External traffic/HTTPS PASS |

The target remains `3600` seconds (1 hour). `NOT_MEASURED` is the only valid result
when the required end stage is absent.  RTO 0 is not inferred from a missing
value.

For RPO, prepare a read-only evidence JSON only after Direct NR is actually
configured and verified:

```bash
python3 operations/preflight/rpo_evidence.py \
  --input /secure/operator-only/rpo-evidence.json \
  --output artifacts/preflight/rpo-evidence.json
```

Until `DB_NR_ENABLED=true` and all source/replica coordinates, lag, dump
timestamp, incident timestamp, and last replicated timestamp are present, the
result is `RPO_STATUS=NR_NOT_READY`.  The helper never connects to MySQL,
starts replication, or claims zero data loss.

### Presentation evidence bundle

After the live run has produced its real runtime records, collect a separate
bundle with the exact `RUN_ID` and the incident ID from that run.  The
collector reads the existing timeline, ChatOps state/audit, optional
correlation-scoped timing JSONL, and the operator-supplied read-only RPO JSON.
It does not start a workflow, connect to AWS/MySQL, or modify any source file.

```bash
RUN_ID="<exact-run-id-recorded-by-this-live-run>"
INCIDENT_ID="<actual-zabbix-or-dr-incident-id>"

python3 operations/preflight/rto_rpo_evidence_collector.py \
  --run-id "$RUN_ID" \
  --incident-id "$INCIDENT_ID" \
  --timeline "${DR_RTO_TIMELINE_FILE:-/var/lib/hospital-dr/rto_timeline.json}" \
  --state-db "${CHATOPS_STATE_DB:-/var/lib/hospital-dr/chatops_state.sqlite3}" \
  --audit "${CHATOPS_AUDIT_FILE:-/var/lib/hospital-dr/audit/chatops_audit.jsonl}" \
  --timing-log "${DR_TIMING_FILE:-/var/lib/hospital-dr/dr_timing.jsonl}" \
  --db-nr-enabled "${DB_NR_ENABLED:-false}" \
  --output-root "${DR_EVIDENCE_ROOT:-/var/lib/hospital-dr/evidence}"
```

When `DB_NR_ENABLED=true`, add `--rpo-input` pointing to the read-only RPO
JSON captured during the same run.  Do not create a new run ID after the run;
the supplied IDs must already match the source records.

The command prints only the run/incident IDs, measured RTO, target, status,
RPO status, replication health, and evidence directory.  It writes
`summary.json`, `rto_timeline.json`, `rpo_evidence.json`, and a SHA-256
`evidence_manifest.txt` under a new run-specific directory.  Existing run
directories are never overwritten.  If `DB_NR_ENABLED=false`, the bundle
deliberately reports `RPO_STATUS=NOT_MEASURABLE`.  Missing events remain
`NOT_MEASURED`; timestamps are never estimated.

## 16. Evidence Capture Checklist

### Before

- [ ] Final preflight JSON and commit recorded
- [ ] Zabbix healthy state
- [ ] Grafana DR/Security/DevSecOps dashboards
- [ ] Router SNMP live (`IP_REDACTED:161`) and Zabbix SNMP availability
- [ ] Catalyst 2950/3560/3550 SNMP live and Grafana Network Devices panel
- [ ] A current required SNMP availability failure can create a candidate;
      unrelated SNMP warnings remain general-alert-only
- [ ] On-premise Web/Doc/DB health
- [ ] AWS stopped standby state, preserved EIPs, no NAT
- [ ] DNS CNAME/Tunnel baseline
- [ ] NR status and backup/master-status evidence

### Incident and approval

- [ ] Zabbix Problem event ID/time
- [ ] General Alert message timestamp
- [ ] Wazuh event if security-related
- [ ] Failover 0/2, 1/2, 2/2 timestamps
- [ ] Distinct approver identities recorded without tokens

### Failover and recovery

- [ ] Automation start and stage results
- [ ] AWS instance/NAT state
- [ ] Web/EMR/DB health
- [ ] External HTTPS and DNS result
- [ ] Grafana RTO/RPO panels
- [ ] Zabbix AWS and Wazuh AWS evidence
- [ ] XDR/security evidence

### Failback and final state

- [ ] Eligible Recovery event while `DR_ACTIVE`
- [ ] DB export/import and unique test-record validation
- [ ] Failback 0/2, 1/2, 2/2
- [ ] A-to-original-CNAME restoration
- [ ] On-premise external HTTPS
- [ ] AWS EC2 stopped and NAT absent
- [ ] EIPs preserved, no unexpected resource
- [ ] Final RTO/RPO classification, commit, and CI result

## 17. Team Dependency Checklist

| Owner | Required before | Pass condition |
|---|---|---|
| Network team | Windows WireGuard and physical monitoring path review | On-prem WG/SNMP path verified; AWS-to-MSP Agent inbound ports are disabled by design because MSP is behind uncontrolled upstream NAT |
| DB team | NR window | `wg-aws-dr` peer/route, listener, observed-source allowlist for `repl1`, matching backup/master-status |
| ChatOps owner | Live approval window | Two distinct approvers and correct Alert/Approval channels |
| Live DR operators | Test start | Two-person approval, incident operator, evidence capture owner |
| MSP security/operator | AWS security validation | Wazuh AWS enrollment and Indexer write/read contracts verified |

No team dependency may be bypassed by opening `IP_REDACTED/0`, changing WireGuard,
rotating credentials, disabling guards, or starting a second monitoring stack.

## 18. Final Demo Readiness Decision

The integrated checker exposes these decision fields:

```text
CODE_READY
MONITORING_CONFIG_READY
SECURITY_CONFIG_READY
AWS_CONFIG_READY
NETWORK_READY
DIRECT_NR_READY
TWO_APPROVERS_READY
EVIDENCE_READY
DEMO_READY
```

The current expected result is `DEMO_READY=false` while the On-Prem Web path,
Zabbix Failback runtime, fixed Slack endpoint, runtime drift, egress workflow,
SNMP, and Direct NR/WG acceptance gates are unresolved. AWS external Agent
ingress remains disabled by design because MSP is behind uncontrolled upstream
NAT; that environment limitation is not a reason to reopen inbound ports.
This is a correct fail-closed result, not a reason to start AWS or weaken a
guard.
