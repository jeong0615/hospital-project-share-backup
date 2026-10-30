# Final DR Integration Runbook and Deep Freeze Plan

This runbook is for the final Hospital DR test window. Do not run the live
integration steps while the environment is frozen.

## Scope and Rules

- AWS region: `ap-northeast-2`
- NR mode: MySQL position-based replication
- On-premise DB endpoint: `AWS_PUBLIC_IP_REDACTED:3306`
- AWS NAT egress allowlist: `AWS_PUBLIC_IP_REDACTED/32`
- AWS has no WireGuard role in the final design.
- WireGuard is only On-Premise <-> MSP communication.
- Do not use `full_failback.sh` alone for the final test. It skips DB and Doc
  failback unless the matching environment variables are set.
- Judge success by service responses and matching data, not by log lines alone.
- Never print secret values, dump contents, tokens, or private keys.

The commands below use the current operational paths. The GitHub staging Repo
is the source and documentation copy; it is not the live execution directory.

## 1. Preflight Without Starting AWS

These checks do not start EC2 or NAT resources.

```bash
cd /home/cloud/hospital-dr-terraform
terraform fmt -check
terraform validate

for script in \
  full_failover.sh full_failback.sh web_db_failback.sh \
  db_failback_to_onprem.sh doc_failback_sync.sh run_demo.sh \
  failback.sh nat_gateway_control.sh dr_environment_control.sh; do
  bash -n "$script"
done

ANSIBLE_CONFIG=/home/cloud/hospital-dr-ansible/ansible.cfg \
ansible-playbook \
  -i /home/cloud/hospital-dr-ansible/inventory.ini \
  /home/cloud/hospital-dr-ansible/site.yml \
  --syntax-check

nat_gateway_control.sh status
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
line. `AWS_PUBLIC_IP_REDACTED` is the AWS NAT source address for the on-premise
firewall, not `DB_SOURCE_HOST`.

## 2. On-Premise and pfSense Gate

Before the AWS test window:

1. Confirm that the on-premise DB listens on TCP 3306.
2. Confirm pfSense forwards the public DB endpoint to the on-premise DB.
3. Allow only `IP_REDACTED/32` to the forwarded TCP 3306 service.
4. Confirm the MySQL `repl` account is allowed from the effective source.
5. Record `SHOW MASTER STATUS\G` immediately before the NR test.
6. Confirm the MSP management path separately from the AWS DB path.

After the AWS DR DB is running, the first live network gate is:

```bash
nc -vz -w 5 IP_REDACTED 3306
```

If it fails, stop. Do not open the AWS Security Group to `AWS_PUBLIC_IP_REDACTED/0`.
Check the NAT route, NAT EIP, pfSense rule/port forward, and MySQL listener.

## 3. Practical Test Order

The conceptual gate is `NR -> Failover -> service/data test -> Failback`.
The current topology has a practical constraint: private DR DB SSH is reached
through the DR Web bastion. Therefore the bastion must be available before an
Ansible-based NR check can run.

Use this operational order:

1. Complete the on-premise and pfSense gate.
2. Start the approved AWS test window and run the full failover workflow.
3. As soon as the DR DB and bastion are reachable, run the NR TCP and status
   gates before declaring failover successful.
4. Verify Web, EMR, and DB health.
5. Generate unique test data and verify it on the promoted DR DB.
6. Run the complete DB/Doc/Web failback workflow.
7. Verify the same data on the on-premise DB and services.
8. Restore DNS, remove NAT, stop EC2, and verify Terraform is clean.

This keeps NR as a failover acceptance gate without pretending that an
unreachable private DB can be checked through Ansible before its bastion is
started.

## 4. Failover and NR Acceptance

Load secrets, set the non-secret test configuration, and run the existing
ChatOps-approved or direct operational entry point. Do not run both paths at
the same time.

```bash
cd /home/cloud/hospital-dr-terraform
source /home/cloud/hospital-dr-secrets/dr.env
export DB_NR_ENABLED=true
export DB_REPL_MODE=position
export DB_SOURCE_HOST=IP_REDACTED
export DB_SOURCE_PORT=3306
export DB_PROMOTE_ON_FAILOVER=true

./full_failover.sh
```

`full_failover.sh` starts the existing three-instance environment when all
instances exist, or delegates to `run_demo.sh` when the set is incomplete.
It enables NAT as needed, configures services, updates Cloudflare, and runs
origin health checks.

NR is accepted only when:

- DR DB to `IP_REDACTED:3306` succeeds;
- `DB_REPL_MODE=position` was explicitly set;
- `Replica_IO_Running=Yes` and `Replica_SQL_Running=Yes` (or legacy
  `Slave_*` equivalents) are reported;
- replication lag is acceptable for the test;
- source file and position are the expected coordinates; and
- a unique source test row is visible on the DR replica before promotion,
  when testing live replication itself.

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
export CLEANUP_NAT_AFTER_FAILBACK=true
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
4. `nat_gateway_control.sh cleanup`: removes the temporary NAT Gateway and
   private default route while preserving the tagged NAT EIP; and
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
./nat_gateway_control.sh status

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
- temporary NAT Gateway and private default route;
- Web EIP, if the final DNS design no longer needs a stable origin address;
- NAT EIP, only after recording that deletion changes the pfSense allowlist.

Deleting the preserved NAT EIP saves its idle public IPv4 cost but invalidates
the fixed `IP_REDACTED/32` rule. Treat it as a deliberate design decision.

## 11. Rebuild One Week Before Demonstration

1. Restore verified Terraform code/state and configure minimum AWS permissions.
2. Run `terraform init`, `fmt`, `validate`, and a reviewed `plan`.
3. Apply VPC, subnets, routes, SGs, IAM roles, S3/SSM, ECR, and EC2.
4. Enable NAT only for package/ECR pull, record its EIP, and update pfSense.
5. Run Ansible for Web, Doc/EMR, and DB. Pull immutable ECR tags or digests;
   do not build on the failover path.
6. Restore the encrypted dump if required, then configure and verify Position
   NR using a consistent source coordinate.
7. Confirm Web/EMR/DB health and Cloudflare DNS/SSL behavior.
8. Rehearse Failover and the complete `web_db_failback.sh` path.
9. Delete temporary NAT, stop EC2, re-run the plan, and record the result.

The rebuild is complete only when service responses, database rows, DNS state,
and cost cleanup all agree.
