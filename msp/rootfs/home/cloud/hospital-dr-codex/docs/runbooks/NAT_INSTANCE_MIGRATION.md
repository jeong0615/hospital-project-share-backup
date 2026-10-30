# Web NAT Instance migration and blackhole recovery

The existing AWS Web instance can act as a routed NAT Instance because it is
in the public subnet, has the preserved Web EIP, and already has
`source_dest_check=false`. This is an explicit, reviewed operation. It is not
enabled by default:

```text
private_egress_mode=nat_gateway
AWS_WEB_NAT_INSTANCE_ENABLED=false
```

The current AWS audit found the following state:

```text
NAT_GATEWAY_STATE=NOT_FOUND
PRIVATE_DEFAULT_ROUTE_STATE=blackhole
```

Therefore the current operation is **BLACKHOLE_RECOVERY**, not a migration away
from a working NAT Gateway. The recovery path must not recreate a NAT Gateway
or reattach the reserved `AWS_PUBLIC_IP_REDACTED` EIP.

## Supported starting states

### A. Existing NAT Gateway migration

Use this only when the existing NAT Gateway is `available` and the private
default route is `active` toward that NAT Gateway. The route can then be
changed to the approved Web ENI while the NAT Gateway and EIP remain intact.

```text
enable_nat_gateway=true
private_egress_mode=web_nat_instance
aws_web_nat_instance_enabled=true
```

### B. BLACKHOLE direct recovery

Use this when the NAT Gateway is `NOT_FOUND` and the private default route is
`blackhole`. Do not run the NAT enable lifecycle and do not set
`enable_nat_gateway=true`:

```text
enable_nat_gateway=false
private_egress_mode=web_nat_instance
aws_web_nat_instance_enabled=true
```

This plan is allowed to repair only the private `IP_REDACTED/0` route to
`AWS_RESOURCE_ID_REDACTED`. The plan guard rejects NAT Gateway creation,
recreation, destruction, EIP changes, EC2 changes, and all unrelated changes.

## Safety contract

- Operational Terraform state is only `/home/cloud/hospital-dr-terraform`.
- `infra/terraform` in the Git checkout is source, never operational state.
- `private_egress_mode=web_nat_instance` requires
  `aws_web_nat_instance_enabled=true` and the approved VPC, Web instance,
  Web private IP, Web EIP, and private route table.
- In BLACKHOLE_RECOVERY mode, `enable_nat_gateway=false` is the operator
  contract. A stale managed NAT resource would produce a destroy plan; the
  plan guard rejects that plan rather than applying it.
- The plan guard accepts only the approved private route change, or an
  explicitly requested no-egress rollback from the approved Web route.
- The reserved NAT EIP allocation is read-only during this procedure. It is
  not released, reassociated, or used as a reason to create a NAT Gateway.
- The Ansible role owns only `HOSPITAL-DR-NAT-FWD` and
  `HOSPITAL-DR-NAT-POSTROUTING`. It never flushes the global firewall and does
  not edit Docker or `wg-aws-dr` chains.
- MASQUERADE is limited to private-subnet Internet egress. It excludes
  `AWS_PUBLIC_IP_REDACTED/16`, `AWS_PUBLIC_IP_REDACTED/24`, and `AWS_PUBLIC_IP_REDACTED/24`, so the routed AWS
  DR WireGuard/NR path is not translated.

## Read-only preflight

From the canonical checkout:

```bash
cd /home/cloud/hospital-dr-codex
AWS_REGION=ap-northeast-2 operations/nat_instance/web_nat_instance_status.sh
```

For BLACKHOLE_RECOVERY, the required preconditions are:

```text
WEB_INSTANCE_STATE=running
SOURCE_DEST_CHECK=False
NAT_GATEWAY_STATE=NOT_FOUND
PRIVATE_DEFAULT_ROUTE_STATE=blackhole
NAT_EIP_STATE=ALLOCATED_UNASSOCIATED or ALLOCATED_ASSOCIATED
NAT_INSTANCE_STATUS=READY_FOR_BLACKHOLE_RECOVERY
```

The current stopped Web host is intentionally **not** ready for the live
operation. The status script must report `NOT_READY` until Web is running.

For the Web host itself, after an approved access path is available:

```bash
sudo /home/cloud/hospital-dr-codex/operations/nat_instance/web_nat_instance_status.sh --local
```

The local check is read-only. It reports `ip_forward`, the iptables backend,
the two project-owned chains, the `wg-aws-dr` interface, and the 10.251 route.

## BLACKHOLE_RECOVERY live sequence

This sequence is documentation for a future approved live window. It was not
executed while preparing this change.

### Step 1 — Web running

Confirm the existing Web instance is running and its public subnet, IGW route,
EIP, ENI, and source/destination check match the approved contract. Do not
start unrelated EC2 instances.

### Step 2 — Ansible check mode

```bash
cd /home/cloud/hospital-dr-codex
AWS_WEB_NAT_INSTANCE_ENABLED=true \
  ansible-playbook -i /home/cloud/hospital-dr-ansible/inventory.ini \
  automation/ansible/aws_web_nat_instance.yml \
  -e aws_web_nat_instance_enabled=true \
  -e aws_web_nat_instance_action=apply \
  --check --diff
```

The check must show only the explicit Web NAT role prerequisites. It must not
touch `wg0`, Docker chains, EC2 lifecycle, or any On-Prem host.

### Step 3 — Apply only the Web NAT role

After reviewing Step 2 in the approved window, repeat the same command without
`--check --diff`. This enables forwarding and the project-owned chains only.

### Step 4 — Verify Web locally

```bash
sudo /home/cloud/hospital-dr-codex/operations/nat_instance/web_nat_instance_status.sh --local
wg show wg-aws-dr
```

Confirm `ip_forward=1`, both project chains are present, Web Internet health is
normal, and the existing WireGuard handshake/routes remain healthy.

### Step 5 — Prepare the BLACKHOLE route plan

Use the operational state directory and explicitly disable NAT Gateway
management for this recovery plan:

```bash
cd /home/cloud/hospital-dr-terraform
terraform plan -input=false \
  -var="enable_nat_gateway=false" \
  -var="private_egress_mode=web_nat_instance" \
  -var="aws_web_nat_instance_enabled=true" \
  -out=/tmp/hospital-dr-web-nat-blackhole-recovery.tfplan

/home/cloud/hospital-dr-codex/operations/nat_instance/web_nat_instance_plan_guard.sh \
  /tmp/hospital-dr-web-nat-blackhole-recovery.tfplan
```

Expected guard output:

```text
NAT_INSTANCE_PLAN=PASS
ROUTE_MODE=WEB_NAT_INSTANCE
NAT_GATEWAY_CREATE_PLANNED=NO
NAT_GATEWAY_RECREATE_PLANNED=NO
NAT_GATEWAY_DESTROY=NO
NAT_EIP_DESTROY=NO
NAT_EIP_ALLOCATION_CHANGE=NO
EC2_REPLACEMENT=NO
WEB_EIP_REPLACEMENT=NO
```

Any NAT Gateway create/destroy/recreate, EIP change, EC2 replacement, or
unrelated resource change is a hard failure. Do not apply that plan.

### Step 6 — Apply only the approved route plan

Only after the guard passes:

```bash
terraform apply -input=false /tmp/hospital-dr-web-nat-blackhole-recovery.tfplan
```

This changes the private `AWS_PUBLIC_IP_REDACTED/0` route from the blackholed NAT target to
`AWS_RESOURCE_ID_REDACTED`. It does not create a NAT Gateway or alter the NAT EIP.

### Step 7 — Validate private egress

From DB and EMR, validate only the required runtime paths:

- DNS resolution
- TCP/443 outbound
- S3 access if required
- SSM health
- application dependency checks
- WireGuard/NR path and `IP_REDACTED -> IP_REDACTED:3306`

Do not change MySQL replication during this validation.

### Step 8 — Observe and report

Report:

```text
CURRENT_EGRESS_MODE=WEB_NAT_INSTANCE
NAT_INSTANCE_STATUS=READY
NAT_GATEWAY_CREATE=NOT_PERFORMED
NAT_EIP_RELEASE=NOT_PERFORMED
```

NAT Gateway retirement is not part of this recovery operation.

## Rollback and failure handling

There is no healthy NAT Gateway rollback target in the current state. Never
recreate one automatically.

- If the route plan fails before apply, the existing `blackhole` route remains
  unchanged.
- If the Web route is applied but validation fails, keep the Web route for
  diagnosis or explicitly return to **no egress**. Do not switch to a newly
  created NAT Gateway.
- After a no-egress rollback, remove the Web NAT rules with the explicit
  disable playbook. The shared `ip_forward=1` sysctl remains because the
  existing `wg-aws-dr` gateway also requires forwarding.

### Explicit no-egress rollback

```bash
cd /home/cloud/hospital-dr-terraform
terraform plan -input=false \
  -var="enable_nat_gateway=false" \
  -var="private_egress_mode=none" \
  -var="aws_web_nat_instance_enabled=true" \
  -out=/tmp/hospital-dr-web-nat-no-egress.tfplan

/home/cloud/hospital-dr-codex/operations/nat_instance/web_nat_instance_plan_guard.sh \
  /tmp/hospital-dr-web-nat-no-egress.tfplan --allow-none-egress

terraform apply -input=false /tmp/hospital-dr-web-nat-no-egress.tfplan
```

Then, only after the route is confirmed removed:

```bash
cd /home/cloud/hospital-dr-codex
ansible-playbook -i /home/cloud/hospital-dr-ansible/inventory.ini \
  automation/ansible/aws_web_nat_instance_disable.yml
```

The no-egress rollback is still a route mutation and must be performed only in
an approved live window. It never creates/deletes a NAT Gateway or releases an
EIP.

## Cost comparison method

Use the AWS Pricing Calculator/current EC2 and VPC pricing pages for the
account's region at decision time; prices are intentionally not hardcoded in
source.

| Option | Incremental cost model | Operational trade-off |
| --- | --- | --- |
| Current NAT Gateway | NAT Gateway hourly + per-GB processing; preserved EIP association | Managed and independent of Web health |
| Existing Web as NAT Instance | No new EC2/EIP line item because Web/EIP/WireGuard already exist; account for traffic/CPU impact | Web becomes an egress dependency; Docker/WireGuard/firewall isolation is required |
| Separate NAT Instance | EC2 hourly + EBS + public IPv4 and traffic | Independent failure domain but additional host, patching, and lifecycle cost |

No NAT Gateway creation, deletion, EIP release, route mutation, EC2 restart,
SG live apply, or WireGuard restart was performed while preparing this code.
