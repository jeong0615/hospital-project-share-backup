# Synthetic HTTPS Probe (separate state/VPC)

This is a dedicated, synthetic-only HTTPS echo service. It is a separate local
Terraform root and workspace from both `synthetic_nat_canary` and production.
There is no backend, remote-state lookup, VPC peering, or route to another
VPC. Terraform does not manage public DNS. The deployment contract uses the
DNS-only A record `nat-probe.hospital-web.pp.ua` pointing to the Probe EIP;
Cloudflare proxying must be off. Default `enable_probe=false` plans no managed
resources. No AWS resource or DNS record was created by this implementation.
The Probe instance waits for its inline role policy, SSM endpoints, and DNS
Firewall association before bootstrapping.

The stack contains one new VPC and one public subnet, one IGW/default route,
one AL2023 `t3.micro` with an encrypted 8-GiB gp3 delete-on-termination root
volume, one EIP, and two single-AZ SSM interface endpoints (`ssm` and
`ssmmessages`). The instance uses IMDSv2. Its SG has no default ingress or
egress: while `allowed_web_eip_ipv4=DISABLED`, it has no ingress rules; after
the other stack returns its Web EIP, it gets one TCP/443 `/32` ingress rule.
Instance egress is only TCP/443 to the two endpoint SGs. A custom subnet NACL
allows only that SSM flow and the exact HTTPS request/return flow. The probe
application separately rejects any source address other than the same exact
Web EIP. No application, DB, ECR, tunnel, SSH key, or operational credential is
included.

The SSM instance role only supports the SSM Agent channel and `GetParameter`
on the Run-ID-specific certificate, key, and source-address parameters; KMS
decrypt is limited to the existing supplied CMK, SSM service, and the two TLS
parameter encryption contexts. The customer-managed KMS key must already
exist, and its key policy must allow the account's IAM role permissions to
take effect. Terraform checks the CMK ARN account/region and key
state/manager/usage/spec without changing the key. The live preflight checks
the instance profile, exact role trust and inline-policy set, absence of
attached managed policies, and exact inline policy. It also performs an SSM
command that requests both SecureString parameters with decryption while
directing values and errors to `/dev/null`; only command status is returned.
This exercises the instance role and key policy. No KMS key is created.

The Probe VPC has its own Route 53 Resolver DNS Firewall association; no other
VPC is associated by this stack. Its allow rule contains only
`ssm.ap-northeast-2.amazonaws.com` and
`ssmmessages.ap-northeast-2.amazonaws.com`; a higher-numbered-priority
catch-all rule returns NXDOMAIN after the allow rule. VPC
`FirewallFailOpen` is `DISABLED`, so filtering fails closed. The live preflight
reads back config, association, rules, and domain lists, then checks that both
SSM names resolve to their endpoint ENI addresses and an external test name
does not resolve. AmazonProvidedDNS itself remains reachable despite SG/NACL
rules; the VPC-only Firewall association filters those Resolver queries.
Direct external DNS and DoH remain blocked by the exact SG/NACL egress
allowlist. The Canary's DNS Firewall is independent.

The HTTPS body at `/v1/source-ip` is exactly the observed TCP peer address in
JSON. It does not log requests. The guest verifies certificate hostname,
minimum seven-day remaining validity, key match, and protected file modes at
startup/self-check; the Canary client validates the public trust chain and
hostname with its system CA store (without a TLS-verification bypass). HTTPS is
TLS 1.2 minimum. The network firewall contract is
the exact AWS SG plus the application peer-IP allowlist; this stack does not
claim a separate host firewall. HTTPS content sent to the approved Canary EIP
is not constrained by a security group; the dedicated Probe service and
hostname only serve the synthetic egress-IP response.

## Public DNS and certificate prerequisites — not yet applied

The selected hostname is `nat-probe.hospital-web.pp.ua`. Before Probe EC2
bootstrap, issue a trusted Let's Encrypt certificate for exactly that name via
DNS-01. Create only the temporary `_acme-challenge.nat-probe.hospital-web.pp.ua`
TXT validation record; remove it and verify removal after issuance. This can
happen before the Probe EIP exists. No ACME automation or DNS API credential is
added to either EC2 or Terraform.

After the Probe stack returns its EIP, create a DNS-only A record for
`nat-probe.hospital-web.pp.ua` with that exact IPv4 and Cloudflare Proxy
disabled. The Canary guest's DNS Firewall test uses `getent` and requires this
A record to resolve to the Probe EIP. The Canary HTTPS request still uses
`curl --resolve` to pin the TCP destination while retaining the hostname for
SNI and CA validation. No AAAA record is used. No TXT/A record or certificate
was created here. DNS-01 ownership validation is described by [Let's
Encrypt](https://letsencrypt.org/docs/challenge-types/).

Issue the certificate off-instance with a trusted ACME client and protect the
local key directory. Put `fullchain.pem` and the unencrypted PEM private key
into two Advanced `SecureString` parameters named exactly for the Run ID:

```bash
aws ssm put-parameter --region ap-northeast-2 \
  --name "/hospital-dr/synthetic-nat-probe/${PROBE_RUN_ID}/fullchain" \
  --type SecureString --tier Advanced --key-id "$EXISTING_KMS_KEY_ARN" \
  --value "file://$TLS_DIR/fullchain.pem" --no-cli-pager >/dev/null
aws ssm put-parameter --region ap-northeast-2 \
  --name "/hospital-dr/synthetic-nat-probe/${PROBE_RUN_ID}/privkey" \
  --type SecureString --tier Advanced --key-id "$EXISTING_KMS_KEY_ARN" \
  --value "file://$TLS_DIR/privkey.pem" --no-cli-pager >/dev/null
```

Omit `--overwrite`; an existing Run-ID parameter is a collision and must be
investigated. Never put certificate contents in `.tfvars`, Terraform state,
user-data, process arguments, shell history, or logs. Terraform/user-data carry
only parameter names. Confirm parameter names, types, key ARN and KMS key
policy by metadata-only read; do not request/decrypt values. On teardown,
delete these two external parameters only after the instance and role are
destroyed.

## Two-stack deployment order (separate approval required)

Both stacks must use the same explicit account and Seoul Region, but distinct
Run IDs, unique non-overlapping CIDRs, and separate local Terraform state.
Choose and inspect CIDRs against *all* current VPCs. Do not use a production
workspace or production state.

Before first apply, `--inventory-run-id` for each selected Run ID must return
zero resources. The Probe overlap expression excludes its own already-created
VPC by the exact `ProbeRunId` tag on subsequent variable-only updates; a prior
resource collision with that Run ID must be resolved before any plan.

Use explicit, distinct Run IDs, and do not use `-auto-approve`. These are
commands for a future separately approved window; they were not run here.

```bash
export PROBE_RUN_ID='probe-replace-me'   # replace with a fresh unique Run ID
export CANARY_RUN_ID='canary-replace-me' # replace with a different fresh Run ID
export PROBE_TFVARS='/secure/operator/path/probe.tfvars'
export CANARY_TFVARS='/secure/operator/path/canary.tfvars'

terraform -chdir=infra/terraform/synthetic_nat_probe init -backend=false -input=false
terraform -chdir=infra/terraform/synthetic_nat_canary init -backend=false -input=false
python3 operations/demo/synthetic_nat_probe.py --inventory-run-id --run-id "$PROBE_RUN_ID"
python3 operations/demo/synthetic_nat_canary.py --inventory-run-id --run-id "$CANARY_RUN_ID"
```

Both inventories must be empty before creating either workspace. Populate the
Probe tfvars with the explicitly reviewed account, non-overlapping CIDRs, AZ,
pinned AMI, exact controlled FQDN, existing same-account CMK, and Run-ID-scoped certificate parameter
names. Keep the Web source disabled for the initial plan:

```bash
terraform -chdir=infra/terraform/synthetic_nat_probe workspace new "$PROBE_RUN_ID"
terraform -chdir=infra/terraform/synthetic_nat_probe plan \
  -var-file="$PROBE_TFVARS" -out="$PROBE_RUN_ID-stage1.tfplan"
terraform -chdir=infra/terraform/synthetic_nat_probe show -no-color "$PROBE_RUN_ID-stage1.tfplan"
# Review account, Run ID, exact resource actions, and absence of HTTPS ingress before proceeding.
terraform -chdir=infra/terraform/synthetic_nat_probe apply "$PROBE_RUN_ID-stage1.tfplan"
terraform -chdir=infra/terraform/synthetic_nat_probe output -json
```

After the Probe EIP is returned, publish the DNS-only A record described above
and confirm it resolves to that EIP before starting the Canary stack. Use the
resulting Probe IPv4 and FQDN in the Canary tfvars; the Canary Run ID must
differ. Create/review/apply its separate workspace and plan. After it
returns the Web EIP, set only the Probe `allowed_web_eip_ipv4` to that exact
`Web-EIP/32`, then review the variable-only Probe plan:

```bash
terraform -chdir=infra/terraform/synthetic_nat_probe plan \
  -var-file="$PROBE_TFVARS" -out="$PROBE_RUN_ID-stage2.tfplan"
terraform -chdir=infra/terraform/synthetic_nat_probe show -no-color "$PROBE_RUN_ID-stage2.tfplan"
# Expected delta: one SG ingress rule and two matching NACL rules plus source-parameter update.
terraform -chdir=infra/terraform/synthetic_nat_probe apply "$PROBE_RUN_ID-stage2.tfplan"
python3 operations/demo/synthetic_nat_probe.py --aws-read-only --run-id "$PROBE_RUN_ID"
python3 operations/demo/synthetic_nat_probe.py --verify-link \
  --run-id "$PROBE_RUN_ID" --canary-run-id "$CANARY_RUN_ID"
python3 operations/demo/synthetic_nat_canary.py --aws-read-only \
  --run-id "$CANARY_RUN_ID" --region ap-northeast-2
```

Do not continue if either inventory is non-empty before creation, a plan touches
resources outside the dedicated stack, the TLS cert is not trusted/valid, or
the live/cross-stack checks are not PASS.

The isolated Canary stack uses its own workspace and reviewed plan:

```bash
terraform -chdir=infra/terraform/synthetic_nat_canary workspace new "$CANARY_RUN_ID"
terraform -chdir=infra/terraform/synthetic_nat_canary plan \
  -var-file="$CANARY_TFVARS" -out="$CANARY_RUN_ID.tfplan"
terraform -chdir=infra/terraform/synthetic_nat_canary show -no-color "$CANARY_RUN_ID.tfplan"
# Apply only after confirming the account, unique Run ID/CIDRs, and synthetic-only resources.
terraform -chdir=infra/terraform/synthetic_nat_canary apply "$CANARY_RUN_ID.tfplan"
```

1. Prepare and review Probe `*.tfvars` with `enable_probe=true`, exact
   `CREATE_SYNTHETIC_NAT_PROBE`, verified FQDN, pinned Amazon-owned AL2023 AMI,
   existing KMS ARN, and `allowed_web_eip_ipv4="DISABLED"`. Verify the two
   SecureString parameters exist without printing values. `plan` must show no
   HTTPS ingress rule. Review exact resource actions, then apply the reviewed
   plan. Apply starts the one probe instance; there is no public HTTPS ingress
   yet. Read `probe_eip` and `probe_domain` from Terraform outputs.
2. Configure the existing Synthetic NAT Canary stack with that exact Probe
   IPv4/domain. Review and apply its separate state. It returns its Web EIP.
3. Set Probe `allowed_web_eip_ipv4="<Canary-Web-EIP>/32"`. Review a plan that
   adds exactly one HTTPS ingress and the matching NACL source/return rules,
   and updates the Run-ID-scoped non-secret source parameter. Apply that plan.
4. Refresh the guest source allowlist through SSM (read-only verification is
   not enough to change guest configuration):

   ```bash
   aws ssm send-command --region ap-northeast-2 \
     --instance-ids "$PROBE_INSTANCE_ID" --document-name AWS-RunShellScript \
     --parameters 'commands=["/usr/local/sbin/hospital-dr-synthetic-probe-refresh"]' \
     --timeout-seconds 30 --query 'Command.CommandId' --output text --no-cli-pager
   ```

   Poll `get-command-invocation` until terminal success; do not print command
   output except its non-secret status. The helper fetches the plain source IP
   from SSM, atomically replaces the guest allowlist, and starts the service.
5. Run Probe live preflight and cross-stack checks, then run Canary preflight.
   Canary `--run` now requires `--probe-run-id` and independently checks account,
   region, Probe IP/domain and `Web EIP/32` against both workspaces before it
   starts the synthetic transaction. The Canary's HTTPS client verifies the
   public trust chain and hostname while confirming the response IP is its
   actual egress IP.

After a separate execution approval, use the existing Canary Runner transaction
and its exact Run-ID confirmation. For an interrupted transaction, restore
before cleanup; never destroy if ownership or guest restoration is unverified:

```bash
python3 operations/demo/synthetic_nat_canary.py --run \
  --run-id "$CANARY_RUN_ID" --probe-run-id "$PROBE_RUN_ID" \
  --confirm-run-id "$CANARY_RUN_ID" --confirm-synthetic-network-cost \
  --region ap-northeast-2
python3 operations/demo/synthetic_nat_canary.py --restore \
  --run-id "$CANARY_RUN_ID" --confirm-run-id "$CANARY_RUN_ID" \
  --region ap-northeast-2
python3 operations/demo/synthetic_nat_canary.py --cleanup \
  --run-id "$CANARY_RUN_ID" --confirm-run-id "$CANARY_RUN_ID" \
  --region ap-northeast-2
```

The Probe A record is public DNS, DNS-only, and resolves to the Probe EIP; the
SG/NACL still allow HTTPS ingress only from the linked Canary Web EIP `/32`.
Remove the A record before releasing the Probe EIP during cleanup. The endpoint
reports no data other than the caller's observed synthetic egress IPv4.

## Read-only checks and partial-failure recovery

```bash
python3 operations/demo/synthetic_nat_probe.py --aws-read-only --run-id "$PROBE_RUN_ID"
python3 operations/demo/synthetic_nat_probe.py --verify-link \
  --run-id "$PROBE_RUN_ID" --canary-run-id "$CANARY_RUN_ID"
python3 operations/demo/synthetic_nat_probe.py --inventory-run-id --run-id "$PROBE_RUN_ID"
```

The live preflight checks the exact AWS account, instance/EIP association, SG
rules, SSM endpoints and route, SSM Online state, exact instance profile/role
trust/inline permissions, KMS metadata and a no-output SecureString decrypt,
Probe-VPC DNS Firewall fail-closed association/rules, and a read-only guest
self-check of private SSM DNS answers, blocked external DNS, service/listener,
TLS hostname/expiry/key match, file modes, and application source allowlist. It
uses SSM Run Command; AWS records that read-only invocation. It will BLOCK if
the source is still `DISABLED`, TLS/service is absent, SSM is offline, DNS
Firewall differs or private endpoint DNS fails, the external test name
resolves, or any IAM/KMS/network rule differs.

On a normal teardown, first restore/complete the Canary runner so its guests are
stopped and the Canary VPC/EIP are destroyed. Then remove Probe ingress by
planning/applying the Probe state with `allowed_web_eip_ipv4="DISABLED"` and
verify the source parameter/readback. Remove the DNS-only A record and verify
its absence before releasing the Probe EIP. Finally destroy the Probe state.
The Terraform dependency graph removes the DNS Firewall association before its
rules/domain lists/VPC configuration. Review a saved destroy plan before apply:

```bash
terraform -chdir=infra/terraform/synthetic_nat_probe workspace select "$PROBE_RUN_ID"
terraform -chdir=infra/terraform/synthetic_nat_probe plan -destroy \
  -var-file="$PROBE_TFVARS" -out="$PROBE_RUN_ID-destroy.tfplan"
terraform -chdir=infra/terraform/synthetic_nat_probe show -no-color "$PROBE_RUN_ID-destroy.tfplan"
# Only after verifying account, workspace, Run-ID tags and the complete target list:
terraform -chdir=infra/terraform/synthetic_nat_probe apply "$PROBE_RUN_ID-destroy.tfplan"
terraform -chdir=infra/terraform/synthetic_nat_probe workspace select default
terraform -chdir=infra/terraform/synthetic_nat_probe workspace delete "$PROBE_RUN_ID"
aws ssm delete-parameters --region ap-northeast-2 \
  --names "/hospital-dr/synthetic-nat-probe/${PROBE_RUN_ID}/fullchain" \
         "/hospital-dr/synthetic-nat-probe/${PROBE_RUN_ID}/privkey" \
  --no-cli-pager >/dev/null
python3 operations/demo/synthetic_nat_probe.py --inventory-run-id --run-id "$PROBE_RUN_ID"
```

If the Terraform state is missing, inventory by `ProbeRunId` first. Do not run
a broad tag-based delete: review the exact VPC, EIP, instance/volume, endpoint
and ENI identities and recover/import the single dedicated Probe state before
destroy. VPC, EBS, EIP, endpoints, IAM and SecureString remnants can continue
to cost money. A remaining resource or an incomplete inventory is BLOCKED, not
cleanup PASS.

## Approximate combined cost (USD, ap-northeast-2)

For the two stacks together: 3 running `t3.micro` EC2s, 4 one-AZ interface
endpoint ENIs, 2 in-use public IPv4/EIPs, and 24 GiB gp3. Approximate baseline:

| Duration | EC2 | Interface endpoints | Public IPv4 | gp3 | Total |
|---:|---:|---:|---:|---:|---:|
| 1 hour | $0.039 | $0.040 | $0.010 | $0.003 | **$0.092** |
| 2 hours | $0.078 | $0.080 | $0.020 | $0.006 | **$0.184** |
| 24 hours | $0.936 | $0.960 | $0.240 | $0.072 | **$2.208** |

These use approximate Seoul rates of $0.013/t3.micro-hour and $0.0912/GiB-month,
AWS PrivateLink $0.01/endpoint-ENI-hour, and AWS public IPv4 $0.005/address-
hour. AWS bills the public IPv4 rate in one-second increments with a 60-second
minimum. At 24 hours with all instances stopped after apply, compute falls by
about $0.936 but endpoints, EIPs and volumes remain about **$1.272**. Two
Advanced certificate parameters add $0.10/month prorated while stored and
Parameter Store API interactions; existing KMS key request charges, HTTPS
data transfer, DNS record/authoritative-query charges and tax are excluded.
The Probe Firewall adds two exact SSM names and one `*` block-list entry (three
stored names): about `$0.0015/month` prorated, plus `$0.60` per million DNS
queries inspected in the first foundational tier. No Advanced DNS Firewall
hourly rule is created. For 1,000 queries the additional query charge is about
`$0.0006`; actual volume is not known. Pricing references:
[EC2 instance pricing](https://aws.amazon.com/ec2/pricing/on-demand/),
[PrivateLink endpoint pricing](https://aws.amazon.com/privatelink/pricing/),
[public IPv4 pricing](https://aws.amazon.com/vpc/pricing/),
[Parameter Store pricing](https://aws.amazon.com/systems-manager/pricing/).

## Current deployment decision

**NO-GO / BLOCKED.** The hostname and certificate method are selected, but
DNS-01 validation, trusted certificate, DNS-only A record to the future Probe
EIP, existing KMS key/key-policy confirmation, account/CIDRs/AZ, Probe and
Canary Run IDs, and reviewed Terraform plans are not provided. No `apply`, DNS
operation, instance launch, or Canary was run.
