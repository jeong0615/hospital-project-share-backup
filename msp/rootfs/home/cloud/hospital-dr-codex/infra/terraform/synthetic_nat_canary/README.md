# Synthetic NAT Canary (isolated Terraform state)

This stack is separate from `infra/terraform` production state. It has no
backend block, imports no production resource, and defaults to zero resources.
It creates no NAT Gateway, app, database, DNS record, or production IAM
reference. Use an approved clean synthetic AMI only.

The two instances are deliberately stopped at the end of `terraform apply`.
They are launched briefly during apply and then stopped, so EC2/EBS/public IPv4
charges begin at apply, not at the later Runner invocation. No apply is part of
the current preparation task.

Required variables deliberately have no deployable defaults: an explicit AWS
account, unused CIDRs, one AZ, pinned AWS-published AL2023 AMI ID, and an
operator-verified probe IP and exact hostname. The provider `allowed_account_ids` check prevents an
accidental account mismatch. Apply requires both `enable_canary=true` and the
exact confirmation string. Keep `.tfstate` and var files local and restricted;
the state contains infrastructure identifiers.

Public Web ingress is empty. Web/EMR egress is limited to the SSM interface
endpoint security group and probe IPv4 TCP/443. EMR's default route points to
the Web ENI; the Web subnet default route points to the IGW. Web source/dest
check is disabled. IPv6 is not allocated. Route 53 Resolver DNS Firewall is
associated only with this VPC, fail-closed, with exact SSM/probe allow names
before a wildcard NXDOMAIN block. AmazonProvidedDNS can be queried despite SG
rules, so the Firewall association is mandatory. HTTPS content to the approved
probe IP is not restricted by an SG; use a dedicated benign echo endpoint.
Direct UDP/TCP DNS to external resolvers and arbitrary DoH destinations are
outside the exact SG/NACL allowlist. The approved probe is still a permitted
HTTPS destination: security groups cannot limit HTTPS URL/content, so the probe
host must be dedicated and return only synthetic egress-IP data. The AMI is
pinned by ID (never `most_recent`) and Terraform/Runner accept only an
available, public, x86_64 HVM/EBS image owned by the official Amazon Linux
publisher (`137112412989`) with the canonical `al2023-ami-*-x86_64` name.
Publisher provenance is stronger than a user-applied tag, but the AMI must
still be re-queried in Seoul before approval and checked against the published
image metadata. Runner startup checks require SSM Online and reject unexpected
application/tunnel processes; they do not constitute a forensic scan of the
image. AWS's AL2023 images usually include SSM Agent, which the live SSM check
confirms. Root volumes are explicitly encrypted, gp3, and delete-on-termination
in the launch block mapping; read-only preflight verifies those live properties.
The read-only AWS query on 2026-10-17 resolved
`/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64` in
`ap-northeast-2` to `AWS_RESOURCE_ID_REDACTED` (Amazon owner
`137112412989`, available, public, x86_64, HVM, EBS root). The SSM parameter is
mutable; re-resolve it and re-check image metadata on the approved deployment
date, then pin that exact ID in the per-Run-ID vars file.

The custom instance role permits only SSM Agent control-plane operations. No
S3, ECR, DB, Cloudflare, or application permissions are attached. Only the
`ssm` and `ssmmessages` endpoints are created by default. Add
`ec2messages` only when the selected AMI/Agent compatibility requires it.

Each subnet uses a Run-ID-tagged Network ACL with explicit TCP 443 probe/SSM
flows and ephemeral-port return paths; all other IPv4/IPv6 subnet traffic is
denied by the ACL. The SG remains the primary stateful host policy. The NAT
middlebox flow uses the exact synthetic EMR address as a CIDR rule, not SG
reference semantics.

The stack never associates an existing/production VPC, peering connection, or
Transit Gateway. It creates its own VPC and only the two declared instances.
Both instances wait for the Run-ID-scoped SSM role policy and DNS Firewall
association before launch, so their first registration/boot steps do not race
those prerequisites.
The main/default SG is cleared to no ingress/egress, the default NACL is
adopted with no allow rules, and the unused default route table is checked for
no internet default route. Standalone SG rules, requester-managed SSM endpoint
ENIs, and every other taggable resource carry the unique `CanaryRunId`;
route/NACL entries and associations are tracked through tagged parent resource
IDs because AWS does not expose independent tags for each embedded entry.

### Cost envelope (ap-northeast-2, USD; updated 2026-10-17)

No NAT Gateway, load balancer, snapshot, or CloudWatch log sink is created.
Using the component rates in the adjacent paragraph, the base Canary stack is
about `$0.053` for one hour, `$0.106` for two hours, and `$1.272` if all
resources remain for 24 hours. These estimates assume both `t3.micro`
instances run for the entire interval, two one-AZ interface endpoints remain
provisioned, one public IPv4 is allocated, and two 8-GiB gp3 volumes remain.
If the optional `ec2messages` endpoint is enabled, add about `$0.01` per
endpoint-hour ($0.01 / $0.02 / $0.24 for those intervals).

Inputs: Seoul `t3.micro` Linux approximately `$0.013` per instance-hour;
interface endpoint `$0.01` per endpoint-ENI-hour; public IPv4
`$0.005` per hour; gp3 `$0.0912` per GB-month, prorated for 16 GiB using a
30-day month. DNS Firewall foundational query and domain-list fees, endpoint
data processing, Internet data transfer, taxes, and any account-specific
credits are excluded; add actual usage. The stack stores three allowed domain
names plus a wildcard block entry. DNS Firewall query pricing is `$0.60` per
million queries and domain names are `$0.0005` per month each; it does not use
the Advanced-rule hourly feature. Instance compute is lower if the hosts run
for less than the stated interval, but EBS, EIP, and endpoints continue to
bill until destroyed/released. AWS charges start during `terraform apply`,
because EC2 instances briefly launch before Terraform stops them. Stopping the
instances does **not** stop endpoint, EIP, or EBS charges. Prices are not a
spend cap. Sources: [AWS regional Price List for EC2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current/ap-northeast-2/index.json),
[AWS regional Price List for VPC](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonVPC/current/ap-northeast-2/index.json),
[PrivateLink pricing](https://aws.amazon.com/privatelink/pricing/),
[VPC pricing](https://aws.amazon.com/vpc/pricing/),
[Route 53 pricing](https://aws.amazon.com/route53/pricing/), and
[EBS pricing](https://aws.amazon.com/ebs/pricing/).

### Deployment approval status (2026-10-17)

**NO-GO — do not plan/apply or run the Canary yet.** A read-only Seoul query
resolved the mutable official AL2023 parameter to
`AWS_RESOURCE_ID_REDACTED`, owner `AWS_ACCOUNT_ID_REDACTED`, name
`al2023-ami-2023.12.20261016.0-kernel-6.18-x86_64`, public/available,
x86_64/HVM/EBS. The source AMI's 8-GiB gp3 snapshot is unencrypted; the launch
mapping explicitly requests encryption and delete-on-termination, and the
Runner verifies those properties on the actual volumes. AWS documents SSM
Agent as present on most AL2023 AMIs, not guaranteed; live SSM Online remains a
post-launch check. Re-resolve the AMI parameter and inspect metadata on the
approved run date.

No dedicated, operator-controlled HTTPS egress-IP probe with a fixed IPv4 and
matching DNS/TLS name is configured or validated. The old public `checkip`
reference and test fixture values are not accepted as approval evidence. A
probe IP allowlist permits arbitrary HTTPS content to that IP; the endpoint
must therefore be dedicated, return only the caller's synthetic egress IPv4,
and have a verified certificate for its exact hostname.

The example still has `expected_account_id=AWS_ACCOUNT_ID_REDACTED`, and Run ID, AZ, and
non-overlapping VPC/subnet CIDRs are not approved. Consequently no deployable
Terraform plan was generated: exact create/update/destroy counts are **not
verified**. Static HCL expansion predicts 61 managed resource instances for
the base two-endpoint configuration (63 with `ec2messages`); the real plan
must be reviewed and must match the approved isolated resource list before
apply. It comprises a new VPC and two subnets; public/private routing and IGW;
two custom NACLs plus explicit rules; isolated SGs/rules and two ENIs; a
Run-ID-scoped SSM role/profile; two interface endpoints; VPC-only DNS Firewall
configuration/lists/group/rules/association; one EIP; and two synthetic EC2s
with encrypted root volumes. Terraform also manages the new VPC's default SG,
NACL, and route table. No production VPC/resource is a Terraform target; the
existing-VPC data lookup is read-only and used only for CIDR-overlap checks.

The 30-minute bound applies to the Runner, not Terraform provisioning or
operator cleanup. Set a **two-hour end-to-end wall-clock cutoff** for apply,
canary, and destroy; this is an operational limit, not an automatic TTL. A
designated operator must monitor the run and perform cleanup immediately on
failure. The 24-hour estimate above is the conservative case where both hosts
are left running; if stopped, subtract `$0.624` compute, but other resources
still accrue charges.

Before a separately approved deployment, re-resolve and inspect the AMI (do
not rely on the example ID):

```bash
AMI_ID="$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --region ap-northeast-2 --query Parameter.Value --output text)"
aws ec2 describe-images --region ap-northeast-2 --image-ids "$AMI_ID" \
  --query 'Images[0].[ImageId,OwnerId,Name,Public,State,Architecture,VirtualizationType,RootDeviceType,PlatformDetails,BlockDeviceMappings[?DeviceName==`/dev/xvda`].Ebs.[VolumeSize,VolumeType,Encrypted,DeleteOnTermination]]' \
  --output json
```

Compare every field with the approval; stop if the publisher, image type, or
region differs. AWS does not guarantee SSM Agent is running just because the
AMI family usually includes it. No package install or guest modification is
part of this deployment.

Initial offline checks (no plan/apply or AWS resource calls):

```bash
terraform -chdir=infra/terraform/synthetic_nat_canary init -input=false
terraform -chdir=infra/terraform/synthetic_nat_canary validate
```

The example is intentionally invalid as a deployable plan. Do not apply this
stack until a separate change approval specifies account, CIDRs, AMI, probe,
budget limit, and Run ID. Use a separate `terraform.<run-id>.tfvars` file with
mode 0600 and one local Terraform workspace per Run ID; the Runner rejects a
changed vars-file hash before destroy. Serialize provisioning and Canary runs.
The Runner's `--run` is a separate explicit approval gate. `--cleanup` destroys
only the selected Run ID workspace after restoring the guest baseline and
stopping the instances. `--inventory-run-id` is read-only inventory, not an
automatic state reconstruction or deletion command. If Runner state is missing,
it deliberately blocks cleanup; reconcile the listed Run-ID-tagged resources
with Terraform state and use an explicitly reviewed recovery procedure.

Approved setup sequence (do not execute before separate approval specifies
account/network/AMI/probe, budget ceiling, and Run ID):

```bash
set -euo pipefail
RUN_ID='synth-20261017-a'
PROBE_RUN_ID='probe-20261017-a' # separate stack/workspace; see ../synthetic_nat_probe/README.md
STACK='infra/terraform/synthetic_nat_canary'
VARS="$STACK/terraform.$RUN_ID.tfvars"
umask 077
if [[ -e "$VARS" ]]; then
  printf 'Refusing to overwrite existing Run-ID var file: %s\n' "$VARS" >&2
  exit 1
fi
cp "$STACK/terraform.tfvars.example" "$VARS"
chmod 0600 "$VARS"
# Pin the reviewed AWS-published AL2023 AMI ID and fill all approved values.
# Do not use production credentials or an AMI containing hospital software/data.
terraform -chdir="$STACK" init -input=false
terraform -chdir="$STACK" workspace new "$RUN_ID"
# Confirm the CLI account matches expected_account_id in the approved vars.
aws sts get-caller-identity --query Account --output text
# Save and restrict the exact plan. Fill approved vars before creating it.
PLAN="$STACK/$RUN_ID.tfplan"
TF_WORKSPACE="$RUN_ID" terraform -chdir="$STACK" plan -input=false -var-file="$(basename "$VARS")" -out="$RUN_ID.tfplan"
chmod 0600 "$PLAN"
terraform -chdir="$STACK" show -no-color "$PLAN"
# Apply this exact, separately reviewed plan only after deployment approval.
TF_WORKSPACE="$RUN_ID" terraform -chdir="$STACK" apply -input=false "$RUN_ID.tfplan"
python3 operations/demo/synthetic_nat_probe.py --aws-read-only --run-id "$PROBE_RUN_ID"
python3 operations/demo/synthetic_nat_probe.py --verify-link --run-id "$PROBE_RUN_ID" --canary-run-id "$RUN_ID"
python3 operations/demo/synthetic_nat_canary.py --aws-read-only --run-id "$RUN_ID"
python3 operations/demo/synthetic_nat_canary.py --run --run-id "$RUN_ID" --probe-run-id "$PROBE_RUN_ID" --confirm-run-id "$RUN_ID" --confirm-synthetic-network-cost
```

The Probe stack is provisioned first with source ingress disabled. After its
EIP is returned, publish the DNS-only A record
`nat-probe.hospital-web.pp.ua` to that exact EIP with Cloudflare Proxy disabled.
Then this stack is provisioned and returns `web_eip`; only then is Probe ingress
bound to that exact `/32`. Use `operations/demo/synthetic_nat_probe.py
--verify-link` to check both Terraform outputs. The configuration itself
requires `enable_canary=true` and
`confirmation=CREATE_SYNTHETIC_NAT_CANARY` in that per-Run-ID vars file. The
Runner's success transaction restores guest networking and destroys that
workspace. If interrupted, run `--restore` then `--cleanup` with the same Run ID
and exact confirmation; if state is unavailable, inventory first and do not
guess or issue broad deletes. Delete a completed workspace only after verifying
its state is empty and the tagged-resource inventory is empty.

Recovery after interruption, only after verifying the exact Run ID and AWS
account:

```bash
python3 operations/demo/synthetic_nat_canary.py --restore --run-id "$RUN_ID" --confirm-run-id "$RUN_ID"
# Proceed only if RESTORE reports PASS:
python3 operations/demo/synthetic_nat_canary.py --cleanup --run-id "$RUN_ID" --confirm-run-id "$RUN_ID"
```

If Terraform apply fails before the Runner has written its state, do not assume
Runner `--cleanup` can recover a partial Terraform graph. In the exact Run-ID
workspace, create and inspect a destroy plan, then apply only that reviewed
plan after confirming it contains only that run's synthetic resources:

```bash
DESTROY_PLAN="$STACK/$RUN_ID.destroy.tfplan"
TF_WORKSPACE="$RUN_ID" terraform -chdir="$STACK" plan -destroy -input=false \
  -var-file="$(basename "$VARS")" -out="$RUN_ID.destroy.tfplan"
chmod 0600 "$DESTROY_PLAN"
terraform -chdir="$STACK" show -no-color "$DESTROY_PLAN"
# After exact Run-ID/resource review and separate operator approval:
TF_WORKSPACE="$RUN_ID" terraform -chdir="$STACK" apply -input=false "$RUN_ID.destroy.tfplan"
```

If local Terraform state is unavailable, do not destroy by guessed IDs:

```bash
python3 operations/demo/synthetic_nat_canary.py --inventory-run-id --run-id "$RUN_ID"
```

The inventory is a reconciliation aid, not authority to delete unrelated
resources. After destroy, verify both workspace state and tagged inventory are
empty, then verify no VPC, endpoint, DNS Firewall association, EIP, ENI, or EBS
volume remains before deleting the local workspace/state and Run-ID tfvars.
Never use production workspace/state.
