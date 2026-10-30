# Hospital DR NAT Gateway Manual Lifecycle

NAT Gateway creation, status inspection, and deletion are deliberately owned by
`operations/nat`. FinOps and the DR environment controller may report or
orchestrate other lifecycle work, but they do not own NAT mutations.

The approved operational Terraform state is always:

```text
/home/cloud/hospital-dr-terraform
```

The scripts fail closed unless that directory and its state identify the
approved VPC, subnet, route table, and preserved EIP:

```text
VPC              AWS_RESOURCE_ID_REDACTED
Public subnet    AWS_RESOURCE_ID_REDACTED
Private RT       AWS_RESOURCE_ID_REDACTED
EIP allocation   AWS_RESOURCE_ID_REDACTED
EIP public IP    AWS_PUBLIC_IP_REDACTED
```

## Manual commands

```bash
cd /home/cloud/hospital-dr-codex

# Read-only status. Exit 0 for READY/OFF, non-zero for DRIFTED/ERROR.
operations/nat/nat_status.sh

# Create only when the approved NAT is absent. Existing READY state is a no-op.
operations/nat/nat_enable.sh

# Remove only the approved private default route and NAT Gateway.
# The preserved EIP is never released.
operations/nat/nat_disable.sh
```

`nat_enable.sh` requires no SSH private key. Full EC2 provisioning retains its
separate SSH public-key contract. `nat_status.sh` never runs Terraform apply or
destroy. Every mutating command validates the operational state before AWS is
changed and validates the AWS result afterwards.

## Systemd

The enable and disable units are manual oneshots that call the scripts above.
NAT morning/evening timers and the old controller-shutdown deletion hook are no
longer part of the repository. A controller or host shutdown must not silently
delete NAT; run `nat_disable.sh` explicitly after checking the DR state.

Runtime unit files require an operator to install/reload them separately:

```bash
sudo systemctl daemon-reload
# These are manual oneshots; do not enable them at boot.
sudo systemctl start hospital-dr-nat-enable.service   # only when NAT is required
sudo systemctl start hospital-dr-nat-disable.service  # only after checking DR state
```

If an older timer installation is still present on a controller, disable those
legacy timer units manually before enabling the oneshots. No timer installer or
timer unit is shipped by this repository.

The commands above are intentionally not run by repository tests or CI.

## Safety contract

- No canonical `infra/terraform/terraform.tfstate` is accepted as operational state.
- No alternate VPC, subnet, route table, or EIP is accepted.
- Existing correct NAT returns `NAT_ALREADY_READY=PASS` without creating another gateway.
- Existing correct EIP is preserved on disable and is never released.
- VPC, subnets, route tables, IGW, EC2, security groups, key pairs, and S3 are not deletion targets.
- Terraform apply is limited to the NAT EIP reference, NAT Gateway, and private route targets.
- AWS changes are not performed by tests.
