# Hospital DR Terraform IAM Least-Privilege Validation Plan

## Scope

AdministratorAccess must remain attached until the four draft policies are
attached and the DR workflows pass validation.

## Draft Policies

- `HospitalDRTerraformProvisionerPolicy.json`
- `HospitalDRTerraformServerlessPolicy.json`
- `HospitalDRTerraformIAMPolicy.json`
- `HospitalDRSecretReadPolicy.json`

## Validation Order

1. Attach the four draft policies to `terraform-admin` while keeping
   `AdministratorAccess`.
2. Run `terraform plan` and confirm there are no access denied errors.
3. Run `run_demo.sh` with the normal DR variables and confirm Terraform,
   Ansible, Cloudflare DNS, Web, Doc, and DB validation still work.
4. Run `failback.sh` or the ChatOps failback path and confirm DNS failback,
   DB failback, Doc sync, EC2 stop, and NAT cleanup still work.
5. Run `nat_gateway_control.sh enable`, `status`, and `disable` to confirm
   NAT Gateway, NAT EIP, and private route operations still work.
6. Only after all checks pass, detach `AdministratorAccess` and repeat steps
   2 through 5.

## Expected Gaps To Watch

- EC2 create/delete APIs may still need `Resource="*"` because Terraform
  creates interdependent VPC, subnet, network interface, security group, EBS,
  AMI, and key pair resources.
- `Describe*` APIs generally require `Resource="*"`.
- Cloudflare permissions are not controlled by AWS IAM. They depend on the
  Cloudflare API token supplied through environment variables or SSM.
- Token rotation after AdministratorAccess removal may require a separate
  SSM write policy for `ssm:PutParameter`.

## Lambda Role Tightening Candidate

The Lambda `hospital-dr-cost-guard-role` can be improved separately by adding
tag conditions for stop/delete/release actions where the EC2 API supports
resource tags. Do not tighten this role in the same change as the Terraform
execution user policy migration.
