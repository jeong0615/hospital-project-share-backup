# DR instance reprovisioning contract

automation/ansible/site.yml is the runtime provisioning entry point for a
fresh or rebuilt DR instance set. It runs the database tier first, then EMR,
then Web, so application services are configured only after the database
contract is in place.

## Responsibilities

- Terraform provisions AWS infrastructure, networking, security groups, IAM
  instance profiles, ECR repositories, and persistent EIP resources.
- Ansible installs the OS packages and enables Docker, MySQL, Nginx, or Apache.
- Ansible pulls an immutable ECR image and creates hospital-dr-web or
  hospital-dr-emr with --restart unless-stopped.
- The Web and EMR Dockerfiles provide the runtime healthcheck used by Ansible.
- Ansible disables the legacy pm2-ubuntu unit and removes only the matching
  Hospital PM2 process; it does not install PM2.
- Database standby protection is persistent in
  roles/db_recovery/files/z-hospital-dr-standby.cnf.
- The playbook first uses Ansible's raw transport to install `python3` and
  `python3-apt` when a minimal Ubuntu host does not have the Python module
  runtime yet. Later plays therefore do not rely on a manually prepared
  target image.
- Apache is started on every run but is reloaded only when its module, site, or
  reverse-proxy configuration changes. The playbook also checks the proxy
  endpoint after the service is ready.

## External configuration

Run infra/terraform/run_demo.sh with DR_SECRET_FILE pointing to the
external secret file. Secret values stay outside Git and are passed to Ansible
through the controller environment. The runtime requires:

- `DR_ANSIBLE_SOURCE_DIR`: canonical playbook and role source. `DR_ANSIBLE_DIR`
  remains the operational directory for the generated inventory and controller
  configuration when those artifacts must be kept outside the checkout.
- `DR_SSH_PRIVATE_KEY`: readable controller-side private key. The legacy
  `SSH_KEY` and `DR_SSH_KEY` names remain accepted as compatibility aliases.
- `DR_SSH_KNOWN_HOSTS_FILE`: optional persistent controller-side known-hosts
  file. The default is `${DR_STATE_DIR}/ssh/known_hosts`; DR SSH paths use
  `StrictHostKeyChecking=accept-new`, so a changed host key still requires an
  explicit operator rotation.
- `operations/runtime/provisioning_preflight.sh`: read-only controller check
  for the key, state, secret contract, immutable ECR tags, and safety flags.
- `operations/runtime/runtime_drift_check.sh --check`: read-only comparison of
  canonical ChatOps/systemd manifests and the FinOps source used by the
  operational wrapper checkout. It reports drift without overwriting runtime
  files or inspecting secret/state contents.
- `operations/runtime/sync_terraform_runtime.sh --check`: compares only the
  approved Terraform module manifest with the operational source directory.
  Use `--apply` only after review; it backs up changed source files under the
  persistent runtime directory and never copies or removes state, tfvars,
  plans, provider data, secrets, or generated artifacts.

- DR_IMAGE_TAG: a 40-character commit SHA that exists in both the Web and
  EMR ECR repositories; mutable tags such as latest are rejected.
- A fresh DB host requires DB_BACKUP_ENCRYPTION_KEY plus a matching
  `.sql.gz.enc` and `.master_status` pair. `DB_ALLOW_EXISTING_DATA=true` is
  only for a known pre-populated DR database and does not make an empty fresh
  host valid.
- Web/EMR application database secrets and MYSQL_ROOT_PASS.
- The application DB service endpoint is configured independently from the
  `dr-db` SSH inventory alias. `DR_DB_SERVICE_MODE=existing` defaults to
  `AWS_PUBLIC_IP_REDACTED:3306`; `DR_DB_PRIVATE_IP` remains only the SSH destination.
  Existing `WEB_DB_PORT` and `DOC_DB_PORT` overrides remain honored in this
  mode.
  An isolated endpoint requires explicit `DR_DB_SERVICE_HOST`, port, and
  isolated instance ID; any legacy per-application port override must match
  the explicit isolated service port. Before Ansible renders the Web/EMR environment, a
  read-only AWS identity check must confirm the running isolated instance,
  private IP, isolated role tags, dedicated security group, and private DB
  subnet. The existing DB tier cannot be deployed in the same run as an
  isolated service endpoint. No DB promotion, restore, or network change is
  performed by this endpoint resolver.
- CF_ZONE_ID, SSH key configuration, and the normal DR host/domain settings.
- The FinOps `provision` entry point sets `DR_PROVISION_ONLY=true`, so a rebuilt
  database remains read-only until an explicit failover promotion.
- The Ansible plays use `any_errors_fatal: true`; a failed database or EMR
  play stops later tiers instead of allowing a partial application deployment.

ECR account and registry values may be supplied with ECR_ACCOUNT_ID or
ECR_REGISTRY; otherwise the instance role account is resolved with STS.
The role must retain least-privilege ECR pull access in the target account.

## Network and lifecycle prerequisites

The Web host is public and can reach the controller for initial SSH
provisioning. EMR and DB remain private and are reached through the Web bastion.
NAT is required before provisioning private hosts because package installation,
STS, and ECR login/pull need outbound access. The normal order is:

1. enable the NAT gateway and private default route;
2. provision the DB, EMR, and Web hosts with Ansible;
3. validate container/application health;
4. remove NAT only when no private outbound operation is still required.

The fixed NAT EIP is an external state/import prerequisite; a fresh Terraform
state must adopt the preserved allocation before any NAT enable operation.
Never allocate or release a replacement EIP for this workflow.

This provisioning order is not the Phase 3 live-test path. Phase 3 uses the
already-provisioned Web/EMR/DB set and the approved Web NAT Instance contract;
it must not invoke `run_demo.sh`, `dr_environment_control.sh provision`, or a
NAT Gateway lifecycle command. If the existing instance set is incomplete, the
live window stops and is rescheduled for a separately reviewed provisioning
operation.

## Optional dedicated AWS DR WireGuard

`aws_dr_wireguard.yml` is a separate, explicit playbook and is not included
by `site.yml`. It is disabled unless `AWS_DR_WG_ENABLED=true` is supplied in
the live operator environment. The playbook configures only `wg-aws-dr`:

- AWS Web gateway: `AWS_PUBLIC_IP_REDACTED/24`, UDP `51821`;
- On-Prem DB client: `IP_REDACTED/32`, `PersistentKeepalive=25`;
- AWS DB route target: `AWS_PUBLIC_IP_REDACTED/32`;
- no `wg0`, legacy `10.250.x.x`, MSP `192.168.200.x`, or MASQUERADE rule.

Both private keys and peer public keys are read from target paths outside the
repository with `no_log` protection. Missing runtime key material fails the
play before the interface is changed. The normal provisioning playbook does
not install WireGuard or restart an existing MSP tunnel.

## Optional Web NAT Instance

`aws_web_nat_instance.yml` is a separate, explicit playbook for the reviewed
candidate migration that lets the existing public Web instance forward private
subnet Internet traffic. It is not included by `site.yml`; the default
`AWS_WEB_NAT_INSTANCE_ENABLED=false` leaves the current NAT Gateway and Web
firewall behavior unchanged. The role owns only project-named iptables chains,
excludes the AWS DR WireGuard/NR destinations, and never flushes Docker or
WireGuard chains. Use the matching `aws_web_nat_instance_disable.yml` only
after an explicitly reviewed route rollback. In the current BLACKHOLE recovery
baseline there is no healthy NAT Gateway rollback target; do not recreate one
automatically and use the documented no-egress rollback if required.
