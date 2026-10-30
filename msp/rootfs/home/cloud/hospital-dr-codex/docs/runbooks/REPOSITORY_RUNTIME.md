# Repository Runtime Layout

The repository is the reproducible source layout for the DR automation. It is
not a replacement for the external secret store or the generated Terraform
state.

## Runtime Paths

Scripts resolve these directories from the clone location by default:

- `DR_REPO_ROOT`: repository root
- `DR_TERRAFORM_DIR`: `infra/terraform`
- `DR_ANSIBLE_DIR`: `automation/ansible`
- `DR_ANSIBLE_SOURCE_DIR`: canonical Ansible playbook/role source; an installed
  `DR_ANSIBLE_DIR` may remain the separate directory for generated inventory and
  controller artifacts
- `DR_OPERATIONS_DIR`: `operations`
- `DR_SECRET_FILE`: external environment file, never stored in this repository
- `DR_PROVISIONING_SECRET_FILE`: optional second external environment file for
  Web/EMR/DB provisioning secrets; it is never stored in this repository
- `DR_SSH_PRIVATE_KEY`: controller-side private key used for AWS SSH and the
  paired Terraform public key. `SSH_KEY` and `DR_SSH_KEY` remain compatibility
  aliases.
- `DR_LOG_DIR`: `var/log` under the clone by default
- `DR_STATE_DIR`: persistent runtime state, `/var/lib/hospital-dr` by default

An installed deployment may set `DR_REPO_ROOT` or the individual directory
variables. The existing `/opt/hospital-dr` layout remains supported when these
variables are set accordingly.

The persistent state helper stores the current DR state in
`/var/lib/hospital-dr/dr_state` by default. The directory is provisioned for
`cloud:cloud` with mode `0750`; the state, lock, and failback-alert flag files
use mode `0640`. Writes use a same-directory temporary file followed by an
atomic rename. Valid states are `IDLE`, `FAILOVER_EXECUTING`, `DR_ACTIVE`,
`FAILBACK_EXECUTING`, `FAILED`, and `PARTIAL_FAILURE`.

State-changing Failover, Failback, FinOps, and DNS entry points also
share the persistent workflow lock at `/var/lib/hospital-dr/workflow.lock`
by default. Nested steps inherit the lock instead of opening a second
lock, so Failover and Failback cannot execute concurrently.

## Rebuild and Provisioning Contract

Terraform owns the AWS resources; Ansible owns OS and application runtime
configuration. automation/ansible/site.yml configures DB first, then EMR,
then Web. Web and EMR are deployed from immutable ECR commit-SHA tags through
DR_IMAGE_TAG; the playbook rejects mutable image tags and waits for the
Dockerfile healthcheck.

Private-host package installation, STS, and ECR pull require a live NAT
gateway and private default route during provisioning. A complete encrypted
DB dump and its matching .master_status file are required unless the
operator explicitly sets DB_ALLOW_EXISTING_DATA=true for a known existing
database. The standby cnf persists server-id=20, binary logging, ROW format,
GTID OFF, and both read-only flags across reboot.

The repository's runtime scripts are the source of truth. Any installed
controller copy such as /opt/hospital-dr must be synchronized from this
repository before execution; a stopped AWS instance alone does not prove that
the current clone is reproducible.

The read-only `operations/runtime/runtime_drift_check.sh --check` command
compares the canonical ChatOps and systemd manifests with their installed
copies, and compares FinOps source files with the operational checkout that
the Terraform wrappers invoke (`/home/cloud/hospital-dr-repo/operations` by
default). Terraform wrappers and state are not mistaken for canonical source.
It reports missing or changed files and never overwrites runtime files.
Terraform has a separate allowlist-based
`operations/runtime/sync_terraform_runtime.sh`: `--check` is the default-safe
mode, while `--apply` preserves the existing operational
`terraform.tfstate`, tfvars, `.terraform`, plans, secrets, and generated files.
Changed Terraform source files are backed up under the persistent runtime
directory before replacement, then the runtime source is validated without an
apply.

## Entry Points

ChatOps-compatible launchers are kept under `infra/terraform`:

- `infra/terraform/full_failover.sh` delegates to
  `operations/failover/full_failover.sh`
- `infra/terraform/web_db_failback.sh` delegates to
  `operations/db/web_db_failback.sh`
- `infra/terraform/run_demo.sh` performs the Terraform, DNS, Ansible, and
  health-check stages
- `run_demo.sh` executes `site.yml` from `DR_ANSIBLE_SOURCE_DIR` while keeping
  generated inventory under `DR_ANSIBLE_DIR`; this prevents a stale external
  Ansible checkout from becoming the execution source.

The complete failback path is intentionally:

`web_db_failback.sh` -> `full_failback.sh` ->
`db_failback_to_onprem.sh` + `doc_failback_sync.sh` -> `failback.sh`

`full_failback.sh` alone keeps its existing optional DB/Doc behavior and must
not be used as the complete ChatOps entry point.

## External Configuration

Before an operational run, provide `DR_SECRET_FILE` and the deployment
configuration through the MSP secret/configuration mechanism. The current MSP
service path is `/home/cloud/hospital-dr-secrets/dr.env`; an explicit
`DR_SECRET_FILE` override remains supported. At minimum, the runbook-specific
SSH key (`DR_SSH_PRIVATE_KEY`), `CF_ZONE_ID`, database secrets, and any
on-premise addresses must be supplied there or through environment variables.
The currently verified controller key is `/home/cloud/.ssh/dr_key`; the key
must remain outside Git with mode `0600` or `0400`. The read-only
`operations/runtime/provisioning_preflight.sh` check should be run before
Ansible or Terraform execution. Secret values must not be passed in command
arguments or committed to Git.

The provisioning secret contract is `MYSQL_ROOT_PASS`, `WEB_DB_PASSWORD`,
`DOC_DB_PASSWORD`, and `SESSION_SECRET`. `DB_ALLOW_EXISTING_DATA=true` is
required when preserving an existing DR database; Direct NR and promotion
must remain disabled for a provisioning-only run. A production TLS source is
still an external input; absence is reported as `NEEDS_AWS_INSPECTION` rather
than being treated as a production certificate.

The timing helper remains `operations/db/dr_timing.sh`; Zabbix delivery remains
best-effort through `operations/db/zbx_send.sh`.
