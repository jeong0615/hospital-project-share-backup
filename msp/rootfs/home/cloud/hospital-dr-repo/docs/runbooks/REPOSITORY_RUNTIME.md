# Repository Runtime Layout

The repository is the reproducible source layout for the DR automation. It is
not a replacement for the external secret store or the generated Terraform
state.

## Runtime Paths

Scripts resolve these directories from the clone location by default:

- `DR_REPO_ROOT`: repository root
- `DR_TERRAFORM_DIR`: `infra/terraform`
- `DR_ANSIBLE_DIR`: `automation/ansible`
- `DR_OPERATIONS_DIR`: `operations`
- `DR_SECRET_FILE`: external environment file, never stored in this repository
- `DR_LOG_DIR`: `var/log` under the clone by default

An installed deployment may set `DR_REPO_ROOT` or the individual directory
variables. The existing `/opt/hospital-dr` layout remains supported when these
variables are set accordingly.

## Entry Points

ChatOps-compatible launchers are kept under `infra/terraform`:

- `infra/terraform/full_failover.sh` delegates to
  `operations/failover/full_failover.sh`
- `infra/terraform/web_db_failback.sh` delegates to
  `operations/db/web_db_failback.sh`
- `infra/terraform/run_demo.sh` performs the Terraform, DNS, Ansible, and
  health-check stages

The complete failback path is intentionally:

`web_db_failback.sh` -> `full_failback.sh` ->
`db_failback_to_onprem.sh` + `doc_failback_sync.sh` -> `failback.sh`

`full_failback.sh` alone keeps its existing optional DB/Doc behavior and must
not be used as the complete ChatOps entry point.

## External Configuration

Before an operational run, provide `DR_SECRET_FILE` and the deployment
configuration through the MSP secret/configuration mechanism. At minimum, the
runbook-specific SSH key, `CF_ZONE_ID`, database secrets, and any on-premise
addresses must be supplied there or through environment variables. Secret
values must not be passed in command arguments or committed to Git.

The timing helper remains `operations/db/dr_timing.sh`; Zabbix delivery remains
best-effort through `operations/db/zbx_send.sh`.
