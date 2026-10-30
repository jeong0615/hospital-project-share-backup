# Dump DB service endpoint switch (pre-DNS only)

`isolated_dump_restore.sh service-cutover` is a separate, explicitly gated
operation. It does not run Terraform, the normal `run_demo.sh` workflow, DNS
helpers, or DR state transitions. Normal Failover continues to deploy Web/EMR
with `IP_REDACTED:3306`.

## Preconditions

- The selected encrypted backup and matching `.master_status` pair are present;
  the supplied SHA-256 must match the local dump.
- Isolated restore and `prepare-service` completed for the same backup, EC2,
  data EBS, staging EBS, private IP, and service SG. The existing
  `service-preflight` is rerun read-only and verifies their root-owned,
  mode-restricted
  receipts, AWS identity, attached volumes, restricted SG rules, listener, and
  `read_only=1` plus `super_read_only=1`.
- `DUMP_RESTORE_EXEC_ENABLED=false` and `DUMP_RESTORE_EXECUTOR` unset remain
  mandatory. This endpoint switch is not the ChatOps Dump Restore Executor.
- A unique UUID is used for the operation. The operator must invoke this only
  before the DNS cutover begins.
- `DUMP_RESTORE_SERVICE_DB_PASSWORD` in the protected secret source must be
  the same dedicated `hospital_dr_service` credential provisioned by
  `prepare-service`.

## Operation

The wrapper requires both the temporary environment opt-in
`DUMP_DB_SERVICE_CUTOVER_ENABLED=true` and the CLI confirmation flag. It
validates the backup/checksum and calls the existing isolated `service-preflight`
before touching either app host. Ansible then:

1. Requires exactly one Web and one EMR target, healthy running containers,
   the managed loopback port/restart contract, and current app env files that
   point to the known existing DR DB `IP_REDACTED:3306`.
2. Stores each exact old env file root-owned mode `0600` in
   `/var/lib/hospital-dr/db-endpoint-cutovers/<UUID>/` and preserves the old
   Docker container by renaming it; the previous container is not deleted.
3. From each existing app container, uses its bundled `mysql2` client and the
   actual app network namespace to perform only `SELECT 1` and inspect MySQL's
   read-only flags. A disposable read-only container uses the same immutable
   image; credentials are staged only on host `/run` tmpfs and bind-mounted
   read-only, never copied into the persistent app container. Probe output
   contains no DB rows or credentials.
4. Recreates the app container using its same immutable image ID and changes
   only `DB_HOST`, `DB_PORT`, `DB_USER`, and `DB_PASSWORD`. It keeps
   `DB_NAME=hospital_db`, and switches to the isolated endpoint on port 3307
   using `hospital_dr_service`.
5. Verifies Web's `/health` (read-only `SELECT 1`) and EMR's
   `/api/patients` (read-only `SELECT` query); response bodies are not retained.

Example invocation template (do not run until the isolated EC2/EBS, backup,
service SG, and app endpoints have been independently approved):

```bash
DUMP_DB_SERVICE_CUTOVER_ENABLED=true \
bash operations/db/isolated_dump_restore.sh service-cutover \
  --region ap-northeast-2 \
  --instance-id <isolated-instance-id> \
  --private-ip <isolated-private-ip> \
  --data-volume-id <isolated-data-volume-id> \
  --stage-volume-id <isolated-stage-volume-id> \
  --service-security-group-id <isolated-service-sg-id> \
  --backup <selected-dump.sql.gz.enc> \
  --expected-sha256 <64-hex-sha256> \
  --cutover-id "$(uuidgen)" \
  --confirm-db-service-switch
```

The wrapper loads the secret file through the existing runtime path. The
password is placed in a short-lived mode-0600 file on `/dev/shm`; it is never
an argv value or logged. Do not add the temporary opt-in to a persistent
service environment.

## Failure and rollback boundary

- A failed preflight/probe makes no app DB config or container change.
- If a switch or post-switch health check fails, the controller invokes the
  rollback playbook before returning. It restores the exact saved env files,
  removes only the newly created app containers, renames the preserved original
  containers back, and verifies their health. If that rollback fails, it exits
  as `DB_SERVICE_SWITCH_ROLLBACK_FAILED`; operator intervention is required.
- A successful result is only `DB_SERVICE_CUTOVER=READY_FOR_DNS_GATE`; this is
  not permission to change DNS and explicitly reports `db_writable=false`. The previous
  env files and stopped containers remain as protected pre-DNS rollback copies.
  This controller has no post-DNS rollback path and must not be reused to undo
  a switch once public traffic can write to the isolated database. If DNS
  cutover has started or traffic has been served, preserve the isolated DB and
  use a separately approved data-reconciliation/rollback decision.
- This operation never changes Cloudflare DNS, service write permissions,
  Terraform/AWS resources, or DR state. The isolated MySQL remains
  `read_only=1` and `super_read_only=1`.

The next DNS gate must consume the `READY_FOR_DNS_GATE` result and independently
require an explicitly approved writable-service DB state, then revalidate the
isolated DB identity, receipts, app health, and DNS rollback snapshot before any
DNS write. Cleanup of the saved old env/container copies is
not part of this operation; it requires a later explicit post-cutover decision.
