# Dump-only DNS transaction (maintenance remains enabled)

This controller is separate from `full_failover.sh`, the normal/emergency
ChatOps workflow, and Failback. It reuses the snapshot/update/readback/rollback
functions in `operations/failover/dns_transaction.sh`, but deliberately does
not call the helper's all-in-one transaction function: rollback is permitted
only after a fresh isolated-DB no-DML and binlog-position proof.

## Behavior

1. Requires an explicit one-command `DUMP_DB_DNS_TRANSACTION_ENABLED=true`, the
   existing public-readiness/read-only/preflight opt-ins, shared DR locks, and
   `DUMP_RESTORE_EXEC_ENABLED=false` with no executor configured. It opens the
   ChatOps approval database read-only and requires the exact request ID to be
   `EXECUTING`, its execution lease to be current, its Dump type/backup ID/SHA
   to match, and its approved approver count to satisfy the stored policy. An
   active one-person test approval must also have an unexpired policy window.
   The request and execution ID are rechecked immediately before each DNS PUT
   and before success is recorded.
2. Revalidates the backup SHA-256, restore/service/cutover/promotion/read-only
   receipts, isolated EC2/EBS/SG identity, app configuration and health
   receipt, current On-Prem DNS pair, DR state, prepared firewall, per-cutover
   expiry timers, and maintenance responses. It also records the isolated
   MySQL binlog file/position before the first DNS PUT.
3. Snapshots both live Cloudflare records through the canonical shell helper,
   checks they still match the approved On-Prem pair, then changes Web and EMR
   to proxied A records for the approved DR Web EIP. Each update and the pair
   receive API readback verification.
4. Checks `/__hospital_dr/health` for both public hostnames. The request is
   pinned to a resolved Cloudflare IPv4 address, uses normal hostname TLS
   verification, requires Cloudflare response headers and an empty HTTP 204,
   and sends the short-lived probe token only in a header.
5. Revalidates the maintenance/fence timer, SELECT-only app grants and binlog
   position. Success is only
   `DUMP_DNS_SWITCHED_MAINTENANCE_WRITES_BLOCKED`: no app write access is
   granted, maintenance stays on, `DR_ACTIVE` is not written, and this is not
   final service activation.
6. Writes a 0600 request-specific event log beside the cutover receipt under
   the transaction state directory. The log contains only fixed phase/status
   codes and request ID; API and probe credentials are excluded.

On a partial PUT, readback mismatch, or public-health failure, automatic DNS
rollback is attempted only if the isolated DB still proves the exact same
backup/operation, app accounts remain SELECT-only, no unapproved sessions or
scheduled writers exist, binary logging is enabled, and its binlog file and
position are unchanged from the pre-PUT baseline. A changed/unreadable binlog
or any unavailable safety proof means no automatic rollback and a
`PARTIAL_FAILURE` receipt for operator reconciliation. A rollback API error or
failed origin readback is also `PARTIAL_FAILURE`, never success. DNS rollback
does not restore On-Prem service health.

## Future operator invocation

The wrapper is intentionally not called by ChatOps and is not connected to
Dump Restore execution. If separately authorized after the real AWS/DB and
Cloudflare configuration is reviewed, invoke it with the exact operation
identities and explicit confirmation, for example:

```bash
DUMP_DB_DNS_TRANSACTION_ENABLED=true \
  operations/db/dump_db_dns_transaction.sh \
  --request-id '<approved-request-uuid>' \
  --instance-id '<isolated-instance-id>' \
  --private-ip '<isolated-private-ip>' \
  --data-volume-id '<isolated-data-volume-id>' \
  --stage-volume-id '<isolated-stage-volume-id>' \
  --service-security-group-id '<isolated-service-security-group-id>' \
  --backup '/home/cloud/db_backups/<selected-backup>.sql.gz.enc' \
  --expected-sha256 '<recorded-sha256>' \
  --promotion-id '<promotion-uuid>' \
  --cutover-id '<cutover-uuid>' \
  --confirm-dns-transaction
```

This command is documentation only in the current implementation task. The
Cloudflare token is loaded from the existing SSM auth helper and is not an
argument. Cloudflare edit permission remains unproven until an authorized
live request is separately approved; no live request was made here.

No function in this stage enables DML, removes maintenance, opens the strict
fence, changes DR state, or stops/starts AWS resources. Those require a later,
separate service-opening stage and explicit approval.
