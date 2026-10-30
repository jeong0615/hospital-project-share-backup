# Dump DB Web/EMR read-only Health Gate

This is a separate, opt-in operation after Dump restore, service preparation,
DB endpoint cutover, write promotion, and `dump_db_dns_preflight.sh`. It is not
called by normal or emergency Failover and it has no DNS transaction, public
Health Check, user-write release, or DR-state transition path.

## What it verifies

The controller acquires the canonical workflow and Failover locks, validates
the encrypted backup pair and SHA-256, then reruns the complete read-only DNS
preflight. The fresh result must match the same backup, promotion, cutover,
isolated EC2, EBS volumes, service SG, and private endpoint. Cloudflare DNS
must still match the approved On-Prem snapshot and DR state must still be
`IDLE` or `FAILED`. It repeats and compares that full preflight after installing
the host fence and setting app restart policy to `no`; any DNS, AWS, DB, or
receipt drift at that boundary triggers rollback before account unlock/app
start.

Before starting either app, it installs a dedicated persistent nftables input
fence on both app hosts. Non-loopback TCP 80/443 are dropped; the fence does
not change other nftables tables. Docker's app port must remain bound only to
`IP_REDACTED:3000`, and the exact cutover containers are changed to restart
policy `no`. The systemd oneshot re-applies the fence before network services
and Docker at boot. The fence remains installed after the Health Gate; this
operation does not remove it.

Only the two isolated-DB app accounts are temporarily unlocked. Their grants
must remain exactly `USAGE` plus `SELECT` on `hospital_db`; the import account
must stay locked, and unknown/remote writer accounts, events, or background
writer paths block the operation. The MySQL server itself may be in its
prepared writable mode, but this operation never grants application DML.

Web `/health` and EMR `GET /api/patients` are called on loopback. The EMR
response body is discarded. A separate in-container probe verifies the
connected server UUID, host/port, schema, current app account, and SELECT-only
grants. Success is recorded only as
`APPS_READONLY_HEALTH_VERIFIED_NOT_DNS_AUTHORIZED`.

## Failure handling

If activation or a Health check fails, the controller attempts both rollback
phases: stop only app containers whose cutover label matches this operation,
restore/verify the ingress fence, then lock the two app accounts and revoke
the Health receipt. If any stop, fence, or account-lock check cannot be
verified, the operation reports rollback failure and does not report success.
The old AWS DR DB, DNS records, and DR state are not changed. A prepare failure
occurs before app start and leaves the previous app/account fence in place;
the stricter ingress fence and `restart=no` may remain and require operator
review.

## Invocation contract

Do not run this until the isolated EC2/EBS actually exists and every prior
receipt and DB service check has been reviewed. `DUMP_RESTORE_EXEC_ENABLED`
must remain false and `DUMP_RESTORE_EXECUTOR` unset. Opt-ins must be supplied
for this invocation only, never made permanent in the secret file:

```bash
DUMP_DB_READONLY_HEALTH_ENABLED=true \
DUMP_DB_DNS_PREFLIGHT_ENABLED=true \
bash operations/db/dump_db_readonly_health.sh \
  --region ap-northeast-2 \
  --instance-id <isolated-instance-id> \
  --private-ip <isolated-private-ip> \
  --data-volume-id <mysql-data-volume-id> \
  --stage-volume-id <dump-stage-volume-id> \
  --service-security-group-id <isolated-service-sg-id> \
  --backup /home/cloud/db_backups/<selected-backup.sql.gz.enc> \
  --expected-sha256 <reviewed-sha256> \
  --promotion-id <promotion-id-from-receipt> \
  --cutover-id <cutover-id-from-receipt> \
  --confirm-readonly-health
```

The wrapper loads the existing secret source and Cloudflare read credential,
acquires both canonical locks, and keeps `DUMP_RESTORE_EXEC_ENABLED=false`.
Do not copy credentials onto command lines or enable the ChatOps Dump
Executor. A successful result proves only the fenced, SELECT-only application
Health Gate; a later reviewed step must independently handle external health,
DNS transaction, and user-write authorization.
