# Dump DB DNS preflight

`dump_db_dns_preflight.sh` is a Dump-only, read-only point-in-time gate. It is
separate from `full_failover.sh` and the DNS transaction helper. A successful
result is `DUMP_DNS_PREFLIGHT_PASSED_NOT_AUTHORIZATION`; it never changes DNS,
DR state, MySQL, credentials, or app containers, and never authorizes app writes.

When an operator is ready to run the read-only checks, use the existing
SSM-backed Cloudflare token loader and pass the exact isolated resource IDs,
backup, promotion ID, and cutover ID:

```bash
DUMP_DB_DNS_PREFLIGHT_ENABLED=true \
DUMP_RESTORE_EXEC_ENABLED=false \
bash operations/db/dump_db_dns_preflight.sh \
  --instance-id <isolated-instance-id> \
  --private-ip <isolated-private-ip> \
  --data-volume-id <mysql-data-volume-id> \
  --stage-volume-id <dump-stage-volume-id> \
  --service-security-group-id <isolated-service-sg-id> \
  --backup /home/cloud/db_backups/<backup>.sql.gz.enc \
  --expected-sha256 <64-character-sha256> \
  --promotion-id <promotion-uuid> \
  --cutover-id <cutover-uuid>
```

The command performs Cloudflare GETs, AWS Describe calls, local receipt/hash
reads, and Ansible read-only inspection. It requires a secured preserved
On-Prem DNS snapshot and DR state `IDLE` or `FAILED`; an unknown state or a live
DNS record differing from that snapshot is a hard stop. Web/EMR public health
is deliberately not called because their containers must remain stopped at this
stage. Their stopped state, loopback listener absence, security-group exposure,
and current DB endpoint are checked instead.

The DB check verifies the encrypted backup hash and linked receipts, isolated
EC2/EBS identity, private listener and service SG, MySQL writable runtime with
application accounts locked and SELECT-only, zero active sessions, disabled
event scheduler, table count and `mysqlcheck`, locked import account, and no
unapproved active services, containers, timers, or cron jobs. It does not claim
a row-by-row comparison against the encrypted SQL artifact; it validates the
restore receipt plus current MySQL structural/table integrity checks.

This is not an authorization or synchronization primitive: the checks are a
point-in-time observation. A later service activation/DNS stage must independently
revalidate its own prerequisites and must not infer permission from this result.
