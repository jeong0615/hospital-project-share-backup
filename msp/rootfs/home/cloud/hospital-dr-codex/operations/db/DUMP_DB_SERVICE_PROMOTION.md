# Isolated Dump DB write promotion fence

This is a manual, separately gated control path. It is not a ChatOps executor and
is not called by normal/emergency Failover, Failback, DNS transactions, or the
19:00 FinOps workflow. `DUMP_RESTORE_EXEC_ENABLED=false` remains required and
`DUMP_RESTORE_EXECUTOR` must remain unset.

## What the promotion stage does

`service-promote` requires both `DUMP_DB_SERVICE_PROMOTION_ENABLED=true` in the
approved environment and `--confirm-write-promotion`. It also requires the exact
successful restore and service-preparation receipts, a matching local backup
SHA-256, isolated EC2/EBS identity, the private service SG, a matching successful
Web/EMR service cutover ID, and fresh read-only app health checks.

Before changing MySQL's persistent `read_only` and `super_read_only` values, it:

1. Confirms the current isolated DB is still read-only and its schema/table count
   and service grants are as expected.
2. Verifies Web and EMR are the exact cutover containers, confirms their current
   DB endpoint is the isolated private IP, and repeats their read-only health
   checks.
3. Confirms the legacy PM2 app service/processes are inactive, stops both app
   containers, and verifies no host process remains on port 3000.
4. Removes INSERT/UPDATE/DELETE privileges from the two fixed app accounts,
   locks those accounts, and verifies there are no remaining sessions.
5. Only then persistently enables MySQL writes and verifies the DB identity,
   listener, schema, grants, account locks, and read-only flags.

The resulting state is `WRITE_PROMOTED_APPS_FENCED`, not the existing
`READY_FOR_DNS_GATE`. MySQL is writable for privileged local administration,
but Web/EMR remain stopped and the application accounts remain locked with only
SELECT privilege. The command never unlocks those accounts, grants application
DML, starts containers, changes DNS, or changes DR state. The next DNS transition
stage must separately define and verify the exact ordering for DNS, account
unlock/grants, app start, health, and the point after which writes make automatic
rollback unsafe.

## Failure and rollback boundary

- Failures before persistent write-enable leave MySQL globally read-only. App
  containers remain stopped if they have already been fenced; they are not
  automatically restarted.
- The promotion status is stored root-only under
  `/var/lib/hospital-dr-dump-restore/status/promotions/` and is single-use by
  promotion ID.
- Once a persistent write-enable command is attempted, an error is recorded as
  `WRITE_STATE_UNKNOWN` unless both MySQL read-only flags are positively observed
  still enabled. No code automatically switches back to the existing DR DB or
  restores DNS. Treat unknown state as a manual reconciliation stop.
- Even after successful promotion, the old DR DB must not be treated as a safe
  rollback target after any application writes. This stage keeps normal app
  writes fenced, but cannot prove absence of privileged local administrative
  writes; therefore automatic rollback remains disabled.

## Not executed during implementation

No promotion command, MySQL statement, app stop/start, AWS operation, DNS update,
DR-state update, Runtime sync, or service restart was performed while adding
this control path. The executor remains disabled. The code and Mock tests do not
constitute proof of a live promotion or of DNS-stage health/write release.
