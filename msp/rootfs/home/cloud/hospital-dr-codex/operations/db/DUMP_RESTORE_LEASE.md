# Dump restore / 19:00 shutdown lease foundation

This change adds only a shared coordination primitive. It does **not** connect
the existing restore controller or `dr_cost_guard.py`, defer a real shutdown,
change DNS, or create an AWS resource. `enable_dump_restore_lease_store` remains
`false`; no Terraform apply was run.

## Storage and concurrency contract

The opt-in table is `hospital-dr-dump-restore-lease`, with string keys `pk` and
`sk`. One control row (`HOSPITAL_DR#DUMP_RESTORE` / `CONTROL`) is the sole
arbitration point. Append-only audit rows use the separate
`HOSPITAL_DR#DUMP_RESTORE_AUDIT` partition and `AUDIT#<time>#<uuid>` sort keys.
The table is on-demand, encrypted, point-in-time
recoverable, and protected from routine Terraform/AWS deletion.

Every read of the control row is strongly consistent. Every state change is a
single DynamoDB transaction containing (a) a conditional revision/state update
to that same control row and (b) an audit Put. A racing writer loses its
condition and must re-read; it may not proceed with the external operation.
Store/API errors are fail-closed. The record has an explicit epoch `expires_at`
and absolute `max_expires_at`; callers compare both values themselves. There is
no DynamoDB TTL attribute or TTL policy, so asynchronous item deletion is never
used to decide whether a lease is valid.

## State transitions

```text
NONE / DUMP_COMPLETED / DUMP_FAILED / SHUTDOWN_COMPLETED
  ├─ authorized Dump start ───────────────> DUMP_ACTIVE
  └─ authorized shutdown claim ──────────> SHUTDOWN_CLAIMED

DUMP_ACTIVE
  ├─ scheduled shutdown arrives ─────────> SHUTDOWN_PENDING
  ├─ Dump owner completes ───────────────> DUMP_COMPLETED
  └─ Dump owner reports failure ─────────> DUMP_FAILED

SHUTDOWN_PENDING
  ├─ Dump owner completes/fails ─────────> SHUTDOWN_PENDING (ready for retry)
  └─ same authorized shutdown claims ────> SHUTDOWN_CLAIMED

SHUTDOWN_CLAIMED
  ├─ shutdown owner completes ───────────> SHUTDOWN_COMPLETED
  └─ shutdown owner reports failure ─────> SHUTDOWN_FAILED
```

`SHUTDOWN_CLAIMED` blocks a new Dump lease. `SHUTDOWN_PENDING` never means that
shutdown was authorized to continue. An expired Dump lease is **not proof** the
restore process or its SSH session has stopped: the shutdown remains pending,
and the expired owner cannot renew, release, or finish it. This intentionally
fails closed; a later integration must add a separately authorized, auditable
reconciliation procedure that proves the old worker is quiescent before handoff.
An expired shutdown claim also blocks new work until reconciled. No silent lease
stealing is implemented.

The owner supplies a UUID operation ID, and renew/finish require both the same
ID and the same authorized principal. Configured role ARNs are compared with
authenticated caller identity; a standard STS assumed-role session ARN is
normalized to its IAM role ARN. A caller must derive its identity from AWS STS,
not from Slack payload or an operator-provided string. Renewals are allowed only
before the current expiry and absolute maximum, and record `renewed_at` plus a
counter. Timing values are deployment inputs, not selected production values.
They must satisfy `0 < renew_interval < lease_duration <= max_duration <= 7d`;
all are zero/unset while the opt-in is disabled. Seven days is a code safety
ceiling, not a recommendation for an actual restore lease.

## IAM boundary

Terraform prepares separate permissions:

- The Dump controller role trusts only the explicit exact principal ARNs in
  `dump_restore_lease_controller_principal_arns` and receives table-scoped
  `GetItem`, control-partition `UpdateItem`, and audit-partition `PutItem`.
- Writes are allowed only when enclosed in a `TransactWriteItems` operation.
  Audit items can be created but not updated or deleted by either runtime role.
- The existing cost-guard execution role receives the same table-scoped,
  transaction-enclosed DynamoDB permissions through a separate opt-in inline
  policy. Its existing EC2,
  SSM, and DNS policy and Lambda code are not changed by this lease foundation.
- `dynamodb:LeadingKeys` is constrained by action: reads may access the control
  and audit partitions, updates only the control partition, and puts only the
  audit partition. Neither role has a DeleteItem permission.

The MSP/controller identity still needs a separately reviewed permission to
`sts:AssumeRole` into the prepared controller role. No trust principal or
credential is inferred here. Before deployment, confirm the runtime caller ARN,
principal trust, transaction-level `LeadingKeys` evaluation in IAM simulation,
and the actual table/role ARNs. The application state machine rejects actors
outside its exact configured allowlists, but production wiring must obtain the
identity from STS and must not accept a caller-supplied actor field.

## Lease timing and operational configuration

The table is created only when `enable_dump_restore_lease_store=true`. Enabling
it also requires explicit values for:

- `dump_restore_lease_ttl_seconds`
- `dump_restore_lease_renew_interval_seconds`
- `dump_restore_lease_max_duration_seconds`
- `dump_restore_lease_controller_principal_arns`

The interval must be shorter than the lease, the maximum must be at least one
lease long, and the maximum cannot exceed the seven-day guardrail. The actual
values must be based on measured restore duration, Lambda timeout/retry behavior,
and heartbeat-loss tolerance before any apply. No timing default is active.

## Required next-phase retry and alert contract

Before connecting the 19:00 Lambda or restore controller, implement and test all
of the following in that separate phase:

1. Start the Dump lease **before** the first operation that uses the Web EC2 as
   an SSH jump host. Abort before SSH/restore work if lease acquisition or a
   strongly consistent state read fails.
2. Renew at the configured interval; stop initiating new restore steps when a
   renewal fails. Record terminal success/failure in a `finally`-safe path, but
   never release an expired lease.
3. Give every scheduled shutdown attempt a stable unique event/operation ID.
   If a valid Dump lease exists, persist `SHUTDOWN_PENDING`; return without DNS
   or EC2 side effects. Repeated invocation with the same ID must be idempotent.
4. After the Dump owner releases a pending lease, retry the shutdown claim and
   re-read state before DNS restoration and again before each EC2 stop. Use
   bounded retry/backoff with an EventBridge retry/DLQ or equivalent durable
   retry path, plus a CloudWatch alarm for pending/expired claims and exhausted
   retries. A pending shutdown must never be considered complete until DNS
   readback and the expected stop result are confirmed.
5. Check the separate promoted-service-DB protection before shutdown. A lease
   must not override a promoted DB, an active DR policy, or any existing safety
   guard.
6. Define and test operator reconciliation for an expired `DUMP_ACTIVE`,
   `SHUTDOWN_PENDING`, or `SHUTDOWN_CLAIMED` record. It must prove the owner is
   quiescent, preserve audit history, and use a conditional transaction; do not
   delete the control row or rely on DynamoDB TTL.

Until that integration is separately reviewed and applied, the existing 19:00
Lambda continues its current behavior and does not consult this table. This
foundation alone cannot prevent the current Lambda from stopping EC2 or changing
DNS during a Dump operation.
