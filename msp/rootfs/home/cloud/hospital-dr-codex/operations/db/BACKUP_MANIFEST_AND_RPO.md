# Backup Manifest and RPO policy

This document describes the new backup evidence contract and a proposed path
to the 15-minute RPO target. It does not change production timers, MySQL, S3,
or replication configuration.

## Evidence contract

New encrypted dumps retain the existing `.master_status` sidecar and add a
JSON Manifest. The uploader publishes the dump and sidecar first and the
Manifest last. The Manifest binds the backup ID, object keys, ciphertext hash
and size, sidecar hash, MySQL binlog coordinates, and UTC backup timestamps.
Restore and preflight recompute the local ciphertext hash and validate the
sidecar/Manifest identity and coordinates. Sidecar-only archives are Legacy
and are not restore-verified; existing remote objects are never rewritten to
retrofit a Manifest.

`data_reference_at` is deliberately null with an unverified evidence status
until a trusted source proves the actual consistent data cutoff. Dump start or
completion time, upload time, and binlog coordinates are not sufficient on
their own. RPO is measured only from an independently verified incident time
to that authenticated recovered-data cutoff; missing evidence remains
`NOT_MEASURED`.

## Current cadence and implication

The checked-in systemd timers run dumps at minutes `00` and `30`, and uploads
at `05` and `35`. This is a nominal 30-minute dump cadence plus a 5-minute
upload offset. With `DB_NR_ENABLED=false`, this path cannot guarantee a
15-minute RPO. The schedule is not proof of actual upload completion,
recoverability, or data freshness.

## Proposed path to the target

1. Prefer NR only after the source/replica identity, running IO and SQL
   threads, applied position, bounded lag, and a trustworthy observation
   timestamp are verified. Record the last verified source data cutoff and
   fail closed when that evidence is stale or unavailable.
2. Keep Dump as a recovery fallback. If it must independently meet the target,
   propose a dump interval no greater than 5 minutes and an upload/verification
   completion bound no greater than 3 minutes. These are design limits, not a
   claim of achieved RPO; validate workload capacity, consistency, encryption,
   and restore duration before any operational schedule change.
3. For each candidate, require a trusted data-cutoff proof and successful
   object integrity/restore verification. Compute RPO from the incident time
   to that cutoff, not from file or upload timestamps. Report over-target as
   `RPO_NOT_GUARANTEED` and absent proof as `NOT_MEASURED`.

No production timer, replication, database, or S3 setting is changed by this
proposal.
