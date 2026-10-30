# Backup Manifest rollout and Canary plan

Status: preparation only. No service, timer, database, or S3 object was changed.

## Read-only findings (2026-10-16)

- The MSP uploader runs from `/home/cloud/scripts/s3_backup_upload.sh`; its
  SHA-256 differs from Canonical `operations/db/s3_backup_upload.sh`
  (`2e2954…` installed, `1133a8…` Canonical). The installed directory does
  not contain `backup_manifest.py`.
- The installed MSP upload timer is loaded, enabled, and active at
  `:05`/`:35`; its service is a oneshot. The checked host does not have the
  On-Prem `hospital-dr-db-backup.timer` or the unit's expected
  `/opt/hospital-dr/operations/db/db_backup.sh` path, so the producer host's
  deployed code and timer state remain unverified.
- MSP ChatOps `chatops_core.py` and `emergency_dr.py` hashes differ from
  Canonical; `rto_timeline.py` matches. The ChatOps sync dry-run passed and
  reports only those two files. Its allowlist now includes `emergency_dr.py`,
  so the same backup/rollback mechanism covers Manifest-aware selection.
- The Canonical producer defaults its SCP destination to
  `/var/lib/hospital-dr/db_backups`; the MSP uploader defaults its source to
  `/home/cloud/db_backups`. The MSP secret-file variable names do not include
  `S3_BACKUP_SOURCE_DIR`; the On-Prem secret file was not available to inspect.
  Confirm the actual transfer destination and uploader source refer to the
  same staging directory before a Canary. The two defaults are not equal.
- The producer currently sets `StrictHostKeyChecking=no` for SCP/SSH. Confirm
  the approved host-key/authentication arrangement before deploying or
  running it; do not treat successful transfer as host identity proof.
- S3 Preflight checks object inventory/metadata and Sidecar/Manifest fields,
  but leaves the encrypted payload as `PENDING_LIVE_TEST`. The restore executor
  validates a local staged set before transferring the encrypted dump and
  Sidecar to the DB host. S3 read-back/hash verification is a separate step.
- `RESTORE_AWS_PROFILE` is now a named role profile for S3 staging only. The
  existing local restore executor does not call AWS or consume that profile; it
  requires the already-staged artifacts under `DUMP_BACKUP_DIR`. This role
  connection therefore proves read authorization, not end-to-end restore.

## Deployment order after separate approval

Do not change either timer. Use a maintenance window after confirming that no
backup or upload oneshot is active, and finish before the next producer run.

1. Confirm the producer host's actual unit, script path, secret-file path,
   known-hosts/authentication, and staging destination. This host could not
   verify those remote facts.
2. On MSP, back up the current uploader into a private, timestamped directory;
   install the helper beside it, then atomically replace the uploader. The
   helper must be readable by `cloud`; uploader remains `0700 cloud:cloud`.
   The updated uploader preserves delivery of legacy pairs without a Manifest
   but never labels them verified or attaches a Manifest to existing S3
   objects.
3. On the confirmed producer host, back up the current script and install
   `db_backup.sh` plus its adjacent `backup_manifest.py`. Keep the existing
   `.master_status`. Verify the actual producer staging destination matches
   the MSP uploader source before allowing the next scheduled run.
4. After one scheduled new-format backup and upload, verify the local set,
   then read the exact three S3 objects under the approved restore/read-only
   role and run the local Manifest verifier. Do not use the uploader-only
   profile if it lacks `GetObject`. Do not use ETag as a SHA-256 substitute.
5. Only after the Canary passes, deploy the consumer path: Preflight/restore
   code from the approved repository release and ChatOps via
   `operations/runtime/sync_chatops_runtime.sh --dry-run`; review its complete
   file list, then use `--restart` only after separate approval. Existing
   Sidecar-only backups remain Legacy and are not retroactively amended.

The MSP-side uploader install/rollback pattern (commands are not run here):

```bash
set -euo pipefail
release_backup="/home/cloud/scripts/backups/manifest-cutover-$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -o cloud -g cloud -m 0700 "$release_backup"
sudo cp -a /home/cloud/scripts/s3_backup_upload.sh "$release_backup/"

helper_tmp="$(sudo mktemp /home/cloud/scripts/.backup_manifest.py.XXXXXX)"
sudo install -o cloud -g cloud -m 0644 \
  /home/cloud/hospital-dr-codex/operations/db/backup_manifest.py "$helper_tmp"
sudo mv -T "$helper_tmp" /home/cloud/scripts/backup_manifest.py

uploader_tmp="$(sudo mktemp /home/cloud/scripts/.s3_backup_upload.sh.XXXXXX)"
sudo install -o cloud -g cloud -m 0700 \
  /home/cloud/hospital-dr-codex/operations/db/s3_backup_upload.sh "$uploader_tmp"
sudo mv -T "$uploader_tmp" /home/cloud/scripts/s3_backup_upload.sh
bash -n /home/cloud/scripts/s3_backup_upload.sh
python3 /home/cloud/scripts/backup_manifest.py --help >/dev/null
```

Rollback the MSP uploader only if the recorded backup directory contains the
old file; leave the timer and all uploaded objects untouched:

```bash
set -euo pipefail
release_backup='/home/cloud/scripts/backups/manifest-cutover-<recorded-UTC-stamp>'
test -s "$release_backup/s3_backup_upload.sh"
uploader_tmp="$(sudo mktemp /home/cloud/scripts/.s3_backup_upload.sh.rollback.XXXXXX)"
sudo install -o cloud -g cloud -m 0700 \
  "$release_backup/s3_backup_upload.sh" "$uploader_tmp"
sudo mv -T "$uploader_tmp" /home/cloud/scripts/s3_backup_upload.sh
bash -n /home/cloud/scripts/s3_backup_upload.sh
```

The producer's deployment/rollback command is intentionally not prescribed
until the actual On-Prem host, deployed unit, release transport, ownership,
and host-key path are read back. The expected unit template target alone is
not evidence that `/opt/hospital-dr/operations/db` exists there.

## Restore Reader staging handoff

For a backup that is not already in the MSP restore directory, use the
read-only `RESTORE_AWS_PROFILE`/`RESTORE_AWS_ROLE_ARN` and the exact
Dump, Sidecar, and Manifest digests obtained from a trusted producer receipt
and separately pinned for the request. The helper checks supplied digests but
does not authenticate their origin or perform ChatOps approval.
`operations/db/s3_backup_stage.py` verifies the assumed Reader Role, Head/Get
sizes, the pinned Manifest SHA-256, the exact three object keys under
`mysql/hospital_db`, ciphertext and Sidecar hashes, and Manifest/Sidecar
binlog coordinates before installing the set without overwriting existing
files. It writes a mode-0600 provenance receipt and reports RPO as
`NOT_MEASURED`; it never decrypts or restores the Dump. Sidecar-only legacy
objects are rejected.

The target `DUMP_BACKUP_DIR` must be an existing, non-symlink directory owned
by the ChatOps execution user with mode `0700`. Do not change permissions on
the existing `/home/cloud/db_backups` (`0775`). Instead, use a dedicated
restore-only directory and point the existing ChatOps environment at it during
an approved configuration window:

```bash
sudo install -d -o cloud -g cloud -m 0700 /home/cloud/db_restore_stage
stat -c '%U:%G %a %n' /home/cloud/db_restore_stage
```

The protected environment file consumed by ChatOps must contain:

```dotenv
DUMP_BACKUP_DIR=/home/cloud/db_restore_stage
```

Read back the effective runtime value and directory owner/mode before
staging. Applying an environment-file change may require a ChatOps restart;
first verify there are no active requests or locks and follow the approved
runtime procedure. This document change does not create the directory, edit
the environment file, or restart the service. Do not run with shell xtrace
enabled. Example after that precondition and after the three hashes are pinned:

```bash
set -euo pipefail
set +x
set -a
source /home/cloud/hospital-dr-secrets/dr.env
set +a
python3 /home/cloud/hospital-dr-codex/operations/db/s3_backup_stage.py \
  --backup-id 'db_backup_<UTC-stamp>.sql.gz.enc' \
  --expected-sha256 '<pinned-ciphertext-sha256>' \
  --expected-sidecar-sha256 '<pinned-sidecar-sha256>' \
  --expected-manifest-sha256 '<pinned-manifest-sha256>'
```

The staged files then become visible to the existing local ChatOps inventory;
that approval and restore path still performs its own validation. The receipt
records `chatops_approval_binding=NOT_PERFORMED`; it is provenance, not
approval, and does not change the RPO gate.

## One-Canary verification

Run only after approval, after both producer and uploader are installed, and
let the existing schedule produce one new backup. Record the backup ID and
the three local digests from the protected staging directory; do not print or
open SQL content. The producer's `BACKUP_MANIFEST=CREATED` alone is not a
verification result.

On the MSP, verify the exact local set:

```bash
set -euo pipefail
backup_id='db_backup_<UTC-stamp>.sql.gz.enc'
base="${backup_id%.sql.gz.enc}"
dir='/home/cloud/db_backups'
python3 /home/cloud/hospital-dr-codex/operations/db/backup_manifest.py verify \
  --dump "$dir/$backup_id" \
  --sidecar "$dir/$base.master_status" \
  --manifest "$dir/$base.manifest.json" \
  --expected-object-prefix 'mysql/hospital_db' \
  --expected-sha256 '<pinned-ciphertext-sha256>' \
  --expected-sidecar-sha256 '<pinned-sidecar-sha256>' \
  --expected-manifest-sha256 '<pinned-manifest-sha256>'
```

For S3 read-back, use the explicit restore/read-only profile and expected role
ARN (never the uploader-only profile). After substituting the new backup ID
and producer-side pinned hashes, the command is:

```bash
set -euo pipefail
source /home/cloud/hospital-dr-secrets/dr.env
: "${S3_BACKUP_BUCKET:?protected config must provide the bucket}"
: "${RESTORE_AWS_PROFILE:?set the already-approved restore/read-only profile}"
: "${RESTORE_AWS_ROLE_ARN:?set the expected role ARN through the approved local config}"
if [[ "$RESTORE_AWS_PROFILE" == "${S3_BACKUP_AWS_PROFILE:-}" ]]; then
  echo 'BLOCKED: uploader profile is not an approved read-back identity' >&2
  exit 2
fi
region="${AWS_REGION:-ap-northeast-2}"
restore_aws() {
  env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
    aws --profile "$RESTORE_AWS_PROFILE" --region "$region" "$@"
}
if [[ ! "$RESTORE_AWS_ROLE_ARN" =~ ^arn:aws:iam::([0-9]{12}):role/([^/]+)$ ]]; then
  echo 'BLOCKED: expected restore role ARN is invalid' >&2
  exit 2
fi
restore_account="${BASH_REMATCH[1]}"
restore_role_name="${BASH_REMATCH[2]}"
actual_account="$(restore_aws sts get-caller-identity --query Account --output text)"
actual_arn="$(restore_aws sts get-caller-identity --query Arn --output text)"
expected_assumed_role_prefix="arn:aws:sts::${restore_account}:assumed-role/${restore_role_name}/"
[[ "$actual_account" == "$restore_account" && "$actual_arn" == "$expected_assumed_role_prefix"* ]] || {
  echo 'BLOCKED: AWS identity does not match the approved restore role' >&2
  exit 2
}

backup_id='db_backup_<UTC-stamp>.sql.gz.enc'
base="${backup_id%.sql.gz.enc}"
prefix="${S3_BACKUP_PREFIX:-mysql/hospital_db}"
verify_dir="$(mktemp -d /tmp/hospital-dr-manifest-canary.XXXXXX)"
chmod 0700 "$verify_dir"
cleanup() {
  case "$verify_dir" in
    /tmp/hospital-dr-manifest-canary.*) rm -rf -- "$verify_dir" ;;
    *) echo 'BLOCKED: unsafe temporary path; manual cleanup required' >&2 ;;
  esac
}
trap cleanup EXIT

restore_aws s3 cp \
  "s3://${S3_BACKUP_BUCKET}/${prefix}/${backup_id}" "$verify_dir/$backup_id" --only-show-errors
restore_aws s3 cp \
  "s3://${S3_BACKUP_BUCKET}/${prefix}/${base}.master_status" \
  "$verify_dir/$base.master_status" --only-show-errors
restore_aws s3 cp \
  "s3://${S3_BACKUP_BUCKET}/${prefix}/${base}.manifest.json" \
  "$verify_dir/$base.manifest.json" --only-show-errors

python3 /home/cloud/hospital-dr-codex/operations/db/backup_manifest.py verify \
  --dump "$verify_dir/$backup_id" \
  --sidecar "$verify_dir/$base.master_status" \
  --manifest "$verify_dir/$base.manifest.json" \
  --expected-object-prefix "$prefix" \
  --expected-sha256 '<pinned-ciphertext-sha256>' \
  --expected-sidecar-sha256 '<pinned-sidecar-sha256>' \
  --expected-manifest-sha256 '<pinned-manifest-sha256>'
```

Require all three exact objects, `BACKUP_MANIFEST=VERIFIED`,
`BINLOG_COORDINATES=PASS`, and matching pinned hashes. Confirm the Manifest
still reports `data_reference_at=null` and evidence `UNVERIFIED`; this Canary
does not prove decrypt/SQL restore or RPO. The dedicated restore profile and
role ARN are configured in the protected MSP environment; IAM authorization
is separately recorded PASS in `docs/DR_STATUS.md`.

## RPO

The checked-in timers are dump `:00`/`:30` and upload `:05`/`:35`; with NR
disabled this cannot guarantee 15 minutes. Keep RPO `NOT_MEASURED` until a
trusted consistent-data cutoff is available. Use verified NR position/lag as
the preferred path, or evaluate a dump cadence of at most 5 minutes with an
upload/verification completion bound of at most 3 minutes. These are proposed
engineering limits, not achieved RPO; validate consistency, workload, upload,
and restore behavior before any timer or DB change.
