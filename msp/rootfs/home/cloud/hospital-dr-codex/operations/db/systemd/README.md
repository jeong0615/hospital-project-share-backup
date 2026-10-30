# DB backup schedules

These unit files are deployment templates. They are not installed by the
repository and do not change the current MSP or On-Premise scheduler.

The two timers are intentionally offset:

| System | Timer | Schedule |
| --- | --- | --- |
| On-Premise DB server | `hospital-dr-db-backup.timer` | Every hour at `:00` and `:30` |
| MSP S3 uploader | `hospital-dr-s3-upload.timer` | Every hour at `:05` and `:35` |

The five-minute offset gives the On-Premise dump and SSH/SCP transfer time to
finish before the MSP uploader scans `/home/cloud/db_backups`. The uploader's
`AccuracySec=30s` setting bounds normal timer dispatch jitter without
collapsing the offset.

## On-Premise DB server

Install `hospital-dr-db-backup.service` and
`hospital-dr-db-backup.timer` after placing `db_backup.sh` and the protected
`dr.env` at the paths expected by the service. Then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hospital-dr-db-backup.timer
systemctl list-timers hospital-dr-db-backup.timer
```

## MSP uploader

Install `hospital-dr-s3-upload.service` and
`hospital-dr-s3-upload.timer` only after the dedicated S3 profile and the
required `S3_BACKUP_*` values are configured in the MSP secret file
`/home/cloud/hospital-dr-secrets/dr.env`. The service unit explicitly sets
`DR_SECRET_FILE` to that external path; the secret file is not stored in this
repository. Manual runs may still override it with `DR_SECRET_FILE`. The
uploader uses `S3_BACKUP_SOURCE_DIR` when set and otherwise reads the actual
MSP staging directory `/home/cloud/db_backups`.

For each complete local set, it checks exact S3 keys with
`s3api list-objects-v2` and never overwrites an existing object. Manifest
sets are validated locally and uploaded as dump, `.master_status`, then
Manifest (the Manifest is the completeness marker). During rollout, a valid
local legacy dump/status pair without a Manifest is still delivered as an
unverified pair to preserve the existing backup flow; no Manifest is attached
to it, and Preflight/ChatOps/restore continue to reject it as verified. The
uploader performs no object reads, so its role needs bucket-list and
object-write permissions only. Read-back verification is a separate step
using the restore/read-only role. Then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hospital-dr-s3-upload.timer
systemctl list-timers hospital-dr-s3-upload.timer
```

Both scripts use `flock`; incomplete or invalid local pairs are skipped. A
partial pre-existing remote set is not overwritten or automatically
reconciled.
