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

For each complete dump/status pair, it checks the exact S3 keys with
`s3api list-objects-v2` and uploads only missing objects. It performs no object
reads; the existing least-privilege design therefore needs bucket-list and
object-write permissions only. Then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hospital-dr-s3-upload.timer
systemctl list-timers hospital-dr-s3-upload.timer
```

Both scripts use `flock`, and the S3 uploader skips incomplete or invalid
local pairs and pairs whose two exact S3 keys already exist.
