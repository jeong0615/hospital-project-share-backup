# Emergency DR ChatOps

The Emergency Console is a separate, private Slack channel surface for
creating a DR request when an automatic or ordinary approval message cannot be
used.  It does not grant authority by channel membership: every button and
modal submission is checked against `SLACK_ADMIN_USER_IDS`.

## Configuration

Set these values in the external `DR_SECRET_FILE`; do not commit the file or
tokens:

```text
SLACK_EMERGENCY_CHANNEL_ID=<private-channel-id>
# Set SLACK_EMERGENCY_BOT_TOKEN only in the external DR_SECRET_FILE.
# Set SLACK_EMERGENCY_SIGNING_SECRET only in the external DR_SECRET_FILE.
EMERGENCY_TTL_SECONDS=900
DUMP_BACKUP_DIR=/home/cloud/db_backups
DUMP_RESTORE_EXEC_ENABLED=false
DUMP_RESTORE_EXECUTOR=
```

The Emergency App is a separate Slack App named `ChatOps Emergency`.  It must
use its own bot token and signing secret; the runtime never falls back to the
Failover bot credential.  Configure its Interactivity Request URL to
`/slack/action`, invite it to the private `긴급승인` channel, and keep the
existing `SLACK_ADMIN_USER_IDS` allowlist.

The minimum Bot Token Scopes used by this implementation are:

- `chat:write` for the Console and request messages
- `pins:write` for pinning the Console

No `conversations.info`/channel-read scope is required.  If `pins:write` is
missing, the Console remains usable and the runtime records
`EMERGENCY_CONSOLE_PIN=SKIPPED_NO_PERMISSION`.

The Console contains exactly four controls: `상태 점검`, `긴급 Failover 요청`,
`긴급 Failback 요청`, and `긴급 Failover (Dump)`.  The status and Dump
controls use Slack's default button style, Failover uses `danger`, and
Failback uses `primary`; no custom Slack styling or emoji is used.

Manual Slack setup order:

1. Create/install the `ChatOps Emergency` App.
2. Configure `chat:write` and `pins:write`.
3. Enable Interactivity with the `/slack/action` callback URL.
4. Store the App bot token and signing secret only in the external
   `DR_SECRET_FILE`.
5. Invite the App to the private `긴급승인` channel and set its channel ID.
6. Restart ChatOps, then allow the existing cleanup worker to create and pin
   the Console.

The existing cleanup worker performs a read-only Emergency Console presence
check every 60 seconds and keeps the normal terminal-message cleanup interval
at 300 seconds. When the persisted message exists, the watchdog makes no
`chat.update` call, does not repin, and does not change the state record. It
creates and pins a replacement only when Slack reports the persisted message
is missing. Slack errors, including rate limits, are left for the next
60-second cycle and do not stop ChatOps.

## Request and approval policy

The console creates `EMERGENCY_FAILOVER` or `EMERGENCY_FAILBACK` requests with
a 15-minute TTL.  Emergency requests bypass automatic detection conditions,
not execution safety checks.  Existing two-distinct-admin approval,
cancel/withdraw, audit, global execution lock, and stale execution recovery
remain in force.  There is no single-admin or MFA path.

Failback requests remain visible when Wazuh is `UNKNOWN` or `BLOCKED`.
`UNKNOWN`/`BLOCKED` is shown as a warning and the approval handler performs a
fresh check; an unsafe request is reset/blocked rather than silently hiding
the request.

## Dump restore

`Dump 복구` inventories Manifest-verified backups and, as a separate manual
candidate, Legacy `.sql.gz.enc` files with a matching parseable `.master_status`
sidecar and OpenSSL `Salted__` marker, newest first (up to 20). Legacy is never
reported as Manifest PASS. The selection modal marks decryption/gzip as pending,
the sidecar as parsed with an unattested computed SHA-256, and RPO as
`NOT_MEASURED`. After a Legacy file is selected, ChatOps checks its checksum,
OpenSSL decryption, gzip stream, and sidecar again before showing confirmation;
failed checks create no request. Confirmation identifies the request as
`LEGACY_MANUAL`, shows the exact verification states, and preserves the
two-admin approval path. Legacy requests are never sent to the existing
`hospital_db` overwrite executor; they are manual separate-schema restore
targets only. Manifest candidates keep the existing flow. Neither selection
modal restores the database directly.
The selection and final confirmation modals are acknowledged immediately; the
selected file checksum and request/message delivery run asynchronously, then
update the same modal with the confirmation or outcome. This avoids Slack's
three-second interaction timeout without skipping checksum revalidation.
`DUMP_RESTORE_EXEC_ENABLED=false` is the default, so even two approvals cannot
run a restore until a separately reviewed executor is configured.  File paths,
passwords, tokens, and private keys are not written to Slack or the audit
record; the audit contains backup ID, timestamp, size/checksum metadata,
`request_origin`, and approval lifecycle fields.

There is currently no dedicated production ChatOps Dump executor in this
repository. `automation/ansible/roles/db_recovery/files/db_restore.sh` is used
by the broader database provisioning role; it is not by itself a ChatOps
executor or an AWS-target-attested restore workflow. Keep execution disabled.
Any future `DUMP_RESTORE_EXECUTOR` must be an absolute, readable executable
reviewed for the AWS DR DB target and must accept both `--backup-id` and
`--expected-sha256`; ChatOps revalidates the selected checksum before launch.
An executable path check does not certify the executor's behavior.

## Security escalation

Only an existing Wazuh destructive `CRITICAL` event affecting an important
hospital host is promoted to `SECURITY_DR_ESCALATION`.  Ordinary auth, FIM,
SCA, vulnerability, SQLi/XSS detection, or generic high-severity events remain
security alerts.  Security escalation still creates a two-admin approval and
never auto-executes a DR workflow.

## Safe contract checks

Use the repository test suite and a local test configuration.  Do not send a
real Slack message or invoke a live workflow while validating the feature.
