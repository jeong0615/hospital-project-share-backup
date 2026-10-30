# Temporary single-admin synthetic MySQL demo

Production Failover, Emergency Failover, Dump Restore, Failback, and Security
requests always require two distinct authorized administrators. Setting
`DR_APPROVAL_REQUIRED=1` does **not** reduce their quorum; the production
Failover preflight reports BLOCKED until the configured production quorum is
back to `2` with at least two authorized administrators.

The bounded one-admin window is accepted only by the localhost-only
`/chatops/synthetic-mysql-demo/request` endpoint. That request is bound in the
server-side SQLite store to the fixed synthetic Canary EC2, database
`hospital_demo`, and the hashed existing AWS MySQL roundtrip runner. It does
not invoke the production Failover shell, change production DR state, or alter
DNS. The one authorized Slack administrator still has to approve the exact
synthetic request; Codex or an operator must not manufacture an approval.

## Enable a short demo window

Use an explicitly scheduled, timezone-qualified deadline no more than four
hours in the future. Do not use this setting to request a production Failover.

```text
DR_APPROVAL_REQUIRED=1
DR_SINGLE_APPROVAL_TEST_EXPIRES_AT=<UTC ISO-8601 timestamp>
```

After the approved ChatOps configuration change and restart, verify the
bounded-mode audit event and that production preflight remains blocked for
this setting. With no other active request, an operator may ask the local
ChatOps service to create the fixed synthetic request:

```bash
curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  -d '{"confirm_synthetic_mysql_demo":true}' \
  http://IP_REDACTED:5000/chatops/synthetic-mysql-demo/request
```

The service returns one request ID and posts the request to Slack. Confirm the
message names the synthetic target and `hospital_demo`; only an authorized
administrator may approve it. Do not create another request while it is
pending or executing. A completed/failed request is not reused; inspect its
result and the pinned synthetic dataset before creating a new request.

## Revert

Immediately after the demo, restore the external configuration:

```text
DR_APPROVAL_REQUIRED=2
DR_SINGLE_APPROVAL_TEST_EXPIRES_AT=
```

Restart only through the approved ChatOps deployment procedure, then verify
the disable audit event, two-admin production preflight contract, and expiry
of unfinished synthetic one-admin requests. Do not roll back or modify the
operational SQLite database to revert this setting.
