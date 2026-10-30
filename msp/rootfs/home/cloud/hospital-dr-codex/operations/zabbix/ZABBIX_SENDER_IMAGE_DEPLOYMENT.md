# Zabbix Sender Python runtime image

The Zabbix 6.0 PostgreSQL server service now builds a derived image from the
official Ubuntu image pinned by OCI index digest. It adds the Sender's runtime
commands (`python3`, `mawk`, `coreutils`, `bash`, `curl`, and CA certificates)
at image-build time. The image build verifies those commands and Python's
`json`, `hashlib`, and `hmac` modules, then restores the upstream `zabbix` UID
1997. It does not alter the upstream entrypoint or command.

The Compose change is limited to `zabbix-server`: PostgreSQL, the database
volume, environment files, Sender and auxiliary script bind mounts, DR state
mount, HMAC environment injection, published port, and Agent/Proxy services
remain as configured. The test image never reads Compose environment files.

## Build and isolated smoke test

From the repository root, on a host with Docker build/run permission:

```bash
bash operations/zabbix/test_sender_image.sh
```

This builds `hospital-dr-zabbix-server:6.0-python3` and runs only a disposable
container with `--network none`, a read-only root filesystem, dropped
capabilities, and a synthetic test-only HMAC key. A stub `curl` verifies the
serialized JSON and signature without sending a request. Expected output ends
with `SENDER_IMAGE_SMOKE=PASS`; no production secret is used.

## Production maintenance procedure (not run by this change)

Before a change, confirm the current image digest and retain a rollback tag for
the running server image. Keep Action 3 and Trigger 24712 disabled. Do not
recreate PostgreSQL or any other service.

```bash
cd /home/cloud/hospital-dr-codex
COMPOSE='docker compose -f monitoring/zabbix/docker-compose.yml'
CID="$($COMPOSE ps -q zabbix-server)"
test -n "$CID"
OLD_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$CID")"
ROLLBACK_TAG="hospital-dr-zabbix-server:rollback-$(date +%Y%m%d%H%M%S)"
docker image tag "$OLD_IMAGE_ID" "$ROLLBACK_TAG"
printf 'ZABBIX_ROLLBACK_IMAGE_TAG=%s\n' "$ROLLBACK_TAG"
$COMPOSE config --quiet
$COMPOSE build --pull zabbix-server
```

Run the isolated smoke test before the maintenance window. At the approved
window, recreate only the server service, without dependencies:

```bash
$COMPOSE up --no-build -d --no-deps --force-recreate zabbix-server
$COMPOSE ps zabbix-server
CID="$($COMPOSE ps -q zabbix-server)"
docker exec "$CID" sh -c 'python3 -c "import json,hashlib,hmac" && echo PYTHON3=AVAILABLE'
docker exec "$CID" sh -c 'test -n "${ZABBIX_PRODUCTION_ACTION_HMAC_KEY:-}" && echo HMAC_ENV=SET'
HOST_SHA="$(sha256sum operations/chatops/send_slack.sh | awk '{print $1}')"
CONTAINER_SHA="$(docker exec "$CID" sha256sum /usr/lib/zabbix/alertscripts/send_slack.sh | awk '{print $1}')"
test "$HOST_SHA" = "$CONTAINER_SHA" && echo SENDER_CONTENT=MATCH
```

Then use Media Type 45's test function once. Confirm the test-only field
diagnostics and Slack test delivery; do not enable Action 3 or Trigger 24712.
Do not run a Production Action as a test.

## Rollback

If the server fails its health/startup checks or the approved non-execution
test fails, stop further changes and restore only the prior server image:

```bash
docker image tag "$ROLLBACK_TAG" hospital-dr-zabbix-server:6.0-python3
$COMPOSE up --no-build -d --no-deps --force-recreate zabbix-server
$COMPOSE ps zabbix-server
```

This does not restore or alter the PostgreSQL volume, environment files, or
ChatOps SQLite. Keep the rollback tag until service and Media Type checks are
accepted. If the recorded tag is unavailable, stop and do not pull an
unverified replacement image.

## Scope limitation

The current Codex session lacks permission to access `/var/run/docker.sock`.
No image was built and no operating container was recreated here. The
Dockerfile and isolated smoke command are ready, but image-environment PASS and
production replacement remain pending execution by an authorized Docker
operator.
