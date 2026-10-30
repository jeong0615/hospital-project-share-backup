#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="hospital-dr-zabbix-server:6.0-python3"
SENDER="$ROOT/operations/chatops/send_slack.sh"
SMOKE="$ROOT/tests/zabbix_sender_image_smoke.py"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "IMAGE_TEST_BLOCKED=docker_daemon_unavailable_or_permission_denied" >&2
  exit 2
fi

docker build --pull \
  --file "$ROOT/monitoring/zabbix/Dockerfile.server" \
  --tag "$IMAGE" \
  "$ROOT/monitoring/zabbix"

SENDER_SHA256="$(sha256sum "$SENDER" | awk '{print $1}')"
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,exec,size=8m,uid=1997,gid=1995,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=bind,source=$SENDER,target=/usr/lib/zabbix/alertscripts/send_slack.sh,readonly" \
  --mount "type=bind,source=$SMOKE,target=/usr/local/lib/zabbix-sender-image-smoke.py,readonly" \
  --env "EXPECTED_SENDER_SHA256=$SENDER_SHA256" \
  --entrypoint /usr/bin/python3 \
  "$IMAGE" /usr/local/lib/zabbix-sender-image-smoke.py
