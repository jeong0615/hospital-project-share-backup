#!/usr/bin/env bash
set -euo pipefail

# Read-only comparison between the canonical repository and installed/runtime
# copies.  Secrets, Terraform state, tfvars, generated files, and databases
# are deliberately outside this manifest.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"

case "${1:---check}" in
  --check) ;;
  *)
    echo "Usage: $0 [--check]" >&2
    exit 2
    ;;
esac

CANONICAL_ROOT="${DR_REPO_ROOT}"
RUNTIME_CHATOPS_DIR="${DR_RUNTIME_CHATOPS_DIR:-/home/cloud/dr_project}"
RUNTIME_SOURCE_REPO="${DR_RUNTIME_SOURCE_REPO:-$CANONICAL_ROOT}"
RUNTIME_FINOPS_DIR="${DR_RUNTIME_FINOPS_DIR:-$CANONICAL_ROOT/operations/finops}"
RUNTIME_SYSTEMD_DIR="${DR_RUNTIME_SYSTEMD_DIR:-/etc/systemd/system}"
RUNTIME_GRAFANA_DASHBOARD_DIR="${DR_RUNTIME_GRAFANA_DASHBOARD_DIR:-/home/cloud/grafana/provisioning/dashboards/json}"
ZABBIX_COMPOSE_FILE="${DR_ZABBIX_COMPOSE_FILE:-/home/cloud/zabbix/docker-compose.yml}"

drift_count=0

check_pair() {
  local label="$1"
  local source_path="$2"
  local runtime_path="$3"
  local required="${4:-true}"

  if [ ! -f "$source_path" ]; then
    echo "[RUNTIME DRIFT] canonical file is missing: $label ($source_path)"
    [ "$required" = "true" ] && drift_count=$((drift_count + 1))
  elif [ ! -f "$runtime_path" ]; then
    if [ "$required" = "true" ]; then
      echo "[RUNTIME DRIFT] installed file is missing: $label ($runtime_path)"
      drift_count=$((drift_count + 1))
    else
      echo "[RUNTIME NOTICE] optional installed file is not present: $label ($runtime_path)"
    fi
  elif ! cmp -s "$source_path" "$runtime_path"; then
    if [ "$required" = "true" ]; then
      echo "[RUNTIME DRIFT] file differs: $label ($runtime_path)"
      drift_count=$((drift_count + 1))
    else
      echo "[RUNTIME NOTICE] optional file differs: $label ($runtime_path)"
    fi
  else
    echo "[RUNTIME MATCH] $label"
  fi
}

echo "[RUNTIME CHECK] canonical root: $CANONICAL_ROOT"
echo "[RUNTIME CHECK] operational source root: $RUNTIME_SOURCE_REPO"
echo "[RUNTIME CHECK] read-only; secret/state/generated files are excluded."

check_pair \
  "runtime/runtime_paths.sh" \
  "$CANONICAL_ROOT/operations/runtime_paths.sh" \
  "$RUNTIME_SOURCE_REPO/operations/runtime_paths.sh"

check_pair \
  "runtime/dr_state.sh" \
  "$CANONICAL_ROOT/operations/runtime/dr_state.sh" \
  "$RUNTIME_SOURCE_REPO/operations/runtime/dr_state.sh"

check_pair \
  "failover/dns_transaction.sh" \
  "$CANONICAL_ROOT/operations/failover/dns_transaction.sh" \
  "$RUNTIME_SOURCE_REPO/operations/failover/dns_transaction.sh"

check_pair \
  "cloudflare_ssm_auth.sh" \
  "$CANONICAL_ROOT/operations/cloudflare_ssm_auth.sh" \
  "$RUNTIME_SOURCE_REPO/operations/cloudflare_ssm_auth.sh"

for name in \
  app.py \
  wsgi.py \
  chatops_audit.py \
  chatops_core.py \
  wazuh_alerts.py \
  wazuh_correlation.py \
  wazuh_failback_gate.py \
  wazuh_live_provider.py \
  rto_timeline.py \
  zabbix_alerts.py \
  zabbix_host_proxy.py; do
  check_pair \
    "chatops/$name" \
    "$CANONICAL_ROOT/operations/chatops/$name" \
    "$RUNTIME_CHATOPS_DIR/$name"
done

# The Zabbix container bind-mounts these scripts from /home/cloud rather than
# from the ChatOps runtime directory.  Validate the effective compose mount
# contract when that deployment exists; do not flag the intentional wrapper
# or the canonical guard mount as false drift.
RUNTIME_ZABBIX_ALERTS_DIR="${DR_RUNTIME_ZABBIX_ALERTS_DIR:-/home/cloud}"
if [ -r "$ZABBIX_COMPOSE_FILE" ] \
  && grep -Fq "$RUNTIME_ZABBIX_ALERTS_DIR/send_failback.sh:/usr/lib/zabbix/alertscripts/send_failback.sh:ro" "$ZABBIX_COMPOSE_FILE" \
  && grep -Fq "$CANONICAL_ROOT/operations/db/zabbix_failback_guard.sh:/usr/lib/zabbix/alertscripts/zabbix_failback_guard.sh:ro" "$ZABBIX_COMPOSE_FILE" \
  && [ -x "$RUNTIME_ZABBIX_ALERTS_DIR/send_failback.sh" ] \
  && grep -Fq "exec bash $CANONICAL_ROOT/operations/chatops/send_failback.sh \"\$@\"" "$RUNTIME_ZABBIX_ALERTS_DIR/send_failback.sh" \
  && [ -x "$CANONICAL_ROOT/operations/db/zabbix_failback_guard.sh" ]; then
  echo "[RUNTIME MATCH] zabbix-alertscript/compose-bind-mounts"
  bash -n "$RUNTIME_ZABBIX_ALERTS_DIR/send_failback.sh"
  bash -n "$CANONICAL_ROOT/operations/db/zabbix_failback_guard.sh"
else
  for name in send_slack.sh send_failback.sh; do
    check_pair \
      "zabbix-alertscript/$name" \
      "$CANONICAL_ROOT/operations/chatops/$name" \
      "$RUNTIME_ZABBIX_ALERTS_DIR/$name"
  done
  check_pair \
    "zabbix-alertscript/zabbix_failback_guard.sh" \
    "$CANONICAL_ROOT/operations/db/zabbix_failback_guard.sh" \
    "${DR_RUNTIME_ZABBIX_GUARD_FILE:-/home/cloud/zabbix_failback_guard.sh}"
fi

for source_path in "$CANONICAL_ROOT"/operations/finops/*.sh; do
  [ -f "$source_path" ] || continue
  name="${source_path##*/}"
  check_pair "finops/$name" "$source_path" "$RUNTIME_FINOPS_DIR/$name"
done

for source_path in \
  "$CANONICAL_ROOT"/operations/chatops/systemd/*.service \
  "$CANONICAL_ROOT"/operations/db/systemd/*.service \
  "$CANONICAL_ROOT"/operations/db/systemd/*.timer \
  "$CANONICAL_ROOT"/infra/terraform/systemd/*.service; do
  [ -f "$source_path" ] || continue
  name="${source_path##*/}"
  case "$name" in
    hospital-dr-chatops-tunnel.service|hospital-dr-db-backup.service|hospital-dr-db-backup.timer)
      check_pair "systemd/$name" "$source_path" "$RUNTIME_SYSTEMD_DIR/$name" false
      ;;
    *)
      check_pair "systemd/$name" "$source_path" "$RUNTIME_SYSTEMD_DIR/$name"
      ;;
  esac
done

for source_path in \
  "$CANONICAL_ROOT"/operations/security/systemd/*.service \
  "$CANONICAL_ROOT"/operations/security/systemd/*.timer; do
  [ -f "$source_path" ] || continue
  name="${source_path##*/}"
  check_pair \
    "systemd/user/$name" \
    "$source_path" \
    "${DR_RUNTIME_SYSTEMD_USER_DIR:-/home/cloud/.config/systemd/user}/$name"
done

for source_path in "$CANONICAL_ROOT"/monitoring/grafana/provisioning/dashboards/json/*.json; do
  [ -f "$source_path" ] || continue
  name="${source_path##*/}"
  check_pair \
    "grafana/dashboard/$name" \
    "$source_path" \
    "$RUNTIME_GRAFANA_DASHBOARD_DIR/$name"
done

for source_path in "$CANONICAL_ROOT"/monitoring/grafana/provisioning/datasources/*.yml; do
  [ -f "$source_path" ] || continue
  name="${source_path##*/}"
  check_pair \
    "grafana/datasource/$name" \
    "$source_path" \
    "${DR_RUNTIME_GRAFANA_DATASOURCE_DIR:-/home/cloud/grafana/provisioning/datasources}/$name"
done

if [ "$drift_count" -ne 0 ]; then
  printf 'RUNTIME_SOURCE_READY=false\n'
  printf '[RUNTIME CHECK] drift_or_missing=%s\n' "$drift_count"
  exit 1
fi

printf 'RUNTIME_SOURCE_READY=true\n'
echo "[RUNTIME CHECK] canonical and installed manifests match."
