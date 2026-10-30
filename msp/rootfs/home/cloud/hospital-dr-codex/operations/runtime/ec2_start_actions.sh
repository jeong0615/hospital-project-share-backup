#!/usr/bin/env bash

# Apply only the start actions from an already validated EC2 inventory JSON.
# This helper never stops or restarts an instance. If an approved instance is
# already stopping, it waits for that transition to finish, verifies the same
# approved identity and state again, then starts only instances now stopped.

dr_ec2_wait_stopping_instances() {
  local region="$1" timeout_seconds="${DR_EC2_STOPPING_WAIT_SECONDS:-180}"
  shift
  local instance_id deadline remaining

  if ! [[ "$timeout_seconds" =~ ^[0-9]{1,3}$ ]] \
      || (( 10#$timeout_seconds < 1 || 10#$timeout_seconds > 300 )); then
    echo "[EC2 START ERROR] DR_EC2_STOPPING_WAIT_SECONDS must be between 1 and 300." >&2
    return 1
  fi
  if ! command -v timeout >/dev/null 2>&1; then
    echo "[EC2 START ERROR] A bounded timeout command is required to wait for EC2 stop transitions." >&2
    return 1
  fi

  deadline=$((SECONDS + 10#$timeout_seconds))
  for instance_id in "$@"; do
    remaining=$((deadline - SECONDS))
    if (( remaining < 1 )); then
      echo "[EC2 START BLOCKED] Stop transition wait exceeded ${timeout_seconds}s." >&2
      return 1
    fi
    echo "[EC2 START] Waiting up to ${remaining}s for the stop transition to finish: ${instance_id}."
    if ! timeout --foreground --signal=TERM --kill-after=5s "${remaining}s" \
        aws ec2 wait instance-stopped --region "$region" --instance-ids "$instance_id"; then
      echo "[EC2 START BLOCKED] ${instance_id} did not reach stopped within the bounded wait." >&2
      return 1
    fi
  done
}

dr_ec2_start_instances_safely() {
  local region="$1" inventory_json="$2" only_role="${3:-}" plan_file full_plan_file row role instance_id state action
  local refreshed_plan_file refresh_needed=0
  local -a start_ids=() pending_ids=() stopping_ids=()
  local -a approved_ids=()
  local -a role_args=()
  local plan_script="${DR_EC2_START_PLAN:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/ec2_start_plan.py}"

  if [ -n "$only_role" ]; then
    case "$only_role" in
      Hospital-Real-Web-Server|Hospital-DR-Doc-Server|Hospital-DR-DB-Server) role_args=(--role "$only_role") ;;
      *) echo "[EC2 START ERROR] Refusing unknown role filter." >&2; return 1 ;;
    esac
  fi
  full_plan_file="$(mktemp)" || return 1
  if ! printf '%s\n' "$inventory_json" | python3 "$plan_script" >"$full_plan_file"; then
    rm -f -- "$full_plan_file"
    return 1
  fi
  while IFS=$'\t' read -r role instance_id state action; do
    [ -n "$instance_id" ] || continue
    approved_ids+=("$instance_id")
  done < "$full_plan_file"
  rm -f -- "$full_plan_file"

  plan_file="$(mktemp)" || return 1
  if ! printf '%s\n' "$inventory_json" | python3 "$plan_script" "${role_args[@]}" >"$plan_file"; then
    rm -f -- "$plan_file"
    return 1
  fi

  while IFS=$'\t' read -r role instance_id state action; do
    [ -n "$instance_id" ] || continue
    case "$state" in
      running) : ;;
      stopped) start_ids+=("$instance_id") ;;
      pending) pending_ids+=("$instance_id") ;;
      stopping) stopping_ids+=("$instance_id") ;;
      *)
        rm -f -- "$plan_file"
        echo "[EC2 START ERROR] Refusing unsafe state for ${role}: ${state}." >&2
        return 1
        ;;
    esac
  done < "$plan_file"
  rm -f -- "$plan_file"

  if ((${#stopping_ids[@]})); then
    dr_ec2_wait_stopping_instances "$region" "${stopping_ids[@]}" || return 1
    refresh_needed=1
  fi

  for instance_id in "${pending_ids[@]}"; do
    echo "[EC2 START] Waiting for already-pending instance: ${instance_id}."
    aws ec2 wait instance-running --region "$region" --instance-ids "$instance_id" || return 1
    refresh_needed=1
  done

  if [ "$refresh_needed" = "1" ]; then
    inventory_json="$(aws ec2 describe-instances --region "$region" \
      --instance-ids "${approved_ids[@]}" --output json)" || {
      echo "[EC2 START ERROR] Could not re-read approved instance identities after lifecycle wait." >&2
      return 1
    }
    refreshed_plan_file="$(mktemp)" || return 1
    if ! printf '%s\n' "$inventory_json" \
        | python3 "$plan_script" "${role_args[@]}" >"$refreshed_plan_file"; then
      rm -f -- "$refreshed_plan_file"
      return 1
    fi
    start_ids=()
    pending_ids=()
    stopping_ids=()
    while IFS=$'\t' read -r role instance_id state action; do
      [ -n "$instance_id" ] || continue
      case "$state" in
        running) : ;;
        stopped) start_ids+=("$instance_id") ;;
        pending) pending_ids+=("$instance_id") ;;
        stopping) stopping_ids+=("$instance_id") ;;
        *)
          rm -f -- "$refreshed_plan_file"
          echo "[EC2 START ERROR] Refusing unsafe state for ${role}: ${state}." >&2
          return 1
          ;;
      esac
    done < "$refreshed_plan_file"
    rm -f -- "$refreshed_plan_file"
    if ((${#stopping_ids[@]} || ${#pending_ids[@]})); then
      echo "[EC2 START BLOCKED] Approved instance lifecycle states did not settle after read-back." >&2
      return 1
    fi
    if [ "${DR_EC2_RECHECK_APPROVAL_ON_WAIT:-0}" = "1" ]; then
      if ! declare -F dr_verify_chatops_failover_launch >/dev/null 2>&1 \
          || ! dr_verify_chatops_failover_launch; then
        echo "[EC2 START BLOCKED] ChatOps approval could not be reverified after the lifecycle wait." >&2
        return 1
      fi
    fi
  fi

  for instance_id in "${start_ids[@]}"; do
    echo "[EC2 START] Starting stopped instance only: ${instance_id}."
    aws ec2 start-instances --region "$region" --instance-ids "$instance_id" >/dev/null || return 1
  done
}
