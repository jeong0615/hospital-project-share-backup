#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../runtime_paths.sh"

mkdir -p "$HOME/scripts"
exec > >(tee -a "$HOME/scripts/dr_log.txt") 2>&1
echo "========================================="
echo "[DR ORCHESTRATION] Recovery workflow started at $(date)."

bash "$DR_TERRAFORM_DIR/run_demo.sh"

echo "[DR ORCHESTRATION] Recovery workflow completed successfully. All target services are provisioned."
echo "========================================="
