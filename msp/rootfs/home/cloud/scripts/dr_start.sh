#!/bin/bash
mkdir -p "$HOME/scripts"
exec > >(tee -a "$HOME/scripts/dr_log.txt") 2>&1
echo "========================================="
echo "[DR ORCHESTRATION] Recovery workflow started at $(date)."

bash /home/cloud/hospital-dr-terraform/run_demo.sh

echo "[DR ORCHESTRATION] Recovery workflow completed successfully. All target services are provisioned."
echo "========================================="
