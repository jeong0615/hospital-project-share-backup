#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/nat_common.sh"

if [ "$#" -ne 0 ]; then
  echo "Usage: $0" >&2
  exit 2
fi

nat_runtime_prepare mutating
nat_enable
