#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/nat_common.sh"

case "${1:-disable}" in
  disable|cleanup)
    [ "$#" -le 1 ] || { echo "Usage: $0 [disable]" >&2; exit 2; }
    ;;
  *)
    echo "Usage: $0 [disable]" >&2
    exit 2
    ;;
esac

nat_runtime_prepare mutating
nat_disable
