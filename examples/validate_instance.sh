#!/usr/bin/env bash
set -euo pipefail

# Retired compatibility entrypoint for the strict read-only checker.
# Usage: ./validate_instance.sh https://api.frontiercompute.cash
#        ./validate_instance.sh http://localhost:3081

if [ "$#" -ne 1 ] || [ "$1" = "--key" ]; then
  echo "Usage: $0 <base_url>" >&2
  echo "REJECTED: this read-only checker never accepts or forwards API keys." >&2
  exit 2
fi
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$REPO_ROOT/conformance/check_api.py" "$1"
