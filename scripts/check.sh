#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: bash scripts/check.sh [--local|--live]

No argument runs the deterministic local evaluator, then the fail-closed live evaluator.
--local runs only repository checks.
--live runs only deployed-source, anchor, and proof checks.
EOF
}

case "${1:-}" in
  "")
    bash "$REPO_ROOT/scripts/check_local.sh"
    bash "$REPO_ROOT/scripts/check_live.sh"
    ;;
  --local)
    exec bash "$REPO_ROOT/scripts/check_local.sh"
    ;;
  --live)
    exec bash "$REPO_ROOT/scripts/check_live.sh"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
