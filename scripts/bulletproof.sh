#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
scripts/bulletproof.sh is retired and cannot run.

The old script wrote synthetic attestations and webhook payloads to its target.
Use scripts/check_local.sh for deterministic repository checks.
Use scripts/check_live.sh for read-only deployed-source, anchor, and proof checks.
EOF

exit 2
