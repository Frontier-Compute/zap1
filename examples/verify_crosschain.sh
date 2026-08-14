#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
RETIRED: this cross-chain example is not a valid ZAP1 count-bound verifier.

The historical contract interface does not accept leaf_count, so it cannot
reconstruct a ZAP1_COUNT_BOUND_V2 root. The repository also lacks an admitted
contract source, ABI, chain ID, runtime code hash, and deployment receipt for
the former Sepolia address.

Use `python3 examples/verify_proof.py <bundle>` for local Merkle inclusion.
Treat every external-chain registry root as a separately trusted input unless
a reviewed bridge and deployment receipt explicitly authenticate it.
EOF

exit 2
