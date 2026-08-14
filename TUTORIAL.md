# ZAP1 in 10 Minutes

From zero to a Merkle receipt checked against its supplied root. Git, curl, and
Python are enough for the first half. Rust is needed for the repository tests.

## Part 1: See the protocol (2 minutes)

Use the exact commit named in the review or build receipt. Do not execute a
mutable script straight from the network.

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
git checkout <reviewed-commit>
bash examples/quickstart.sh
```

You just queried the live ZAP1 API. Treat its counts as current API output, not as the fixed numbers in this tutorial.

## Part 2: Verify a proof yourself (3 minutes)

Pick a leaf hash from the events feed:

```bash
LEAF=$(curl -sf https://api.frontiercompute.cash/events?limit=1 | python3 -c "import json,sys; print(json.load(sys.stdin)['events'][0]['leaf_hash'])")
echo "Leaf: $LEAF"
```

Fetch the full proof bundle:

```bash
curl -sf "https://api.frontiercompute.cash/verify/$LEAF/proof.json" | python3 -m json.tool
```

The bundle contains a leaf hash, event type, proof path, supplied root, and an anchor reference when available. It is enough to recompute Merkle inclusion, but not to prove the underlying event claim or decrypt a shielded memo.

Now verify that the supplied leaf hash and proof path resolve to the supplied
root:

```bash
python3 examples/verify_proof.py $LEAF
```

The verifier recomputes tree nodes with `NordicShield_MRK` and the count-bound
root commitment with `NordicShield_RTK`. A match proves Merkle inclusion for
the supplied leaf hash under the supplied root. If the public bundle withholds
the typed preimage, its event-type label remains claimed server metadata. The
origin and publication of the root remain separate questions.

## Part 3: Check the Zcash transaction reference (2 minutes)

When a bundle has an anchor reference, check whether the transaction exists:

```bash
python3 examples/verify_onchain.py examples/live_ownership_attest_proof.json
```

This command confirms transaction existence when possible and then exits
incomplete. Normal Orchard memo plaintext is encrypted and is not recoverable
from raw transaction hex alone. A transaction ID proves existence, not the
claimed memo-to-root binding.

## Part 4: Cross-chain verifier status

The old Sepolia example is retired. Its historical contract interface did not
accept `leaf_count`, so it could not reconstruct the current count-bound root.
The repository also lacks the source, ABI, runtime code hash, chain ID, and
deployment receipt needed to admit that contract as reviewer evidence. No
Zcash bridge authenticates a separately registered root.

## Part 5: Use the verification SDK (1 minute)

### Rust

The published `zap1-verify` `0.2.1` crate is the legacy raw-root verifier and
covers types `0x01-0x09`. The count-bound, 18-type `0.3.0` code below is a
repository candidate and is not published. Reviewers should build it from this
exact checkout.

```rust
use zap1_verify::{compute_leaf_hash, verify_proof, EventPayload};

// Recompute a PROGRAM_ENTRY leaf
let leaf = compute_leaf_hash(&EventPayload::ProgramEntry {
    wallet_hash: b"wallet_abc",
});

// Verify a proof path against the count-bound v2 root commitment
let valid = verify_proof(&leaf, &siblings, leaf_count, &root);
```

The repository candidate includes Rust verifier code. The browser verifier is
repository-local and no verify-widget npm package is published.

### JavaScript

Published `@frontiercompute/zap1` `0.2.1` supports count-bound v2 roots with
gated legacy support. The deterministic evaluator checks it against the shared
corpus before it is used as a reviewer path.

### Decode any Zcash memo

The published `zcash-memo-decode` `0.1.1` labels through `0x0C`. Governance
and agent labels are in the repository `0.1.2` candidate and are not yet
published.

```rust
use zcash_memo_decode::classify;

let result = classify(memo_bytes);
// Returns: Zap1 { event_type, payload_hash }
//      or: Zip302Tvlv { parts }
//      or: PlainText { text }
//      or: Binary | Empty
```

Zero dependencies. Classifies ZAP1, ZIP 302, text, binary, and empty memos.

## Part 6: Deploy your own instance (bonus)

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
test -z "$(git status --porcelain)"
REV=$(git rev-parse HEAD)
bash scripts/build_image.sh "zap1:$REV"
# Copy receipt_path from the output and keep its .sha256 sidecar.
export ZAP1_OPERATOR_UFVK='uview1...from-a-wallet-you-control'
export ZAP1_ANCHOR_TO_ADDRESS='u1...from-the-same-wallet'
export ZAP1_SCAN_FROM_HEIGHT='<wallet-birthday-height>'
bash scripts/operator-setup.sh myoperator 3081 /absolute/path/to/build-receipt.env
cd operators/myoperator
./run.sh
```

This creates a private operator configuration pinned to the exact image ID in
the checksummed build receipt. It also copies the exact archived API checker
and schema into the operator directory. The generated run script verifies
those bytes, refuses image builds and pulls, checks build identity before a
bounded scanner catch-up, then requires RPC reachability, consistent scanner
heights, lag within the configured limit, and a final strict API check. It
stops the container if any gate fails. It does not create or import wallet
secrets, and anchoring is disabled until the operator performs a separate
authorized wallet setup.

## What you just did

1. Queried the current public ZAP1 API
2. Recomputed a Merkle proof against a supplied root
3. Attempted the fail-closed chain-memo check
4. Checked a supplied root in the Ethereum demo registry
5. Used the Rust and Python verification tools
6. Decoded a Zcash shielded memo
7. Followed the exact-image operator workflow for your own instance

The protocol is open. Merkle proof consistency, root publication, and the truth of an underlying claim are distinct verification layers.

## Links

- Protocol: [github.com/Frontier-Compute/zap1](https://github.com/Frontier-Compute/zap1)
- Spec: [ONCHAIN_PROTOCOL.md](ONCHAIN_PROTOCOL.md)
- Verification SDK: [crates.io/crates/zap1-verify](https://crates.io/crates/zap1-verify)
- JavaScript verifier: [npmjs.com/package/@frontiercompute/zap1](https://www.npmjs.com/package/@frontiercompute/zap1) (`0.2.1`, count-bound v2 with gated legacy support)
- Solidity verifier: [github.com/Frontier-Compute/zap1-verify-sol](https://github.com/Frontier-Compute/zap1-verify-sol)
- Memo decoder: [crates.io/crates/zcash-memo-decode](https://crates.io/crates/zcash-memo-decode)
- Operator guide: [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md)
