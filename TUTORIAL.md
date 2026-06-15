# ZAP1 in 10 Minutes

From zero to a verified attestation proof. No install needed for the first half. Rust toolchain for the second.

## Part 1: See the protocol (2 minutes)

Run this from any terminal with curl and python3:

```bash
bash <(curl -sf https://raw.githubusercontent.com/Frontier-Compute/zap1/main/examples/quickstart.sh)
```

You just queried a live attestation protocol on Zcash mainnet. 5 anchored Merkle roots, 18 event types, proofs verifiable by anyone.

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

The bundle contains: leaf hash, event type, proof path (sibling hashes), root, anchor txid, and block height. Everything needed to verify independently.

Now verify the proof path resolves to the root:

```bash
python3 examples/verify_proof.py $LEAF
```

The verifier recomputes the Merkle path using BLAKE2b-256 with `NordicShield_` personalization. If the derived root matches the anchored root, the proof is valid. No server trust involved.

## Part 3: Verify on Zcash (2 minutes)

The root was anchored in a Zcash shielded transaction. Check it:

```bash
python3 examples/verify_onchain.py examples/live_ownership_attest_proof.json
```

This fetches the anchor transaction from Zebra RPC, decodes the memo, and confirms it contains `ZAP1:09:{root}`. The chain is the source of truth.

## Part 4: Verify on Ethereum (2 minutes)

The same proof is verifiable on Ethereum via the Solidity verifier. Requires [Foundry](https://getfoundry.sh/):

```bash
bash examples/verify_crosschain.sh $LEAF
```

Output:

```
Zcash   Leaf:   075b00df...
Zcash   Root:   024e3651...
Zcash   Anchor: block 3286631

Ethereum  Calling ZAP1Verifier at 0x3fD65055...

PROOF VALID
Anchor registered: true
Verified on: Ethereum Sepolia
```

The Solidity contract uses the EIP-152 BLAKE2b precompile with the same personalization constants. Same math, different chain. No bridge, no custodian.

## Part 5: Use the verification SDK (1 minute)

### Rust

```bash
cargo add zap1-verify
```

```rust
use zap1_verify::{compute_leaf_hash, verify_proof};

// Recompute a PROGRAM_ENTRY leaf
let leaf = compute_leaf_hash(0x01, b"wallet_abc");

// Verify a proof path against the count-bound v2 root commitment
let valid = verify_proof(&leaf, &siblings, leaf_count, &root);
```

83KB of WASM. One dependency. Works in browsers.

### JavaScript

```bash
npm i @frontiercompute/zap1
```

```javascript
import { verifyProof, computeLeafHash } from '@frontiercompute/zap1';

const leaf = computeLeafHash(0x01, 'wallet_abc');
const valid = verifyProof(leaf, siblings, root);
```

### Decode any Zcash memo

```bash
cargo add zcash-memo-decode
```

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
bash scripts/operator-setup.sh myoperator 3081
cd operators/myoperator && ./run.sh
```

This generates keys, .env, docker-compose, and a run script. Your own attestation protocol instance with its own Merkle tree and anchor address.

Run the conformance kit against it:

```bash
python3 conformance/check.py --url http://127.0.0.1:3081
```

## What you just did

1. Queried a live attestation protocol on Zcash mainnet
2. Verified a Merkle proof independently (no server trust)
3. Confirmed the anchor on-chain via Zebra RPC
4. Verified the same proof on Ethereum via the Solidity contract
5. Used the Rust and JS verification SDKs
6. Decoded a Zcash shielded memo
7. Deployed your own instance

The protocol is open, the proofs are self-contained, and the verification works across chains. Build on it.

## Links

- Protocol: [github.com/Frontier-Compute/zap1](https://github.com/Frontier-Compute/zap1)
- Spec: [ONCHAIN_PROTOCOL.md](ONCHAIN_PROTOCOL.md)
- Verification SDK: [crates.io/crates/zap1-verify](https://crates.io/crates/zap1-verify)
- JS SDK: [npmjs.com/package/@frontiercompute/zap1](https://www.npmjs.com/package/@frontiercompute/zap1)
- Solidity verifier: [github.com/Frontier-Compute/zap1-verify-sol](https://github.com/Frontier-Compute/zap1-verify-sol)
- Memo decoder: [crates.io/crates/zcash-memo-decode](https://crates.io/crates/zcash-memo-decode)
- Operator guide: [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md)
