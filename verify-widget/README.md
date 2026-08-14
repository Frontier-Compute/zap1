# verify-widget

Client-side Merkle-bundle consistency checker for ZAP1.

After a bundle is obtained, BLAKE2b-256 hashing, Merkle path walking, and
comparison with the supplied root run in the browser. This does not authenticate
the root's publication or prove the underlying event claim.

## Files

| File | Description |
|------|-------------|
| `blake2b.js` | Pure JS BLAKE2b-256 with personalization support (RFC 7693). ES module, zero dependencies. |
| `ProofVerifier.jsx` | React component that fetches from its explicit `apiBase`, binds the response to the requested leaf hash, validates the bundle, walks the Merkle path, and compares the supplied root. |
| `verify-standalone.html` | Single HTML file verifier. No build step, no dependencies. BLAKE2b self-test on load. |

## Usage

### Standalone (no build step)

Serve or open `verify-standalone.html` directly. Enter a leaf hash, then click
Verify. The page fetches from the canonical API named on the page, requires the
returned leaf to match the request, walks the path locally, and shows MATCH or
MISMATCH against the supplied root. It recomputes a typed leaf only if the
required preimages are separately supplied.

### React component

This widget is repository-local. No `@frontier-compute/verify-widget` npm
package is published.

```jsx
import ProofVerifier from './verify-widget/ProofVerifier.jsx';

<ProofVerifier apiBase="https://api.frontiercompute.cash" />
```

`apiBase` defaults to the canonical endpoint above. Set it explicitly for a
self-hosted service. The component rejects non-HTTP(S) bases and never sends a
request until the leaf hash and endpoint pass local validation.

### BLAKE2b library

```js
import { blake2b256, hexToBytes, bytesToHex, computeLeafHash, nodeHash, walkProof } from './verify-widget/blake2b.js';

// Compute a PROGRAM_ENTRY leaf hash
const leaf = computeLeafHash('PROGRAM_ENTRY', 'your_wallet_hash');
console.log(bytesToHex(leaf));
```

## Personalizations

| Context | Personalization (16 bytes) | Hex |
|---------|---------------------------|-----|
| Leaf hash | `NordicShield_\x00\x00\x00` | `4e6f726469635368 69656c645f000000` |
| Node hash | `NordicShield_MRK` | `4e6f726469635368 69656c645f4d524b` |

## Supported Event Types

| Type | Leaf construction |
|------|-------------------|
| `PROGRAM_ENTRY` (0x01) | Reconstructed only when the caller separately supplies the subject preimage. |
| `OWNERSHIP_ATTEST` (0x02) | Reconstructed only when the caller separately supplies both subject and serial preimages. |

For every type, the widget can walk the supplied path from the declared leaf
hash to the supplied root. That check does not reconstruct event fields,
authenticate the root, or prove the claim. Public proof bundles withhold stored
wallet and serial preimages.

## Test Vector

```
Input: PROGRAM_ENTRY, wallet_hash = "e2e_wallet_20260327"
Leaf:  075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b
```

Compared against the repository fixture and Python `hashlib.blake2b`. This is
not a live deployment receipt.

## API

The verifier fetches proof bundles from:

```
GET /verify/{leaf_hash}/proof.json
```

Response includes `leaf`, `proof` (sibling array), `root`, `anchor` (txid + block height).

## Tests

```bash
node verify-widget/verifier.test.mjs
```

The zero-network regression suite checks requested-hash binding, exact
protocol and scheme labels, strict 32-byte lowercase hashes, strict proof
positions, the historical legacy cutoff, standalone parity, and self-hosted
endpoint selection.

## Protocol

See [ONCHAIN_PROTOCOL.md](../ONCHAIN_PROTOCOL.md) for the full ZAP1 specification.

## License

MIT
