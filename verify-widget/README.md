# verify-widget

Zero-trust in-browser Merkle proof verifier for the Nordic Shield on-chain protocol (ZAP1).

All verification runs client-side. No server involved. BLAKE2b-256 with Nordic Shield personalizations, Merkle path walking, and root comparison - entirely in the browser.

## Files

| File | Description |
|------|-------------|
| `blake2b.js` | Pure JS BLAKE2b-256 with personalization support (RFC 7693). ES module, zero dependencies. |
| `ProofVerifier.jsx` | React component for zero-trust proof verification. Fetches proof bundle, recomputes leaf hash, walks Merkle path, compares root. |
| `verify-standalone.html` | Single HTML file verifier. No build step, no dependencies. BLAKE2b self-test on load. |

## Usage

### Standalone (no build step)

Serve or open `verify-standalone.html` directly. Enter a leaf hash, click Verify. The page fetches the proof bundle from the API, recomputes every hash locally, and shows VERIFIED or FAILED.

### React component

```jsx
import { ProofVerifier } from '@frontier-compute/verify-widget/verifier';

<ProofVerifier apiBase="https://pay.frontiercompute.io" />
```

### BLAKE2b library

```js
import { blake2b256, hexToBytes, bytesToHex, computeLeafHash, nodeHash, walkProof } from '@frontier-compute/verify-widget';

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
| `PROGRAM_ENTRY` (0x01) | `BLAKE2b(0x01 \|\| wallet_hash_utf8)` |
| `OWNERSHIP_ATTEST` (0x02) | `BLAKE2b(0x02 \|\| len_be16(wallet) \|\| wallet \|\| len_be16(serial) \|\| serial)` |

Additional event types (0x03 - 0x08) are verified by Merkle path walk against the declared leaf hash.

## Test Vector

```
Input: PROGRAM_ENTRY, wallet_hash = "e2e_wallet_20260327"
Leaf:  075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b
```

Verified against Python `hashlib.blake2b` and the live API at `pay.frontiercompute.io`.

## API

The verifier fetches proof bundles from:

```
GET /verify/{leaf_hash}/proof.json
```

Response includes `leaf`, `proof` (sibling array), `root`, `anchor` (txid + block height).

## Protocol

See [ONCHAIN_PROTOCOL.md](../ONCHAIN_PROTOCOL.md) for the full ZAP1 specification.

## License

MIT
