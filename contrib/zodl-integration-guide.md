# ZAP1 CrossPay Attestation - Zodl Integration Guide

## What this adds

Every CrossPay swap gets a verifiable receipt anchored to Zcash mainnet.  The user can prove a swap happened without revealing source address, destination, or amount.  The proof is a Merkle leaf hash tied to a Zcash on-chain anchor transaction.

What the user sees: a "Verified" badge on swap history with a link to the proof page.  What the chain sees: a BLAKE2b hash in a Merkle tree, root committed via shielded memo.

No PII on-chain.  No trust in Frontier Compute servers - the proof is independently verifiable from the Zcash blockchain.

## How it works

1. CrossPay completes a swap via NEAR Intents
2. The app posts a TRANSFER event to ZAP1 with the wallet hashes and intent TX ID
3. ZAP1 returns a leaf hash and inserts it into the Merkle tree
4. The Merkle root is periodically anchored to Zcash (every 10 events or 24h)
5. The user can verify at `pay.frontiercompute.io/verify/{leaf_hash}`

The TRANSFER event (type 0x07) is used because a CrossPay swap is an ownership transfer - value moves from shielded ZEC to a destination asset on another chain.  The NEAR Intent TX ID serves as the serial number binding the two sides.

Hash construction: `BLAKE2b_32(0x07 || len(source_wallet_hash) || source_wallet_hash || len(dest_wallet_hash) || dest_wallet_hash || len(intent_txid) || intent_txid)` with `NordicShield_` personalization.

## 3-line integration (TypeScript)

```typescript
import { CrossPayAttestation } from "@AnchorPay/zodl-crossPay-attestation";

const zap1 = new CrossPayAttestation("https://pay.frontiercompute.io", API_KEY);

const receipt = await zap1.attest(swapResult);
```

`receipt.leafHash` is the verifiable proof.  `receipt.verifyUrl` links to the proof page.

## Full example

```typescript
import { CrossPayAttestation, CrossPaySwap } from "@AnchorPay/zodl-crossPay-attestation";

const zap1 = new CrossPayAttestation("https://pay.frontiercompute.io", process.env.ZAP1_API_KEY!);

// After CrossPay swap completes via NEAR Intents
const swap: CrossPaySwap = {
  sourceWalletHash: "a1b2c3...",   // BLAKE2b hash of the shielded z-addr or UA
  destWalletHash: "d4e5f6...",     // BLAKE2b hash of destination address
  sourceAsset: "ZEC",
  destAsset: "USDC",
  amountSourceZat: 100000000,      // 1 ZEC in zatoshis
  amountDestSmallest: 28500000,    // 28.50 USDC in smallest unit
  intentTxId: "near_intent_abc123",
  route: "ZEC -> NEAR -> Base:USDC",
  success: true,
};

const receipt = await zap1.attest(swap);

console.log(receipt.leafHash);     // 64-char hex leaf hash
console.log(receipt.verifyUrl);    // https://pay.frontiercompute.io/verify/{hash}

// Verify later
const check = await zap1.verify(receipt.leafHash);
console.log(check.valid);          // true
console.log(check.anchored);       // true after next Zcash anchor
```

## Failed swap attestation

Failed swaps can also be attested.  This lets users prove they initiated a swap even if the intent did not resolve.

```typescript
const failedSwap: CrossPaySwap = {
  sourceWalletHash: "a1b2c3...",
  destWalletHash: "d4e5f6...",
  sourceAsset: "ZEC",
  destAsset: "ETH",
  amountSourceZat: 50000000,
  amountDestSmallest: 0,
  intentTxId: "near_intent_xyz789",
  route: "ZEC -> NEAR -> ETH",
  success: false,
  failureReason: "intent_timeout",
};

const receipt = await zap1.attestFailed(failedSwap);
// serial_number is stored as "FAILED:near_intent_xyz789"
```

## Kotlin (Android)

The memo parser is already available via PR [#2173](https://github.com/zodl-inc/zodl-android/pull/2173).  For CrossPay attestation, add the network call after swap completion.

```kotlin
// Post-swap attestation call
suspend fun attestSwap(
    sourceWalletHash: String,
    destWalletHash: String,
    intentTxId: String,
    apiKey: String
): String {
    val url = URL("https://pay.frontiercompute.io/event")
    val conn = url.openConnection() as HttpURLConnection
    conn.requestMethod = "POST"
    conn.setRequestProperty("Content-Type", "application/json")
    conn.setRequestProperty("Authorization", "Bearer $apiKey")
    conn.doOutput = true

    val body = """
        {
            "event_type": "TRANSFER",
            "wallet_hash": "$sourceWalletHash",
            "new_wallet_hash": "$destWalletHash",
            "serial_number": "$intentTxId"
        }
    """.trimIndent()

    conn.outputStream.bufferedWriter().use { it.write(body) }

    val response = conn.inputStream.bufferedReader().readText()
    val json = JSONObject(response)
    return json.getString("leaf_hash")
}

// Usage after CrossPay swap
val leafHash = attestSwap(
    sourceWalletHash = walletHash,
    destWalletHash = destHash,
    intentTxId = nearIntentTx.id,
    apiKey = BuildConfig.ZAP1_API_KEY
)

// Display verification link
val verifyUrl = "https://pay.frontiercompute.io/verify/$leafHash"
```

The existing `Zap1MemoFormatter` from the memo rendering PR will parse any ZAP1 memos the user receives, including TRANSFER events from CrossPay swaps.  See `contrib/zodl-android/Zap1MemoFormatter.kt`.

## Swift (iOS)

```swift
func attestSwap(
    sourceWalletHash: String,
    destWalletHash: String,
    intentTxId: String,
    apiKey: String
) async throws -> String {
    let url = URL(string: "https://pay.frontiercompute.io/event")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")

    let body: [String: Any] = [
        "event_type": "TRANSFER",
        "wallet_hash": sourceWalletHash,
        "new_wallet_hash": destWalletHash,
        "serial_number": intentTxId
    ]
    request.httpBody = try JSONSerialization.data(withJSONObject: body)

    let (data, response) = try await URLSession.shared.data(for: request)
    guard let http = response as? HTTPURLResponse, http.statusCode == 201 else {
        throw URLError(.badServerResponse)
    }

    let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    return json["leaf_hash"] as! String
}

// Usage
let leafHash = try await attestSwap(
    sourceWalletHash: walletHash,
    destWalletHash: destHash,
    intentTxId: nearIntentTx.id,
    apiKey: Config.zap1ApiKey
)

let verifyUrl = "https://pay.frontiercompute.io/verify/\(leafHash)"
```

The existing `Zap1MemoParser` handles memo rendering.  See `contrib/zodl-ios/Zap1MemoParser.swift`.

## API reference

### POST /event

Creates a TRANSFER attestation leaf.

```
POST https://pay.frontiercompute.io/event
Authorization: Bearer {API_KEY}
Content-Type: application/json

{
    "event_type": "TRANSFER",
    "wallet_hash": "{source_wallet_hash}",
    "new_wallet_hash": "{dest_wallet_hash}",
    "serial_number": "{near_intent_txid}"
}
```

Response (201):

```json
{
    "status": "created",
    "event_type": "TRANSFER",
    "wallet_hash": "a1b2c3...",
    "leaf_hash": "e7f8a9...64 hex chars",
    "root_hash": "b3c4d5...64 hex chars",
    "verify_url": "/verify/e7f8a9..."
}
```

### GET /verify/{leaf_hash}/check

Verify a leaf exists and is anchored.

```json
{
    "protocol": "ZAP1",
    "valid": true,
    "leaf_hash": "e7f8a9...",
    "event_type": "TRANSFER",
    "root": "b3c4d5...",
    "server_verified": true
}
```

### GET /verify/{leaf_hash}/proof.json

Full proof bundle with Merkle path, root, and anchor txid for independent verification.

## Verification page

Every leaf hash has a human-readable verification page at:

```
https://pay.frontiercompute.io/verify/{leaf_hash}
```

This page shows the leaf hash, event type, Merkle proof path, root hash, and the Zcash anchor transaction.  Users can share this URL as proof of swap.

## What wallet hashes to use

The `wallet_hash` fields must be BLAKE2b-256 hashes, not raw addresses.  This keeps addresses off the attestation layer.

For shielded ZEC (source): hash the z-address or unified address the funds came from.  
For the destination: hash the receiving address on the target chain.

Use `NordicShield_` as the BLAKE2b personalization for consistency with ZAP1 hash construction.  Or use any deterministic hash - the important thing is that the same input always produces the same hash so the user can recompute it.

## Links

- Verify page: `https://pay.frontiercompute.io/verify/{leaf_hash}`
- Protocol spec: [ONCHAIN_PROTOCOL.md](../ONCHAIN_PROTOCOL.md)
- OpenAPI spec: [conformance/openapi.yaml](../conformance/openapi.yaml)
- Memo rendering PR (Android): [zodl-inc/zodl-android#2173](https://github.com/zodl-inc/zodl-android/pull/2173)
- Memo rendering issue (iOS): [zodl-inc/zodl-ios#1670](https://github.com/zodl-inc/zodl-ios/issues/1670)
- TypeScript module: [zodl-crossPay-attestation.ts](./zodl-crossPay-attestation.ts)
- npm: `@AnchorPay/zap1-verify` (verification SDK)
- Android memo parser: [zodl-android/Zap1MemoFormatter.kt](./zodl-android/Zap1MemoFormatter.kt)
- iOS memo parser: [zodl-ios/Zap1MemoParser.swift](./zodl-ios/Zap1MemoParser.swift)

## API key

Request an API key from zk_nd3r.  The key is passed as a Bearer token in the Authorization header.  Without it, POST /event returns 401.

GET endpoints (verify, proof, stats) are public and require no auth.
