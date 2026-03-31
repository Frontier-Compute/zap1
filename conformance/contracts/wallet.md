# Wallet Contract

How a Zcash wallet consumes ZAP1 attestation data.

## Input

Decrypted memo bytes from Orchard or Sapling trial decryption.

## Detection

```rust
let decoded = zcash_memo_decode::decode(memo_bytes);
```

If `decoded` is `MemoFormat::Attestation`, the memo contains a ZAP1 event.

## Display

| Format | Wallet action |
|---|---|
| Text | show as transaction note |
| Attestation (ZAP1) | show event badge + link to verifier |
| Attestation (NSM1) | same, legacy format |
| Zip302Tvlv | parse structured parts per ZIP 302 |
| Empty | no display |
| Binary | show "binary data (N bytes)" |
| Unknown | show "unrecognized memo" |

## Failure modes

- WASM init fails: fall back to text-only display
- unknown event type byte: display "unknown attestation (0xNN)"
- malformed ZAP1 prefix: decoder returns Text with the raw string

## Stability

The `MemoFormat` enum is additive only. New variants may be added in future versions. Unknown variants should be handled gracefully.

## Dependencies

- `zcash-memo-decode` on crates.io (zero deps, MIT)
- no network calls required
