# ZAP1 Memo Parser Conformance Suite

Cross-platform test vectors for ZAP1 memo parsing.  Validates Kotlin (Android),  Swift (iOS),  and Node.js implementations against the same 20+ test cases.

## Run

**Node.js:**
```
node run-node.cjs
```

**Kotlin:**
```
kotlinc -script run-kotlin.kts
```

**Swift:**
```
swift run-swift.swift
```

## Test vectors

`test-vectors.json` covers:
- All 15 standard event types (0x01-0x0F)
- Agent event types (0x40-0x42)
- Legacy NSM1 prefix
- Null-byte padded memos (real Zcash 512-byte format)
- Edge cases: empty,  truncated,  wrong prefix,  non-hex,  uppercase hex
- Historical operator fixture under a root mapped by the API to a mainnet transaction reference

## Related PRs

- zodl-android: github.com/zodl-inc/zodl-android/pull/2173 (closed unmerged 2026-07-29)
- zodl-ios: github.com/zodl-inc/zodl-ios/pull/1680 (closed unmerged 2026-07-29)
