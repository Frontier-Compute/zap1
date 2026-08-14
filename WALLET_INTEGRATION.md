# Wallet Integration Roadmap

Status: repository proposal; no wallet integration is merged

## Target: Zodl (formerly Zashi)

Zodl is the active public home of the former Zashi code line. Josh Swihart (founder) and the ECC team that built Zashi formed Zcash Open Development Lab (ZODL) in January 2025.

| Platform | Repo | Language |
|---|---|---|
| Android | [zodl-inc/zodl-android](https://github.com/zodl-inc/zodl-android) | Kotlin (Jetpack Compose) |
| iOS | [zodl-inc/zodl-ios](https://github.com/zodl-inc/zodl-ios) | Swift (SwiftUI) |

## Memo Pipeline

### Android

1. `TransactionRepository.kt` calls `synchronizer.getMemos()` - returns `List<String>`
2. `GetTransactionDetailByIdUseCase.kt` combines memos into `DetailedTransactionData`
3. `TransactionDetailVM.kt` maps strings into `TransactionDetailMemosState` (lines 273-275, 315-317)
4. `TransactionDetailInfoMemo.kt` renders the memo card with 130-char expand/collapse

### iOS

1. `TransactionDetailsStore.swift` calls `sdkSynchronizer.getMemos(rawID)`
2. `TransactionDetailsView.swift` renders in `messageViews()` with 130-char expansion threshold
3. `TransactionState.swift` and `MessageView.swift` handle list-level rendering

## First PR Scope

Detect `ZAP1:` and `NSM1:` prefixes in resolved memo strings. Replace plain text rendering with a typed attestation card:

- Event label (PROGRAM_ENTRY, DEPLOYMENT, MERKLE_ROOT, etc.)
- Shortened payload hash
- Copy action
- Verify link (configurable base URL, e.g. `frontiercompute.io/verify.html#{hash}`)
- Raw memo fallback for malformed strings

No send flow changes. No ZIP 302 composition. No light client sync changes.

### Files to change

- **Android** (5-7 files): new `Zap1MemoFormatter.kt` parser, modify `TransactionDetailVM.kt` memo mapping, add attestation card composable, update strings
- **iOS** (5-6 files): new `Zap1MemoParser.swift`, modify `TransactionDetailsStore.swift` memo resolution, add attestation card view, update strings

### Parser (Kotlin, ~30 lines)

```kotlin
object Zap1MemoFormatter {
    private val ZAP1_REGEX = Regex("^(ZAP1|NSM1):([0-9a-f]{2}):([0-9a-f]{64})$")

    private val EVENT_NAMES = mapOf(
        "01" to "PROGRAM_ENTRY", "02" to "OWNERSHIP_ATTEST",
        "03" to "CONTRACT_ANCHOR", "04" to "DEPLOYMENT",
        "05" to "HOSTING_PAYMENT", "06" to "SHIELD_RENEWAL",
        "07" to "TRANSFER", "08" to "EXIT",
        "09" to "MERKLE_ROOT", "0a" to "STAKING_DEPOSIT",
        "0b" to "STAKING_WITHDRAW", "0c" to "STAKING_REWARD",
        "0d" to "GOVERNANCE_PROPOSAL", "0e" to "GOVERNANCE_VOTE",
        "0f" to "GOVERNANCE_RESULT",
        "40" to "AGENT_REGISTER", "41" to "AGENT_POLICY",
        "42" to "AGENT_ACTION"
    )

    fun format(memo: String): Zap1Attestation? {
        val match = ZAP1_REGEX.matchEntire(memo.trim()) ?: return null
        val prefix = match.groupValues[1]
        val typeHex = match.groupValues[2]
        val hash = match.groupValues[3]
        val name = EVENT_NAMES[typeHex] ?: "UNKNOWN_0x$typeHex"
        return Zap1Attestation(prefix, typeHex, name, hash)
    }

    data class Zap1Attestation(
        val prefix: String, val typeHex: String,
        val eventName: String, val payloadHash: String
    )
}
```

The parser may recognize the wire shape of any two-digit type byte, but only
`0x01` through `0x0F` and `0x40` through `0x42` are defined by the
active registry. A wallet must render every other byte as unassigned, not as a
valid extension.

## What the User Sees

| Memo content | Display |
|---|---|
| Regular text | Unchanged (current behavior) |
| `ZAP1:01:075b00df...` | "ZAP1 Attestation: PROGRAM_ENTRY" + short hash + Verify link |
| `ZAP1:09:024e3651...` | "ZAP1 Attestation: MERKLE_ROOT" + short hash + Verify link |
| `NSM1:04:f265b9a0...` | "ZAP1 Attestation: DEPLOYMENT (legacy)" + short hash + Verify link |
| Malformed `ZAP1:xx:...` | Raw memo text (fallback) |

## Timeline

These are planning estimates, not maintainer commitments.

- Android: 3-5 working days
- iOS: 4-6 working days
- Review and maintainer feedback: 3-5 working days
- Total for detail view on both platforms: 2-3 weeks

## Follow-up PRs

- Transaction history badge/icon for ZAP1 memos
- Memo-aware search/filter
- ZIP 302 structured memo rendering (after partType stabilizes)
- In-wallet proof verification via zap1-verify WASM

## References

The Android PR 2173 and iOS PR 1680 closed unmerged on 2026-07-29. iOS issue
1670 remained open at the 2026-08-13 cutoff. Those receipts do not establish
wallet adoption.

- [Zodl Android transaction detail VM](https://github.com/zodl-inc/zodl-android/blob/main/ui-lib/src/main/java/co/electriccoin/zcash/ui/screen/transactiondetail/TransactionDetailVM.kt)
- [Zodl Android memo UI](https://github.com/zodl-inc/zodl-android/blob/main/ui-lib/src/main/java/co/electriccoin/zcash/ui/screen/transactiondetail/infoitems/TransactionDetailInfoMemo.kt)
- [Zodl iOS transaction details store](https://github.com/zodl-inc/zodl-ios/blob/main/modules/Sources/Features/TransactionDetails/TransactionDetailsStore.swift)
- [Zodl iOS transaction details view](https://github.com/zodl-inc/zodl-ios/blob/main/modules/Sources/Features/TransactionDetails/TransactionDetailsView.swift)
- [zcash-memo-decode on crates.io](https://crates.io/crates/zcash-memo-decode) (published `0.1.1`; repository candidate `0.1.2` is not published)
- [ZIP 302 partType request](https://github.com/zcash/zips/issues/1250)
- [ZAP1 wallet contract](conformance/contracts/wallet.md)
