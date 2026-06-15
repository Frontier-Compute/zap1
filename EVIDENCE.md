# ZAP1 Evidence Packet

Snapshot date: 2026-04-02
Generated: 2026-04-02T06:57:32Z

## Protocol State

```json
{
    "deployed_types": 15,
    "event_types": 18,
    "frost_ciphersuite": "FROST(Pallas, BLAKE2b-512)",
    "frost_status": "design_complete",
    "frost_threshold": "2-of-3",
    "hash_function": "BLAKE2b-256",
    "leaf_personalization": "NordicShield_",
    "node_personalization": "NordicShield_MRK",
    "protocol": "ZAP1",
    "reserved_types": 3,
    "specification": "https://github.com/Frontier-Compute/zap1/blob/main/ONCHAIN_PROTOCOL.md",
    "verification_sdk": "zap1-verify (Rust + WASM)",
    "verification_sdk_repo": "https://github.com/Frontier-Compute/zap1-verify",
    "version": "3.0.0",
    "zip_status": "draft"
}
```

## Network Stats

```json
{
    "event_types": [
        "PROGRAM_ENTRY",
        "OWNERSHIP_ATTEST",
        "CONTRACT_ANCHOR",
        "DEPLOYMENT",
        "HOSTING_PAYMENT",
        "SHIELD_RENEWAL",
        "TRANSFER",
        "EXIT",
        "MERKLE_ROOT",
        "STAKING_DEPOSIT",
        "STAKING_WITHDRAW",
        "STAKING_REWARD",
        "GOVERNANCE_PROPOSAL",
        "GOVERNANCE_VOTE",
        "GOVERNANCE_RESULT",
        "AGENT_REGISTER",
        "AGENT_POLICY",
        "AGENT_ACTION"
    ],
    "first_anchor_block": 3286631,
    "last_anchor_block": 3293076,
    "network": "MainNetwork",
    "protocol": "ZAP1",
    "total_anchors": 5,
    "total_leaves": 38,
    "type_counts": {
        "CONTRACT_ANCHOR": 1,
        "DEPLOYMENT": 11,
        "EXIT": 0,
        "GOVERNANCE_PROPOSAL": 2,
        "GOVERNANCE_RESULT": 1,
        "GOVERNANCE_VOTE": 4,
        "AGENT_REGISTER": 4,
        "AGENT_POLICY": 3,
        "AGENT_ACTION": 8,
        "HOSTING_PAYMENT": 0,
        "MERKLE_ROOT": 0,
        "OWNERSHIP_ATTEST": 1,
        "PROGRAM_ENTRY": 1,
        "SHIELD_RENEWAL": 0,
        "STAKING_DEPOSIT": 1,
        "STAKING_REWARD": 1,
        "STAKING_WITHDRAW": 0,
        "TRANSFER": 0
    }
}
```

## Anchor Status

```json
{
    "anchor_threshold": 10,
    "current_root": "14ead3d0ad6e20f9f076dd9c8de73f454bcee305e1eee863c7db15a28d88c934",
    "last_anchor_height": null,
    "last_anchor_txid": null,
    "leaf_count": 38,
    "needs_anchor": true,
    "recommendation": "anchor now",
    "unanchored_leaves": 15
}
```

## Anchor History

```json
{
    "anchors": [
        {
            "created_at": "2026-03-27T03:29:26.270894724+00:00",
            "height": 3286631,
            "leaf_count": 2,
            "root": "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a",
            "txid": "98e1d6a01614c464c237f982d9dc2138c5f8aa08342f67b867a18a4ce998af9a"
        },
        {
            "created_at": "2026-03-27T23:13:00.465042404+00:00",
            "height": 3287612,
            "leaf_count": 12,
            "root": "a5b78c57b062f2e632fd40e8fbbdaf59ab7e527b860cf7db2385bc180cbbf362",
            "txid": "3c764a810f4646772fc665b29225a0ffe0e423282ddbfa746d8d27e7a68676a6"
        },
        {
            "created_at": "2026-03-28T08:27:34.257951207+00:00",
            "height": 3288022,
            "leaf_count": 12,
            "root": "437e12dd66cfcb9e0277b231efabd3ebeb1cc8c0e612bb4ee97c04b93c1f1745",
            "txid": "dfab64cd1114371ceb9e7a38fa9ea0ca880767fc71f7832b7c3873205659ff5c"
        },
        {
            "created_at": "2026-03-31T17:13:48.913389982+00:00",
            "height": 3292017,
            "leaf_count": 14,
            "root": "b09b16becc20047cfc5b97673904d3df978355bb851082b3be4f36f68b9eacf1",
            "txid": "59e8fe14a161cf518b6a30f9c17663f60e161544f138c5c35e46beaaac2b8782"
        },
        {
            "created_at": "2026-04-01T01:17:17.730249876+00:00",
            "height": 3293076,
            "leaf_count": 23,
            "root": "308c7df6482f0552ca20cb7e35bac3c511cc88b9b888ace309f9889d8aa6dedf",
            "txid": "c07ceac55b2f50c8a2a1db665a663c634c0ce10300798874cac74c50836c80e3"
        }
    ],
    "last_anchor_age_hours": 29,
    "total": 5
}
```

## Verification

```
ZAP1 validation check
====================

pass  protocol/info returns ZAP1
pass  mainnet anchors > 0
pass  mainnet leaves > 0
pass  offline proof bundle verifies
pass  memo decode returns zap1
skip  explorer reachable (optional web surface HTTP 000000)
skip  simulator reachable (optional web surface HTTP 000000)
pass  zap1-verify on crates.io
pass  events feed returns data
pass  current live proof endpoint verifies
pass  zcash-memo-decode on crates.io
pass  ZIP-1243 conformance vectors
pass  live API schema check
pass  cargo metadata locked
pass  zap1-verify tests pass
pass  zcash-memo-decode tests pass

14 pass, 0 fail
```

## Repository State

| Repo | Branch | SHA | CI |
|---|---|---|---|
| zap1 | main | 851f877 | success |
| zap1-verify | main | 6096e74 | success |
| zap1-js | main | 1bfd374 | success |
| zap1-simulator | master | 2fdcb7d | success |
| zap1-explorer | master | 1a010f8 | success |
| zcash-memo-decode | main | ae487de | success |
| zap1-verify-sol | main | cd9de34 | success |

## Ethereum Sepolia

- Contract: `0x3fD65055A8dC772C848E7F227CE458803005C87F`
- Etherscan: https://sepolia.etherscan.io/address/0x3fD65055A8dC772C848E7F227CE458803005C87F
- Sourcify: verified (exact match)
- Etherscan: verified (source readable)
- Anchors registered: 5

## Published Packages

- zap1-verify: 0.2.1 (crates.io)
- zcash-memo-decode: 0.1.1 (crates.io)
- @frontiercompute/zap1 (npm)

## Public Integration

- ZIP draft: [zcash/zips PR #1243](https://github.com/zcash/zips/pull/1243)
- ZIP 302 partType request: [zcash/zips #1250](https://github.com/zcash/zips/issues/1250)
- Zodl Android PR: [zodl-inc/zodl-android #2173](https://github.com/zodl-inc/zodl-android/pull/2173)
- Zodl iOS issue: [zodl-inc/zodl-ios #1670](https://github.com/zodl-inc/zodl-ios/issues/1670)
