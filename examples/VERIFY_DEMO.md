# Verify this demo package

This directory contains a real audit export from Zcash mainnet.

## One command

```bash
cargo run --bin zap1_audit -- --export examples/demo_audit_package.json
```

Expected output:
```
pass: PROGRAM_ENTRY 075b00df2860 anchor=3286631
pass: OWNERSHIP_ATTEST de62554ad386 anchor=3286631

2 pass, 0 fail
```

## What you just verified

Two Merkle proofs from block 3,286,631 on Zcash mainnet:
1. A PROGRAM_ENTRY event (participant joined)
2. An OWNERSHIP_ATTEST event (wallet linked to hardware serial Z15P-E2E-001)

Each proof walks from the leaf hash to the anchored root using BLAKE2b-256 with `NordicShield_MRK` node personalization. The root is committed on-chain in txid `98e1d6a0...`.

## Verify on-chain

Confirm the anchor transaction exists:
```bash
curl -s https://pay.frontiercompute.io/anchor/history | python3 -m json.tool
```

Look for block 3,286,631 with root `024e3651...`.

## Create your own export

```bash
cargo run --bin zap1_export -- --api-url https://pay.frontiercompute.io --wallet-hash <hash> --profile auditor
```

Profiles: `auditor`, `counterparty`, `member`, `regulator`.
