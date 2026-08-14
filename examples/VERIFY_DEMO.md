# Verify this demo package

This directory contains a historical operator export and reproducible Merkle
fixtures. It is not an independent audit.

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

Two operator-issued event claims:

1. a `PROGRAM_ENTRY` claim
2. an `OWNERSHIP_ATTEST` claim

Each proof walks from the leaf hash to the supplied root using BLAKE2b-256 with
`NordicShield_MRK` node personalization. The API records txid
`98e1d6a0...` for that historical root. The txid proves transaction existence,
not the contents of its encrypted memo.

The check establishes that each supplied leaf and proof path is consistent with
the supplied root under the declared historical scheme. It does not establish
that the operator-issued claims are true or complete.

## Check the transaction reference

Confirm the recorded transaction reference exists:
```bash
curl -s https://api.frontiercompute.cash/anchor/history | python3 -m json.tool
```

Look for txid `98e1d6a0...` at block `3,286,631`. The API also returns the
operator-recorded root `024e3651...`. The transaction and height are public;
the encrypted memo needs a separate safe opening before it can be treated as
independently bound to that root.

## Create your own export

```bash
cargo run --bin zap1_export -- --api-url https://api.frontiercompute.cash --wallet-hash <hash> --profile auditor
```

Profiles: `auditor`, `counterparty`, `member`, `regulator`.
