# Shielded Revenue Proofs

Status: Draft  
Date: 2026-04-01

## Problem

With shielded coinbase outputs, mining revenue arrives privately. This is good for privacy but creates a gap: participants sometimes need to prove they received income without revealing how much.

Scenarios:
- A miner applies for a loan and needs to demonstrate income
- A DAO participant proves they received staking rewards
- An operator shows auditors that payouts were distributed
- A pool participant proves they were paid for a specific period

In all cases, the need is the same: prove an event happened without revealing the value.

## How ZAP1 Addresses This

ZAP1 attestation events commit the *existence* of an operation, not its *amount*. The leaf hash covers the wallet, period, and operation type. The amount is an input to the hash but not recoverable from the hash.

A HOSTING_PAYMENT leaf proves "this wallet was paid for hosting in March 2026." It does not reveal the amount. A POOL_PAYOUT leaf proves "this participant received a payout for period Q1." The amount is hashed into the commitment but cannot be extracted.

The proof chain:

```
1. Wallet holder requests proof from ZAP1 API
2. API returns: leaf hash, proof path, root, anchor txid
3. Holder presents proof to a verifier (lender, auditor, counterparty)
4. Verifier checks: proof path resolves to root, root is anchored on Zcash
5. Verifier concludes: this wallet participated in this operation at this time
```

The verifier learns *what happened* and *when*, not *how much*.

## Selective Disclosure

For cases where the amount SHOULD be revealed (e.g., tax reporting, loan underwriting), the wallet holder can disclose the hash preimage. The verifier recomputes the leaf hash from the disclosed fields and confirms it matches the committed leaf.

```
1. Holder discloses: wallet_hash, serial_number, month, year, amount
2. Verifier computes: BLAKE2b_32(0x05 || len(serial) || serial || month_be || year_be)
3. Verifier checks: computed hash == leaf hash in the proof
4. Verifier now knows the exact inputs, confirmed by the on-chain anchor
```

This is opt-in. The holder chooses what to reveal. The on-chain commitment lets
the verifier check that the disclosed values match the committed leaf and the
anchored root. It does not, by itself, prove the off-chain truth of those values;
that still depends on the verifier's policy and any external evidence they
require.

## Cross-Chain Revenue Proof

Using the Solidity verifier on Ethereum:

```
1. Zcash miner earns shielded block rewards
2. ZAP1 attests POOL_PAYOUT for the period
3. Root is anchored (via coinbase memo or separate tx)
4. Anchor is registered on the Ethereum verifier contract
5. DeFi protocol on Ethereum calls verifyProof()
6. If valid: the miner proves income to an EVM lending protocol
```

The DeFi protocol sees: "this Zcash address participated in mining and was paid for period X." It does not see the amount, the Zcash transaction, or any other wallet activity.

## Integration with ZAP1 Export

The `zap1_export` tool already produces selective disclosure packages:

```bash
zap1_export --profile auditor --wallet WALLET_HASH
zap1_export --profile counterparty --wallet WALLET_HASH --serial SERIAL
zap1_export --profile regulator --wallet WALLET_HASH --full
```

Profiles control what gets disclosed:
- `auditor` - leaf hashes, proof paths, roots, anchor refs (no preimages)
- `counterparty` - above + specific event preimages for disclosed operations
- `regulator` - full preimage disclosure for all events

Each export is self-contained: the recipient can verify every claim offline using the proof paths and the anchor chain.

## Event Types Used

Any ZAP1 event type can serve as a revenue proof:

| Type | What it proves (without amount) |
|------|--------------------------------|
| `HOSTING_PAYMENT` (0x05) | Hosting was paid for a period |
| `STAKING_REWARD` (0x0C) | Staking reward was received |
| `POOL_PAYOUT` (0x22) | Pool payout was distributed |
| `POOL_HASHRATE` (0x21) | Hashrate was allocated |
| `GOVERNANCE_RESULT` (0x0F) | Governance outcome was recorded |

## Relationship to Credential Systems

This is a building block for ZK credential systems (see ONCHAIN_PROTOCOL.md, Credential Profile). A wallet with N revenue proofs can derive a credential like "active miner for 6+ months" or "all hosting payments current" without revealing which specific events or amounts.

The revenue proof is the leaf. The credential is an aggregate property over many leaves. ZAP1 provides the leaves. A future credential layer derives the properties.
