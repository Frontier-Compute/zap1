# Wyoming DAO LLC Compliance via Zcash

## Section VI Requirement

Wyoming Statute 17-31-104(c) requires a DAO LLC to identify a "smart contract" or equivalent on-chain artifact that governs or records the entity's operations.

## How ZAP1 Satisfies This

LiquidLV DAO LLC (Wyoming) uses the following Zcash Orchard address as its Section VI identifier:

```
u1qzfssuy2n2puqvafzjtq6qvjul7e985u75xsrnppcpd5c0sujs727xngaecx5yt4ljy6qlkr8hxsvj6d8gmxd7g6c9p3993hh5zwenq7
```

This is diversifier index 2 of the anchor UFVK. All ZAP1 Merkle root commitments are broadcast as shielded memo transactions from this address.

## What It Proves

The on-chain anchor history provides:

- **Operational record.** Every lifecycle state change (entry, ownership, deployment, hosting, renewal, transfer, exit) is committed to a Merkle tree whose root is anchored to Zcash.
- **Public verifiability.** Anyone can verify that a commitment was made at a specific block height by checking the anchor transaction.
- **Private operations.** The underlying data (participant identity, wallet hashes, serial numbers) stays off-chain. Only derived hashes appear in the shielded memo.
- **Audit path.** A viewing key holder can decrypt the memo and verify the full commitment chain.

## Verification

1. Check the anchor history: `https://pay.frontiercompute.io/anchor/history`
2. Verify a specific proof: `https://pay.frontiercompute.io/verify/{leaf_hash}/check`
3. Confirm the anchor transaction on any Zcash explorer using the txid
4. Use `verify_proof.py` from the [zap1 repo](https://github.com/Frontier-Compute/zap1) for independent verification

## Why Zcash

A Wyoming DAO LLC typically points to an Ethereum smart contract address for Section VI compliance. Zcash offers a different model:

- The operational record is on-chain and verifiable (same as Ethereum)
- The operational data is private (unlike Ethereum, where smart contract state is public)
- The entity can prove compliance to regulators via viewing keys without exposing operations to competitors

This makes Zcash suitable for DAOs that need public accountability and private operations simultaneously.

## First Anchor

- Txid: `98e1d6a01614c464c237f982d9dc2138c5f8aa08342f67b867a18a4ce998af9a`
- Block: 3,286,631
- Root: `024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a`
- Date: March 27, 2026
