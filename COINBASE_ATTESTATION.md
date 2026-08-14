# Coinbase attestation research note

Status: proposal, not implemented

Zcash supports shielded coinbase under ZIP 213. That does not by itself provide
a public ZAP1 root transport. Shielded memo contents are encrypted, and current
NU6.3 Zebra consensus code requires the Orchard component of a coinbase
transaction to be empty.

Primary references:

- [ZIP 213: Shielded Coinbase](https://zips.z.cash/zip-0213)
- [Zebra coinbase structure checks](https://github.com/ZcashFoundation/zebra/blob/main/zebra-consensus/src/transaction/check.rs)

The active ZAP1 implementation does not inject roots into block templates,
does not scan coinbase transactions as a distinct attestation transport, and
does not expose a verifier for a coinbase-carried root.

The proposed mining-pool event bytes `0x20` to `0x27` are unassigned. They are
not reserved by the active registry and the API rejects them. Any future
allocation needs a versioned registry change, exact hash vectors, scanner
support, and a verifier that checks the serialized transaction field carrying
the commitment.

The production path remains a separately created shielded transaction with a
recorded txid and height. Public verification can check transaction existence.
Binding the listed root to an encrypted memo still requires a safe opening
artifact.
