# ZAP1 credential design v0.1

Status: design only, not implemented

This note sketches selective-disclosure claims that could be built from ZAP1
receipts. The current verifier does not issue or validate these credentials.
Names such as `good_standing_90d` are requested operator claims, not facts
created by a Merkle proof.

## Base receipt

A proposed credential would contain:

```text
(claim_type, disclosed_witnesses, proof_bundles, root, transaction_reference)
```

For every positive event claim, the verifier would need to:

1. recompute the event leaf from the disclosed witness
2. verify inclusion under the supplied root and declared Merkle scheme
3. apply the claim-specific rule to the disclosed fields
4. check freshness under its own policy

A txid and height can establish transaction existence. Binding the supplied
root to an encrypted Orchard memo needs a separate safe opening.

## Candidate claims

### `good_standing_90d`

Possible evidence:

- disclosed `PROGRAM_ENTRY` preimage and inclusion proof
- disclosed `HOSTING_PAYMENT` preimages and inclusion proofs
- operator-issued timestamps or periods

The current system cannot prove that no payment gap or later `EXIT` exists.
It has no complete event-universe commitment and no non-inclusion proof.
Therefore `good standing` cannot be verified from current bundles.

### `deployed_asset`

Possible evidence:

- disclosed `OWNERSHIP_ATTEST` preimage and inclusion proof
- disclosed `DEPLOYMENT` preimage and inclusion proof
- equality checks over the disclosed serial field

This would show consistency of selected operator-issued claims. It would not
prove physical possession, facility installation, current ownership, or the
absence of a later transfer or exit.

### `payments_current`

Possible evidence:

- disclosed `HOSTING_PAYMENT` preimage
- inclusion proof
- verifier policy for acceptable month, year, and staleness

A `HOSTING_PAYMENT` leaf is an application claim. It does not identify a
wallet transaction, amount, payer, payee, or settlement unless separate primary
payment evidence is supplied. The public proof bundle withholds the preimage,
so a credential issuer must disclose it explicitly.

## Privacy boundary

A Merkle path reveals sibling hashes and the supplied root. Disclosed witnesses
reveal whatever fields the issuer includes. The historical field name
`wallet_hash` does not guarantee that the value was derived safely. Operators
must submit domain-separated pseudonyms and consider correlation across
credentials.

Selective disclosure is not zero knowledge. It hides undisclosed preimages but
does not prove their absence, unlinkability, or the truth of disclosed claims.

## Missing machinery

Production credentials require:

- a versioned credential schema
- authenticated witness provenance
- exact issuance and revocation rules
- completeness or non-inclusion machinery for negative claims
- root-authentication and safe memo-opening policy
- expiry and replay rules
- conformance vectors and an independent implementation

Until those exist, these are application design sketches. No legal, adoption,
payment, ownership, or good-standing conclusion should cite this document as
proof.
