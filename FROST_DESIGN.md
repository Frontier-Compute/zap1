# FROST Signing Architecture for ZAP1 Anchors

Status: Experimental design. Not production custody.

## Current implementation

The repository can build an Orchard anchor transaction and run a 2-of-3
FROST(Pallas, BLAKE2b-512) signing round. The current runtime is deliberately
classified as a co-located compatibility experiment:

- one process holds `ANCHOR_SEED`, which can derive the full spending key;
- that same process loads two long-term FROST shares;
- both signing rounds and aggregation happen in that process;
- there is no remote signer policy boundary or independent approval step.

The threshold math is real. The custody separation is not. Compromise of the
process or `ANCHOR_SEED` is enough to authorize a spend without an independent
share holder.

Runtime activation fails closed unless all of these values are explicit:

```text
SIGNING_MODE=frost
EXPERIMENTAL_COLOCATED_FROST_ENABLED=true
NETWORK=Testnet
FROST_SHARE_PATH_2=/path/to/first-share.json
FROST_SHARE_PATH_3=/path/to/second-share.json
```

This opt-in is for an authorized non-production experiment only. The runtime
rejects this signing mode on mainnet.

## Loader invariants

Before a share can be used, the implementation requires:

- ciphersuite exactly `FROST(Pallas, BLAKE2b-512)`;
- threshold exactly `2` and maximum signers exactly `3`;
- two distinct regular files, including hard-link identity checks;
- distinct participant identifiers;
- identical VSS commitment vectors;
- `group_verifying_key` equal to `commitment[0]`;
- each signing share to pass the VSS equation for its identifier;
- each declared verifying share to match the signing share and commitment;
- the FROST group key to match the Orchard wallet spend validating key.

Any mismatch stops startup. There is no fallback from FROST mode to single-key
signing.

## Production target

Production threshold custody requires a different process topology:

1. Build the unsigned anchor transaction in a coordinator with no full spending
   key and no signing quorum.
2. Keep each long-term share in a separate signer process and custody domain.
3. Show each signer the root, memo, recipient, amount, network, and transaction
   digest before approval.
4. Bind one-time nonce commitments and signature shares to that exact signing
   session.
5. Aggregate and verify the signature before broadcast.
6. Record the transaction identifier and confirmation independently of the
   signer transport.

At least two signer processes must be independent of the coordinator and of
each other. Removing only `ANCHOR_SEED` is insufficient if the coordinator still
holds two shares.

## Threat boundary

A real 2-of-3 deployment can tolerate loss or compromise of one share. It does
not protect against two-share collusion, bad transaction review, compromised
signer policy, nonce reuse, broadcast failure, or an incorrect Merkle root.

The current co-located experiment does not claim the one-share compromise
property. Its purpose is compatibility testing and negative validation of
ceremony inputs.

## Promotion gate

Do not describe FROST as production custody until all of these receipts exist:

- two independent signer services with authenticated, replay-resistant sessions;
- no full spending key and fewer than two shares in the coordinator process;
- testnet transaction and recovery tests;
- signer policy tests for wrong root, memo, recipient, amount, and network;
- nonce lifecycle and crash-recovery tests;
- an explicit mainnet authority gate and rollback procedure.

The ZAP1 memo and Merkle proof formats do not depend on the signing topology, so
historical proof verification remains unchanged.
