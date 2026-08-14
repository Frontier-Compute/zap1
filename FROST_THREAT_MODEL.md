# FROST Threat Model for ZAP1 Anchors

Date: 2026-08-13

Status: Experimental co-located implementation. Not production custody.

## Scope

ZAP1 can use a RedPallas signature produced by a 2-of-3
FROST(Pallas, BLAKE2b-512) group for Orchard spend authorization. This changes
the transaction signing mechanism. It does not change the ZAP1 memo, leaf,
Merkle root, proof bundle, or confirmation semantics.

## Current custody fact

The current embedded path loads all of this material into one process:

- `ANCHOR_SEED`, which derives the full Orchard spending key;
- two long-term FROST share files;
- the FROST coordinator and aggregator;
- the transaction builder and broadcaster.

This topology does not provide independent threshold custody. A process
compromise can reach the full key and a FROST quorum. The implementation proves
that the signature path works with Orchard transaction construction. It does not
prove that one compromised host cannot spend.

The runtime rejects `SIGNING_MODE=frost` unless the operator also sets the
narrow opt-in `EXPERIMENTAL_COLOCATED_FROST_ENABLED=true`. This gate is for an
explicitly authorized non-production experiment, and the runtime also requires
`NETWORK=Testnet`. It is not a production waiver.

## Cryptographic input controls

The share loader accepts only the fixed 2-of-3 profile:

- ciphersuite: `FROST(Pallas, BLAKE2b-512)`;
- threshold: `2`;
- maximum signers: `3`;
- two distinct regular files and two distinct participant identifiers;
- the same two-coefficient VSS commitment vector in both files;
- group verifying key equal to the constant coefficient commitment;
- each secret share valid against the VSS commitment;
- each public verifying share derived from its secret share and commitment.

The anchor wallet separately requires the derived group key to equal its Orchard
spend validating key. Every mismatch stops startup. FROST mode never falls back
to the single-key signer.

These checks reject corrupt or mixed ceremony artifacts. They do not create a
custody boundary between values loaded into the same process.

## Assets

The signing system protects authority to spend anchor-wallet funds and authorize
future root-carrying transactions. It does not establish that the selected root
is correct, that an off-chain event is true, or that a transaction confirms.

## Adversaries

Relevant adversaries include:

- an attacker controlling the anchor process or host;
- an attacker replacing one or both share files;
- a stale or mixed ceremony package;
- a coordinator proposing the wrong root, memo, recipient, amount, or network;
- two colluding share holders in a future distributed deployment;
- a signer or coordinator reusing nonce material;
- a broadcaster that drops, duplicates, or misreports a transaction.

## Current implementation ruling

The co-located path mitigates malformed ceremony inputs and exercises the
cryptographic signing interface. It does not mitigate:

- compromise of the anchor process;
- compromise of `ANCHOR_SEED`;
- unilateral operation by the holder of both local shares;
- lack of an independent transaction review;
- process memory disclosure of both shares;
- two-share collusion.

Do not describe the current path as multisig custody, independent approval,
distributed signing, treasury protection, or single-host compromise resistance.

## Production target

A production topology requires four separate roles:

1. A coordinator builds an unsigned transaction and holds no full spending key
   and no signing quorum.
2. Signer A holds one long-term share and enforces local transaction policy.
3. Signer B holds another long-term share in a separate custody domain and
   enforces the same policy independently.
4. A broadcaster records submission and confirmation state without gaining
   signing authority.

The third share remains an independent recovery share. Any two shares can sign,
so custody policy must prevent two shares from sharing one compromise domain.

Each signer must verify the network, root, memo, recipient, amount, fee, expiry,
transaction digest, signer set, and one-time session identifier before creating
a nonce commitment or signature share. Signer transport must be authenticated,
replay-resistant, and crash-safe. Nonces must never be reused.

## What a distributed 2-of-3 deployment would and would not provide

With independent signer processes, compromise or loss of one share need not
authorize a spend or stop signing. Any two share holders can still authorize a
transaction. FROST does not protect against bad application data, permissive
signer policy, two-party collusion, relay failure, or chain reorganization.

Threshold signing protects authorization only. It does not prove the Merkle root
or its off-chain inputs are correct.

## Promotion requirements

Production promotion remains blocked until there are receipts for:

- removal of `ANCHOR_SEED` and any two-share quorum from the coordinator;
- two independently operated signer services;
- authenticated and replay-resistant session transport;
- signer-side transaction policy tests;
- nonce lifecycle, restart, timeout, and partial-round recovery tests;
- complete testnet transaction construction, broadcast, and confirmation;
- rotation and loss-of-one-share recovery;
- an explicit mainnet activation authority and rollback plan.

Until those requirements pass, keep `SIGNING_MODE=single_key` in production and
keep `EXPERIMENTAL_COLOCATED_FROST_ENABLED=false`.

## Test boundary

Local tests cover valid signing, rerandomized signing, exact 2-of-3 parameters,
file identity, unique identifiers, common commitments, group-key binding,
declared verifying-share consistency, and VSS validation of each secret share.
They do not establish production custody or network deployment.
