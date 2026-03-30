# FROST Threshold Signing Design Package

Date: 2026-03-28
Status: Design package and migration plan
Applies to: Nordic Shield ZAP1 anchor signing

## 1. Scope

This document describes how 2-of-3 FROST threshold signing would replace the current single-operator anchor signing path for `MERKLE_ROOT` commitments in the ZAP1 protocol.

It is intentionally limited to anchor signing. It does not change:

- ZAP1 memo format
- Merkle leaf construction
- Merkle root calculation
- proof bundle structure
- `PROGRAM_ENTRY`, `OWNERSHIP_ATTEST`, or other lifecycle event semantics

It changes only the authorization mechanism used when broadcasting the shielded transaction that carries the `ZAP1:09:{root_hex}` anchor memo.

## 2. Current State

Today, anchor signing is single-key and hot-wallet based.

Current production flow:

1. The reference implementation or `auto_anchor.sh` determines that anchoring is required.
2. The current Merkle root is encoded as `ZAP1:09:{root_hex}`.
3. `zingo-cli quicksend` or `anchor_root send` builds and broadcasts a shielded self-transfer carrying that memo.
4. The resulting txid is recorded in `merkle_roots.anchor_txid`.
5. After confirmation, `anchor_height` is recorded and the proof bundle is complete.

Source references:

- `ONCHAIN_PROTOCOL.md`
- `auto_anchor.sh`
- `src/bin/anchor_root.rs`
- `src/scanner.rs`

Current weakness:

- one operator-controlled seed can authorize all future anchors
- compromise of that seed is sufficient to forge future root-commit transactions from the anchor wallet
- operational separation is procedural only, not cryptographic

## 3. Existing FROST Assets

Two prototype code paths exist locally:

- `frost-custody/`
  Notes:
  Uses Ed25519. This is legacy and not correct for Zcash Orchard authorization.

- `frost-custody-pallas/`
  Notes:
  Uses `reddsa::frost::redpallas` on the Pallas curve, which is the correct direction for Orchard-compatible spend authorization.

The completed 2-of-3 Pallas ceremony produced:

- Ciphersuite: `FROST(Pallas, BLAKE2b-512)`
- Threshold: `2-of-3`
- Group verifying key:
  `5138a0e57d707a0f634f394cdd56999398047d44229b22cb062189caa2c90e90`

Stored key artifacts:

- `group_verifying_key.txt`
- `share-0100.json`
- `share-0200.json`
- `share-0300.json`

Current share placement plan from the prototype:

- share `0100`: operator VPS
- share `0200`: encrypted backup
- share `0300`: trusted second party or offline removable media

Important boundary:

- the Pallas prototype currently demonstrates key generation and share serialization
- it does not yet sign a real Zcash Orchard transaction end-to-end
- live anchor signing remains conditional on upstream stabilization

## 4. Integration Plan

### 4.1 Target Architecture

FROST replaces only the spend authorization step inside the anchor transaction flow.

Target flow:

1. The reference implementation computes the current unanchored Merkle root.
2. The anchor coordinator builds an unsigned anchor transaction with:
   - recipient: the existing shielded anchor address
   - amount: existing anchor dust amount
   - memo: `ZAP1:09:{root_hex}`
3. The coordinator derives the Orchard transaction sighash for that unsigned transaction.
4. The coordinator opens a FROST signing session for signer set `{i, j}` where any two of the three shares participate.
5. Each signer produces nonce commitments for the session.
6. The coordinator constructs the signing package bound to:
   - transaction sighash
   - signer identifiers
   - nonce commitments
   - group key
7. Each signer returns a signature share over the transaction sighash.
8. The coordinator aggregates the signature shares into one RedPallas signature that verifies under the group verifying key `5138a0e57d707a0f634f394cdd56999398047d44229b22cb062189caa2c90e90`.
9. The finalized transaction is assembled and broadcast.
10. `anchor_txid` and then `anchor_height` are recorded exactly as today.

### 4.2 Components

The production cutover requires four logical components.

Component A: unsigned anchor transaction builder

- builds the exact Orchard transaction body now sent by `zingo-cli`
- must expose the transaction sighash before final signature insertion
- must keep memo encoding identical to the current `MERKLE_ROOT` anchor

Component B: FROST coordinator

- selects two signers out of three
- manages one signing session per anchor attempt
- collects nonce commitments
- constructs the FROST signing package
- aggregates signature shares
- never holds two long-term shares locally in steady state

Component C: signer agents

- one agent per share location
- accepts signing packages only after local policy checks
- returns nonce commitments and signature shares
- never exports the long-term secret share

Component D: broadcaster / recorder

- broadcasts the finalized transaction
- extracts txid
- records `anchor_txid` and later `anchor_height`
- preserves current proof-bundle semantics

### 4.3 ZAP1 Compatibility

FROST does not alter the ZAP1 protocol contract.

Unchanged:

- memo type remains `0x09`
- memo payload remains the raw 32-byte Merkle root rendered as `ZAP1:09:{root_hex}`
- proof bundles still point to the anchored root, txid, and mined block height
- verifiers continue checking inclusion proof plus memo/root match

The signing system changes who authorizes the transaction, not what is committed on-chain.

### 4.4 Operational Roles

Recommended share holders:

- Share A: operator hot host used for coordination and one signing share
- Share B: encrypted recovery environment under separate access controls
- Share C: independent human counterparty or offline hardware share custodian

Recommended signer policies:

- no signer auto-signs without seeing root hash, leaf count, and intended recipient
- at least one signer should validate that the memo root equals the current unanchored root from the database or API
- at least one signer should be outside the main operator VPS trust boundary

## 5. Threat Model

### 5.1 Assets

Protected assets:

- authority to broadcast future `MERKLE_ROOT` anchor transactions
- continuity of the anchor wallet identity
- integrity of the memo root committed on-chain
- liveness of anchor operations

Non-protected assets:

- correctness of Merkle root computation itself
- correctness of off-chain business data used to create leaves
- proof verification logic on participant systems

### 5.2 Adversaries

Adversary classes:

- external attacker compromising the operator VPS
- malicious insider with access to one operational environment
- compromised backup service or backup credential set
- rogue coordinator attempting to get a signer to authorize an unintended transaction
- colluding two-share holders

### 5.3 What 2-of-3 Mitigates

Single-host key compromise

- if the operator VPS is compromised and only one share is exposed, the attacker cannot produce a valid anchor signature alone
- this is the main improvement over the current single-seed model

Rogue operator / unilateral signing

- one operator cannot authorize a new anchor without a second signer
- unilateral misuse of the anchor wallet becomes materially harder

Insider threat at one location

- theft of one share from backup storage or one human custodian does not authorize spending or anchoring by itself

Loss of one share

- one lost or unavailable share does not brick the anchor wallet because the remaining two shares still satisfy threshold

Operational segregation

- custody can be divided across three operational domains with different failure modes and access controls

### 5.4 What 2-of-3 Does Not Mitigate

Two-share collusion

- any two share holders can authorize an anchor transaction
- FROST does not prevent collusion by threshold participants

Bad root selection before signing

- if the signers approve a transaction with the wrong root in the memo, FROST faithfully authorizes that wrong root
- threshold signing protects authorization, not application semantics

Compromised coordinator plus permissive second signer

- if the coordinator constructs a malicious transaction and a second signer does not verify transaction contents, the threshold policy fails operationally

Broadcast-layer censorship or failure

- FROST does not solve relay failure, mempool rejection, or chain-level confirmation delays

Historic proof invalidation

- FROST does not change old anchors or repair any pre-existing data-quality problems

### 5.5 Trust Assumptions Per Share Holder

Share A: operator VPS

- assumed capable of coordination, database/API reads, and transaction assembly
- not trusted to sign alone
- expected to be the most exposed environment

Share B: encrypted backup holder

- assumed able to recover and sign in a controlled environment
- should not share runtime credentials with Share A
- should require a separate authentication channel and separate storage key

Share C: independent custodian

- assumed independent of the operator VPS
- may be a second human operator, legal counterparty, or offline hardware-controlled process
- must verify session metadata before participating

Minimum trust posture:

- any one share holder may fail or be compromised without total loss of signing authority
- no policy should assume Share A is honest by default

## 6. Migration Path

The migration must preserve anchor continuity and backward compatibility.

### Phase 0: Current production baseline

- keep current `zingo-cli` anchor path as production default
- continue recording `anchor_txid` and `anchor_height` exactly as today
- no change to proof bundles

### Phase 1: Freeze key material and document custody

1. Treat `share-*.json` as ceremony output, not application runtime config.
2. Remove any unnecessary local copies of shares `0200` and `0300` from the operator host after verified distribution.
3. Record out-of-band custody metadata:
   - holder
   - storage method
   - recovery procedure
   - revocation / rotation trigger

### Phase 2: Introduce a shadow coordinator

1. Build a coordinator that:
   - reads candidate root and anchor transaction parameters
   - constructs unsigned transaction intent
   - derives the transaction sighash
2. Run it in shadow mode only.
3. For each real anchor, store:
   - root hash
   - signer set that would have been chosen
   - sighash or canonical signing transcript identifier
4. Do not broadcast FROST-signed transactions yet.

Acceptance for this phase:

- FROST coordinator derives the same transaction intent that the single-key path would have broadcast
- no change to production signing

### Phase 3: Signer service bring-up

1. Implement signer services for two independent shares.
2. Require session approval fields:
   - root hash
   - memo string
   - recipient address
   - amount in zats
   - chain
3. Produce nonce commitments and signature shares for test transactions first.
4. Verify aggregated signatures against the group verifying key before any network broadcast.

Acceptance for this phase:

- successful aggregate signature verification under group key
- no production transaction broadcast required yet

### Phase 4: Testnet cutover

1. Move the FROST path to testnet.
2. Build and sign complete Orchard anchor transactions on testnet.
3. Confirm:
   - tx broadcast works
   - txid extraction works
   - memo root is unchanged
   - proof bundle generation still works

Acceptance for this phase:

- end-to-end anchor on testnet using threshold signing

### Phase 5: Mainnet guarded activation

1. Keep the current single-key path available as a manual fallback.
2. Enable FROST only for anchor transactions, not all wallet actions.
3. Start with operator-triggered manual anchors, not unattended automation.
4. Require explicit confirmation from two signers for each mainnet anchor.
5. After several successful anchors, re-enable automation around the FROST coordinator if desired.

Rollback:

- if upstream APIs or signer reliability regress, revert to the current single-key path without changing proof semantics

### Phase 6: Key rotation and old-proof compatibility

Existing proof bundles remain valid because they bind to:

- leaf hash
- Merkle proof
- root hash
- anchor txid
- anchor height

They do not depend on the private signing method used to authorize the anchor transaction.

Backward compatibility guarantee:

- anchors created under the single-key wallet remain valid forever
- future FROST-signed anchors use the same proof format
- no participant reissue or bundle migration is required purely because anchor signing changes

Operational note:

- if the anchor wallet address itself changes during migration, proof bundles remain valid for already-mined anchors because they reference txid and block height, not a mutable wallet alias
- however, keeping the same anchor wallet/address is preferable to minimize operator complexity and public explanation burden

## 7. Prerequisites

Live FROST anchor signing depends on upstream work that is not yet stable enough for production cutover.

### 7.1 Orchard `unstable-frost`

Needed:

- stable APIs for RedPallas / Orchard-compatible threshold signing
- predictable transaction sighash interface for external signing
- compatibility guarantees across crate updates

Current status:

- `unstable-frost` remains API-unstable
- production integration should not be pinned to it without a stabilization plan

### 7.2 `frost-rerandomized`

Needed:

- rerandomized signing flow compatible with Orchard spend authorization requirements
- clear guidance on nonce and transcript handling for RedPallas-based Zcash signing

Current status:

- library support exists in the ecosystem
- production Zcash transaction integration is not yet turnkey

### 7.3 `zcash-sign`

Needed:

- transaction builder that cleanly separates:
  - unsigned transaction construction
  - Orchard sighash derivation
  - external signature injection
- compatibility with the current Zebra / Orchard transaction path

Current status:

- `zcash-sign` is the most relevant upstream reference path
- it is not yet a drop-in replacement for the current production anchor flow

### 7.4 ZIP 312 and upstream protocol finalization

Needed:

- stable upstream transaction and authorization semantics for the target signing flow
- confidence that the chosen signing transcript will not churn underneath deployed code

Current status:

- production deployment should wait for the relevant upstream pieces to settle

### 7.5 Local implementation status

What is ready locally:

- Pallas 2-of-3 dealer key generation
- share serialization
- public group verifying key output

What is not ready locally:

- full signing-round implementation for Orchard transactions
- transaction builder that accepts aggregate FROST signatures
- production-safe signer transport and approval UX

## 8. Test Vectors

This section includes the public ceremony artifacts that exist today and can be verified independently. It does not publish secret shares or a fabricated aggregate signature.

### 8.1 Key Ceremony Vector

Ciphersuite:

- `FROST(Pallas, BLAKE2b-512)`

Threshold parameters:

- threshold: `2`
- max signers: `3`

Group verifying key:

- `5138a0e57d707a0f634f394cdd56999398047d44229b22cb062189caa2c90e90`

Dealer commitment vector from the generated share packages:

- commitment[0]:
  `5138a0e57d707a0f634f394cdd56999398047d44229b22cb062189caa2c90e90`
- commitment[1]:
  `8812e907da7f4e56d0509097228a067801ecb702262822027bf3a40dc35fbb38`

Participant identifiers:

- signer `0100`:
  `0100000000000000000000000000000000000000000000000000000000000000`
- signer `0200`:
  `0200000000000000000000000000000000000000000000000000000000000000`
- signer `0300`:
  `0300000000000000000000000000000000000000000000000000000000000000`

Public verifying shares:

- signer `0100`:
  `a2bf0278248da08a1c977e91d411b728ce5819a3084b43bc9110d5458d4e8ea0`
- signer `0200`:
  `fd02bd6f5bbd631b72d8e39a52d8e106ae278bc5b37354413b331314ef9a3b95`
- signer `0300`:
  `f96ca7656a5ff9fd3f248f9673c9db42e471aec017b67abc5771263194d1d99e`

Consistency checks:

- all three share files carry the same group verifying key
- all three share files carry the same commitment vector
- each identifier is unique
- any future aggregate signature must verify against the group key above

### 8.2 Canonical Anchor Intent Vector

This is the application-level message context that FROST would authorize for the first mainnet anchor already described in the protocol doc.

Anchor root:

- `024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a`

ZAP1 memo:

- `ZAP1:09:024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a`

Anchor amount:

- `1000` zats

Current recipient address used by `auto_anchor.sh`:

- `u10lx80uy82s0xfs72eyfq4w0g5z79n672lsjf7tlu5ep2gsp99q6gjdjsazcq34r6w55recw60v0230qdhdr9azl466zshtur2gwxmg5f`

Canonical signer set for a 2-of-3 example round:

- aggregator/coordinator: share holder `0100`
- signers: `0100` and `0200`
- offline reserve share: `0300`

Expected invariant:

- the aggregate signature produced by signers `0100` and `0200` must verify under group key
  `5138a0e57d707a0f634f394cdd56999398047d44229b22cb062189caa2c90e90`

### 8.3 Signing-Round Boundary

The current local prototype does not yet emit a real Orchard transaction signing transcript with:

- per-round nonce commitments
- signing package bytes
- signature share bytes
- final aggregate signature bytes

Those round artifacts are intentionally not invented here.

Deliverable boundary:

- The design package covers the ciphersuite, custody split, group key, public verifying shares, threat model, integration plan, and migration path
- Future work can add real transaction-signing vectors once the upstream Orchard / FROST interfaces are stable enough to produce them against testnet or mainnet-compatible staging

## 9. Implementation Notes

- The legacy Ed25519 prototype should not be used for Zcash signing.
- Any production FROST path should be built on the Pallas / RedPallas stack only.
- Signer transport should be authenticated and replay-resistant.
- Nonce material must be single-use and signer-local.
- The coordinator should persist enough session metadata for postmortem analysis but never store long-term secret shares.

## 10. Decision

Decision as of 2026-03-28:

- adopt now: Pallas key ceremony output and custody documentation
- prototype now: coordinator and signer scaffolding in shadow mode
- defer: live mainnet FROST anchor signing until Orchard-compatible APIs and transaction-building interfaces stabilize
