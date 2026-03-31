# ONCHAIN_PROTOCOL.md

**Version:** 2.2.0  
**Date:** 2026-03-28  
**Status:** Deployed on Zcash mainnet

## 1. Overview

ZAP1 uses the Zcash blockchain as the source of truth for attestation operations. Every significant event is represented as a structured memo commitment and aggregated into a BLAKE2b Merkle tree whose root is periodically anchored to Zcash. Participants verify ownership, deployment, hosting history, renewal history, transfer history, and exit history from the chain record plus Merkle proofs, with no trust required in a private operator database. Nordic Shield is the first production deployment of this protocol.

ZAP1 is the open attestation protocol layer, implemented through the reference tooling and operating procedures described here. No participant PII is recorded on-chain; only wallet hashes, serial hashes, and derived payload hashes are used.

Mainnet proof reference:

- first anchor txid: `98e1d6a01614c464c237f982d9dc2138c5f8aa08342f67b867a18a4ce998af9a`
- block height: `3,286,631`
- anchored root: `024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a`

## 2. Memo Protocol

This binary layout is a transitional encoding. When ZIP 302 (Structured Memos)
ships, ZAP1 payloads should be carried as a ZIP 302 part type. The attestation
semantics below (event types, hash construction, Merkle rules) are independent
of the memo container.

The deployed memo encoding is:

```text
ZAP1:{type}:{payload_hash}
```

Where:

- `ZAP1` is the protocol marker (legacy memos use `NSM1`, accepted during decode)
- `{type}` is the two-digit lowercase hex event type byte (01-0c)
- `{payload_hash}` is the 64-character hex encoding of the 32-byte BLAKE2b-256 payload hash

Total memo size: 73 bytes (4 + 1 + 2 + 1 + 64 + 1 separators). Fits in any Zcash shielded memo (512 bytes pre-ZIP 231, 16 KiB post-ZIP 231).

The payload hash is computed per event type using BLAKE2b-256 with `NordicShield_` personalization. See EVENT_SCHEMA.md for the full hash construction rules per type.

Transaction types:

| Type | Name | Payload definition | Status |
| --- | --- | --- | --- |
| `0x01` | `PROGRAM_ENTRY` | `hash(wallet_hash)` | Active |
| `0x02` | `OWNERSHIP_ATTEST` | `hash(wallet_hash || serial_number)` | Active |
| `0x03` | `CONTRACT_ANCHOR` | `hash(serial_number || contract_sha256)` | Active |
| `0x04` | `DEPLOYMENT` | `hash(serial_number || facility_id || timestamp)` | Active |
| `0x05` | `HOSTING_PAYMENT` | `hash(serial_number || month || year)` | Active |
| `0x06` | `SHIELD_RENEWAL` | `hash(wallet_hash || year)` | Active |
| `0x07` | `TRANSFER` | `hash(old_wallet || new_wallet || serial_number)` | Active |
| `0x08` | `EXIT` | `hash(wallet_hash || serial_number || timestamp)` | Active |
| `0x09` | `MERKLE_ROOT` | raw 32-byte Merkle root | Active |
| `0x0A` | `STAKING_DEPOSIT` | `hash(wallet_hash || amount_zat_be || validator_id)` | Reserved for Crosslink |
| `0x0B` | `STAKING_WITHDRAW` | `hash(wallet_hash || amount_zat_be)` | Reserved for Crosslink |
| `0x0C` | `STAKING_REWARD` | `hash(wallet_hash || epoch_be || reward_zat_be)` | Reserved for Crosslink |

The protocol now defines twelve event types: nine deployed in production and three reserved for Crosslink staking.

## 3. Hash Construction

All event hashes use BLAKE2b with 32-byte output and the personalization string:

```text
NordicShield_
```

Input construction by type:

```text
PROGRAM_ENTRY      = BLAKE2b_32(0x01 || wallet_hash)
OWNERSHIP_ATTEST   = BLAKE2b_32(0x02 || len(wallet_hash) || wallet_hash || len(serial_number) || serial_number)
CONTRACT_ANCHOR    = BLAKE2b_32(0x03 || len(serial_number) || serial_number || len(contract_sha256) || contract_sha256)
DEPLOYMENT         = BLAKE2b_32(0x04 || len(serial_number) || serial_number || len(facility_id) || facility_id || timestamp_be)
HOSTING_PAYMENT    = BLAKE2b_32(0x05 || len(serial_number) || serial_number || month_be || year_be)
SHIELD_RENEWAL     = BLAKE2b_32(0x06 || len(wallet_hash) || wallet_hash || year_be)
TRANSFER           = BLAKE2b_32(0x07 || len(old_wallet) || old_wallet || len(new_wallet) || new_wallet || len(serial_number) || serial_number)
EXIT               = BLAKE2b_32(0x08 || len(wallet_hash) || wallet_hash || len(serial_number) || serial_number || timestamp_be)
MERKLE_ROOT        = current_root
STAKING_DEPOSIT    = BLAKE2b_32(0x0A || wallet_hash || amount_zat_be || validator_id)
STAKING_WITHDRAW   = BLAKE2b_32(0x0B || wallet_hash || amount_zat_be)
STAKING_REWARD     = BLAKE2b_32(0x0C || wallet_hash || epoch_be || reward_zat_be)
```

Implementation notes:

- `wallet_hash` is an operator-generated hash derived from the participant wallet
- `serial_hash` in the memo layout is `BLAKE2b_32(serial_number)` when a serial exists
- `contract_sha256` is the SHA-256 digest of the hosted contract artifact
- integer fields are big-endian
- no memo payload includes participant name, email, phone number, or postal address
- `STAKING_DEPOSIT`, `STAKING_WITHDRAW`, and `STAKING_REWARD` are reserved for Crosslink. They are not yet active, and their hash construction is preliminary and subject to change when the Crosslink staking protocol finalizes.

## 4. Merkle Tree

The protocol uses an append-only binary BLAKE2b Merkle tree.

Rules:

- each program event produces one leaf
- leaves are ordered by insertion sequence
- the tree only grows; leaves are never deleted or rewritten
- parent nodes are computed as `BLAKE2b_32(left || right)`
- node hashing uses the personalization `NordicShield_MRK`
- if a layer has an odd leaf count, the final node is duplicated
- the current root is recomputed after each insertion
- root history is preserved so older proofs remain tied to a specific anchor

Persistence model:

- `merkle_leaves`: leaf hash, event type, wallet hash, serial number, created time
- `merkle_roots`: root hash, leaf count, anchor txid, anchor height, created time

An inclusion proof consists of the leaf hash, ordered sibling hashes, sibling positions, the derived root, and the anchor transaction reference for that root.

## 5. On-Chain Anchoring

The current Merkle root is periodically committed to Zcash in a shielded transaction.

Anchor rules:

- memo type is always `0x09`
- payload is the 32-byte current Merkle root
- send path uses `zingo-cli`
- anchor cadence is every 10 events or every 24 hours, whichever comes first
- the resulting txid and mined block height are recorded with the root

Operational flow:

1. The reference implementation reads the latest root from the Merkle store.
2. The root is encoded as an `ZAP1:09` memo.
3. A dust self-transfer or controlled shielded transfer is broadcast with that memo.
4. The txid becomes the public proof handle for that committed root.
5. When mined, the block height is recorded alongside the root.

The txid is part of the proof bundle. A verifier checks the memo in the mined transaction and confirms it matches the Merkle root derived from the proof path.

## 6. Participant Verification

Participant verification flow:

1. Open `pay.frontiercompute.io/verify/{leaf_hash}`.
2. Read the displayed leaf hash, Merkle proof path, root, anchor txid, and block height.
3. Recompute the event leaf from the participant wallet hash and, where applicable, the serial number.
4. Walk the proof path to recompute the root.
5. Confirm the derived root equals the displayed root.
6. Open the anchor txid in a Zcash explorer or with local node tooling.
7. Confirm the memo contains the matching `ZAP1:09` root commitment.
8. Confirm the transaction is mined at the stated block height on Zcash mainnet.

CLI verification can be implemented as:

```bash
verify_leaf --wallet-hash <wallet_hash> --serial <serial> --proof <proof.json> --txid <anchor_txid>
```

The CLI tool is a verifier convenience. The verification model does not depend on a Frontier Compute web page.

## 7. Lifecycle Flow

The full participant lifecycle uses these event classes:

1. Participant pays the starter-pack invoice: `PROGRAM_ENTRY`
2. Machine serial is assigned to the wallet: `OWNERSHIP_ATTEST`
3. Hosting contract artifact is hashed and committed: `CONTRACT_ANCHOR`
4. Machine is installed and activated at the facility: `DEPLOYMENT`
5. Monthly hosting invoice is paid: `HOSTING_PAYMENT`
6. Annual privacy shield is renewed: `SHIELD_RENEWAL`
7. Ownership changes to a new wallet: `TRANSFER`
8. Participant exits or requests delivery or termination: `EXIT`
9. Every batch of deployed events is committed by `MERKLE_ROOT`
10. Reserved Crosslink staking events (`STAKING_DEPOSIT`, `STAKING_WITHDRAW`, `STAKING_REWARD`) remain inactive until the staking protocol is finalized

This produces a continuous on-chain record for the program lifecycle, while keeping participant identity off-chain.

## 8. Transfer Protocol

Ownership transfers are recorded as permanent program events.

Transfer flow:

1. Current owner supplies a new wallet hash.
2. Operator verifies transfer intent off-chain.
3. The protocol creates a `TRANSFER` event binding old wallet, new wallet, and serial number.
4. The transfer leaf is inserted into the Merkle tree.
5. A later `MERKLE_ROOT` anchor commits that transfer to Zcash.
6. Old owner dashboard state changes to transferred.
7. New owner dashboard state includes the inherited machine history.

The old and new wallet hashes are the only ownership identifiers used in the on-chain record.

## 9. Wyoming DAO LLC Compliance

Section VI of the LiquidLV DAO LLC articles of organization requires a public smart contract identifier. LiquidLV DAO LLC uses the Zcash anchor address for the ZAP1 protocol as that identifier.

Compliance mapping:

- the anchor address is the public identifier
- `ONCHAIN_PROTOCOL.md` is the published protocol specification
- Merkle root anchor transactions are the public audit trail
- the sequence of anchored roots shows the DAO's program operations on-chain

For Wyoming filing purposes, the protocol is the DAO's audit and commitment layer implemented on Zcash. The anchor address and this specification together identify the mechanism used for DAO operations under Section VI.

## 10. Security Considerations

- no participant PII is written to the chain
- BLAKE2b personalization separates ZAP1 hashes from other protocol contexts
- Merkle proofs are non-interactive and independently checkable
- shielded memos limit public disclosure while still allowing controlled verification
- anchor transactions are low-value self-commits, minimizing cost
- FROST 2-of-3 signing can protect treasury or protocol-controlled funds where used
- serial assignment still depends on correct operational handling by the operator
- the chain record is immutable after confirmation, but off-chain business inputs must still be entered correctly

## 11. API Reference

The deployed API exposes event insertion, lifecycle lookup, and operational stats. The protocol now defines twelve event types (nine deployed, three reserved for Crosslink staking). This section documents the protocol-level contract for those endpoints.

### `POST /event`

Creates one protocol event and inserts the corresponding leaf into the Merkle tree. Requires API key authentication.

Common required fields for all event requests:

- `event_type`  - one of: `CONTRACT_ANCHOR`, `DEPLOYMENT`, `HOSTING_PAYMENT`, `SHIELD_RENEWAL`, `TRANSFER`, `EXIT`
- `wallet_hash`  - participant wallet identifier

Timestamps are generated server-side. `PROGRAM_ENTRY` and `OWNERSHIP_ATTEST` are created automatically by the scanner and `/assign` endpoint respectively, not via `/event`.

Required fields by event type:

| Event type | Required fields |
| --- | --- |
| `CONTRACT_ANCHOR` | `wallet_hash`, `serial_number`, `contract_sha256` |
| `DEPLOYMENT` | `wallet_hash`, `serial_number`, `facility_id` |
| `HOSTING_PAYMENT` | `wallet_hash`, `serial_number`, `month`, `year` |
| `SHIELD_RENEWAL` | `wallet_hash`, `year` |
| `TRANSFER` | `wallet_hash` (old), `new_wallet_hash`, `serial_number` |
| `EXIT` | `wallet_hash`, `serial_number` |

Response includes `leaf_hash`, `root_hash`, and `verify_url`.

Protocol notes:

- `PROGRAM_ENTRY` is created automatically when a `program` or `initial` invoice transitions to `paid`
- `OWNERSHIP_ATTEST` is created automatically via `POST /assign`
- `HOSTING_PAYMENT` and `SHIELD_RENEWAL` are also created automatically when the corresponding invoice type (`hosting` or `renewal`) is paid
- `MERKLE_ROOT` is the anchor commitment; created by the `anchor_root` binary or anchor automation

### `GET /lifecycle/{wallet_hash}`

Returns the lifecycle view for one participant wallet hash.

Expected contents:

- wallet-scoped event history
- linked serials
- leaf hashes
- proof and anchor references where available
- current participant state derived from the committed event sequence

### `GET /stats`

Returns aggregate operational state for the deployed stack.

Expected contents:

- Merkle leaf counts
- root counts
- event counts by type
- scanner or chain sync status
- other deployment-level metrics suitable for operator and public status surfaces

### `POST /auto-invoice`

Generates monthly hosting invoices for all active miners. Requires API key authentication.

Request fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `amount_zec` | number | Yes | Per-machine hosting amount in ZEC before wallet aggregation |
| `month` | integer | Yes | `1..12` |
| `year` | integer | Yes | `2020..2100` |
| `expires_in_hours` | integer | No | Defaults to `168` hours |

Behavior notes:

- aggregates miner assignments by wallet
- multiplies `amount_zec` by machine count per wallet
- skips wallets that already have a hosting invoice for that billing month
- generates one invoice per wallet for the billing period
- response includes invoice metadata and pay links

Expected response shape:

| Field | Meaning |
| --- | --- |
| `created` | Number of invoices created |
| `skipped` | Number of wallets skipped because an invoice already exists |
| `invoices` | Created invoices with `invoice_id`, `wallet_hash`, `machines`, `serials`, `pay_url` |
| `period` | Billing period in `YYYY-MM` format |

### `GET /cohort`

Returns aggregate program and cohort stats for operator views and participant dashboards.

Response fields:

| Field | Meaning |
| --- | --- |
| `total_machines` | Total machines in the program |
| `total_participants` | Total participant wallets with miner assignments |
| `total_hashrate_khs` | Aggregate planned or assigned hashrate in KH/s |
| `total_kw` | Aggregate power draw in kW |
| `current_tier` | Current hosting tier |
| `machines_to_next_tier` | Machines needed to reach the next tier |
| `next_tier` | Next hosting tier target |
| `total_leaves` | Total Merkle leaves |
| `total_anchors` | Total anchored Merkle roots |
| `first_anchor_block` | First anchored block height |
| `last_anchor_block` | Most recent anchored block height |
| `zec_per_month_per_machine` | Current planning estimate for monthly ZEC output per machine |
| `estimated_total_zec_month` | Aggregate estimated monthly ZEC output across the cohort |

### `GET /miner/{wallet_hash}`

The participant dashboard now includes:

- revenue estimate fields: `ZEC / month`, `ZEC / year`, `All-in cost / ZEC`, `Hosting / month`
- cohort progress data: total machines, current tier, machines to next tier, progress bar

Dashboard notes:

- revenue scales with the number of machines assigned to the wallet
- hosting cost is tier-aware
- the rendered dashboard is a participant convenience surface, not a protocol proof surface

## 12. Profiles

ZAP1 defines a base profile and reserves extension points for future proving and credential systems.

### ZAP1 Base Profile (current, deployed)

Deterministic hash-and-Merkle attestation. Event payloads are hashed with BLAKE2b-256 using domain-separated personalization. Leaves are aggregated into a Merkle tree. Roots are anchored to Zcash via shielded memos. Verification: recompute hash, walk Merkle path, check anchor.

This profile is stable. All existing proof bundles, test vectors, and verification tools target the base profile.

### ZAP1 Proof Profile (reserved)

Optional ZK proof attachment for proof-carrying attestation. When present, a `proof_commitment` field in the event bundle binds a zero-knowledge proof to the leaf hash. The proof attests that the payload was correctly derived from private inputs matching a declared schema, without revealing those inputs.

The proof profile is proving-system agnostic. Implementations may use any system that produces a verifiable commitment, including but not limited to:
- Jolt (a16z crypto)  - zkVM for general computation
- Nova / SuperNova  - folding schemes for incremental computation
- Halo 2 (Zcash Foundation)  - recursive proof composition

The base profile leaf hash remains unchanged. The proof commitment is an optional extension that verification tools may check when present and ignore when absent.

### ZAP1 Credential Profile (reserved)

Derive privacy-preserving credentials from attestation history. A participant with N lifecycle events committed to the Merkle tree can prove properties of their history (e.g., "participant for 6+ months", "all hosting payments current") without revealing their wallet hash or specific events.

This profile enables cross-operator credential portability: a credential derived from one ZAP1 deployment can be verified against the anchored Merkle root without contacting the issuing operator.

The credential profile depends on the proof profile and is not expected to deploy before proving system integration stabilizes.

## 13. Versioning and Extension Policy

- The event type registry (0x01 - 0x0C) is append-only. Existing types are never redefined.
- New event types are allocated by incrementing the type byte. Types 0x0D - 0xFF are reserved.
- Profiles are namespaced: `base`, `proof`, `credential`. New profiles do not modify the base profile.
- Hash construction rules for the base profile are frozen at v2.2.0. Changes require a new major version.
- The `NordicShield_` personalization is deployment-specific. Other deployments may use different personalization strings without conflicting with the protocol specification. The zap1-verify SDK (v0.2.0+) accepts configurable personalization.
