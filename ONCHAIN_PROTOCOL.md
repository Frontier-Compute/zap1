# ONCHAIN_PROTOCOL.md

**Specification Version: 3.0.0**

**Version:** 3.0.0  
**Date:** 2026-03-28  
**Status:** Reference implementation; older reachable service reports Mainnet

## 1. Overview

ZAP1 aggregates typed event claims into a BLAKE2b Merkle tree whose root can be written to an encrypted Zcash memo. Merkle proofs let a verifier recompute inclusion in a supplied root. Transaction IDs establish transaction existence, but Orchard memo contents are encrypted; independently binding a root to a transaction requires a safe disclosure/opening artifact. A Merkle proof does not establish that the underlying event claim is true. An older reachable service reports Mainnet; that does not establish deployment of the current repository candidate.

ZAP1 is the open attestation protocol layer implemented by the reference
tooling described here. The memo carries a derived payload hash, not the event
preimage. The service still stores operator-submitted fields off-chain, so
integrators must apply their own pseudonymization and access controls.
The `/miner/{wallet_hash}` route family, `/lifecycle/{wallet_hash}`, and full
`GET /invoice/{id}` JSON route require operator bearer authentication. Payment
pages use UUID invoice URLs as bearer capabilities and can disclose a payment
request to anyone who obtains the URL.

Historical mainnet transaction reference:

- first recorded txid: `98e1d6a01614c464c237f982d9dc2138c5f8aa08342f67b867a18a4ce998af9a`
- block height: `3,286,631`
- API-recorded root: `024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a`
- scheme: `ZAP1_LEGACY_DUPLICATE_ODD` (historical anchor; current roots use count-bound commitments)

The reference deployment records this root-to-transaction mapping. The
transaction can be independently located, but no public memo-opening artifact
is currently published, so the encrypted memo contents are not independently
verified by this document alone.

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
- `{type}` is the two-digit lowercase hex event type byte from the defined registry
- `{payload_hash}` is the 64-character hex encoding of the 32-byte BLAKE2b-256 payload hash

Total memo size: 72 bytes (4 + 1 + 2 + 1 + 64). Fits in any Zcash shielded memo (512 bytes pre-ZIP 231, 16 KiB post-ZIP 231).

The payload hash is computed per event type using BLAKE2b-256 with `NordicShield_` personalization. See [docs/EVENT_SCHEMA.md](docs/EVENT_SCHEMA.md) for the full hash construction rules per type.

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
| `0x09` | `MERKLE_ROOT` | raw 32-byte Merkle root commitment | Active |
| `0x0A` | `STAKING_DEPOSIT` | `hash(wallet_hash || amount_zat_be || validator_id)` | Implemented, experimental/legacy |
| `0x0B` | `STAKING_WITHDRAW` | `hash(wallet_hash || amount_zat_be || validator_id)` | Implemented, experimental/legacy |
| `0x0C` | `STAKING_REWARD` | `hash(wallet_hash || amount_zat_be || epoch_be)` | Implemented, experimental/legacy |
| `0x0D` | `GOVERNANCE_PROPOSAL` | `hash(wallet_hash || proposal_id || proposal_hash)` | Implemented, experimental/legacy |
| `0x0E` | `GOVERNANCE_VOTE` | `hash(wallet_hash || proposal_id || vote_commitment)` | Implemented, experimental/legacy |
| `0x0F` | `GOVERNANCE_RESULT` | `hash(wallet_hash || proposal_id || result_hash)` | Implemented, experimental/legacy |
| `0x40` | `AGENT_REGISTER` | `hash(agent_id || pubkey_hash || model_hash || policy_hash)` | Implemented |
| `0x41` | `AGENT_POLICY` | `hash(agent_id || policy_version_be || rules_hash)` | Implemented |
| `0x42` | `AGENT_ACTION` | `hash(agent_id || action_type || input_hash || output_hash)` | Implemented |

The reference implementation defines 18 event types. `POST /event` accepts 15;
`PROGRAM_ENTRY`, `OWNERSHIP_ATTEST`, and `MERKLE_ROOT` are system-managed.

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
MERKLE_ROOT        = current count-bound Merkle root commitment
STAKING_DEPOSIT     = BLAKE2b_32(0x0A || len(wallet_hash) || wallet_hash || amount_zat_be || len(validator_id) || validator_id)
STAKING_WITHDRAW    = BLAKE2b_32(0x0B || len(wallet_hash) || wallet_hash || amount_zat_be || len(validator_id) || validator_id)
STAKING_REWARD      = BLAKE2b_32(0x0C || len(wallet_hash) || wallet_hash || amount_zat_be || epoch_be)
GOVERNANCE_PROPOSAL = BLAKE2b_32(0x0D || len(wallet_hash) || wallet_hash || len(proposal_id) || proposal_id || len(proposal_hash) || proposal_hash)
GOVERNANCE_VOTE     = BLAKE2b_32(0x0E || len(wallet_hash) || wallet_hash || len(proposal_id) || proposal_id || len(vote_commitment) || vote_commitment)
GOVERNANCE_RESULT   = BLAKE2b_32(0x0F || len(wallet_hash) || wallet_hash || len(proposal_id) || proposal_id || len(result_hash) || result_hash)
AGENT_REGISTER      = BLAKE2b_32(0x40 || len(agent_id) || agent_id || len(pubkey_hash) || pubkey_hash || len(model_hash) || model_hash || len(policy_hash) || policy_hash)
AGENT_POLICY        = BLAKE2b_32(0x41 || len(agent_id) || agent_id || policy_version_be || len(rules_hash) || rules_hash)
AGENT_ACTION        = BLAKE2b_32(0x42 || len(agent_id) || agent_id || len(action_type) || action_type || len(input_hash) || input_hash || len(output_hash) || output_hash)
```

Implementation notes:

- except for the historical `PROGRAM_ENTRY` formula, `len(value)` is the
  UTF-8 byte length encoded as an unsigned two-byte big-endian integer
- `PROGRAM_ENTRY` hashes the submitted `wallet_hash` bytes directly after
  the type byte for compatibility with the implemented profile
- `wallet_hash` is an operator-submitted subject identifier; the API does not
  independently derive or authenticate it
- `serial_hash` in the memo layout is `BLAKE2b_32(serial_number)` when a serial exists
- `contract_sha256` is the SHA-256 digest of the hosted contract artifact
- integer fields are big-endian
- no memo payload includes participant name, email, phone number, or postal address
- types `0x0A` through `0x0F` are accepted by the current implementation and
  occur in historical data, but their higher-level staking and governance
  semantics remain experimental; they are not a claim that Crosslink is final

## 4. Merkle Tree

The protocol uses an append-only binary BLAKE2b Merkle tree.

Rules:

- each program event produces one leaf
- leaves are ordered by insertion sequence
- the tree only grows; leaves are never deleted or rewritten
- parent nodes are computed as `BLAKE2b_32(left || right)`
- node hashing uses the personalization `NordicShield_MRK`
- if a layer has an odd node count, the final node carries up unchanged
- the raw tree root is committed as `BLAKE2b_32(0x01 || leaf_count_be_u64 || raw_tree_root)`
- root commitment hashing uses the personalization `NordicShield_RTK`
- the current committed root is recomputed after each insertion
- root rows are preserved; only roots with a recorded transaction reference
  have an anchor mapping
- historical anchors produced before count binding used odd-node duplication and are verified only under `ZAP1_LEGACY_DUPLICATE_ODD`

Persistence model:

- `merkle_leaves`: leaf hash, event type, wallet hash, serial number, created time
- `merkle_roots`: root hash, leaf count, anchor txid, anchor height, created time

An inclusion proof consists of the leaf hash, ordered sibling hashes, sibling positions, leaf count, the derived root commitment, and the anchor transaction reference for that root.

## 5. On-Chain Anchoring

The current Merkle root is periodically committed to Zcash in a shielded transaction.

Anchor rules:

- memo type is always `0x09`
- payload is the 32-byte current Merkle root commitment
- send path uses `zingo-cli`
- intended anchor trigger is every 10 events or every 24 hours, whichever comes
  first; public liveness must be checked because the trigger is not a guarantee
- the resulting txid and mined block height are recorded with the root

Operational flow:

1. The reference implementation reads the latest root from the Merkle store.
2. The root is encoded as an `ZAP1:09` memo.
3. A dust self-transfer or controlled shielded transfer is broadcast with that memo.
4. The deployment records the txid as the transaction reference claimed for that root.
5. When mined, the block height is recorded alongside the root.

The txid is part of the proof bundle. Transaction existence and mined height are
independently checkable. Orchard memo contents are encrypted, so a public txid
alone does not bind the supplied root to the transaction. That binding requires
a safe memo disclosure/opening artifact, which the reference deployment does
not currently publish.

## 6. Participant Verification

Participant verification flow:

1. Open `api.frontiercompute.cash/verify/{leaf_hash}`.
2. Read the displayed leaf hash, Merkle proof path, root, anchor txid, and block height.
3. Recompute the event leaf from event preimages separately disclosed to the verifier, including the participant wallet hash and, where applicable, the serial number.
4. Walk the proof path to recompute the raw tree root.
5. Commit `leaf_count` and the raw tree root with `NordicShield_RTK`, then confirm the derived root commitment equals the displayed root.
6. Open the anchor txid in a Zcash explorer or with local node tooling.
7. Confirm the transaction exists and is mined at the stated block height.
8. If a safe memo disclosure/opening artifact is supplied, verify it separately
   to bind the root commitment to the encrypted transaction memo.

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
9. A root becomes eligible for publication under the configured anchor trigger
10. Experimental/legacy staking and governance event encodings remain distinct
    from any claim that the corresponding external protocol is final

This produces an append-only application Merkle record. Some roots have
API-recorded Zcash transaction references. Event preimages stay out of the
memo, but the service stores submitted identifiers off-chain. Public
event feeds and proof bundles withhold those preimages. The
`/miner/{wallet_hash}` route family, `/lifecycle/{wallet_hash}`, and full
`GET /invoice/{id}` JSON route require operator bearer authentication. Payment
pages use UUID invoice URLs as bearer capabilities and can disclose a payment
request to anyone who obtains the URL. Public
root-to-memo binding still requires a safe disclosure artifact.

## 8. Transfer Protocol

Ownership transfers are recorded as permanent program events.

Transfer flow:

1. Current owner supplies a new wallet hash.
2. Operator verifies transfer intent off-chain.
3. The protocol creates a `TRANSFER` event binding old wallet, new wallet, and serial number.
4. The transfer leaf is inserted into the Merkle tree.
5. A later `MERKLE_ROOT` operation records a Zcash transaction reference for the covering root.
6. Old owner dashboard state changes to transferred.
7. New owner dashboard state includes the inherited machine history.

The memo contains only the derived payload hash. The old and new subject
identifiers remain in the application record and in any witness the operator
chooses to disclose.

## 9. Wyoming filing boundary

The operator associated a Zcash address and this protocol note with its own DAO
filing records. Wyoming Statute 17-31-106(b) addresses a publicly available
identifier for a smart contract directly used to manage, facilitate, or operate
a DAO.

This specification does not establish that:

- the address is a statutory smart-contract identifier
- the address or protocol appeared in accepted articles
- the filing is legally sufficient
- the entity remains in good standing

Those conclusions require filed articles, current state records, and qualified
legal review. See `WYOMING_DAO_COMPLIANCE.md`.

## 10. Security Considerations

- no raw participant PII is written to the chain by the implemented memo construction
- BLAKE2b personalization separates ZAP1 hashes from other protocol contexts
- Merkle proofs are non-interactive and independently checkable
- shielded memos limit public disclosure while still allowing controlled verification
- the `/miner/{wallet_hash}` route family, `/lifecycle/{wallet_hash}`, and full `GET /invoice/{id}` JSON route require operator bearer authentication; UUID payment-page URLs are bearer capabilities
- anchor transactions are low-value self-commits, minimizing cost
- the repository's current co-located FROST experiment does not provide independent threshold custody; production use requires separate signer processes and removal of the full spending key from the coordinator
- serial assignment still depends on correct operational handling by the operator
- a confirmed transaction is immutable under normal chain assumptions; the
  application's root-to-txid mapping and business inputs remain
  operator-controlled records

## 11. API Reference

The deployed API exposes authenticated event insertion and participant detail
routes alongside public aggregate, proof, and operational status routes. The
registry contains 18 defined types: 15 accepted by `POST /event` and 3
system-managed types. This section documents the protocol-level contract.

### `POST /event`

Creates one protocol event and inserts the corresponding leaf into the Merkle tree. Requires API key authentication.

Common required fields for all event requests:

- `event_type` - one of the 15 write-API types: `CONTRACT_ANCHOR`,
  `DEPLOYMENT`, `HOSTING_PAYMENT`, `SHIELD_RENEWAL`, `TRANSFER`, `EXIT`,
  `STAKING_DEPOSIT`, `STAKING_WITHDRAW`, `STAKING_REWARD`,
  `GOVERNANCE_PROPOSAL`, `GOVERNANCE_VOTE`, `GOVERNANCE_RESULT`,
  `AGENT_REGISTER`, `AGENT_POLICY`, or `AGENT_ACTION`
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

These event names are application classifications. A leaf created after an
invoice state transition does not by itself prove payer, payee, amount,
settlement, or the completeness of payment history. Primary chain and wallet
evidence is a separate layer.

### `GET /invoice/{id}`

Returns the full invoice JSON record. Requires operator bearer authentication.

### `GET /pay/{id}`

Returns the participant-facing payment page without operator authentication.
The UUID invoice URL is a bearer capability. Anyone who obtains it can view the
payment request, including its address, amount, status, and rendered memo
metadata.

### `GET /lifecycle/{wallet_hash}`

Returns the lifecycle view for one participant wallet hash. Requires operator
bearer authentication.

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
| `total_anchors` | Roots with recorded transaction references |
| `first_anchor_block` | First recorded transaction height |
| `last_anchor_block` | Most recent recorded transaction height |

### `GET /miner/{wallet_hash}`

The participant dashboard requires operator bearer authentication and includes:

- assigned miner status and telemetry when available
- billing invoice amounts, status, and payment links
- cohort progress data: total machines, current tier, machines to next tier, and progress bar

Dashboard notes:

- the dashboard does not calculate or promise expected ZEC output, revenue, or cost per ZEC
- a configured payout destination and miner telemetry do not prove a payout
- the rendered dashboard is a participant convenience surface, not a protocol proof surface

## 12. Profiles

ZAP1 defines a base profile and reserves extension points for future proving and credential systems.

### ZAP1 Base Profile (current repository profile)

Deterministic hash-and-Merkle attestation. Event payloads are hashed with
BLAKE2b-256 using domain-separated personalization. Leaves are aggregated into
a Merkle tree. The reference operator records Zcash transaction references for
roots. Public verification recomputes the leaf and Merkle path against the
supplied root; independently checking encrypted memo contents additionally
requires a safe disclosure/opening artifact.

This is the current repository implementation profile. Existing proof bundles,
test vectors, and verifier candidates target it. That is an implementation
compatibility statement, not standards adoption.

### ZAP1 Proof Profile (reserved)

Optional ZK proof attachment for proof-carrying attestation. If implemented, a
`proof_commitment` field could bind an external proof to a leaf. What that
proof establishes would depend on the external statement, proving system,
verification key, and verifier policy. ZAP1 does not implement that profile.

The proof profile is proving-system agnostic. Implementations may use any system that produces a verifiable commitment, including but not limited to:
- Jolt (a16z crypto)  - zkVM for general computation
- Nova / SuperNova  - folding schemes for incremental computation
- Halo 2 (Zcash Foundation)  - recursive proof composition

Any future proof commitment requires a versioned extension and explicit
verification policy. Current base verifiers do not treat an absent or unknown
proof as a verified statement.

### ZAP1 Credential Profile (reserved)

This design slot explores selective disclosure over event receipts. Current
inclusion proofs cannot establish history completeness, payment status,
non-exit, or good standing. No credential issuer or verifier is implemented.

Any future portable credential would need a versioned schema, disclosed
witnesses, issuer authentication, revocation and freshness rules, and a trusted
root policy. Authenticating root publication remains separate.

The credential profile depends on the proof profile and is not expected to deploy before proving system integration stabilizes.

## 13. Versioning and Extension Policy

- The defined event registry (`0x01`-`0x0F`, `0x40`-`0x42`) is
  append-only. Existing type-byte assignments are never redefined.
- `0x00` is invalid. Unassigned byte values are not implemented merely
  because a profile document discusses them; allocation requires a versioned
  registry update and vectors.
- Profiles are namespaced: `base`, `proof`, `credential`. New profiles do not modify the base profile.
- Hash construction rules for the base profile are frozen at v3.0.0. Changes require a new major version.
- The `NordicShield_` personalization is deployment-specific. Other deployments may use different personalization strings without conflicting with the protocol specification. The zap1-verify SDK (v0.2.0+) accepts configurable personalization.

## Changelog

### 3.0.0 documentation errata (2026-08-03)
- Reconciled the registry text and tables with the 18 implemented memo types
- Recorded the 15 write-API / 3 system-managed split
- Distinguished Merkle inclusion, transaction existence, encrypted-memo binding, and event truth

### 3.0.0 (2026-03-31)
- Added type byte prefix to leaf hash construction (Section 3)
- Renumbered sections 12-15 to fix gap from removed sections
- Clarified domain separation constants
- Added STAKING_DEPOSIT, STAKING_WITHDRAW, STAKING_REWARD event types

### 2.2.0
- Initial public specification
