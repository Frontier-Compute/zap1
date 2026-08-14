# ZAP1 Event Schema v1.0

Typed event definitions for the ZAP1 implementation profile. Each event commits
a BLAKE2b-256 hash of its payload fields to a Merkle tree. The API can record a
Zcash transaction reference for a root. Transaction existence does not reveal
an encrypted memo or independently prove that the memo contains the root.

Personalization: `NordicShield_` (leaf), `NordicShield_MRK` (tree node).

## Wire format

```
ZAP1:{type_hex}:{payload_hash_hex}
```

Legacy prefix `NSM1` is accepted during decode.

Field names such as `wallet_hash` are historical API names. The service checks
bounds but does not derive a hash or pseudonym for the caller. Integrators must
derive domain-separated pseudonymous values before submission. Public event
feeds and proof bundles withhold stored subject preimages. The
`/miner/{wallet_hash}` route family, `/lifecycle/{wallet_hash}`, and full
`GET /invoice/{id}` JSON route require operator bearer authentication. Payment
pages use UUID invoice URLs as bearer capabilities and can disclose a payment
request to anyone who obtains the URL.

## Event types

### 0x01 PROGRAM_ENTRY

Operator claim that a subject joined the program.

```
payload = BLAKE2b-256("NordicShield_", 0x01 || wallet_hash_bytes)
```

Fields:
- `wallet_hash`: operator-supplied pseudonymous subject identifier (raw bytes, no length prefix)

Note: PROGRAM_ENTRY is the only type that does not length-prefix its field. All other types use 2-byte big-endian length prefixes.

Issued when: payment received and confirmed for program entry.

### 0x02 OWNERSHIP_ATTEST

Links a participant wallet to a specific hardware serial.

```
payload = BLAKE2b-256("NordicShield_", 0x02 || len(wallet_hash) || wallet_hash || len(serial) || serial)
```

Fields:
- `wallet_hash`: participant address hash (length-prefixed)
- `serial_number`: hardware identifier string (length-prefixed)

Issued when: hardware assigned to participant.

### 0x03 CONTRACT_ANCHOR

Commits the hash of a hosting contract artifact.

```
payload = BLAKE2b-256("NordicShield_", 0x03 || len(serial) || serial || len(contract_sha256) || contract_sha256)
```

Fields:
- `serial_number`: hardware identifier (length-prefixed)
- `contract_sha256`: SHA-256 hash of the contract document (length-prefixed hex string)

Issued when: hosting contract signed or updated.

### 0x04 DEPLOYMENT

Records hardware installation at a facility.

```
payload = BLAKE2b-256("NordicShield_", 0x04 || len(serial) || serial || len(facility_id) || facility_id || timestamp_be)
```

Fields:
- `serial_number`: hardware identifier (length-prefixed)
- `facility_id`: facility identifier string (length-prefixed)
- `timestamp`: unix seconds, big-endian u64

Issued when: miner racked and connected.

### 0x05 HOSTING_PAYMENT

Monthly hosting invoice paid.

```
payload = BLAKE2b-256("NordicShield_", 0x05 || len(serial) || serial || month_be || year_be)
```

Fields:
- `serial_number`: hardware identifier (length-prefixed)
- `month`: 1-12, big-endian u32
- `year`: big-endian u32

Issued when: monthly hosting payment confirmed.

### 0x06 SHIELD_RENEWAL

Annual privacy shield renewed.

```
payload = BLAKE2b-256("NordicShield_", 0x06 || len(wallet_hash) || wallet_hash || year_be)
```

Fields:
- `wallet_hash`: participant address hash (length-prefixed)
- `year`: big-endian u32

Issued when: annual renewal payment confirmed.

### 0x07 TRANSFER

Ownership transferred to a new wallet.

```
payload = BLAKE2b-256("NordicShield_", 0x07 || len(old_wallet) || old_wallet || len(new_wallet) || new_wallet || len(serial) || serial)
```

Fields:
- `old_wallet_hash`: previous owner address hash (length-prefixed)
- `new_wallet_hash`: new owner address hash (length-prefixed)
- `serial_number`: hardware identifier (length-prefixed)

Issued when: ownership change requested and confirmed.

### 0x08 EXIT

Participant exit or hardware release.

```
payload = BLAKE2b-256("NordicShield_", 0x08 || len(wallet_hash) || wallet_hash || len(serial) || serial || timestamp_be)
```

Fields:
- `wallet_hash`: participant address hash (length-prefixed)
- `serial_number`: hardware identifier (length-prefixed)
- `timestamp`: unix seconds, big-endian u64

Issued when: participant exits or hardware is released from program.

### 0x09 MERKLE_ROOT

Anchors the current Merkle tree root to Zcash mainnet.

```
payload = raw 32-byte Merkle root (no hash wrapping)
```

This is the anchor event. The root commits the state of all prior leaves.

Issued when: anchor automation fires (threshold count or interval).

### 0x0A STAKING_DEPOSIT

```
payload = BLAKE2b-256("NordicShield_", 0x0A || len(wallet_hash) || wallet_hash || amount_zat_be || len(validator_id) || validator_id)
```

### 0x0B STAKING_WITHDRAW

```
payload = BLAKE2b-256("NordicShield_", 0x0B || len(wallet_hash) || wallet_hash || amount_zat_be || len(validator_id) || validator_id)
```

### 0x0C STAKING_REWARD

```
payload = BLAKE2b-256("NordicShield_", 0x0C || len(wallet_hash) || wallet_hash || amount_zat_be || epoch_be)
```

These three constructions are implemented and accepted by `POST /event`. They
commit operator-supplied staking claims; they do not inspect or prove Crosslink
consensus state.

### 0x0D GOVERNANCE_PROPOSAL

```
payload = BLAKE2b-256("NordicShield_", 0x0D || len(wallet_hash) || wallet_hash || len(proposal_id) || proposal_id || len(proposal_hash) || proposal_hash)
```

### 0x0E GOVERNANCE_VOTE

```
payload = BLAKE2b-256("NordicShield_", 0x0E || len(wallet_hash) || wallet_hash || len(proposal_id) || proposal_id || len(vote_commitment) || vote_commitment)
```

### 0x0F GOVERNANCE_RESULT

```
payload = BLAKE2b-256("NordicShield_", 0x0F || len(wallet_hash) || wallet_hash || len(proposal_id) || proposal_id || len(result_hash) || result_hash)
```

These are operator-submitted governance claims. They do not prove proposal
validity, voter eligibility, vote secrecy, tally correctness, or a Zcash
governance outcome.

### 0x40 AGENT_REGISTER

```
payload = BLAKE2b-256("NordicShield_", 0x40 || len(agent_id) || agent_id || len(pubkey_hash) || pubkey_hash || len(model_hash) || model_hash || len(policy_hash) || policy_hash)
```

### 0x41 AGENT_POLICY

```
payload = BLAKE2b-256("NordicShield_", 0x41 || len(agent_id) || agent_id || policy_version_be || len(rules_hash) || rules_hash)
```

### 0x42 AGENT_ACTION

```
payload = BLAKE2b-256("NordicShield_", 0x42 || len(agent_id) || agent_id || len(action_type) || action_type || len(input_hash) || input_hash || len(output_hash) || output_hash)
```

These are operator-submitted agent claims. They do not attest model identity,
provider identity, authorization, tool execution, policy compliance, or the
truth of inputs and outputs. Those require separate evidence and authority.

## Length-prefix encoding

All variable-length fields use a 2-byte big-endian length prefix:

```
len(field) = field.len() as u16, big-endian
```

## Verification

Given a leaf hash from a proof bundle:

1. Reconstruct the payload from known fields using the schema above
2. Hash with BLAKE2b-256 and `NordicShield_` personalization
3. Compare to the leaf hash in the proof bundle
4. Walk the Merkle proof using `NordicShield_MRK` personalization
5. Compare the derived root to the root supplied in the proof bundle
6. Check the recorded transaction exists at the stated height; encrypted memo
   binding requires a separate safe disclosure/opening artifact

SDK: [zap1-verify](https://github.com/Frontier-Compute/zap1-verify) (Rust + WASM)
JS: [zap1-js](https://github.com/Frontier-Compute/zap1-js)

## ZIP 302 target encoding

If a compatible ZIP 302 structured-memo assignment is approved, ZAP1 payloads
could be carried in the TVLV container (`0xF7` prefix). No assignment, merge,
or adoption is claimed. The active implementation profile uses
`ZAP1:{type}:{hash}`.

Reference encoder/decoder: `cargo run --bin zip302_tvlv`
