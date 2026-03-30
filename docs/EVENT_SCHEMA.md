# ZAP1 Event Schema v1.0

Typed event definitions for the ZAP1 attestation protocol. Each event commits a BLAKE2b-256 hash of its payload fields to the Merkle tree, anchored on Zcash mainnet via shielded memos.

Personalization: `NordicShield_` (leaf), `NordicShield_MRK` (tree node).

## Wire format

```
ZAP1:{type_hex}:{payload_hash_hex}
```

Legacy prefix `NSM1` is accepted during decode.

## Event types

### 0x01 PROGRAM_ENTRY

Participant joined the program.

```
payload = BLAKE2b-256("NordicShield_", 0x01 || wallet_hash_bytes)
```

Fields:
- `wallet_hash`: BLAKE2b-256 of participant's Zcash unified address (hex string, length-prefixed)

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

### 0x0A-0x0C (Reserved)

Reserved for Crosslink staking integration:
- `0x0A` STAKING_DEPOSIT
- `0x0B` STAKING_WITHDRAW
- `0x0C` STAKING_REWARD

Not deployed. Schema will be published when staking integration begins.

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
5. Compare the derived root to the anchored root on-chain

SDK: [zap1-verify](https://github.com/Frontier-Compute/zap1-verify) (Rust + WASM)
JS: [zap1-js](https://github.com/Frontier-Compute/zap1-js)

## ZIP 302 target encoding

When ZIP 302 structured memos ship, ZAP1 payloads will be carried as a registered `partType` in the TVLV container (0xF7 prefix). The current wire format (`ZAP1:{type}:{hash}`) is the transitional encoding.

Reference encoder/decoder: `cargo run --bin zip302_tvlv`
