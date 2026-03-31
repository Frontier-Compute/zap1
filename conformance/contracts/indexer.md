# Indexer Contract

How a Zaino-backed or standalone indexer ingests ZAP1 data.

## Two ingestion paths

### Path A: API polling

```
GET /events?limit=100
```

Poll for new events. Each event includes verify_url and proof_url for on-demand proof retrieval.

### Path B: Zaino direct scanning

```bash
cargo run --bin memo_scan -- --ufvk $UFVK --start $HEIGHT --end $HEIGHT --json
```

Scans blocks via Zaino CompactTxStreamer gRPC. Trial decrypts Orchard outputs and classifies memos using zcash-memo-decode. Outputs one JSON line per non-empty memo.

## Anchor verification

```bash
cargo run --bin zaino_adapter -- --zaino-url http://127.0.0.1:8137
```

Fetches all anchor blocks via Zaino, retrieves raw transactions, confirms anchor txids are present.

## Storage

Store locally: leaf_hash, event_type, wallet_hash, serial_number, created_at, anchor_height, anchor_txid, root.

## Failure modes

- Zaino unavailable: fall back to API polling
- block range exceeds indexed height: cap at GetLatestBlock tip
- memo decryption fails (not addressed to this UFVK): skip silently

## Stability

- /events schema: stable per conformance/api_schemas.json
- memo_scan JSON line format: one object per line, format field always present
- zaino_adapter output: human-readable, not a stable machine contract

## Example

See `examples/consumer_indexer.sh` for a working implementation.
