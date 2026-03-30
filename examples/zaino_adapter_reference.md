# Zaino Adapter Reference Output

Captured from live mainnet run on March 30, 2026.

## Command

```bash
cargo run --bin zaino_adapter -- --zaino-url http://127.0.0.1:8137 --api-url http://127.0.0.1:3080
```

## Expected output

```
zaino adapter: connecting to http://127.0.0.1:8137
anchors from API: 3
zaino chain tip: ~3291000 (varies)
  pass: anchor block=3286631 txid=98e1d6a01614.. leaves=2 tx_bytes=9165
  pass: anchor block=3287612 txid=3c764a810f46.. leaves=12 tx_bytes=9165
  pass: anchor block=3288022 txid=dfab64cd1114.. leaves=12 tx_bytes=9165
  range: streamed 1392 blocks from 3286631 to 3288022 via zaino

result: 3 pass, 0 fail, 3 total anchors
```

## What it verifies

For each ZAP1 anchor:
1. Fetches the compact block at the anchor height via Zaino GetBlock
2. Confirms the anchor txid appears in that block's transaction list
3. Retrieves the full raw transaction via Zaino GetTransaction
4. Confirms the transaction data is non-empty

Then streams the full block range between first and last anchor via GetBlockRange.

## gRPC methods exercised

- GetLatestBlock (chain tip)
- GetBlock (per anchor height)
- GetTransaction (per anchor txid)
- GetBlockRange (first to last anchor)

## Infrastructure requirements

- Zaino 0.2.0+ serving CompactTxStreamer on port 8137
- ZAP1 API serving anchor history on the configured API URL
- Zebra 4.3.0+ connected to Zaino
