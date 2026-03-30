# ZAP1 Operator Runbook

Run one ZAP1 instance against your own Zebra node.

## 1. Requirements

- Rust 1.85.1 if running from source
- Docker if running the container image
- Zebra RPC reachable from the ZAP1 process
- One Orchard UFVK dedicated to this instance
- Disk for the SQLite database
- Optional: `zingo-cli` for anchor automation

## 2. Core components

- `zap1`: API, scanner, Merkle store, anchor loop
- `zap1_ops`: operator status rollup
- `zap1_audit`: standalone proof verifier
- `anchor_root`: manual anchor sender and recorder

## 3. Required environment

`zap1` reads these env vars:

```bash
UFVK=uview1...
NETWORK=Mainnet
ZEBRA_RPC_URL=http://127.0.0.1:8232
LISTEN_ADDR=127.0.0.1:3080
DB_PATH=/data/zap1.db
SCAN_FROM_HEIGHT=3284026
API_KEY=...
```

Notes:

- `UFVK` is required
- `NETWORK` accepts `Mainnet` or falls back to testnet
- `DB_PATH` defaults to `/data/zap1.db` in code
- `.env.example` still says `/data/nsm1.db`; use `/data/zap1.db` for new installs

## 4. Anchor automation environment

Anchor automation is enabled only when `ANCHOR_ZINGO_CLI` is set.

```bash
ANCHOR_ZINGO_CLI=/usr/local/bin/zingo-cli
ANCHOR_CHAIN=mainnet
ANCHOR_SERVER=http://127.0.0.1:8232
ANCHOR_DATA_DIR=/var/lib/zingo
ANCHOR_TO_ADDRESS=u1...
ANCHOR_AMOUNT_ZAT=1000
ANCHOR_THRESHOLD=10
ANCHOR_INTERVAL_HOURS=24
ANCHOR_WEBHOOK_URL=https://example.com/hook
```

Optional failure alerts:

```bash
SIGNAL_NUMBER=+15551234567
SIGNAL_API_URL=http://127.0.0.1:8080
```

## 5. Docker path

Build and run:

```bash
docker build -t zap1:latest .
docker run -d \
  --name zap1 \
  --restart unless-stopped \
  --network host \
  -v /srv/zap1-data:/data \
  --env-file .env.mainnet \
  zap1:latest
```

The container starts `zap1` by default. Do not override the command with `nsm1`.

## 6. Source path

```bash
cargo build --release
UFVK=... NETWORK=Mainnet ZEBRA_RPC_URL=http://127.0.0.1:8232 \
LISTEN_ADDR=127.0.0.1:3080 DB_PATH=/data/zap1.db \
./target/release/zap1
```

## 7. Boot checks

Check:

```bash
curl -s http://127.0.0.1:3080/protocol/info
curl -s http://127.0.0.1:3080/health
curl -s http://127.0.0.1:3080/stats
curl -s http://127.0.0.1:3080/anchor/status
```

Expect `protocol=ZAP1`, `rpc_reachable=true`, `scanner_operational=true`, and `sync_lag` near zero once caught up.

## 8. Monitoring

Primary operator command:

```bash
cargo run --bin zap1_ops -- --base-url http://127.0.0.1:3080 --json
```

Interpretation: `ok` = healthy, `warn` = operator attention needed, `critical` = inconsistency or degraded state.

Watch `scanner.sync_lag`, `anchors.last_anchor_age_hours`, `anchors.unanchored_leaves`, and `queue.pending_invoices`.

Nightly public check:

```bash
python3 scripts/check_anchor_liveness.py
```

## 9. Manual anchor path

If automation is disabled or degraded:

```bash
cargo run --bin anchor_root -- send \
  --db /data/zap1.db \
  --zingo-cli /usr/local/bin/zingo-cli \
  --chain mainnet \
  --server http://127.0.0.1:8232 \
  --data-dir /var/lib/zingo \
  --to u1... \
  --amount-zat 1000
```

After the transaction confirms:

```bash
cargo run --bin anchor_root -- record \
  --db /data/zap1.db \
  --root <root_hash> \
  --txid <txid> \
  --height <block_height>
```

## 10. Failure recovery

Scanner unhealthy:

- verify Zebra is up and RPC is reachable
- verify `ZEBRA_RPC_URL`
- run `zap1_ops`
- restart `zap1` only after RPC is good

Anchor failures:

- verify `ANCHOR_ZINGO_CLI`, `ANCHOR_SERVER`, `ANCHOR_DATA_DIR`, `ANCHOR_TO_ADDRESS`
- check the anchor loop backoff in logs
- use `anchor_root send` if automation is blocked

State drift:

- compare `/stats`, `/anchor/history`, and `/anchor/status`
- run `zap1_ops`
- if proof output looks wrong, regenerate from the anchored root that covers the leaf

## 11. Proof verification

Verify a published bundle without trusting the API:

```bash
cargo run --bin zap1_audit -- --bundle examples/live_ownership_attest_proof.json
```

Or against a live bundle URL:

```bash
cargo run --bin zap1_audit -- --bundle-url https://pay.example.com/verify/<leaf_hash>/proof.json
```

This checks the Merkle proof locally. You still need to confirm the txid and memo on-chain.

## 12. Logs

The service logs network, Zebra RPC target, scan start height, UFVK load result, DB open, scanner start, and anchor automation state.

`Anchor automation disabled (ANCHOR_ZINGO_CLI not set)` means the API is healthy and only automated anchoring is off.
