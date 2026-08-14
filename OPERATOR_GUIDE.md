# ZAP1 Operator Guide

Run one ZAP1 instance from one reviewed commit and one exact Docker image ID.

## Boundary

The setup script creates deployment files and an API key. It does not create a
wallet, spending seed, transaction, anchor, or signer. Supply a UFVK and Orchard
address from a wallet you control. Keep broadcast disabled until a separate
transaction authority is granted.

## Requirements

- Linux host with Git, Docker Compose v2, Python 3, tar, awk, and sha256sum
- Zebra synced to the selected network and reachable from ZAP1
- A wallet-controlled Orchard UFVK and address
- A clean checkout of the exact commit to build

Zaino is optional for compact-block reads. Rust is not needed on the host when
the Docker path is used.

## Build and seal

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
test -z "$(git status --porcelain)"
REV=$(git rev-parse HEAD)
bash scripts/build_image.sh "zap1:$REV"
```

The last command prints:

- the exact `sha256:...` image ID
- Git revision and tree
- runtime-source manifest hash
- Dockerfile hash
- receipt path and receipt hash

The receipt also contains the image labels and every embedded `BUILD_INFO`
field. Its `.sha256` sidecar detects receipt changes when the sidecar is
preserved through a trusted channel. Preserve both files. The receipt binds the
declared source identity to that local image. It does not claim bit-for-bit
reproducibility, independent rebuild, or signer identity.

## Generate the pinned deployment

Copy `receipt_path` from the build output, then supply wallet-controlled
inputs:

```bash
export ZAP1_OPERATOR_UFVK='uview1...'
export ZAP1_ANCHOR_TO_ADDRESS='u1...'
export ZAP1_SCAN_FROM_HEIGHT='<wallet-birthday-height>'
bash scripts/operator-setup.sh myoperator 3081 /absolute/path/to/build-receipt.env
```

The setup script fails unless:

- the checkout is clean
- the receipt sidecar verifies
- receipt revision, tree, source manifest, and Dockerfile hash match the clean Git archive
- the exact image ID exists locally
- the image labels and embedded `BUILD_INFO` match the receipt and archive

It writes:

- `operators/myoperator/.env`, mode 0600
- `operators/myoperator/docker-compose.yml`, pinned to the image ID with pulls disabled
- `operators/myoperator/run.sh`
- `operators/myoperator/evaluator/`, containing the exact archived checker and schema

No `.seed` file is created.

## Start and verify

```bash
cd operators/myoperator
./run.sh
```

The run script verifies the pinned checker and schema hashes before starting
Compose. It uses `--no-build --pull never`, binds `/build/info` to the exact
revision, tree, source manifest, build-assurance fields, and deployment image
ID, then allows the scanner to catch up. Readiness requires RPC reachability,
internally consistent heights, and sync lag no greater than 10 blocks. The
final strict API check runs from the pinned evaluator directory. Any failure
stops the container, even if an HTTP health endpoint returned 200.

The startup deadline defaults to 3600 seconds and the poll interval to 5
seconds. Override them only when the initial scan needs longer. The final lag
limit can also be tightened or relaxed explicitly:

```bash
ZAP1_STARTUP_WAIT_SECONDS=7200 \
ZAP1_STARTUP_POLL_SECONDS=5 \
ZAP1_MAX_SYNC_LAG_BLOCKS=10 \
./run.sh
```

Read the surfaces directly:

```bash
curl -sf http://127.0.0.1:3081/build/info | python3 -m json.tool
curl -sf http://127.0.0.1:3081/health | python3 -m json.tool
curl -sf http://127.0.0.1:3081/protocol/info | python3 -m json.tool
curl -sf http://127.0.0.1:3081/stats | python3 -m json.tool
curl -sf http://127.0.0.1:3081/anchor/status | python3 -m json.tool
```

## Anchoring

Generated deployments set `ANCHOR_BROADCAST_ENABLED=false` and provision no
signer. The automatic `zingo-cli quicksend` path is unsupported. Do not treat
CLI presence as transaction authority.

For an operator-authorized external-wallet send, request the prepared QR with
the API key in the Authorization header:

```bash
export ZAP1_API_BASE="${ZAP1_API_BASE:?set ZAP1_API_BASE to this deployment}"
curl -sf \
  -H "Authorization: Bearer $API_KEY" \
  "${ZAP1_API_BASE%/}/admin/anchor/qr"
```
Use one operator and one live tab for a send. Reload immediately before
scanning, and record a broadcast before requesting the page again.


After the exact transaction confirms, record its root, txid, and height:

```bash
export ZAP1_API_BASE="${ZAP1_API_BASE:?set ZAP1_API_BASE to this deployment}"
curl -sf -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"root":"ROOT_HASH","txid":"TXID","height":BLOCK_HEIGHT}' \
  "${ZAP1_API_BASE%/}/admin/anchor/record"
```

API keys belong only in Authorization headers. Never place them in URLs,
query strings, screenshots, or logs. A recorded txid proves a transaction
reference exists. Encrypted memo-to-root binding still requires a separate
safe opening.

## Monitoring

```bash
export ZAP1_API_BASE="${ZAP1_API_BASE:?set ZAP1_API_BASE to this deployment}"
cargo run --locked --bin zap1_ops -- --base-url "${ZAP1_API_BASE%/}" --json
python3 scripts/check_anchor_liveness.py
```

Watch scanner lag, RPC reachability, unanchored leaves, anchor age, and
cross-consistency among `/stats`, `/anchor/history`, and
`/anchor/status`.

## Backup

The state is one SQLite database at `DB_PATH`, normally
`/data/zap1.db`. Use SQLite's online backup command against a live database:

```bash
sqlite3 operators/myoperator/data/zap1.db ".backup /path/to/zap1-backup.db"
```

Back up before upgrades. Never replace the database from an unverified copy.

## Core environment

| Variable | Required | Purpose |
|---|---:|---|
| `UFVK` | yes | Wallet-controlled full viewing key for scanning |
| `NETWORK` | yes | Exactly `Mainnet` or `Testnet` |
| `ZEBRA_RPC_URL` | yes | Zebra JSON-RPC endpoint |
| `LISTEN_ADDR` | yes | API listen address |
| `DB_PATH` | yes | SQLite path |
| `ZAP1_SCAN_FROM_HEIGHT` | setup | Wallet birthday height copied to runtime `SCAN_FROM_HEIGHT` |
| `API_KEY` | yes for writes | Bearer credential for write and admin routes |
| `ZAP1_DEPLOYMENT_IMAGE_ID` | container | Exact image ID exposed by `/build/info` |
| `ZAINO_GRPC_URL` | no | Optional compact-block endpoint |
| `ANCHOR_TO_ADDRESS` | manual flow | Wallet-controlled shielded address |
| `ANCHOR_BROADCAST_ENABLED` | no | Defaults false; transaction authority gate |
| `TRIAL_KEY_ISSUANCE_ENABLED` | no | Defaults false |

Signal and webhook configuration are optional. Webhook registration also
requires the API key in the Authorization header.
