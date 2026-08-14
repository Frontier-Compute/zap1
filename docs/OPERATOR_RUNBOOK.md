# ZAP1 Operator Runbook

This runbook starts, checks, backs up, upgrades, and rolls back one deployment.
The build and setup procedure is in [OPERATOR_GUIDE.md](../OPERATOR_GUIDE.md).

## 1. Frozen inputs

Before first start, retain:

- exact Git revision
- exact Git tree
- runtime-source manifest hash
- Dockerfile hash
- exact Docker image ID
- build receipt and its `.sha256` sidecar
- generated operator directory
- pinned evaluator checker and schema hashes in the generated `run.sh`

The compose service must use the `sha256:...` image ID, never a mutable tag.
`pull_policy: never` and `--no-build --pull never` are part of the gate.

## 2. Start

```bash
cd operators/myoperator
./run.sh
```

`run.sh` verifies its pinned checker and schema before Compose starts. It then
binds `/build/info` to the sealed revision, tree, source manifest, build
assurance, and image ID before allowing scanner catch-up. Readiness requires
RPC reachability, consistent heights, and lag within the configured limit. The
final schema and source-parity check uses the pinned evaluator bytes. Any red
gate stops the container.

Defaults are a 3600 second startup deadline, a 5 second poll interval, and a
10 block maximum sync lag. For a larger initial scan window:

```bash
ZAP1_STARTUP_WAIT_SECONDS=7200 ./run.sh
```

## 3. Boot checks

```bash
curl -sf http://127.0.0.1:3081/build/info | python3 -m json.tool
curl -sf http://127.0.0.1:3081/health | python3 -m json.tool
curl -sf http://127.0.0.1:3081/protocol/info | python3 -m json.tool
curl -sf http://127.0.0.1:3081/stats | python3 -m json.tool
curl -sf http://127.0.0.1:3081/anchor/status | python3 -m json.tool
```

Require:

- `/build/info.deployment.image_id` equals the receipt image ID
- deployment revision, source tree, and source manifest equal the receipt
- build metadata is complete, locked, path-remapped, and manifest-verified
- Zebra RPC is reachable
- scanner state is operational after catch-up
- stats classify every stored leaf

Anchor freshness is a separate state. Do not turn stale anchoring into a green
build verdict.

## 4. Monitoring

```bash
cargo run --locked --bin zap1_ops -- --base-url http://127.0.0.1:3081 --json
python3 scripts/check_anchor_liveness.py
```

Monitor:

- scanner sync lag and last successful scan
- Zebra RPC reachability
- unanchored leaf count
- last anchor age
- pending invoices and broadcast journal state
- agreement among `/stats`, `/anchor/history`, and `/anchor/status`

## 5. Anchor procedure

Default state is `ANCHOR_BROADCAST_ENABLED=false`. The generated deployment
has no signer. Automatic `zingo-cli quicksend` is unsupported.

Only after an exact transaction authorization:

1. Fetch `/admin/anchor/qr` with `Authorization: Bearer ...`.
2. Check the root and amount before approving the external-wallet send.
3. Wait for confirmation.
4. POST root, txid, and height to `/admin/anchor/record` with the same header.
5. Re-read `/anchor/status` and `/anchor/history`.

Never put an API key in a URL or query string. Never infer send authority from
a configured binary, key, seed, wallet, queue, or stale prior approval.

## 6. Backup

Use SQLite online backup while the service is live:

```bash
cd operators/myoperator
sqlite3 data/zap1.db ".backup /secure/backup/zap1-$(date -u +%Y%m%dT%H%M%SZ).db"
```

Record the backup hash:

```bash
sha256sum /secure/backup/zap1-*.db
```

Protect the backup as restricted operational data. It can contain submitted
subject identifiers and transaction records.

## 7. Upgrade

Never rebuild through Compose and never retag `latest`.

1. Check out the reviewed target commit in a clean tree.
2. Run `scripts/build_image.sh`.
3. Preserve the new receipt and sidecar.
4. Back up the database.
5. Run `scripts/operator-setup.sh` into a new operator directory or verify the
   new receipt manually before changing the existing image ID.
6. Start the exact new image ID.
7. Require exact `/build/info` parity plus health, scanner, stats, and anchor
   checks.
8. Preserve the prior receipt and image ID for rollback.

A changed commit, tree, manifest, Dockerfile, image ID, database schema, or
authority reopens the deployment gate.

## 8. Rollback

Rollback means restoring the prior exact image ID and a database state
compatible with that image. Do not guess schema compatibility.

1. Stop writes.
2. Preserve the failed image logs, `/build/info`, and database copy.
3. Restore the prior pinned compose file and compatible database backup.
4. Start with `--no-build --pull never`.
5. Re-run exact build parity and operational checks.

## 9. Failure handling

Scanner red:

- verify Zebra independently
- verify `ZEBRA_RPC_URL`
- inspect scanner lag and logs
- restart only after the dependency is healthy

Build parity red:

- stop promotion
- compare the receipt, image labels, embedded `BUILD_INFO`, and live
  `/build/info`
- do not accept a green health endpoint as an override

Anchor red:

- leave broadcast disabled
- inspect the prepared/broadcast journal and current root
- use the authorized external-wallet flow only if transaction authority is fresh

Proof red:

- preserve the bundle bytes
- recompute its count-bound Merkle path locally
- keep proof consistency, transaction existence, and encrypted memo binding as
  three separate rulings
