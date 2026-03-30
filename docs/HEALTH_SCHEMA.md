# ZAP1 Health Schema

Machine-readable health output contract for operator monitoring tools.

## Endpoint

`GET /health` returns JSON conforming to this schema.

## Fields

```json
{
  "last_scanned_height": 3290894,
  "chain_tip": 3290894,
  "sync_lag": 0,
  "pending_invoices": 1,
  "scanner_operational": true,
  "network": "MainNetwork",
  "rpc_reachable": true
}
```

| Field | Type | Meaning |
|---|---|---|
| last_scanned_height | u32 | highest block the scanner has processed |
| chain_tip | u32 | current chain tip from the node backend |
| sync_lag | u32 | chain_tip - last_scanned_height |
| pending_invoices | usize | invoices awaiting payment confirmation |
| scanner_operational | bool | scanner loop is running and not stalled |
| network | string | MainNetwork or TestNetwork |
| rpc_reachable | bool | last RPC/gRPC call to the node succeeded |

## Thresholds

Recommended alerting thresholds for `zap1_ops`:

| Condition | Level | Default |
|---|---|---|
| sync_lag > 100 | critical | scanner is falling behind |
| sync_lag > 20 | warning | scanner is catching up |
| rpc_reachable = false | critical | node backend is down |
| scanner_operational = false | critical | scanner loop has stopped |
| pending_invoices > 10 | warning | payment backlog |

## Anchor status

`GET /anchor/status` returns:

```json
{
  "current_root": "437e12dd...",
  "leaf_count": 12,
  "unanchored_leaves": 0,
  "last_anchor_txid": "dfab64cd...",
  "last_anchor_height": 3288022,
  "needs_anchor": false,
  "recommendation": "up to date"
}
```

| Field | Type | Meaning |
|---|---|---|
| current_root | hex string | current Merkle tree root |
| leaf_count | usize | total leaves under current root |
| unanchored_leaves | u32 | leaves added since last anchor |
| last_anchor_txid | hex string or null | txid of most recent anchor |
| last_anchor_height | u32 or null | block height of most recent anchor |
| needs_anchor | bool | unanchored leaves exceed threshold |
| recommendation | string | human-readable next action |

## Operator rollup

`zap1_ops` aggregates /health, /stats, /anchor/status, and /anchor/history into a single verdict:

```bash
cargo run --bin zap1_ops -- --base-url http://127.0.0.1:3080 --json
```

Output schema:

```json
{
  "status": "ok|warn|critical",
  "protocol": "ZAP1",
  "version": "2.2.0",
  "network": "MainNetwork",
  "scanner": { "operational": true, "rpc_reachable": true, "sync_lag": 0, ... },
  "anchors": { "total_anchors": 3, "total_leaves": 12, "needs_anchor": false, ... },
  "queue": { "pending_invoices": 0 },
  "warnings": [],
  "errors": []
}
```

Status values:
- `ok`: all checks pass, no warnings
- `warn`: non-critical issues (stale anchor, pending work, queue backlog)
- `critical`: data mismatch, scanner down, RPC unreachable, or protocol mismatch

## Integration

Feed `zap1_ops --json` output into Prometheus (via json_exporter), Grafana, or any monitoring stack. The `status` field maps directly to alert severity.

For Prometheus:
```yaml
zap1_scanner_lag{instance="prod"} 0
zap1_anchor_count{instance="prod"} 3
zap1_leaf_count{instance="prod"} 12
zap1_unanchored_leaves{instance="prod"} 0
zap1_status{instance="prod",level="ok"} 1
```
