# Operator Contract

How an operator deploys and monitors a ZAP1 instance.

## Setup

See `docs/OPERATOR_RUNBOOK.md` for full deployment instructions.

## Health monitoring

```
GET /health
```

Returns scanner status, chain sync lag, pending invoices, RPC reachability. Schema in `conformance/api_schemas.json`.

## Operator rollup

```bash
cargo run --bin zap1_ops -- --base-url http://127.0.0.1:3080 --json
```

Aggregates /health, /stats, /anchor/status, /anchor/history into a single verdict. Machine-readable JSON with status: ok/warn/critical.

Thresholds documented in `docs/HEALTH_SCHEMA.md`.

## Anchor status

```
GET /anchor/status
```

Returns current root, leaf count, unanchored leaves, and whether an anchor is needed.

## Audit

```bash
cargo run --bin zap1_audit -- --bundle proof.json
cargo run --bin zap1_audit -- --export package.json
```

Verifies proof bundles and export packages offline.

## Selective disclosure

```bash
cargo run --bin zap1_export -- --wallet-hash <hash> --profile auditor -o package.json
```

Produces scoped audit packages. Profiles: auditor, counterparty, member, regulator.

## Failure modes

- scanner stops: /health shows scanner_operational=false
- Zebra RPC down: /health shows rpc_reachable=false
- anchor stale: zap1_ops reports warning or critical based on age threshold
- leaf count mismatch: zap1_ops reports critical

## Stability

- /health schema: stable per conformance/api_schemas.json
- zap1_ops JSON output: stable per docs/HEALTH_SCHEMA.md
- export profile names: stable (auditor, counterparty, member, regulator)
