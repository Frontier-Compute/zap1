# Structural Buildout

This repo now exposes three operator and validation tools.

## 1. `zap1_audit`

Standalone proof-bundle verifier.

Use:
- verify a ZAP1 proof bundle without the hosted verify page
- print the anchor facts to confirm on-chain

Usage:

```bash
cargo run --bin zap1_audit -- --bundle examples/live_ownership_attest_proof.json
```

Or against a live proof bundle URL:

```bash
cargo run --bin zap1_audit -- --bundle-url https://pay.frontiercompute.io/verify/<leaf_hash>/proof.json
```

## 2. `zip302_tvlv`

Reference ZIP 302 TVLV encoder/decoder.

Use:
- encode TVLV memo payloads
- decode TVLV memo payloads

Encode:

```bash
cargo run --bin zip302_tvlv -- encode examples/zip302_parts_example.json
```

Decode:

```bash
cargo run --bin zip302_tvlv -- decode <memo_hex>
```

## 3. Anchor liveness proof

Nightly GitHub Actions check plus local script.

Use:
- check public anchor surfaces for freshness and consistency
- fail on drift in protocol label, anchor counts, or latest anchor facts

Local run:

```bash
python3 scripts/check_anchor_liveness.py
```

Workflow:

- `.github/workflows/anchor-liveness.yml`

Files:

- `src/bin/zap1_audit.rs`
- `src/bin/zip302_tvlv.rs`
- `scripts/check_anchor_liveness.py`
- `.github/workflows/anchor-liveness.yml`
