# Structural Buildout

This repo now exposes three operator and validation tools.

## 1. `zap1_audit`

Standalone proof-bundle verifier.

Use:
- recompute a ZAP1 Merkle path without the hosted verify page
- print the supplied root and recorded transaction reference

This verifies internal consistency under the supplied root. It does not prove
the event claim, completeness, or encrypted-memo contents.

Usage:

```bash
cargo run --bin zap1_audit -- --bundle examples/live_ownership_attest_proof.json
```

Or against a live proof bundle URL:

```bash
cargo run --bin zap1_audit -- --bundle-url https://api.frontiercompute.cash/verify/<leaf_hash>/proof.json
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

## 3. Anchor liveness check

Nightly GitHub Actions checks plus a local script.

Use:
- check public anchor surfaces for freshness and internal consistency
- fail on drift in protocol label, recorded counts, or latest API fields

Liveness is an operator-surface check. It is not a memo opening or an
independent audit of the historical records.

Local run:

```bash
python3 scripts/check_anchor_liveness.py
```

Workflow:

- `.github/workflows/anchor-liveness.yml`

The scheduled `public-monitor` keeps three claims separate:

- anchor structure and cross-surface consistency must remain valid;
- a stale anchor with pending work is reported as a warning while transaction
  authority is paused;
- the public API contract and preimage-redaction boundary still fail closed.

The manual `exact-deployment` mode is the only workflow path that reads the
operator-provided expected image ID and admin API secret. It remains strict on
source parity, authenticated admin behavior, anchor freshness, and the current
proof. A green public monitor is not a deployment attestation.

Files:

- `src/bin/zap1_audit.rs`
- `src/bin/zip302_tvlv.rs`
- `scripts/check_anchor_liveness.py`
- `.github/workflows/anchor-liveness.yml`
