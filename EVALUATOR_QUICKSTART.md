# ZAP1 Evaluator Quickstart

This guide is the reviewer-facing entrypoint. For the full walkthrough, see [`QUICKSTART.md`](QUICKSTART.md).

## Fastest path

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
bash scripts/evaluate.sh
```

This runs the validation path and forwards to `scripts/check.sh`. The proof
verification step is offline-first; live API reads are used for current
status/freshness.

## What it proves

- the live API is reachable and reports `protocol: ZAP1`
- anchored roots and leaves exist on mainnet
- bundled proof material verifies without trusting a server
- current live proof routing is checked when the deployment exposes it for the
  latest leaf
- memo decode returns `zap1` for a known attestation
- explorer and simulator are reachable
- published crates are live
- local Rust checks run when the toolchain is available

## Manual surfaces

- Live protocol info: `https://api.frontiercompute.cash/protocol/info`
- Live stats: `https://api.frontiercompute.cash/stats`
- Anchor status: `https://api.frontiercompute.cash/anchor/status`
- Anchor history: `https://api.frontiercompute.cash/anchor/history`
- Offline proof check: `python3 examples/verify_proof.py`
- Optional live freshness check: `python3 examples/verify_proof.py --live-status`
- Browser verifier: `https://frontiercompute.io/verify.html`

## Supporting docs

- Full walkthrough: [`QUICKSTART.md`](QUICKSTART.md)
- Evidence snapshot: [`EVIDENCE.md`](EVIDENCE.md)
- Protocol spec: [`ONCHAIN_PROTOCOL.md`](ONCHAIN_PROTOCOL.md)
- Test vectors: [`TEST_VECTORS.md`](TEST_VECTORS.md)
- Operator runbook: [`docs/OPERATOR_RUNBOOK.md`](docs/OPERATOR_RUNBOOK.md)
