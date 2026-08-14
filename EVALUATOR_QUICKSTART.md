# ZAP1 Evaluator Quickstart

This guide is the reviewer-facing entrypoint. For the full walkthrough, see [`QUICKSTART.md`](QUICKSTART.md).

## Fastest path on Linux or macOS

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
bash scripts/evaluate.sh --local
```

This runs deterministic repository checks without trusting the deployment.

On Windows, run from an x64 Visual Studio developer environment with Git Bash,
Node, Python 3, the stable MSVC Rust toolchain, and `protoc` on `PATH`:

```bat
"C:\Program Files\Git\bin\bash.exe" scripts/evaluate.sh --local
```

Plain PowerShell does not supply the Bash utilities or MSVC linker environment
required by this evaluator.

To add the fail-closed live gate, use a clean checkout of the commit recorded
in the operator-local pinned-image receipt:

```bash
ZAP1_EXPECTED_DEPLOYMENT_IMAGE_ID=sha256:... bash scripts/evaluate.sh --live
```

With no flag, `scripts/evaluate.sh` runs local checks first and then live
checks, but the receipt image ID environment variable is still required. The
live gate requires exact parity between the evaluator checkout, the expected
image ID copied from that local receipt, and the metadata declared by
`/build/info`. It also requires `scanner_operational` and `rpc_reachable` to be
true and enforces a maximum sync lag of 10 blocks by default. Override that
explicit policy with `ZAP1_MAX_SYNC_LAG_BLOCKS`.

The image ID, revision, tree, and manifest returned by `/build/info` are
service-declared metadata. Equality rejects stale or different declarations.
It does not remotely attest the bytes serving the request. The operator-local
receipt separately pins the image built from the clean archive.

## What it checks

- locked repository metadata and Rust tests
- the admitted 18-type implementation profile
- protocol fixtures and compatibility vectors
- Python, Rust, and TypeScript output agreement on the frozen equivalence corpus
- bundled valid proofs pass and invalid proofs fail
- live declared source metadata and image ID parity when `--live` is selected
- live scanner, RPC, bounded sync-lag, and public preimage-redaction policy
- current anchor liveness and a freshly fetched proof bundle in the live gate

These checks do not prove the underlying event claims. Zcash shielded memo
contents are encrypted, so transaction existence alone does not independently
bind a listed root to a transaction. That requires a safe disclosure artifact,
which is not currently published.

The local implementation-profile run intentionally reports two live-only
skips:

- `6.5` checks the current event leaf and its verification path.
- `6.6` checks that the live stats endpoint returns leaf data.

A local pass with those two skips is only a local verdict. For deployment
acceptance, `scripts/evaluate.sh --live` is the mandatory gate. It covers
`6.5` by fetching the current leaf, checking the returned bundle against that
request, and independently verifying the proof. It covers `6.6` through the
live API schema and stats checks. The same gate also enforces declared build
parity, scanner and RPC health, bounded sync lag, public redaction, and anchor
liveness.

Because the public bundle withholds the leaf witness, its event-type label is
server metadata. The live gate requires the explicit
`unverified_server_metadata_without_disclosed_witness` marker.

## Manual surfaces

- Live protocol info: `https://api.frontiercompute.cash/protocol/info`
- Live stats: `https://api.frontiercompute.cash/stats`
- Anchor status: `https://api.frontiercompute.cash/anchor/status`
- Anchor history: `https://api.frontiercompute.cash/anchor/history`
- Live build identity: `https://api.frontiercompute.cash/build/info`
- Local proof-bundle check: `python3 examples/verify_proof.py`
- Optional live freshness check: `python3 examples/verify_proof.py --live-status`
- Browser verifier source: `verify-widget/verify-standalone.html` (local/static;
  do not treat a separately hosted copy as current without checking its build)

## Supporting docs

- Full walkthrough: [`QUICKSTART.md`](QUICKSTART.md)
- Evidence snapshot: [`EVIDENCE.md`](EVIDENCE.md)
- Protocol spec: [`ONCHAIN_PROTOCOL.md`](ONCHAIN_PROTOCOL.md)
- Test vectors: [`TEST_VECTORS.md`](TEST_VECTORS.md)
- Operator runbook: [`docs/OPERATOR_RUNBOOK.md`](docs/OPERATOR_RUNBOOK.md)
