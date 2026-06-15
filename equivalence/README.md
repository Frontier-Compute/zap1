# ZAP1 verifier equivalence

Three independently written ZAP1 verifier surfaces, the Python `verify_proof.py`,
the Rust `zap1-verify` crate, and the TypeScript-family Node runner, each run
over a frozen corpus of verification cases and emit a canonical SHA-256
fingerprint per case. CI fails if the outputs differ, or if the reference output
drifts from the committed reference. The result is a machine-checked statement
that the verifiers agree on the corpus.

## Why

The repo ships more than one verifier surface and a multi-client conformance
set, but nothing mechanically tied the implementations together. A subtle
encoding gap between the Python and Rust verifiers could pass every per-language
test and still disagree on a real proof. This check closes that gap: the digest
is the only artifact that crosses between the two, and it is compared in CI,
outside either verifier.

## How it works

- `corpus.json`: ten frozen cases. Four valid v2 proofs, one gated historical
  legacy proof, and five rejections (wrong root, wrong leaf count, ungated legacy
  downgrade, legacy anchor height above the cutoff, tampered sibling). It is
  built by `gen_corpus.py` so every hash is computed, not pasted, and it doubles
  as a verifier conformance vector set.
- `fingerprint.py`, `rust/src/main.rs`, and `typescript/fingerprint.mjs`: each
  reads the corpus, runs its own verifier, and prints `<id> <sha256>` lines per
  `SPEC.md`.
- `fingerprints.expected.txt`: the committed reference, produced by the Python
  side. If every verifier changes the same way, the cross check still passes but
  this file fails, which forces a conscious regeneration.
- `.github/workflows/verifier-equivalence.yml`: runs all implementations and
  diffs each output against Python and the committed reference.

## Trust assumptions

State plainly what a green check does and does not mean. This mirrors the
honesty section of the work this pattern is borrowed from (Tachyon/Ragu,
`qa/lean/docs/src/ragu/fingerprint.md`).

A match shows the implementations agree on the corpus. It is a consistency
check between two implementations we control. It is not a proof and it is not a
boundary against an attacker. In particular:

- It does not show either verifier matches the protocol's intent. If both
  encode the same wrong rule, they agree and the check is green. This is the
  shadowed-bug case from Ragu's notes, one level down: agreement is not
  correctness. The defense is the spec and the leaf-hash vectors, which must be
  read by hand.
- Independent implementations can still share a fault when they share a spec or
  a habit of thought. The classic N-version result (Knight and Leveson, 1986) is
  that independently written programs fail in correlated ways more often than
  independence would predict. So treat agreement as evidence, not certainty.
- It trusts SHA-256 collision resistance and the two encoders realizing the same
  `SPEC.md`.
- It covers the verifier path, including the browser/TypeScript-family proof
  logic shape. It does not cover witness or proof generation, the server, or
  anything on chain.

What stays hand-inspected, the trusted boundary: `SPEC.md`, the leaf-hash and
root definitions, and the corpus itself. Everything else is mechanically tied to
those.

## Ecosystem fit

- This is a verifier conformance vector set in the Zcash test-vector tradition.
  Any third party can run the corpus against their own ZAP1 verifier.
- The mechanism is the vk-style fingerprint-equivalence check published by
  Tachyon/Ragu (Bowe, Derei, zkSecurity), applied here to two verifier
  implementations rather than to a circuit and its formal model. The pattern is
  cited, the pedigree is not borrowed: that work proves cryptographic soundness
  in Lean, this checks that two hash-and-compare verifiers agree.
- A fuzzing pass over the corpus is a later slot.

## Where this sits

This raises assurance that the published verifier is free of implementation
drift. It is not adoption and not funding, which remain the binding constraints.
Its value toward those is narrow and real: it lets any ZAP1-facing claim point at
a frozen, third-party-runnable equivalence corpus instead of a single verifier.

## Run it

```
python3 equivalence/fingerprint.py
cargo run --manifest-path equivalence/rust/Cargo.toml -- equivalence/corpus.json
node equivalence/typescript/fingerprint.mjs
```

Regenerate after changing the case set:

```
python3 equivalence/gen_corpus.py
python3 equivalence/fingerprint.py > equivalence/fingerprints.expected.txt
```
