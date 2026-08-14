# ZAP1 evidence index

Cutoff: 2026-08-13

This is the current reviewer index. It separates code, runtime state, public
records, and claims. A green check in one layer does not certify another.

## Code state

- The canonical implementation registry defines 18 types: `0x01-0x0F` and
  `0x40-0x42`.
- `POST /event` accepts 15 operator-written types. `PROGRAM_ENTRY`,
  `OWNERSHIP_ATTEST`, and `MERKLE_ROOT` are system-managed.
- The current tree commitment binds the leaf count. Historical raw-root proofs
  are accepted only under the explicit legacy scheme and height cutoff. The
  verifier applies that cutoff to anchor metadata supplied by the bundle.
- Public `/events`, `/verify/{leaf}/proof.json`, and verification pages withhold
  stored wallet and serial preimages.
- FROST support is experimental, Testnet-only, and colocated. One process still
  holds `ANCHOR_SEED` and two shares. This is not independent threshold custody.

The implementation profile and fixed vectors live in:

- `src/memo.rs`
- `docs/EVENT_SCHEMA.md`
- `TEST_VECTORS.md`
- `conformance/implementation_profile_vectors.json`
- `conformance/implementation_profile_check.py`

## Proof boundary

A proof bundle can establish that a leaf hash is included under the supplied
Merkle root. It does not prove the truth, completeness, or independent origin
of the event claim.

Without the leaf witness, Merkle inclusion does not authenticate the displayed
event type. Public bundles mark that label as
`unverified_server_metadata_without_disclosed_witness`.

A recorded txid and height establish a transaction reference after configured
node lookup. They do not reveal an encrypted Orchard memo or independently bind
that memo to the supplied root. That requires a separate safe opening artifact.

Legacy eligibility is therefore a check on the bundle's declared envelope,
not independent proof of chain time. A separate chain-binding check must tie
the supplied anchor metadata to a mined transaction and safely opened memo
before it can bind the root to the chain. References to a canonical root or
txid mean the service recorded and returned the required encoding. They do not
claim blockchain canonicality or root-to-transaction binding.

The service stores operator-submitted fields. Public feeds and proof bundles
withhold them. Integrators must submit domain-separated pseudonyms.
Participant, lifecycle, and full invoice routes require operator bearer
authentication. Payment pages use unguessable invoice URLs as bearer
capabilities and can disclose a payment request to anyone who obtains the URL.

## Package state

| Artifact | Public release | Repository candidate | Boundary |
| --- | --- | --- | --- |
| `zap1-verify` | crates.io `0.2.1` | `0.3.0` | Public `0.2.1` covers `0x01-0x09` and legacy raw-root verification. The 18-type count-bound candidate is not published. |
| `zcash-memo-decode` | crates.io `0.1.1` | `0.1.2` | Public `0.1.1` labels through `0x0C`. Governance and agent labels are only in the repository candidate. |
| `@frontiercompute/zap1` | npm `0.2.1` | same line | Published with count-bound v2 and gated legacy support. |
| verify widget | none | repository-local | No `@frontier-compute/verify-widget` npm package is published. |

No package publication is implied by candidate source.

## Runtime gate

Mutable production facts come from fresh live reads, not this file. The live
evaluator compares the revision, source tree, source manifest, and image ID
declared by `/build/info` with a clean checkout and the expected ID from an
operator-local pinned-image receipt. This is declared metadata parity, not
remote attestation of the bytes serving the request.

The pre-deploy public service was still on an older build at the 2026-08-13
cutoff. Its stats and source metadata are not evidence for this candidate.

## Public records

The machine-readable digest index is
[`evidence/public-records-20260813.json`](evidence/public-records-20260813.json).
It carries exact locators, observation times, hashes, and claim boundaries for:

- application #31 and its Ready For Vote administrative state;
- the applicant-authored funding clarification and project-only forum update;
- the separate ZCG security-bounty ledger row;
- Daira-Emma Hopwood's direct terminology review and the still-draft ZIP state;
- bounded searches for a direct Zooko endorsement, with none claimed.

The pack does not reproduce the frozen HTTP response bodies. A reviewer can
check the recorded digests only if they already possess those exact historical
bytes. Fresh reads can test current state, but they cannot recreate a changed
historical response. Treat this file as a digest index, not a self-contained
public archive.

Ready For Vote is not an award. A reaction is not an endorsement. A review
comment is not approval. A tx reference is not a memo opening. Applicant text
is not independent validation.

## Deterministic review

Run the deterministic repository checks with the committed lockfile:

```bash
bash scripts/check.sh --local
```

The live gate additionally requires a clean checkout of the commit recorded in
the operator-local build receipt and the image ID copied from that receipt. Its
generated checksum must be checked separately:

```bash
export ZAP1_EXPECTED_DEPLOYMENT_IMAGE_ID='sha256:<64 lowercase hex characters>'
# Optional explicit policy override. Default: 10 blocks.
export ZAP1_MAX_SYNC_LAG_BLOCKS=10
bash scripts/check.sh --live
```

The local evaluator must fail on vector, compatibility, equivalence, schema,
or locked-test defects. The live evaluator must fail on declared metadata
parity, scanner or RPC status, bounded sync lag, public preimage redaction,
anchor liveness, or proof-verification defects. Skips are not passes.

## Explicit non-claims

- The research ZIP is open, draft, and unmerged.
- No independently verified external production adopter is evidenced here.
- No Zooko, Daira, ZCG, FPF, or Zcash Foundation endorsement is claimed.
- No FROST production custody, DKG, or independent signer quorum is claimed.
- No award, payout, payment, or receivable is inferred from eligibility or
  attention.
- Booked cash: `$0`.
- Hard receivable: `$0`.
