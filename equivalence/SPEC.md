# ZAP1 verifier equivalence fingerprint: encoding spec

Version `zap1-verifier-equiv-v1`.

A fingerprint is the SHA-256 digest of a canonical byte encoding of one
verification case: its inputs, plus the outputs the verifier produced for it
(verdict, result scheme, and the two computed roots). Each implementation runs
its own verifier over the shared corpus and prints one line per case:

```
<case_id> <sha256_hex>
```

Lines are sorted by `case_id`. Two implementations produce identical output only
if their verifiers agree on every case, up to a SHA-256 collision.

## Inputs

A case comes from `equivalence/corpus.json`:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable case identifier. |
| `leaf_hash` | hex(32) | The leaf being proven. |
| `leaf_count` | integer >= 1 | Leaf count bound into the v2 root. |
| `proof` | array | Steps `{ "hash": hex(32), "position": "left"\|"right" }`. |
| `expected_root` | hex(32) | The root the proof is checked against. |
| `scheme` | string or null | Caller-supplied root scheme hint. |
| `anchor_height` | integer or null | Anchor height, for the historical legacy gate. |
| `allow_historical_legacy` | bool | Caller flag permitting the legacy raw-root path. |

`note` is documentation only and is not encoded.

## Outputs (recomputed per implementation)

Each verifier computes, with no shared state:

- `raw_root`: fold of the leaf through the proof path using the ZAP1 node hash.
- `count_bound_root`: `commit_root(leaf_count, raw_root)`.
- `valid` and `result_scheme`, by the standard ZAP1 verdict order:
  1. if `count_bound_root == expected_root`: valid, `ZAP1_COUNT_BOUND_V2`.
  2. else if `raw_root == expected_root` and the legacy gate passes: valid,
     `ZAP1_LEGACY_DUPLICATE_ODD`.
  3. else: invalid, `INVALID`.

Legacy gate: `(allow_historical_legacy or scheme == "ZAP1_LEGACY_DUPLICATE_ODD")`
and `anchor_height is not null` and `anchor_height <= 3317133`.

## Preimage byte layout

All integers are unsigned big-endian. Length-prefixed strings are a 4-byte
big-endian length followed by the UTF-8 bytes. Field elements are raw 32 bytes.

```
"zap1-verifier-equiv-v1"            22 raw ASCII bytes (domain separator)
lp(case_id)                         u32 len + bytes
leaf_hash                           32
leaf_count                          u64
proof_len                           u64
  per step:
    position                        1 byte  (left = 0x00, right = 0x01)
    sibling                         32
expected_root                       32
scheme        none -> 0x00,  some -> 0x01 + lp(scheme)
anchor_height none -> 0x00,  some -> 0x01 + u64
allow_historical_legacy            1 byte  (0x00 / 0x01)
valid                              1 byte  (0x00 / 0x01)
lp(result_scheme)                   u32 len + bytes
count_bound_root                    32
raw_root                            32
```

`fingerprint = lowercase_hex(sha256(preimage))`.

The encoding is injective: every token is fixed width or length-prefixed, so the
preimage decodes unambiguously. Both halves of the digest preimage, inputs and
outputs, are present, so a divergence in any verifier behavior (verdict, scheme
classification, or either computed root) changes the digest.

## Adding another implementation

Implement the same verifier and the same encoding in the new language, emit the
sorted `<id> <digest>` lines, and add a CI step that diffs the output against
`equivalence/fingerprints.expected.txt`. The corpus and the reference file are
the contract; no language is privileged. Python, Rust, and the TypeScript-family
Node runner are the current checked implementations.
