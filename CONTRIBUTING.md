# Contributing to zap1

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

## Code of Conduct

This project follows the [Zcash Community Code of Conduct](https://forum.zcashcommunity.com/t/zcg-code-of-conduct/41787).

## Reporting Bugs

Open an issue on [GitHub](https://github.com/Frontier-Compute/zap1/issues) with:
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error output
- Your environment (OS, Rust version, Docker version)

For security vulnerabilities, see [Security](#security) below.

## Getting Started

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
cargo fmt --check
cargo test --release --test memo_merkle_test
```

Or build and test inside Docker (matches CI):

```bash
docker build --target builder -t zap1-test .
docker run --rm zap1-test cargo test --release --test memo_merkle_test
```

## Style Guides

This project follows the [librustzcash style guides](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md#styleguides) as primary reference.

### Rust

- Run `cargo fmt` before committing. CI rejects unformatted code.
- No `unsafe` without justification and a `// SAFETY:` comment.
- Public API items require documentation (`///` doc comments).
- Prefer type-safe wrappers over raw primitives for domain types.
- Error types should be enums, not strings.
- Side effects (I/O, network, database) stay out of pure computation paths.
- Keep `use` imports sorted and grouped (std, external, crate).

### Commits

- Imperative mood in the subject line ("add keygen binary", not "added keygen binary")
- Subject under 72 characters
- Body explains *why*, not *what* (the diff shows what)
- One logical change per commit. Squash fixups before merging.
- Update `CHANGELOG.md` for any user-visible or API-level change.

### Pull Requests

1. Branch from `main`.
2. One logical change per PR. Stacked PRs are fine for larger work.
3. Write tests for new functionality. All tests must pass.
4. Run the ship checklist before opening:
   - `cargo fmt --check`
   - `cargo test --release --test memo_merkle_test`
   - `cargo clippy`
   - No emdashes, no AI-generated language, no grant references in code
5. Open as draft if work is in progress. Convert to ready when CI is green.
6. Describe what changed and why in the PR body.
7. Rebase on `main` if the branch falls behind. Do not merge commits from `main` into your branch.

### Protocol Changes

Changes to the ZAP1 memo protocol (event types, hash construction, Merkle tree rules) require updating all of:
- `ONCHAIN_PROTOCOL.md` (specification)
- `TEST_VECTORS.md` (new vectors for changed/added types)
- `conformance/hash_vectors.json` (machine-readable vectors)
- `tests/memo_merkle_test.rs` (test assertions)
- `verify_proof.py` (Python reference verifier)

Event type bytes are append-only. Existing types are never redefined.

### Versioning

The protocol follows semantic versioning. Hash construction rules for existing event types are frozen at their introduction version. Changes to frozen types require a new major version.

## Security

Report vulnerabilities privately via Signal (see `SECURITY.md`). Do not open public issues for security vulnerabilities. Confirmed issues will be acknowledged within 48 hours.
