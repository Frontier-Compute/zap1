# Contributing to zap1

## Overview

zap1 is the reference implementation and on-chain attestation engine for the ZAP1 protocol. Contributions that improve the protocol, scanner, verification surfaces, or documentation are welcome.

## Getting Started

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
docker build --target builder -t zap1-test .
docker run --rm zap1-test cargo test --release --test memo_merkle_test
```

## Code Style

- Rust: follow standard `rustfmt` conventions and the [librustzcash style guides](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md#styleguides) as primary reference for Zcash integration code
- Commits: imperative mood, concise subject line
- No `unsafe` without justification
- All public API changes require test coverage

## Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure `cargo test` passes
5. Submit a PR with a clear description of what changed and why

## Protocol Changes

Changes to the ZAP1 memo protocol (event types, hash construction, Merkle tree rules) require updating:
- `ONCHAIN_PROTOCOL.md`
- `verify_proof.py`
- Test vectors in `tests/`

## Security

Report vulnerabilities via Signal (see `SECURITY.md`). Do not open public issues for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
