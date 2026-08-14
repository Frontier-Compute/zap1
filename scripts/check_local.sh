#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

find_python() {
  if [ -n "${PYTHON:-}" ]; then
    printf '%s\n' "$PYTHON"
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s\n' python3
  elif command -v python >/dev/null 2>&1; then
    printf '%s\n' python
  else
    printf '%s\n' "Python 3 is required" >&2
    return 1
  fi
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

configure_msvc_linker() {
  case "$(uname -s)" in
    MINGW*|MSYS*)
      if [ -n "${CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER:-}" ]; then
        return
      fi

      local candidate
      while IFS= read -r candidate; do
        candidate="${candidate//$'\r'/}"
        candidate="${candidate//\\//}"
        case "$candidate" in
          */Git/usr/bin/link.exe)
            ;;
          */link.exe)
            export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="$candidate"
            return
            ;;
        esac
      done < <(where.exe link.exe 2>/dev/null || true)

      printf 'MSVC link.exe is required. Run from a Visual Studio developer environment.\n' >&2
      exit 1
      ;;
  esac
}

run() {
  printf '\n== %s ==\n' "$1"
  shift
  "$@"
}

PYTHON_BIN="$(find_python)"
require_command cargo
require_command node
require_command diff
require_command tr
configure_msvc_linker

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zap1-local-evaluator.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

printf 'ZAP1 deterministic local evaluator\n'
printf 'Repository: %s\n' "$REPO_ROOT"

printf '\n== locked Cargo metadata ==\n'
cargo metadata --locked --format-version 1 --no-deps >/dev/null
run "implementation profile" "$PYTHON_BIN" conformance/implementation_profile_check.py
run "conformance fixtures" "$PYTHON_BIN" conformance/check.py
run "compatibility vectors" "$PYTHON_BIN" scripts/check_compatibility.py
run "live evaluator self-tests" "$PYTHON_BIN" conformance/check_api.py --self-test
run "browser verifier regressions" node verify-widget/verifier.test.mjs

printf '\n== Python verifier fingerprints ==\n'
"$PYTHON_BIN" equivalence/fingerprint.py | tr -d '\r' >"$TMP_ROOT/fp-python.txt"
printf '\n== Rust verifier fingerprints ==\n'
cargo run --quiet --locked --manifest-path equivalence/rust/Cargo.toml -- \
  equivalence/corpus.json | tr -d '\r' >"$TMP_ROOT/fp-rust.txt"
printf '\n== TypeScript verifier fingerprints ==\n'
node equivalence/typescript/fingerprint.mjs | tr -d '\r' >"$TMP_ROOT/fp-typescript.txt"
tr -d '\r' <equivalence/fingerprints.expected.txt >"$TMP_ROOT/fp-expected.txt"

run "Python and Rust fingerprints agree" \
  diff -u "$TMP_ROOT/fp-python.txt" "$TMP_ROOT/fp-rust.txt"
run "Python and TypeScript fingerprints agree" \
  diff -u "$TMP_ROOT/fp-python.txt" "$TMP_ROOT/fp-typescript.txt"
run "fingerprints match the frozen reference" \
  diff -u "$TMP_ROOT/fp-expected.txt" "$TMP_ROOT/fp-python.txt"

run "locked workspace all-target tests" \
  cargo test --workspace --all-targets --locked

printf '\nPASS: deterministic local evaluator\n'
