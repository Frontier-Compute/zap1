#!/usr/bin/env python3
"""Compute the runtime-source manifest used by the ZAP1 image build."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


INPUTS = (
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "src",
    "proto",
    "zap1-verify",
    "zcash-memo-decode",
    "migrations",
    "tests",
)


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for item in INPUTS:
        path = root / item
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(candidate for candidate in path.rglob("*") if candidate.is_file())
        else:
            raise FileNotFoundError(f"required source input is missing: {item}")
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def manifest_digest(root: Path) -> str:
    outer = hashlib.sha256()
    for path in source_files(root):
        relative = path.relative_to(root).as_posix()
        file_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        outer.update(f"{file_digest}  {relative}\n".encode("utf-8"))
    return outer.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository or extracted source root",
    )
    args = parser.parse_args()
    print(manifest_digest(args.root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
