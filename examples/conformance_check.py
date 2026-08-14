#!/usr/bin/env python3
"""Retired compatibility entrypoint for the strict API checker."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    checker = Path(__file__).resolve().parents[1] / "conformance" / "check_api.py"
    if not checker.is_file():
        print(
            "RETIRED: use conformance/check_api.py from an exact ZAP1 checkout.",
            file=sys.stderr,
        )
        return 2
    if "--key" in sys.argv:
        print(
            "REJECTED: this read-only checker never accepts or forwards API keys.",
            file=sys.stderr,
        )
        return 2
    return subprocess.run([sys.executable, str(checker), *sys.argv[1:]], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
