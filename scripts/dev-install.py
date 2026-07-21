#!/usr/bin/env python3
"""Install cairn's dev/test environment against the LOCKED suite substrate.

The paved path for both local dev and CI (Plan 019 B2). By default it installs
the regista spine at the exact released version pinned in ``SUITE.lock`` — the
artifact the suite ships — instead of a sibling's ``main`` / an editable checkout.
Developing against the lock is what catches integration skew (e.g. the 2026-07-21
interop break: a suite developed against a newer sibling than the lock pinned)
*before* interop time, not after.

Same install shape in dev and CI, so "works on my machine" means "works in CI".

Escape hatch — set ``DEV_AGAINST`` for deliberate cross-member work:

    DEV_AGAINST unset / lock   the locked release from PyPI            (default)
    DEV_AGAINST=sibling        editable ../regista working tree        (local co-dev)
    DEV_AGAINST=main | <ref>   regista from git at that branch/tag/SHA

Resolution lives in ``scripts/suite_lock.py`` (the single source of truth reader).

Usage:
    python scripts/dev-install.py            # install against the lock
    python scripts/dev-install.py --print    # show what it WOULD do, install nothing
    DEV_AGAINST=main python scripts/dev-install.py
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import suite_lock

_ROOT = Path(__file__).resolve().parent.parent


def _banner(target: str) -> None:
    line = "=" * 72
    print(line)
    print(f"  dev-install: developing against {target}")
    print("  source: SUITE.lock  (single source of truth for what to develop against)")
    print(line)


def _run(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=str(_ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="print the resolved install plan without installing anything",
    )
    parser.add_argument(
        "--no-ruff",
        action="store_true",
        help="skip installing ruff (the lint tool); CI installs it, some envs have it already",
    )
    args = parser.parse_args(argv)

    regista_req = suite_lock.regista_requirement()
    target = suite_lock.describe_target()

    pip = [sys.executable, "-m", "pip", "install"]
    steps: list[list[str]] = [
        [*pip, "--upgrade", "pip"],
        [*pip, *regista_req],
    ]
    if not args.no_ruff:
        steps.append([*pip, "ruff"])
    # The [dev] extra carries pytest, ruff, mypy, the crypto libs, and the pinned
    # conformance kit (agent-suite-conformance==1.0.0). regista is already resolved
    # above, so this editable install just satisfies the floor with the locked
    # version (pip ignores [tool.uv.sources], so the local ../regista override
    # only applies under `uv`, not this pip-based paved path).
    steps.append([*pip, "-e", ".[dev]"])

    _banner(target)
    if args.print_only:
        print("plan (not executing):")
        for step in steps:
            print("  + " + " ".join(step))
        return 0

    for step in steps:
        _run(step)
    print(f"\ndev-install: done — environment is developing against {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
