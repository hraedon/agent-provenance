#!/usr/bin/env python3
"""Resolve what suite spine (regista) to develop against, from SUITE.lock.

Single source of truth for "what to develop against" (Plan 019 B2). ``SUITE.lock``
pins the released regista version this cairn release composes with; by
default dev + CI install *that* version from PyPI, so feature work happens against
the artifact the suite ships, not against a sibling's ``main``. Cross-member work
is still possible — but only through one obvious switch, ``DEV_AGAINST``:

    DEV_AGAINST unset / "lock"   regista-hraedon==<SUITE.lock [spine].version>   (default)
    DEV_AGAINST=sibling          -e ../regista   (editable local checkout; co-dev)
    DEV_AGAINST=main | <ref>     regista-hraedon @ git+https://…/regista.git@<ref>

Reading ``[spine].version`` (not the umbrella agent-suite/SUITE.lock) means CI
resolves the spine without cloning agent-suite; the two locks are kept in
agreement (this face-local copy is vendored from the umbrella).

CLI:
    python scripts/suite_lock.py version              # -> 0.5.4
    python scripts/suite_lock.py requirement          # -> the pip requirement token(s)
    python scripts/suite_lock.py requirement --dev-against main
"""

from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

_LOCK = Path(__file__).resolve().parent.parent / "SUITE.lock"
_SIBLING = Path(__file__).resolve().parent.parent.parent / "regista"

# Default mode when DEV_AGAINST is unset/empty: develop against the locked release.
_LOCK_MODE = "lock"


def _load() -> dict:
    if not _LOCK.is_file():
        raise SystemExit(f"suite_lock: no SUITE.lock at {_LOCK}")
    return tomllib.loads(_LOCK.read_text(encoding="utf-8"))


def _spine(data: dict) -> dict:
    spine = data.get("spine")
    if not spine:
        raise SystemExit("suite_lock: SUITE.lock has no [spine] section")
    return spine


def regista_version(data: dict | None = None) -> str:
    """The locked PyPI version to develop against."""
    spine = _spine(data or _load())
    version = spine.get("version")
    if not version:
        raise SystemExit(
            "suite_lock: [spine].version missing from SUITE.lock — it must record "
            "the released regista version to develop against (Plan 019 B2)."
        )
    return str(version)


def _distribution(spine: dict) -> str:
    return str(spine.get("distribution", "regista-hraedon"))


def _git_url(spine: dict) -> str:
    repo = spine.get("repo", "hraedon/regista")
    return f"git+https://github.com/{repo}.git"


def dev_against() -> str:
    """The active DEV_AGAINST mode (env), defaulting to the lock."""
    return (os.environ.get("DEV_AGAINST") or _LOCK_MODE).strip()


def regista_requirement(mode: str | None = None, data: dict | None = None) -> list[str]:
    """The ``pip install`` argument list for regista under the given mode.

    Returns a list so the editable/sibling case can carry the ``-e`` flag as its
    own token.
    """
    data = data or _load()
    spine = _spine(data)
    mode = (mode or dev_against()).strip()
    dist = _distribution(spine)

    if mode in ("", _LOCK_MODE):
        return [f"{dist}=={regista_version(data)}"]
    if mode == "sibling":
        if not (_SIBLING / ".git").exists():
            raise SystemExit(
                f"suite_lock: DEV_AGAINST=sibling but no regista checkout at {_SIBLING}"
            )
        return ["-e", str(_SIBLING)]
    # Anything else is treated as a git ref (branch/tag/SHA) — the deliberate
    # cross-member escape hatch. "main" is the common case.
    return [f"{dist} @ {_git_url(spine)}@{mode}"]


def describe_target(mode: str | None = None, data: dict | None = None) -> str:
    """Human-readable one-liner of what will be developed against."""
    data = data or _load()
    mode = (mode or dev_against()).strip()
    if mode in ("", _LOCK_MODE):
        version = regista_version(data)
        return f"regista {version} (locked release, from PyPI) — DEV_AGAINST={_LOCK_MODE}"
    if mode == "sibling":
        return f"regista editable sibling at {_SIBLING} — DEV_AGAINST=sibling (deliberate co-dev)"
    return f"regista @ git ref '{mode}' — DEV_AGAINST={mode} (deliberate cross-member work)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version", help="print the locked regista version")
    p_req = sub.add_parser("requirement", help="print the pip install token(s) for regista")
    p_req.add_argument(
        "--dev-against",
        default=None,
        help="override the DEV_AGAINST mode (lock|sibling|main|<ref>)",
    )
    sub.add_parser("describe", help="print a human-readable description of the target")
    args = parser.parse_args(argv)

    if args.cmd == "version":
        print(regista_version())
        return 0
    if args.cmd == "requirement":
        print(" ".join(regista_requirement(mode=args.dev_against)))
        return 0
    if args.cmd == "describe":
        print(describe_target())
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
