"""Develop-against-lock enforcement (Plan 019 B2).

SUITE.lock is the single source of truth for *what to develop against*. These
tests are the mechanical control (the enforcement layer, per Plan 019 §2): they
fail if CI is wired to install the regista spine from a hardcoded version pin or
a sibling ``@main`` instead of the locked release — the exact drift that put a
stale ``regista-hraedon==0.5.1`` in CI while SUITE.lock pinned 0.5.3, and the
develop-against-``main`` skew that broke interop on 2026-07-21.

Pure unit tests — no DB, no network.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import suite_lock  # noqa: E402  (script helper, resolved via the sys.path insert)

_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_LOCK = _ROOT / "SUITE.lock"


def _lock() -> dict:
    return tomllib.loads(_LOCK.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The resolver: default is the locked release; the hatch is explicit.
# ---------------------------------------------------------------------------


def test_locked_version_is_read_from_suite_lock():
    assert suite_lock.regista_version() == _lock()["spine"]["version"]


def test_default_requirement_pins_the_locked_release(monkeypatch):
    """Unset DEV_AGAINST -> install regista-hraedon at the SUITE.lock version."""
    monkeypatch.delenv("DEV_AGAINST", raising=False)
    version = _lock()["spine"]["version"]
    assert suite_lock.regista_requirement() == [f"regista-hraedon=={version}"]


def test_lock_mode_is_explicit_default():
    version = _lock()["spine"]["version"]
    assert suite_lock.regista_requirement(mode="lock") == [f"regista-hraedon=={version}"]


def test_git_ref_hatch_installs_from_that_ref():
    assert suite_lock.regista_requirement(mode="main") == [
        "regista-hraedon @ git+https://github.com/hraedon/regista.git@main"
    ]
    # An arbitrary ref (branch/tag/SHA) is honored, not just "main".
    assert suite_lock.regista_requirement(mode="feature/x") == [
        "regista-hraedon @ git+https://github.com/hraedon/regista.git@feature/x"
    ]


def test_env_selects_mode(monkeypatch):
    monkeypatch.setenv("DEV_AGAINST", "main")
    assert suite_lock.dev_against() == "main"
    assert suite_lock.regista_requirement()[0].startswith("regista-hraedon @ git+")


# ---------------------------------------------------------------------------
# The SUITE.lock face-local copy stays internally coherent + agrees with the
# umbrella (checked here as: it records a released version + the tag's SHA).
# ---------------------------------------------------------------------------


def test_suite_lock_records_released_spine_version():
    spine = _lock()["spine"]
    assert spine["distribution"] == "regista-hraedon"
    # A released, PEP 440-ish version (not a "-rc"/"-dev" pre-release to develop against).
    assert re.fullmatch(r"\d+\.\d+\.\d+", spine["version"]), spine["version"]
    # 40-hex commit the version was cut from (== umbrella [components.regista].revision).
    assert re.fullmatch(r"[0-9a-f]{40}", spine["sha"]), spine["sha"]
    assert spine["describe"] == f"v{spine['version']}"


# ---------------------------------------------------------------------------
# CI is wired through the paved installer — no hardcoded pin, no unguarded @main.
# This is the control that would have caught the 0.5.1-vs-0.5.3 drift.
# ---------------------------------------------------------------------------


def test_ci_installs_deps_through_dev_install():
    ci = _CI.read_text(encoding="utf-8")
    # cairn's dep-installing lane (`lint-and-test`, matrixed over py 3.13/3.14)
    # must install through the paved installer. cairn has no Windows lane; the
    # js-test lane installs no Python deps. So one invocation is expected.
    assert ci.count("scripts/dev-install.py") >= 1, (
        "the lint-and-test lane must install via scripts/dev-install.py "
        "(develop-against-lock, Plan 019 B2)"
    )


def test_ci_carries_no_hardcoded_regista_pin():
    ci = _CI.read_text(encoding="utf-8")
    # A literal `regista-hraedon==<digit>` in CI is the anti-pattern this plan
    # kills: it drifts from SUITE.lock silently. The version must come from the
    # lock. (An illustrative `==<[spine].version>` in a comment is not a pin.)
    hardcoded = re.findall(r"regista-hraedon==\s*\d[\w.]*", ci)
    assert not hardcoded, (
        f"CI hardcodes a regista version {hardcoded} — it drifts from SUITE.lock. "
        "Install via scripts/dev-install.py, which reads [spine].version."
    )


def test_ci_carries_no_unguarded_sibling_install():
    ci = _CI.read_text(encoding="utf-8")
    # A raw git+ install of the spine in CI would be developing against @main
    # without the DEV_AGAINST hatch. The hatch is an env var on dev-install, not
    # a raw pip line, so the git URL must not appear in the workflow text.
    assert "git+https://github.com/hraedon/regista" not in ci, (
        "CI must not install regista from git directly; use DEV_AGAINST on "
        "scripts/dev-install.py for deliberate cross-member work."
    )


def test_dev_install_has_no_version_literal():
    """The installer resolves the version from the lock, never hardcodes it."""
    src = (_SCRIPTS / "dev-install.py").read_text(encoding="utf-8")
    assert "regista-hraedon==" not in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
