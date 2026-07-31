"""WI-026 meta-guard: prove the conformance gate *runs*, not *skips*.

The silent-skip bug (2026-07-24) bit three components: their
``test_cli_conformance.py`` did ``pytest.importorskip("agent_suite.conformance")``
against a module that was never installed, so every case skipped, CI stayed green,
and zero contract was enforced. A skipped gate is indistinguishable from a passing
one in a green build — the canonical "fails open" hazard.

Kit 1.1.0 ships both meta-guard helpers; this file consumes the shipped
``ConformanceGateError`` rather than a local copy (WI-023). The empty-dimension
guard (``assert_cases_declared``) lives in ``test_cli_conformance.py``. This file
catches the other half — "the whole module skipped" — by running the conformance
module as a subprocess and asserting at least one case *passed* (not all-skipped).

The guard is factored into a pure function (``require_gate_ran``) so a deny-case
can prove it rejects an all-skip summary — not a tautology (process-calibration
§5).

Import note: ``importorskip`` keeps a kit-less local checkout (no ``[dev]`` extra,
e.g. a 3.11 runtime env — the kit requires py>=3.12) from hard-erroring at
collection. In CI the kit is a mandatory pinned dep, so this guard runs and
enforces; if the kit import name ever drifts again, the live-case test below
reddens the build instead of silently skipping (WI-026).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

# Kit 1.1.0 ships ConformanceGateError; consume it rather than a local copy.
conformance = pytest.importorskip("agent_suite.conformance")
ConformanceGateError = conformance.ConformanceGateError

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE_TEST = REPO_ROOT / "tests" / "test_cli_conformance.py"


# A pytest summary line carries the timing suffix "in <number>s". Anchoring to
# that suffix — rather than scanning the whole captured stream — means a
# count-like token printed by a test under examination (e.g. a CLI emitting JSON
# with a "passed" field) cannot be mistaken for pytest's own summary. Counts are
# parsed from the LAST summary line only. The trailing ``=+`` run is optional so
# the parser matches BOTH the default reporter's decorated summary
# ("===== N passed in Xs =====") and the quiet reporter's bare line
# ("N passed in Xs") — the gate runs the default reporter (no ``-q``) for a
# stable, always-present summary line.
_SUMMARY_LINE_RE = re.compile(r"^(?P<line>.*?\bin \d+(?:\.\d+)?s)\s*(?:=+\s*)?$", re.MULTILINE)
_COUNT_RE = {
    "passed": re.compile(r"(\d+)\s+passed"),
    "skipped": re.compile(r"(\d+)\s+skipped"),
    "failed": re.compile(r"(\d+)\s+failed"),
    "error": re.compile(r"(\d+)\s+errors?\b"),
}


def _summary_counts(output: str) -> dict[str, int]:
    """Parse pytest counts from the LAST summary line in ``output``."""
    summary_matches = list(_SUMMARY_LINE_RE.finditer(output))
    line = summary_matches[-1].group("line") if summary_matches else ""
    counts: dict[str, int] = {}
    for key, pattern in _COUNT_RE.items():
        m = pattern.search(line)
        counts[key] = int(m.group(1)) if m else 0
    return counts


def require_gate_ran(
    output: str,
    *,
    exit_code: int = 0,
    minimum_passed: int = 1,
) -> dict[str, int]:
    """Meta-guard: assert the conformance gate ran at least ``minimum_passed``
    cases AND exited cleanly.

    Two independent signals, both required:
    - ``exit_code == 0`` — pytest exited success.
    - ``passed >= minimum_passed`` parsed from the last summary line — catches
      the importorskip class, where pytest exits 0 but every case skipped.
    """
    counts = _summary_counts(output)
    fragment = output.strip().splitlines()[-1] if output.strip() else "<no output>"
    if exit_code != 0:
        raise ConformanceGateError(
            f"conformance gate did not exit cleanly (exit {exit_code}); "
            f"counts={counts}; last line: {fragment!r}"
        )
    if counts["passed"] < minimum_passed:
        raise ConformanceGateError(
            f"conformance gate ran {counts['passed']} case(s) (minimum "
            f"{minimum_passed}); {counts['skipped']} skipped. An all-skip, "
            f"zero-pass run means importorskip fired against a missing/wrong kit "
            f"module — the gate enforced nothing. See docs/cli-contract.md §7 "
            f"(WI-026). Last line: {fragment!r}"
        )
    return counts


def _run_pytest(test_path: Path, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Run pytest on ``test_path`` with color disabled and return the result.

    Deliberately NOT ``-q``: the quiet reporter prints a terse progress line whose
    short summary can be elided or reformatted across pytest versions, which makes
    the ``in <num>s`` summary-line parse below fragile. The default reporter always
    emits a stable ``N passed[, M skipped] in Xs`` summary line that ``_SUMMARY_LINE_RE``
    anchors on. Color is forced off (``--color=no`` + ``NO_COLOR``/``PY_COLORS``) so
    ANSI escapes can never corrupt that parse.
    """
    env = {
        **os.environ,
        "NO_COLOR": "1",
        "PY_COLORS": "0",
    }
    env.pop("FORCE_COLOR", None)
    proc = subprocess.run(
        [
            sys.executable, "-m", "pytest", str(test_path),
            "-p", "no:cacheprovider", "--no-header", "--color=no",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return proc


def test_conformance_gate_runs_at_least_one_case(tmp_path: Path) -> None:
    """The live conformance module must exit 0 and pass >=1 case (not all-skip)."""
    proc = _run_pytest(CONFORMANCE_TEST, tmp_path)
    counts = require_gate_ran(
        proc.stdout + proc.stderr, exit_code=proc.returncode, minimum_passed=1
    )
    assert counts["passed"] >= 1, counts


def test_require_gate_ran_accepts_a_clean_passing_summary() -> None:
    """Positive control: a clean exit-0 run with a passing summary passes."""
    counts = require_gate_ran(
        "..........                               [100%]\n10 passed in 1.24s\n",
        exit_code=0,
    )
    assert counts["passed"] == 10


def test_require_gate_ran_rejects_an_all_skip_summary() -> None:
    """Deny case: an exit-0 all-skip summary (importorskip fired) is rejected."""
    with pytest.raises(ConformanceGateError, match="importorskip"):
        require_gate_ran(
            "s.....                                   [100%]\n5 skipped in 0.5s\n",
            exit_code=0,
        )


def test_require_gate_ran_rejects_nonzero_exit() -> None:
    """Deny case: a nonzero exit is rejected even if a 'passed' count appears."""
    with pytest.raises(ConformanceGateError, match="did not exit cleanly"):
        require_gate_ran(
            "1 passed in 0.5s\n",  # decoy summary that looks healthy
            exit_code=1,
        )


def test_require_gate_ran_ignores_count_like_test_output() -> None:
    """Deny case: count-like strings printed by a test must not be parsed as summary."""
    noisy = "some CLI printed: 1 passed, awesome\n5 skipped in 0.5s\n"
    with pytest.raises(ConformanceGateError, match="importorskip"):
        require_gate_ran(noisy, exit_code=0)


def test_require_gate_ran_rejects_when_no_summary_printed() -> None:
    """Deny case: a crashed pytest that printed no summary is rejected."""
    with pytest.raises(ConformanceGateError):
        require_gate_ran("Fatal Python error: Segmentation fault\n", exit_code=-11)


def test_meta_guard_detects_a_real_importorskip_skip(tmp_path: Path) -> None:
    """End-to-end falsifier: a module that importorskip's a bogus name fails to
    collect, and ``require_gate_ran`` flags it.
    """
    bogus = tmp_path / "test_skips_silently.py"
    bogus.write_text(
        "import pytest\n"
        "pytest.importorskip('agent_suite.conformance.this_does_not_exist_xyz')\n"
        "def test_dummy() -> None:\n"
        "    assert False  # would fail if it ran; it must not run\n"
    )
    proc = _run_pytest(bogus, tmp_path)
    with pytest.raises(ConformanceGateError) as exc:
        require_gate_ran(proc.stdout + proc.stderr, exit_code=proc.returncode, minimum_passed=1)
    msg = str(exc.value)
    assert "did not exit cleanly" in msg or "importorskip" in msg, msg
