"""cairn's CLI run through the CLI contract v1 conformance kit (Plan 018 WI-2).

The kit is the centrally versioned package ``agent_suite_conformance``, consumed
pinned as ``agent-suite-conformance==1.0.0`` from PyPI (Plan 019 B1) via the
``[dev]`` extra — never copied, never imported by runtime code. Source checkouts
may still expose the legacy PEP 420 ``agent_suite.conformance`` layout.

cairn's CLI is click (not argparse); the contract boundary is the console entry
``cairn._cli:cli_entry``, which runs the group with ``standalone_mode=False`` and
converts operational ``ClickException``s / unexpected exceptions into the
envelope on stdout while leaving usage errors at exit 2.

Scope note (Plan 019 B3 / WI-023): ``doctor --json`` is a health *reporter* — it
emits a valid document and exits 1 when the box is merely unconfigured, which is
neither a clean exit-0 success nor an operational-error envelope. cairn has no
other hermetic exit-0 JSON verb (the rest write files or mutate config), so a
``SuccessCase`` is honestly omitted rather than faked. What is asserted:

- **§2/§3** via an ``ErrorCase``: ``verify --format json`` against a malformed
  key file is a documented operational failure — the boundary emits a
  ``CAIRN_ERROR`` envelope on stdout with exit 1. (This path used to *traceback*
  on the unguarded ``json.loads``; this WI also wraps it, so §4 holds here too.)
- **§2** via a ``UsageCase``: an unknown verb exits 2.
- **§4** via a ``BrokenPipeCase``: closing ``doctor --json``'s stdout early
  produces no traceback.

The module also implements the 1.1-style empty-dimension guard locally using the
1.0.0 wheel API, so the conformance gate fails loudly if a refactor empties a
case dimension.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    import agent_suite_conformance as conformance
except ModuleNotFoundError:
    conformance = pytest.importorskip("agent_suite.conformance")

BrokenPipeCase = conformance.BrokenPipeCase
ErrorCase = conformance.ErrorCase
UsageCase = conformance.UsageCase
run_broken_pipe_case = conformance.run_broken_pipe_case
run_error_case = conformance.run_error_case
run_usage_case = conformance.run_usage_case

# `python -m cairn` invokes the *bridge*, not the CLI; the CLI is the `cairn`
# console script installed next to this interpreter.
_CAIRN = str(Path(sys.executable).parent / "cairn")

# Fixtures for the ErrorCase: files that exist (so click.Path(exists=True)
# passes) but hold malformed content (so the key loader raises an operational
# ClickException). Created once at import.
_TMP = tempfile.mkdtemp(prefix="cairn-conformance-")
_GARBAGE_KEYS = os.path.join(_TMP, "keys.json")
_GARBAGE_BUNDLE = os.path.join(_TMP, "bundle.json")
Path(_GARBAGE_KEYS).write_text("not json\n")
Path(_GARBAGE_BUNDLE).write_text("not json\n")

# An empty HOME so the broken-pipe doctor probe reads no real cairn config.
_EMPTY_HOME = tempfile.mkdtemp(prefix="cairn-conformance-home-")


ERROR_CASES = [
    ErrorCase(
        name="verify-malformed-keys",
        argv=(
            _CAIRN, "verify",
            "--bundle-path", _GARBAGE_BUNDLE,
            "--keys", _GARBAGE_KEYS,
            "--format", "json",
        ),
        expect_code="CAIRN_ERROR",
    ),
]

USAGE_CASES = [
    UsageCase(name="unknown-verb", argv=(_CAIRN, "bogusverb")),
]

BROKEN_PIPE_CASES = [
    BrokenPipeCase(
        name="doctor-broken-pipe",
        argv=(_CAIRN, "doctor", "--json"),
        env={"HOME": _EMPTY_HOME},
    ),
]


def _assert_cases_declared(**named_groups: list[Any]) -> None:
    """Local 1.1-style guard: every declared case dimension must be non-empty.

    The 1.0.0 wheel does not ship ``assert_cases_declared``. Implementing the
    same shape locally keeps the gate fails-closed when a refactor empties a
    dimension, without depending on an unpublished kit version.
    """
    if not named_groups:
        raise AssertionError(
            "assert_cases_declared was called with no case groups; a guard that "
            "protects no dimensions enforces nothing."
        )
    short = sorted((name, len(group)) for name, group in named_groups.items() if len(group) < 1)
    if short:
        which = ", ".join(f"{name} ({n})" for name, n in short)
        raise AssertionError(
            f"conformance gate declared fewer than 1 case(s) for dimension(s): {which}"
        )


_assert_cases_declared(
    error=ERROR_CASES,
    usage=USAGE_CASES,
    broken_pipe=BROKEN_PIPE_CASES,
)


@pytest.mark.parametrize("case", ERROR_CASES, ids=lambda c: c.name)
def test_error_conformance(case: ErrorCase) -> None:
    assert run_error_case(case) == []


@pytest.mark.parametrize("case", USAGE_CASES, ids=lambda c: c.name)
def test_usage_conformance(case: UsageCase) -> None:
    assert run_usage_case(case) == []


@pytest.mark.parametrize("case", BROKEN_PIPE_CASES, ids=lambda c: c.name)
def test_broken_pipe_conformance(case: BrokenPipeCase) -> None:
    assert run_broken_pipe_case(case) == []
