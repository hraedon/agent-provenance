"""cairn's CLI run through the CLI contract v1 conformance kit (Plan 018 WI-2).

The kit is the centrally versioned package ``agent_suite.conformance`` — the
PEP 420 namespace shipped by the published ``agent-suite-conformance`` wheel —
consumed pinned as ``agent-suite-conformance==1.1.0`` via the ``[dev]`` extra
(Plan 019 B1 / WI-023). Never copied, never imported by runtime code.

cairn's CLI is click (not argparse); the contract boundary is the console entry
``cairn._cli:cli_entry``, which runs the group with ``standalone_mode=False`` and
converts operational ``ClickException``s / unexpected exceptions into the
envelope on stdout while leaving usage errors at exit 2.

What is asserted (every dimension non-empty; the shipped ``assert_cases_declared``
guard fails collection loudly if a refactor empties one — WI-026):

- **§1/§2** via a ``SuccessCase``: ``install-harness claude --dry-run --json``
  exits 0 with a pure-JSON stdout. Contract §2 ratifies dry-run-as-success
  (WI-021, 2026-07-20): a dry-run that computes and prints its plan exits 0 and
  acts on nothing. The case is hermetic — ``HOME`` is pinned to an empty dir and
  harness-binary detection is non-fatal (``_detect_harness_version`` returns
  ``None`` when the binary is absent), so it passes on a bare CI runner with no
  harness installed. (Earlier revisions of this module claimed cairn had no
  hermetic exit-0 JSON verb and omitted the success dimension; the install-harness
  dry-run is exactly that verb, so the dimension is now honestly declared.)
- **§2/§3** via an ``ErrorCase``: ``verify --format json`` against a malformed
  key file is a documented operational failure — the boundary emits a
  ``CAIRN_ERROR`` envelope on stdout with exit 1. (This path used to *traceback*
  on the unguarded ``json.loads``; WI-023's predecessor wrapped it, so §4 holds
  here too.)
- **§2** via a ``UsageCase``: an unknown verb exits 2.
- **§4** via a ``BrokenPipeCase``: closing ``doctor --json``'s stdout early
  produces no traceback.

Import note: the published wheel ships the ``agent_suite.conformance`` namespace,
NOT a top-level ``agent_suite_conformance`` module (a prior revision imported the
latter and silently fell through to ``importorskip`` on every run). ``importorskip``
is the documented primitive for a local, kit-less checkout (a dev who skipped the
``[dev]`` extra); in CI the kit is a mandatory pinned dep, and the whole-module-skip
class is caught by ``test_conformance_meta_guard.py``.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# The published wheel ships the PEP 420 namespace ``agent_suite.conformance``.
# importorskip keeps a kit-less local checkout (no [dev] extra) from hard-erroring;
# CI installs the pinned kit, and test_conformance_meta_guard.py proves the gate
# ran (not skipped) so importorskip firing there reddens the build (WI-026).
conformance = pytest.importorskip("agent_suite.conformance")

BrokenPipeCase = conformance.BrokenPipeCase
ErrorCase = conformance.ErrorCase
SuccessCase = conformance.SuccessCase
UsageCase = conformance.UsageCase
assert_cases_declared = conformance.assert_cases_declared
run_broken_pipe_case = conformance.run_broken_pipe_case
run_error_case = conformance.run_error_case
run_success_case = conformance.run_success_case
run_usage_case = conformance.run_usage_case

# `python -m cairn` invokes the *bridge*, not the CLI; the CLI is the `cairn`
# console script installed next to this interpreter.
_CAIRN = str(Path(sys.executable).parent / ("cairn.exe" if os.name == "nt" else "cairn"))

# Fixtures for the ErrorCase: files that exist (so click.Path(exists=True)
# passes) but hold malformed content (so the key loader raises an operational
# ClickException). Created once at import.
_TMP = tempfile.mkdtemp(prefix="cairn-conformance-")
_GARBAGE_KEYS = os.path.join(_TMP, "keys.json")
_GARBAGE_BUNDLE = os.path.join(_TMP, "bundle.json")
Path(_GARBAGE_KEYS).write_text("not json\n")
Path(_GARBAGE_BUNDLE).write_text("not json\n")

# An empty HOME so the success/broken-pipe probes read no real cairn config and
# plan into a throwaway directory (hermetic regardless of the operator's box).
_EMPTY_HOME = tempfile.mkdtemp(prefix="cairn-conformance-home-")

# Inherited operator config to strip from the success probe. The kit merges
# os.environ into the case env before spawning the CLI, so on a dogfooding box a
# live CAIRN_*/REGISTA_* var (or AGENT_SUITE_CONFIG) could perturb the dry-run
# plan or its exit code. Capture only what is actually present at import (minimal,
# not a hardcoded mega-list) and unset it, so the success case stays hermetic.
# (In the source-checkout lane the conftest autouse fixture already clears these;
# this is belt-and-suspenders that also covers the conftest-less wheel lane.)
_INHERITED_CONFIG_ENV = tuple(
    name
    for name in os.environ
    if name.startswith(("CAIRN_", "REGISTA_")) or name == "AGENT_SUITE_CONFIG"
)


SUCCESS_CASES = [
    # Contract §2 (WI-021): a --dry-run that prints its plan exits 0. The output
    # is a JSON array of per-harness plan results — a single valid JSON document.
    SuccessCase(
        name="install-harness-claude-dry-run-json",
        argv=(_CAIRN, "install-harness", "claude", "--dry-run", "--json"),
        env={"HOME": _EMPTY_HOME},
        unset_env=_INHERITED_CONFIG_ENV,
    ),
]

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

# WI-026 meta-guard (shipped by kit 1.1.0): fail collection loudly if any contract
# dimension empties. A zero-case dimension enforces nothing and — because this
# module is the kit-importing surface — would be indistinguishable from a pass in
# green CI. (The whole-module-skip class is covered by test_conformance_meta_guard.py.)
assert_cases_declared(
    minimum=1,
    success=SUCCESS_CASES,
    error=ERROR_CASES,
    usage=USAGE_CASES,
    broken_pipe=BROKEN_PIPE_CASES,
)


@pytest.mark.parametrize("case", SUCCESS_CASES, ids=lambda c: c.name)
def test_success_conformance(case: SuccessCase) -> None:
    assert run_success_case(case) == []


@pytest.mark.parametrize("case", ERROR_CASES, ids=lambda c: c.name)
def test_error_conformance(case: ErrorCase) -> None:
    assert run_error_case(case) == []


@pytest.mark.parametrize("case", USAGE_CASES, ids=lambda c: c.name)
def test_usage_conformance(case: UsageCase) -> None:
    assert run_usage_case(case) == []


@pytest.mark.parametrize("case", BROKEN_PIPE_CASES, ids=lambda c: c.name)
def test_broken_pipe_conformance(case: BrokenPipeCase) -> None:
    assert run_broken_pipe_case(case) == []
