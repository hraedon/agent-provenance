"""The observed-model invariant probe, and the gate contract it has to satisfy.

The behavioral tests below check that the probe measures the right thing. The
``test_genesis_gate_contract_*`` tests check something different and easy to
break by accident: the probe's *report shape* is consumed across a repo
boundary by agent-suite's pre-genesis admission gate
(``agent_suite/genesis_gate.py``, ``PROBE_SPECS`` +
``_parse_probe_result``), which validates it strictly and fail-closed. A
rename, an extra print to stdout, a ``probe_version`` bump, or a stray exit
code reddens the suite gate — in another repo, where cairn's own CI would not
see it. The constants here are a deliberate in-repo mirror of that consumer's
requirements so the coupling breaks loudly at cairn's test time instead.

Mirrored from agent-suite (verified against it 2026-08-20, WI-045):

- ``PROBE_SPECS`` entry ``component="cairn"``, command
  ``("cairn", "invariants", "probe", "--json")``, the three required check ids,
  and ``preflight_capability=True`` (so ``schedule install`` runs the
  ``--help`` parser check below).
- ``PROBE_REPORT_VERSION == 1``, ``_PROBE_CHECK_STATUSES``, the
  ``component``/``ok``/``probe_version`` type rules, cairn-prefixed and unique
  non-empty check ids, required checks at status ``pass``, exit code in
  ``(0, 1)`` and ``(exit == 0) == ok``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from cairn._invariant_probe import (
    evaluate_runtime_dispatch,
    evaluate_unavailable_observation,
    invariant_probe_report,
)

#: agent-suite ``genesis_gate.PROBE_REPORT_VERSION``. Bumping the probe's
#: ``probe_version`` without landing the matching bump there fails the gate
#: closed ("unsupported or missing probe_version").
GATE_PROBE_REPORT_VERSION = 1

#: agent-suite ``genesis_gate.PROBE_SPECS[cairn].required_checks``. These ids
#: are frozen: the gate looks them up by exact string and treats a missing id
#: as malformed. Renaming one is a cross-repo breaking change.
GATE_REQUIRED_CHECK_IDS = frozenset(
    {
        "cairn.runtime_model_observed",
        "cairn.unavailable_model_named",
        "cairn.observation_failure_nonblocking",
    }
)

#: agent-suite ``genesis_gate._PROBE_CHECK_STATUSES``.
GATE_CHECK_STATUSES = frozenset({"pass", "measured", "fail"})

#: agent-suite ``genesis_gate.PROBE_SPECS[cairn].command``.
GATE_PROBE_COMMAND = ("cairn", "invariants", "probe", "--json")

#: agent-suite ``schedule._help_exposes_invariant_probe``: the usage line must
#: name the executable immediately followed by ``invariants probe``. Prose that
#: merely mentions the phrase is not accepted.
GATE_HELP_USAGE_PATTERN = (
    r"\busage:\s+(?:\S*[/\\])?" + re.escape("cairn") + r"\s+invariants\s+probe(?:\s|\[)"
)

# `python -m cairn` invokes the *bridge*, not the CLI; the CLI is the `cairn`
# console script installed next to this interpreter (same resolution as
# tests/test_cli_conformance.py).
_CAIRN = Path(sys.executable).parent / "cairn"

requires_console_script = pytest.mark.skipif(
    not _CAIRN.is_file(),
    reason=f"cairn console script not installed at {_CAIRN} (needs `pip install -e .`)",
)


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke the installed console script with operator config stripped.

    The gate invokes ``cairn`` from PATH on a live box, so this exercises the
    real entry point, real stream separation and the real exit code rather than
    an in-process click runner.
    """
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("CAIRN_", "REGISTA_")) and name != "AGENT_SUITE_CONFIG"
    }
    return subprocess.run(
        [str(_CAIRN), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_genesis_gate_contract_report_shape() -> None:
    """The in-process report satisfies every structural rule the gate applies."""
    report = invariant_probe_report()

    assert report["component"] == "cairn"
    assert isinstance(report["ok"], bool)
    # `type(...) is int` on purpose: the gate rejects bool (a subclass of int)
    # and float, so `isinstance(..., int)` would be a weaker assertion than the
    # consumer's own check.
    assert type(report["probe_version"]) is int
    assert report["probe_version"] == GATE_PROBE_REPORT_VERSION

    checks = report["checks"]
    assert isinstance(checks, list)
    assert all(isinstance(check, dict) for check in checks)

    ids = [check["id"] for check in checks]
    assert all(isinstance(check_id, str) and check_id.strip() for check_id in ids)
    assert len(set(ids)) == len(checks), f"duplicate check ids: {ids}"
    # The gate rejects a probe that emits checks owned by another component.
    assert all(check_id.startswith("cairn.") for check_id in ids), ids
    assert GATE_REQUIRED_CHECK_IDS.issubset(set(ids)), sorted(GATE_REQUIRED_CHECK_IDS - set(ids))
    assert all(check["status"] in GATE_CHECK_STATUSES for check in checks)

    by_id = {check["id"]: check for check in checks}
    for check_id in sorted(GATE_REQUIRED_CHECK_IDS):
        # cairn has no "measured"-status required check (only regista's
        # store_invariant_measurements is exempted), so a required check that
        # is not "pass" is a gate failure whenever the report claims ok.
        assert by_id[check_id]["status"] == "pass", check_id

    assert report["ok"] is (all(check["status"] == "pass" for check in checks))


@requires_console_script
def test_genesis_gate_contract_cli_stdout_is_one_json_object() -> None:
    """Stdout carries the report and nothing else; logs go to stderr."""
    completed = _run_cli(*GATE_PROBE_COMMAND[1:])

    # json.loads is the gate's own parse; it fails on a log line, a banner, or
    # two concatenated documents.
    body = json.loads(completed.stdout)
    assert isinstance(body, dict)
    assert body["component"] == "cairn"
    assert type(body["probe_version"]) is int
    assert body["probe_version"] == GATE_PROBE_REPORT_VERSION
    assert isinstance(body["ok"], bool)
    assert {check["id"] for check in body["checks"]} >= GATE_REQUIRED_CHECK_IDS

    # structlog is configured onto stderr precisely so this holds.
    assert "cairn.model_observation" not in completed.stdout


@requires_console_script
def test_genesis_gate_contract_cli_exit_code_agrees_with_ok() -> None:
    """Exit code is 0 or 1 and agrees with the report's own verdict."""
    completed = _run_cli(*GATE_PROBE_COMMAND[1:])

    assert completed.returncode in (0, 1), completed.returncode
    body = json.loads(completed.stdout)
    # The gate downgrades to FAIL when the process and the report disagree,
    # even if every check passed.
    assert (completed.returncode == 0) is body["ok"]


@requires_console_script
def test_genesis_gate_contract_help_exposes_the_probe_to_preflight() -> None:
    """`schedule install`'s parser-only preflight can see the command.

    cairn's ProbeSpec leaves ``preflight_capability`` at its default True, so a
    usage line the matcher does not recognize blocks installing the probe
    schedule — separately from the probe ever running.
    """
    completed = _run_cli("invariants", "probe", "--help")

    assert completed.returncode == 0, completed.stderr
    # Both streams, because the matcher considers both.
    normalized = " ".join(f"{completed.stdout}\n{completed.stderr}".split()).lower()
    assert re.search(GATE_HELP_USAGE_PATTERN, normalized), normalized[:400]


def test_behavioral_probe_passes() -> None:
    report = invariant_probe_report()

    assert report["ok"] is True
    assert {check["status"] for check in report["checks"]} == {"pass"}


def test_runtime_dispatch_probe_fails_on_requested_model_laundering() -> None:
    check = evaluate_runtime_dispatch(
        {
            "observed_provider_id": "provider-a",
            "observed_model_id": "nemotron-3-ultra",
            "observed_model_lineage": "nemotron",
            "requested_provider_id": "provider-a",
            "requested_model_id": "nemotron-3-ultra",
            "declared_model_lineage": "nemotron",
            "status": "matched",
        }
    )

    assert check["status"] == "fail"


def test_unavailable_probe_fails_if_missing_model_reads_as_observed() -> None:
    check = evaluate_unavailable_observation(
        {
            "status": "observed",
            "observed_model_id": None,
            "observed_model_lineage": None,
        }
    )

    assert check["status"] == "fail"
