"""Live proof logic for session-bound provenance verification.

Extracted from ``scripts/e2e_proof.py`` (Plan 009 WI-2.2, finding F-2) so the
proof logic is testable without a live harness or Postgres.  The script queries
the store, constructs :class:`ProofEvent` rows, and calls :func:`run_proof`;
the tests construct :class:`ProofEvent` rows directly and assert that each
negative scenario produces a failure.

The chain-integrity check delegates to :class:`cairn.verifier.Verifier` (the
canonical verifier) rather than counting NULL predecessor hashes in SQL.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cairn.verifier_types import VerificationReport


@dataclass(frozen=True)
class ProofEvent:
    """Simplified event representation for proof logic.

    Carries only the fields the proof needs — the script builds these from
    SQL rows, the tests build them directly.  Full :class:`regista._types.Event`
    objects (with signatures, canonical envelopes) are only needed by the
    canonical verifier, which runs separately.
    """

    transition: str | None
    global_seq: int | None
    entity_id: str
    entity_kind: str = "work_item"
    payload: dict[str, Any] | None = None
    on_behalf_of: dict[str, Any] | None = None


@dataclass(frozen=True)
class ProofFailure:
    check: str
    detail: str


@dataclass
class ProofResult:
    passed: bool
    failures: list[ProofFailure] = field(default_factory=list)
    session_entity_id: str | None = None
    tool_call_events: list[ProofEvent] = field(default_factory=list)


def _has_correlated_file_path(
    tool_end_events: list[ProofEvent],
    expected_file_name: str,
) -> bool:
    """Return True if any tool_call_end event has a file path whose basename
    matches *expected_file_name* exactly.

    Checks both ``payload.files[].path`` and
    ``payload.tool_args_redacted.file_paths``.  An exact basename match
    (not a substring) prevents a different file that merely contains the
    correlation marker from satisfying the proof (B4).
    """
    for ev in tool_end_events:
        payload = ev.payload or {}
        files = payload.get("files") or []
        for f in files:
            path = f.get("path", "")
            if path and Path(path).name == expected_file_name:
                return True
        redacted = payload.get("tool_args_redacted") or {}
        for path in redacted.get("file_paths", []):
            if path and Path(path).name == expected_file_name:
                return True
    return False


def find_session_attestation(
    events: list[ProofEvent],
    baseline_seq: int,
    expected_file_name: str,
) -> str | None:
    """Return the entity_id of the first *correlated* session_attestation
    after baseline.

    A session is "correlated" when at least one of its ``tool_call_end``
    events (after baseline) references a file path whose basename matches
    *expected_file_name*.  This binds the proof to the specific session the
    script launched, not just any session that started after the baseline
    (B1).

    Returns ``None`` when no correlated session_attestation event has
    ``global_seq > baseline_seq``.  When multiple correlated sessions
    exist, the one with the smallest ``global_seq`` wins (the earliest
    new session).
    """
    candidates = [
        ev
        for ev in events
        if ev.transition == "session_attestation"
        # "note" is the v6 entity kind for session-scoped events (regista
        # 0.7's closed registry); "session" is the pre-v6 spelling, still
        # read for historical stores.
        and ev.entity_kind in ("session", "note")
        and ev.global_seq is not None
        and ev.global_seq > baseline_seq
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda e: e.global_seq or 0)
    for candidate in candidates:
        tool_events = find_tool_call_ends(
            events, candidate.entity_id, baseline_seq
        )
        if _has_correlated_file_path(tool_events, expected_file_name):
            return candidate.entity_id
    return None


def find_tool_call_ends(
    events: list[ProofEvent],
    session_entity_id: str,
    baseline_seq: int,
) -> list[ProofEvent]:
    """Return tool_call_end events bound to *session_entity_id* after baseline.

    Binding is via the delegation context naming the session, read through
    the one shared carrier helper (:func:`cairn.schema.delegation_chain_of`):
    pre-v6 rows carry it as the writer-level ``on_behalf_of``; v6 rows carry
    it inside the signed payload. Events at or before the baseline sequence
    are excluded so stale activity cannot satisfy the proof.
    """
    from cairn.schema import delegation_chain_of

    result: list[ProofEvent] = []
    for ev in events:
        if ev.transition != "tool_call_end":
            continue
        if ev.global_seq is None or ev.global_seq <= baseline_seq:
            continue
        obo = delegation_chain_of(ev) or {}
        if obo.get("session_id") == session_entity_id:
            result.append(ev)
    return result


def verify_harness_version(
    events: list[ProofEvent],
    session_entity_id: str,
    expected_version: str,
) -> list[ProofFailure]:
    """Verify the session attestation carries the real harness version."""
    failures: list[ProofFailure] = []
    for ev in events:
        if ev.transition != "session_attestation":
            continue
        if ev.entity_id != session_entity_id:
            continue
        payload = ev.payload or {}
        harnesses = payload.get("harnesses", [])
        if not harnesses:
            failures.append(
                ProofFailure(
                    check="harness_version",
                    detail="session_attestation has no harnesses",
                )
            )
            continue
        attested_hv = harnesses[0].get("version", "unknown")
        if attested_hv == "unknown" or attested_hv != expected_version:
            failures.append(
                ProofFailure(
                    check="harness_version",
                    detail=f"attested={attested_hv}, expected={expected_version}",
                )
            )
    return failures


def verify_digests(
    tool_end_events: list[ProofEvent],
    expected_outputs: dict[str, str],
) -> list[ProofFailure]:
    """Verify attested digests match independently computed sha256.

    *expected_outputs* maps tool name (``"Read"``, ``"Bash"``) to the real
    output string whose sha256 hex digest should appear in the event's
    ``result_summary.stdout_digest``.
    """
    failures: list[ProofFailure] = []
    found: set[str] = set()
    for ev in tool_end_events:
        payload = ev.payload or {}
        tool = payload.get("tool", "")
        if tool not in expected_outputs:
            continue
        found.add(tool)
        rs = payload.get("result_summary", {})
        digest = rs.get("stdout_digest", "")
        expected = hashlib.sha256(
            expected_outputs[tool].encode("utf-8")
        ).hexdigest()
        if digest != expected:
            failures.append(
                ProofFailure(
                    check="digest",
                    detail=f"{tool}: attested={digest}, expected={expected}",
                )
            )
    for tool in expected_outputs:
        if tool not in found:
            failures.append(
                ProofFailure(
                    check="digest",
                    detail=f"no {tool} tool_call_end event found for this session",
                )
            )
    return failures


def verify_correlation(
    tool_end_events: list[ProofEvent],
    expected_file_name: str,
) -> list[ProofFailure]:
    """Verify tool_call_end events reference the expected file.

    At least one event must have a file path whose basename matches
    *expected_file_name* exactly — either in ``payload.files[].path`` or
    in ``payload.tool_args_redacted.file_paths``.  An exact basename match
    (not a substring) prevents a different file that merely contains the
    correlation marker from satisfying the proof (B4).
    """
    if _has_correlated_file_path(tool_end_events, expected_file_name):
        return []
    return [
        ProofFailure(
            check="correlation",
            detail=(
                f"no tool_call_end event references expected file "
                f"{expected_file_name}"
            ),
        )
    ]


def verify_chain_integrity(report: VerificationReport) -> list[ProofFailure]:
    """Check the canonical verifier's report for chain integrity."""
    failures: list[ProofFailure] = []
    if report.signature_failed > 0:
        failures.append(
            ProofFailure(
                check="chain",
                detail=f"{report.signature_failed} signature failure(s)",
            )
        )
    if report.hash_mismatch > 0:
        failures.append(
            ProofFailure(
                check="chain",
                detail=f"{report.hash_mismatch} hash mismatch(es)",
            )
        )
    if report.chain_contiguity_violations:
        kinds = [v.kind for v in report.chain_contiguity_violations]
        failures.append(
            ProofFailure(
                check="chain",
                detail=(
                    f"{len(report.chain_contiguity_violations)} chain "
                    f"contiguity violation(s): {kinds}"
                ),
            )
        )
    if not report.all_ok:
        failures.append(
            ProofFailure(
                check="chain",
                detail="canonical verifier report: not all_ok",
            )
        )
    return failures


def run_proof(
    events: list[ProofEvent],
    baseline_seq: int,
    expected_harness_version: str,
    expected_outputs: dict[str, str],
    expected_file_name: str,
    verifier_report: VerificationReport | None = None,
) -> ProofResult:
    """Run the full proof logic against a list of events.

    This is the testable core extracted from the e2e_proof script.  The script
    queries the store, builds :class:`ProofEvent` rows, and calls this; the
    tests build rows directly and assert failures.

    *expected_file_name* is the basename of the test file the script created
    (e.g. ``"{correlation_id}.txt"``).  It is used both to bind the proof to
    the launched session (B1) and to verify the correlation marker (B4).
    """
    failures: list[ProofFailure] = []

    session_entity_id = find_session_attestation(
        events, baseline_seq, expected_file_name
    )
    if session_entity_id is None:
        failures.append(
            ProofFailure(
                check="session_binding",
                detail=(
                    "no session_attestation after baseline is correlated "
                    "to the launched session"
                ),
            )
        )
        return ProofResult(passed=False, failures=failures)

    failures.extend(
        verify_harness_version(events, session_entity_id, expected_harness_version)
    )

    tool_events = find_tool_call_ends(events, session_entity_id, baseline_seq)
    if not tool_events:
        failures.append(
            ProofFailure(
                check="tool_calls",
                detail=(
                    "no tool_call_end events found for this session "
                    "after baseline"
                ),
            )
        )

    failures.extend(verify_digests(tool_events, expected_outputs))
    failures.extend(verify_correlation(tool_events, expected_file_name))

    if verifier_report is not None:
        failures.extend(verify_chain_integrity(verifier_report))

    return ProofResult(
        passed=len(failures) == 0,
        failures=failures,
        session_entity_id=session_entity_id,
        tool_call_events=tool_events,
    )
