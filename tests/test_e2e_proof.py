"""Negative tests for the live e2e proof logic (Plan 009 WI-2.2, finding F-2).

Each test verifies that the proof FAILS under a specific adversarial
condition.  These tests do not require a live harness or Postgres — they
construct :class:`cairn.proof.ProofEvent` rows (and, for chain-integrity
tests, full signed :class:`regista._types.Event` objects) directly.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cairn.proof import (
    ProofEvent,
    find_session_attestation,
    find_tool_call_ends,
    run_proof,
    verify_chain_integrity,
    verify_correlation,
)
from cairn.verifier import Verifier
from cairn.verifier_types import VerificationReport

KEY_ID = "cairn-test-001"
KEY_SECRET = b"supersecret-test-key-32bytes!!"


def _make_session_attestation(
    session_id: str,
    global_seq: int,
    harness_version: str = "2.1.200",
    entity_kind: str = "session",
) -> ProofEvent:
    return ProofEvent(
        transition="session_attestation",
        global_seq=global_seq,
        entity_id=session_id,
        entity_kind=entity_kind,
        payload={
            "version": "1",
            "principal_id": "human:test",
            "session_id": session_id,
            "attested_at": "2026-07-10T12:00:00Z",
            "harnesses": [{"name": "claude", "version": harness_version}],
            "scope_statement": "In scope: claude.",
        },
        on_behalf_of={"principal_id": "human:test", "session_id": session_id},
    )


def _make_tool_call_end(
    session_id: str,
    global_seq: int,
    tool: str = "Read",
    stdout_digest: str | None = None,
    file_paths: list[str] | None = None,
    work_item_id: str | None = None,
) -> ProofEvent:
    payload: dict[str, Any] = {
        "tool": tool,
        "tool_args_hash": "sha256:abc",
        "harness": {"name": "claude", "version": "2.1.200"},
    }
    if stdout_digest is not None:
        payload["result_summary"] = {"stdout_digest": stdout_digest}
    if file_paths:
        payload["files"] = [{"path": p} for p in file_paths]
        payload["tool_args_redacted"] = {"tool": tool, "file_paths": file_paths}
    return ProofEvent(
        transition="tool_call_end",
        global_seq=global_seq,
        entity_id=work_item_id or str(uuid.uuid4()),
        entity_kind="work_item",
        payload=payload,
        on_behalf_of={"principal_id": "human:test", "session_id": session_id},
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _make_signed_event(
    transition: str,
    payload: dict[str, Any],
    *,
    event_seq: int = 0,
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
    prev_event_hash: bytes | None = None,
    entity_kind: str = "work_item",
    on_behalf_of: dict[str, Any] | None = None,
    work_item_id: uuid.UUID | None = None,
) -> Any:
    from regista._signing import sign_event
    from regista._types import Event

    ev_id = uuid.uuid4()
    wi_id = work_item_id or uuid.uuid4()
    now = datetime.now(UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="agent-1",
        key_id=KEY_ID,
        event_seq=event_seq,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition=transition,
        payload=payload,
        key=KEY_SECRET,
        on_behalf_of=on_behalf_of,
        prev_event_hash=prev_event_hash,
        global_seq=global_seq,
        prev_global_event_hash=prev_global_event_hash,
        entity_kind=entity_kind,
    )
    return Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=event_seq,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id=KEY_ID,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition=transition,
        payload=payload,
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
        prev_event_hash=prev_event_hash,
        global_seq=global_seq,
        prev_global_event_hash=prev_global_event_hash,
        entity_kind=entity_kind,
        on_behalf_of=on_behalf_of,
    )


def _build_passing_events(
    session_id: str,
    baseline_seq: int,
    correlation_id: str,
    file_content: str,
    bash_output: str,
) -> list[ProofEvent]:
    """Build the event set that a successful proof session would produce."""
    seq = baseline_seq + 1
    events: list[ProofEvent] = [
        _make_session_attestation(session_id, seq),
    ]
    seq += 1
    events.append(
        _make_tool_call_end(
            session_id,
            seq,
            tool="Read",
            stdout_digest=_sha256(file_content),
            file_paths=[f"/tmp/proof/{correlation_id}.txt"],
        )
    )
    seq += 1
    events.append(
        _make_tool_call_end(
            session_id,
            seq,
            tool="Bash",
            stdout_digest=_sha256(bash_output),
        )
    )
    return events


# ----------------------------------------------------------------------
# 1. Concurrent decoy session
# ----------------------------------------------------------------------


def test_concurrent_decoy_session_does_not_satisfy_proof() -> None:
    """A concurrent decoy session with its own tool calls must not satisfy the proof.

    With session binding (B1), the decoy session is not selected because its
    tool calls don't reference the expected file.  The proof fails at
    session_binding.
    """
    decoy_session = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    real_content = "real file content"
    baseline = 100

    events: list[ProofEvent] = [
        _make_session_attestation(decoy_session, baseline + 1),
        _make_tool_call_end(
            decoy_session,
            baseline + 2,
            tool="Read",
            stdout_digest=_sha256("decoy content"),
            file_paths=["/tmp/other.txt"],
        ),
        _make_tool_call_end(
            decoy_session,
            baseline + 3,
            tool="Bash",
            stdout_digest=_sha256("decoy output"),
        ),
    ]

    found = find_session_attestation(events, baseline, f"{correlation_id}.txt")
    assert found is None

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": real_content, "Bash": correlation_id},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert not result.passed
    assert any(f.check == "session_binding" for f in result.failures)


def test_real_session_found_among_decoys() -> None:
    """When the real session's attestation comes first, the proof passes even
    if a decoy session exists later."""
    real_session = str(uuid.uuid4())
    decoy_session = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = f"proof {correlation_id}"
    bash_output = correlation_id
    baseline = 100

    events = _build_passing_events(
        real_session, baseline, correlation_id, file_content, bash_output
    )
    events.append(_make_session_attestation(decoy_session, baseline + 4))
    events.append(
        _make_tool_call_end(
            decoy_session,
            baseline + 5,
            tool="Read",
            stdout_digest=_sha256("decoy"),
        )
    )

    found = find_session_attestation(events, baseline, f"{correlation_id}.txt")
    assert found == real_session

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert result.passed


def test_decoy_tool_calls_not_bound_to_real_session() -> None:
    """Tool calls from a decoy session are not found when querying the real session."""
    real_session = str(uuid.uuid4())
    decoy_session = str(uuid.uuid4())
    baseline = 100

    events: list[ProofEvent] = [
        _make_session_attestation(real_session, baseline + 1),
        _make_tool_call_end(
            decoy_session,
            baseline + 2,
            tool="Read",
            stdout_digest=_sha256("decoy"),
        ),
    ]

    real_tools = find_tool_call_ends(events, real_session, baseline)
    decoy_tools = find_tool_call_ends(events, decoy_session, baseline)
    assert len(real_tools) == 0
    assert len(decoy_tools) == 1


# ----------------------------------------------------------------------
# 2. Stale matching events
# ----------------------------------------------------------------------


def test_stale_events_before_baseline_not_picked_up() -> None:
    """Old tool_call_end events with the same harness version must not satisfy the proof.

    Events at or before the baseline sequence are excluded.  With session
    binding (B1), a session whose only tool calls are before baseline is
    not selected at all — the proof fails at session_binding.
    """
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = "proof content"
    bash_output = correlation_id
    baseline = 100

    stale_read = _make_tool_call_end(
        session_id,
        global_seq=50,
        tool="Read",
        stdout_digest=_sha256(file_content),
        file_paths=[f"/tmp/proof/{correlation_id}.txt"],
    )
    stale_bash = _make_tool_call_end(
        session_id,
        global_seq=51,
        tool="Bash",
        stdout_digest=_sha256(bash_output),
    )

    events: list[ProofEvent] = [
        stale_read,
        stale_bash,
        _make_session_attestation(session_id, baseline + 1),
    ]

    tool_events = find_tool_call_ends(events, session_id, baseline)
    assert len(tool_events) == 0, "stale events before baseline must be excluded"

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert not result.passed
    assert any(f.check == "session_binding" for f in result.failures)


def test_stale_session_attestation_before_baseline_ignored() -> None:
    """A session_attestation at or before baseline must not be picked up."""
    session_id = str(uuid.uuid4())
    baseline = 100

    stale_attestation = _make_session_attestation(session_id, global_seq=50)

    found = find_session_attestation(
        [stale_attestation], baseline, f"{uuid.uuid4()}.txt"
    )
    assert found is None


# ----------------------------------------------------------------------
# 3. Mutated hash — canonical verifier detects corruption
# ----------------------------------------------------------------------


def test_mutated_prev_global_event_hash_detected(hmac_keys: Path) -> None:
    """A corrupted prev_global_event_hash is detected by the canonical verifier."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    wi_id = uuid.uuid4()

    ev1 = _make_signed_event(
        "tool_call_begin",
        {"tool": "Read", "tool_args_hash": "sha256:abc"},
        event_seq=0,
        global_seq=1,
        work_item_id=wi_id,
    )

    import hashlib as _hl

    real_prev_hash = _hl.sha256(
        bytes(ev1.canonical_envelope or b"") + bytes(ev1.signature)
    ).digest()
    corrupted_hash = bytes(b ^ 0xFF for b in real_prev_hash[:1]) + real_prev_hash[1:]

    ev2 = _make_signed_event(
        "tool_call_end",
        {"tool": "Read", "tool_args_hash": "sha256:abc"},
        event_seq=1,
        global_seq=2,
        prev_global_event_hash=corrupted_hash,
        work_item_id=wi_id,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([ev1, ev2])
    assert not report.all_ok
    assert len(report.chain_contiguity_violations) > 0

    failures = verify_chain_integrity(report)
    assert len(failures) > 0
    assert any(f.check == "chain" for f in failures)


# ----------------------------------------------------------------------
# 4. Missing event — canonical verifier detects the gap
# ----------------------------------------------------------------------


def test_missing_event_detected(hmac_keys: Path) -> None:
    """A deleted event in the chain is detected by the canonical verifier."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    wi_id = uuid.uuid4()

    ev0 = _make_signed_event(
        "tool_call_begin",
        {"tool": "Read", "tool_args_hash": "sha256:0"},
        event_seq=0,
        global_seq=1,
        work_item_id=wi_id,
    )
    ev1 = _make_signed_event(
        "tool_call_begin",
        {"tool": "Read", "tool_args_hash": "sha256:1"},
        event_seq=1,
        global_seq=2,
        work_item_id=wi_id,
    )
    ev2 = _make_signed_event(
        "tool_call_end",
        {"tool": "Read", "tool_args_hash": "sha256:1"},
        event_seq=2,
        global_seq=3,
        work_item_id=wi_id,
    )

    verifier = Verifier(key_set)
    report_full = verifier.verify_events([ev0, ev1, ev2])
    assert len(report_full.sequence_gaps) == 0

    report_missing = verifier.verify_events([ev0, ev2])
    assert len(report_missing.sequence_gaps) == 1
    assert report_missing.sequence_gaps[0].kind == "missing_seq"
    assert not report_missing.all_ok

    failures = verify_chain_integrity(report_missing)
    assert len(failures) > 0


# ----------------------------------------------------------------------
# 5. Wrong digest — proof detects mismatch
# ----------------------------------------------------------------------


def test_wrong_digest_detected() -> None:
    """An attested digest that doesn't match the real output is caught."""
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    real_content = "real file content"
    wrong_content = "tampered content"
    baseline = 100

    events: list[ProofEvent] = [
        _make_session_attestation(session_id, baseline + 1),
        _make_tool_call_end(
            session_id,
            baseline + 2,
            tool="Read",
            stdout_digest=_sha256(wrong_content),
            file_paths=[f"/tmp/proof/{correlation_id}.txt"],
        ),
        _make_tool_call_end(
            session_id,
            baseline + 3,
            tool="Bash",
            stdout_digest=_sha256(correlation_id),
        ),
    ]

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": real_content, "Bash": correlation_id},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert not result.passed
    digest_failures = [f for f in result.failures if f.check == "digest"]
    assert len(digest_failures) == 1
    assert "Read" in digest_failures[0].detail


def test_missing_tool_call_detected() -> None:
    """A missing tool_call_end event for an expected tool is caught."""
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = "proof content"
    baseline = 100

    events: list[ProofEvent] = [
        _make_session_attestation(session_id, baseline + 1),
        _make_tool_call_end(
            session_id,
            baseline + 2,
            tool="Read",
            stdout_digest=_sha256(file_content),
            file_paths=[f"/tmp/proof/{correlation_id}.txt"],
        ),
    ]

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": correlation_id},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert not result.passed
    assert any(
        f.check == "digest" and "Bash" in f.detail for f in result.failures
    )


# ----------------------------------------------------------------------
# 6. Unavailable store — proof fails with a clear error
# ----------------------------------------------------------------------


def test_empty_events_fails_clearly() -> None:
    """When the store is unreachable (no events), the proof fails clearly."""
    correlation_id = str(uuid.uuid4())
    result = run_proof(
        events=[],
        baseline_seq=0,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": "content", "Bash": "output"},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert not result.passed
    assert any(
        f.check == "session_binding" and "no session_attestation" in f.detail
        for f in result.failures
    )


def test_no_session_after_baseline_fails() -> None:
    """Events exist but no session_attestation after baseline → clear failure."""
    session_id = str(uuid.uuid4())
    baseline = 100

    events: list[ProofEvent] = [
        _make_session_attestation(session_id, global_seq=50),
        _make_tool_call_end(
            session_id,
            global_seq=51,
            tool="Read",
            stdout_digest=_sha256("content"),
        ),
    ]

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": "content"},
        expected_file_name=f"{uuid.uuid4()}.txt",
    )
    assert not result.passed
    assert any(f.check == "session_binding" for f in result.failures)


# ----------------------------------------------------------------------
# Correlation marker tests
# ----------------------------------------------------------------------


def test_correlation_marker_not_referenced_fails() -> None:
    """Tool calls that don't reference the expected file fail the proof.

    With session binding (B1), a session whose tool calls reference a
    different file is not selected at all — the proof fails at
    session_binding.
    """
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    different_id = str(uuid.uuid4())
    file_content = "proof content"
    baseline = 100

    events: list[ProofEvent] = [
        _make_session_attestation(session_id, baseline + 1),
        _make_tool_call_end(
            session_id,
            baseline + 2,
            tool="Read",
            stdout_digest=_sha256(file_content),
            file_paths=[f"/tmp/proof/{different_id}.txt"],
        ),
        _make_tool_call_end(
            session_id,
            baseline + 3,
            tool="Bash",
            stdout_digest=_sha256(correlation_id),
        ),
    ]

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": correlation_id},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert not result.passed
    assert any(f.check == "session_binding" for f in result.failures)


def test_correlation_marker_in_file_path_passes() -> None:
    """Tool calls referencing the correlation marker in file paths pass."""
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = "proof content"
    bash_output = correlation_id
    baseline = 100

    events = _build_passing_events(
        session_id, baseline, correlation_id, file_content, bash_output
    )

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert result.passed
    assert result.session_entity_id == session_id


# ----------------------------------------------------------------------
# Happy path — all checks pass
# ----------------------------------------------------------------------


def test_happy_path_passes() -> None:
    """A well-formed event set with correct digests and correlation passes."""
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = f"cairn e2e proof {correlation_id}\n"
    bash_output = correlation_id
    baseline = 100

    events = _build_passing_events(
        session_id, baseline, correlation_id, file_content, bash_output
    )

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert result.passed
    assert len(result.failures) == 0
    assert result.session_entity_id == session_id
    assert len(result.tool_call_events) == 2


# ----------------------------------------------------------------------
# Harness version tests
# ----------------------------------------------------------------------


def test_unknown_harness_version_fails() -> None:
    """An attested harness version of 'unknown' fails the proof."""
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = "proof content"
    bash_output = correlation_id
    baseline = 100

    events: list[ProofEvent] = [
        _make_session_attestation(session_id, baseline + 1, harness_version="unknown"),
    ]
    events.extend(
        _build_passing_events(
            session_id, baseline + 1, correlation_id, file_content, bash_output
        )
    )

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert not result.passed
    assert any(f.check == "harness_version" for f in result.failures)


def test_wrong_harness_version_fails() -> None:
    """An attested harness version that doesn't match the expected fails."""
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = "proof content"
    bash_output = correlation_id
    baseline = 100

    events: list[ProofEvent] = [
        _make_session_attestation(session_id, baseline + 1, harness_version="1.0.42"),
    ]
    events.extend(
        _build_passing_events(
            session_id, baseline + 1, correlation_id, file_content, bash_output
        )
    )

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert not result.passed
    assert any(f.check == "harness_version" for f in result.failures)


# ----------------------------------------------------------------------
# Chain integrity via canonical verifier
# ----------------------------------------------------------------------


def test_chain_integrity_clean_report_passes() -> None:
    """A clean VerificationReport produces no chain failures."""
    report = VerificationReport()
    report.signature_failed = 0
    report.hash_mismatch = 0
    report.chain_contiguity_violations = []
    report.bundle_hash_ok = True
    report.chain_integrity_ok = None

    failures = verify_chain_integrity(report)
    assert len(failures) == 0


def test_chain_integrity_signature_failure_detected() -> None:
    """A signature failure in the verifier report is surfaced."""
    report = VerificationReport()
    report.signature_failed = 1

    failures = verify_chain_integrity(report)
    assert len(failures) > 0
    assert any("signature" in f.detail for f in failures)


def test_chain_integrity_hash_mismatch_detected() -> None:
    """A hash mismatch in the verifier report is surfaced."""
    report = VerificationReport()
    report.hash_mismatch = 2

    failures = verify_chain_integrity(report)
    assert len(failures) > 0
    assert any("hash mismatch" in f.detail for f in failures)


# ----------------------------------------------------------------------
# M5: run_proof with a verifier report (exercises the actual proof path)
# ----------------------------------------------------------------------


def test_run_proof_fails_on_chain_integrity_failure() -> None:
    """run_proof fails when the verifier report has chain integrity failures.

    This exercises the actual proof path (run_proof with a verifier_report),
    not just verify_chain_integrity in isolation (M5).
    """
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = "proof content"
    bash_output = correlation_id
    baseline = 100

    events = _build_passing_events(
        session_id, baseline, correlation_id, file_content, bash_output
    )

    report = VerificationReport()
    report.signature_failed = 1
    report.hash_mismatch = 0
    report.chain_contiguity_violations = []
    report.bundle_hash_ok = True
    report.chain_integrity_ok = False

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
        verifier_report=report,
    )
    assert not result.passed
    chain_failures = [f for f in result.failures if f.check == "chain"]
    assert len(chain_failures) > 0


def test_run_proof_fails_on_hash_mismatch_in_report() -> None:
    """run_proof surfaces a hash mismatch from the verifier report (M5)."""
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = "proof content"
    bash_output = correlation_id
    baseline = 100

    events = _build_passing_events(
        session_id, baseline, correlation_id, file_content, bash_output
    )

    report = VerificationReport()
    report.signature_failed = 0
    report.hash_mismatch = 3
    report.bundle_hash_ok = True
    report.chain_integrity_ok = True

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
        verifier_report=report,
    )
    assert not result.passed
    assert any(f.check == "chain" and "hash mismatch" in f.detail for f in result.failures)


def test_run_proof_passes_with_clean_verifier_report() -> None:
    """run_proof passes when the verifier report is clean (M5 happy path)."""
    session_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = "proof content"
    bash_output = correlation_id
    baseline = 100

    events = _build_passing_events(
        session_id, baseline, correlation_id, file_content, bash_output
    )

    report = VerificationReport()
    report.signature_failed = 0
    report.hash_mismatch = 0
    report.chain_contiguity_violations = []
    report.bundle_hash_ok = True
    report.chain_integrity_ok = True

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
        verifier_report=report,
    )
    assert result.passed


# ----------------------------------------------------------------------
# B1: Decoy session before real session — real session is selected
# ----------------------------------------------------------------------


def test_decoy_before_real_session_real_selected() -> None:
    """When a decoy session appears before the real session, B1 skips the
    decoy (no correlated tool calls) and selects the real session.
    """
    real_session = str(uuid.uuid4())
    decoy_session = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    file_content = f"proof {correlation_id}"
    bash_output = correlation_id
    baseline = 100

    # Decoy session first (lower global_seq) but no correlated tool calls
    events: list[ProofEvent] = [
        _make_session_attestation(decoy_session, baseline + 1),
        _make_tool_call_end(
            decoy_session,
            baseline + 2,
            tool="Read",
            stdout_digest=_sha256("decoy"),
            file_paths=["/tmp/other.txt"],
        ),
    ]
    # Real session second (higher global_seq) with correlated tool calls
    events.extend(
        _build_passing_events(
            real_session, baseline + 2, correlation_id, file_content, bash_output
        )
    )

    found = find_session_attestation(events, baseline, f"{correlation_id}.txt")
    assert found == real_session

    result = run_proof(
        events=events,
        baseline_seq=baseline,
        expected_harness_version="2.1.200",
        expected_outputs={"Read": file_content, "Bash": bash_output},
        expected_file_name=f"{correlation_id}.txt",
    )
    assert result.passed
    assert result.session_entity_id == real_session


# ----------------------------------------------------------------------
# B4: verify_correlation — exact basename match (not substring)
# ----------------------------------------------------------------------


def test_verify_correlation_accepts_exact_basename() -> None:
    """verify_correlation accepts file paths whose basename matches exactly."""
    correlation_id = str(uuid.uuid4())
    expected_file_name = f"{correlation_id}.txt"

    events = [
        _make_tool_call_end(
            "session-1",
            1,
            tool="Read",
            file_paths=[f"/tmp/some/other/dir/{correlation_id}.txt"],
        ),
    ]

    failures = verify_correlation(events, expected_file_name)
    assert len(failures) == 0


def test_verify_correlation_rejects_wrong_basename() -> None:
    """verify_correlation rejects file paths whose basename doesn't match."""
    correlation_id = str(uuid.uuid4())
    different_id = str(uuid.uuid4())
    expected_file_name = f"{correlation_id}.txt"

    events = [
        _make_tool_call_end(
            "session-1",
            1,
            tool="Read",
            file_paths=[f"/tmp/proof/{different_id}.txt"],
        ),
    ]

    failures = verify_correlation(events, expected_file_name)
    assert len(failures) == 1
    assert failures[0].check == "correlation"


def test_verify_correlation_rejects_substring_match() -> None:
    """verify_correlation rejects paths where the marker is a substring but
    not the exact basename (B4).
    """
    correlation_id = str(uuid.uuid4())
    expected_file_name = f"{correlation_id}.txt"

    # The correlation_id appears as a substring but the basename is different
    events = [
        _make_tool_call_end(
            "session-1",
            1,
            tool="Read",
            file_paths=[f"/tmp/proof/prefix-{correlation_id}.txt"],
        ),
    ]

    failures = verify_correlation(events, expected_file_name)
    assert len(failures) == 1
    assert failures[0].check == "correlation"


def test_verify_correlation_accepts_redacted_file_paths() -> None:
    """verify_correlation also checks tool_args_redacted.file_paths."""
    correlation_id = str(uuid.uuid4())
    expected_file_name = f"{correlation_id}.txt"

    events = [
        _make_tool_call_end(
            "session-1",
            1,
            tool="Read",
            file_paths=[f"/tmp/proof/{correlation_id}.txt"],
        ),
    ]

    failures = verify_correlation(events, expected_file_name)
    assert len(failures) == 0
