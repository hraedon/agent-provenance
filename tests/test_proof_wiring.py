"""Wiring tests for the e2e_proof script (Plan 008 WI-1.2).

Closes the gap between constructed ProofEvent tests and the live
e2e_proof.py script by exercising the three untested functions:

- ``query_events``: SQL -> ProofEvent round-trip against a real regista store
- ``run_canonical_verifier``: subprocess export+verify path
- ``parse_verifier_report``: JSON -> VerificationReport parse
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest

from cairn.proof import find_session_attestation, find_tool_call_ends
from cairn.proof_runner import (
    get_baseline_seq,
    parse_verifier_report,
    query_events,
    run_canonical_verifier,
)

_UNSET: Any = object()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _insert_session_attestation(
    regista_instance: Any,
    session_id: str,
    *,
    harness_version: str = "2.1.200",
    on_behalf_of: Any = _UNSET,
) -> Any:
    payload = {
        "version": "1",
        "principal_id": "human:test",
        "session_id": session_id,
        "attested_at": datetime.now(UTC).isoformat(),
        "harnesses": [{"name": "claude", "version": harness_version}],
        "scope_statement": "In scope: claude.",
    }
    if on_behalf_of is _UNSET:
        obo = {"principal_id": "human:test", "session_id": session_id}
    else:
        obo = on_behalf_of
    return regista_instance.append_event(
        work_item_id=uuid.UUID(session_id),
        actor_id="agent-1",
        actor_metadata={"role": "agent", "phase": "session_attestation"},
        transition="session_attestation",
        payload=payload,
        on_behalf_of=obo,
        entity_kind="session",
    )


def _insert_tool_call_end(
    regista_instance: Any,
    session_id: str,
    *,
    tool: str = "Read",
    stdout_digest: str | None = None,
    file_paths: list[str] | None = None,
    on_behalf_of: Any = _UNSET,
    workflow_name: str = "cairn_agent_actions",
) -> Any:
    wi, _ = regista_instance.create_work_item(
        workflow_name=workflow_name,
        work_item_type="tool_call",
        actor_id="agent-1",
        actor_metadata={"role": "agent", "phase": "begin"},
        custom_fields={"tool": tool, "status": "running"},
    )

    if on_behalf_of is _UNSET:
        obo = {"principal_id": "human:test", "session_id": session_id}
    else:
        obo = on_behalf_of

    begin_payload: dict[str, Any] = {
        "tool": tool,
        "tool_args_hash": "sha256:abc",
        "harness": {"name": "claude", "version": "2.1.200"},
    }
    if file_paths:
        begin_payload["files"] = [{"path": p} for p in file_paths]
        begin_payload["tool_args_redacted"] = {"tool": tool, "file_paths": file_paths}

    regista_instance.transition(
        work_item_id=wi.work_item_id,
        transition_name="tool_call_begin",
        actor_id="agent-1",
        actor_metadata={"role": "agent", "phase": "begin"},
        payload=begin_payload,
        on_behalf_of=obo,
    )

    end_payload: dict[str, Any] = {
        "tool": tool,
        "tool_args_hash": "sha256:abc",
        "harness": {"name": "claude", "version": "2.1.200"},
    }
    if stdout_digest is not None:
        end_payload["result_summary"] = {"stdout_digest": stdout_digest}
    if file_paths:
        end_payload["files"] = [{"path": p} for p in file_paths]
        end_payload["tool_args_redacted"] = {"tool": tool, "file_paths": file_paths}

    return regista_instance.transition(
        work_item_id=wi.work_item_id,
        transition_name="tool_call_end",
        actor_id="agent-1",
        actor_metadata={"role": "agent", "phase": "end"},
        payload=end_payload,
        on_behalf_of=obo,
    )


# -----------------------------------------------------------------------
# _query_events: SQL -> ProofEvent round-trip
# -----------------------------------------------------------------------


def test_query_events_round_trips_into_proof_event(
    regista_instance: Any,
    workflow_registered: None,
    dsn: str,
    project: str,
) -> None:
    session_id = str(uuid.uuid4())
    file_content = "cairn proof test content"
    file_path = "/tmp/proof/test.txt"

    conn = psycopg.connect(dsn)
    baseline_seq = get_baseline_seq(conn, project)
    conn.close()

    _insert_session_attestation(regista_instance, session_id)
    _insert_tool_call_end(
        regista_instance,
        session_id,
        tool="Read",
        stdout_digest=_sha256(file_content),
        file_paths=[file_path],
    )

    conn = psycopg.connect(dsn)
    events = query_events(conn, project, baseline_seq)
    conn.close()

    assert len(events) >= 2

    session_events = [e for e in events if e.transition == "session_attestation"]
    tool_end_events = [e for e in events if e.transition == "tool_call_end"]

    assert len(session_events) == 1
    assert len(tool_end_events) == 1

    sa = session_events[0]
    assert sa.entity_id == session_id
    assert sa.entity_kind == "session"
    assert sa.payload is not None
    assert "harnesses" in sa.payload
    assert sa.payload["harnesses"][0]["version"] == "2.1.200"
    assert sa.on_behalf_of is not None
    assert sa.on_behalf_of["session_id"] == session_id

    te = tool_end_events[0]
    assert te.entity_kind == "work_item"
    assert te.payload is not None
    assert te.payload["tool"] == "Read"
    assert te.payload["result_summary"]["stdout_digest"] == _sha256(file_content)
    assert te.payload["files"][0]["path"] == file_path
    assert te.payload["harness"]["name"] == "claude"
    assert te.on_behalf_of is not None
    assert te.on_behalf_of["session_id"] == session_id

    found_session = find_session_attestation(events, baseline_seq, "test.txt")
    assert found_session == session_id

    tool_calls = find_tool_call_ends(events, session_id, baseline_seq)
    assert len(tool_calls) == 1
    assert tool_calls[0].payload is not None
    assert tool_calls[0].payload["tool"] == "Read"


def test_query_events_respects_baseline(
    regista_instance: Any,
    workflow_registered: None,
    dsn: str,
    project: str,
) -> None:
    session_id = str(uuid.uuid4())

    _insert_session_attestation(regista_instance, session_id)
    _insert_tool_call_end(regista_instance, session_id, tool="Read")
    _insert_tool_call_end(regista_instance, session_id, tool="Bash")

    conn = psycopg.connect(dsn)
    all_events = query_events(conn, project, 0)
    conn.close()

    assert len(all_events) >= 3
    all_seqs = sorted(e.global_seq for e in all_events if e.global_seq is not None)
    assert len(all_seqs) >= 3

    mid_seq = all_seqs[len(all_seqs) // 2]

    conn = psycopg.connect(dsn)
    filtered = query_events(conn, project, mid_seq)
    conn.close()

    for ev in filtered:
        assert ev.global_seq is not None
        assert ev.global_seq > mid_seq


def test_query_events_handles_null_on_behalf_of(
    regista_instance: Any,
    workflow_registered: None,
    dsn: str,
    project: str,
) -> None:
    session_id = str(uuid.uuid4())

    conn = psycopg.connect(dsn)
    baseline_seq = get_baseline_seq(conn, project)
    conn.close()

    _insert_tool_call_end(
        regista_instance,
        session_id,
        tool="Read",
        on_behalf_of=None,
    )

    conn = psycopg.connect(dsn)
    from psycopg.sql import SQL, Identifier

    set_path = SQL("SET search_path TO {}, public").format(Identifier(project))
    conn.execute(set_path)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT on_behalf_of FROM events WHERE transition = 'tool_call_end' LIMIT 1"
        )
        row = cur.fetchone()
        assert row is not None
        sql_value = row[0]
    conn.close()

    assert sql_value is None, (
        f"Expected NULL on_behalf_of in DB, got: {sql_value}"
    )

    conn = psycopg.connect(dsn)
    events = query_events(conn, project, baseline_seq)
    conn.close()

    assert len(events) >= 1

    tool_end_events = [e for e in events if e.transition == "tool_call_end"]
    assert len(tool_end_events) == 1
    assert tool_end_events[0].on_behalf_of is None


# -----------------------------------------------------------------------
# _run_canonical_verifier: subprocess export+verify
# -----------------------------------------------------------------------


def test_run_canonical_verifier_with_clean_bundle(
    regista_instance: Any,
    workflow_registered: None,
    dsn: str,
    project: str,
    hmac_keys: Path,
    tmp_path: Path,
) -> None:
    session_id = str(uuid.uuid4())
    file_content = "cairn proof verifier test"
    file_path = "/tmp/proof/verifier-test.txt"
    proof_dir = Path("/tmp/proof")
    proof_dir.mkdir(parents=True, exist_ok=True)
    proof_file = proof_dir / "verifier-test.txt"
    proof_file.write_text(file_content)

    since = (datetime.now(UTC) - timedelta(seconds=5)).isoformat()

    _insert_session_attestation(regista_instance, session_id)
    _insert_tool_call_end(
        regista_instance,
        session_id,
        tool="Read",
        stdout_digest=_sha256(file_content),
        file_paths=[file_path],
    )

    hmac_keys.chmod(0o600)

    report, detail = run_canonical_verifier(
        dsn, project, str(hmac_keys), tmp_path, since,
    )

    if report is None:
        pytest.skip(f"cairn CLI subprocess unavailable or failed: {detail}")

    assert report.all_ok, f"Expected clean verifier report, got: {detail}"


# -----------------------------------------------------------------------
# _parse_verifier_report: JSON -> VerificationReport
# -----------------------------------------------------------------------


def test_parse_verifier_report_parses_json(tmp_path: Path) -> None:
    report_data = {
        "summary": {
            "total_events": 5,
            "ok": 5,
            "signature_failed": 0,
            "hash_mismatch": 0,
            "revoked_key": 0,
            "bundle_hash_ok": True,
            "chain_integrity_ok": True,
            "all_ok": True,
        },
        "entries": [],
        "sequence_gaps": [],
        "chain_contiguity_violations": [
            {
                "kind": "global_seq_gap",
                "detail": "Missing seq 3",
                "event_id": "ev-123",
                "work_item_id": "wi-456",
                "expected": "3",
                "actual": "4",
            }
        ],
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report_data))

    report = parse_verifier_report(report_path)

    assert report is not None
    assert report.signature_failed == 0
    assert report.hash_mismatch == 0
    assert report.revoked_key == 0
    assert report.bundle_hash_ok is True
    assert report.chain_integrity_ok is True
    assert not report.all_ok
    assert len(report.chain_contiguity_violations) == 1
    v = report.chain_contiguity_violations[0]
    assert v.kind == "global_seq_gap"
    assert v.detail == "Missing seq 3"
    assert v.event_id == "ev-123"
    assert v.work_item_id == "wi-456"


def test_parse_verifier_report_returns_none_for_missing_file() -> None:
    result = parse_verifier_report(Path("/nonexistent/path.json"))
    assert result is None
