"""Unit tests for Cairn adapter and verifier."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest
from substrate import Substrate

from cairn import CairnAdapter, CairnConfig
from cairn.schema import (
    FileDigest,
    ScopeAttestationPayload,
    ToolCallBegin,
    hash_payload,
)
from cairn.verifier import VerificationReport, Verifier

# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------


@pytest.fixture
def hmac_keys(tmp_path: Path) -> Path:
    """Create a minimal substrate HMAC key file."""
    key_file = tmp_path / "keys.json"
    key_file.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": "cairn-test-001",
                        "secret": "supersecret-test-key-32bytes!!",
                        "status": "active",
                        "alg": "HMAC-SHA256",
                    }
                ]
            }
        )
    )
    return key_file


@pytest.fixture(scope="function")
def substrate_instance(hmac_keys: Path, tmp_path: Path) -> Substrate:
    """Create a fresh in-memory substrate for each test."""
    dsn = os.environ.get(
        "SUBSTRATE_TEST_DSN",
        "postgresql://substrate_test:substrate_test@localhost/substrate_test",
    )
    project = f"cairn_test_{uuid.uuid4().hex[:8]}"
    try:
        sub = Substrate.create_project(
            dsn=dsn,
            project=project,
            hmac_key_path=str(hmac_keys),
        )
    except Exception:
        pytest.skip("Postgres not available; set SUBSTRATE_TEST_DSN to run")
    yield sub
    sub.close()


@pytest.fixture
def workflow_registered(substrate_instance: Substrate) -> None:
    substrate_instance.register_workflow_file(
        "workflows/cairn_agent_actions.yaml"
    )


@pytest.fixture
def adapter(
    substrate_instance: Substrate, workflow_registered: None
) -> CairnAdapter:
    return CairnAdapter(
        substrate_instance,
        config=CairnConfig("opencode", "0.1.0"),
        on_behalf_of={
            "principal_id": "human:test",
            "session_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        },
    )


# ----------------------------------------------------------------------
# Schema tests
# ----------------------------------------------------------------------


def test_file_digest_roundtrip() -> None:
    fd = FileDigest(path="/tmp/foo", pre_digest="abc", post_digest="def")
    assert FileDigest.from_dict(fd.to_dict()) == fd


def test_tool_call_begin_roundtrip() -> None:
    tcb = ToolCallBegin(
        tool="Edit",
        tool_args_hash="sha256:abc",
        files=[FileDigest("/tmp/foo", "pre", None)],
        on_behalf_of={"principal_id": "me"},
        harness=CairnConfig("opencode", "0.1.0"),
    )
    assert ToolCallBegin.from_dict(tcb.to_dict()) == tcb


def test_hash_payload_stable() -> None:
    payload = {"b": 2, "a": 1}
    h1 = hash_payload(payload)
    h2 = hash_payload(payload)
    assert h1 == h2
    assert len(h1) == 64


def test_scope_attestation_roundtrip() -> None:
    sa = ScopeAttestationPayload(
        version="1",
        principal_id="human:plm",
        attested_at="2026-05-24T12:00:00Z",
        harnesses=[{"name": "opencode", "version": "0.1.0"}],
        scope_statement="In scope: opencode.",
        harness_config_digests={"opencode": "sha256:abc"},
    )
    assert ScopeAttestationPayload.from_dict(sa.to_dict()) == sa


def test_verify_scope_attestation_in_report() -> None:
    from datetime import UTC, datetime

    from substrate._signing import sign_event
    from substrate._types import Event

    key_bytes = b"supersecret-test-key-32bytes!!"
    key_set = {"cairn-test-001": key_bytes}

    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="agent-1",
        key_id="cairn-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_end",
        payload={
            "version": "1",
            "principal_id": "human:plm",
            "attested_at": "2026-05-24T12:00:00Z",
            "harnesses": [{"name": "opencode", "version": "0.1.0"}],
            "scope_statement": "In scope: opencode.",
            "harness_config_digests": {"opencode": "sha256:abc"},
        },
        key=key_bytes,
    )
    event = Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="cairn-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_end",
        payload={
            "version": "1",
            "principal_id": "human:plm",
            "attested_at": "2026-05-24T12:00:00Z",
            "harnesses": [{"name": "opencode", "version": "0.1.0"}],
            "scope_statement": "In scope: opencode.",
            "harness_config_digests": {"opencode": "sha256:abc"},
        },
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert len(report.scope_attestations) == 1
    text = Verifier.format_report(report)
    assert "SCOPE ATTESTATIONS" in text
    assert "opencode" in text


# ----------------------------------------------------------------------
# Adapter tests
# ----------------------------------------------------------------------


def test_attest_scope(adapter: CairnAdapter) -> None:
    ev = adapter.attest_scope(
        principal_id="human:test",
        harnesses=[{"name": "opencode", "version": "0.1.0"}],
        scope_statement="In scope: opencode.",
        harness_config_digests={"opencode": "sha256:abc"},
    )
    assert ev is not None
    payload = ev.payload or {}
    assert payload.get("version") == "1"
    assert payload.get("principal_id") == "human:test"
    assert payload.get("scope_statement") == "In scope: opencode."


def test_begin_tool_call_creates_work_item(
    adapter: CairnAdapter, tmp_path: Path
) -> None:
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello\n")

    wi = adapter.begin_tool_call(
        tool="Edit",
        tool_args={
            "filePath": str(test_file),
            "oldString": "hello",
            "newString": "world",
        },
        files=[str(test_file)],
    )
    assert wi is not None
    assert wi.custom_fields["tool"] == "Edit"
    assert wi.custom_fields["status"] == "running"

    events = adapter._sub.read_events(work_item_id=wi.work_item_id)
    assert len(events) >= 1


def test_begin_and_end_tool_call(
    adapter: CairnAdapter, tmp_path: Path
) -> None:
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello\n")

    wi = adapter.begin_tool_call(
        tool="Edit",
        tool_args={
            "filePath": str(test_file),
            "oldString": "hello",
            "newString": "world",
        },
        files=[str(test_file)],
    )
    test_file.write_text("world\n")

    ev = adapter.end_tool_call(
        wi.work_item_id,
        result_summary={"exit_code": 0},
        files=[str(test_file)],
    )
    assert ev is not None
    assert ev.transition == "tool_call_end"
    payload = ev.payload or {}
    assert payload.get("tool") == "Edit"


# ----------------------------------------------------------------------
# Verifier tests
# ----------------------------------------------------------------------


def test_verify_single_signature(hmac_keys: Path) -> None:
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from substrate._signing import sign_event
    from substrate._types import Event

    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="agent-1",
        key_id="cairn-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Edit", "tool_args_hash": "sha256:abc"},
        key=key_bytes,
    )
    event = Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="cairn-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Edit", "tool_args_hash": "sha256:abc"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert report.total_events == 1
    assert report.ok == 1
    assert report.all_ok


def test_verify_bad_key(hmac_keys: Path) -> None:
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: b"wrong-key"}

    from datetime import UTC, datetime

    from substrate._signing import sign_event
    from substrate._types import Event

    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="agent-1",
        key_id="cairn-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={},
        key=key_bytes,
    )
    event = Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="cairn-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert report.signature_failed == 1
    assert not report.all_ok


def test_format_report() -> None:
    report = VerificationReport()
    report.total_events = 2
    report.ok = 2
    text = Verifier.format_report(report)
    assert "ALL CHECKS PASSED" in text
    assert "Total events examined" in text


def test_verify_bundle_file(hmac_keys: Path, tmp_path: Path) -> None:
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from substrate._signing import sign_event
    from substrate._types import Event

    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="agent-1",
        key_id="cairn-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read", "tool_args_hash": "sha256:abc"},
        key=key_bytes,
    )
    event = Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="cairn-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read", "tool_args_hash": "sha256:abc"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    bundle = {
        "manifest": {"events_count": 1},
        "events": [event.to_dict()],
    }
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))

    verifier = Verifier(key_set)
    report = verifier.verify_bundle(bundle_path)
    assert report.ok == 1
