"""Unit tests for Cairn adapter and verifier."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

import pytest
from regista import Regista

from cairn import CairnAdapter, CairnConfig
from cairn.schema import (
    FileDigest,
    ScopeAttestationPayload,
    ToolCallBegin,
    check_key_file_permissions,
    digest_file,
    hash_payload,
)
from cairn.verifier import (
    FileProvenanceEntry,
    KeyRotationEntry,
    ScopeAttestationEntry,
    VerificationEntry,
    VerificationReport,
    Verifier,
)

# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------


@pytest.fixture(scope="function")
def regista_instance(hmac_keys: Path, tmp_path: Path) -> Regista:
    """Create a fresh in-memory regista for each test."""
    dsn = os.environ.get(
        "REGISTA_TEST_DSN",
        "postgresql://regista_test:regista_test@localhost/regista_test",
    )
    project = f"cairn_test_{uuid.uuid4().hex[:8]}"
    try:
        sub = Regista.create_project(
            dsn=dsn,
            project=project,
            hmac_key_path=str(hmac_keys),
        )
    except Exception:
        pytest.skip("Postgres not available; set REGISTA_TEST_DSN to run")
    yield sub
    sub.close()


@pytest.fixture
def adapter(regista_instance: Regista, workflow_registered: None) -> CairnAdapter:
    return CairnAdapter(
        regista_instance,
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
        principal_id="human:owner",
        attested_at="2026-05-24T12:00:00Z",
        harnesses=[{"name": "opencode", "version": "0.1.0"}],
        scope_statement="In scope: opencode.",
        harness_config_digests={"opencode": "sha256:abc"},
    )
    assert ScopeAttestationPayload.from_dict(sa.to_dict()) == sa


def test_verify_scope_attestation_in_report() -> None:
    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

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
            "principal_id": "human:owner",
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
            "principal_id": "human:owner",
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


def test_begin_tool_call_creates_work_item(adapter: CairnAdapter, tmp_path: Path) -> None:
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


def test_begin_and_end_tool_call(adapter: CairnAdapter, tmp_path: Path) -> None:
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

    from regista._signing import sign_event
    from regista._types import Event

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

    from regista._signing import sign_event
    from regista._types import Event

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

    from regista._signing import sign_event
    from regista._types import Event

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


def test_verify_bundle_with_valid_hash(hmac_keys: Path, tmp_path: Path) -> None:
    import hashlib

    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

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
        payload={"tool": "Read"},
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
        payload={"tool": "Read"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    manifest = {"events_count": 1}
    bundle = {"manifest": manifest, "events": [event.to_dict()]}
    canonical = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    manifest["bundle_hash"] = digest

    bundle_path = tmp_path / "bundle_hashed.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))

    verifier = Verifier(key_set)
    report = verifier.verify_bundle(bundle_path)
    assert report.ok == 1
    assert report.bundle_hash_ok is True
    assert report.all_ok


def test_verify_bundle_tampered_hash(hmac_keys: Path, tmp_path: Path) -> None:
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

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
        payload={"tool": "Read"},
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
        payload={"tool": "Read"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    bundle = {
        "manifest": {
            "events_count": 1,
            "bundle_hash": "sha256:deadbeef",
        },
        "events": [event.to_dict()],
    }
    bundle_path = tmp_path / "bundle_tampered.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))

    verifier = Verifier(key_set)
    report = verifier.verify_bundle(bundle_path)
    assert report.bundle_hash_ok is False
    assert not report.all_ok
    assert "mismatch" in (report.bundle_hash_detail or "")


# ----------------------------------------------------------------------
# Sequence gap detection tests
# ----------------------------------------------------------------------


def test_verify_events_sequence_ok(hmac_keys: Path) -> None:
    """Contiguous event_seq values produce no gaps."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    events = []
    for seq in range(3):
        ev_id = uuid.uuid4()
        sig, c_hash, env = sign_event(
            event_id=ev_id,
            work_item_id=wi_id,
            actor_id="agent-1",
            key_id="cairn-test-001",
            event_seq=seq,
            workflow_name="cairn_agent_actions",
            workflow_version=1,
            timestamp=now,
            transition="tool_call_begin",
            payload={"tool": "Read", "tool_args_hash": f"sha256:{seq}"},
            key=key_bytes,
        )
        events.append(
            Event(
                event_id=ev_id,
                work_item_id=wi_id,
                event_seq=seq,
                actor_id="agent-1",
                actor_kind="agent",
                actor_metadata=None,
                key_id="cairn-test-001",
                workflow_name="cairn_agent_actions",
                workflow_version=1,
                timestamp=now,
                transition="tool_call_begin",
                payload={"tool": "Read", "tool_args_hash": f"sha256:{seq}"},
                payload_canonical_hash=c_hash,
                signature=sig,
                canonical_envelope=env,
            )
        )

    verifier = Verifier(key_set)
    report = verifier.verify_events(events)
    assert len(report.sequence_gaps) == 0
    assert report.all_ok


def test_verify_events_sequence_gap(hmac_keys: Path) -> None:
    """Missing event_seq is detected within a work item."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    events = []
    # seq 0, 2 (skip 1) — same work item
    for seq in [0, 2]:
        ev_id = uuid.uuid4()
        sig, c_hash, env = sign_event(
            event_id=ev_id,
            work_item_id=wi_id,
            actor_id="agent-1",
            key_id="cairn-test-001",
            event_seq=seq,
            workflow_name="cairn_agent_actions",
            workflow_version=1,
            timestamp=now,
            transition="tool_call_begin",
            payload={"tool": "Read", "tool_args_hash": f"sha256:{seq}"},
            key=key_bytes,
        )
        events.append(
            Event(
                event_id=ev_id,
                work_item_id=wi_id,
                event_seq=seq,
                actor_id="agent-1",
                actor_kind="agent",
                actor_metadata=None,
                key_id="cairn-test-001",
                workflow_name="cairn_agent_actions",
                workflow_version=1,
                timestamp=now,
                transition="tool_call_begin",
                payload={"tool": "Read", "tool_args_hash": f"sha256:{seq}"},
                payload_canonical_hash=c_hash,
                signature=sig,
                canonical_envelope=env,
            )
        )

    verifier = Verifier(key_set)
    report = verifier.verify_events(events)
    assert len(report.sequence_gaps) == 1
    assert report.sequence_gaps[0].kind == "missing_seq"
    assert report.sequence_gaps[0].expected_seq == 1
    assert report.sequence_gaps[0].actual_seq == 2
    assert not report.all_ok


# ----------------------------------------------------------------------
# JSON report format tests
# ----------------------------------------------------------------------


def test_format_report_json_keys() -> None:
    report = VerificationReport()
    report.total_events = 1
    report.ok = 1
    result = Verifier.format_report_json(report)
    assert "summary" in result
    assert "entries" in result
    assert "sequence_gaps" in result
    assert "file_provenance" in result
    assert "scope_attestations" in result
    assert "bundle" in result
    assert "verification_note" in result
    assert result["summary"]["all_ok"] is True


def test_format_report_json_serializable() -> None:
    import json as json_mod

    report = VerificationReport()
    report.total_events = 2
    report.ok = 1
    report.signature_failed = 1
    result = Verifier.format_report_json(report)
    # Must be JSON-serializable
    text = json_mod.dumps(result)
    assert text
    parsed = json_mod.loads(text)
    assert parsed["summary"]["signature_failed"] == 1


# ----------------------------------------------------------------------
# Bundle chain verification tests
# ----------------------------------------------------------------------


def test_verify_bundle_chain_valid(hmac_keys: Path, tmp_path: Path) -> None:
    """Two bundles with correct previous_bundle_hash chain verify."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    def make_event(seq: int) -> Event:
        ev_id = uuid.uuid4()
        wi_id = uuid.uuid4()
        now = datetime.now(UTC)
        sig, c_hash, env = sign_event(
            event_id=ev_id,
            work_item_id=wi_id,
            actor_id="agent-1",
            key_id="cairn-test-001",
            event_seq=seq,
            workflow_name="cairn_agent_actions",
            workflow_version=1,
            timestamp=now,
            transition="tool_call_begin",
            payload={"tool": "Read"},
            key=key_bytes,
        )
        return Event(
            event_id=ev_id,
            work_item_id=wi_id,
            event_seq=seq,
            actor_id="agent-1",
            actor_kind="agent",
            actor_metadata=None,
            key_id="cairn-test-001",
            workflow_name="cairn_agent_actions",
            workflow_version=1,
            timestamp=now,
            transition="tool_call_begin",
            payload={"tool": "Read"},
            payload_canonical_hash=c_hash,
            signature=sig,
            canonical_envelope=env,
        )

    # Bundle 1
    ev1 = make_event(0)
    manifest1: dict = {"events_count": 1}
    bundle1: dict = {"manifest": manifest1, "events": [ev1.to_dict()]}
    canonical1 = json.dumps(bundle1, separators=(",", ":"), sort_keys=True).encode("utf-8")
    hash1 = "sha256:" + hashlib.sha256(canonical1).hexdigest()
    manifest1["bundle_hash"] = hash1
    p1 = tmp_path / "bundle1.json"
    p1.write_text(json.dumps(bundle1, indent=2))

    # Bundle 2 (references bundle 1)
    ev2 = make_event(1)
    manifest2: dict = {"events_count": 1, "previous_bundle_hash": hash1}
    bundle2: dict = {"manifest": manifest2, "events": [ev2.to_dict()]}
    canonical2 = json.dumps(bundle2, separators=(",", ":"), sort_keys=True).encode("utf-8")
    hash2 = "sha256:" + hashlib.sha256(canonical2).hexdigest()
    manifest2["bundle_hash"] = hash2
    p2 = tmp_path / "bundle2.json"
    p2.write_text(json.dumps(bundle2, indent=2))

    verifier = Verifier(key_set)
    report = verifier.verify_bundle_chain([p1, p2])
    assert report.all_ok
    assert report.total_events == 2
    assert report.ok == 2


def test_verify_bundle_chain_broken(hmac_keys: Path, tmp_path: Path) -> None:
    """Two bundles with wrong previous_bundle_hash detect the break."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    def make_event(seq: int) -> Event:
        ev_id = uuid.uuid4()
        wi_id = uuid.uuid4()
        now = datetime.now(UTC)
        sig, c_hash, env = sign_event(
            event_id=ev_id,
            work_item_id=wi_id,
            actor_id="agent-1",
            key_id="cairn-test-001",
            event_seq=seq,
            workflow_name="cairn_agent_actions",
            workflow_version=1,
            timestamp=now,
            transition="tool_call_begin",
            payload={"tool": "Read"},
            key=key_bytes,
        )
        return Event(
            event_id=ev_id,
            work_item_id=wi_id,
            event_seq=seq,
            actor_id="agent-1",
            actor_kind="agent",
            actor_metadata=None,
            key_id="cairn-test-001",
            workflow_name="cairn_agent_actions",
            workflow_version=1,
            timestamp=now,
            transition="tool_call_begin",
            payload={"tool": "Read"},
            payload_canonical_hash=c_hash,
            signature=sig,
            canonical_envelope=env,
        )

    # Bundle 1
    ev1 = make_event(0)
    manifest1: dict = {"events_count": 1}
    bundle1: dict = {"manifest": manifest1, "events": [ev1.to_dict()]}
    canonical1 = json.dumps(bundle1, separators=(",", ":"), sort_keys=True).encode("utf-8")
    hash1 = "sha256:" + hashlib.sha256(canonical1).hexdigest()
    manifest1["bundle_hash"] = hash1
    p1 = tmp_path / "bundle1.json"
    p1.write_text(json.dumps(bundle1, indent=2))

    # Bundle 2 with WRONG previous hash
    ev2 = make_event(1)
    manifest2: dict = {"events_count": 1, "previous_bundle_hash": "sha256:deadbeef"}
    bundle2: dict = {"manifest": manifest2, "events": [ev2.to_dict()]}
    canonical2 = json.dumps(bundle2, separators=(",", ":"), sort_keys=True).encode("utf-8")
    hash2 = "sha256:" + hashlib.sha256(canonical2).hexdigest()
    manifest2["bundle_hash"] = hash2
    p2 = tmp_path / "bundle2.json"
    p2.write_text(json.dumps(bundle2, indent=2))

    verifier = Verifier(key_set)
    report = verifier.verify_bundle_chain([p1, p2])
    assert not report.all_ok
    assert report.chain_integrity_ok is False


# ----------------------------------------------------------------------
# Schema utility tests
# ----------------------------------------------------------------------


def test_digest_file_streaming(tmp_path: Path) -> None:
    """digest_file uses streaming hash (produces correct result for non-trivial file)."""
    f = tmp_path / "test.txt"
    content = b"hello world " * 10000
    f.write_bytes(content)
    result = digest_file(str(f))
    assert result is not None
    assert len(result) == 64
    # Verify it matches a known hash
    assert result == hashlib.sha256(content).hexdigest()


def test_digest_file_nonexistent(tmp_path: Path) -> None:
    result = digest_file(str(tmp_path / "nonexistent.txt"))
    assert result is None


def test_digest_file_empty(tmp_path: Path) -> None:
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    result = digest_file(str(f))
    assert result is not None
    assert result == hashlib.sha256(b"").hexdigest()


def test_check_key_file_permissions_ok(tmp_path: Path) -> None:
    key_file = tmp_path / "keys.json"
    key_file.write_text("{}")
    key_file.chmod(0o600)
    warnings = check_key_file_permissions(str(key_file))
    assert len(warnings) == 0


def test_check_key_file_permissions_world_readable(tmp_path: Path) -> None:
    key_file = tmp_path / "keys.json"
    key_file.write_text("{}")
    key_file.chmod(0o644)
    warnings = check_key_file_permissions(str(key_file))
    assert any("world-readable" in w for w in warnings)


def test_check_key_file_permissions_group_readable(tmp_path: Path) -> None:
    key_file = tmp_path / "keys.json"
    key_file.write_text("{}")
    key_file.chmod(0o640)
    warnings = check_key_file_permissions(str(key_file))
    assert any("group-readable" in w for w in warnings)


# ----------------------------------------------------------------------
# Bundle diff tests
# ----------------------------------------------------------------------


def test_diff_bundles_identical(hmac_keys: Path, tmp_path: Path) -> None:
    """Two identical bundles produce an empty diff."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

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

    bundle = {"manifest": {"events_count": 1}, "events": [event.to_dict()]}
    p1 = tmp_path / "b1.json"
    p2 = tmp_path / "b2.json"
    p1.write_text(json.dumps(bundle))
    p2.write_text(json.dumps(bundle))

    from cairn.verifier import Verifier

    diff = Verifier({}).diff_bundles(p1, p2)
    assert not diff.has_changes
    assert diff.events_added == 0
    assert diff.events_removed == 0


def test_diff_bundles_new_event(hmac_keys: Path, tmp_path: Path) -> None:
    """Newer bundle with an extra event shows as added."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    def make_event(seq: int) -> Event:
        ev_id = uuid.uuid4()
        wi_id = uuid.uuid4()
        now = datetime.now(UTC)
        sig, c_hash, env = sign_event(
            event_id=ev_id,
            work_item_id=wi_id,
            actor_id="agent-1",
            key_id="cairn-test-001",
            event_seq=seq,
            workflow_name="cairn_agent_actions",
            workflow_version=1,
            timestamp=now,
            transition="tool_call_begin",
            payload={"tool": "Read", "tool_args_hash": f"sha256:{seq}"},
            key=key_bytes,
        )
        return Event(
            event_id=ev_id,
            work_item_id=wi_id,
            event_seq=seq,
            actor_id="agent-1",
            actor_kind="agent",
            actor_metadata=None,
            key_id="cairn-test-001",
            workflow_name="cairn_agent_actions",
            workflow_version=1,
            timestamp=now,
            transition="tool_call_begin",
            payload={"tool": "Read", "tool_args_hash": f"sha256:{seq}"},
            payload_canonical_hash=c_hash,
            signature=sig,
            canonical_envelope=env,
        )

    ev1 = make_event(0)
    ev2 = make_event(1)

    bundle1 = {"manifest": {"events_count": 1}, "events": [ev1.to_dict()]}
    bundle2 = {"manifest": {"events_count": 2}, "events": [ev1.to_dict(), ev2.to_dict()]}

    p1 = tmp_path / "b1.json"
    p2 = tmp_path / "b2.json"
    p1.write_text(json.dumps(bundle1))
    p2.write_text(json.dumps(bundle2))

    diff = Verifier({}).diff_bundles(p1, p2)
    assert diff.has_changes
    assert diff.events_added == 1
    assert diff.events_removed == 0
    assert diff.older_event_count == 1
    assert diff.newer_event_count == 2

    text = Verifier.format_diff(diff)
    assert "EVENTS" in text
    assert "New event" in text

    json_result = Verifier.format_diff_json(diff)
    assert json_result["events_added"] == 1
    assert json_result["has_changes"] is True


def test_diff_bundles_scope_change(hmac_keys: Path, tmp_path: Path) -> None:
    """Changed scope attestation is detected."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    def make_scope_event(scope: str) -> Event:
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
                "principal_id": "human:test",
                "attested_at": "2026-05-24T12:00:00Z",
                "harnesses": [{"name": "opencode", "version": "0.1.0"}],
                "scope_statement": scope,
            },
            key=key_bytes,
        )
        return Event(
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
                "principal_id": "human:test",
                "attested_at": "2026-05-24T12:00:00Z",
                "harnesses": [{"name": "opencode", "version": "0.1.0"}],
                "scope_statement": scope,
            },
            payload_canonical_hash=c_hash,
            signature=sig,
            canonical_envelope=env,
        )

    ev1 = make_scope_event("In scope: opencode.")
    ev2 = make_scope_event("In scope: opencode, claude-code.")

    bundle1 = {"manifest": {"events_count": 1}, "events": [ev1.to_dict()]}
    bundle2 = {"manifest": {"events_count": 1}, "events": [ev2.to_dict()]}

    p1 = tmp_path / "b1.json"
    p2 = tmp_path / "b2.json"
    p1.write_text(json.dumps(bundle1))
    p2.write_text(json.dumps(bundle2))

    from cairn.verifier import Verifier

    diff = Verifier({}).diff_bundles(p1, p2)
    assert diff.has_changes
    scope_entries = [e for e in diff.entries if e.kind == "scope_changed"]
    assert len(scope_entries) == 1
    assert "opencode" in scope_entries[0].detail


# ----------------------------------------------------------------------
# HTML report tests
# ----------------------------------------------------------------------


def test_format_report_html_valid() -> None:
    """HTML report produces valid HTML with key sections."""
    report = VerificationReport()
    report.total_events = 2
    report.ok = 2
    html = Verifier.format_report_html(report)
    assert "<!DOCTYPE html>" in html
    assert "Cairn Verification Report" in html
    assert "ALL CHECKS PASSED" in html
    assert "</html>" in html


def test_format_report_html_shows_failures() -> None:
    """HTML report shows failed events in red."""
    report = VerificationReport()
    report.total_events = 1
    report.signature_failed = 1
    report.entries.append(
        VerificationEntry(
            event_id="abc-123",
            work_item_id="wi-1",
            event_seq=0,
            timestamp="2026-05-24T12:00:00Z",
            transition="tool_call_begin",
            result="signature_failed",
            detail="HMAC mismatch",
        )
    )
    html = Verifier.format_report_html(report)
    assert "VERIFICATION FAILED" in html
    assert "signature_failed" in html
    assert "abc-123" in html


def test_format_report_html_shows_scope_attestation() -> None:
    """HTML report includes scope attestation details."""
    report = VerificationReport()
    report.total_events = 1
    report.ok = 1
    report.scope_attestations.append(
        ScopeAttestationEntry(
            event_id="ev-1",
            work_item_id="wi-1",
            version="1",
            principal_id="human:test",
            attested_at="2026-05-24T12:00:00Z",
            harnesses=[{"name": "opencode", "version": "0.1.0"}],
            scope_statement="In scope: opencode.",
        )
    )
    html = Verifier.format_report_html(report)
    assert "Scope Attestation" in html
    assert "human:test" in html
    assert "In scope: opencode." in html


def test_format_report_html_shows_file_provenance() -> None:
    """HTML report includes file provenance table."""
    report = VerificationReport()
    report.total_events = 1
    report.ok = 1
    report.file_provenance.append(
        FileProvenanceEntry(
            work_item_id="wi-1",
            event_id="ev-1",
            path="/tmp/test.py",
            pre_digest="sha256:aaa",
            post_digest="sha256:bbb",
            current_digest="sha256:bbb",
            digest_match=True,
        )
    )
    html = Verifier.format_report_html(report)
    assert "File Provenance" in html
    assert "/tmp/test.py" in html
    assert "OK" in html


def test_format_report_html_no_external_deps() -> None:
    """HTML report has no external CDN or URL references."""
    report = VerificationReport()
    report.total_events = 0
    html = Verifier.format_report_html(report)
    assert "https://" not in html
    assert "http://" not in html
    assert "cdn" not in html.lower()
    # All CSS should be inlined
    assert "<style>" in html


# ----------------------------------------------------------------------
# Key rotation tests
# ----------------------------------------------------------------------


def test_key_rotation_detected(hmac_keys: Path) -> None:
    """Key rotation events are detected and verified."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {
        "cairn-test-001": key_bytes,
        "cairn-test-002": b"new-key-for-rotation-test-32bytes",
    }

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    # Create a key rotation event signed by the predecessor key
    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    payload = {
        "tool": "key_rotation",
        "predecessor_key_id": "cairn-test-001",
        "successor_key_id": "cairn-test-002",
        "rotated_at": now.isoformat(),
    }
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="system",
        key_id="cairn-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_end",
        payload=payload,
        key=key_bytes,
    )
    event = Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=0,
        actor_id="system",
        actor_kind="agent",
        actor_metadata=None,
        key_id="cairn-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_end",
        payload=payload,
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert len(report.key_rotations) == 1
    kr = report.key_rotations[0]
    assert kr.predecessor_key_id == "cairn-test-001"
    assert kr.successor_key_id == "cairn-test-002"
    assert kr.signature_valid is True
    assert report.key_rotation_failures == 0
    assert report.all_ok


def test_key_rotation_wrong_signer(hmac_keys: Path) -> None:
    """Key rotation signed by wrong key is detected as failure."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {
        "cairn-test-001": key_bytes,
        "cairn-test-002": b"new-key-for-rotation-test-32bytes",
    }

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    # Claims predecessor is 001, but actually signed by 002
    payload = {
        "tool": "key_rotation",
        "predecessor_key_id": "cairn-test-001",
        "successor_key_id": "cairn-test-002",
        "rotated_at": now.isoformat(),
    }
    wrong_key = b"new-key-for-rotation-test-32bytes"
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="system",
        key_id="cairn-test-002",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_end",
        payload=payload,
        key=wrong_key,
    )
    event = Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=0,
        actor_id="system",
        actor_kind="agent",
        actor_metadata=None,
        key_id="cairn-test-002",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_end",
        payload=payload,
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert len(report.key_rotations) == 1
    kr = report.key_rotations[0]
    assert kr.signature_valid is False
    assert "signed by key_id=cairn-test-002" in (kr.detail or "")
    assert report.key_rotation_failures == 1
    assert not report.all_ok


def test_key_rotation_in_report_text() -> None:
    """Key rotations appear in the text report."""
    report = VerificationReport()
    report.total_events = 1
    report.ok = 1
    report.key_rotations.append(
        KeyRotationEntry(
            event_id="ev-1",
            work_item_id="wi-1",
            predecessor_key_id="old-key",
            successor_key_id="new-key",
            rotated_at="2026-05-26T12:00:00Z",
            signature_valid=True,
        )
    )
    text = Verifier.format_report(report)
    assert "KEY ROTATIONS" in text
    assert "old-key" in text
    assert "new-key" in text
    assert "OK" in text


def test_key_rotation_in_report_json() -> None:
    """Key rotations appear in the JSON report."""
    report = VerificationReport()
    report.total_events = 1
    report.ok = 1
    report.key_rotations.append(
        KeyRotationEntry(
            event_id="ev-1",
            work_item_id="wi-1",
            predecessor_key_id="old-key",
            successor_key_id="new-key",
            rotated_at="2026-05-26T12:00:00Z",
            signature_valid=False,
            detail="bad sig",
        )
    )
    result = Verifier.format_report_json(report)
    assert len(result["key_rotations"]) == 1
    assert result["key_rotations"][0]["predecessor_key_id"] == "old-key"
    assert result["key_rotations"][0]["signature_valid"] is False


def test_non_rotation_event_ignored(hmac_keys: Path) -> None:
    """Regular tool call events are not treated as key rotations."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {"cairn-test-001": key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

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

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert len(report.key_rotations) == 0
    assert report.key_rotation_failures == 0
    assert report.all_ok


# ----------------------------------------------------------------------
# Ed25519 signing tests
# ----------------------------------------------------------------------


def _make_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair for testing. Returns (signing_key, verify_key)."""
    pytest.importorskip("nacl.signing")
    from nacl.signing import SigningKey

    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return bytes(signing_key), bytes(verify_key)


def test_ed25519_signature_verifies() -> None:
    """An Ed25519-signed event verifies with the public key."""
    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    signing_key, verify_key = _make_ed25519_keypair()
    key_set = {"ed25519-test-001": verify_key}

    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="agent-1",
        key_id="ed25519-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Edit", "tool_args_hash": "sha256:abc"},
        key=signing_key,
        scheme=get_scheme("ed25519"),
    )
    event = Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="ed25519-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Edit", "tool_args_hash": "sha256:abc"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
        scheme_id="ed25519",
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert report.total_events == 1
    assert report.ok == 1
    assert report.all_ok
    assert report.scheme_counts == {"ed25519": 1}


def test_ed25519_wrong_key_fails() -> None:
    """An Ed25519-signed event fails verification with a different public key."""
    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    signing_key, _ = _make_ed25519_keypair()
    _, wrong_verify_key = _make_ed25519_keypair()
    key_set = {"ed25519-test-001": wrong_verify_key}

    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="agent-1",
        key_id="ed25519-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Edit"},
        key=signing_key,
        scheme=get_scheme("ed25519"),
    )
    event = Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="ed25519-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Edit"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
        scheme_id="ed25519",
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert report.signature_failed == 1
    assert not report.all_ok


def test_mixed_hmac_ed25519_bundle() -> None:
    """A bundle with both HMAC and Ed25519 events verifies correctly."""
    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    hmac_key = b"hmac-test-key-32bytes-long-enough"
    signing_key, verify_key = _make_ed25519_keypair()
    key_set = {
        "hmac-key-001": hmac_key,
        "ed25519-key-001": verify_key,
    }

    now = datetime.now(UTC)

    # HMAC event
    hmac_ev_id = uuid.uuid4()
    hmac_sig, hmac_chash, hmac_env = sign_event(
        event_id=hmac_ev_id,
        work_item_id=uuid.uuid4(),
        actor_id="agent-1",
        key_id="hmac-key-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read"},
        key=hmac_key,
    )
    hmac_event = Event(
        event_id=hmac_ev_id,
        work_item_id=uuid.uuid4(),
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="hmac-key-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read"},
        payload_canonical_hash=hmac_chash,
        signature=hmac_sig,
        canonical_envelope=hmac_env,
        scheme_id="hmac-sha256",
    )

    # Ed25519 event
    ed_ev_id = uuid.uuid4()
    ed_sig, ed_chash, ed_env = sign_event(
        event_id=ed_ev_id,
        work_item_id=uuid.uuid4(),
        actor_id="agent-2",
        key_id="ed25519-key-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Edit"},
        key=signing_key,
        scheme=get_scheme("ed25519"),
    )
    ed_event = Event(
        event_id=ed_ev_id,
        work_item_id=uuid.uuid4(),
        event_seq=0,
        actor_id="agent-2",
        actor_kind="agent",
        actor_metadata=None,
        key_id="ed25519-key-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Edit"},
        payload_canonical_hash=ed_chash,
        signature=ed_sig,
        canonical_envelope=ed_env,
        scheme_id="ed25519",
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([hmac_event, ed_event])
    assert report.total_events == 2
    assert report.ok == 2
    assert report.all_ok
    assert report.scheme_counts == {"hmac-sha256": 1, "ed25519": 1}

    # Report text should mention both schemes
    text = Verifier.format_report(report)
    assert "hmac-sha256" in text
    assert "ed25519" in text
    assert "Ed25519 (asymmetric) signatures were found" in text


# ----------------------------------------------------------------------
# Delegation chain validation tests
# ----------------------------------------------------------------------


def test_delegation_chain_valid(hmac_keys: Path) -> None:
    """A valid on_behalf_of delegation chain passes validation."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    delegation = {
        "principal_id": "human:alice",
        "session_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "authenticated_at": now.isoformat(),
        "scope": ["read", "write"],
    }
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
        payload={"tool": "Edit"},
        key=key_bytes,
        on_behalf_of=delegation,
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
        payload={"tool": "Edit"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
        on_behalf_of=delegation,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert len(report.delegation_chains) == 1
    dc = report.delegation_chains[0]
    assert dc.principal_id == "human:alice"
    assert dc.session_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert dc.validation_ok is True
    assert dc.validation_detail is None
    assert report.all_ok


def test_delegation_chain_expired(hmac_keys: Path) -> None:
    """An expired delegation chain is detected as invalid."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime, timedelta

    from regista._signing import sign_event
    from regista._types import Event

    ev_id = uuid.uuid4()
    wi_id = uuid.uuid4()
    now = datetime.now(UTC)
    # expires_at is in the past
    expired = (now - timedelta(hours=1)).isoformat()
    delegation = {
        "principal_id": "human:bob",
        "expires_at": expired,
    }
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
        payload={"tool": "Edit"},
        key=key_bytes,
        on_behalf_of=delegation,
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
        payload={"tool": "Edit"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
        on_behalf_of=delegation,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert len(report.delegation_chains) == 1
    dc = report.delegation_chains[0]
    assert dc.principal_id == "human:bob"
    assert dc.validation_ok is False
    assert dc.validation_detail is not None
    assert (
        "expired" in dc.validation_detail.lower()
        or "DELEGATION_CHAIN_EXPIRED" in dc.validation_detail
    )
    assert report.delegation_chain_failures == 1
    assert not report.all_ok


def test_no_delegation_chain(hmac_keys: Path) -> None:
    """Events without on_behalf_of produce no delegation chain entries."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

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
        payload={"tool": "Read"},
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
        payload={"tool": "Read"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert len(report.delegation_chains) == 0
    assert report.all_ok


# ----------------------------------------------------------------------
# Scheme count tests
# ----------------------------------------------------------------------


def test_scheme_counts_in_report(hmac_keys: Path) -> None:
    """Scheme counts are tracked in the report."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    now = datetime.now(UTC)
    events = []
    for i in range(3):
        ev_id = uuid.uuid4()
        sig, c_hash, env = sign_event(
            event_id=ev_id,
            work_item_id=uuid.uuid4(),
            actor_id="agent-1",
            key_id="cairn-test-001",
            event_seq=i,
            workflow_name="cairn_agent_actions",
            workflow_version=1,
            timestamp=now,
            transition="tool_call_begin",
            payload={"tool": "Read"},
            key=key_bytes,
        )
        events.append(
            Event(
                event_id=ev_id,
                work_item_id=uuid.uuid4(),
                event_seq=i,
                actor_id="agent-1",
                actor_kind="agent",
                actor_metadata=None,
                key_id="cairn-test-001",
                workflow_name="cairn_agent_actions",
                workflow_version=1,
                timestamp=now,
                transition="tool_call_begin",
                payload={"tool": "Read"},
                payload_canonical_hash=c_hash,
                signature=sig,
                canonical_envelope=env,
                scheme_id="hmac-sha256",
            )
        )

    verifier = Verifier(key_set)
    report = verifier.verify_events(events)
    assert report.scheme_counts == {"hmac-sha256": 3}
    assert report.all_ok


def test_verify_bundle_with_timestamp_batches(tmp_path: Path) -> None:
    """Verifier populates timestamp_batches from bundle and logs uncovered events."""
    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    key_bytes = b"supersecret-test-key-32bytes!!"
    key_set = {"cairn-test-001": key_bytes}

    ev_id = uuid.uuid4()
    now = datetime.now(UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=uuid.uuid4(),
        actor_id="agent-1",
        key_id="cairn-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read"},
        key=key_bytes,
    )
    ev = Event(
        event_id=ev_id,
        work_item_id=uuid.uuid4(),
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="cairn-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    ts_batch_id = str(uuid.uuid4())
    manifest: dict = {"events_count": 1}
    bundle: dict = {
        "manifest": manifest,
        "events": [ev.to_dict()],
        "timestamp_batches": [
            {
                "batch_id": ts_batch_id,
                "event_ids": [str(ev_id)],
                "merkle_root": "a" * 64,
                "status": "confirmed",
                "tsa_timestamp": now.isoformat(),
            }
        ],
    }
    canonical = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    manifest["bundle_hash"] = digest

    bundle_path = tmp_path / "bundle_ts.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))

    verifier = Verifier(key_set)
    report = verifier.verify_bundle(bundle_path)
    assert report.all_ok
    assert len(report.timestamp_batches) == 1
    assert report.timestamp_batches[0].batch_id == ts_batch_id
    assert report.timestamp_batches[0].status == "confirmed"
    assert report.timestamp_batches[0].event_count == 1


def test_verify_bundle_without_timestamp_batches(tmp_path: Path) -> None:
    """Verifier handles bundles without timestamp_batches gracefully."""
    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    key_bytes = b"supersecret-test-key-32bytes!!"
    key_set = {"cairn-test-001": key_bytes}

    ev_id = uuid.uuid4()
    now = datetime.now(UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=uuid.uuid4(),
        actor_id="agent-1",
        key_id="cairn-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read"},
        key=key_bytes,
    )
    ev = Event(
        event_id=ev_id,
        work_item_id=uuid.uuid4(),
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="cairn-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    manifest: dict = {"events_count": 1}
    bundle: dict = {"manifest": manifest, "events": [ev.to_dict()]}
    canonical = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    manifest["bundle_hash"] = digest

    bundle_path = tmp_path / "bundle_no_ts.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))

    verifier = Verifier(key_set)
    report = verifier.verify_bundle(bundle_path)
    assert report.all_ok
    assert report.timestamp_batches == []


def get_scheme(scheme_id: str):
    from regista._signing_scheme import get_scheme as _get_scheme

    return _get_scheme(scheme_id)


# ----------------------------------------------------------------------
# Tests for new verifier enforcement (v1 spec items 3, 4, 6, 8)
# ----------------------------------------------------------------------


def _make_signed_event(
    key_bytes: bytes,
    key_id: str = "cairn-test-001",
    event_seq: int = 0,
    transition: str = "tool_call_begin",
    payload: dict | None = None,
    timestamp=None,
    work_item_id=None,
):
    """Helper to create a signed event for verifier tests."""
    from datetime import UTC, datetime

    from regista._signing import sign_event
    from regista._types import Event

    ev_id = uuid.uuid4()
    wi_id = work_item_id or uuid.uuid4()
    now = timestamp or datetime.now(UTC)
    payload = payload or {"tool": "Read"}
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="agent-1",
        key_id=key_id,
        event_seq=event_seq,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition=transition,
        payload=payload,
        key=key_bytes,
    )
    return Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=event_seq,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id=key_id,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition=transition,
        payload=payload,
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )


def test_scope_coverage_no_violation(hmac_keys: Path) -> None:
    """Tool call with matching scope attestation passes."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    now = datetime.now(UTC)
    wi_id = uuid.uuid4()

    # Scope attestation event (predates tool call)
    scope_ev = _make_signed_event(
        key_bytes,
        event_seq=0,
        transition="scope_statement",
        payload={
            "harnesses": [{"name": "claude-code"}],
            "scope_statement": "full access",
            "version": "1",
            "principal_id": "test-user",
            "attested_at": now.isoformat(),
        },
        timestamp=now,
        work_item_id=wi_id,
    )

    # Tool call event (covered by scope)
    tool_ev = _make_signed_event(
        key_bytes,
        event_seq=1,
        transition="tool_call_begin",
        payload={"tool": "Read", "harness": "claude-code"},
        timestamp=now,
        work_item_id=wi_id,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([scope_ev, tool_ev])
    assert len(report.scope_violations) == 0
    assert report.all_ok


def test_scope_coverage_violation(hmac_keys: Path) -> None:
    """Tool call from harness not in scope is flagged."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from datetime import UTC, datetime

    now = datetime.now(UTC)
    wi_id = uuid.uuid4()

    # Scope attestation for claude-code only
    scope_ev = _make_signed_event(
        key_bytes,
        event_seq=0,
        transition="scope_statement",
        payload={
            "harnesses": [{"name": "claude-code"}],
            "scope_statement": "limited",
            "version": "1",
            "principal_id": "test-user",
            "attested_at": now.isoformat(),
        },
        timestamp=now,
        work_item_id=wi_id,
    )

    # Tool call from an unscoped harness
    tool_ev = _make_signed_event(
        key_bytes,
        event_seq=1,
        transition="tool_call_begin",
        payload={"tool": "Write", "harness": "opencode"},
        timestamp=now,
        work_item_id=wi_id,
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([scope_ev, tool_ev])
    assert len(report.scope_violations) == 1
    assert report.scope_violations[0].harness == "opencode"
    assert "not in active scope" in report.scope_violations[0].detail
    assert not report.all_ok


def test_scope_coverage_no_attestation(hmac_keys: Path) -> None:
    """Tool call with no scope attestation at all is flagged."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    tool_ev = _make_signed_event(
        key_bytes,
        transition="tool_call_begin",
        payload={"tool": "Read", "harness": "claude-code"},
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([tool_ev])
    assert len(report.scope_violations) == 1
    assert "No scope attestation" in report.scope_violations[0].detail


def test_key_revocation_event_detected(hmac_keys: Path) -> None:
    """key_revocation events are collected in the report."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    rev_ev = _make_signed_event(
        key_bytes,
        transition="tool_call_begin",
        payload={
            "tool": "key_revocation",
            "revoked_key_id": "some-key",
            "revoked_at": "2026-05-27T00:00:00Z",
        },
    )

    verifier = Verifier(key_set)
    report = verifier.verify_events([rev_ev])
    assert len(report.key_revocations) == 1
    assert report.key_revocations[0].key_id == "some-key"


def test_key_revocation_post_revocation_flagged(hmac_keys: Path) -> None:
    """Events signed after key revocation are flagged."""
    key_data = json.loads(hmac_keys.read_text())
    key_id = key_data["keys"][0]["key_id"]
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")

    from datetime import UTC, datetime

    before_revocation = datetime(2026, 1, 1, tzinfo=UTC)
    after_revocation = datetime(2026, 6, 1, tzinfo=UTC)

    # Key is revoked at 2026-03-01
    key_set = {key_id: key_bytes}
    key_meta = {key_id: {"role": "actor", "revoked_at": "2026-03-01T00:00:00Z"}}

    # Event signed before revocation — OK
    ev_before = _make_signed_event(
        key_bytes,
        key_id=key_id,
        event_seq=0,
        timestamp=before_revocation,
    )

    # Event signed after revocation — should be flagged
    ev_after = _make_signed_event(
        key_bytes,
        key_id=key_id,
        event_seq=1,
        timestamp=after_revocation,
    )

    verifier = Verifier(key_set, key_metadata=key_meta)
    report = verifier.verify_events([ev_before, ev_after])
    # Should have 2 entries: 1 for the key_revocation tool detection (none here)
    # + 1 for the post-revocation event
    violations = [kr for kr in report.key_revocations if kr.detail is not None]
    assert len(violations) == 1
    assert violations[0].event_id == str(ev_after.event_id)


def test_temporal_ordering_authenticated_after_event(hmac_keys: Path) -> None:
    """authenticated_at after event.timestamp is flagged."""
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_data["keys"][0]["key_id"]: key_bytes}

    from dataclasses import replace
    from datetime import UTC, datetime

    ev_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    auth_time = "2026-01-01T13:00:00Z"  # 1 hour AFTER event

    ev = _make_signed_event(
        key_bytes,
        timestamp=ev_time,
        transition="tool_call_begin",
        payload={"tool": "Read"},
    )
    # Inject on_behalf_of with authenticated_at after event time
    ev = replace(ev, on_behalf_of={
        "principal_id": "test-user",
        "authenticated_at": auth_time,
    })

    verifier = Verifier(key_set)
    report = verifier.verify_events([ev])
    tvs = [t for t in report.temporal_violations if t.kind == "authenticated_after_event"]
    assert len(tvs) == 1
    assert "authenticated_at" in tvs[0].detail


def test_role_gate_actor_signs_auditor_transition(hmac_keys: Path) -> None:
    """Actor key signing an auditor-only transition is flagged."""
    key_data = json.loads(hmac_keys.read_text())
    key_id = key_data["keys"][0]["key_id"]
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_id: key_bytes}
    key_meta = {key_id: {"role": "actor"}}

    ev = _make_signed_event(
        key_bytes,
        key_id=key_id,
        transition="auditor_attestation",
        payload={"verdict": "passed"},
    )

    verifier = Verifier(key_set, key_metadata=key_meta)
    report = verifier.verify_events([ev])
    assert len(report.role_gate_violations) == 1
    assert report.role_gate_violations[0].role == "actor"
    assert "auditor" in report.role_gate_violations[0].detail


def test_role_gate_auditor_signs_actor_transition(hmac_keys: Path) -> None:
    """Auditor key signing an actor-only transition is flagged."""
    key_data = json.loads(hmac_keys.read_text())
    key_id = key_data["keys"][0]["key_id"]
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_id: key_bytes}
    key_meta = {key_id: {"role": "auditor"}}

    ev = _make_signed_event(
        key_bytes,
        key_id=key_id,
        transition="tool_call_begin",
        payload={"tool": "Read"},
    )

    verifier = Verifier(key_set, key_metadata=key_meta)
    report = verifier.verify_events([ev])
    assert len(report.role_gate_violations) == 1
    assert report.role_gate_violations[0].role == "auditor"
    assert "actor" in report.role_gate_violations[0].detail


def test_role_gate_no_metadata_no_violation(hmac_keys: Path) -> None:
    """Without key_metadata, role gate is skipped (backward-compatible)."""
    key_data = json.loads(hmac_keys.read_text())
    key_id = key_data["keys"][0]["key_id"]
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_id: key_bytes}

    ev = _make_signed_event(
        key_bytes,
        key_id=key_id,
        transition="auditor_attestation",
        payload={"verdict": "passed"},
    )

    # No key_metadata — role gate should not fire
    verifier = Verifier(key_set)
    report = verifier.verify_events([ev])
    assert len(report.role_gate_violations) == 0


def test_role_gate_matching_role_no_violation(hmac_keys: Path) -> None:
    """Actor signing actor-transition and auditor signing auditor-transition is OK."""
    key_data = json.loads(hmac_keys.read_text())
    key_id = key_data["keys"][0]["key_id"]
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_id: key_bytes}
    key_meta = {key_id: {"role": "actor"}}

    ev = _make_signed_event(
        key_bytes,
        key_id=key_id,
        transition="tool_call_begin",
        payload={"tool": "Read"},
    )

    verifier = Verifier(key_set, key_metadata=key_meta)
    report = verifier.verify_events([ev])
    assert len(report.role_gate_violations) == 0


def test_all_ok_includes_new_checks(hmac_keys: Path) -> None:
    """all_ok returns False when any new violation type is present."""
    key_data = json.loads(hmac_keys.read_text())
    key_id = key_data["keys"][0]["key_id"]
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    key_set = {key_id: key_bytes}
    key_meta = {key_id: {"role": "actor"}}

    # Auditor signing actor transition — role violation
    ev = _make_signed_event(
        key_bytes,
        key_id=key_id,
        transition="tool_call_begin",
        payload={"tool": "Read"},
    )

    verifier = Verifier(key_set, key_metadata={key_id: {"role": "auditor"}})
    report = verifier.verify_events([ev])
    assert not report.all_ok


# ---------------------------------------------------------------------------
# BC-229: TSA signature verification
# ---------------------------------------------------------------------------


def _build_signed_tsa_token(merkle_root: bytes, cert, private_key) -> bytes:
    """Build a minimal CMS-signed TSA token for testing."""
    import hashlib

    from asn1crypto import algos, cms, core, tsp as asn1tsp
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    hash_algo = "sha256"
    digest = hashlib.sha256(merkle_root).digest()
    tst_info = asn1tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.5",
            "message_imprint": asn1tsp.MessageImprint(
                {
                    "hash_algorithm": {"algorithm": hash_algo},
                    "hashed_message": digest,
                }
            ),
            "serial_number": 1,
            "gen_time": "20260101000000Z",
        }
    )
    tst_info_der = tst_info.dump()

    encap = cms.EncapsulatedContentInfo({"content_type": "tst_info"})
    encap["content"] = core.ParsableOctetString(tst_info_der)

    md = hashlib.sha256(tst_info_der).digest()
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [md]}),
        ]
    )

    data_to_sign = signed_attrs.untag().dump()
    signature = private_key.sign(data_to_sign, padding.PKCS1v15(), crypto_hashes.SHA256())

    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.IssuerAndSerialNumber(
                {"issuer": cert.issuer, "serial_number": cert.serial_number}
            ),
            "digest_algorithm": {"algorithm": "sha256"},
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signed_attrs": signed_attrs,
            "signature": signature,
        }
    )

    signed = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": encap,
            "certificates": [cms.CertificateChoices({"certificate": cert})],
            "signer_infos": [signer_info],
        }
    )
    ci = cms.ContentInfo({"content_type": "signed_data", "content": signed})
    return ci.dump()


def _generate_test_cert():
    """Generate a self-signed RSA certificate for testing."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def test_tsa_signature_verification_with_trust_anchor(tmp_path: Path) -> None:
    """BC-229: verify_tsa_token_full verifies CMS signature against trust anchor."""
    from asn1crypto import x509 as asn1_x509
    from cryptography.hazmat.primitives import serialization
    from regista._timestamping import TSAConfig, verify_tsa_token_full

    cert_pem, key = _generate_test_cert()
    cert_der = cert_pem.public_bytes(serialization.Encoding.DER)
    cert_asn1 = asn1_x509.Certificate.load(cert_der)

    merkle_root = hashlib.sha256(b"test-merkle").digest()
    token = _build_signed_tsa_token(merkle_root, cert_asn1, key)

    # Write trust anchor to file
    anchor_path = tmp_path / "tsa-cert.pem"
    anchor_path.write_bytes(cert_pem.public_bytes(serialization.Encoding.PEM))

    config = TSAConfig(tsa_url="", tsa_cert_path=str(anchor_path))
    ok, detail = verify_tsa_token_full(token, merkle_root, config)
    assert ok, f"Expected verification to pass, got: {detail}"
    assert "verified" in detail.lower() or "ok" in detail.lower()


def test_tsa_signature_verification_wrong_anchor(tmp_path: Path) -> None:
    """BC-229: verify_tsa_token_full rejects token signed by different key."""
    from asn1crypto import x509 as asn1_x509
    from cryptography.hazmat.primitives import serialization
    from regista._timestamping import TSAConfig, verify_tsa_token_full

    cert_pem, key = _generate_test_cert()
    cert_der = cert_pem.public_bytes(serialization.Encoding.DER)
    cert_asn1 = asn1_x509.Certificate.load(cert_der)

    merkle_root = hashlib.sha256(b"test-merkle").digest()
    token = _build_signed_tsa_token(merkle_root, cert_asn1, key)

    # Write a DIFFERENT cert as trust anchor
    other_cert, _ = _generate_test_cert()
    anchor_path = tmp_path / "wrong-cert.pem"
    anchor_path.write_bytes(other_cert.public_bytes(serialization.Encoding.PEM))

    config = TSAConfig(tsa_url="", tsa_cert_path=str(anchor_path))
    ok, detail = verify_tsa_token_full(token, merkle_root, config)
    assert not ok, f"Expected verification to fail with wrong anchor, got: {detail}"


def test_tsa_no_trust_anchor_skips_signature(tmp_path: Path) -> None:
    """BC-229: without tsa_cert_path, only message imprint is checked."""
    from asn1crypto import x509 as asn1_x509
    from cryptography.hazmat.primitives import serialization
    from regista._timestamping import TSAConfig, verify_tsa_token_full

    cert_pem, key = _generate_test_cert()
    cert_der = cert_pem.public_bytes(serialization.Encoding.DER)
    cert_asn1 = asn1_x509.Certificate.load(cert_der)

    merkle_root = hashlib.sha256(b"test-merkle").digest()
    token = _build_signed_tsa_token(merkle_root, cert_asn1, key)

    config = TSAConfig(tsa_url="")  # No tsa_cert_path
    ok, detail = verify_tsa_token_full(token, merkle_root, config)
    assert ok
    assert "not checked" in detail.lower() or "imprint" in detail.lower()


def test_verifier_timestamp_signature_verification(tmp_path: Path) -> None:
    """BC-229: Verifier._verify_timestamp_signatures sets verified field."""
    import datetime

    from asn1crypto import x509 as asn1_x509
    from cryptography.hazmat.primitives import serialization
    from regista._signing import sign_event
    from regista._types import Event

    key_bytes = b"supersecret-test-key-32bytes!!"
    key_set = {"cairn-test-001": key_bytes}

    # Generate TSA cert and build a signed token
    cert_pem, tsa_key = _generate_test_cert()
    cert_der = cert_pem.public_bytes(serialization.Encoding.DER)
    cert_asn1 = asn1_x509.Certificate.load(cert_der)

    merkle_root_hex = "aa" * 32
    merkle_root = bytes.fromhex(merkle_root_hex)
    token = _build_signed_tsa_token(merkle_root, cert_asn1, tsa_key)
    token_hex = token.hex()

    # Write trust anchor
    anchor_path = tmp_path / "tsa-cert.pem"
    anchor_path.write_bytes(cert_pem.public_bytes(serialization.Encoding.PEM))

    # Build a signed event
    ev_id = uuid.uuid4()
    now = datetime.datetime.now(datetime.UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=uuid.uuid4(),
        actor_id="agent-1",
        key_id="cairn-test-001",
        event_seq=0,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read"},
        key=key_bytes,
    )
    ev = Event(
        event_id=ev_id,
        work_item_id=uuid.uuid4(),
        event_seq=0,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id="cairn-test-001",
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition="tool_call_begin",
        payload={"tool": "Read"},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )

    ts_batch_id = str(uuid.uuid4())
    manifest: dict = {"events_count": 1}
    bundle: dict = {
        "manifest": manifest,
        "events": [ev.to_dict()],
        "timestamp_batches": [
            {
                "batch_id": ts_batch_id,
                "event_ids": [str(ev_id)],
                "merkle_root": merkle_root_hex,
                "status": "confirmed",
                "tsa_timestamp": now.isoformat(),
                "tsa_token": token_hex,
            }
        ],
    }
    canonical = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    manifest["bundle_hash"] = digest

    bundle_path = tmp_path / "bundle_ts_verify.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))

    # Verify WITH trust anchor
    verifier = Verifier(key_set, tsa_cert_path=str(anchor_path))
    report = verifier.verify_bundle(bundle_path)
    assert report.all_ok
    assert len(report.timestamp_batches) == 1
    assert report.timestamp_batches[0].verified is True
    assert report.timestamp_batches[0].verification_detail is not None

    # Verify WITHOUT trust anchor — verified should be None
    verifier_no_anchor = Verifier(key_set)
    report_no_anchor = verifier_no_anchor.verify_bundle(bundle_path)
    assert report_no_anchor.all_ok
    assert report_no_anchor.timestamp_batches[0].verified is None
