"""Unit tests for Cairn adapter and verifier."""

from __future__ import annotations

import hashlib
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
    substrate_instance.register_workflow_file("workflows/cairn_agent_actions.yaml")


@pytest.fixture
def adapter(substrate_instance: Substrate, workflow_registered: None) -> CairnAdapter:
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
        principal_id="human:owner",
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


def test_verify_bundle_with_valid_hash(hmac_keys: Path, tmp_path: Path) -> None:
    import hashlib

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

    from substrate._signing import sign_event
    from substrate._types import Event

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

    from substrate._signing import sign_event
    from substrate._types import Event

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

    from substrate._signing import sign_event
    from substrate._types import Event

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

    from substrate._signing import sign_event
    from substrate._types import Event

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

    from substrate._signing import sign_event
    from substrate._types import Event

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

    from substrate._signing import sign_event
    from substrate._types import Event

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

    from substrate._signing import sign_event
    from substrate._types import Event

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

    from substrate._signing import sign_event
    from substrate._types import Event

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

    verifier = Verifier(key_set)
    report = verifier.verify_events([event])
    assert len(report.key_rotations) == 0
    assert report.key_rotation_failures == 0
    assert report.all_ok
