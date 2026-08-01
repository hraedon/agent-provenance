"""WI-011: verifier coverage for session-entity paths.

The session-entity support (WI-004..WI-009) added an ``entity_kind`` axis to
the log, but the cairn verifier paths that consume it lacked direct tests.
This module locks in the cairn-owned behaviour:

* **WI-007** — sequence checks group by ``(entity_kind, entity_id)``, so a
  ``work_item`` and a ``session`` that share one UUID are verified as two
  distinct entities (no false gap), while a real gap in either is still caught.
* **WI-008** — events carrying a populated ``global_seq`` verify correctly; the
  field is genuinely bound into the signature (a tampered ``global_seq`` fails).
* session events participate in the global hash chain (``prev_global_event_hash``)
  across entity kinds without contiguity violations.

The concurrent allocation of non-work-item sequences (WI-011 item 1) lives in
regista's ``EventStore`` (``test_concurrency.py``) and is exercised there — it is
not cairn code. The OpenCode plugin ``session.started`` event handler (item 2) is
covered by the Bun suite in ``integrations/opencode``.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from regista._signing import sign_event
from regista._types import Event

from cairn.verifier import Verifier

_KEY_ID = "cairn-test-001"


def _key_material(hmac_keys: Path) -> tuple[bytes, dict[str, bytes]]:
    key_data = json.loads(hmac_keys.read_text())
    key_bytes = key_data["keys"][0]["secret"].encode("utf-8")
    return key_bytes, {key_data["keys"][0]["key_id"]: key_bytes}


def _make_event(
    key_bytes: bytes,
    *,
    entity_id: uuid.UUID,
    seq: int,
    entity_kind: str = "work_item",
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
    transition: str = "tool_call_begin",
    timestamp: datetime | None = None,
    event_id: uuid.UUID | None = None,
) -> Event:
    """Build a signed event for *entity_id* under *entity_kind*.

    ``work_item_id`` is set to *entity_id* so ``effective_entity_id`` resolves to
    it for both kinds; the ``entity_kind`` is what the verifier groups on.
    """
    ev_id = event_id or uuid.uuid4()
    now = timestamp or datetime.now(UTC)
    payload = {"tool": "Read", "tool_args_hash": f"sha256:{seq}"}
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=entity_id,
        actor_id="agent-1",
        key_id=_KEY_ID,
        event_seq=seq,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition=transition,
        payload=payload,
        key=key_bytes,
        global_seq=global_seq,
        prev_global_event_hash=prev_global_event_hash,
        entity_kind=entity_kind,
        actor_kind="agent",
    )
    return Event(
        event_id=ev_id,
        work_item_id=entity_id,
        event_seq=seq,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=None,
        key_id=_KEY_ID,
        workflow_name="cairn_agent_actions",
        workflow_version=1,
        timestamp=now,
        transition=transition,
        payload=payload,
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
        global_seq=global_seq,
        prev_global_event_hash=prev_global_event_hash,
        entity_kind=entity_kind,
        entity_id=entity_id,
    )


# ---------------------------------------------------------------------------
# WI-007 — mixed entity kinds sharing one UUID
# ---------------------------------------------------------------------------


def test_session_entity_event_verifies(hmac_keys: Path) -> None:
    """A lone session-entity event verifies through the cairn verifier."""
    key_bytes, key_set = _key_material(hmac_keys)
    ev = _make_event(
        key_bytes,
        entity_id=uuid.uuid4(),
        seq=0,
        entity_kind="session",
        transition="session_attestation",
    )
    report = Verifier(key_set).verify_events([ev])
    assert report.ok == 1
    assert report.entries[0].result == "ok"


def test_mixed_entity_kinds_sharing_uuid_are_separate_entities(hmac_keys: Path) -> None:
    """A work_item and a session sharing one UUID, each with seq 0,1, must NOT
    produce a false sequence gap (WI-007 groups by (entity_kind, entity_id))."""
    key_bytes, key_set = _key_material(hmac_keys)
    shared = uuid.uuid4()
    base = datetime.now(UTC)
    events = [
        _make_event(key_bytes, entity_id=shared, seq=0, entity_kind="work_item",
                    timestamp=base),
        _make_event(key_bytes, entity_id=shared, seq=1, entity_kind="work_item",
                    timestamp=base),
        _make_event(key_bytes, entity_id=shared, seq=0, entity_kind="session",
                    transition="session_attestation", timestamp=base),
        _make_event(key_bytes, entity_id=shared, seq=1, entity_kind="session",
                    transition="session_attestation", timestamp=base),
    ]
    report = Verifier(key_set).verify_events(events)
    assert report.sequence_gaps == []
    assert report.all_ok


def test_mixed_entity_kinds_a_gap_in_one_kind_is_still_detected(
    hmac_keys: Path,
) -> None:
    """The separate-grouping must not hide a real gap: a work_item log missing
    seq 1 is flagged even though a contiguous session shares the same UUID."""
    key_bytes, key_set = _key_material(hmac_keys)
    shared = uuid.uuid4()
    base = datetime.now(UTC)
    events = [
        # work_item: seq 0, 2 — gap at 1
        _make_event(key_bytes, entity_id=shared, seq=0, entity_kind="work_item",
                    timestamp=base),
        _make_event(key_bytes, entity_id=shared, seq=2, entity_kind="work_item",
                    timestamp=base),
        # session: contiguous 0, 1 — must not be implicated
        _make_event(key_bytes, entity_id=shared, seq=0, entity_kind="session",
                    transition="session_attestation", timestamp=base),
        _make_event(key_bytes, entity_id=shared, seq=1, entity_kind="session",
                    transition="session_attestation", timestamp=base),
    ]
    report = Verifier(key_set).verify_events(events)
    gaps = [g for g in report.sequence_gaps if g.kind == "missing_seq"]
    assert len(gaps) == 1
    assert gaps[0].expected_seq == 1
    assert gaps[0].actual_seq == 2


# ---------------------------------------------------------------------------
# WI-008 — v2 events with a populated global_seq
# ---------------------------------------------------------------------------


def test_event_with_populated_global_seq_verifies(hmac_keys: Path) -> None:
    """An event carrying global_seq verifies ok end to end (WI-008 regression:
    the verifier must thread global_seq through to signature verification)."""
    key_bytes, key_set = _key_material(hmac_keys)
    ev = _make_event(key_bytes, entity_id=uuid.uuid4(), seq=0, global_seq=5)
    report = Verifier(key_set).verify_events([ev])
    assert report.ok == 1
    assert report.entries[0].result == "ok"


def test_global_seq_is_bound_into_the_signed_envelope(hmac_keys: Path) -> None:
    """global_seq is part of what the signature covers: two events identical in
    every other field but global_seq produce different signed envelopes. This is
    the invariant WI-008 relies on — a populated global_seq cannot be altered
    without invalidating the signature."""
    key_bytes, _key_set = _key_material(hmac_keys)
    entity_id = uuid.uuid4()
    ev_id = uuid.uuid4()
    now = datetime.now(UTC)
    # Two events identical in every field but global_seq.
    ev_a = _make_event(key_bytes, entity_id=entity_id, seq=0, global_seq=5,
                       event_id=ev_id, timestamp=now)
    ev_b = _make_event(key_bytes, entity_id=entity_id, seq=0, global_seq=6,
                       event_id=ev_id, timestamp=now)
    assert bytes(ev_a.canonical_envelope) != bytes(ev_b.canonical_envelope)
    assert ev_a.signature != ev_b.signature


def test_mixed_legacy_and_global_seq_events_both_verify(hmac_keys: Path) -> None:
    """The WI-008 fix must not break OLD events: a batch mixing a legacy event
    (no global_seq) and a v2 event (populated global_seq) verifies cleanly."""
    key_bytes, key_set = _key_material(hmac_keys)
    base = datetime.now(UTC)
    legacy = _make_event(key_bytes, entity_id=uuid.uuid4(), seq=0,
                         global_seq=None, timestamp=base)
    modern = _make_event(key_bytes, entity_id=uuid.uuid4(), seq=0,
                         global_seq=9, timestamp=base)
    assert legacy.global_seq is None  # genuinely a pre-global_seq event
    report = Verifier(key_set).verify_events([legacy, modern])
    assert report.ok == 2
    assert all(e.result == "ok" for e in report.entries)


# ---------------------------------------------------------------------------
# session events in the global hash chain
# ---------------------------------------------------------------------------


def test_session_event_chains_across_entity_kinds(hmac_keys: Path) -> None:
    """A session event chained via prev_global_event_hash to a preceding
    work_item event produces no chain-contiguity violation."""
    key_bytes, key_set = _key_material(hmac_keys)
    base = datetime.now(UTC)
    ev1 = _make_event(key_bytes, entity_id=uuid.uuid4(), seq=0,
                      entity_kind="work_item", global_seq=1, timestamp=base)
    link = hashlib.sha256(
        bytes(ev1.canonical_envelope) + bytes(ev1.signature)
    ).digest()
    ev2 = _make_event(
        key_bytes,
        entity_id=uuid.uuid4(),
        seq=0,
        entity_kind="session",
        transition="session_attestation",
        global_seq=2,
        prev_global_event_hash=link,
        timestamp=base,
    )
    report = Verifier(key_set).verify_events([ev1, ev2])
    assert report.chain_contiguity_violations == []
    assert report.ok == 2


def test_session_event_with_a_broken_chain_link_is_detected(hmac_keys: Path) -> None:
    """A wrong prev_global_event_hash on a session event is a contiguity
    violation — the chain walk is not bypassed for non-work-item entities."""
    key_bytes, key_set = _key_material(hmac_keys)
    base = datetime.now(UTC)
    ev1 = _make_event(key_bytes, entity_id=uuid.uuid4(), seq=0,
                      entity_kind="work_item", global_seq=1, timestamp=base)
    ev2 = _make_event(
        key_bytes,
        entity_id=uuid.uuid4(),
        seq=0,
        entity_kind="session",
        transition="session_attestation",
        global_seq=2,
        prev_global_event_hash=b"\x00" * 32,  # wrong link
        timestamp=base,
    )
    report = Verifier(key_set).verify_events([ev1, ev2])
    assert report.chain_contiguity_violations
    assert not report.all_ok
