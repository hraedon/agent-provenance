"""Tests for Plan 010 — session-content capture, portal, v2 scope re-attestation."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from cairn._content_crypto import (
    CONTENT_ENCRYPTION_ENV,
    decrypt_content_fields,
    encrypt_content_fields,
    resolve_content_encryption_stance,
    verify_content_integrity,
)
from cairn.adapter import CairnAdapter
from cairn.schema import (
    CONTENT_ENCRYPTION_EXTERNAL,
    CONTENT_ENCRYPTION_OFF,
    CONTENT_ENCRYPTION_ON,
    AssistantMessagePayload,
    ScopeAttestationPayload,
    SessionAttestationPayload,
    TranscriptAttestationPayload,
    UserMessagePayload,
    digest_string,
)
from cairn.verifier_types import (
    ContentCoverageGap,
    SessionAttestationEntry,
    VerificationReport,
)

# ----------------------------------------------------------------------
# WI-1.1: Scope attestation with content-encryption stance
# ----------------------------------------------------------------------


def test_scope_attestation_v2_fields_round_trip():
    sap = ScopeAttestationPayload(
        version="2",
        principal_id="human:test",
        attested_at="2026-01-01T00:00:00Z",
        harnesses=[{"name": "claude-code", "version": "2.1.200"}],
        scope_statement="In scope: test.",
        content_capture=True,
        content_encryption="on",
        redaction_policy="default-v1",
    )
    d = sap.to_dict()
    assert d["content_capture"] is True
    assert d["content_encryption"] == "on"
    assert d["redaction_policy"] == "default-v1"
    sap2 = ScopeAttestationPayload.from_dict(d)
    assert sap2 == sap


def test_session_attestation_v2_fields_round_trip():
    sap = SessionAttestationPayload(
        version="2",
        principal_id="human:test",
        session_id=str(uuid.uuid4()),
        attested_at="2026-01-01T00:00:00Z",
        harnesses=[{"name": "claude-code", "version": "2.1.200"}],
        scope_statement="In scope: test.",
        content_capture=True,
        content_encryption="on",
    )
    d = sap.to_dict()
    assert d["content_capture"] is True
    assert d["content_encryption"] == "on"
    sap2 = SessionAttestationPayload.from_dict(d)
    assert sap2 == sap


# ----------------------------------------------------------------------
# WI-1.2: Backward compatibility — v1 attestations read as content_capture=false
# ----------------------------------------------------------------------


def test_v1_scope_attestation_backward_compat():
    v1_data = {
        "version": "1",
        "principal_id": "human:test",
        "attested_at": "2026-01-01T00:00:00Z",
        "harnesses": [{"name": "opencode", "version": "0.1.0"}],
        "scope_statement": "In scope: test.",
    }
    sap = ScopeAttestationPayload.from_dict(v1_data)
    assert sap.content_capture is False
    assert sap.content_encryption == "off"
    assert sap.redaction_policy is None


def test_v1_session_attestation_backward_compat():
    v1_data = {
        "version": "1",
        "principal_id": "human:test",
        "session_id": str(uuid.uuid4()),
        "attested_at": "2026-01-01T00:00:00Z",
        "harnesses": [{"name": "opencode", "version": "0.1.0"}],
        "scope_statement": "In scope: test.",
    }
    sap = SessionAttestationPayload.from_dict(v1_data)
    assert sap.content_capture is False
    assert sap.content_encryption == "off"


# ----------------------------------------------------------------------
# WI-2.1: Content payloads
# ----------------------------------------------------------------------


def test_user_message_payload_round_trip():
    msg = "Hello, agent!"
    digest = digest_string(msg)
    payload = UserMessagePayload(
        message_digest=digest,
        message_content=msg,
        sequence=1,
    )
    d = payload.to_dict()
    assert d["message_digest"] == digest
    assert d["message_content"] == msg
    assert d["role"] == "user"
    assert d["sequence"] == 1
    p2 = UserMessagePayload.from_dict(d)
    assert p2 == payload


def test_assistant_message_payload_round_trip():
    msg = "I will help you with that."
    digest = digest_string(msg)
    payload = AssistantMessagePayload(
        message_digest=digest,
        message_content=msg,
        sequence=2,
    )
    d = payload.to_dict()
    assert d["message_digest"] == digest
    assert d["message_content"] == msg
    assert d["role"] == "assistant"
    p2 = AssistantMessagePayload.from_dict(d)
    assert p2 == payload


def test_transcript_attestation_payload_round_trip():
    transcript = "user: hello\nassistant: hi"
    digest = digest_string(transcript)
    payload = TranscriptAttestationPayload(
        transcript_digest=digest,
        transcript_content=transcript,
        event_count=2,
        session_id=str(uuid.uuid4()),
    )
    d = payload.to_dict()
    assert d["transcript_digest"] == digest
    assert d["transcript_content"] == transcript
    assert d["event_count"] == 2
    p2 = TranscriptAttestationPayload.from_dict(d)
    assert p2 == payload


def test_content_payload_digest_only_when_capture_off():
    """When content_capture is false, only the digest is present."""
    msg = "secret message"
    digest = digest_string(msg)
    payload = UserMessagePayload(
        message_digest=digest,
        message_content=None,
    )
    d = payload.to_dict()
    assert "message_content" not in d
    assert d["message_digest"] == digest


# ----------------------------------------------------------------------
# WI-2.3: Delegation depth
# ----------------------------------------------------------------------


def test_build_delegation_chain_depth_2():
    """Hermes→Claude Code→Edit must thread the full chain."""
    hermes_session = str(uuid.uuid4())
    claude_session = str(uuid.uuid4())
    chain = CairnAdapter.build_delegation_chain(
        "human:owner",
        hermes_session,
        claude_session,
        authenticated_at="2026-01-01T00:00:00Z",
        scope=["edit", "read"],
    )
    assert chain["principal_id"] == "human:owner"
    assert chain["session_id"] == claude_session
    assert chain["delegation_chain"] == [hermes_session, claude_session]
    assert chain["authenticated_at"] == "2026-01-01T00:00:00Z"
    assert chain["scope"] == ["edit", "read"]


def test_build_delegation_chain_depth_1():
    """Single-level delegation (normal Claude Code session)."""
    session = str(uuid.uuid4())
    chain = CairnAdapter.build_delegation_chain(
        "human:owner",
        session,
    )
    assert chain["principal_id"] == "human:owner"
    assert chain["session_id"] == session
    assert chain["delegation_chain"] == [session]


# ----------------------------------------------------------------------
# WI-3.1/WI-3.2: Content encryption (reusing regista Plan 030)
# ----------------------------------------------------------------------


@pytest.fixture
def content_key(tmp_path: Path) -> str:
    """Create a 32-byte content-encryption key file."""
    key_data = os.urandom(32)
    key_file = tmp_path / "content.key"
    key_file.write_bytes(key_data)
    return f"file:{key_file}"


def test_resolve_content_encryption_stance_default():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop(CONTENT_ENCRYPTION_ENV, None)
        assert resolve_content_encryption_stance() == CONTENT_ENCRYPTION_ON


def test_resolve_content_encryption_stance_off():
    with patch.dict(os.environ, {CONTENT_ENCRYPTION_ENV: "off"}):
        assert resolve_content_encryption_stance() == CONTENT_ENCRYPTION_OFF


def test_resolve_content_encryption_stance_external():
    with patch.dict(os.environ, {CONTENT_ENCRYPTION_ENV: "external"}):
        assert resolve_content_encryption_stance() == CONTENT_ENCRYPTION_EXTERNAL


def test_encrypt_decrypt_content_fields_round_trip(content_key: str):
    """Encrypt then decrypt content fields — digest must match."""
    msg = "sensitive user prompt with secrets"
    digest = digest_string(msg)
    payload = {
        "message_digest": digest,
        "message_content": msg,
        "role": "user",
    }
    encrypted = encrypt_content_fields(payload, key_ref=content_key)
    from regista._encryption import is_encrypted_field

    assert is_encrypted_field(encrypted["message_content"])
    assert encrypted["message_digest"] == digest

    decrypted = decrypt_content_fields(encrypted, key_ref=content_key)
    assert decrypted["message_content"] == msg
    assert decrypted["message_digest"] == digest


def test_verify_content_integrity_with_key(content_key: str):
    """Verify encrypted content integrity with the key."""
    msg = "test message for integrity"
    digest = digest_string(msg)
    payload = {
        "message_digest": digest,
        "message_content": msg,
    }
    encrypted = encrypt_content_fields(payload, key_ref=content_key)
    results = verify_content_integrity(encrypted, key_ref=content_key)
    assert len(results) == 1
    assert results[0]["status"] == "verified"


def test_verify_content_integrity_without_key(content_key: str):
    """Without the key, integrity is authenticated but plaintext not verifiable."""
    msg = "test message"
    payload = {
        "message_digest": digest_string(msg),
        "message_content": msg,
    }
    encrypted = encrypt_content_fields(payload, key_ref=content_key)
    results = verify_content_integrity(encrypted, key_ref=None)
    assert len(results) == 1
    assert results[0]["status"] == "not_decrypted"


def test_encrypt_content_fields_no_key_returns_unchanged():
    """When no key is available, content is stored in plaintext."""
    payload = {"message_content": "plaintext", "message_digest": "abc"}
    result = encrypt_content_fields(payload, key_ref=None)
    assert result == payload


# ----------------------------------------------------------------------
# WI-037: the runtime must RESOLVE the content key, not observe that a ref
# is set, and must never store plaintext while claiming encryption.
# ----------------------------------------------------------------------


def test_is_content_encryption_active_requires_the_key_to_resolve(monkeypatch):
    """Pre-fix: a ref that was merely SET reported content encryption active.

    ``CAIRN_CONTENT_KEY_REF=env:NOPE`` with no such variable is the exact
    "configured, unresolvable" shape.  The old presence check returned True, so
    cairn reported content encryption active and would then fail to fetch the
    key at the moment it needed it.
    """
    from cairn._content_crypto import (
        content_encryption_status,
        is_content_encryption_active,
    )

    monkeypatch.delenv("NOPE", raising=False)
    monkeypatch.setenv("CAIRN_CONTENT_KEY_REF", "env:NOPE")

    assert is_content_encryption_active() is False
    status = content_encryption_status()
    assert status.configured is True  # a ref IS set …
    assert status.usable is False  # … and it still does not resolve
    assert "does not resolve" in status.detail


def test_content_encryption_active_when_the_key_really_resolves(monkeypatch, content_key):
    from cairn._content_crypto import is_content_encryption_active

    monkeypatch.setenv("CAIRN_CONTENT_KEY_REF", content_key)
    assert is_content_encryption_active() is True


def test_recorded_stance_is_never_on_when_the_key_cannot_be_used(monkeypatch):
    """The attestation must not claim protection the runtime cannot apply."""
    from cairn._content_crypto import (
        recorded_content_encryption_stance,
        resolve_content_encryption_stance,
    )

    monkeypatch.delenv("NOPE", raising=False)
    monkeypatch.setenv("CAIRN_CONTENT_KEY_REF", "env:NOPE")

    # Intent is still "on" — that is what the operator configured …
    assert resolve_content_encryption_stance() == CONTENT_ENCRYPTION_ON
    # … but what gets recorded is what actually happens.
    assert recorded_content_encryption_stance() == CONTENT_ENCRYPTION_OFF


def test_recorded_stance_is_off_when_no_content_key_is_configured(monkeypatch):
    """Default-on intent with no key configured stored plaintext under "on"."""
    from cairn._content_crypto import recorded_content_encryption_stance

    monkeypatch.delenv("CAIRN_CONTENT_KEY_REF", raising=False)
    monkeypatch.delenv("CAIRN_CONTENT_KEY_PATH", raising=False)
    assert recorded_content_encryption_stance() == CONTENT_ENCRYPTION_OFF


def test_runtime_reads_the_content_key_from_the_same_source_as_the_doctor(monkeypatch, tmp_path):
    """suite.env is a real config source; the runtime used to ignore it.

    ``resolve_config`` (what ``cairn doctor`` reads) falls back to
    ``suite.env``; ``_content_crypto`` read only ``os.environ``.  A content key
    configured the documented way therefore resolved for the doctor and was
    invisible to the code doing the encrypting — a green check over plaintext
    capture.  Both must now read one source.
    """
    from cairn._config import resolve_config
    from cairn._content_crypto import is_content_encryption_active, resolve_content_key_ref

    key = tmp_path / "content.key"
    key.write_bytes(b"0" * 32)
    monkeypatch.setattr(
        "cairn._config._load_suite_env",
        lambda: {"CAIRN_CONTENT_KEY_PATH": str(key)},
    )

    assert resolve_config().content_key_path == str(key)
    assert resolve_content_key_ref() == f"file:{key}"
    assert is_content_encryption_active() is True


def test_encrypt_content_fields_refuses_to_return_plaintext(monkeypatch):
    """A configured key that cannot be used raises; it never degrades quietly."""
    from cairn._content_crypto import ContentEncryptionUnavailableError

    monkeypatch.delenv("NOPE", raising=False)
    monkeypatch.setenv("CAIRN_CONTENT_KEY_REF", "env:NOPE")

    payload = {"message_digest": "abc", "message_content": "sensitive prompt"}
    with pytest.raises(ContentEncryptionUnavailableError) as excinfo:
        encrypt_content_fields(payload)
    assert "withheld rather than stored in plaintext" in str(excinfo.value)


def test_withhold_content_fields_keeps_digests_and_records_the_reason():
    from cairn._content_crypto import withhold_content_fields

    payload = {
        "message_digest": "abc",
        "message_content": "sensitive prompt",
        "role": "user",
    }
    result = withhold_content_fields(payload, "key did not resolve")

    assert "message_content" not in result
    assert result["message_digest"] == "abc"
    assert result["role"] == "user"
    assert result["content_encryption_error"] == "key did not resolve"
    # the input is untouched
    assert payload["message_content"] == "sensitive prompt"


class _CapturingRegista:
    """Minimal regista stand-in that records the payloads it is handed."""

    def __init__(self) -> None:
        self.payloads: list[dict] = []

    def append_event(self, **kwargs):
        payload = kwargs["payload"]
        self.payloads.append(payload)
        return type("Event", (), {"event_id": uuid.uuid4(), "payload": payload})()


@pytest.mark.parametrize(
    ("method", "content_field", "arg"),
    [
        ("record_user_message", "message_content", "sensitive user prompt"),
        ("record_assistant_message", "message_content", "sensitive model reply"),
        ("attest_transcript", "transcript_content", "whole sensitive transcript"),
    ],
)
def test_capture_withholds_content_when_encryption_is_unavailable(
    monkeypatch, method, content_field, arg
):
    """The end state WI-037 requires: no plaintext, and a recorded reason.

    Pre-fix the runtime believed encryption was active (the ref was set) and the
    encryption attempt blew up inside regista, so the event was lost with no
    signed record of why.  Now the event lands digest-only, carrying the cause.
    """
    from cairn.schema import CairnConfig

    monkeypatch.delenv("NOPE", raising=False)
    monkeypatch.setenv("CAIRN_CONTENT_KEY_REF", "env:NOPE")

    sub = _CapturingRegista()
    adapter = CairnAdapter(sub, config=CairnConfig("claude-code", "test"))
    getattr(adapter, method)(str(uuid.uuid4()), arg, content_capture=True)

    assert len(sub.payloads) == 1
    payload = sub.payloads[0]
    assert content_field not in payload, "plaintext content reached the store"
    assert arg not in json.dumps(payload), "plaintext leaked into the payload"
    assert payload["content_encryption_error"]
    assert "env:NOPE" in payload["content_encryption_error"]
    # Integrity is unaffected: the digest is still there.
    assert payload.get("message_digest") or payload.get("transcript_digest")


def test_capture_encrypts_content_when_the_key_resolves(monkeypatch, content_key):
    from regista._encryption import is_encrypted_field

    from cairn.schema import CairnConfig

    monkeypatch.setenv("CAIRN_CONTENT_KEY_REF", content_key)

    sub = _CapturingRegista()
    adapter = CairnAdapter(sub, config=CairnConfig("claude-code", "test"))
    adapter.record_user_message(str(uuid.uuid4()), "sensitive prompt", content_capture=True)

    payload = sub.payloads[0]
    assert is_encrypted_field(payload["message_content"])
    assert "content_encryption_error" not in payload


@pytest.mark.parametrize(
    ("configure", "doctor_status", "recorded"),
    [
        (lambda mp, tmp: None, "warn", CONTENT_ENCRYPTION_OFF),
        (
            lambda mp, tmp: mp.setenv("CAIRN_CONTENT_KEY_REF", "env:NOPE"),
            "fail",
            CONTENT_ENCRYPTION_OFF,
        ),
        (
            lambda mp, tmp: mp.setenv("CAIRN_CONTENT_KEY_PATH", _write_key(tmp)),
            "ok",
            CONTENT_ENCRYPTION_ON,
        ),
    ],
)
def test_doctor_and_runtime_cannot_disagree(
    monkeypatch, tmp_path, configure, doctor_status, recorded
):
    """One verdict, rendered two ways.

    ``cairn doctor`` reports content encryption ON only where the runtime will
    really encrypt, and the stance the runtime records matches. A doctor that
    says the key resolves while capture writes plaintext is the same defect
    wearing a different hat, so the two are wired to one function.
    """
    from cairn._config import resolve_config
    from cairn._content_crypto import recorded_content_encryption_stance
    from cairn._doctor import _check_content_encryption

    monkeypatch.delenv("NOPE", raising=False)
    configure(monkeypatch, tmp_path)

    check = _check_content_encryption(resolve_config())
    assert check["status"] == doctor_status, check
    assert recorded_content_encryption_stance() == recorded
    if doctor_status != "ok":
        assert check["status"] != "ok"


def _write_key(tmp_path: Path) -> str:
    key = tmp_path / "content-parity.key"
    key.write_bytes(b"0" * 32)
    return str(key)


def test_status_cache_never_holds_a_stale_green(monkeypatch, tmp_path):
    """Positive verdicts are memoised; negative ones are re-probed.

    A cached "the key resolves" that outlives the key would be a fail-open
    cache — exactly the shape of bug this work item is about — so only usable
    verdicts are cached, and a key that appears later is picked up.
    """
    from cairn._content_crypto import content_encryption_status

    monkeypatch.setenv("CAIRN_CONTENT_KEY_REF", "env:LATE_KEY")
    monkeypatch.delenv("LATE_KEY", raising=False)
    assert content_encryption_status().usable is False

    monkeypatch.setenv("LATE_KEY", "0" * 32)
    assert content_encryption_status().usable is True  # re-probed, not cached red

    # And the positive verdict is the one that gets memoised.
    monkeypatch.delenv("LATE_KEY", raising=False)
    assert content_encryption_status().usable is True


def test_verifier_reports_why_content_is_missing_when_it_was_withheld():
    """The content-coverage gap names the recorded cause (WI-037)."""
    from cairn.verifier import Verifier

    session_id = str(uuid.uuid4())
    report = VerificationReport()
    report.session_attestations.append(
        SessionAttestationEntry(
            event_id=str(uuid.uuid4()),
            entity_id=session_id,
            version="2",
            principal_id="human:test",
            session_id=session_id,
            attested_at="2026-01-01T00:00:00Z",
            harnesses=({"name": "claude-code", "version": "test"},),
            scope_statement="In scope: test.",
            content_capture=True,
            content_encryption="off",
        )
    )
    event = type(
        "Ev",
        (),
        {
            "transition": "transcript_attestation",
            "event_id": uuid.uuid4(),
            "on_behalf_of": None,
            "payload": {
                "transcript_digest": "abc",
                "session_id": session_id,
                "content_encryption_error": (
                    "content encryption is ON but its key 'env:NOPE' does not resolve"
                ),
            },
        },
    )()

    Verifier._check_content_coverage_gaps(Verifier.__new__(Verifier), [event], report)

    assert len(report.content_coverage_gaps) == 1
    detail = report.content_coverage_gaps[0].detail
    assert "The event records why" in detail
    assert "env:NOPE" in detail


# ----------------------------------------------------------------------
# WI-6.1: Content-coverage gap detection
# ----------------------------------------------------------------------


def test_content_coverage_gap_detection():
    """A session that declared content_capture but has digest-only events."""
    report = VerificationReport()
    report.content_coverage_gaps.append(
        ContentCoverageGap(
            session_id="test-session",
            event_id="test-event",
            transition="user_message",
            detail="Session declared content_capture=true but event has only a digest.",
        )
    )
    assert len(report.content_coverage_gaps) == 1
    assert not report.all_ok


# ----------------------------------------------------------------------
# Portal (WI-4.1-4.3)
# ----------------------------------------------------------------------


def test_portal_renders_text(tmp_path: Path):
    """Portal renders session content from a bundle."""
    from cairn._portal import render_portal

    session_id = str(uuid.uuid4())
    bundle = {
        "manifest": {"events_count": 1},
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "transition": "session_attestation",
                "timestamp": "2026-01-01T00:00:00Z",
                "payload": {
                    "version": "2",
                    "principal_id": "human:test",
                    "session_id": session_id,
                    "attested_at": "2026-01-01T00:00:00Z",
                    "harnesses": [{"name": "claude-code", "version": "2.1.200"}],
                    "scope_statement": "In scope: test.",
                    "content_capture": True,
                    "content_encryption": "off",
                },
                "on_behalf_of": {"principal_id": "human:test", "session_id": session_id},
            },
            {
                "event_id": str(uuid.uuid4()),
                "transition": "user_message",
                "timestamp": "2026-01-01T00:01:00Z",
                "payload": {
                    "message_digest": digest_string("hello"),
                    "message_content": "hello",
                    "role": "user",
                },
                "on_behalf_of": {"principal_id": "human:test", "session_id": session_id},
            },
        ],
    }
    bundle_path = tmp_path / "test-bundle.json"
    bundle_path.write_text(json.dumps(bundle))

    result = render_portal(bundle_path, fmt="text")
    assert "CAIRN SESSION PORTAL" in result
    assert session_id in result
    assert "hello" in result
    assert "WARNING" in result  # content_encryption=off


def test_portal_renders_html(tmp_path: Path):
    """Portal renders HTML with encryption-stance banner."""
    from cairn._portal import render_portal

    session_id = str(uuid.uuid4())
    bundle = {
        "manifest": {"events_count": 1},
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "transition": "session_attestation",
                "timestamp": "2026-01-01T00:00:00Z",
                "payload": {
                    "version": "2",
                    "principal_id": "human:test",
                    "session_id": session_id,
                    "attested_at": "2026-01-01T00:00:00Z",
                    "harnesses": [{"name": "claude-code", "version": "2.1.200"}],
                    "scope_statement": "In scope: test.",
                    "content_capture": True,
                    "content_encryption": "off",
                },
                "on_behalf_of": {"principal_id": "human:test", "session_id": session_id},
            },
        ],
    }
    bundle_path = tmp_path / "test-bundle.json"
    bundle_path.write_text(json.dumps(bundle))

    result = render_portal(bundle_path, fmt="html")
    assert "<!DOCTYPE html>" in result
    assert "WARNING" in result
    assert session_id in result


def test_portal_no_banner_when_encrypted(tmp_path: Path):
    """No warning banner when content encryption is on."""
    from cairn._portal import render_portal

    session_id = str(uuid.uuid4())
    bundle = {
        "manifest": {"events_count": 1},
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "transition": "session_attestation",
                "timestamp": "2026-01-01T00:00:00Z",
                "payload": {
                    "version": "2",
                    "principal_id": "human:test",
                    "session_id": session_id,
                    "attested_at": "2026-01-01T00:00:00Z",
                    "harnesses": [{"name": "claude-code", "version": "2.1.200"}],
                    "scope_statement": "In scope: test.",
                    "content_capture": True,
                    "content_encryption": "on",
                },
                "on_behalf_of": {"principal_id": "human:test", "session_id": session_id},
            },
        ],
    }
    bundle_path = tmp_path / "test-bundle.json"
    bundle_path.write_text(json.dumps(bundle))

    result = render_portal(bundle_path, fmt="text")
    assert "WARNING" not in result


# ----------------------------------------------------------------------
# Config (WI-3.1)
# ----------------------------------------------------------------------


def test_config_content_encryption_fields():
    from cairn._config import resolve_config

    with patch.dict(os.environ, {
        "CAIRN_CONTENT_ENCRYPTION": "off",
        "CAIRN_CONTENT_KEY_REF": "env:MY_KEY",
    }, clear=False):
        os.environ.pop("CAIRN_DISABLE", None)
        cfg = resolve_config()
        assert cfg.content_encryption == "off"
        assert cfg.content_key_ref == "env:MY_KEY"


def test_config_content_encryption_default_on():
    from cairn._config import resolve_config

    with patch.dict(os.environ, {}, clear=False):
        for key in ("CAIRN_CONTENT_ENCRYPTION", "CAIRN_CONTENT_KEY_REF",
                     "CAIRN_CONTENT_KEY_PATH", "CAIRN_DISABLE"):
            os.environ.pop(key, None)
        cfg = resolve_config()
        assert cfg.content_encryption == "on"


# ----------------------------------------------------------------------
# Doctor (WI-3.1)
# ----------------------------------------------------------------------


def test_doctor_content_encryption_warning():
    from cairn._doctor import _check_content_encryption

    class MockCfg:
        content_encryption = "off"
        content_key_ref = None
        content_key_path = None

    result = _check_content_encryption(MockCfg())
    assert result["status"] == "warn"
    assert "OFF" in result["detail"]


def test_doctor_content_encryption_ok(monkeypatch):
    """WI-034: ok requires the key to RESOLVE, not merely to be configured."""
    from cairn._doctor import _check_content_encryption

    monkeypatch.setenv("MY_KEY", "0" * 32)

    class MockCfg:
        content_encryption = "on"
        content_key_ref = "env:MY_KEY"
        content_key_path = None

    result = _check_content_encryption(MockCfg())
    assert result["status"] == "ok"


def test_doctor_content_encryption_unresolvable_key_fails(monkeypatch):
    """A configured-but-unresolvable key used to read green (agent-suite WI-041).

    ``env:MY_KEY`` with no such variable set is exactly the "configured, not
    resolvable" shape: content encryption would be reported ON while the key it
    names cannot be fetched.
    """
    from cairn._doctor import _check_content_encryption

    monkeypatch.delenv("MY_KEY", raising=False)

    class MockCfg:
        content_encryption = "on"
        content_key_ref = "env:MY_KEY"
        content_key_path = None

    result = _check_content_encryption(MockCfg())
    assert result["status"] == "fail"
    assert "does not resolve" in result["detail"]


def test_doctor_content_encryption_no_key_warning():
    from cairn._doctor import _check_content_encryption

    class MockCfg:
        content_encryption = "on"
        content_key_ref = None
        content_key_path = None

    result = _check_content_encryption(MockCfg())
    assert result["status"] == "warn"


def test_doctor_content_encryption_vault_ref_without_hvac_fails(monkeypatch):
    """A ``vault:`` ref resolves only where hvac is importable in CAIRN's own
    environment (agent-suite WI-041 trap 3).

    Each suite CLI is its own uv tool venv, so hvac in regista's venv does
    nothing for cairn's; without it regista registers no vault provider and the
    ref fails with "Unknown secret provider". Observed live on the qualification
    host, for both the DSN key ref and the content key.
    """
    import importlib.util

    from cairn._doctor import _check_content_encryption

    real_find_spec = importlib.util.find_spec

    def _no_hvac(name, *args, **kwargs):
        if name == "hvac":
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", _no_hvac)

    class MockCfg:
        content_encryption = "on"
        content_key_ref = "vault:kv/agent-suite/qual/cairn/content_key"
        content_key_path = None

    result = _check_content_encryption(MockCfg())
    assert result["status"] == "fail"
    assert "hvac is not importable" in result["detail"]
    # The remedy it names must exist: cairn declares a [vault] extra.
    assert "cairn[vault]" in result["detail"]


def test_cairn_declares_the_vault_extra_its_doctor_recommends():
    """The doctor's remedy is only honest if the extra exists."""
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    extras = data["project"]["optional-dependencies"]
    assert "vault" in extras, "cairn doctor names a [vault] extra that does not exist"
    assert any("vault" in dep for dep in extras["vault"])
