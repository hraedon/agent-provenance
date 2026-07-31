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
