"""Unit tests for cairn.schema — canonical event schema and helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cairn.schema import (
    FileDigest,
    ResultSummary,
    ScopeAttestationPayload,
    ToolCallBegin,
    ToolCallEnd,
    build_redacted_args,
    check_key_file_permissions,
    digest_file,
    digest_string,
    hash_payload,
)

# ----------------------------------------------------------------------
# hash_payload
# ----------------------------------------------------------------------


def test_hash_payload_deterministic():
    h1 = hash_payload({"b": 2, "a": 1})
    h2 = hash_payload({"a": 1, "b": 2})
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_hash_payload_differs_for_different_input():
    h1 = hash_payload({"a": 1})
    h2 = hash_payload({"a": 2})
    assert h1 != h2


# ----------------------------------------------------------------------
# digest_file
# ----------------------------------------------------------------------


def test_digest_file_returns_sha256(tmp_path: Path):
    f = tmp_path / "test.txt"
    f.write_text("hello world")
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert digest_file(str(f)) == expected


def test_digest_file_returns_none_for_missing(tmp_path: Path):
    assert digest_file(str(tmp_path / "nonexistent.txt")) is None


def test_digest_file_returns_none_for_directory(tmp_path: Path):
    assert digest_file(str(tmp_path)) is None


def test_digest_file_streaming_large_file(tmp_path: Path):
    """Verify streaming hash matches one-shot hash for files > 64KiB."""
    content = b"x" * 100_000  # ~100 KiB
    f = tmp_path / "large.bin"
    f.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert digest_file(str(f)) == expected


def test_digest_file_empty_file(tmp_path: Path):
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()
    assert digest_file(str(f)) == expected


# ----------------------------------------------------------------------
# digest_string
# ----------------------------------------------------------------------


def test_digest_string_returns_sha256():
    expected = hashlib.sha256(b"hello").hexdigest()
    assert digest_string("hello") == expected


def test_digest_string_none_returns_none():
    assert digest_string(None) is None


# ----------------------------------------------------------------------
# check_key_file_permissions
# ----------------------------------------------------------------------


def test_check_key_file_permissions_secure(tmp_path: Path):
    key = tmp_path / "key.pem"
    key.write_bytes(b"secret")
    key.chmod(0o600)
    assert check_key_file_permissions(str(key)) == []


def test_check_key_file_permissions_group_readable(tmp_path: Path):
    key = tmp_path / "key.pem"
    key.write_bytes(b"secret")
    key.chmod(0o640)
    warnings = check_key_file_permissions(str(key))
    assert any("group-readable" in w for w in warnings)


def test_check_key_file_permissions_world_readable(tmp_path: Path):
    key = tmp_path / "key.pem"
    key.write_bytes(b"secret")
    key.chmod(0o644)
    warnings = check_key_file_permissions(str(key))
    assert any("world-readable" in w for w in warnings)


def test_check_key_file_permissions_group_writable(tmp_path: Path):
    key = tmp_path / "key.pem"
    key.write_bytes(b"secret")
    key.chmod(0o620)
    warnings = check_key_file_permissions(str(key))
    assert any("group-writable" in w for w in warnings)


def test_check_key_file_permissions_world_writable(tmp_path: Path):
    key = tmp_path / "key.pem"
    key.write_bytes(b"secret")
    key.chmod(0o602)
    warnings = check_key_file_permissions(str(key))
    assert any("world-writable" in w for w in warnings)


def test_check_key_file_permissions_missing_file():
    warnings = check_key_file_permissions("/nonexistent/path/key.pem")
    assert any("stat failed" in w for w in warnings)


# ----------------------------------------------------------------------
# FileDigest round-trip
# ----------------------------------------------------------------------


def test_file_digest_round_trip():
    fd = FileDigest(path="/tmp/foo.py", pre_digest="sha256:aaa", post_digest=None)
    d = fd.to_dict()
    assert d == {"path": "/tmp/foo.py", "pre_digest": "sha256:aaa"}
    fd2 = FileDigest.from_dict(d)
    assert fd2 == fd


# ----------------------------------------------------------------------
# ResultSummary round-trip
# ----------------------------------------------------------------------


def test_result_summary_round_trip():
    rs = ResultSummary(exit_code=0, stdout_digest="sha256:bbb", error=None)
    d = rs.to_dict()
    assert d == {"exit_code": 0, "stdout_digest": "sha256:bbb"}
    rs2 = ResultSummary.from_dict(d)
    assert rs2 == rs


# ----------------------------------------------------------------------
# ToolCallBegin / ToolCallEnd round-trip
# ----------------------------------------------------------------------


def test_tool_call_begin_round_trip():
    tcb = ToolCallBegin(
        tool="Edit",
        tool_args_hash="sha256:ccc",
        tool_args_redacted={"tool": "Edit", "file_paths": ["/tmp/foo"]},
        files=[FileDigest(path="/tmp/foo", pre_digest="sha256:ddd", post_digest=None)],
        on_behalf_of={"principal_id": "human:test"},
    )
    d = tcb.to_dict()
    tcb2 = ToolCallBegin.from_dict(d)
    assert tcb2 == tcb


def test_tool_call_end_round_trip():
    tce = ToolCallEnd(
        tool="Edit",
        tool_args_hash="sha256:ccc",
        result_summary=ResultSummary(exit_code=0),
    )
    d = tce.to_dict()
    tce2 = ToolCallEnd.from_dict(d)
    assert tce2 == tce


# ----------------------------------------------------------------------
# ScopeAttestationPayload round-trip
# ----------------------------------------------------------------------


def test_scope_attestation_payload_round_trip():
    sap = ScopeAttestationPayload(
        version="1",
        principal_id="human:test",
        attested_at="2026-01-01T00:00:00Z",
        harnesses=[{"name": "opencode", "version": "0.1.0"}],
        scope_statement="In scope: test.",
        harness_config_digests={"opencode": "sha256:eee"},
    )
    d = sap.to_dict()
    sap2 = ScopeAttestationPayload.from_dict(d)
    assert sap2 == sap


# ----------------------------------------------------------------------
# build_redacted_args
# ----------------------------------------------------------------------


def test_build_redacted_args_basic():
    r = build_redacted_args(tool="Edit", file_paths=["/tmp/foo"])
    assert r == {"tool": "Edit", "file_paths": ["/tmp/foo"]}


def test_build_redacted_args_with_command():
    r = build_redacted_args(tool="Bash", command="run tests")
    assert r == {"tool": "Bash", "command_description": "run tests"}
