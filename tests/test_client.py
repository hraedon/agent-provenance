"""Unit tests for CairnClient high-level SDK."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from cairn.client import CairnClient, ToolCallContext

# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------
# ``dsn``, ``project``, ``hmac_keys``, and ``regista_instance`` are provided
# by conftest.py (single source). The pre-check in conftest skips fast when
# Postgres is unreachable (WI-001).


@pytest.fixture
def client(dsn: str, project: str, hmac_keys: Path, workflow_registered: None) -> CairnClient:
    return CairnClient(
        dsn=dsn,
        project=project,
        key_path=hmac_keys,
        harness_name="test-agent",
        harness_version="0.1.0",
        principal_id="human:test-user",
        session_id=str(uuid.uuid4()),
    )


# ----------------------------------------------------------------------
# Lifecycle tests
# ----------------------------------------------------------------------


def test_client_context_manager(
    dsn: str, project: str, hmac_keys: Path, workflow_registered: None
) -> None:
    """Client works as a context manager."""
    with CairnClient(
        dsn=dsn,
        project=project,
        key_path=hmac_keys,
        harness_name="test-agent",
        harness_version="0.1.0",
        principal_id="human:test",
    ) as cairn:
        assert cairn.principal_id == "human:test"
        assert cairn.session_id
    # Should not raise on double close
    cairn.close()


def test_client_detects_principal(dsn: str, project: str, hmac_keys: Path) -> None:
    """Client detects principal from environment when not specified."""
    old_val = os.environ.get("PRINCIPAL_ID")
    try:
        os.environ["PRINCIPAL_ID"] = "human:env-detected"
        c = CairnClient(dsn=dsn, project=project, key_path=hmac_keys)
        assert c.principal_id == "human:env-detected"
    finally:
        if old_val is None:
            os.environ.pop("PRINCIPAL_ID", None)
        else:
            os.environ["PRINCIPAL_ID"] = old_val


# ----------------------------------------------------------------------
# Scope attestation tests
# ----------------------------------------------------------------------


def test_attest_scope(client: CairnClient) -> None:
    """attest_scope records a scope attestation event."""
    ev = client.attest_scope(
        harnesses=[{"name": "test-agent", "version": "0.1.0"}],
        scope_statement="In scope: test-agent.",
    )
    assert ev is not None
    payload = ev.payload or {}
    assert payload.get("version") == "1"
    assert payload.get("principal_id") == "human:test-user"
    assert payload.get("scope_statement") == "In scope: test-agent."


def test_attest_scope_defaults(client: CairnClient) -> None:
    """attest_scope uses client defaults when args omitted."""
    ev = client.attest_scope()
    assert ev is not None
    payload = ev.payload or {}
    assert payload.get("scope_statement") == "In scope: test-agent."
    harnesses = payload.get("harnesses", [])
    assert len(harnesses) == 1
    assert harnesses[0]["name"] == "test-agent"


# ----------------------------------------------------------------------
# Tool call tests
# ----------------------------------------------------------------------


def test_begin_and_end(client: CairnClient, tmp_path: Path) -> None:
    """begin + end logs a complete tool call."""
    f = tmp_path / "test.txt"
    f.write_text("hello\n")

    tc = client.begin("Write", args={"filePath": str(f)}, files=[str(f)])
    assert tc.tool == "Write"
    assert tc.work_item_id is not None

    ev = client.end(tc, exit_code=0, stdout="written")
    assert ev is not None
    assert ev.transition == "tool_call_end"


def test_begin_and_end_with_error(client: CairnClient, tmp_path: Path) -> None:
    """begin + end with error records a failed tool call."""
    f = tmp_path / "test.txt"
    f.write_text("hello\n")

    tc = client.begin("Write", args={"filePath": str(f)}, files=[str(f)])
    ev = client.end(tc, error="permission denied")
    assert ev is not None
    assert ev.transition == "tool_call_fail"


def test_tool_call_context_manager(client: CairnClient, tmp_path: Path) -> None:
    """tool_call context manager handles begin/end automatically."""
    f = tmp_path / "test.txt"
    f.write_text("hello\n")

    with client.tool_call("Edit", args={"filePath": str(f)}, files=[str(f)]) as tc:
        tc.set_result(exit_code=0)

    # Should have recorded the event (no way to get the event from here,
    # but no exception means success)
    assert tc._ended


def test_tool_call_context_manager_exception(client: CairnClient, tmp_path: Path) -> None:
    """tool_call context manager records failure on exception."""
    f = tmp_path / "test.txt"
    f.write_text("hello\n")

    with pytest.raises(ValueError, match="boom"):
        with client.tool_call("Edit", args={"filePath": str(f)}, files=[str(f)]) as tc:
            raise ValueError("boom")

    assert tc._ended
    assert tc._error == "boom"


def test_tool_call_context_manager_no_args(client: CairnClient) -> None:
    """tool_call works with no args or files."""
    with client.tool_call("Bash") as tc:
        tc.set_result(exit_code=0)
    assert tc._ended


def test_double_end_safe(client: CairnClient) -> None:
    """Calling end() twice is safe."""
    tc = client.begin("Read")
    tc.end()
    result = tc.end()
    assert result is None


# ----------------------------------------------------------------------
# ToolCallContext tests
# ----------------------------------------------------------------------


def test_tool_call_context_set_result() -> None:
    """set_result populates the result summary."""
    tc = ToolCallContext(
        client=None,  # type: ignore[arg-type]
        work_item_id=uuid.uuid4(),
        tool="Edit",
        files=[],
    )
    tc.set_result(exit_code=0, stdout="ok", stderr="")
    assert tc._result_summary == {"exit_code": 0, "stdout": "ok", "stderr": ""}


def test_tool_call_context_set_error() -> None:
    """set_error populates the error."""
    tc = ToolCallContext(
        client=None,  # type: ignore[arg-type]
        work_item_id=uuid.uuid4(),
        tool="Edit",
        files=[],
    )
    tc.set_error("something broke")
    assert tc._error == "something broke"
