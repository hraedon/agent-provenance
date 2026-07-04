"""Unit tests for integrations/claude-code/cairn_hook.py."""

from __future__ import annotations

import json
import os
import uuid
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cairn._claude_hook import (
    _call_key,
    _extract_files,
    _mark_degraded,
    _next_state_file,
    _oldest_state_file,
    _resolve_settings_digest,
    _state_dir,
    handle_post,
    handle_pre,
    handle_session_end,
    handle_session_start,
)


@pytest.fixture(autouse=True)
def _clear_env(tmp_path: Path):
    orig = {
        k: os.environ.get(k)
        for k in [
            "CAIRN_DSN",
            "CAIRN_PROJECT",
            "CAIRN_KEY_PATH",
            "CAIRN_DISABLE",
            "PRINCIPAL_ID",
            "CAIRN_STATE_DIR",
            "CAIRN_BRIDGE_PATH",
        ]
    }
    os.environ["CAIRN_STATE_DIR"] = str(tmp_path / "cairn-state")
    yield
    for k, v in orig.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    d = tmp_path / "cairn-state" / "test-session"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_call_key_stable():
    k1 = _call_key("Edit", {"filePath": "/tmp/foo", "oldString": "x", "newString": "y"})
    k2 = _call_key("Edit", {"filePath": "/tmp/foo", "oldString": "x", "newString": "y"})
    assert k1 == k2


def test_call_key_differs_for_different_args():
    k1 = _call_key("Edit", {"filePath": "/tmp/foo"})
    k2 = _call_key("Edit", {"filePath": "/tmp/bar"})
    assert k1 != k2


def test_extract_files_from_filepath():
    files = _extract_files("Edit", {"filePath": "/tmp/foo.py"})
    assert files == ["/tmp/foo.py"]


def test_extract_files_from_path():
    files = _extract_files("Read", {"filePath": "/tmp/bar.py"})
    assert files == ["/tmp/bar.py"]


def test_extract_files_from_bash():
    files = _extract_files("Bash", {"command": "echo hello"})
    assert files == []


def test_extract_files_empty():
    assert _extract_files("Glob", {"pattern": "**/*.py"}) == []


def test_state_dir_created(tmp_path: Path):
    sd = _state_dir("my-session")
    assert sd.exists()
    assert sd.name == "my-session"


@patch("cairn._claude_hook._run_bridge")
def test_handle_pre_creates_state(mock_bridge: MagicMock, state_dir: Path) -> None:
    wi_id = str(uuid.uuid4())
    mock_bridge.return_value = {"status": "ok", "work_item_id": wi_id, "args_hash": "sha256:abc"}

    hook_input = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": {"filePath": "/tmp/foo.py", "oldString": "x", "newString": "y"},
            "session_id": "test-session",
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_pre()

    mock_bridge.assert_called_once()
    call_args = mock_bridge.call_args[0][0]
    assert call_args["action"] == "begin"
    assert call_args["tool"] == "Edit"
    assert call_args["session_id"] == "test-session"

    key = _call_key("Edit", {"filePath": "/tmp/foo.py", "oldString": "x", "newString": "y"})
    state_file = _oldest_state_file(state_dir, key)
    assert state_file is not None
    assert state_file.exists()
    state = json.loads(state_file.read_text())
    assert state["work_item_id"] == wi_id


@patch("cairn._claude_hook._run_bridge")
def test_handle_pre_bridge_fails_gracefully(mock_bridge: MagicMock, state_dir: Path) -> None:
    mock_bridge.return_value = None

    hook_input = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": {"filePath": "/tmp/foo.py"},
            "session_id": "test-session",
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_pre()

    state_files = [f for f in state_dir.iterdir() if f.name != "degradation.log"]
    assert len(state_files) == 0
    degradation_log = state_dir / "degradation.log"
    assert degradation_log.exists()


@patch("cairn._claude_hook._run_bridge")
def test_handle_post_reads_state_and_calls_end(mock_bridge: MagicMock, state_dir: Path) -> None:
    wi_id = str(uuid.uuid4())
    tool_input = {"filePath": "/tmp/foo.py", "oldString": "x", "newString": "y"}
    key = _call_key("Edit", tool_input)
    state_file = _next_state_file(state_dir, key)
    state_file.write_text(
        json.dumps(
            {
                "work_item_id": wi_id,
                "session_id": "test-session",
                "tool": "Edit",
            }
        )
    )

    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    hook_input = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_output": "edited successfully",
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post()

    mock_bridge.assert_called_once()
    call_args = mock_bridge.call_args[0][0]
    assert call_args["action"] == "end"
    assert call_args["work_item_id"] == wi_id
    assert call_args["error"] is None
    assert not state_file.exists()


@patch("cairn._claude_hook._run_bridge")
def test_handle_post_failure_passes_error(mock_bridge: MagicMock, state_dir: Path) -> None:
    wi_id = str(uuid.uuid4())
    tool_input = {"command": "rm -rf /"}
    key = _call_key("Bash", tool_input)
    state_file = _next_state_file(state_dir, key)
    state_file.write_text(
        json.dumps(
            {
                "work_item_id": wi_id,
                "session_id": "test-session",
                "tool": "Bash",
            }
        )
    )

    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    hook_input = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_output": "permission denied",
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post(failure=True)

    call_args = mock_bridge.call_args[0][0]
    assert call_args["error"] == "permission denied"


@patch("cairn._claude_hook._run_bridge")
def test_handle_post_no_state_does_nothing(mock_bridge: MagicMock, state_dir: Path) -> None:
    hook_input = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": {"filePath": "/tmp/nonexistent.py"},
            "session_id": "test-session",
            "tool_output": "ok",
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post()

    mock_bridge.assert_not_called()


@patch("cairn._claude_hook._run_bridge")
def test_handle_session_start(mock_bridge: MagicMock) -> None:
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    hook_input = json.dumps(
        {
            "session_id": "my-session",
            "cwd": "/projects/foo",
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_session_start()

    mock_bridge.assert_called_once()
    call_args = mock_bridge.call_args[0][0]
    assert call_args["action"] == "attest_session"
    assert call_args["session_id"] == "my-session"
    assert any(h["name"] == "claude-code" for h in call_args["harnesses"])


def test_handle_session_end_cleans_state_dir(state_dir: Path) -> None:
    state_file = state_dir / "stale.json"
    state_file.write_text('{"work_item_id": "abc"}')
    assert state_dir.exists()
    assert state_file.exists()

    hook_input = json.dumps({"session_id": "test-session"})

    with patch("sys.stdin", StringIO(hook_input)):
        from cairn._claude_hook import handle_session_end

        handle_session_end()

    assert not state_file.exists()
    assert not state_dir.exists()


# ----------------------------------------------------------------------
# _mark_degraded
# ----------------------------------------------------------------------


def test_mark_degraded_writes_log(state_dir: Path) -> None:
    _mark_degraded("test-session", "pre", "bridge call failed for Edit")

    log_file = state_dir / "degradation.log"
    assert log_file.exists()
    lines = log_file.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["action"] == "pre"
    assert "Edit" in entry["detail"]
    assert "ts" in entry


def test_mark_degraded_appends(state_dir: Path) -> None:
    _mark_degraded("test-session", "pre", "first failure")
    _mark_degraded("test-session", "post", "second failure")

    log_file = state_dir / "degradation.log"
    lines = log_file.read_text().strip().splitlines()
    assert len(lines) == 2


# ----------------------------------------------------------------------
# _resolve_settings_digest
# ----------------------------------------------------------------------


def test_resolve_settings_digest_from_project_dir(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"key": "value"}')

    with patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": str(tmp_path)}):
        digest = _resolve_settings_digest()

    assert digest is not None
    assert digest.startswith("sha256:")
    assert len(digest) == 71  # "sha256:" + 64 hex chars


def test_resolve_settings_digest_returns_none_when_missing(tmp_path: Path) -> None:
    with patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": str(tmp_path)}, clear=False):
        with patch("cairn._claude_hook.Path.home", return_value=tmp_path):
            digest = _resolve_settings_digest()

    assert digest is None


# ----------------------------------------------------------------------
# handle_session_end with degradation log
# ----------------------------------------------------------------------


def test_handle_session_end_preserves_degradation_log(state_dir: Path) -> None:
    state_file = state_dir / "stale.json"
    state_file.write_text('{"work_item_id": "abc"}')

    _mark_degraded("test-session", "pre", "bridge failure")

    hook_input = json.dumps({"session_id": "test-session"})
    with patch("sys.stdin", StringIO(hook_input)):
        handle_session_end()

    assert not state_file.exists()
    degradation_log = state_dir / "degradation.log"
    assert degradation_log.exists()
    assert state_dir.exists()


# ----------------------------------------------------------------------
# handle_post bridge failure creates degradation log
# ----------------------------------------------------------------------


@patch("cairn._claude_hook._run_bridge")
def test_handle_post_bridge_failure_creates_degradation(
    mock_bridge: MagicMock, state_dir: Path
) -> None:
    wi_id = str(uuid.uuid4())
    tool_input = {"filePath": "/tmp/foo.py"}
    key = _call_key("Edit", tool_input)
    state_file = _next_state_file(state_dir, key)
    state_file.write_text(
        json.dumps({"work_item_id": wi_id, "session_id": "test-session", "tool": "Edit"})
    )

    mock_bridge.return_value = None

    hook_input = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_output": "ok",
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post()

    degradation_log = state_dir / "degradation.log"
    assert degradation_log.exists()
    entry = json.loads(degradation_log.read_text().strip())
    assert entry["action"] == "post"


# ----------------------------------------------------------------------
# handle_session_start with config digest
# ----------------------------------------------------------------------


@patch("cairn._claude_hook._run_bridge")
def test_handle_session_start_includes_config_digest(
    mock_bridge: MagicMock, tmp_path: Path
) -> None:
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"test": true}')

    with patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": str(tmp_path)}):
        hook_input = json.dumps({"session_id": "my-session"})
        with patch("sys.stdin", StringIO(hook_input)):
            handle_session_start()

    call_args = mock_bridge.call_args[0][0]
    assert "harness_config_digests" in call_args
    digests = call_args["harness_config_digests"]
    assert "claude-code" in digests
    assert digests["claude-code"].startswith("sha256:")


# ----------------------------------------------------------------------
# _state_dir permissions
# ----------------------------------------------------------------------


def test_state_dir_permissions_are_restrictive(tmp_path: Path) -> None:
    os.environ["CAIRN_STATE_DIR"] = str(tmp_path / "restricted")
    sd = _state_dir("perm-test")

    import stat

    mode = stat.S_IMODE(sd.stat().st_mode)
    assert mode == 0o700


# ----------------------------------------------------------------------
# _safe_session_id
# ----------------------------------------------------------------------


def test_safe_session_id_sanitizes():
    from cairn._claude_hook import _safe_session_id

    assert _safe_session_id("abc-123") == "abc-123"
    assert _safe_session_id("../../../etc/passwd") == ".._.._.._etc_passwd"
    assert _safe_session_id("session/with/slashes") == "session_with_slashes"


# ----------------------------------------------------------------------
# WI-023: repeated identical tool calls don't collide
# ----------------------------------------------------------------------


def test_next_state_file_increments_seq(state_dir: Path) -> None:
    """Repeated identical tool calls get unique state files (WI-023)."""
    key = _call_key("Edit", {"filePath": "/tmp/foo.py"})
    f1 = _next_state_file(state_dir, key)
    f1.write_text('{"work_item_id": "wi-1"}')
    f2 = _next_state_file(state_dir, key)
    f2.write_text('{"work_item_id": "wi-2"}')

    assert f1 != f2
    assert f1.exists()
    assert f2.exists()


def test_oldest_state_file_returns_fifo(state_dir: Path) -> None:
    """_oldest_state_file returns the first-created file (FIFO)."""
    key = _call_key("Edit", {"filePath": "/tmp/foo.py"})
    f1 = _next_state_file(state_dir, key)
    f1.write_text('{"work_item_id": "wi-1"}')
    f2 = _next_state_file(state_dir, key)
    f2.write_text('{"work_item_id": "wi-2"}')

    oldest = _oldest_state_file(state_dir, key)
    assert oldest == f1


def test_oldest_state_file_none_when_empty(state_dir: Path) -> None:
    key = _call_key("Edit", {"filePath": "/tmp/foo.py"})
    assert _oldest_state_file(state_dir, key) is None


@patch("cairn._claude_hook._run_bridge")
def test_repeated_identical_tool_calls_dont_collide(
    mock_bridge: MagicMock, state_dir: Path
) -> None:
    """Two identical begin/end pairs don't overwrite each other (WI-023)."""
    wi1 = str(uuid.uuid4())
    wi2 = str(uuid.uuid4())
    mock_bridge.side_effect = [
        {"status": "ok", "work_item_id": wi1, "args_hash": "sha256:abc"},
        {"status": "ok", "event_id": str(uuid.uuid4())},
        {"status": "ok", "work_item_id": wi2, "args_hash": "sha256:def"},
        {"status": "ok", "event_id": str(uuid.uuid4())},
    ]

    tool_input = {"filePath": "/tmp/identical.py", "oldString": "a", "newString": "b"}
    hook_begin = json.dumps(
        {"tool_name": "Edit", "tool_input": tool_input, "session_id": "test-session"}
    )
    hook_end = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_output": "ok",
        }
    )

    with patch("sys.stdin", StringIO(hook_begin)):
        handle_pre()
    with patch("sys.stdin", StringIO(hook_end)):
        handle_post()
    with patch("sys.stdin", StringIO(hook_begin)):
        handle_pre()
    with patch("sys.stdin", StringIO(hook_end)):
        handle_post()

    end_calls = [c[0][0] for c in mock_bridge.call_args_list if c[0][0]["action"] == "end"]
    assert len(end_calls) == 2
    assert end_calls[0]["work_item_id"] == wi1
    assert end_calls[1]["work_item_id"] == wi2
