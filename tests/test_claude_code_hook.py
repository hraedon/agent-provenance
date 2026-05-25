"""Unit tests for integrations/claude-code/cairn_hook.py."""

from __future__ import annotations

import json
import os
import sys
import uuid
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integrations" / "claude-code"))

from cairn_hook import (
    _call_key,
    _extract_files,
    _state_dir,
    handle_post,
    handle_pre,
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


@patch("cairn_hook._run_bridge")
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
    state_file = state_dir / f"{key}.json"
    assert state_file.exists()
    state = json.loads(state_file.read_text())
    assert state["work_item_id"] == wi_id


@patch("cairn_hook._run_bridge")
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

    files = list(state_dir.iterdir())
    assert len(files) == 0


@patch("cairn_hook._run_bridge")
def test_handle_post_reads_state_and_calls_end(mock_bridge: MagicMock, state_dir: Path) -> None:
    wi_id = str(uuid.uuid4())
    tool_input = {"filePath": "/tmp/foo.py", "oldString": "x", "newString": "y"}
    key = _call_key("Edit", tool_input)
    state_file = state_dir / f"{key}.json"
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


@patch("cairn_hook._run_bridge")
def test_handle_post_failure_passes_error(mock_bridge: MagicMock, state_dir: Path) -> None:
    wi_id = str(uuid.uuid4())
    tool_input = {"command": "rm -rf /"}
    key = _call_key("Bash", tool_input)
    state_file = state_dir / f"{key}.json"
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


@patch("cairn_hook._run_bridge")
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


@patch("cairn_hook._run_bridge")
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
    assert call_args["action"] == "attest_scope"
    assert call_args["session_id"] == "my-session"
    assert any(h["name"] == "claude-code" for h in call_args["harnesses"])


def test_handle_session_end_cleans_state_dir(state_dir: Path) -> None:
    state_file = state_dir / "stale.json"
    state_file.write_text('{"work_item_id": "abc"}')
    assert state_dir.exists()
    assert state_file.exists()

    hook_input = json.dumps({"session_id": "test-session"})

    with patch("sys.stdin", StringIO(hook_input)):
        from cairn_hook import handle_session_end

        handle_session_end()

    assert not state_file.exists()
    assert not state_dir.exists()
