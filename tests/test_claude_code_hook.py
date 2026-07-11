"""Unit tests for integrations/claude-code/cairn_hook.py."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cairn._claude_hook import (
    _CANONICAL_RESPONSE_FIELD,
    _LEGACY_RESPONSE_FIELD,
    _TRANSPORT_CAP,
    _call_key,
    _compute_output_digest,
    _extract_files,
    _extract_tool_response,
    _mark_degraded,
    _next_state_file,
    _normalize_response,
    _oldest_state_file,
    _resolve_settings_digest,
    _safe_session_id,
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
            "CAIRN_STATE_DIR",
            "CAIRN_BRIDGE_PATH",
            "CAIRN_CAPTURE_DIR",
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

    tool_output_text = "edited successfully"
    hook_input = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_response": tool_output_text,
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
def test_handle_post_digest_is_reproducible(mock_bridge: MagicMock, state_dir: Path) -> None:
    """WI-1.2/WI-1.3: the attested digest equals an independently computed
    sha256 of the real (full, untruncated) tool output."""
    wi_id = str(uuid.uuid4())
    tool_input = {"command": "echo hello"}
    key = _call_key("Bash", tool_input)
    state_file = _next_state_file(state_dir, key)
    state_file.write_text(
        json.dumps({"work_item_id": wi_id, "session_id": "test-session", "tool": "Bash"})
    )
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    real_output = "line one\nline two\nline three\n"
    hook_input = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_response": real_output,
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post()

    call_args = mock_bridge.call_args[0][0]
    rs = call_args["result_summary"]
    expected_digest = hashlib.sha256(real_output.encode("utf-8")).hexdigest()
    assert rs["stdout_digest"] == expected_digest
    assert rs["stdout_digest_alg"] == "sha256"
    assert rs["stdout_bytes_total"] == len(real_output.encode("utf-8"))
    assert rs["stdout_truncated"] is False


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
            "tool_response": "permission denied",
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
            "tool_response": "ok",
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
            "tool_response": "ok",
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
            "tool_response": "ok",
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


# ----------------------------------------------------------------------
# Plan 009 WI-1.1: tool_response field + normalization
# ----------------------------------------------------------------------


def test_extract_tool_response_prefers_canonical_field() -> None:
    """The canonical field (tool_response) is preferred over tool_output."""
    payload = {
        _CANONICAL_RESPONSE_FIELD: "canonical",
        _LEGACY_RESPONSE_FIELD: "legacy",
    }
    assert _extract_tool_response(payload) == "canonical"


def test_extract_tool_response_falls_back_to_legacy() -> None:
    """Legacy tool_output is used when tool_response is absent."""
    payload = {_LEGACY_RESPONSE_FIELD: "legacy"}
    assert _extract_tool_response(payload) == "legacy"


def test_extract_tool_response_empty_when_neither_present() -> None:
    assert _extract_tool_response({}) == ""


def test_normalize_response_string() -> None:
    assert _normalize_response("hello") == "hello"


def test_normalize_response_none() -> None:
    assert _normalize_response(None) == ""


def test_normalize_response_content_array() -> None:
    """Anthropic content-block array shape: {"content": [{"type":"text","text":"..."}]}"""
    value = {"content": [{"type": "text", "text": "first"}, {"type": "text", "text": "second"}]}
    assert _normalize_response(value) == "first\nsecond"


def test_normalize_response_bash_style() -> None:
    value = {"stdout": "cmd output", "stderr": "errors", "exit_code": 0}
    assert _normalize_response(value) == "cmd output"


def test_normalize_response_freeform_dict() -> None:
    value = {"foo": "bar", "n": 42}
    result = _normalize_response(value)
    assert json.loads(result) == value


# ----------------------------------------------------------------------
# Plan 009 WI-1.2: digest semantics under truncation
# ----------------------------------------------------------------------


@patch("cairn._claude_hook._run_bridge")
def test_handle_post_digest_covers_full_output_when_truncated(
    mock_bridge: MagicMock, state_dir: Path
) -> None:
    """WI-1.2: when output exceeds the transport cap, the digest still
    covers the FULL output — an auditor holding the real output can
    reproduce it.  truncated=True and bytes_total reflects the full size."""
    wi_id = str(uuid.uuid4())
    tool_input = {"command": "yes | head -5000"}
    key = _call_key("Bash", tool_input)
    state_file = _next_state_file(state_dir, key)
    state_file.write_text(
        json.dumps({"work_item_id": wi_id, "session_id": "test-session", "tool": "Bash"})
    )
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    # Output larger than the 2000-char transport cap.
    real_output = "x" * (_TRANSPORT_CAP + 5000)
    hook_input = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_response": real_output,
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post()

    call_args = mock_bridge.call_args[0][0]
    rs = call_args["result_summary"]
    # Digest covers the FULL output.
    expected = hashlib.sha256(real_output.encode("utf-8")).hexdigest()
    assert rs["stdout_digest"] == expected
    assert rs["stdout_bytes_total"] == len(real_output.encode("utf-8"))
    assert rs["stdout_truncated"] is True
    # Transported text is capped.
    assert len(rs["stdout"]) == _TRANSPORT_CAP


@patch("cairn._claude_hook._run_bridge")
def test_handle_post_digest_not_truncated_for_small_output(
    mock_bridge: MagicMock, state_dir: Path
) -> None:
    """WI-1.2: small output — truncated=False, digest matches."""
    wi_id = str(uuid.uuid4())
    tool_input = {"command": "echo hi"}
    key = _call_key("Bash", tool_input)
    state_file = _next_state_file(state_dir, key)
    state_file.write_text(
        json.dumps({"work_item_id": wi_id, "session_id": "test-session", "tool": "Bash"})
    )
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    real_output = "hi\n"
    hook_input = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_response": real_output,
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post()

    rs = mock_bridge.call_args[0][0]["result_summary"]
    assert rs["stdout_digest"] == hashlib.sha256(real_output.encode("utf-8")).hexdigest()
    assert rs["stdout_truncated"] is False
    assert rs["stdout_bytes_total"] == len(real_output.encode("utf-8"))


def test_compute_output_digest_matches_independent_sha256() -> None:
    """The helper produces the same digest as an independent sha256."""
    text = "some tool output\nwith multiple lines\n"
    digest, total = _compute_output_digest(text)
    assert digest == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert total == len(text.encode("utf-8"))


def test_compute_output_digest_multibyte_utf8() -> None:
    """bytes_total counts UTF-8 bytes, not characters."""
    text = "café ☕ 日本語"  # multibyte chars
    digest, total = _compute_output_digest(text)
    assert digest == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert total == len(text.encode("utf-8"))
    assert total > len(text)  # multibyte


# ----------------------------------------------------------------------
# Plan 009 WI-1.3: recorded-reality fixtures (tool_response shapes)
# ----------------------------------------------------------------------


@patch("cairn._claude_hook._run_bridge")
def test_handle_post_with_content_array_response(mock_bridge: MagicMock, state_dir: Path) -> None:
    """Fixture mirroring real Claude Code tool_response shape:
    {"content": [{"type":"text","text":"..."}]}.

    The digest covers the extracted text, not the raw JSON."""
    wi_id = str(uuid.uuid4())
    tool_input = {"filePath": "/tmp/read.py"}
    key = _call_key("Read", tool_input)
    state_file = _next_state_file(state_dir, key)
    state_file.write_text(
        json.dumps({"work_item_id": wi_id, "session_id": "test-session", "tool": "Read"})
    )
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    file_content = "def hello():\n    print('world')\n"
    hook_input = json.dumps(
        {
            "tool_name": "Read",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_response": {
                "content": [{"type": "text", "text": file_content}],
            },
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post()

    rs = mock_bridge.call_args[0][0]["result_summary"]
    # Digest is over the extracted text, not the raw dict.
    assert rs["stdout_digest"] == hashlib.sha256(file_content.encode("utf-8")).hexdigest()
    assert rs["stdout_bytes_total"] == len(file_content.encode("utf-8"))


@patch("cairn._claude_hook._run_bridge")
def test_handle_post_failure_with_content_array(mock_bridge: MagicMock, state_dir: Path) -> None:
    """PostToolUseFailure with a content-array tool_response: the error
    field carries the real failure detail, not just 'tool call failed'."""
    wi_id = str(uuid.uuid4())
    tool_input = {"command": "false"}
    key = _call_key("Bash", tool_input)
    state_file = _next_state_file(state_dir, key)
    state_file.write_text(
        json.dumps({"work_item_id": wi_id, "session_id": "test-session", "tool": "Bash"})
    )
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    error_detail = "command exited with code 1"
    hook_input = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": tool_input,
            "session_id": "test-session",
            "tool_response": {
                "content": [{"type": "text", "text": error_detail}],
            },
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post(failure=True)

    call_args = mock_bridge.call_args[0][0]
    assert call_args["error"] == error_detail
    rs = call_args["result_summary"]
    assert rs["stdout_digest"] == hashlib.sha256(error_detail.encode("utf-8")).hexdigest()


@patch("cairn._claude_hook._run_bridge")
def test_handle_post_legacy_tool_output_fallback(mock_bridge: MagicMock, state_dir: Path) -> None:
    """Legacy harnesses that still send tool_output (no tool_response) are
    handled — the fallback produces a correct digest over the real output."""
    wi_id = str(uuid.uuid4())
    tool_input = {"command": "echo legacy"}
    key = _call_key("Bash", tool_input)
    state_file = _next_state_file(state_dir, key)
    state_file.write_text(
        json.dumps({"work_item_id": wi_id, "session_id": "test-session", "tool": "Bash"})
    )
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    real_output = "legacy output\n"
    hook_input = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": tool_input,
            "session_id": "test-session",
            _LEGACY_RESPONSE_FIELD: real_output,
        }
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_post()

    rs = mock_bridge.call_args[0][0]["result_summary"]
    assert rs["stdout_digest"] == hashlib.sha256(real_output.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------
# Plan 009 WI-1.1: capture mode (CAIRN_CAPTURE_DIR)
# ----------------------------------------------------------------------


@patch("cairn._claude_hook._run_bridge")
def test_capture_mode_writes_raw_payload(mock_bridge: MagicMock, tmp_path: Path) -> None:
    """When CAIRN_CAPTURE_DIR is set, the raw hook stdin is written verbatim."""
    mock_bridge.return_value = {"status": "ok", "work_item_id": str(uuid.uuid4()), "args_hash": "x"}
    capture_dir = tmp_path / "captures"
    hook_input = json.dumps(
        {"tool_name": "Edit", "tool_input": {"filePath": "/tmp/x.py"}, "session_id": "cap-session"}
    )

    with patch.dict(os.environ, {"CAIRN_CAPTURE_DIR": str(capture_dir)}):
        with patch("sys.stdin", StringIO(hook_input)):
            handle_pre()

    files = list(capture_dir.glob("*.json"))
    assert len(files) == 1
    assert json.loads(files[0].read_text())["tool_name"] == "Edit"


@patch("cairn._claude_hook._run_bridge")
def test_capture_mode_off_by_default(mock_bridge: MagicMock, tmp_path: Path) -> None:
    """Without CAIRN_CAPTURE_DIR, no capture files are written."""
    mock_bridge.return_value = {"status": "ok", "work_item_id": str(uuid.uuid4()), "args_hash": "x"}
    capture_dir = tmp_path / "captures"
    hook_input = json.dumps(
        {"tool_name": "Edit", "tool_input": {"filePath": "/tmp/x.py"}, "session_id": "cap2-session"}
    )

    with patch("sys.stdin", StringIO(hook_input)):
        handle_pre()

    assert not capture_dir.exists()


# ----------------------------------------------------------------------
# Plan 009 WI-1.1: recorded-reality fixture tests
# These tests load REAL Claude Code 2.1.206 hook payloads captured via
# CAIRN_CAPTURE_DIR, sanitized and committed as fixtures.  They verify
# that the attested digest equals an independently computed sha256 of
# the REAL tool output (the field the harness actually sends), not a
# hand-written assumption.
# ----------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "hook_payloads"


def _load_fixture(name: str) -> dict[str, Any]:
    return json.loads((_FIXTURES_DIR / name).read_text())


def _setup_state_and_post(
    mock_bridge: MagicMock,
    state_dir: Path,
    fixture: dict[str, Any],
    *,
    failure: bool = False,
) -> dict[str, Any]:
    """Set up a state file from the fixture's PreToolUse fields, feed
    the PostToolUse payload, and return the bridge call args."""
    wi_id = str(uuid.uuid4())
    tool_input = fixture["tool_input"]
    tool_name = fixture["tool_name"]
    session_id = fixture["session_id"]
    key = _call_key(tool_name, tool_input)
    # Write state file to the dir matching the fixture's session_id.
    fixture_state_dir = state_dir.parent / _safe_session_id(session_id)
    fixture_state_dir.mkdir(parents=True, exist_ok=True)
    state_file = _next_state_file(fixture_state_dir, key)
    state_file.write_text(
        json.dumps({"work_item_id": wi_id, "session_id": session_id, "tool": tool_name})
    )
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}

    with patch("sys.stdin", StringIO(json.dumps(fixture))):
        handle_post(failure=failure)

    return mock_bridge.call_args[0][0]


@patch("cairn._claude_hook._run_bridge")
def test_fixture_post_read_digest_matches_real_file_content(
    mock_bridge: MagicMock, state_dir: Path
) -> None:
    """Recorded PostToolUse (Read): the attested digest equals sha256 of
    the real file content extracted from tool_response.file.content."""
    fixture = _load_fixture("post_read.json")
    call_args = _setup_state_and_post(mock_bridge, state_dir, fixture)

    real_output = fixture["tool_response"]["file"]["content"]
    rs = call_args["result_summary"]
    assert rs["stdout_digest"] == hashlib.sha256(real_output.encode("utf-8")).hexdigest()
    assert rs["stdout_bytes_total"] == len(real_output.encode("utf-8"))
    assert rs["stdout_truncated"] is False


@patch("cairn._claude_hook._run_bridge")
def test_fixture_post_bash_digest_matches_real_stdout(
    mock_bridge: MagicMock, state_dir: Path
) -> None:
    """Recorded PostToolUse (Bash): the attested digest equals sha256 of
    the real stdout extracted from tool_response.stdout."""
    fixture = _load_fixture("post_bash.json")
    call_args = _setup_state_and_post(mock_bridge, state_dir, fixture)

    real_output = fixture["tool_response"]["stdout"]
    rs = call_args["result_summary"]
    assert rs["stdout_digest"] == hashlib.sha256(real_output.encode("utf-8")).hexdigest()
    assert rs["stdout_bytes_total"] == len(real_output.encode("utf-8"))


@patch("cairn._claude_hook._run_bridge")
def test_fixture_post_write_digest_matches_real_content(
    mock_bridge: MagicMock, state_dir: Path
) -> None:
    """Recorded PostToolUse (Write): the attested digest equals sha256 of
    the real written content from tool_response.content."""
    fixture = _load_fixture("post_write.json")
    call_args = _setup_state_and_post(mock_bridge, state_dir, fixture)

    real_output = fixture["tool_response"]["content"]
    rs = call_args["result_summary"]
    assert rs["stdout_digest"] == hashlib.sha256(real_output.encode("utf-8")).hexdigest()
    assert rs["stdout_bytes_total"] == len(real_output.encode("utf-8"))


@patch("cairn._claude_hook._run_bridge")
def test_fixture_post_failure_carries_real_error_detail(
    mock_bridge: MagicMock, state_dir: Path
) -> None:
    """Recorded PostToolUseFailure (Read): the error field carries the
    REAL failure detail from the harness, not generic 'tool call failed'.
    The digest covers the real error text."""
    fixture = _load_fixture("post_failure_read.json")
    call_args = _setup_state_and_post(mock_bridge, state_dir, fixture, failure=True)

    real_error = fixture["error"]
    assert call_args["error"] == real_error
    rs = call_args["result_summary"]
    assert rs["stdout_digest"] == hashlib.sha256(real_error.encode("utf-8")).hexdigest()


@patch("cairn._claude_hook._run_bridge")
def test_fixture_session_start_attests_real_session_id(
    mock_bridge: MagicMock,
) -> None:
    """Recorded SessionStart: the hook attests with the real session_id
    from the harness payload."""
    mock_bridge.return_value = {"status": "ok", "event_id": str(uuid.uuid4())}
    fixture = _load_fixture("session_start.json")

    with patch("sys.stdin", StringIO(json.dumps(fixture))):
        handle_session_start()

    call_args = mock_bridge.call_args[0][0]
    assert call_args["session_id"] == fixture["session_id"]
