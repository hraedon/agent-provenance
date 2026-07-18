"""Cairn Codex hook adapter (Plan 011 WI-1.1 / WI-2.1 / WI-2.2).

Drives ``cairn._codex_hook`` with synthetic Codex hook JSON (no real prompts,
paths, hosts, identities, or secrets) and a stubbed bridge, asserting the
event->cairn-event mapping, explicit ``tool_use_id`` correlation, honest
degradation on malformed/incomplete input, and the Stop JSON-output contract.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

import cairn._codex_hook as ch


@pytest.fixture(autouse=True)
def _isolate_state(monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_STATE_DIR", str(tmp_path / "sessions"))


class _Bridge:
    """Records every bridge payload; returns a canned reply."""

    def __init__(self, reply=None):
        self.calls: list[dict] = []
        self._reply = reply if reply is not None else {"status": "ok", "work_item_id": "wi-1"}

    def __call__(self, payload):
        self.calls.append(payload)
        return self._reply


def _feed(monkeypatch, obj_or_str) -> None:
    raw = obj_or_str if isinstance(obj_or_str, str) else json.dumps(obj_or_str)
    monkeypatch.setattr("sys.stdin", io.StringIO(raw))


def _stub_bridge(monkeypatch, reply=None) -> _Bridge:
    bridge = _Bridge(reply)
    monkeypatch.setattr(ch, "_run_bridge", bridge)
    return bridge


def _degradation_text(tmp_path, session_id: str) -> str:
    log = tmp_path / "sessions" / session_id / "degradation.log"
    return log.read_text() if log.is_file() else ""


# --- SessionStart -----------------------------------------------------------


def test_session_start_attests_codex_with_named_scope(monkeypatch):
    bridge = _stub_bridge(monkeypatch, {"status": "ok"})
    monkeypatch.setattr(ch, "_detect_codex_version", lambda: "0.144.1")
    _feed(monkeypatch, {"session_id": "s1", "hook_event_name": "SessionStart", "model": "gpt"})

    ch.handle_session_start()

    assert len(bridge.calls) == 1
    call = bridge.calls[0]
    assert call["action"] == "attest_session"
    assert call["harnesses"][0] == {"name": "codex", "version": "0.144.1"}
    # Decision 7: scope names captured AND uncaptured tool paths.
    assert "Bash" in call["scope_statement"]
    assert "unified exec" in call["scope_statement"]
    assert "WebSearch" in call["scope_statement"]
    assert "session_id" not in json.loads(
        (Path(os.environ["CAIRN_STATE_DIR"]) / "codex-health.json").read_text()
    )


def test_session_start_attests_plugin_config_digest_only(monkeypatch, tmp_path):
    bridge = _stub_bridge(monkeypatch, {"status": "ok"})
    monkeypatch.setattr(ch, "_detect_codex_version", lambda: "0.144.5")
    plugin = tmp_path / "plugin"
    hooks = plugin / "hooks" / "hooks.json"
    hooks.parent.mkdir(parents=True)
    hooks.write_text('{"token":"must-not-cross-bridge"}')
    monkeypatch.setenv("PLUGIN_ROOT", str(plugin))
    _feed(monkeypatch, {"session_id": "s1", "hook_event_name": "SessionStart"})

    ch.handle_session_start()

    call = bridge.calls[0]
    assert call["harness_config_digests"]["codex"].startswith("sha256:")
    assert "must-not-cross-bridge" not in json.dumps(call)


# --- PreToolUse / PostToolUse correlation -----------------------------------


def _pre(session="s1", turn="t1", tid="call-1", tool="Bash", args=None):
    return {
        "hook_event_name": "PreToolUse", "session_id": session, "turn_id": turn,
        "tool_use_id": tid, "tool_name": tool, "tool_input": args or {"command": "ls"},
    }


def test_pre_then_post_pairs_by_tool_use_id(monkeypatch, tmp_path):
    bridge = _stub_bridge(monkeypatch, {"status": "ok", "work_item_id": "wi-42"})
    _feed(monkeypatch, _pre())
    ch.handle_pre()

    assert bridge.calls[0]["action"] == "begin"
    assert bridge.calls[0]["tool"] == "Bash"
    # State file was written keyed by (turn, tool_use_id).
    state_files = list((tmp_path / "sessions" / "s1").glob("*.json"))
    assert len(state_files) == 1

    post = {
        "hook_event_name": "PostToolUse", "session_id": "s1", "turn_id": "t1",
        "tool_use_id": "call-1", "tool_name": "Bash", "tool_input": {"command": "ls"},
        "tool_response": "file1\nfile2\n",
    }
    _feed(monkeypatch, post)
    ch.handle_post()

    end = bridge.calls[1]
    assert end["action"] == "end"
    assert end["work_item_id"] == "wi-42"
    assert end["result_summary"]["exit_code"] == 0
    assert end["result_summary"]["stdout_digest"].startswith("sha256:") or end[
        "result_summary"
    ]["stdout_digest"]
    assert "stdout" not in end["result_summary"]
    assert "file1" not in json.dumps(end)
    # State file consumed on end.
    assert list((tmp_path / "sessions" / "s1").glob("*.json")) == []


def test_codex_never_writes_raw_capture_payloads(monkeypatch, tmp_path):
    capture = tmp_path / "raw-capture"
    monkeypatch.setenv("CAIRN_CAPTURE_DIR", str(capture))
    _stub_bridge(monkeypatch, {"status": "ok", "work_item_id": "wi-secret"})
    payload = _pre(args={"command": "echo highly-sensitive-value"})
    _feed(monkeypatch, payload)

    ch.handle_pre()

    assert not capture.exists()


def test_post_nonzero_exit_from_structured_response(monkeypatch, tmp_path):
    _stub_bridge(monkeypatch, {"status": "ok", "work_item_id": "wi-9"})
    _feed(monkeypatch, _pre(tid="call-2"))
    ch.handle_pre()

    bridge = _stub_bridge(monkeypatch, {"status": "ok"})
    _feed(monkeypatch, {
        "hook_event_name": "PostToolUse", "session_id": "s1", "turn_id": "t1",
        "tool_use_id": "call-2", "tool_name": "Bash", "tool_input": {"command": "false"},
        "tool_response": {"output": "boom", "exit_code": 3},
    })
    ch.handle_post()
    end = bridge.calls[0]
    assert end["result_summary"]["exit_code"] == 3
    assert end["error"].startswith("tool call failed (response sha256:")
    assert "boom" not in end["error"]
    assert "stdout" not in end["result_summary"]


def test_post_without_begin_is_named_degradation(monkeypatch, tmp_path):
    _stub_bridge(monkeypatch, {"status": "ok"})
    _feed(monkeypatch, {
        "hook_event_name": "PostToolUse", "session_id": "sX", "turn_id": "t1",
        "tool_use_id": "orphan", "tool_name": "Bash", "tool_input": {},
        "tool_response": "x",
    })
    ch.handle_post()
    assert "orphan end" in _degradation_text(tmp_path, "sX")


def test_pre_missing_tool_use_id_degrades(monkeypatch, tmp_path):
    _stub_bridge(monkeypatch, {"status": "ok"})
    _feed(monkeypatch, {
        "hook_event_name": "PreToolUse", "session_id": "sY", "turn_id": "t1",
        "tool_name": "Bash", "tool_input": {},  # no tool_use_id
    })
    ch.handle_pre()
    assert "missing tool_use_id" in _degradation_text(tmp_path, "sY")


def test_subagent_id_attached_to_tool_call(monkeypatch):
    bridge = _stub_bridge(monkeypatch, {"status": "ok", "work_item_id": "wi-1"})
    payload = _pre(tid="call-3")
    payload.update({"agent_id": "agent-7", "agent_type": "reviewer"})
    _feed(monkeypatch, payload)
    ch.handle_pre()
    assert bridge.calls[0]["subagent"] == {"agent_id": "agent-7", "agent_type": "reviewer"}


# --- Stop + robustness ------------------------------------------------------


def test_stop_emits_valid_json_and_never_blocks(monkeypatch, capsys):
    _stub_bridge(monkeypatch)
    _feed(monkeypatch, {"hook_event_name": "Stop", "session_id": "s1"})
    ch.handle_stop()
    out = capsys.readouterr().out.strip()
    assert json.loads(out) == {}  # valid JSON, no continuation


def test_malformed_json_does_not_crash(monkeypatch, tmp_path):
    _stub_bridge(monkeypatch)
    _feed(monkeypatch, "{not json")
    ch.handle_pre()  # must not raise
    # session falls back to "unknown"; a degradation is recorded.
    assert _degradation_text(tmp_path, "unknown")


def test_main_stop_emits_json_even_on_handler_error(monkeypatch, capsys):
    def boom():
        raise RuntimeError("bridge exploded")

    monkeypatch.setattr(ch, "handle_stop", boom)
    monkeypatch.setattr(ch, "_DISPATCH", {"stop": boom})
    _feed(monkeypatch, {"hook_event_name": "Stop", "session_id": "s1"})
    rc = ch.main(["stop"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out.strip()) == {}
