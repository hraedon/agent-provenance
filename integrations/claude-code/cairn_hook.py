#!/usr/bin/env python3
"""Cairn hook for Claude Code.

Handles PreToolUse, PostToolUse, PostToolUseFailure, and SessionStart events.
Dispatches to the `cairn-bridge` script for regista communication.

Manages work_item_id state between Pre and Post calls via session-scoped
temp files under ${CAIRN_STATE_DIR:-/tmp/cairn-sessions}/{session_id}/.

Usage (from .claude/settings.json)::

    See settings.example.json for a ready-to-use configuration.
    All hooks use the form::

        python3 ${CLAUDE_PROJECT_DIR}/integrations/claude-code/cairn_hook.py <action>

    Actions: pre, post, post-failure, session-start, session-end

Environment::

    CAIRN_DSN             Postgres DSN for regista
    CAIRN_PROJECT         Regista project name
    CAIRN_KEY_PATH        Path to HMAC key file
    CAIRN_STATE_DIR       Directory for session state (default: /tmp/cairn-sessions)
    CAIRN_DISABLE         If set, silently exits 0
    PRINCIPAL_ID          Human principal (default: OS user)
    CAIRN_HARNESS_NAME    Harness name (default: claude-code)
    CAIRN_HARNESS_VERSION Harness version (default: unknown)
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_DEFAULT_STATE_DIR = "/tmp/cairn-sessions"
_FALLBACK_SESSION_ID = "unknown"
_FALLBACK_TOOL_NAME = "unknown"


def _safe_session_id(session_id: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9._-]", "_", session_id)
    if sanitized != session_id:
        print(
            f"cairn_hook: session_id sanitized {session_id!r} -> {sanitized!r}",
            file=sys.stderr,
        )
    return sanitized


def _state_dir(session_id: str) -> Path:
    base = os.environ.get("CAIRN_STATE_DIR", _DEFAULT_STATE_DIR)
    d = Path(base) / _safe_session_id(session_id)
    d.mkdir(parents=True, exist_ok=True)
    # Restrict directory permissions to owner-only (0o700).
    try:
        d.chmod(0o700)
    except OSError:
        pass
    # Also restrict the base directory if we created it.
    base_path = Path(base)
    if base_path.exists():
        try:
            base_path.chmod(0o700)
        except OSError:
            pass
    return d


def _call_key(tool_name: str, tool_input: dict) -> str:
    canonical = json.dumps(tool_input, separators=(",", ":"), sort_keys=True)
    h = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    safe_tool = tool_name.replace("/", "_").replace("\\", "_")
    return f"{safe_tool}:{h}"


def _run_bridge(payload: dict) -> dict | None:
    bridge = os.environ.get("CAIRN_BRIDGE_PATH", "cairn-bridge")
    try:
        result = subprocess.run(
            [bridge],
            input=json.dumps(payload) + "\n",
            capture_output=True,
            text=True,
            timeout=10,
            env=os.environ,
        )
        if result.returncode != 0:
            return None
        if result.stdout.strip():
            return json.loads(result.stdout.strip())
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass
    return None


def _mark_degraded(session_id: str, action: str, detail: str) -> None:
    ts = datetime.datetime.now(datetime.UTC).isoformat()
    sd = _state_dir(session_id)
    marker = sd / "degradation.log"
    entry = json.dumps({"ts": ts, "action": action, "detail": detail}, separators=(",", ":"))
    with marker.open("a") as f:
        f.write(entry + "\n")


def _extract_files(tool_name: str, tool_input: dict) -> list[str]:
    files: list[str] = []
    for key in ("filePath", "file_path", "path", "file"):
        if key in tool_input and isinstance(tool_input[key], str):
            files.append(tool_input[key])
    for key in ("files", "paths"):
        if key in tool_input:
            val = tool_input[key]
            if isinstance(val, list):
                files.extend(v for v in val if isinstance(v, str))
            elif isinstance(val, str):
                files.append(val)
    return files


def handle_pre() -> None:
    hook_input = json.loads(sys.stdin.read())
    tool_name = hook_input.get("tool_name", _FALLBACK_TOOL_NAME)
    tool_input = hook_input.get("tool_input", {})
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)

    files = _extract_files(tool_name, tool_input)

    reply = _run_bridge(
        {
            "action": "begin",
            "tool": tool_name,
            "args": tool_input,
            "files": files,
            "session_id": session_id,
        }
    )

    if reply and reply.get("status") == "ok":
        key = _call_key(tool_name, tool_input)
        state_file = _state_dir(session_id) / f"{key}.json"
        state_file.write_text(
            json.dumps(
                {
                    "work_item_id": reply["work_item_id"],
                    "session_id": session_id,
                    "tool": tool_name,
                }
            )
        )
    else:
        _mark_degraded(session_id, "pre", f"bridge call failed for {tool_name}")


def handle_post(*, failure: bool = False) -> None:
    hook_input = json.loads(sys.stdin.read())
    tool_name = hook_input.get("tool_name", _FALLBACK_TOOL_NAME)
    tool_input = hook_input.get("tool_input", {})
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    tool_output = hook_input.get("tool_output", "")

    key = _call_key(tool_name, tool_input)
    state_file = _state_dir(session_id) / f"{key}.json"

    if not state_file.exists():
        return

    try:
        state = json.loads(state_file.read_text())
    except (json.JSONDecodeError, OSError):
        return

    work_item_id = state.get("work_item_id")
    if not work_item_id:
        return

    files = _extract_files(tool_name, tool_input)

    error = None
    if failure:
        error = str(tool_output)[:500] if tool_output else "tool call failed"

    stdout_text = ""
    if isinstance(tool_output, str):
        stdout_text = tool_output[:2000]
    elif isinstance(tool_output, dict):
        stdout_text = json.dumps(tool_output)[:2000]

    reply = _run_bridge(
        {
            "action": "end",
            "work_item_id": work_item_id,
            "session_id": session_id,
            "result_summary": {
                "exit_code": 1 if failure else 0,
                "stdout": stdout_text,
            },
            "files": files,
            "error": error,
        }
    )
    if not reply or reply.get("status") != "ok":
        _mark_degraded(session_id, "post", f"bridge call failed for {tool_name} end")

    try:
        state_file.unlink(missing_ok=True)
    except OSError:
        pass


def _resolve_settings_digest() -> str | None:
    candidates: list[Path] = []
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        candidates.append(Path(project_dir) / ".claude" / "settings.json")
    home = Path.home()
    candidates.append(home / ".claude" / "settings.json")
    for p in candidates:
        if p.is_file():
            return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
    return None


def handle_session_start() -> None:
    hook_input = json.loads(sys.stdin.read())
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)

    harness_name = os.environ.get("CAIRN_HARNESS_NAME", "claude-code")
    config_digest = _resolve_settings_digest()

    reply = _run_bridge(
        {
            "action": "attest_session",
            "session_id": session_id,
            "harnesses": [
                {
                    "name": harness_name,
                    "version": os.environ.get("CAIRN_HARNESS_VERSION", _FALLBACK_TOOL_NAME),
                }
            ],
            "scope_statement": "In scope: claude-code.",
            "harness_config_digests": {harness_name: config_digest} if config_digest else None,
        }
    )
    if not reply or reply.get("status") != "ok":
        _mark_degraded(session_id, "session_start", "session attestation bridge call failed")


def handle_session_end() -> None:
    hook_input = json.loads(sys.stdin.read())
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    state = _state_dir(session_id)
    if not state.exists():
        return
    has_degradation = (state / "degradation.log").exists()
    for f in state.iterdir():
        if has_degradation and f.name == "degradation.log":
            continue
        try:
            f.unlink()
        except OSError:
            pass
    if not has_degradation:
        try:
            state.rmdir()
        except OSError:
            pass


def main() -> None:
    if os.environ.get("CAIRN_DISABLE"):
        return

    if len(sys.argv) < 2:
        print(
            "Usage: cairn_hook.py <pre|post|post-failure|session-start|session-end>",
            file=sys.stderr,
        )
        sys.exit(1)

    action = sys.argv[1]

    try:
        if action == "pre":
            handle_pre()
        elif action == "post":
            handle_post()
        elif action == "post-failure":
            handle_post(failure=True)
        elif action == "session-start":
            handle_session_start()
        elif action == "session-end":
            handle_session_end()
        else:
            print(f"Unknown action: {action}", file=sys.stderr)
            sys.exit(1)
    except Exception as exc:
        print(f"cairn_hook error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
