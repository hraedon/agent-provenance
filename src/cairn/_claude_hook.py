#!/usr/bin/env python3
"""Cairn hook for Claude Code.

Handles PreToolUse, PostToolUse, PostToolUseFailure, SessionStart,
SessionEnd, MessageDisplay, Stop, SubagentStart, SubagentStop, and
PostCompact events.  Dispatches to the `cairn-bridge` script for regista
communication.

Manages work_item_id state between Pre and Post calls via session-scoped
temp files under ${CAIRN_STATE_DIR:-/tmp/cairn-sessions}/{session_id}/.

Usage (from .claude/settings.json)::

    cairn-claude-hook <action>

    Actions: pre, post, post-failure, session-start, session-end,
    message-display, stop, subagent-start, subagent-stop, post-compact

``cairn-claude-hook`` is a console script installed by the same distribution
as this module, so its shebang pins cairn's own interpreter.  A bare
``python3 -m cairn._claude_hook`` is still accepted (and still recognised as
cairn-owned on upgrade) but must not be generated: module resolution then
depends on whatever ``python3`` the harness's PATH finds, which is not cairn's
interpreter under any isolated install — uv tool, pipx or venv (WI-033).
``--selftest`` prints a marker and exits without side effects; install and
doctor use it to verify the hook actually runs.

Environment (resolved via cairn._config — REGISTA_* preferred, CAIRN_* fallback)::

    REGISTA_DSN / CAIRN_DSN          Postgres DSN for regista
    REGISTA_KEY_PATH / CAIRN_KEY_PATH Path to signing key file
    CAIRN_PROJECT                      Regista project name
    CAIRN_STATE_DIR                    Directory for session state (default: /tmp/cairn-sessions)
    CAIRN_DISABLE                      If set, silently exits 0
    CAIRN_CAPTURE_DIR                   If set, raw stdin of every hook invocation
                                      is written verbatim here (Plan 009 WI-1.1
                                      capture mode — for recording real payloads
                                      to use as test fixtures).
    PRINCIPAL_ID                       Human principal (default: OS user)
    CAIRN_HARNESS_NAME                 Harness name (default: claude-code)
    CAIRN_HARNESS_VERSION              Harness version (default: unknown)

Capture correctness (Plan 009):
  - ``tool_response`` is the canonical field Claude Code 2.1.200+ sends
    (``tool_output`` is kept as a legacy fallback).
  - PostToolUseFailure carries the error detail in the ``error`` field,
    not in ``tool_response`` (verified from real Claude Code 2.1.206
    capture).  The hook uses the error text as the digest preimage so
    the attested digest and error detail reflect the real failure.
  - The output digest is computed over the FULL untruncated output (UTF-8
    bytes) before truncating for transport.  See
    ``docs/digest-preimage-definition.md``.
  - Recorded-reality ``tool_response`` shapes (from Claude Code 2.1.206):
    * Read:  ``{"type":"text", "file":{"content":"..."}}``
    * Bash:  ``{"stdout":"...", "stderr":"..."}``
    * Write: ``{"type":"create", "content":"..."}``
    * Edit:  ``{"filePath":"...", "structuredPatch":[...]}``  (free-form JSON)

Subagent attribution (Plan 009 WI-3.1, verified from real Claude Code
2.1.207 capture):
  - Every hook payload fired *inside* a subagent carries ``agent_id`` and
    ``agent_type``; payloads from the main loop carry neither.  Pre/Post
    attribute per-call from the payload itself — correct even when
    multiple subagents run in parallel — and the identity is threaded to
    the bridge as ``subagent`` and into the pre/post pairing key (so an
    identical command run concurrently by parent and subagent cannot
    mis-pair).
  - ``SubagentStart``/``SubagentStop`` are attested to the session entity
    (delegation window open/close); stop digests the subagent's final
    reply and transcript file.
  - ``PostCompact`` is attested to the session entity: context loss is
    provenance-relevant, and the digest covers the summary that replaced
    the dropped context.
  - ``PostToolBatch`` is deliberately NOT attested: its ``tool_calls``
    entries carry the same ``tool_use_id``s as the individual
    ``PostToolUse`` events (verified from capture), so per-call
    attestation already covers every batch member and attesting the
    batch would double-count them.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

from ._hook_selftest import is_selftest, selftest_line

_DEFAULT_STATE_DIR = str(Path(tempfile.gettempdir()) / "cairn-sessions")
_FALLBACK_SESSION_ID = "unknown"
_FALLBACK_TOOL_NAME = "unknown"

# Maximum characters of tool output transported to the bridge for human
# review.  The *digest* (WI-1.2) is always computed over the FULL output
# before this cap is applied — the cap only limits the transported text,
# not the audited preimage.
_TRANSPORT_CAP = 2000

# Canonical field name sent by Claude Code 2.1.200+ (verified by ``strings``
# on the harness binary: 16 hits for ``tool_response``, zero for
# ``tool_output``).  We keep ``tool_output`` as a legacy fallback for older
# harness releases (Plan 009 WI-1.1).
_CANONICAL_RESPONSE_FIELD = "tool_response"
_LEGACY_RESPONSE_FIELD = "tool_output"


def _capture_raw(action: str, hook_input_str: str) -> None:
    """When ``CAIRN_CAPTURE_DIR`` is set, write the raw hook stdin verbatim.

    Plan 009 WI-1.1: a capture mode lets the operator record real harness
    payloads from a live Claude Code session, which are then sanitized and
    committed as test fixtures (``tests/fixtures/hook_payloads/``).  This
    is how we test against recorded reality rather than hand-written
    payloads.
    """
    capture_dir = os.environ.get("CAIRN_CAPTURE_DIR")
    if not capture_dir:
        return
    cdir = Path(capture_dir)
    cdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%S%f")
    dest = cdir / f"{ts}_{action}.json"
    try:
        dest.write_text(hook_input_str)
    except OSError:
        pass


def _normalize_response(value: Any) -> str:
    """Normalize a ``tool_response`` / ``tool_output`` value to text.

    Claude Code's ``tool_response`` field can arrive in several shapes
    depending on the tool.  This helper extracts a plain text
    representation suitable for digesting.

    Shapes handled (verified from real Claude Code 2.1.206 captures):
      - ``str`` — used directly
      - ``{"content": [{"type":"text","text":"..."}]}`` — content-block
        array (text blocks joined with newline)
      - ``{"file": {"content": "..."}}`` — Read tool nested file content
      - ``{"stdout": "..."}`` — Bash-style output
      - ``{"content": "..."}`` (string) — Write tool top-level content
      - Other ``dict`` / ``list`` — canonical JSON

    The preimage contract (Plan 009 WI-1.2): the digest covers the UTF-8
    encoding of the string returned here.  An auditor reproduces the digest
    by applying the same normalization to the real output, then encoding to
    UTF-8.  See ``docs/digest-preimage-definition.md``.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        # Anthropic content-block array: {"content": [{"type":"text","text":"..."}]}
        content = value.get("content")
        if isinstance(content, list):
            parts: list[str] = []
            for block in content:
                if isinstance(block, dict):
                    if isinstance(block.get("text"), str):
                        parts.append(block["text"])
                elif isinstance(block, str):
                    parts.append(block)
            if parts:
                return "\n".join(parts)
        # Read tool: {"type": "text", "file": {"content": "...", ...}}
        # (verified from real Claude Code 2.1.206 capture — Plan 009 WI-1.1)
        file_obj = value.get("file")
        if isinstance(file_obj, dict):
            file_content = file_obj.get("content")
            if isinstance(file_content, str):
                return file_content
        # Standard output fields: Bash stdout, Write content, etc.
        # "content" is checked here for the Write shape where it's a
        # top-level string (the list case is handled above).
        for key in ("stdout", "output", "result", "text", "content"):
            v = value.get(key)
            if isinstance(v, str):
                return v
        # Free-form dict — canonical JSON.
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if isinstance(value, list):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value)


def _extract_tool_response(hook_input: dict[str, Any]) -> str:
    """Read the tool result from the hook input (Plan 009 WI-1.1).

    Claude Code 2.1.200 sends ``tool_response``; older releases sent
    ``tool_output``.  We prefer the canonical field and fall back to the
    legacy field for one release of backward compatibility.
    """
    if _CANONICAL_RESPONSE_FIELD in hook_input:
        return _normalize_response(hook_input[_CANONICAL_RESPONSE_FIELD])
    if _LEGACY_RESPONSE_FIELD in hook_input:
        return _normalize_response(hook_input[_LEGACY_RESPONSE_FIELD])
    return ""


def _compute_output_digest(text: str) -> tuple[str, int]:
    """Compute the SHA-256 digest and byte length of the full output.

    Returns ``(digest_hex, bytes_total)`` where ``digest_hex`` is the bare
    hex SHA-256 of the UTF-8 encoding of ``text``, and ``bytes_total`` is
    the number of UTF-8 bytes.  This is the preimage contract: an auditor
    holding the real output computes ``sha256(output.encode("utf-8"))`` and
    compares the hex digest.  See ``docs/digest-preimage-definition.md``.
    """
    full_bytes = text.encode("utf-8")
    return hashlib.sha256(full_bytes).hexdigest(), len(full_bytes)


def _safe_session_id(session_id: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9._-]", "_", session_id)
    if sanitized in (".", ".."):
        sanitized = "_"
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


def _extract_subagent(hook_input: dict[str, Any]) -> dict[str, Any] | None:
    """Read the subagent identity from a hook payload (Plan 009 WI-3.1).

    Claude Code stamps every hook payload fired inside a subagent with
    ``agent_id``/``agent_type``; main-loop payloads carry neither.
    """
    agent_id = hook_input.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        return None
    sub: dict[str, Any] = {"agent_id": agent_id}
    agent_type = hook_input.get("agent_type")
    if isinstance(agent_type, str) and agent_type:
        sub["agent_type"] = agent_type
    return sub


def _call_key(tool_name: str, tool_input: dict[str, Any], agent_id: str | None = None) -> str:
    canonical = json.dumps(tool_input, separators=(",", ":"), sort_keys=True)
    # The pre/post pairing key includes the subagent identity: parent and
    # subagent can run the same tool with identical args concurrently, and
    # without agent_id in the key the FIFO pairing could attribute one's
    # result to the other (Plan 009 WI-3.1).
    if agent_id:
        canonical = f"{agent_id}\x00{canonical}"
    h = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    safe_tool = re.sub(r"[^a-zA-Z0-9._-]", "_", tool_name)
    return f"{safe_tool}:{h}"


def _next_state_file(state_dir: Path, key: str) -> Path:
    """Find the next available state file for this call key (WI-023).

    Repeated identical tool calls (same tool, same args) would collide on
    the same ``{key}.json`` filename.  Instead we use ``{key}.{seq}.json``
    where ``seq`` is a monotonically increasing integer, so each begin
    gets a unique state file.  The matching post picks the oldest (FIFO).

    Uses ``O_EXCL`` to handle concurrent pre hooks safely (adversarial
    review H2): if two pre hooks race on the same seq, the loser retries
    with the next seq.
    """
    prefix = f"{key}."
    max_seq = 0
    for f in state_dir.glob(f"{prefix}*.json"):
        stem = f.stem
        try:
            seq = int(stem.rsplit(".", 1)[-1])
            max_seq = max(max_seq, seq)
        except ValueError:
            continue
    for attempt in range(max_seq + 1, max_seq + 100):
        candidate = state_dir / f"{key}.{attempt}.json"
        try:
            fd = os.open(
                str(candidate),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(fd)
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError(f"could not allocate state file for {key}")


def _oldest_state_file(state_dir: Path, key: str) -> Path | None:
    """Find the oldest state file for this call key (WI-023).

    Returns ``None`` if no state file exists for this key.  Also checks
    for the legacy ``{key}.json`` format (backward compat, adversarial
    review H3).
    """
    legacy = state_dir / f"{key}.json"
    if legacy.exists():
        return legacy
    prefix = f"{key}."
    candidates: list[tuple[int, Path]] = []
    for f in state_dir.glob(f"{prefix}*.json"):
        stem = f.stem
        try:
            seq = int(stem.rsplit(".", 1)[-1])
            candidates.append((seq, f))
        except ValueError:
            continue
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0])
    return candidates[0][1]


def _run_bridge(payload: dict[str, Any]) -> dict[str, Any] | None:
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
            return cast(dict[str, Any], json.loads(result.stdout.strip()))
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


def _note_withheld_content(
    session_id: str, action: str, reply: dict[str, Any] | None
) -> None:
    """Record locally that the bridge withheld content it could not encrypt.

    The event itself already carries the reason (signed, WI-037); this puts the
    same fact where an operator looks first, so "encryption broke and content
    stopped being captured" is attributable without querying the store.
    """
    if not reply:
        return
    note = reply.get("content_encryption_error")
    if isinstance(note, str) and note:
        _mark_degraded(session_id, action, note)


def _extract_files(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
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
    raw = sys.stdin.read()
    _capture_raw("pre", raw)
    hook_input = json.loads(raw)
    tool_name = hook_input.get("tool_name", _FALLBACK_TOOL_NAME)
    tool_input = hook_input.get("tool_input", {})
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    subagent = _extract_subagent(hook_input)

    files = _extract_files(tool_name, tool_input)

    bridge_payload: dict[str, Any] = {
        "action": "begin",
        "tool": tool_name,
        "args": tool_input,
        "files": files,
        "session_id": session_id,
    }
    if subagent:
        bridge_payload["subagent"] = subagent
    reply = _run_bridge(bridge_payload)

    if reply and reply.get("status") == "ok":
        wi_id = reply.get("work_item_id")
        if not wi_id:
            _mark_degraded(session_id, "pre", "bridge returned ok but no work_item_id")
            return
        key = _call_key(tool_name, tool_input, subagent["agent_id"] if subagent else None)
        state_file = _next_state_file(_state_dir(session_id), key)
        with open(state_file, "w") as f:
            f.write(json.dumps(
                {
                    "work_item_id": reply["work_item_id"],
                    "session_id": session_id,
                    "tool": tool_name,
                }
            ))
    else:
        _mark_degraded(session_id, "pre", f"bridge call failed for {tool_name}")


def handle_post(*, failure: bool = False) -> None:
    raw = sys.stdin.read()
    _capture_raw("post-failure" if failure else "post", raw)
    hook_input = json.loads(raw)
    tool_name = hook_input.get("tool_name", _FALLBACK_TOOL_NAME)
    tool_input = hook_input.get("tool_input", {})
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    subagent = _extract_subagent(hook_input)

    # WI-1.1: read tool_response (canonical for Claude Code 2.1.200+) with
    # tool_output as a legacy fallback.
    full_output = _extract_tool_response(hook_input)

    # PostToolUseFailure carries the error detail in the "error" field,
    # not in tool_response (verified from real Claude Code 2.1.206
    # capture — Plan 009 WI-1.1).  When tool_response is absent, use
    # the error text as the output for digesting so the attested digest
    # and error detail reflect the real failure.
    if failure and not full_output:
        error_text = hook_input.get("error")
        if isinstance(error_text, str) and error_text:
            full_output = error_text

    # WI-1.2: digest the FULL untruncated output before truncating for
    # transport.  An auditor reproduces this digest against the complete
    # real output; the truncated text is only for human review.
    stdout_digest, bytes_total = _compute_output_digest(full_output)
    truncated = len(full_output) > _TRANSPORT_CAP
    stdout_text = full_output[:_TRANSPORT_CAP]

    key = _call_key(tool_name, tool_input, subagent["agent_id"] if subagent else None)
    state_file = _oldest_state_file(_state_dir(session_id), key)

    if state_file is None:
        _mark_degraded(session_id, "post", f"state file missing for {tool_name}")
        return

    try:
        state = json.loads(state_file.read_text())
    except (json.JSONDecodeError, OSError):
        _mark_degraded(session_id, "post", f"state file unreadable for {tool_name}")
        try:
            state_file.unlink(missing_ok=True)
        except OSError:
            pass
        return

    work_item_id = state.get("work_item_id")
    if not work_item_id:
        try:
            state_file.unlink(missing_ok=True)
        except OSError:
            pass
        return

    files = _extract_files(tool_name, tool_input)

    error = None
    if failure:
        error = full_output[:500] if full_output else "tool call failed"

    end_payload: dict[str, Any] = {
        "action": "end",
        "work_item_id": work_item_id,
        "session_id": session_id,
        "result_summary": {
            "exit_code": 1 if failure else 0,
            "stdout": stdout_text,
            "stdout_digest": stdout_digest,
            "stdout_digest_alg": "sha256",
            "stdout_bytes_total": bytes_total,
            "stdout_truncated": truncated,
        },
        "files": files,
        "error": error,
    }
    if subagent:
        end_payload["subagent"] = subagent
    reply = _run_bridge(end_payload)
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


def _detect_harness_version() -> str | None:
    """Detect the live Claude Code version at attestation time.

    The install-time ``CAIRN_HARNESS_VERSION`` pin goes stale on every harness
    auto-update (the 2026-07-11 live proof caught an attestation claiming the
    pinned 2.1.206 while 2.1.207 was actually running), so the session
    attestation prefers live detection and only falls back to the pin.
    """
    try:
        result = subprocess.run(
            ["claude", "--version"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.stdout)
    return m.group(1) if m else None


def handle_session_start() -> None:
    raw = sys.stdin.read()
    _capture_raw("session-start", raw)
    hook_input = json.loads(raw)
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)

    harness_name = os.environ.get("CAIRN_HARNESS_NAME", "claude-code")
    config_digest = _resolve_settings_digest()
    harness_version = (
        _detect_harness_version()
        or os.environ.get("CAIRN_HARNESS_VERSION", _FALLBACK_TOOL_NAME)
    )

    reply = _run_bridge(
        {
            "action": "attest_session",
            "session_id": session_id,
            "harnesses": [
                {
                    "name": harness_name,
                    "version": harness_version,
                }
            ],
            "scope_statement": "In scope: claude-code.",
            "harness_config_digests": {harness_name: config_digest} if config_digest else None,
        }
    )
    if not reply or reply.get("status") != "ok":
        _mark_degraded(session_id, "session_start", "session attestation bridge call failed")


def handle_session_end() -> None:
    raw = sys.stdin.read()
    _capture_raw("session-end", raw)
    hook_input = json.loads(raw)
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


def handle_message_display() -> None:
    """Capture assistant message content (Plan 010 WI-2.2).

    Claude Code's ``MessageDisplay`` hook fires when the model produces
    output.  We capture the assistant's message content as a signed
    event — this is the v2 content-capture surface.
    """
    raw = sys.stdin.read()
    _capture_raw("message-display", raw)
    hook_input = json.loads(raw)
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)

    message = ""
    if "message" in hook_input:
        msg_val = hook_input["message"]
        if isinstance(msg_val, str):
            message = msg_val
        elif isinstance(msg_val, dict):
            content = msg_val.get("content")
            if isinstance(content, list):
                parts: list[str] = []
                for block in content:
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        parts.append(block["text"])
                if parts:
                    message = "\n".join(parts)
            elif isinstance(content, str):
                message = content
            else:
                message = json.dumps(msg_val, sort_keys=True, ensure_ascii=False)
        else:
            message = str(msg_val)
    elif "text" in hook_input:
        message = str(hook_input["text"])

    if not message:
        return

    reply = _run_bridge(
        {
            "action": "assistant_message",
            "session_id": session_id,
            "message": message,
        }
    )
    if not reply or reply.get("status") != "ok":
        _mark_degraded(session_id, "message_display", "assistant message bridge call failed")
    _note_withheld_content(session_id, "message_display", reply)


def handle_stop() -> None:
    """Capture transcript attestation on session stop (Plan 010 WI-2.2).

    When Claude Code emits a ``Stop`` event, we attest the session
    transcript.  The transcript is the concatenation of all captured
    messages in order — the digest is computed over the full transcript.
    """
    raw = sys.stdin.read()
    _capture_raw("stop", raw)
    hook_input = json.loads(raw)
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)

    reply = _run_bridge(
        {
            "action": "transcript_attestation",
            "session_id": session_id,
            "transcript": raw,
        }
    )
    if not reply or reply.get("status") != "ok":
        _mark_degraded(session_id, "stop", "transcript attestation bridge call failed")
    _note_withheld_content(session_id, "stop", reply)


def handle_subagent_start() -> None:
    """Attest that a subagent began executing (Plan 009 WI-3.1).

    The delegation window opens here; tool calls inside it carry the same
    ``agent_id`` on their own events (per-call attribution).
    """
    raw = sys.stdin.read()
    _capture_raw("subagent-start", raw)
    hook_input = json.loads(raw)
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    subagent = _extract_subagent(hook_input)
    if not subagent:
        _mark_degraded(session_id, "subagent_start", "payload carried no agent_id")
        return

    reply = _run_bridge(
        {
            "action": "subagent_start",
            "session_id": session_id,
            "agent_id": subagent["agent_id"],
            "agent_type": subagent.get("agent_type"),
        }
    )
    if not reply or reply.get("status") != "ok":
        _mark_degraded(session_id, "subagent_start", "subagent start bridge call failed")


def handle_subagent_stop() -> None:
    """Attest that a subagent finished (Plan 009 WI-3.1).

    Digests the subagent's final reply and its transcript file at stop
    time (the subagent analogue of the WI-3.2 transcript attestation).
    """
    raw = sys.stdin.read()
    _capture_raw("subagent-stop", raw)
    hook_input = json.loads(raw)
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    subagent = _extract_subagent(hook_input)
    if not subagent:
        _mark_degraded(session_id, "subagent_stop", "payload carried no agent_id")
        return

    last_message = hook_input.get("last_assistant_message")
    transcript_path = hook_input.get("agent_transcript_path")

    reply = _run_bridge(
        {
            "action": "subagent_stop",
            "session_id": session_id,
            "agent_id": subagent["agent_id"],
            "agent_type": subagent.get("agent_type"),
            "last_assistant_message": last_message if isinstance(last_message, str) else None,
            "agent_transcript_path": transcript_path
            if isinstance(transcript_path, str)
            else None,
        }
    )
    if not reply or reply.get("status") != "ok":
        _mark_degraded(session_id, "subagent_stop", "subagent stop bridge call failed")


def handle_post_compact() -> None:
    """Attest that the harness compacted the session context (Plan 009 WI-3.1).

    Events after this point were produced by a model that no longer saw
    the full history — an auditor must see the discontinuity in the chain.
    """
    raw = sys.stdin.read()
    _capture_raw("post-compact", raw)
    hook_input = json.loads(raw)
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)

    trigger = hook_input.get("trigger")
    compact_summary = hook_input.get("compact_summary")

    reply = _run_bridge(
        {
            "action": "compaction",
            "session_id": session_id,
            "trigger": trigger if isinstance(trigger, str) and trigger else "unknown",
            "compact_summary": compact_summary if isinstance(compact_summary, str) else None,
        }
    )
    if not reply or reply.get("status") != "ok":
        _mark_degraded(session_id, "post_compact", "compaction bridge call failed")
    _note_withheld_content(session_id, "post_compact", reply)


def _env_truthy(name: str) -> bool:
    val = os.environ.get(name)
    if val is None:
        return False
    return val.strip().lower() in ("1", "true", "yes", "on")


def main() -> None:
    # Liveness probe first: it must answer even when cairn is disabled, and it
    # must not touch stdin, the state dir or the store, because install and
    # doctor run it to verify the hook they wrote/found actually executes
    # (WI-033/WI-034).  Reaching this line already proves the command resolved
    # and this interpreter could import cairn.
    if is_selftest(sys.argv[1:]):
        print(selftest_line("claude"))
        return

    if _env_truthy("CAIRN_DISABLE"):
        return

    if len(sys.argv) < 2:
        print(
            "Usage: cairn-claude-hook <pre|post|post-failure|session-start|session-end"
            "|message-display|stop|subagent-start|subagent-stop|post-compact>",
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
        elif action == "message-display":
            handle_message_display()
        elif action == "stop":
            handle_stop()
        elif action == "subagent-start":
            handle_subagent_start()
        elif action == "subagent-stop":
            handle_subagent_stop()
        elif action == "post-compact":
            handle_post_compact()
        else:
            print(f"Unknown action: {action}", file=sys.stderr)
            sys.exit(1)
    except Exception as exc:
        print(f"cairn_hook error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
