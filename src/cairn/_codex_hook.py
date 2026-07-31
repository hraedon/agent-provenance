"""Cairn Codex lifecycle-hook adapter (Plan 011).

Codex command hooks receive a JSON object on stdin and are dispatched by the
``hook_event_name``.  ``cairn install-harness codex`` registers this module as
the command for the events cairn attests, invoking it as::

    cairn-codex-hook <action>

``cairn-codex-hook`` is a console script from the same distribution, so its
shebang pins cairn's own interpreter and the string is stable at packaging
time — which is what lets the shipped Codex plugin
(``plugins/cairn/hooks/hooks.json``) and the directly generated hooks be
byte-identical (WI-033).

where ``<action>`` is one of ``session-start``, ``pre``, ``post``, ``stop``
(see :data:`CODEX_HOOK_ACTIONS`).  The module reuses the Claude adapter's
bridge/state/digest/degradation machinery (:mod:`cairn._claude_hook`) and only
re-implements the parts that differ for Codex:

* **Field names.**  Codex sends ``session_id``, ``turn_id``, ``tool_name``,
  ``tool_use_id``, ``tool_input``, ``tool_response``, ``agent_id``,
  ``agent_type`` (verified against the published hook schema,
  https://learn.chatgpt.com/docs/hooks).
* **Correlation.**  Codex provides an explicit ``tool_use_id``; begin/end pair
  deterministically on ``(session_id, turn_id, tool_use_id)`` (Plan 011
  Decision 3) rather than the timing/heuristic key the Claude adapter derives.
* **Stop output.**  ``Stop`` must emit valid JSON on stdout when it exits 0
  (plain text is invalid for this event).  This adapter always prints a
  non-blocking ``{}`` and never requests continuation (Decision 5): provenance
  must not stop or rewrite the user's Codex turn.

Scope (attested honestly, Decision 7): local function tools (including Bash /
unified exec, ``apply_patch``, MCP calls, and subagent dispatch) are captured
via Pre/PostToolUse.  Hosted tools such as WebSearch and specialized paths that
opt out of the local function-tool hook path are NOT captured and are named as
out of scope in the session attestation.  Subagent *tool* activity is
attributed via the top-level ``agent_id``/``agent_type``; the
SubagentStart/Stop delegation lifecycle (Plan 011 WI-2.3) and
concurrency-stress hardening (WI-2.4) are not yet implemented.

Design invariant: a hook failure is recorded in the bounded per-session
degradation log and never propagates — every entry point returns cleanly (and
``stop`` still emits valid JSON) so a bridge/store outage cannot break Codex.
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
from typing import Any

from ._claude_hook import (
    _FALLBACK_SESSION_ID,
    _FALLBACK_TOOL_NAME,
    _TRANSPORT_CAP,
    _compute_output_digest,
    _extract_files,
    _mark_degraded,
    _run_bridge,
    _safe_session_id,
    _state_dir,
)
from ._hook_selftest import is_selftest, selftest_line

# hook_event_name -> install action token (and back). Only events Cairn handles
# are registered; SessionStart and tool events attest, while Stop performs
# cleanup and emits Codex's required non-blocking JSON response.
CODEX_HOOK_ACTIONS: dict[str, str] = {
    "SessionStart": "session-start",
    "PreToolUse": "pre",
    "PostToolUse": "post",
    "Stop": "stop",
}

# Tool paths this adapter captures vs. the ones it cannot see, named verbatim in
# the session scope attestation so no auditor mistakes silence for coverage.
_CAPTURED_TOOLS = (
    "local function tools including Bash/unified exec, apply_patch, MCP calls, "
    "and Agent/spawn_agent dispatch"
)
_UNCAPTURED_TOOLS = (
    "hosted tools such as WebSearch and specialized tool paths that opt out "
    "of Codex's local function-tool hook path"
)

_CODEX_HEALTH_FILE = "codex-health.json"


def _record_activity(session_id: str, event: str) -> None:
    """Record non-secret local proof that a Codex bridge call succeeded.

    Doctor cannot inspect Codex's persisted hook trust: the supported operator
    surface is the interactive ``/hooks`` browser.  This marker therefore does
    not claim trust.  It records only a timestamp, event name, and a one-way
    digest of the session id so doctor can distinguish configured-only wiring
    from a hook that has actually reached Cairn.
    """
    base = Path(os.environ.get("CAIRN_STATE_DIR", tempfile.gettempdir() + "/cairn-sessions"))
    try:
        base.mkdir(parents=True, exist_ok=True)
        try:
            base.chmod(0o700)
        except OSError:
            pass
        payload = {
            "schema_version": 1,
            "harness": "codex",
            "event": event,
            "last_success_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "session_digest": "sha256:"
            + hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest(),
        }
        fd, tmp_name = tempfile.mkstemp(dir=str(base), prefix=".codex-health-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(payload, handle, sort_keys=True)
                handle.write("\n")
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, base / _CODEX_HEALTH_FILE)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
    except OSError:
        # Health telemetry must never make an otherwise successful provenance
        # write interfere with the Codex turn.
        return


def _read_input() -> tuple[str, dict[str, Any]]:
    """Read and parse the hook stdin. Returns (raw, parsed) with ``{}`` on
    malformed JSON so the caller can degrade instead of raising."""
    raw = sys.stdin.read()
    try:
        parsed = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    return raw, parsed


def _subagent(hook_input: dict[str, Any]) -> dict[str, Any] | None:
    """Build the bridge ``subagent`` payload from Codex's top-level
    ``agent_id``/``agent_type`` when a tool call originates inside a subagent."""
    agent_id = hook_input.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        return None
    out: dict[str, Any] = {"agent_id": agent_id}
    agent_type = hook_input.get("agent_type")
    if isinstance(agent_type, str) and agent_type:
        out["agent_type"] = agent_type
    return out


def _tool_state_file(session_id: str, hook_input: dict[str, Any]) -> Path | None:
    """Deterministic per-tool-call state file keyed by the explicit correlation
    identity ``(turn_id, tool_use_id)``. Returns None when ``tool_use_id`` is
    absent — a named degradation, not a guessed pairing."""
    tool_use_id = hook_input.get("tool_use_id")
    if not isinstance(tool_use_id, str) or not tool_use_id:
        return None
    turn_id = hook_input.get("turn_id")
    turn = turn_id if isinstance(turn_id, str) and turn_id else "noturn"
    key = _safe_session_id(f"codex-{turn}-{tool_use_id}")
    return _state_dir(session_id) / f"{key}.json"


def _detect_codex_version() -> str | None:
    """Live Codex version at attestation time (``codex --version``); None if the
    binary is absent or unparseable (mirrors the Claude adapter's live probe)."""
    try:
        result = subprocess.run(
            ["codex", "--version"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.stdout)
    return m.group(1) if m else None


def _config_digest() -> str | None:
    """Digest the active Cairn hook definition without reading credentials.

    Plugin hooks receive ``PLUGIN_ROOT`` from Codex.  The direct fallback uses
    ``$CODEX_HOME/hooks.json``.  Only the digest crosses the bridge; config
    content is never logged or persisted by Cairn.
    """
    plugin_root = os.environ.get("PLUGIN_ROOT")
    if plugin_root:
        candidate = Path(plugin_root) / "hooks" / "hooks.json"
    else:
        codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
        candidate = codex_home / "hooks.json"
    if not candidate.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with candidate.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return f"sha256:{digest.hexdigest()}"


def handle_session_start() -> None:
    _, hook_input = _read_input()
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    harness_name = os.environ.get("CAIRN_HARNESS_NAME", "codex")
    harness_version = _detect_codex_version() or os.environ.get(
        "CAIRN_HARNESS_VERSION", _FALLBACK_TOOL_NAME
    )
    scope = (
        f"In scope: {harness_name}. Captured tool paths: {_CAPTURED_TOOLS}. "
        f"NOT captured: {_UNCAPTURED_TOOLS}."
    )
    config_digest = _config_digest()
    payload: dict[str, Any] = {
        "action": "attest_session",
        "session_id": session_id,
        "harnesses": [{"name": harness_name, "version": harness_version}],
        "scope_statement": scope,
    }
    if config_digest is not None:
        payload["harness_config_digests"] = {"codex": config_digest}
    reply = _run_bridge(
        payload
    )
    if not reply or reply.get("status") != "ok":
        _mark_degraded(session_id, "codex:session_start", "session attestation bridge call failed")
    else:
        _record_activity(session_id, "SessionStart")


def handle_pre() -> None:
    _, hook_input = _read_input()
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    tool_name = hook_input.get("tool_name", _FALLBACK_TOOL_NAME)
    tool_input = hook_input.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}

    state_file = _tool_state_file(session_id, hook_input)
    if state_file is None:
        _mark_degraded(session_id, "codex:pre", f"missing tool_use_id for {tool_name}")
        return

    subagent = _subagent(hook_input)
    payload: dict[str, Any] = {
        "action": "begin",
        "tool": tool_name,
        "args": tool_input,
        "files": _extract_files(tool_name, tool_input),
        "session_id": session_id,
    }
    if subagent:
        payload["subagent"] = subagent
    reply = _run_bridge(payload)

    if reply and reply.get("status") == "ok":
        work_item_id = reply.get("work_item_id")
        if not work_item_id:
            _mark_degraded(
                session_id, "codex:pre", "bridge returned ok but no work_item_id"
            )
            return
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(
            json.dumps(
                {"work_item_id": work_item_id, "session_id": session_id, "tool": tool_name}
            )
        )
    else:
        _mark_degraded(session_id, "codex:pre", f"bridge call failed for {tool_name}")


def handle_post() -> None:
    _, hook_input = _read_input()
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    tool_name = hook_input.get("tool_name", _FALLBACK_TOOL_NAME)
    tool_input = hook_input.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}

    # tool_response may be a string or a structured object; normalize to text
    # for the digest (audited over the full preimage before truncation).
    response = hook_input.get("tool_response", "")
    if not isinstance(response, str):
        response = json.dumps(response, sort_keys=True, default=str)
    stdout_digest, bytes_total = _compute_output_digest(response)
    truncated = len(response) > _TRANSPORT_CAP
    state_file = _tool_state_file(session_id, hook_input)
    if state_file is None:
        _mark_degraded(session_id, "codex:post", f"missing tool_use_id for {tool_name}")
        return
    if not state_file.is_file():
        _mark_degraded(
            session_id,
            "codex:post",
            f"no begin state for {tool_name} (orphan end)",
        )
        return
    try:
        state = json.loads(state_file.read_text())
    except (json.JSONDecodeError, OSError):
        _mark_degraded(
            session_id, "codex:post", f"state file unreadable for {tool_name}"
        )
        state_file.unlink(missing_ok=True)
        return

    work_item_id = state.get("work_item_id")
    if not work_item_id:
        state_file.unlink(missing_ok=True)
        return

    # Codex reports shell failures inside tool_response; an explicit numeric
    # exit_code in the response object is honored when present.
    exit_code = 0
    if isinstance(hook_input.get("tool_response"), dict):
        raw_code = hook_input["tool_response"].get("exit_code")
        if isinstance(raw_code, int):
            exit_code = raw_code

    subagent = _subagent(hook_input)
    payload: dict[str, Any] = {
        "action": "end",
        "work_item_id": work_item_id,
        "session_id": session_id,
        "result_summary": {
            "exit_code": exit_code,
            "stdout_digest": stdout_digest,
            "stdout_digest_alg": "sha256",
            "stdout_bytes_total": bytes_total,
            "stdout_truncated": truncated,
        },
        "files": _extract_files(tool_name, tool_input),
        # Never persist raw failure output: it can contain credentials or PII.
        # The full response digest remains independently reproducible.
        "error": (
            f"tool call failed (response sha256:{stdout_digest})"
            if exit_code != 0
            else None
        ),
    }
    if subagent:
        payload["subagent"] = subagent
    reply = _run_bridge(payload)
    if not reply or reply.get("status") != "ok":
        _mark_degraded(
            session_id, "codex:post", f"bridge call failed for {tool_name} end"
        )
    else:
        _record_activity(session_id, "PostToolUse")
    state_file.unlink(missing_ok=True)


def handle_stop() -> None:
    """Stop: best-effort session-state cleanup, then emit a valid non-blocking
    JSON response. Never requests continuation (Decision 5)."""
    _, hook_input = _read_input()
    session_id = hook_input.get("session_id", _FALLBACK_SESSION_ID)
    try:
        state = _state_dir(session_id)
        if state.exists():
            has_degradation = (state / "degradation.log").exists()
            for f in state.iterdir():
                if has_degradation and f.name == "degradation.log":
                    continue
                f.unlink(missing_ok=True)
            if not has_degradation:
                state.rmdir()
    except OSError:
        pass
    # Codex requires valid JSON on stdout for Stop; {} lets the turn end normally.
    print(json.dumps({}))


_DISPATCH = {
    "session-start": handle_session_start,
    "pre": handle_pre,
    "post": handle_post,
    "stop": handle_stop,
}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    # Side-effect-free liveness probe (WI-033/WI-034): install and doctor run
    # it to verify the command they wrote/found actually executes.  It must
    # answer before dispatch so it never emits Codex hook JSON or touches the
    # store; reaching it proves cairn imported under this interpreter.
    if is_selftest(args):
        print(selftest_line("codex"))
        return 0
    action = args[0] if args else ""
    handler = _DISPATCH.get(action)
    if handler is None:
        # Unknown action: stay non-blocking. Emit valid JSON so a mis-registered
        # Stop-family hook still satisfies the event contract.
        print(json.dumps({}))
        return 0
    try:
        handler()
    except Exception as exc:  # never break the Codex turn (Decision 5)
        try:
            _mark_degraded(
                _FALLBACK_SESSION_ID,
                f"codex:{action or 'unknown'}",
                f"unhandled hook error: {exc}",
            )
        except Exception:
            pass
        if action == "stop":
            print(json.dumps({}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
