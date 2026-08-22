"""cairn — Hermes plugin for tool-call provenance attestation.

.. attention::

   **PROVISIONAL — unverified hook surface.** The ``register(ctx)`` /
   ``ctx.register_hook(...)`` API, the ``**kwargs`` contract documented
   below, and ``plugin.yaml`` manifest are an *assumed* Hermes (Nous
   Research) plugin surface. They have **not** been validated against the
   real Hermes harness — Plan 010 WI-5.1 (interception-surface research,
   one WI per harness) is still open and is the prerequisite that must
   confirm the actual lifecycle events, tool-call interception points,
   transcript/session-end surface, and delegation semantics Hermes
   exposes. Expect the hook names, the kwargs shape, and the manifest
   format to need adjustment once validated against the real API. Do not
   ship this against a live Hermes until WI-5.1 closes.

Registers ``pre_tool_call`` / ``post_tool_call`` hooks that call cairn's
:class:`~cairn.adapter.CairnAdapter` in-process (not via stdin bridge).

The adapter is lazily initialized on first ``pre_tool_call`` so a missing
regista DSN doesn't crash Hermes startup — it degrades silently with a
logged warning, matching the Claude hook's ``CAIRN_DISABLE`` behaviour.

Config resolution reuses :func:`cairn._config.resolve_config` (env-var
precedence: process env → legacy alias → ``suite.env`` file).

Hooks receive ``**kwargs`` including: ``tool_name``, ``args``, ``result``,
``session_id``, ``tool_call_id``, ``turn_id``, ``api_request_id``,
``duration_ms``, ``status``, ``error_type``, ``error_message``.

Session identity: the real session id is captured on ``on_session_start``
and threaded through every subsequent tool-call event's ``on_behalf_of``
delegation chain (mirroring how the opencode plugin threads ``session_id``
on each ``tool.execute.before``/``after``). The adapter default carries
only ``principal_id`` — no placeholder session id ever escapes into a
persisted event.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fail-open guard
# ---------------------------------------------------------------------------

_DISABLE_FLAG = object()  # sentinel: CAIRN_DISABLE is set
_INIT_FAILED = object()  # sentinel: adapter init failed
_LOCK: Any = None  # lazily created (threading import deferred)
_ADAPTER: Any = None  # CairnAdapter | None
_REGISTA: Any = None  # Regista | None
_CFG: Any = None  # CairnEnvConfig | None

# Maps tool_call_id → work_item_id (uuid.UUID).  Thread-safety: Hermes
# runs hooks sequentially within a session, but we use a lock for safety.
_WORK_ITEMS: dict[str, uuid.UUID] = {}

# Real session id (normalized to a UUID string) captured on
# ``on_session_start`` and reused as the fallback for tool-call events that
# don't carry their own ``session_id`` kwarg.  This mirrors the opencode
# plugin, which threads ``session_id`` on every event rather than stashing a
# placeholder.  ``None`` means no session has started yet.
_SESSION_ID: str | None = None


def _ensure_lock() -> Any:
    global _LOCK
    if _LOCK is None:
        import threading
        _LOCK = threading.Lock()
    return _LOCK


def _is_disabled() -> bool:
    """Check CAIRN_DISABLE — if truthy, silently skip all hooks."""
    val = os.environ.get("CAIRN_DISABLE")
    if val is None:
        return False
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_truthy(name: str) -> bool:
    value = os.environ.get(name)
    return value is not None and value.strip().lower() in ("1", "true", "yes", "on")


def _get_adapter() -> tuple[Any, Any, Any]:
    """Lazily initialize the CairnAdapter.

    Returns ``(adapter, regista, cfg)`` or ``(None, None, None)`` if
    init fails (fail-open).  Uses sentinels to avoid re-attempting on
    every hook call after a failure.
    """
    global _ADAPTER, _REGISTA, _CFG

    if _is_disabled():
        return (None, None, None)

    if _ADAPTER is _INIT_FAILED or _REGISTA is _INIT_FAILED:
        return (None, None, None)

    if _ADAPTER is not None and _REGISTA is not None and _CFG is not None:
        return (_ADAPTER, _REGISTA, _CFG)

    lock = _ensure_lock()
    with lock:
        # Double-check after acquiring lock.
        if _ADAPTER is not None and _REGISTA is not None:
            return (_ADAPTER, _REGISTA, _CFG)
        if _ADAPTER is _INIT_FAILED:
            return (None, None, None)

        try:
            from cairn._config import resolve_config

            cfg = resolve_config()

            if not cfg.is_configured:
                missing = ", ".join(cfg.missing())
                logger.debug(
                    "cairn plugin: not configured (missing: %s) — hooks disabled",
                    missing,
                )
                _ADAPTER = _INIT_FAILED
                _REGISTA = _INIT_FAILED
                _CFG = _INIT_FAILED
                return (None, None, None)

            from regista import Regista

            from cairn import CairnAdapter, CairnConfig

            # Resolve key_path (handles key_ref via temp file).
            key_path = _resolve_key_path(cfg)

            sub = Regista(
                dsn=cfg.dsn,
                project=cfg.project,
                hmac_key_path=key_path,
            )

            harness_name = cfg.harness_name or "hermes"
            harness_version = cfg.harness_version or "unknown"

            adapter = CairnAdapter(
                sub,
                config=CairnConfig(harness_name, harness_version),
                # Adapter default carries only principal_id — the real
                # session_id is threaded per-event via _resolve_session_id
                # (see on_pre_tool_call / on_post_tool_call). No placeholder
                # session id ("pending" or otherwise) ever escapes into a
                # persisted event.
                on_behalf_of={
                    "principal_id": cfg.principal_id or "human:unknown",
                },
            )

            _ADAPTER = adapter
            _REGISTA = sub
            _CFG = cfg
            logger.debug(
                "cairn plugin: adapter initialized (harness=%s, project=%s)",
                harness_name,
                cfg.project,
            )
            return (_ADAPTER, _REGISTA, _CFG)

        except Exception as exc:
            logger.debug(
                "cairn plugin: init failed (%s) — hooks disabled", exc, exc_info=True
            )
            _ADAPTER = _INIT_FAILED
            _REGISTA = _INIT_FAILED
            _CFG = _INIT_FAILED
            return (None, None, None)


def _resolve_key_path(cfg: Any) -> str:
    """Return a usable ``hmac_key_path`` from the config.

    When ``key_path`` is set, return it directly.
    When ``key_ref`` is set, create a temporary key-set JSON that uses
    ``secret_ref`` so regista's KeySet resolves the key material from the
    configured backend (env, vault, azure).
    """
    if cfg.key_path:
        return cfg.key_path
    if not cfg.key_ref:
        raise RuntimeError("neither key_path nor key_ref configured")

    import atexit
    import json
    import tempfile

    from regista._secrets import resolve as resolve_secret

    raw = resolve_secret(cfg.key_ref)

    key_set: dict[str, Any]
    try:
        key_data = json.loads(raw)
        if isinstance(key_data, dict) and "keys" in key_data:
            # NOTE: a keyset resolved to inline secret material (not a
            # secret_ref) lands verbatim in a 0o600 temp file cleaned at
            # exit. Fail-closed key hygiene would refuse inline secrets and
            # require secret_ref; revisit once WI-5.1 validates the backend.
            key_set = key_data
        else:
            key_set = {
                "keys": [
                    {
                        "key_id": "cairn-resolved",
                        "scheme": "hmac-sha256",
                        "secret_ref": cfg.key_ref,
                    }
                ]
            }
    except (json.JSONDecodeError, UnicodeDecodeError):
        key_set = {
            "keys": [
                {
                    "key_id": "cairn-resolved",
                    "scheme": "hmac-sha256",
                    "secret_ref": cfg.key_ref,
                }
            ]
        }

    fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="cairn-key-")
    os.chmod(tmp_path, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(key_set, f)
    atexit.register(_cleanup_temp_key, tmp_path)
    return tmp_path


def _cleanup_temp_key(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# File extraction (mirrors cairn._claude_hook._extract_files)
# ---------------------------------------------------------------------------


def _extract_files(args: dict[str, Any]) -> list[str]:
    """Extract file paths from tool args.

    Checks common keys used by Hermes tools (read_file, write_file, patch,
    terminal workdir, etc.).
    """
    files: list[str] = []
    for key in ("filePath", "file_path", "path", "file"):
        val = args.get(key)
        if isinstance(val, str):
            files.append(val)
    for key in ("files", "paths"):
        val = args.get(key)
        if isinstance(val, list):
            files.extend(v for v in val if isinstance(v, str))
        elif isinstance(val, str):
            files.append(val)
    return files


# ---------------------------------------------------------------------------
# Session ID normalization (regista requires valid UUID)
# ---------------------------------------------------------------------------


def _normalize_session_id(session_id: str) -> str:
    """Ensure session_id is a valid UUID string.

    Hermes session IDs may not be UUIDs.  If not, derive a deterministic
    UUID v5 from the string so audit grouping is stable.
    """
    try:
        uuid.UUID(session_id)
        return session_id
    except (ValueError, TypeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, session_id))


def _resolve_session_id(**kwargs: Any) -> str | None:
    """Resolve the real session id for an event.

    Mirrors the opencode plugin, which threads ``session_id`` on every
    ``tool.execute.before``/``after`` call: prefer the ``session_id`` kwarg
    the harness hands us for *this* event, then fall back to the id captured
    on ``on_session_start``. Returns ``None`` only when neither is available
    (no session-start fired and the harness omitted the kwarg) — in which
    case the caller records with ``principal_id`` only rather than emitting
    a bogus placeholder.
    """
    raw = kwargs.get("session_id")
    if raw is None or not str(raw).strip():
        return _SESSION_ID
    return _normalize_session_id(str(raw))


def _build_delegation(cfg: Any, **kwargs: Any) -> dict[str, Any]:
    """Build the ``on_behalf_of`` chain for a tool-call event.

    Always carries ``principal_id``; carries ``session_id`` when a real one
    can be resolved. A placeholder (``"pending"`` etc.) is never used, so no
    bogus session id escapes into a persisted event.
    """
    delegation: dict[str, Any] = {
        "principal_id": cfg.principal_id or "human:unknown",
    }
    session_id = _resolve_session_id(**kwargs)
    if session_id is not None:
        delegation["session_id"] = session_id
    return delegation


def _safe(fn: Any) -> None:
    """Execute ``fn()`` and swallow any exception (fail-open)."""
    try:
        fn()
    except Exception as exc:
        logger.debug("cairn plugin hook failed: %s", exc, exc_info=True)


def _mark_model_degraded(session_id: str, detail: str) -> None:
    try:
        from cairn._claude_hook import _mark_degraded

        _mark_degraded(session_id, "hermes:model_observation", detail)
    except Exception:
        logger.debug("cairn plugin: could not persist model observation degradation")


# ---------------------------------------------------------------------------
# Hook callbacks
# ---------------------------------------------------------------------------


def register(ctx: Any) -> None:
    """Register hook callbacks with the Hermes plugin context."""
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("on_session_end", on_session_end)


def on_pre_tool_call(**kwargs: Any) -> None:
    """Record the start of a tool call via CairnAdapter.begin_tool_call."""
    adapter, _regista, cfg = _get_adapter()
    if adapter is None:
        return

    tool_name = str(kwargs.get("tool_name") or "unknown")
    args = kwargs.get("args") or {}
    if not isinstance(args, dict):
        args = {}
    tool_call_id = str(kwargs.get("tool_call_id") or "")

    def _record() -> None:
        files = _extract_files(args)

        # Thread the real session_id (from this event's kwargs, else the id
        # captured on session start) into the delegation chain — never the
        # adapter default, which carries principal_id only.
        delegation = _build_delegation(cfg, **kwargs)

        wi = adapter.begin_tool_call(
            tool=tool_name,
            tool_args=args,
            files=files,
            on_behalf_of=delegation,
        )
        work_item_id = wi.work_item_id

        if tool_call_id:
            lock = _ensure_lock()
            with lock:
                _WORK_ITEMS[tool_call_id] = work_item_id

    _safe(_record)


def on_post_tool_call(**kwargs: Any) -> None:
    """Record the completion of a tool call via CairnAdapter.end_tool_call."""
    adapter, _regista, cfg = _get_adapter()
    if adapter is None:
        return

    tool_call_id = str(kwargs.get("tool_call_id") or "")
    result = kwargs.get("result")
    status = str(kwargs.get("status") or "ok")

    def _record() -> None:
        work_item_id: uuid.UUID | None = None
        if tool_call_id:
            lock = _ensure_lock()
            with lock:
                work_item_id = _WORK_ITEMS.pop(tool_call_id, None)

        if work_item_id is None:
            logger.debug(
                "cairn plugin: post_tool_call has no matching pre (tool_call_id=%s)",
                tool_call_id,
            )
            return

        # Build result summary.
        stdout_text = ""
        if isinstance(result, str):
            stdout_text = result[:2000]
        elif isinstance(result, dict):
            import json
            stdout_text = json.dumps(result)[:2000]
        elif result is not None:
            stdout_text = str(result)[:2000]

        exit_code = 0 if status == "ok" else 1

        # Thread the real session_id into the end event's delegation chain,
        # matching the begin event (opencode parity).
        delegation = _build_delegation(cfg, **kwargs)

        adapter.end_tool_call(
            work_item_id,
            result_summary={
                "exit_code": exit_code,
                "stdout": stdout_text,
            },
            error=str(kwargs.get("error_message")) if status != "ok" else None,
            on_behalf_of=delegation,
        )

    _safe(_record)


def on_session_start(**kwargs: Any) -> None:
    """Record a session-level attestation via CairnAdapter.attest_session."""
    adapter, _regista, cfg = _get_adapter()
    if adapter is None or cfg is None:
        return

    session_id_raw = str(kwargs.get("session_id") or "default")

    def _record() -> None:
        session_id = _normalize_session_id(session_id_raw)

        # Capture the real session id so subsequent tool-call events that
        # don't carry their own session_id kwarg still attribute correctly
        # (mirrors opencode, which threads session_id on every event).
        global _SESSION_ID
        lock = _ensure_lock()
        with lock:
            _SESSION_ID = session_id

        harness_name = cfg.harness_name or "hermes"
        harness_version = cfg.harness_version or "unknown"

        adapter.attest_session(
            principal_id=cfg.principal_id or "human:unknown",
            session_id=session_id,
            harnesses=[
                {"name": harness_name, "version": harness_version},
            ],
            scope_statement=f"In scope: {harness_name}.",
        )
        single_model_service = _env_truthy("CAIRN_SINGLE_MODEL_SERVICE")
        observed_model = None
        observed_provider = None
        if single_model_service:
            observed_model = os.environ.get("CAIRN_HERMES_MODEL") or os.environ.get(
                "HERMES_MODEL"
            )
            observed_provider = os.environ.get("CAIRN_HERMES_PROVIDER") or os.environ.get(
                "HERMES_PROVIDER"
            )
        try:
            event = adapter.record_model_observation(
                session_id,
                source="hermes.single_model_service_environment",
                observation_basis=(
                    "single_model_service_declaration"
                    if observed_model
                    else "unavailable"
                ),
                observed_provider_id=observed_provider,
                observed_model_id=observed_model,
                declared_model_lineage=os.environ.get("CAIRN_MODEL_LINEAGE"),
                on_behalf_of=_build_delegation(cfg, session_id=session_id),
            )
            if event is not None and (event.payload or {}).get("status") == "unavailable":
                _mark_model_degraded(session_id, "service model environment unavailable")
        except Exception as exc:
            _mark_model_degraded(session_id, f"capture failed: {type(exc).__name__}")

    _safe(_record)


def on_session_end(**kwargs: Any) -> None:
    """Clean up session state for this session."""
    # Clear any orphaned work items for this session.
    session_id = str(kwargs.get("session_id") or "")

    def _cleanup() -> None:
        lock = _ensure_lock()
        with lock:
            # Work items are keyed by tool_call_id, not session_id.
            # We clear all entries since Hermes sessions are assumed sequential
            # (PROVISIONAL — WI-5.1 unverified). Concurrent sessions would need
            # session-scoped tracking instead of a global clear.
            if session_id:
                _WORK_ITEMS.clear()
                # Drop the captured session id — a new session must
                # re-capture. Only clear when we can identify the ending
                # session, so a spurious session_end without an id is a
                # true no-op rather than wiping in-flight attribution.
                global _SESSION_ID
                _SESSION_ID = None

    _safe(_cleanup)


def reset_for_tests() -> None:
    """Reset module state for testing."""
    global _ADAPTER, _REGISTA, _CFG, _WORK_ITEMS, _SESSION_ID
    lock = _ensure_lock()
    with lock:
        _ADAPTER = None
        _REGISTA = None
        _CFG = None
        _WORK_ITEMS = {}
        _SESSION_ID = None


# TODO(WI-5.2): delegation depth-2 is not wired here.
#
# Plan 010 WI-5.2 requires a depth-2 delegation chain for
# Hermes → sub-agent (Claude Code / Codex) → tool call, so a sub-agent's
# tool calls attribute to both the Hermes session and the human principal
# rather than flattening to "Hermes did it" or orphaning as "Claude did it
# unsanctioned."
#
# The chain is not wired because the (PROVISIONAL, WI-5.1-still-open) Hermes
# hook surface assumed above does not expose sub-agent delegation context:
# ``on_pre_tool_call`` / ``on_post_tool_call`` receive only the Hermes
# session's own ``session_id`` — there is no ``parent_session_id``,
# ``subagent_id``, ``delegate_of``, or child-session field in the kwargs
# contract. With no sub-agent context to read, depth-2 cannot be populated
# without inventing data.
#
# Once WI-5.1 confirms the real Hermes delegation hooks (e.g. a
# ``subagent_start``/``subagent_end`` pair carrying the child session id, or
# a ``parent_session_id`` field on tool-call events), extend
# ``_build_delegation`` to emit a multi-level ``on_behalf_of``:
#   {"principal_id": <human>, "session_id": <hermes>,
#    "on_behalf_of": {"session_id": <child>, "harness": "claude-code"}}
# and thread the child context through ``begin_tool_call`` / ``end_tool_call``.
# The adapter and regista already support arbitrary delegation depth (BC-197);
# only the harness context is missing.
