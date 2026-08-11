#!/usr/bin/env python3
"""Lightweight bridge for OpenCode skill integration.

Receives tool calls from the OpenCode TypeScript plugin via stdin
(JSON serialized), computes file digests, and writes regista events.

Usage::

    echo '{"action":"begin", "tool":"Edit", ...}' \
        | python3 -m cairn
    echo '{"action":"end", "work_item_id":"...", ...}' \
        | python3 -m cairn

Environment::

    CAIRN_DSN            Postgres DSN for regista
    CAIRN_PROJECT        Regista project name
    CAIRN_KEY_PATH       Path to HMAC key file
    CAIRN_HARNESS_NAME   Harness name (default: opencode)
    CAIRN_HARNESS_VERSION Harness version (default: detected)
    PRINCIPAL_ID         Human principal (default: detected from OS user)
    CAIRN_DISABLE        If set to a truthy value (1/true/yes/on), silently exits 0
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import sys
import tempfile
import uuid
from typing import Any, cast

# Silence regista/structlog logging before importing anything that uses it
logging.basicConfig(level=logging.CRITICAL)
import structlog  # noqa: E402

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

from regista import Regista  # noqa: E402

from cairn import CairnAdapter, CairnConfig  # noqa: E402
from cairn._config import _parse_bool, resolve_config  # noqa: E402
from cairn._content_crypto import CONTENT_ENCRYPTION_ERROR_FIELD  # noqa: E402
from cairn.schema import hash_payload  # noqa: E402

_MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MiB safety limit on stdin


def _resolve_key_path(cfg: Any) -> str:
    """Return a usable ``hmac_key_path`` from the config.

    When ``key_ref`` is set, create a temporary key-set JSON that uses
    ``secret_ref`` so regista's KeySet resolves the key material from the
    configured backend (env, vault, azure) — no plaintext key on disk.
    When ``key_path`` is set, return it directly.

    The temp file is created with 0o600 permissions from the start (no
    race window) and registered for cleanup at process exit.
    """
    if cfg.key_path:
        return cast(str, cfg.key_path)
    if not cfg.key_ref:
        raise RuntimeError("neither key_path nor key_ref configured")

    from regista._secrets import resolve as resolve_secret

    key_ref = cfg.key_ref
    try:
        raw = resolve_secret(key_ref)
    except Exception as exc:
        sys.stderr.write(f"cairn_bridge: failed to resolve key_ref: {exc}\n")
        sys.exit(1)

    key_set: dict[str, Any]
    try:
        key_data = json.loads(raw)
        if isinstance(key_data, dict) and "keys" in key_data:
            key_set = key_data
        else:
            key_set = {
                "keys": [
                    {
                        "key_id": "cairn-resolved",
                        "scheme": "hmac-sha256",
                        "secret_ref": key_ref,
                    }
                ]
            }
    except (json.JSONDecodeError, UnicodeDecodeError):
        key_set = {
            "keys": [
                {
                    "key_id": "cairn-resolved",
                    "scheme": "hmac-sha256",
                    "secret_ref": key_ref,
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


def main() -> None:
    if _parse_bool(os.environ.get("CAIRN_DISABLE")):
        return

    raw = sys.stdin.read(_MAX_INPUT_BYTES)
    if not raw:
        sys.stderr.write("cairn_bridge: no input\n")
        sys.exit(1)

    try:
        msg = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"cairn_bridge: bad JSON: {exc}\n")
        sys.exit(1)

    cfg = resolve_config()

    dsn = cfg.dsn
    project = cfg.project
    key_path = cfg.key_path
    key_ref = cfg.key_ref

    if not all([dsn, project, key_path or key_ref]):
        missing = ", ".join(
            m
            for m, v in [
                ("DSN", dsn),
                ("PROJECT", project),
                ("KEY_PATH or KEY_REF", key_path or key_ref),
            ]
            if not v
        )
        sys.stderr.write(
            f"cairn_bridge: missing required config: {missing}\n"
            "Set REGISTA_DSN/REGISTA_KEY_PATH (or legacy CAIRN_DSN/CAIRN_KEY_PATH) "
            "and CAIRN_PROJECT.\n"
        )
        sys.exit(1)

    harness_name = cfg.harness_name
    harness_version = cfg.harness_version
    principal_id = cfg.principal_id or "human:unknown"

    action = msg.get("action")
    files = [f for f in (msg.get("files") or []) if isinstance(f, str)]

    if action not in (
        "attest_scope",
        "attest_session",
        "begin",
        "end",
        "user_message",
        "assistant_message",
        "transcript_attestation",
        "subagent_start",
        "subagent_stop",
        "compaction",
        "model_observation",
    ):
        sys.stderr.write(f"cairn_bridge: unknown action {action!r}\n")
        sys.exit(1)

    session_id = msg.get("session_id")
    if not session_id:
        sys.stderr.write("cairn_bridge: session_id required for audit grouping\n")
        sys.exit(1)

    # regista requires session_id to be a valid UUID.  If the harness
    # provides a non-UUID string (e.g. opencode's "ses_..."), derive a
    # deterministic UUID v5 from it.
    try:
        uuid.UUID(session_id)
    except ValueError:
        session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, session_id))

    sub = Regista(dsn=dsn, project=project, hmac_key_path=_resolve_key_path(cfg))
    adapter = CairnAdapter(
        sub,
        config=CairnConfig(harness_name, harness_version),
        on_behalf_of={
            "principal_id": principal_id,
            "session_id": session_id,
        },
    )

    try:
        result = _dispatch(
            adapter,
            action,
            msg,
            principal_id,
            harness_name,
            harness_version,
            session_id,
            files,
        )
    finally:
        sub.close()

    print(json.dumps(result))


def _content_reply(event: Any) -> dict[str, Any]:
    """Reply for a content-capturing action, surfacing a withheld-content note.

    When content encryption was configured and unusable, the adapter records the
    event digest-only and writes the reason into the signed payload (WI-037).
    Passing it back lets the *hook* log a local, attributable degradation record
    too, so the operator does not have to read the store to find out.
    """
    reply: dict[str, Any] = {"status": "ok", "event_id": str(event.event_id)}
    payload = getattr(event, "payload", None)
    if isinstance(payload, dict):
        note = payload.get(CONTENT_ENCRYPTION_ERROR_FIELD)
        if isinstance(note, str) and note:
            reply[CONTENT_ENCRYPTION_ERROR_FIELD] = note
            sys.stderr.write(f"cairn_bridge: {note}\n")
    return reply


def _dispatch(
    adapter: CairnAdapter,
    action: str,
    msg: dict[str, Any],
    principal_id: str,
    harness_name: str,
    harness_version: str,
    session_id: str,
    files: list[str],
) -> dict[str, Any]:
    if action == "attest_scope":
        event = adapter.attest_scope(
            principal_id=principal_id,
            harnesses=msg.get(
                "harnesses",
                [{"name": harness_name, "version": harness_version}],
            ),
            scope_statement=msg.get("scope_statement", f"In scope: {harness_name}."),
            harness_config_digests=msg.get("harness_config_digests"),
        )
        return {"status": "ok", "event_id": str(event.event_id)}

    if action == "attest_session":
        event = adapter.attest_session(
            principal_id=principal_id,
            session_id=session_id,
            harnesses=msg.get(
                "harnesses",
                [{"name": harness_name, "version": harness_version}],
            ),
            scope_statement=msg.get("scope_statement", f"In scope: {harness_name}."),
            harness_config_digests=msg.get("harness_config_digests"),
        )
        return {"status": "ok", "event_id": str(event.event_id)}

    if action == "model_observation":
        observation_id = msg.get("observation_id")
        model_event_id = (
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"cairn:model-observation:{session_id}:{observation_id}",
            )
            if isinstance(observation_id, str) and observation_id
            else None
        )
        event = adapter.record_model_observation(
            session_id=session_id,
            source=msg.get("source", f"{harness_name}.unknown"),
            observation_basis=msg.get("observation_basis", "runtime_metadata"),
            observed_provider_id=msg.get("observed_provider_id"),
            observed_model_id=msg.get("observed_model_id"),
            requested_provider_id=msg.get("requested_provider_id"),
            requested_model_id=msg.get("requested_model_id"),
            declared_model_lineage=msg.get("declared_model_lineage"),
            event_id=model_event_id,
        )
        payload = event.payload if isinstance(event.payload, dict) else {}
        return {
            "status": "ok",
            "event_id": str(event.event_id),
            "observation_status": payload.get("status"),
            "observed_model_lineage": payload.get("observed_model_lineage"),
            "finding": payload.get("finding"),
        }

    subagent = msg.get("subagent")
    if not (isinstance(subagent, dict) and subagent.get("agent_id")):
        subagent = None

    if action == "begin":
        args = msg.get("args", {})
        args_hash = "sha256:" + hash_payload(args)
        wi = adapter.begin_tool_call(
            tool=msg.get("tool", "unknown"),
            tool_args=args,
            files=files,
            subagent=subagent,
        )
        return {
            "status": "ok",
            "work_item_id": str(wi.work_item_id),
            "args_hash": args_hash,
        }

    if action == "end":
        wi_id_str = msg.get("work_item_id")
        if not wi_id_str:
            sys.stderr.write("cairn_bridge: work_item_id required for end\n")
            sys.exit(1)
        wi_id = uuid.UUID(wi_id_str)
        event = adapter.end_tool_call(
            wi_id,
            result_summary=msg.get("result_summary"),
            files=files,
            error=msg.get("error"),
            subagent=subagent,
        )
        return {"status": "ok", "event_id": str(event.event_id)}

    if action == "user_message":
        message = msg.get("message", "")
        content_capture = msg.get("content_capture", True)
        event = adapter.record_user_message(
            session_id=session_id,
            message=message,
            sequence=msg.get("sequence"),
            content_capture=content_capture,
        )
        return _content_reply(event)

    if action == "assistant_message":
        message = msg.get("message", "")
        content_capture = msg.get("content_capture", True)
        event = adapter.record_assistant_message(
            session_id=session_id,
            message=message,
            sequence=msg.get("sequence"),
            content_capture=content_capture,
        )
        return _content_reply(event)

    if action == "transcript_attestation":
        transcript = msg.get("transcript", "")
        content_capture = msg.get("content_capture", True)
        event = adapter.attest_transcript(
            session_id=session_id,
            transcript=transcript,
            event_count=msg.get("event_count"),
            content_capture=content_capture,
        )
        return _content_reply(event)

    if action == "subagent_start":
        agent_id = msg.get("agent_id")
        if not agent_id:
            sys.stderr.write("cairn_bridge: agent_id required for subagent_start\n")
            sys.exit(1)
        event = adapter.record_subagent_start(
            session_id=session_id,
            agent_id=agent_id,
            agent_type=msg.get("agent_type"),
        )
        return {"status": "ok", "event_id": str(event.event_id)}

    if action == "subagent_stop":
        agent_id = msg.get("agent_id")
        if not agent_id:
            sys.stderr.write("cairn_bridge: agent_id required for subagent_stop\n")
            sys.exit(1)
        event = adapter.record_subagent_stop(
            session_id=session_id,
            agent_id=agent_id,
            agent_type=msg.get("agent_type"),
            last_assistant_message=msg.get("last_assistant_message"),
            agent_transcript_path=msg.get("agent_transcript_path"),
        )
        return {"status": "ok", "event_id": str(event.event_id)}

    if action == "compaction":
        event = adapter.record_compaction(
            session_id=session_id,
            trigger=msg.get("trigger", "unknown"),
            compact_summary=msg.get("compact_summary"),
            content_capture=msg.get("content_capture", False),
        )
        return _content_reply(event)

    raise ValueError(f"unreachable: action={action}")


if __name__ == "__main__":
    main()
