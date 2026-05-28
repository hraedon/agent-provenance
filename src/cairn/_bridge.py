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
    CAIRN_DISABLE        If set to any value, silently exits 0
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from typing import Any

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
from cairn.schema import hash_payload  # noqa: E402

_MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MiB safety limit on stdin


def main() -> None:
    if os.environ.get("CAIRN_DISABLE"):
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

    dsn = os.environ.get("CAIRN_DSN")
    project = os.environ.get("CAIRN_PROJECT")
    key_path = os.environ.get("CAIRN_KEY_PATH")

    if not all([dsn, project, key_path]):
        sys.stderr.write("cairn_bridge: CAIRN_DSN, CAIRN_PROJECT, CAIRN_KEY_PATH required\n")
        sys.exit(1)

    harness_name = os.environ.get("CAIRN_HARNESS_NAME", "opencode")
    harness_version = os.environ.get("CAIRN_HARNESS_VERSION", "unknown")
    try:
        _default_principal = f"human:{os.getlogin()}"
    except OSError:
        import getpass

        _default_principal = f"human:{getpass.getuser()}"
    principal_id = os.environ.get("PRINCIPAL_ID", _default_principal)

    action = msg.get("action")
    files = [f for f in (msg.get("files") or []) if isinstance(f, str)]

    if action not in ("attest_scope", "begin", "end"):
        sys.stderr.write(f"cairn_bridge: unknown action {action!r}\n")
        sys.exit(1)

    session_id = msg.get("session_id")
    if not session_id:
        sys.stderr.write("cairn_bridge: session_id required for audit grouping\n")
        sys.exit(1)

    sub = Regista(dsn=dsn, project=project, hmac_key_path=key_path)
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

    if action == "begin":
        args = msg.get("args", {})
        args_hash = "sha256:" + hash_payload(args)
        wi = adapter.begin_tool_call(
            tool=msg.get("tool", "unknown"),
            tool_args=args,
            files=files,
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
        )
        return {"status": "ok", "event_id": str(event.event_id)}

    raise ValueError(f"unreachable: action={action}")


if __name__ == "__main__":
    main()
