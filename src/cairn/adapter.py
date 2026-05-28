"""Harness adapter — normalizes agent tool calls into regista events.

The adapter sits between the agent harness (Claude Code, OpenCode, etc.)
and regista.  It owns the canonical schema defined in :mod:`cairn.schema`.

Usage::

    from regista import Regista
    from cairn import CairnAdapter, CairnConfig

    sub = Regista(dsn=..., project="cairn", hmac_key_path=...)
    adapter = CairnAdapter(sub, config=CairnConfig("opencode", "0.x.y"))

    # Pre-tool-use
    wi = adapter.begin_tool_call(
        tool="Edit",
        tool_args={"filePath": "/projects/foo/bar.py", "oldString": "x", "newString": "y"},
        files=["/projects/foo/bar.py"],
        on_behalf_of={
            "principal_id": "human:plm",
            "session_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        },
    )

    # Post-tool-use
    adapter.end_tool_call(
        wi.work_item_id,
        result_summary={"exit_code": 0},
        files=["/projects/foo/bar.py"],
    )
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any

import structlog
from regista import Regista

from .schema import (
    CairnConfig,
    FileDigest,
    ResultSummary,
    ScopeAttestationPayload,
    ToolCallBegin,
    ToolCallEnd,
    build_redacted_args,
    digest_file,
    digest_string,
    hash_payload,
)

log = structlog.get_logger()


class CairnAdapter:
    """Bridge between agent harnesses and the regista event log."""

    # Default workflow used when the adapter creates its own work items.
    # Harness integrations may override these.
    DEFAULT_WORKFLOW = "cairn_agent_actions"
    DEFAULT_WORK_ITEM_TYPE = "tool_call"
    DEFAULT_ACTOR_KIND = "agent"

    def __init__(
        self,
        regista: Regista,
        config: CairnConfig,
        *,
        workflow_name: str = DEFAULT_WORKFLOW,
        work_item_type: str = DEFAULT_WORK_ITEM_TYPE,
        actor_id: str | None = None,
        actor_kind: str = DEFAULT_ACTOR_KIND,
        on_behalf_of: dict[str, Any] | None = None,
    ) -> None:
        """
        Args:
            regista: Connected Regista instance.
            config: Harness metadata (name, version, config digest).
            workflow_name: Workflow to use for created work items.
            work_item_type: Work-item type to use for created work items.
            actor_id: Default actor identifier (falls back to principal_id).
            actor_kind: Default actor kind (``agent``, ``human``, ``system``).
            on_behalf_of: Default delegation chain applied to every event.
        """
        self._sub = regista
        self._config = config
        self._workflow = workflow_name
        self._work_item_type = work_item_type
        self._actor_id = actor_id or (on_behalf_of["principal_id"] if on_behalf_of else "cairn")
        self._actor_kind = actor_kind
        self._on_behalf_of = on_behalf_of

    # ------------------------------------------------------------------
    # Scope attestation (signed first-class event)
    # ------------------------------------------------------------------

    def attest_scope(
        self,
        principal_id: str,
        harnesses: list[dict[str, Any]],
        scope_statement: str,
        harness_config_digests: dict[str, str] | None = None,
        *,
        attested_at: str | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
    ) -> Any:
        """Record a signed scope-attestation event.

        The scope attestation declares which harnesses are configured and
        therefore in scope for audit.  Every attestation is an immutable,
        signed regista event that an auditor can verify.

        Args:
            principal_id: Human principal on whose behalf this deployment
                is configured (e.g. ``human:plm``).
            harnesses: List of harness dicts, each with ``name``,
                ``version``, and optional ``config_digest``.
            scope_statement: Human-readable scope statement matching
                README §2.
            harness_config_digests: Map ``harness_name → sha256`` of the
                harness configuration at attestation time.
            attested_at: ISO-8601 timestamp (defaults to now).
            actor_id: Actor for this event (defaults to adapter default).
            event_id: Explicit UUID for idempotency.

        Returns:
            The :class:`~regista.Event` that records the attestation.
        """
        actor = actor_id or self._actor_id
        ts = attested_at or datetime.datetime.now(datetime.UTC).isoformat().replace("+", "Z")
        payload = ScopeAttestationPayload(
            version="1",
            principal_id=principal_id,
            attested_at=ts,
            harnesses=harnesses,
            scope_statement=scope_statement,
            harness_config_digests=harness_config_digests,
        ).to_dict()

        wi, _creation_event = self._sub.create_work_item(
            workflow_name=self._workflow,
            work_item_type=self._work_item_type,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "attestation"},
            custom_fields={"tool": "scope_attestation", "status": "running"},
            event_id=event_id,
        )

        self._sub.transition(
            work_item_id=wi.work_item_id,
            transition_name="tool_call_begin",
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "attestation"},
            payload={"tool": "scope_attestation", "tool_args_hash": ""},
            on_behalf_of={"principal_id": principal_id},
        )

        event = self._sub.transition(
            work_item_id=wi.work_item_id,
            transition_name="tool_call_end",
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "attestation"},
            payload=payload,
            on_behalf_of={"principal_id": principal_id},
        )

        log.info(
            "cairn.scope_attestation",
            work_item_id=str(wi.work_item_id),
            principal_id=principal_id,
            actor=actor,
        )
        return event

    # ----------------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------------

    def begin_tool_call(
        self,
        tool: str,
        tool_args: dict[str, Any],
        *,
        files: list[str] | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        parent_action_event_id: str | None = None,
        work_item_id: uuid.UUID | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
    ) -> Any:
        """Record the start of a tool call.

        Args:
            tool: Tool name (``Edit``, ``Write``, ``Read``, ``Bash``, …).
            tool_args: Raw tool arguments (will be hashed, not stored).
            files: Files touched by this tool call.
            on_behalf_of: Delegation chain overriding the adapter default.
            parent_action_event_id: Previous ``event_id`` in a causal chain.
            work_item_id: Existing work item to append to, or ``None`` to create
                a fresh work item for this action.
            actor_id: Actor for this event (defaults to adapter default).
            event_id: Explicit UUID for idempotency.

        Returns:
            The :class:`~regista.WorkItem` that carries this tool call.
        """
        actor = actor_id or self._actor_id
        delegation = on_behalf_of or self._on_behalf_of

        file_digests = self._digest_files(files, post=False)
        tool_args_hash = hash_payload(tool_args)
        redacted = build_redacted_args(
            tool=tool,
            file_paths=[f.path for f in file_digests] if file_digests else None,
        )

        payload = ToolCallBegin(
            tool=tool,
            tool_args_hash=tool_args_hash,
            tool_args_redacted=redacted,
            files=file_digests or None,
            on_behalf_of=delegation,
            parent_action_event_id=parent_action_event_id,
            harness=self._config,
        ).to_dict()

        if work_item_id is None:
            custom_fields = {"tool": tool, "status": "running"}
            wi, _event = self._sub.create_work_item(
                workflow_name=self._workflow,
                work_item_type=self._work_item_type,
                actor_id=actor,
                actor_kind=self._actor_kind,
                actor_metadata={"role": "agent", "phase": "begin"},
                custom_fields=custom_fields,
                event_id=event_id,
            )
            work_item_id = wi.work_item_id

        # Transition to running (works from new -> running or running -> running)
        self._sub.transition(
            work_item_id=work_item_id,
            transition_name="tool_call_begin",
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "begin"},
            payload=payload,
            on_behalf_of=delegation,
        )

        if parent_action_event_id:
            # Regista links connect work items, not events.
            # In v1 we store the parent_event_id in the payload;
            # true causal links via regista typed links come in v2.
            pass

        log.info(
            "cairn.tool_call_begin",
            work_item_id=str(work_item_id),
            tool=tool,
            actor=actor,
        )
        return self._sub.get_work_item(work_item_id)

    def end_tool_call(
        self,
        work_item_id: uuid.UUID,
        *,
        result_summary: dict[str, Any] | None = None,
        files: list[str] | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        parent_action_event_id: str | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
        error: str | None = None,
    ) -> Any:
        """Record the completion (or failure) of a tool call.

        Args:
            work_item_id: The work item returned by :meth:`begin_tool_call`.
            result_summary: Result metadata (exit_code, stdout_digest, …).
            files: Files touched by this tool call (post-digests appended).
            on_behalf_of: Delegation chain overriding the adapter default.
            parent_action_event_id: Previous ``event_id`` in a causal chain.
            actor_id: Actor for this event (defaults to adapter default).
            event_id: Explicit UUID for idempotency.
            error: If set, the tool call is treated as failed.

        Returns:
            The appended :class:`~regista.Event`.
        """
        actor = actor_id or self._actor_id
        delegation = on_behalf_of or self._on_behalf_of

        file_digests = self._digest_files(files, post=True)
        rs = ResultSummary(
            exit_code=result_summary.get("exit_code") if result_summary else None,
            stdout_digest=digest_string(result_summary.get("stdout")) if result_summary else None,
            stderr_digest=digest_string(result_summary.get("stderr")) if result_summary else None,
            error=error,
        )

        # We need the original tool name / hash from the begin event
        begin_payload = self._resolve_begin_payload(work_item_id)

        payload = ToolCallEnd(
            tool=begin_payload["tool"],
            tool_args_hash=begin_payload["tool_args_hash"],
            files=file_digests or None,
            result_summary=rs,
            on_behalf_of=delegation,
            parent_action_event_id=parent_action_event_id,
            harness=self._config,
        ).to_dict()

        transition_name = "tool_call_fail" if error else "tool_call_end"
        event = self._sub.transition(
            work_item_id=work_item_id,
            transition_name=transition_name,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "end"},
            payload=payload,
            on_behalf_of=delegation,
        )

        log.info(
            "cairn.tool_call_end",
            work_item_id=str(work_item_id),
            actor=actor,
            error=error,
        )
        return event

    # ----------------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------------

    def _digest_files(self, paths: list[str] | None, *, post: bool) -> list[FileDigest] | None:
        """Compute pre or post digests for a list of file paths."""
        if not paths:
            return None
        out: list[FileDigest] = []
        for p in paths:
            if post:
                out.append(FileDigest(path=p, pre_digest=None, post_digest=digest_file(p)))
            else:
                out.append(FileDigest(path=p, pre_digest=digest_file(p), post_digest=None))
        return out

    def _resolve_begin_payload(self, work_item_id: uuid.UUID) -> dict[str, Any]:
        """Fetch the ``tool_call_begin`` payload for a work item.

        Reads all begin events and returns the last one (matching the most
        recent begin transition).  Falls back to work-item custom fields
        if no begin payload is found.
        """
        events = self._sub.read_events(
            work_item_id=work_item_id,
            transition="tool_call_begin",
        )
        # Walk events in order; keep the last one with a valid payload.
        best: dict[str, Any] | None = None
        for ev in events:
            payload = ev.payload or {}
            if "tool" in payload and "tool_args_hash" in payload:
                best = payload
        if best is not None:
            return best

        # Fallback: read the creation event's custom fields
        wi = self._sub.get_work_item(work_item_id)
        if wi is None:
            raise RuntimeError(f"Work item {work_item_id} not found")
        tool = wi.custom_fields.get("tool", "unknown")
        log.warning(
            "cairn.begin_payload_missing",
            work_item_id=str(work_item_id),
            fallback_tool=tool,
        )
        return {"tool": tool, "tool_args_hash": "sha256:undefined"}
