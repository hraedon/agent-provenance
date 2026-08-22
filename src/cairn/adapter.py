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
            "principal_id": "human:owner",
            "session_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        },
    )

    # Post-tool-use
    adapter.end_tool_call(
        wi.work_item_id,
        result_summary={"exit_code": 0},
        files=["/projects/foo/bar.py"],
    )

regista 0.7 (v6 epoch) notes:

* The project must be provisioned before the adapter can write: a v6 genesis,
  a ``principal_key_accepted`` for the signing principal, and a signed
  ``workflow_registered`` for ``cairn_agent_actions``.  Provisioning is an
  operator action (suite bootstrap); the adapter never opens an epoch or
  registers a workflow implicitly.
* The signing actor must be a canonical regista principal (``kind:subject``)
  whose key the project has accepted.  The adapter's default actor is the
  ``service:cairn`` principal; when ``on_behalf_of`` carries a principal, that
  principal signs (its key must be accepted by the project).
* ``on_behalf_of`` has no v6 envelope field: regista refuses it at the writer
  (``INVALID_ARGUMENT``).  The delegation context is recorded inside the signed
  *payload* (cairn's own schema carries it), which is where these tests and the
  verifier read it.
* Session-scoped events are written as ``entity_kind="note"`` — the v6 closed
  registry's non-work-item, UUID-addressed, independently readable entity
  (regista 0.7.0 AMENDMENTS §1).  Pre-v6 artifacts with ``entity_kind="session"``
  remain verifiable by the read-only verifier.
* The signed producer identity is process-level (``REGISTA_PRODUCER_*``); the
  adapter seeds the harness half from its :class:`CairnConfig` when the process
  has not declared one.  Model lineage lives only in the producer, never in
  ``actor_metadata`` (regista refuses producer fields there).
"""

from __future__ import annotations

import datetime
import os
import uuid
from typing import Any

import structlog
from regista import Regista

from ._content_crypto import (
    ContentEncryptionUnavailableError,
    encrypt_content_fields,
    recorded_content_encryption_stance,
    withhold_content_fields,
)
from .schema import (
    AssistantMessagePayload,
    CairnConfig,
    CompactionPayload,
    FileDigest,
    ResultSummary,
    ScopeAttestationPayload,
    SessionAttestationPayload,
    SubagentIdentity,
    SubagentStartPayload,
    SubagentStopPayload,
    ToolCallBegin,
    ToolCallEnd,
    TranscriptAttestationPayload,
    UserMessagePayload,
    build_redacted_args,
    digest_file,
    digest_string,
    hash_payload,
)

log = structlog.get_logger()

# The v6 entity kind for session-scoped events. regista 0.7's closed registry
# has no "session" kind; ``note`` is the non-work-item, UUID-addressed,
# independently readable entity (AMENDMENTS §1), which is exactly the role the
# session log plays. Historical rows written as "session" by pre-v6 cairn stay
# verifiable by the read-only verifier.
SESSION_ENTITY_KIND = "note"

# Environment variables the v6 writer resolves the process producer from
# (``regista.resolve_producer``'s documented contract names). Seeding them here
# is cairn's only channel: the public write API resolves the producer from the
# process environment and accepts no per-call producer argument, by design —
# the producer is a property of the running process, not of a business call.
_PRODUCER_ENV_HARNESS = "REGISTA_PRODUCER_HARNESS"
_PRODUCER_ENV_HARNESS_VERSION = "REGISTA_PRODUCER_HARNESS_VERSION"


def _ensure_producer_env(config: CairnConfig) -> None:
    """Seed the harness half of the v6 producer identity from the adapter config.

    An unset producer is a refusal at every write (``LOAD_BEARING_FIELD_MISSING``)
    — regista deliberately provides no default, because an invented harness name
    would be a signed falsehood. The falsehood to avoid here is the mirror
    image: silently *overwriting* a producer the operator already declared for
    this process. So: fill the harness fields only when they are unset, and
    never touch ``REGISTA_PRODUCER_MODEL`` / ``REGISTA_PRODUCER_MODEL_LINEAGE``
    (cairn does not know the model; setting exactly one of the pair is itself a
    refusal, and that is the operator's signal to fix their environment).
    """
    if not os.environ.get(_PRODUCER_ENV_HARNESS):
        os.environ[_PRODUCER_ENV_HARNESS] = config.harness_name
    if not os.environ.get(_PRODUCER_ENV_HARNESS_VERSION):
        os.environ[_PRODUCER_ENV_HARNESS_VERSION] = config.harness_version


class CairnAdapter:
    """Bridge between agent harnesses and the regista event log."""

    # Default workflow used when the adapter creates its own work items.
    # Harness integrations may override these.
    DEFAULT_WORKFLOW = "cairn_agent_actions"
    DEFAULT_WORK_ITEM_TYPE = "tool_call"
    DEFAULT_ACTOR_KIND = "agent"
    # Canonical v6 principal for the cairn service itself (``kind:subject`` —
    # bare names are refused by the v6 envelope grammar). Used only when no
    # ``on_behalf_of`` principal and no explicit actor are supplied.
    DEFAULT_ACTOR_ID = "service:cairn"

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
            on_behalf_of: Default delegation chain recorded in every payload.
        """
        self._sub = regista
        self._config = config
        self._workflow = workflow_name
        self._work_item_type = work_item_type
        self._actor_id = actor_id or (
            on_behalf_of["principal_id"] if on_behalf_of else self.DEFAULT_ACTOR_ID
        )
        self._actor_kind = actor_kind
        self._on_behalf_of = on_behalf_of
        _ensure_producer_env(config)

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
        content_capture: bool = False,
        content_encryption: str | None = None,
        redaction_policy: str | None = None,
    ) -> Any:
        """Record a signed scope-attestation event.

        The scope attestation declares which harnesses are configured and
        therefore in scope for audit.  Every attestation is an immutable,
        signed regista event that an auditor can verify.

        Args:
            principal_id: Human principal on whose behalf this deployment
                is configured (e.g. ``human:owner``).
            harnesses: List of harness dicts, each with ``name``,
                ``version``, and optional ``config_digest``.
            scope_statement: Human-readable scope statement matching
                README §2.
            harness_config_digests: Map ``harness_name → sha256`` of the
                harness configuration at attestation time.
            attested_at: ISO-8601 timestamp (defaults to now).
            actor_id: Actor for this event (defaults to adapter default).
            event_id: Explicit UUID for idempotency.
            content_capture: Whether this session captures content (v2).
            content_encryption: ``"on"`` | ``"off"`` | ``"external"``.
                Defaults to resolving from the environment.
            redaction_policy: Name/digest of the active redaction policy.

        Returns:
            The :class:`~regista.Event` that records the attestation.
        """
        actor = actor_id or self._actor_id
        ts = attested_at or datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
        if content_encryption is None:
            # The VERIFIED stance, not the configured one: an attestation that
            # says "on" while the key does not resolve is the defect WI-037
            # closed.  This resolves the content key once per session, which is
            # where the claim is made — not on every captured event.
            content_encryption = recorded_content_encryption_stance()
        payload = ScopeAttestationPayload(
            version="2" if content_capture else "1",
            principal_id=principal_id,
            attested_at=ts,
            harnesses=harnesses,
            scope_statement=scope_statement,
            harness_config_digests=harness_config_digests,
            content_capture=content_capture,
            content_encryption=content_encryption,
            redaction_policy=redaction_policy,
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
        )

        event = self._sub.transition(
            work_item_id=wi.work_item_id,
            transition_name="tool_call_end",
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "attestation"},
            payload=payload,
        )

        log.info(
            "cairn.scope_attestation",
            work_item_id=str(wi.work_item_id),
            principal_id=principal_id,
            actor=actor,
        )
        return event

    def attest_session(
        self,
        principal_id: str,
        session_id: str,
        harnesses: list[dict[str, Any]],
        scope_statement: str,
        harness_config_digests: dict[str, str] | None = None,
        *,
        attested_at: str | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
        content_capture: bool = False,
        content_encryption: str | None = None,
        redaction_policy: str | None = None,
    ) -> Any:
        """Record a session-level attestation as a non-work-item entity.

        Uses the v6 ``note`` entity kind (the closed registry's UUID-addressed
        non-work-item entity) so the attestation is structurally distinct from
        tool-call events (BC-005). No work item is created.

        Args:
            principal_id: Human principal on whose behalf this session runs.
            session_id: Session identifier (UUID string).
            harnesses: List of harness dicts with name and version.
            scope_statement: Human-readable scope statement.
            harness_config_digests: Map harness_name → sha256 of config.
            attested_at: ISO-8601 timestamp (defaults to now).
            actor_id: Actor for this event (defaults to adapter default).
            event_id: Explicit UUID for idempotency.
            content_capture: Whether this session captures content (v2).
            content_encryption: ``"on"`` | ``"off"`` | ``"external"``.
                Defaults to resolving from the environment.
            redaction_policy: Name/digest of the active redaction policy.

        Returns:
            The appended Event recording the attestation.
        """
        actor = actor_id or self._actor_id
        ts = attested_at or datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
        if content_encryption is None:
            # The VERIFIED stance, not the configured one: an attestation that
            # says "on" while the key does not resolve is the defect WI-037
            # closed.  This resolves the content key once per session, which is
            # where the claim is made — not on every captured event.
            content_encryption = recorded_content_encryption_stance()
        payload = SessionAttestationPayload(
            version="2" if content_capture else "1",
            principal_id=principal_id,
            session_id=session_id,
            attested_at=ts,
            harnesses=harnesses,
            scope_statement=scope_statement,
            harness_config_digests=harness_config_digests,
            content_capture=content_capture,
            content_encryption=content_encryption,
            redaction_policy=redaction_policy,
            on_behalf_of={
                "principal_id": principal_id,
                "session_id": session_id,
            },
        ).to_dict()

        try:
            entity_id = uuid.UUID(session_id) if isinstance(session_id, str) else session_id
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"session_id must be a valid UUID string, got {session_id!r}: {exc}"
            ) from exc

        event = self._sub.append_event(
            work_item_id=entity_id,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "session_attestation"},
            transition="session_attestation",
            payload=payload,
            entity_kind=SESSION_ENTITY_KIND,
            event_id=event_id,
        )

        log.info(
            "cairn.session_attestation",
            session_id=session_id,
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
        subagent: dict[str, Any] | None = None,
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
            subagent: ``{"agent_id", "agent_type"}`` when this call executed
                inside a subagent (Plan 009 WI-3.1) — attributes the call to
                the subagent, not the parent loop.

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
            subagent=SubagentIdentity.from_dict(subagent) if subagent else None,
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
        subagent: dict[str, Any] | None = None,
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
            subagent: ``{"agent_id", "agent_type"}`` when this call executed
                inside a subagent (Plan 009 WI-3.1).

        Returns:
            The appended :class:`~regista.Event`.
        """
        actor = actor_id or self._actor_id
        delegation = on_behalf_of or self._on_behalf_of

        file_digests = self._digest_files(files, post=True)
        rs = self._build_result_summary(result_summary, error=error)

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
            subagent=SubagentIdentity.from_dict(subagent) if subagent else None,
        ).to_dict()

        transition_name = "tool_call_fail" if error else "tool_call_end"
        event = self._sub.transition(
            work_item_id=work_item_id,
            transition_name=transition_name,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "end"},
            payload=payload,
        )

        log.info(
            "cairn.tool_call_end",
            work_item_id=str(work_item_id),
            actor=actor,
            error=error,
        )
        return event

    # ----------------------------------------------------------------------
    # Content capture (Plan 010 WI-2.1)
    # ----------------------------------------------------------------------

    def _encrypt_or_withhold(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Encrypt content fields, or withhold them and say so (WI-037).

        Silently storing plaintext when a content key was configured is the one
        branch that must never happen: the operator has been told encryption is
        on, so plaintext is worse than no content at all.  When encryption is
        unavailable the content is dropped, the digests are kept (integrity and
        the chain are unaffected), and the reason is recorded IN the signed
        payload — so the store itself carries the explanation, and the verifier's
        content-coverage check reports a gap with a cause rather than a mystery.
        """
        try:
            return encrypt_content_fields(payload)
        except ContentEncryptionUnavailableError as exc:
            log.warning(
                "cairn.content_encryption_unavailable",
                key_ref=exc.key_ref,
                reason=exc.reason,
                action="content withheld; event recorded digest-only",
            )
            return withhold_content_fields(payload, str(exc))

    def record_user_message(
        self,
        session_id: str,
        message: str,
        *,
        sequence: int | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
        content_capture: bool = True,
    ) -> Any:
        """Record a user message (the human's prompt) as a signed event.

        The message digest is always computed (integrity).  When
        ``content_capture`` is true, the message content is also stored,
        encrypted at rest when content encryption is on (WI-3.2).
        """
        actor = actor_id or self._actor_id
        delegation = on_behalf_of or self._on_behalf_of
        message_digest = digest_string(message) or ""

        content: str | None = message if content_capture else None
        payload = UserMessagePayload(
            message_digest=message_digest,
            message_content=content,
            sequence=sequence,
            on_behalf_of=delegation,
            harness=self._config,
        ).to_dict()

        if content_capture:
            payload = self._encrypt_or_withhold(payload)

        entity_id = uuid.UUID(session_id) if isinstance(session_id, str) else session_id
        event = self._sub.append_event(
            work_item_id=entity_id,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "user_message"},
            transition="user_message",
            payload=payload,
            entity_kind=SESSION_ENTITY_KIND,
            event_id=event_id,
        )
        log.info("cairn.user_message", session_id=session_id, actor=actor)
        return event

    def record_assistant_message(
        self,
        session_id: str,
        message: str,
        *,
        sequence: int | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
        content_capture: bool = True,
    ) -> Any:
        """Record an assistant message (the model's response) as a signed event.

        The message digest is always computed (integrity).  When
        ``content_capture`` is true, the message content is also stored,
        encrypted at rest when content encryption is on (WI-3.2).
        """
        actor = actor_id or self._actor_id
        delegation = on_behalf_of or self._on_behalf_of
        message_digest = digest_string(message) or ""

        content: str | None = message if content_capture else None
        payload = AssistantMessagePayload(
            message_digest=message_digest,
            message_content=content,
            sequence=sequence,
            on_behalf_of=delegation,
            harness=self._config,
        ).to_dict()

        if content_capture:
            payload = self._encrypt_or_withhold(payload)

        entity_id = uuid.UUID(session_id) if isinstance(session_id, str) else session_id
        event = self._sub.append_event(
            work_item_id=entity_id,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "assistant_message"},
            transition="assistant_message",
            payload=payload,
            entity_kind=SESSION_ENTITY_KIND,
            event_id=event_id,
        )
        log.info("cairn.assistant_message", session_id=session_id, actor=actor)
        return event

    def attest_transcript(
        self,
        session_id: str,
        transcript: str,
        *,
        event_count: int | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
        content_capture: bool = True,
    ) -> Any:
        """Record a transcript attestation (whole-session or segment).

        Upgraded from digest-only (Plan 009 WI-3.2) to content-optional.
        The transcript digest is always present (integrity).  When
        ``content_capture`` is true, the transcript content is also
        stored, encrypted at rest when content encryption is on (WI-3.2).
        """
        actor = actor_id or self._actor_id
        delegation = on_behalf_of or self._on_behalf_of
        transcript_digest = digest_string(transcript) or ""

        content: str | None = transcript if content_capture else None
        payload = TranscriptAttestationPayload(
            transcript_digest=transcript_digest,
            transcript_content=content,
            event_count=event_count,
            session_id=session_id,
            on_behalf_of=delegation,
            harness=self._config,
        ).to_dict()

        if content_capture:
            payload = self._encrypt_or_withhold(payload)

        entity_id = uuid.UUID(session_id) if isinstance(session_id, str) else session_id
        event = self._sub.append_event(
            work_item_id=entity_id,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "transcript_attestation"},
            transition="transcript_attestation",
            payload=payload,
            entity_kind=SESSION_ENTITY_KIND,
            event_id=event_id,
        )
        log.info("cairn.transcript_attestation", session_id=session_id, actor=actor)
        return event

    # ----------------------------------------------------------------------
    # Subagent lifecycle + compaction (Plan 009 WI-3.1)
    # ----------------------------------------------------------------------

    def record_subagent_start(
        self,
        session_id: str,
        agent_id: str,
        *,
        agent_type: str | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
    ) -> Any:
        """Record that a subagent began executing within a session.

        Appended to the session entity so the chain shows when the
        delegation window opened.  Tool calls inside the window carry the
        same ``agent_id`` on their own events (per-call attribution).
        """
        actor = actor_id or self._actor_id
        delegation = on_behalf_of or self._on_behalf_of

        payload = SubagentStartPayload(
            agent_id=agent_id,
            agent_type=agent_type,
            on_behalf_of=delegation,
            harness=self._config,
        ).to_dict()

        entity_id = uuid.UUID(session_id) if isinstance(session_id, str) else session_id
        event = self._sub.append_event(
            work_item_id=entity_id,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "subagent_start"},
            transition="subagent_start",
            payload=payload,
            entity_kind=SESSION_ENTITY_KIND,
            event_id=event_id,
        )
        log.info("cairn.subagent_start", session_id=session_id, agent_id=agent_id, actor=actor)
        return event

    def record_subagent_stop(
        self,
        session_id: str,
        agent_id: str,
        *,
        agent_type: str | None = None,
        last_assistant_message: str | None = None,
        agent_transcript_path: str | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
    ) -> Any:
        """Record that a subagent finished executing.

        Digests the subagent's final reply and (when the harness exposed a
        readable path) its transcript file at stop time.  Digest-only —
        subagent content capture flows through the same message events as
        the parent.
        """
        actor = actor_id or self._actor_id
        delegation = on_behalf_of or self._on_behalf_of

        transcript_digest = digest_file(agent_transcript_path) if agent_transcript_path else None
        payload = SubagentStopPayload(
            agent_id=agent_id,
            agent_type=agent_type,
            last_assistant_message_digest=digest_string(last_assistant_message),
            agent_transcript_path=agent_transcript_path,
            agent_transcript_digest=transcript_digest,
            on_behalf_of=delegation,
            harness=self._config,
        ).to_dict()

        entity_id = uuid.UUID(session_id) if isinstance(session_id, str) else session_id
        event = self._sub.append_event(
            work_item_id=entity_id,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "subagent_stop"},
            transition="subagent_stop",
            payload=payload,
            entity_kind=SESSION_ENTITY_KIND,
            event_id=event_id,
        )
        log.info("cairn.subagent_stop", session_id=session_id, agent_id=agent_id, actor=actor)
        return event

    def record_compaction(
        self,
        session_id: str,
        trigger: str,
        *,
        compact_summary: str | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        actor_id: str | None = None,
        event_id: uuid.UUID | None = None,
        content_capture: bool = False,
    ) -> Any:
        """Record that the harness compacted the session context.

        Context loss is provenance-relevant: events after this point were
        produced by a model that no longer saw the full history.  The
        summary that replaced the dropped context is digested; under
        content capture it is also stored (encrypted at rest when content
        encryption is on).
        """
        actor = actor_id or self._actor_id
        delegation = on_behalf_of or self._on_behalf_of

        content: str | None = compact_summary if content_capture else None
        payload = CompactionPayload(
            trigger=trigger,
            compact_summary_digest=digest_string(compact_summary),
            compact_summary_content=content,
            on_behalf_of=delegation,
            harness=self._config,
        ).to_dict()

        if content_capture:
            payload = self._encrypt_or_withhold(payload)

        entity_id = uuid.UUID(session_id) if isinstance(session_id, str) else session_id
        event = self._sub.append_event(
            work_item_id=entity_id,
            actor_id=actor,
            actor_kind=self._actor_kind,
            actor_metadata={"role": "agent", "phase": "compaction"},
            transition="compaction",
            payload=payload,
            entity_kind=SESSION_ENTITY_KIND,
            event_id=event_id,
        )
        log.info("cairn.compaction", session_id=session_id, trigger=trigger, actor=actor)
        return event

    # ----------------------------------------------------------------------
    # Delegation depth (Plan 010 WI-2.3)
    # ----------------------------------------------------------------------

    @staticmethod
    def build_delegation_chain(
        principal_id: str,
        *session_chain: str,
        authenticated_at: str | None = None,
        scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Build a multi-level delegation chain (WI-2.3).

        For a Hermes→Claude Code→Edit session, the chain is::

            principal_id (human) → session_id (Hermes) → session_id (Claude Code)

        The full chain is threaded as ``on_behalf_of`` on every event,
        so a sub-agent's tool calls attribute correctly to both the
        parent session and the human principal.  A flat "Hermes did it"
        or orphaned "Claude did it" is impossible.

        Args:
            principal_id: The human principal.
            *session_chain: Session IDs from outermost to innermost
                (e.g. ``hermes_session, claude_session``).
            authenticated_at: When the principal was authenticated.
            scope: The scope of the delegation.

        Returns:
            A delegation chain dict suitable for ``on_behalf_of``.
        """
        chain: dict[str, Any] = {
            "principal_id": principal_id,
        }
        if session_chain:
            chain["session_id"] = session_chain[-1]
            chain["delegation_chain"] = list(session_chain)
        if authenticated_at:
            chain["authenticated_at"] = authenticated_at
        if scope:
            chain["scope"] = scope
        return chain

    # ----------------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------------

    @staticmethod
    def _build_result_summary(
        result_summary: dict[str, Any] | None, *, error: str | None
    ) -> ResultSummary:
        """Build a :class:`ResultSummary` from the bridge payload.

        Digest semantics (Plan 009 WI-1.2): when the capture boundary (the
        Claude Code hook) pre-computes ``stdout_digest`` over the *full*
        untruncated output, we use it verbatim — the auditor reproduces it
        against the complete real output.  When only the (possibly
        truncated) ``stdout`` text is present (legacy / OpenCode path), we
        fall back to computing the digest from that text, preserving
        backward compatibility while that path catches up to the new
        contract.
        """
        if not result_summary:
            return ResultSummary(error=error)

        stdout_digest = result_summary.get("stdout_digest")
        stdout_digest_alg = result_summary.get("stdout_digest_alg")
        stdout_bytes_total = result_summary.get("stdout_bytes_total")
        stdout_truncated = result_summary.get("stdout_truncated")

        if stdout_digest is None and result_summary.get("stdout") is not None:
            stdout_digest = digest_string(result_summary.get("stdout"))

        return ResultSummary(
            exit_code=result_summary.get("exit_code"),
            stdout_digest=stdout_digest,
            stdout_digest_alg=stdout_digest_alg,
            stdout_bytes_total=stdout_bytes_total,
            stdout_truncated=stdout_truncated,
            stderr_digest=digest_string(result_summary.get("stderr")),
            error=error,
        )

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
