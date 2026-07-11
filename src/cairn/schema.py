"""Canonical event schema for Cairn.

Normalizes tool calls from different harnesses into a uniform regista payload.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from regista._jcs import canonicalize


@dataclass(frozen=True)
class FileDigest:
    path: str
    pre_digest: str | None
    post_digest: str | None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"path": self.path}
        if self.pre_digest is not None:
            d["pre_digest"] = self.pre_digest
        if self.post_digest is not None:
            d["post_digest"] = self.post_digest
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileDigest:
        return cls(
            path=data["path"],
            pre_digest=data.get("pre_digest"),
            post_digest=data.get("post_digest"),
        )


@dataclass(frozen=True)
class ResultSummary:
    exit_code: int | None = None
    stdout_digest: str | None = None
    stdout_digest_alg: str | None = None
    stdout_bytes_total: int | None = None
    stdout_truncated: bool | None = None
    stderr_digest: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.exit_code is not None:
            d["exit_code"] = self.exit_code
        if self.stdout_digest is not None:
            d["stdout_digest"] = self.stdout_digest
        if self.stdout_digest_alg is not None:
            d["stdout_digest_alg"] = self.stdout_digest_alg
        if self.stdout_bytes_total is not None:
            d["stdout_bytes_total"] = self.stdout_bytes_total
        if self.stdout_truncated is not None:
            d["stdout_truncated"] = self.stdout_truncated
        if self.stderr_digest is not None:
            d["stderr_digest"] = self.stderr_digest
        if self.error is not None:
            d["error"] = self.error
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResultSummary:
        return cls(
            exit_code=data.get("exit_code"),
            stdout_digest=data.get("stdout_digest"),
            stdout_digest_alg=data.get("stdout_digest_alg"),
            stdout_bytes_total=data.get("stdout_bytes_total"),
            stdout_truncated=data.get("stdout_truncated"),
            stderr_digest=data.get("stderr_digest"),
            error=data.get("error"),
        )


@dataclass(frozen=True)
class CairnConfig:
    harness_name: str
    harness_version: str
    config_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.harness_name,
            "version": self.harness_version,
        }
        if self.config_digest is not None:
            d["config_digest"] = self.config_digest
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CairnConfig:
        return cls(
            harness_name=data["name"],
            harness_version=data["version"],
            config_digest=data.get("config_digest"),
        )


@dataclass(frozen=True)
class SubagentIdentity:
    """The subagent a tool call executed inside (Plan 009 WI-3.1).

    Claude Code stamps every hook payload fired inside a subagent with
    ``agent_id``/``agent_type`` (verified from real 2.1.207 capture);
    payloads from the main loop carry neither.  Attribution is therefore
    per-call from the payload itself — correct even when multiple
    subagents run in parallel — and a subagent's tool calls can never
    masquerade as the parent's.
    """

    agent_id: str
    agent_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"agent_id": self.agent_id}
        if self.agent_type is not None:
            d["agent_type"] = self.agent_type
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubagentIdentity:
        return cls(agent_id=data["agent_id"], agent_type=data.get("agent_type"))


@dataclass(frozen=True)
class ToolCallBegin:
    tool: str
    tool_args_hash: str
    tool_args_redacted: dict[str, Any] | None = None
    files: list[FileDigest] | None = None
    on_behalf_of: dict[str, Any] | None = None
    parent_action_event_id: str | None = None
    harness: CairnConfig | None = None
    subagent: SubagentIdentity | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tool": self.tool,
            "tool_args_hash": self.tool_args_hash,
        }
        if self.tool_args_redacted is not None:
            d["tool_args_redacted"] = self.tool_args_redacted
        if self.files is not None:
            d["files"] = [f.to_dict() for f in self.files]
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        if self.parent_action_event_id is not None:
            d["parent_action_event_id"] = self.parent_action_event_id
        if self.harness is not None:
            d["harness"] = self.harness.to_dict()
        if self.subagent is not None:
            d["subagent"] = self.subagent.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolCallBegin:
        return cls(
            tool=data["tool"],
            tool_args_hash=data["tool_args_hash"],
            tool_args_redacted=data.get("tool_args_redacted"),
            files=[FileDigest.from_dict(f) for f in data["files"]] if "files" in data else None,
            on_behalf_of=data.get("on_behalf_of"),
            parent_action_event_id=data.get("parent_action_event_id"),
            harness=CairnConfig.from_dict(data["harness"]) if "harness" in data else None,
            subagent=SubagentIdentity.from_dict(data["subagent"]) if "subagent" in data else None,
        )


@dataclass(frozen=True)
class ToolCallEnd:
    tool: str
    tool_args_hash: str
    files: list[FileDigest] | None = None
    result_summary: ResultSummary | None = None
    on_behalf_of: dict[str, Any] | None = None
    parent_action_event_id: str | None = None
    harness: CairnConfig | None = None
    subagent: SubagentIdentity | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tool": self.tool,
            "tool_args_hash": self.tool_args_hash,
        }
        if self.files is not None:
            d["files"] = [f.to_dict() for f in self.files]
        if self.result_summary is not None:
            d["result_summary"] = self.result_summary.to_dict()
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        if self.parent_action_event_id is not None:
            d["parent_action_event_id"] = self.parent_action_event_id
        if self.harness is not None:
            d["harness"] = self.harness.to_dict()
        if self.subagent is not None:
            d["subagent"] = self.subagent.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolCallEnd:
        return cls(
            tool=data["tool"],
            tool_args_hash=data["tool_args_hash"],
            files=[FileDigest.from_dict(f) for f in data["files"]] if "files" in data else None,
            result_summary=ResultSummary.from_dict(data["result_summary"])
            if "result_summary" in data
            else None,
            on_behalf_of=data.get("on_behalf_of"),
            parent_action_event_id=data.get("parent_action_event_id"),
            harness=CairnConfig.from_dict(data["harness"]) if "harness" in data else None,
            subagent=SubagentIdentity.from_dict(data["subagent"]) if "subagent" in data else None,
        )


ToolCallEvent = ToolCallBegin | ToolCallEnd


def hash_payload(payload: dict[str, Any]) -> str:
    """SHA-256 over RFC 8785 canonical JSON."""
    return hashlib.sha256(canonicalize(payload)).hexdigest()


def build_redacted_args(
    *,
    tool: str,
    file_paths: list[str] | None = None,
    command: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Build a human-reviewable redacted form of tool arguments.

    Includes only structural metadata (file paths touched, command description),
    not full content or secrets.
    """
    d: dict[str, Any] = {"tool": tool}
    if file_paths is not None:
        d["file_paths"] = file_paths
    if command is not None:
        d["command_description"] = command
    if description is not None:
        d["description"] = description
    return d


def digest_file(path: str) -> str | None:
    """Return SHA-256 hex digest of file contents, or None if the file does not exist.

    Returns None (rather than a hash of empty bytes) so that auditors can
    distinguish "file was absent" from "file was empty" — a critical
    distinction for tamper-evident logs.

    Uses streaming hash to avoid loading entire file into memory.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


CONTENT_ENCRYPTION_ON = "on"
CONTENT_ENCRYPTION_OFF = "off"
CONTENT_ENCRYPTION_EXTERNAL = "external"

_CONTENT_ENCRYPTION_VALID = frozenset({
    CONTENT_ENCRYPTION_ON,
    CONTENT_ENCRYPTION_OFF,
    CONTENT_ENCRYPTION_EXTERNAL,
})


@dataclass(frozen=True)
class ScopeAttestationPayload:
    version: str
    principal_id: str
    attested_at: str
    harnesses: list[dict[str, Any]]
    scope_statement: str
    harness_config_digests: dict[str, str] | None = None
    content_capture: bool = False
    content_encryption: str = CONTENT_ENCRYPTION_OFF
    redaction_policy: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "version": self.version,
            "principal_id": self.principal_id,
            "attested_at": self.attested_at,
            "harnesses": self.harnesses,
            "scope_statement": self.scope_statement,
        }
        if self.harness_config_digests is not None:
            d["harness_config_digests"] = self.harness_config_digests
        d["content_capture"] = self.content_capture
        d["content_encryption"] = self.content_encryption
        if self.redaction_policy is not None:
            d["redaction_policy"] = self.redaction_policy
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScopeAttestationPayload:
        return cls(
            version=data["version"],
            principal_id=data["principal_id"],
            attested_at=data["attested_at"],
            harnesses=data["harnesses"],
            scope_statement=data["scope_statement"],
            harness_config_digests=data.get("harness_config_digests"),
            content_capture=data.get("content_capture", False),
            content_encryption=data.get("content_encryption", CONTENT_ENCRYPTION_OFF),
            redaction_policy=data.get("redaction_policy"),
        )


@dataclass(frozen=True)
class SessionAttestationPayload:
    version: str
    principal_id: str
    session_id: str
    attested_at: str
    harnesses: list[dict[str, Any]]
    scope_statement: str
    harness_config_digests: dict[str, str] | None = None
    content_capture: bool = False
    content_encryption: str = CONTENT_ENCRYPTION_OFF
    redaction_policy: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "version": self.version,
            "principal_id": self.principal_id,
            "session_id": self.session_id,
            "attested_at": self.attested_at,
            "harnesses": self.harnesses,
            "scope_statement": self.scope_statement,
        }
        if self.harness_config_digests is not None:
            d["harness_config_digests"] = self.harness_config_digests
        d["content_capture"] = self.content_capture
        d["content_encryption"] = self.content_encryption
        if self.redaction_policy is not None:
            d["redaction_policy"] = self.redaction_policy
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionAttestationPayload:
        return cls(
            version=data["version"],
            principal_id=data["principal_id"],
            session_id=data["session_id"],
            attested_at=data["attested_at"],
            harnesses=data["harnesses"],
            scope_statement=data["scope_statement"],
            harness_config_digests=data.get("harness_config_digests"),
            content_capture=data.get("content_capture", False),
            content_encryption=data.get("content_encryption", CONTENT_ENCRYPTION_OFF),
            redaction_policy=data.get("redaction_policy"),
        )


@dataclass(frozen=True)
class UserMessagePayload:
    """The human's prompt/message to the agent (Plan 010 WI-2.1).

    The ``message_digest`` is always present (integrity).  The
    ``message_content`` is present only when ``content_capture=true`` (v2);
    it is encrypted at rest when content encryption is on.
    """

    message_digest: str
    message_content: str | dict[str, Any] | None = None
    role: str = "user"
    sequence: int | None = None
    on_behalf_of: dict[str, Any] | None = None
    harness: CairnConfig | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "message_digest": self.message_digest,
            "role": self.role,
        }
        if self.message_content is not None:
            d["message_content"] = self.message_content
        if self.sequence is not None:
            d["sequence"] = self.sequence
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        if self.harness is not None:
            d["harness"] = self.harness.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserMessagePayload:
        return cls(
            message_digest=data["message_digest"],
            message_content=data.get("message_content"),
            role=data.get("role", "user"),
            sequence=data.get("sequence"),
            on_behalf_of=data.get("on_behalf_of"),
            harness=CairnConfig.from_dict(data["harness"]) if "harness" in data else None,
        )


@dataclass(frozen=True)
class AssistantMessagePayload:
    """The model's response/reasoning (Plan 010 WI-2.1).

    The ``message_digest`` is always present (integrity).  The
    ``message_content`` is present only when ``content_capture=true`` (v2);
    it is encrypted at rest when content encryption is on.
    """

    message_digest: str
    message_content: str | dict[str, Any] | None = None
    role: str = "assistant"
    sequence: int | None = None
    on_behalf_of: dict[str, Any] | None = None
    harness: CairnConfig | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "message_digest": self.message_digest,
            "role": self.role,
        }
        if self.message_content is not None:
            d["message_content"] = self.message_content
        if self.sequence is not None:
            d["sequence"] = self.sequence
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        if self.harness is not None:
            d["harness"] = self.harness.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssistantMessagePayload:
        return cls(
            message_digest=data["message_digest"],
            message_content=data.get("message_content"),
            role=data.get("role", "assistant"),
            sequence=data.get("sequence"),
            on_behalf_of=data.get("on_behalf_of"),
            harness=CairnConfig.from_dict(data["harness"]) if "harness" in data else None,
        )


@dataclass(frozen=True)
class TranscriptAttestationPayload:
    """A whole-session or segment digest + optional content (Plan 010 WI-2.1).

    Upgraded from digest-only (Plan 009 WI-3.2) to content-optional.
    The ``transcript_digest`` is always present (integrity).  The
    ``transcript_content`` is present only when ``content_capture=true`` (v2);
    it is encrypted at rest when content encryption is on.
    """

    transcript_digest: str
    transcript_content: str | dict[str, Any] | None = None
    event_count: int | None = None
    session_id: str | None = None
    on_behalf_of: dict[str, Any] | None = None
    harness: CairnConfig | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "transcript_digest": self.transcript_digest,
        }
        if self.transcript_content is not None:
            d["transcript_content"] = self.transcript_content
        if self.event_count is not None:
            d["event_count"] = self.event_count
        if self.session_id is not None:
            d["session_id"] = self.session_id
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        if self.harness is not None:
            d["harness"] = self.harness.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TranscriptAttestationPayload:
        return cls(
            transcript_digest=data["transcript_digest"],
            transcript_content=data.get("transcript_content"),
            event_count=data.get("event_count"),
            session_id=data.get("session_id"),
            on_behalf_of=data.get("on_behalf_of"),
            harness=CairnConfig.from_dict(data["harness"]) if "harness" in data else None,
        )


@dataclass(frozen=True)
class SubagentStartPayload:
    """A subagent began executing within a session (Plan 009 WI-3.1).

    Recorded from Claude Code's ``SubagentStart`` hook, whose payload
    carries ``agent_id`` and ``agent_type`` on top of the session base
    fields (verified from real 2.1.207 capture).
    """

    agent_id: str
    agent_type: str | None = None
    on_behalf_of: dict[str, Any] | None = None
    harness: CairnConfig | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"agent_id": self.agent_id}
        if self.agent_type is not None:
            d["agent_type"] = self.agent_type
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        if self.harness is not None:
            d["harness"] = self.harness.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubagentStartPayload:
        return cls(
            agent_id=data["agent_id"],
            agent_type=data.get("agent_type"),
            on_behalf_of=data.get("on_behalf_of"),
            harness=CairnConfig.from_dict(data["harness"]) if "harness" in data else None,
        )


@dataclass(frozen=True)
class SubagentStopPayload:
    """A subagent finished executing (Plan 009 WI-3.1).

    ``last_assistant_message_digest`` covers the subagent's final reply
    (the text the parent received).  ``agent_transcript_digest`` covers
    the subagent's transcript file at stop time when the harness exposed
    a readable path — the subagent analogue of the WI-3.2 transcript
    attestation.
    """

    agent_id: str
    agent_type: str | None = None
    last_assistant_message_digest: str | None = None
    agent_transcript_path: str | None = None
    agent_transcript_digest: str | None = None
    on_behalf_of: dict[str, Any] | None = None
    harness: CairnConfig | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"agent_id": self.agent_id}
        if self.agent_type is not None:
            d["agent_type"] = self.agent_type
        if self.last_assistant_message_digest is not None:
            d["last_assistant_message_digest"] = self.last_assistant_message_digest
        if self.agent_transcript_path is not None:
            d["agent_transcript_path"] = self.agent_transcript_path
        if self.agent_transcript_digest is not None:
            d["agent_transcript_digest"] = self.agent_transcript_digest
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        if self.harness is not None:
            d["harness"] = self.harness.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubagentStopPayload:
        return cls(
            agent_id=data["agent_id"],
            agent_type=data.get("agent_type"),
            last_assistant_message_digest=data.get("last_assistant_message_digest"),
            agent_transcript_path=data.get("agent_transcript_path"),
            agent_transcript_digest=data.get("agent_transcript_digest"),
            on_behalf_of=data.get("on_behalf_of"),
            harness=CairnConfig.from_dict(data["harness"]) if "harness" in data else None,
        )


@dataclass(frozen=True)
class CompactionPayload:
    """The harness compacted the session context (Plan 009 WI-3.1).

    Context loss is provenance-relevant: events after a compaction were
    produced by a model that no longer saw the full history.  The digest
    covers the compaction summary that replaced the dropped context;
    ``compact_summary_content`` is present only under content capture
    (encrypted at rest when content encryption is on).
    """

    trigger: str
    compact_summary_digest: str | None = None
    compact_summary_content: str | dict[str, Any] | None = None
    on_behalf_of: dict[str, Any] | None = None
    harness: CairnConfig | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"trigger": self.trigger}
        if self.compact_summary_digest is not None:
            d["compact_summary_digest"] = self.compact_summary_digest
        if self.compact_summary_content is not None:
            d["compact_summary_content"] = self.compact_summary_content
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        if self.harness is not None:
            d["harness"] = self.harness.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompactionPayload:
        return cls(
            trigger=data["trigger"],
            compact_summary_digest=data.get("compact_summary_digest"),
            compact_summary_content=data.get("compact_summary_content"),
            on_behalf_of=data.get("on_behalf_of"),
            harness=CairnConfig.from_dict(data["harness"]) if "harness" in data else None,
        )


def digest_string(text: str | None) -> str | None:
    """Return SHA-256 hex digest of a string, or None if input is None."""
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_key_file_permissions(path: str) -> list[str]:
    """Check that a key file has restrictive permissions.

    Returns a list of warning strings (empty if permissions are acceptable).
    Warns if the file is readable by group or others, or if it is a symlink
    (which could point to an attacker-controlled target).
    """
    import os
    import stat

    warnings: list[str] = []
    try:
        # Check for symlinks first (lstat does not follow them).
        lst = os.lstat(path)
        if stat.S_ISLNK(lst.st_mode):
            warnings.append(
                f"Key file {path} is a symlink — resolve the real path "
                "before using for signing"
            )
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        if mode & stat.S_IRGRP:
            warnings.append(f"Key file {path} is group-readable (mode {oct(mode)})")
        if mode & stat.S_IROTH:
            warnings.append(f"Key file {path} is world-readable (mode {oct(mode)})")
        if mode & stat.S_IWGRP:
            warnings.append(f"Key file {path} is group-writable (mode {oct(mode)})")
        if mode & stat.S_IWOTH:
            warnings.append(f"Key file {path} is world-writable (mode {oct(mode)})")
    except OSError:
        warnings.append(f"Could not check permissions on {path} (stat failed)")
    return warnings
