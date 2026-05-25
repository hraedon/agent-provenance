"""Canonical event schema for Cairn.

Normalizes tool calls from different harnesses into a uniform substrate payload.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from substrate._jcs import canonicalize


@dataclass(frozen=True)
class FileDigest:
    path: str
    pre_digest: str | None
    post_digest: str | None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"path": self.path}
        if self.pre_digest is not None:
            d["pre_digest"] = self.pre_digest
        if self.post_digest is not None:
            d["post_digest"] = self.post_digest
        return d

    @classmethod
    def from_dict(cls, data: dict) -> FileDigest:
        return cls(
            path=data["path"],
            pre_digest=data.get("pre_digest"),
            post_digest=data.get("post_digest"),
        )


@dataclass(frozen=True)
class ResultSummary:
    exit_code: int | None = None
    stdout_digest: str | None = None
    stderr_digest: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {}
        if self.exit_code is not None:
            d["exit_code"] = self.exit_code
        if self.stdout_digest is not None:
            d["stdout_digest"] = self.stdout_digest
        if self.stderr_digest is not None:
            d["stderr_digest"] = self.stderr_digest
        if self.error is not None:
            d["error"] = self.error
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ResultSummary:
        return cls(
            exit_code=data.get("exit_code"),
            stdout_digest=data.get("stdout_digest"),
            stderr_digest=data.get("stderr_digest"),
            error=data.get("error"),
        )


@dataclass(frozen=True)
class CairnConfig:
    harness_name: str
    harness_version: str
    config_digest: str | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "name": self.harness_name,
            "version": self.harness_version,
        }
        if self.config_digest is not None:
            d["config_digest"] = self.config_digest
        return d

    @classmethod
    def from_dict(cls, data: dict) -> CairnConfig:
        return cls(
            harness_name=data["name"],
            harness_version=data["version"],
            config_digest=data.get("config_digest"),
        )


@dataclass(frozen=True)
class ToolCallBegin:
    tool: str
    tool_args_hash: str
    tool_args_redacted: dict[str, Any] | None = None
    files: list[FileDigest] | None = None
    on_behalf_of: dict[str, Any] | None = None
    parent_action_event_id: str | None = None
    harness: CairnConfig | None = None

    def to_dict(self) -> dict:
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
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ToolCallBegin:
        return cls(
            tool=data["tool"],
            tool_args_hash=data["tool_args_hash"],
            tool_args_redacted=data.get("tool_args_redacted"),
            files=[FileDigest.from_dict(f) for f in data["files"]] if "files" in data else None,
            on_behalf_of=data.get("on_behalf_of"),
            parent_action_event_id=data.get("parent_action_event_id"),
            harness=CairnConfig.from_dict(data["harness"]) if "harness" in data else None,
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

    def to_dict(self) -> dict:
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
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ToolCallEnd:
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
    """
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


@dataclass(frozen=True)
class ScopeAttestationPayload:
    version: str
    principal_id: str
    attested_at: str
    harnesses: list[dict[str, Any]]
    scope_statement: str
    harness_config_digests: dict[str, str] | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "version": self.version,
            "principal_id": self.principal_id,
            "attested_at": self.attested_at,
            "harnesses": self.harnesses,
            "scope_statement": self.scope_statement,
        }
        if self.harness_config_digests is not None:
            d["harness_config_digests"] = self.harness_config_digests
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ScopeAttestationPayload:
        return cls(
            version=data["version"],
            principal_id=data["principal_id"],
            attested_at=data["attested_at"],
            harnesses=data["harnesses"],
            scope_statement=data["scope_statement"],
            harness_config_digests=data.get("harness_config_digests"),
        )


def digest_string(text: str | None) -> str | None:
    """Return SHA-256 hex digest of a string, or None if input is None."""
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
