"""Cairn — Cryptographic provenance for agentic workflows."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .adapter import CairnAdapter
from .client import CairnClient, ToolCallContext
from .schema import (
    CONTENT_ENCRYPTION_EXTERNAL,
    CONTENT_ENCRYPTION_OFF,
    CONTENT_ENCRYPTION_ON,
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
    ToolCallEvent,
    TranscriptAttestationPayload,
    UserMessagePayload,
    check_key_file_permissions,
)
from .verifier import SessionAttestationEntry


def _get_version() -> str:
    try:
        return _pkg_version("cairn")
    except PackageNotFoundError:
        return "0.1.0"


__version__ = _get_version()

__all__ = [
    "CONTENT_ENCRYPTION_EXTERNAL",
    "CONTENT_ENCRYPTION_OFF",
    "CONTENT_ENCRYPTION_ON",
    "AssistantMessagePayload",
    "CairnAdapter",
    "CairnClient",
    "CairnConfig",
    "CompactionPayload",
    "FileDigest",
    "ResultSummary",
    "ScopeAttestationPayload",
    "SessionAttestationEntry",
    "SessionAttestationPayload",
    "SubagentIdentity",
    "SubagentStartPayload",
    "SubagentStopPayload",
    "ToolCallBegin",
    "ToolCallContext",
    "ToolCallEnd",
    "ToolCallEvent",
    "TranscriptAttestationPayload",
    "UserMessagePayload",
    "__version__",
    "check_key_file_permissions",
]
