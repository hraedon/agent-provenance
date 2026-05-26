"""Cairn — Cryptographic provenance for agentic workflows."""

from __future__ import annotations

__version__ = "0.1.0"

from .adapter import CairnAdapter
from .client import CairnClient, ToolCallContext
from .schema import (
    CairnConfig,
    FileDigest,
    ResultSummary,
    ScopeAttestationPayload,
    ToolCallBegin,
    ToolCallEnd,
    ToolCallEvent,
    check_key_file_permissions,
)

__all__ = [
    "CairnAdapter",
    "CairnClient",
    "CairnConfig",
    "FileDigest",
    "ResultSummary",
    "ScopeAttestationPayload",
    "ToolCallBegin",
    "ToolCallContext",
    "ToolCallEnd",
    "ToolCallEvent",
    "check_key_file_permissions",
]
