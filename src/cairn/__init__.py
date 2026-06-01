"""Cairn — Cryptographic provenance for agentic workflows."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

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


def _get_version() -> str:
    try:
        return _pkg_version("cairn")
    except PackageNotFoundError:
        return "0.1.0"


__version__ = _get_version()

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
    "__version__",
    "check_key_file_permissions",
]
