"""Config resolution for cairn — suite-aware env var precedence.

Precedence (highest first):
   1. Explicit process env (REGISTA_DSN / REGISTA_KEY_PATH / REGISTA_KEY_REF)
   2. Legacy alias (CAIRN_DSN / CAIRN_KEY_PATH / CAIRN_KEY_REF) — warns on fallback
   3. suite.env file (if present)

Cairn-specific vars (CAIRN_PROJECT, CAIRN_HARNESS_NAME, etc.) have no
REGISTA_ equivalent and are read directly.

Key resolution: when ``key_ref`` is set (e.g. ``env:MY_SECRET_KEY`` or
``vault:secret/data/cairn/private_key``), the signing key is resolved at
bridge startup via ``regista._secrets.resolve()`` — no plaintext key on
disk.  When ``key_path`` is set, the key is read from a file as before.
"""

from __future__ import annotations

import dataclasses
import os
import sys
import tempfile
from pathlib import Path

_DEFAULT_STATE_DIR = str(Path(tempfile.gettempdir()) / "cairn-sessions")


def _parse_bool(val: str | None) -> bool:
    """Parse a boolean env var.

    Only ``1``, ``true``, ``yes``, ``on`` (case-insensitive) are truthy.
    This prevents ``CAIRN_DISABLE=false`` from accidentally enabling the
    disabled state (WI-012).
    """
    if val is None:
        return False
    return val.strip().lower() in ("1", "true", "yes", "on")

_suite_config = os.environ.get("AGENT_SUITE_CONFIG")
_SUITE_ENV_PATHS = [
    p
    for p in [
        Path(_suite_config) if _suite_config and _suite_config.strip() else None,
        Path.home() / ".config" / "agent-suite" / "suite.env",
        Path("/etc/agent-suite/suite.env"),
    ]
    if p is not None
]


def _load_suite_env() -> dict[str, str]:
    for p in _SUITE_ENV_PATHS:
        if p.is_file():
            vals: dict[str, str] = {}
            for line in p.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    vals[k.strip()] = v.strip()
            return vals
    return {}


def _resolve(key_suite: str, key_legacy: str, suite_env: dict[str, str]) -> str | None:
    val = os.environ.get(key_suite)
    if val:
        return val
    val = os.environ.get(key_legacy)
    if val:
        print(
            f"cairn: WARNING: {key_legacy} is deprecated, use {key_suite}",
            file=sys.stderr,
        )
        return val
    val = suite_env.get(key_suite)
    if val:
        return val
    val = suite_env.get(key_legacy)
    if val:
        print(
            f"cairn: WARNING: {key_legacy} in suite.env is deprecated, use {key_suite}",
            file=sys.stderr,
        )
        return val
    return None


@dataclasses.dataclass(frozen=True)
class CairnEnvConfig:
    dsn: str | None = None
    key_path: str | None = None
    key_ref: str | None = None
    project: str | None = None
    harness_name: str = "claude-code"
    harness_version: str = "unknown"
    principal_id: str | None = None
    state_dir: str = _DEFAULT_STATE_DIR
    disabled: bool = False
    content_key_ref: str | None = None
    content_key_path: str | None = None
    content_encryption: str = "on"

    @property
    def is_configured(self) -> bool:
        return all([self.dsn, self.key_path or self.key_ref, self.project])

    def missing(self) -> list[str]:
        missing = []
        if not self.dsn:
            missing.append("DSN")
        if not self.key_path and not self.key_ref:
            missing.append("KEY_PATH or KEY_REF")
        if not self.project:
            missing.append("PROJECT")
        return missing


def resolve_config() -> CairnEnvConfig:
    suite_env = _load_suite_env()

    dsn = _resolve("REGISTA_DSN", "CAIRN_DSN", suite_env)
    key_path = _resolve("REGISTA_KEY_PATH", "CAIRN_KEY_PATH", suite_env)
    key_ref = _resolve("REGISTA_KEY_REF", "CAIRN_KEY_REF", suite_env)
    project = (
        os.environ.get("CAIRN_PROJECT")
        or suite_env.get("CAIRN_PROJECT")
    )

    import getpass

    try:
        _default_principal = f"human:{os.getlogin()}"
    except OSError:
        _default_principal = f"human:{getpass.getuser()}"

    harness_name = (
        os.environ.get("CAIRN_HARNESS_NAME")
        or suite_env.get("CAIRN_HARNESS_NAME")
        or "claude-code"
    )
    harness_version = (
        os.environ.get("CAIRN_HARNESS_VERSION")
        or suite_env.get("CAIRN_HARNESS_VERSION")
        or "unknown"
    )
    principal_id = (
        os.environ.get("PRINCIPAL_ID")
        or suite_env.get("PRINCIPAL_ID")
        or _default_principal
    )
    state_dir = (
        os.environ.get("CAIRN_STATE_DIR")
        or suite_env.get("CAIRN_STATE_DIR")
        or _DEFAULT_STATE_DIR
    )
    disabled = _parse_bool(os.environ.get("CAIRN_DISABLE"))

    content_key_ref = (
        os.environ.get("CAIRN_CONTENT_KEY_REF")
        or suite_env.get("CAIRN_CONTENT_KEY_REF")
    )
    content_key_path = (
        os.environ.get("CAIRN_CONTENT_KEY_PATH")
        or suite_env.get("CAIRN_CONTENT_KEY_PATH")
    )
    content_encryption_raw = (
        os.environ.get("CAIRN_CONTENT_ENCRYPTION")
        or suite_env.get("CAIRN_CONTENT_ENCRYPTION")
        or "on"
    )
    content_encryption = content_encryption_raw.strip().lower()
    if content_encryption not in ("on", "off", "external"):
        content_encryption = "on"

    return CairnEnvConfig(
        dsn=dsn,
        key_path=key_path,
        key_ref=key_ref,
        project=project,
        harness_name=harness_name,
        harness_version=harness_version,
        principal_id=principal_id,
        state_dir=state_dir,
        disabled=disabled,
        content_key_ref=content_key_ref,
        content_key_path=content_key_path,
        content_encryption=content_encryption,
    )
