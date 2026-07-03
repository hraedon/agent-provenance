"""Config resolution for cairn — suite-aware env var precedence.

Precedence (highest first):
  1. Explicit process env (REGISTA_DSN / REGISTA_KEY_PATH)
  2. Legacy alias (CAIRN_DSN / CAIRN_KEY_PATH) — warns on fallback
  3. suite.env file (if present)

Cairn-specific vars (CAIRN_PROJECT, CAIRN_HARNESS_NAME, etc.) have no
REGISTA_ equivalent and are read directly.
"""

from __future__ import annotations

import dataclasses
import os
import sys
from pathlib import Path

_SUITE_ENV_PATHS = [
    Path(os.environ.get("AGENT_SUITE_CONFIG", "")),
    Path.home() / ".config" / "agent-suite" / "suite.env",
    Path("/etc/agent-suite/suite.env"),
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
    project: str | None = None
    harness_name: str = "claude-code"
    harness_version: str = "unknown"
    principal_id: str | None = None
    state_dir: str = "/tmp/cairn-sessions"
    disabled: bool = False

    @property
    def is_configured(self) -> bool:
        return all([self.dsn, self.key_path, self.project])

    def missing(self) -> list[str]:
        missing = []
        if not self.dsn:
            missing.append("DSN")
        if not self.key_path:
            missing.append("KEY_PATH")
        if not self.project:
            missing.append("PROJECT")
        return missing


def resolve_config() -> CairnEnvConfig:
    suite_env = _load_suite_env()

    dsn = _resolve("REGISTA_DSN", "CAIRN_DSN", suite_env)
    key_path = _resolve("REGISTA_KEY_PATH", "CAIRN_KEY_PATH", suite_env)
    project = (
        os.environ.get("CAIRN_PROJECT")
        or suite_env.get("CAIRN_PROJECT")
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
        or "/tmp/cairn-sessions"
    )
    disabled = bool(os.environ.get("CAIRN_DISABLE"))

    return CairnEnvConfig(
        dsn=dsn,
        key_path=key_path,
        project=project,
        harness_name=harness_name,
        harness_version=harness_version,
        principal_id=principal_id,
        state_dir=state_dir,
        disabled=disabled,
    )
