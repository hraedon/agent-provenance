"""Shared test fixtures for cairn tests."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from _dbutil import postgres_reachable, resolve_test_dsn

# Env vars that influence cairn behavior at runtime.  Tests must never
# inherit the operator's real config (suite.env + live env) — on a
# dogfooding box that causes false failures and, worse, could write to
# the live regista store if a mock boundary slips (WI-026).
_CONFIG_ENV_VARS = [
    # Config resolution (resolve_config)
    "REGISTA_DSN", "CAIRN_DSN",
    "REGISTA_KEY_PATH", "CAIRN_KEY_PATH",
    "REGISTA_KEY_REF", "CAIRN_KEY_REF",
    "CAIRN_PROJECT",
    "CAIRN_HARNESS_NAME", "CAIRN_HARNESS_VERSION",
    "PRINCIPAL_ID",
    "CAIRN_STATE_DIR",
    "CAIRN_DISABLE",
    "CAIRN_CONTENT_KEY_REF", "CAIRN_CONTENT_KEY_PATH",
    "CAIRN_CONTENT_ENCRYPTION",
    "AGENT_SUITE_CONFIG",
    # Doctor / install / hook runtime
    "CAIRN_BRIDGE_PATH",
    "CAIRN_CAPTURE_DIR",
    "CAIRN_CLAUDE_SETTINGS",
    "CAIRN_OPENCODE_CONFIG",
    "CAIRN_HERMES_HOME",
    "CAIRN_CLAUDE_PROJECTS",
    "CAIRN_OPENCODE_SESSIONS",
    "CAIRN_CODEX_SESSIONS",
    "CAIRN_MAX_ATTESTATION_AGE_HOURS",
    "CLAUDE_PROJECT_DIR",
]


@pytest.fixture(autouse=True)
def _isolate_config_env(monkeypatch):
    """Isolate every test from the operator's real config.

    Clears all CAIRN_*/REGISTA_*/PRINCIPAL_ID/AGENT_SUITE_CONFIG env vars,
    patches ``_load_suite_env`` to return ``{}``, and resets the
    import-time ``_SUITE_ENV_PATHS`` cache so no test reads the
    operator's ``suite.env`` file or settings paths.  ``REGISTA_TEST_DSN``
    is preserved so DB-dependent tests can still find the test database.
    """
    for var in _CONFIG_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("cairn._config._load_suite_env", lambda: {})
    monkeypatch.setattr("cairn._config._SUITE_ENV_PATHS", [])
    # The content-encryption verdict memoises resolvable keys for the life of
    # the process (WI-037); a verdict from a previous test must never leak into
    # the next one, or a test could pass on a stale "key resolves".
    from cairn._content_crypto import reset_content_encryption_status_cache

    reset_content_encryption_status_cache()


@pytest.fixture
def hmac_keys(tmp_path: Path) -> Path:
    """Create a minimal regista HMAC key file."""
    key_file = tmp_path / "keys.json"
    key_file.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": "cairn-test-001",
                        "secret": "supersecret-test-key-32bytes!!",
                        "status": "active",
                        "alg": "HMAC-SHA256",
                    }
                ]
            }
        )
    )
    return key_file


@pytest.fixture
def dsn() -> str:
    return resolve_test_dsn()


@pytest.fixture
def project() -> str:
    return f"cairn_test_{uuid.uuid4().hex[:8]}"


@pytest.fixture
def regista_instance(dsn: str, project: str, hmac_keys: Path):
    """Create a fresh Postgres-backed regista project for each test.

    Skips fast when Postgres is unreachable or the role is unavailable —
    regista's pool retries auth failures indefinitely, so a pre-check keeps
    the suite from hanging (WI-001).
    """
    from regista import Regista

    if not postgres_reachable(dsn):
        pytest.skip("Postgres not available; set REGISTA_TEST_DSN to run")
    sub = Regista.create_project(
        dsn=dsn,
        project=project,
        hmac_key_path=str(hmac_keys),
    )
    yield sub
    sub.close()


@pytest.fixture
def workflow_registered(regista_instance) -> None:
    regista_instance.register_workflow_file("workflows/cairn_agent_actions.yaml")
