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
    # v6 process producer identity (regista resolves it from the process
    # environment, and regista.testing's epoch helpers set it directly in
    # os.environ — outside monkeypatch). Without a per-test restore, a
    # producer configured by one test silently signs every later test's
    # events (the same isolation agent-notes' conftest enforces).
    "REGISTA_PRODUCER_HARNESS",
    "REGISTA_PRODUCER_HARNESS_VERSION",
    "REGISTA_PRODUCER_MODEL",
    "REGISTA_PRODUCER_MODEL_LINEAGE",
]

# The canonical principals cairn's tests write as. regista 0.7's v6 epoch
# requires every signing actor to be a canonical principal (kind:subject)
# whose key the project has accepted, so the fixture keyset carries one
# throwaway Ed25519 key per principal and open_v6_epoch accepts exactly
# these — no more (an acceptance is authority, not a fixture convenience).
CAIRN_TEST_PRINCIPALS: tuple[str, ...] = (
    "service:cairn",   # adapter default actor
    "human:test",      # test_cairn / hermes / integrity adapters
    "human:test-user",  # test_client principal
    "human:owner",     # attestation payloads / delegation principals
    "agent:worker",    # direct writer calls (proof wiring)
)


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
def v6_keyset(tmp_path: Path):
    """A throwaway Ed25519 v6 keyset covering exactly the test principals.

    regista 0.7's public consumer-testing surface (AMENDMENTS §5): the file
    is written by ``make_v6_keyset`` and doubles as the handle's key path.
    """
    from regista.testing import make_v6_keyset

    return make_v6_keyset(tmp_path, principals=CAIRN_TEST_PRINCIPALS)


@pytest.fixture
def regista_instance(dsn: str, project: str, v6_keyset):
    """Create a fresh Postgres-backed regista project with an open v6 epoch.

    Skips fast when Postgres is unreachable or the role is unavailable —
    regista's pool retries auth failures indefinitely, so a pre-check keeps
    the suite from hanging (WI-001).

    The epoch (genesis + exactly the ``CAIRN_TEST_PRINCIPALS`` acceptances)
    is opened through regista's public testing helper; constructing the
    handle never opens one implicitly.
    """
    from regista import Regista
    from regista.testing import open_v6_epoch

    if not postgres_reachable(dsn):
        pytest.skip("Postgres not available; set REGISTA_TEST_DSN to run")
    sub = Regista.create_project(
        dsn=dsn,
        project=project,
        hmac_key_path=v6_keyset.path,
    )
    open_v6_epoch(sub, v6_keyset, principals=CAIRN_TEST_PRINCIPALS)
    yield sub
    sub.close()


@pytest.fixture
def workflow_registered(regista_instance) -> None:
    """Register cairn's workflow as a signed v6 workflow_registered event."""
    regista_instance.register_workflow_file("workflows/cairn_agent_actions.yaml")
