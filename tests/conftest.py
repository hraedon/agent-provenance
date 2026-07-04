"""Shared test fixtures for cairn tests."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from _dbutil import postgres_reachable, resolve_test_dsn


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
