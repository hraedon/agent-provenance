"""Shared test fixtures for cairn tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from regista import Regista


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
def workflow_registered(regista_instance: Regista) -> None:
    regista_instance.register_workflow_file("workflows/cairn_agent_actions.yaml")
