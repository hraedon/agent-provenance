"""Unit tests for cairn._bridge (OpenCode bridge)."""

from __future__ import annotations

import json
import os
import uuid
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cairn._bridge import main as bridge_main


@pytest.fixture
def _valid_env(tmp_path: Path) -> Path:
    """Set minimal valid env vars for the bridge."""
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"keys": []}))
    os.environ["CAIRN_DSN"] = "postgresql://u:p@localhost/db"
    os.environ["CAIRN_PROJECT"] = "test"
    os.environ["CAIRN_KEY_PATH"] = str(key_file)
    os.environ["PRINCIPAL_ID"] = "human:test"
    return key_file


def _run_bridge(
    stdin_data: str | None, *, capsys: pytest.CaptureFixture[str]
) -> tuple[int, str, str]:
    """Run the bridge main with patched stdin and capture stdout/stderr."""
    with patch("sys.stdin", StringIO(stdin_data or "")):
        try:
            bridge_main()
            return 0, capsys.readouterr().out, capsys.readouterr().err
        except SystemExit as exc:
            outerr = capsys.readouterr()
            return exc.code if isinstance(exc.code, int) else 1, outerr.out, outerr.err


# ----------------------------------------------------------------------
# Error path tests
# ----------------------------------------------------------------------


def test_cairn_disable_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    os.environ["CAIRN_DISABLE"] = "1"
    # Even with no stdin and no other env vars, should exit 0
    rc, _out, _err = _run_bridge(None, capsys=capsys)
    assert rc == 0


def test_no_input_exits_1(_valid_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc, _out, err = _run_bridge(None, capsys=capsys)
    assert rc == 1
    assert "no input" in err


def test_bad_json_exits_1(_valid_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc, _out, err = _run_bridge("not-json{}", capsys=capsys)
    assert rc == 1
    assert "bad JSON" in err


def test_missing_env_exits_1(capsys: pytest.CaptureFixture[str]) -> None:
    os.environ.pop("CAIRN_DSN", None)
    rc, _out, err = _run_bridge('{"action":"begin"}', capsys=capsys)
    assert rc == 1
    assert "CAIRN_DSN" in err


def test_unknown_action_exits_1(_valid_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc, _out, err = _run_bridge('{"action":"frobnicate"}', capsys=capsys)
    assert rc == 1
    assert "unknown action" in err


# ----------------------------------------------------------------------
# Action tests (mocked regista / adapter)
# ----------------------------------------------------------------------


def _make_mock_wi(work_item_id: uuid.UUID | None = None) -> MagicMock:
    wi = MagicMock()
    wi.work_item_id = work_item_id or uuid.uuid4()
    wi.custom_fields = {"tool": "Edit", "status": "running"}
    return wi


def _make_mock_event(event_id: uuid.UUID | None = None) -> MagicMock:
    ev = MagicMock()
    ev.event_id = event_id or uuid.uuid4()
    ev.payload = {"version": "1", "scope_statement": "test"}
    return ev


@patch("cairn._bridge.Regista")
@patch("cairn._bridge.CairnAdapter")
def test_attest_scope(
    mock_adapter_cls: Any,
    mock_regista_cls: Any,
    _valid_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    adapter = mock_adapter_cls.return_value
    adapter.attest_scope.return_value = _make_mock_event()

    rc, out, _err = _run_bridge(
        json.dumps(
            {
                "action": "attest_scope",
                "harnesses": [{"name": "opencode", "version": "0.2.0"}],
                "scope_statement": "In scope: opencode test.",
                "session_id": "test-session",
            }
        ),
        capsys=capsys,
    )
    assert rc == 0
    data = json.loads(out)
    assert data["status"] == "ok"
    assert "event_id" in data
    adapter.attest_scope.assert_called_once()


@patch("cairn._bridge.Regista")
@patch("cairn._bridge.CairnAdapter")
def test_model_observation_has_restart_stable_event_id(
    mock_adapter_cls: Any,
    mock_regista_cls: Any,
    _valid_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    adapter = mock_adapter_cls.return_value
    event = _make_mock_event()
    event.payload = {"status": "mismatch", "observed_model_lineage": "glm"}
    adapter.record_model_observation.return_value = event
    observation_id = '["test-session","provider-b","glm-5.2"]'

    rc, out, _err = _run_bridge(
        json.dumps(
            {
                "action": "model_observation",
                "session_id": "test-session",
                "source": "opencode.message.updated",
                "observation_id": observation_id,
                "observed_provider_id": "provider-b",
                "observed_model_id": "glm-5.2",
            }
        ),
        capsys=capsys,
    )

    assert rc == 0
    assert json.loads(out)["observation_status"] == "mismatch"
    normalized_session = str(uuid.uuid5(uuid.NAMESPACE_URL, "test-session"))
    expected = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"cairn:model-observation:{normalized_session}:{observation_id}",
    )
    assert adapter.record_model_observation.call_args.kwargs["event_id"] == expected


@patch("cairn._bridge.Regista")
@patch("cairn._bridge.CairnAdapter")
def test_begin(
    mock_adapter_cls: Any,
    mock_regista_cls: Any,
    _valid_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    wi_id = uuid.UUID("12345678-1234-5678-1234-567812345678")
    mock_adapter_cls.return_value.begin_tool_call.return_value = _make_mock_wi(wi_id)

    rc, out, _err = _run_bridge(
        json.dumps(
            {
                "action": "begin",
                "tool": "Edit",
                "args": {"path": "/tmp/foo"},
                "session_id": "test-session",
            }
        ),
        capsys=capsys,
    )
    assert rc == 0
    data = json.loads(out)
    assert data["status"] == "ok"
    assert data["work_item_id"] == str(wi_id)
    assert "sha256:" in data["args_hash"]


@patch("cairn._bridge.Regista")
@patch("cairn._bridge.CairnAdapter")
def test_end(
    mock_adapter_cls: Any,
    mock_regista_cls: Any,
    _valid_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ev_id = uuid.UUID("87654321-4321-8765-4321-876543218765")
    mock_adapter_cls.return_value.end_tool_call.return_value = _make_mock_event(ev_id)

    rc, out, _err = _run_bridge(
        json.dumps(
            {
                "action": "end",
                "work_item_id": str(ev_id),
                "result_summary": {"exit_code": 0},
                "session_id": "test-session",
            }
        ),
        capsys=capsys,
    )
    assert rc == 0
    data = json.loads(out)
    assert data["status"] == "ok"
    assert data["event_id"] == str(ev_id)


@patch("cairn._bridge.Regista")
@patch("cairn._bridge.CairnAdapter")
def test_end_missing_work_item_id(
    mock_adapter_cls: Any,
    mock_regista_cls: Any,
    _valid_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, _out, err = _run_bridge(
        json.dumps(
            {
                "action": "end",
                "result_summary": {"exit_code": 0},
                "session_id": "test-session",
            }
        ),
        capsys=capsys,
    )
    assert rc == 1
    assert "work_item_id required" in err


@patch("cairn._bridge.Regista")
@patch("cairn._bridge.CairnAdapter")
def test_session_id_passthrough(
    mock_adapter_cls: Any,
    mock_regista_cls: Any,
    _valid_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    wi_id = uuid.uuid4()
    mock_adapter_cls.return_value.begin_tool_call.return_value = _make_mock_wi(wi_id)

    explicit_session = "my-explicit-session-id"
    rc, _out, _err = _run_bridge(
        json.dumps(
            {
                "action": "begin",
                "tool": "Edit",
                "args": {"path": "/tmp/foo"},
                "session_id": explicit_session,
            }
        ),
        capsys=capsys,
    )
    assert rc == 0

    call_kwargs = mock_adapter_cls.call_args
    on_behalf_of = call_kwargs.kwargs.get("on_behalf_of") or call_kwargs[1].get("on_behalf_of")
    assert on_behalf_of is not None
    # Non-UUID session IDs are hashed to a deterministic UUID v5
    expected_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, explicit_session))
    assert on_behalf_of["session_id"] == expected_uuid


@patch("cairn._bridge.Regista")
@patch("cairn._bridge.CairnAdapter")
def test_session_id_required(
    mock_adapter_cls: Any,
    mock_regista_cls: Any,
    _valid_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, _out, err = _run_bridge(
        json.dumps({"action": "begin", "tool": "Edit", "args": {"path": "/tmp/foo"}}),
        capsys=capsys,
    )
    assert rc == 1
    assert "session_id required" in err
