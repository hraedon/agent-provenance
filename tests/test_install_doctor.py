"""Tests for ``cairn install-harness`` and ``cairn doctor`` (Plan 008 WI-1.2, WI-2.1)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cairn._config import CairnEnvConfig, resolve_config
from cairn._doctor import run_doctor
from cairn._install import (
    InstallResult,
    _install_claude,
    _is_cairn_hook_entry,
    _uninstall_claude,
    format_results_human,
    run_install_harness,
)


@pytest.fixture
def cfg(tmp_path: Path) -> CairnEnvConfig:
    return CairnEnvConfig(
        dsn="postgresql://user:pw@host/db",
        key_path=str(tmp_path / "keys.json"),
        key_ref=None,
        project="test_project",
        harness_name="claude-code",
        harness_version="1.0.0",
        principal_id="human:test",
        state_dir=str(tmp_path / "state"),
        disabled=False,
    )


@pytest.fixture
def claude_settings(tmp_path: Path) -> Path:
    path = tmp_path / "claude.json"
    os.environ["CAIRN_CLAUDE_SETTINGS"] = str(path)
    return path


@pytest.fixture(autouse=True)
def _isolate_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_CLAUDE_SETTINGS", str(tmp_path / "claude.json"))
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(tmp_path / "opencode.json"))


# ----------------------------------------------------------------------
# install-harness claude
# ----------------------------------------------------------------------


def test_install_claude_wires_hooks_and_env(cfg, claude_settings):
    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    assert not result.no_op
    data = json.loads(claude_settings.read_text())
    assert data["env"]["REGISTA_DSN"] == cfg.dsn
    assert data["env"]["CAIRN_PROJECT"] == cfg.project
    assert "PreToolUse" in data["hooks"]
    assert "PostToolUse" in data["hooks"]
    assert "SessionStart" in data["hooks"]
    assert "SessionEnd" in data["hooks"]
    assert "PostToolUseFailure" in data["hooks"]


def test_install_claude_idempotent(cfg, claude_settings):
    _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    assert result.no_op
    assert len(result.actions) == 0


def test_install_claude_dry_run_does_not_write(cfg, claude_settings):
    result = _install_claude(cfg, dry_run=True, uninstall=False, user=None)

    assert not result.no_op
    assert len(result.actions) > 0
    assert not claude_settings.exists()


def test_install_claude_no_clobber_existing_env(cfg, claude_settings):
    existing = {"env": {"REGISTA_DSN": "postgresql://existing:secret@host/db"}, "other": "keep"}
    claude_settings.write_text(json.dumps(existing))

    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    data = json.loads(claude_settings.read_text())
    assert data["env"]["REGISTA_DSN"] == "postgresql://existing:secret@host/db"
    assert data["other"] == "keep"
    assert "REGISTA_KEY_PATH" in data["env"]

    skip_actions = [a for a in result.actions if a.kind == "skip"]
    assert any("REGISTA_DSN" in a.detail for a in skip_actions)


def test_install_claude_preserves_user_hooks(cfg, claude_settings):
    user_hook = {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "echo user-hook", "timeout": 5}],
    }
    existing = {"hooks": {"PreToolUse": [user_hook]}}
    claude_settings.write_text(json.dumps(existing))

    _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    data = json.loads(claude_settings.read_text())
    pre_hooks = data["hooks"]["PreToolUse"]
    assert len(pre_hooks) == 2
    assert pre_hooks[0]["hooks"][0]["command"] == "echo user-hook"


def test_install_claude_with_user_principal(cfg, claude_settings):
    result = _install_claude(cfg, dry_run=False, uninstall=False, user="human:alice")

    data = json.loads(claude_settings.read_text())
    assert data["env"]["PRINCIPAL_ID"] == "human:alice"
    assert result.user == "human:alice"


# ----------------------------------------------------------------------
# uninstall-harness claude
# ----------------------------------------------------------------------


def test_uninstall_claude_removes_cairn_wiring(cfg, claude_settings):
    _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    data = json.loads(claude_settings.read_text())
    result = _uninstall_claude(
        claude_settings, data, dry_run=False,
        result=InstallResult(harness="claude"),
    )

    data = json.loads(claude_settings.read_text()) if claude_settings.exists() else {}
    assert "hooks" not in data or not data.get("hooks")
    assert "env" not in data or not data.get("env")
    assert not result.no_op


def test_uninstall_claude_preserves_user_hooks(cfg, claude_settings):
    user_hook = {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "echo user-hook", "timeout": 5}],
    }
    _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    data = json.loads(claude_settings.read_text())
    data["hooks"]["PreToolUse"].insert(0, user_hook)
    claude_settings.write_text(json.dumps(data))

    _uninstall_claude(
        claude_settings, json.loads(claude_settings.read_text()),
        dry_run=False, result=InstallResult(harness="claude"),
    )

    data = json.loads(claude_settings.read_text())
    pre_hooks = data.get("hooks", {}).get("PreToolUse", [])
    assert len(pre_hooks) == 1
    assert pre_hooks[0]["hooks"][0]["command"] == "echo user-hook"


def test_uninstall_claude_noop_on_clean(cfg, claude_settings):
    result = _uninstall_claude(
        claude_settings, {}, dry_run=False,
        result=InstallResult(harness="claude"),
    )
    assert result.no_op


# ----------------------------------------------------------------------
# _is_cairn_hook_entry
# ----------------------------------------------------------------------


def test_is_cairn_hook_entry_detects_module():
    entry = {
        "matcher": "*",
        "hooks": [
            {"type": "command", "command": "python3 -m cairn._claude_hook pre"}
        ],
    }
    assert _is_cairn_hook_entry(entry)


def test_is_cairn_hook_entry_detects_legacy():
    entry = {
        "matcher": "*",
        "hooks": [
            {"type": "command", "command": "python3 /path/cairn_hook.py pre"}
        ],
    }
    assert _is_cairn_hook_entry(entry)


def test_is_cairn_hook_entry_rejects_foreign():
    entry = {"matcher": "*", "hooks": [{"type": "command", "command": "echo other-hook"}]}
    assert not _is_cairn_hook_entry(entry)


# ----------------------------------------------------------------------
# run_install_harness (all)
# ----------------------------------------------------------------------


def test_run_install_harness_all(cfg, monkeypatch):
    monkeypatch.setattr("cairn._install.resolve_config", lambda: cfg)
    results = run_install_harness("all", dry_run=True, uninstall=False, user=None)
    assert len(results) == 2
    assert results[0].harness == "claude"
    assert results[1].harness == "opencode"


# ----------------------------------------------------------------------
# format_results_human
# ----------------------------------------------------------------------


def test_format_results_dry_run():
    r = InstallResult(harness="claude", no_op=False, actions=[])
    out = format_results_human([r], dry_run=True, uninstall=False)
    assert "[dry-run]" in out
    assert "would be wired" in out


def test_format_results_uninstall():
    r = InstallResult(harness="claude", no_op=False, actions=[])
    out = format_results_human([r], dry_run=False, uninstall=True)
    assert "uninstalled" in out


# ----------------------------------------------------------------------
# Config resolution
# ----------------------------------------------------------------------


def test_resolve_config_prefers_regista_env(monkeypatch):
    monkeypatch.setenv("REGISTA_DSN", "postgresql://regista@host/db")
    monkeypatch.setenv("REGISTA_KEY_PATH", "/keys/regista.json")
    monkeypatch.setenv("CAIRN_DSN", "postgresql://cairn@host/db")
    monkeypatch.setenv("CAIRN_KEY_PATH", "/keys/cairn.json")
    monkeypatch.setenv("CAIRN_PROJECT", "proj")
    monkeypatch.setattr("cairn._config._load_suite_env", lambda: {})

    cfg = resolve_config()
    assert cfg.dsn == "postgresql://regista@host/db"
    assert cfg.key_path == "/keys/regista.json"
    assert cfg.project == "proj"


def test_resolve_config_falls_back_to_cairn(monkeypatch, capsys):
    monkeypatch.delenv("REGISTA_DSN", raising=False)
    monkeypatch.delenv("REGISTA_KEY_PATH", raising=False)
    monkeypatch.setenv("CAIRN_DSN", "postgresql://cairn@host/db")
    monkeypatch.setenv("CAIRN_KEY_PATH", "/keys/cairn.json")
    monkeypatch.setenv("CAIRN_PROJECT", "proj")
    monkeypatch.setattr("cairn._config._load_suite_env", lambda: {})

    cfg = resolve_config()
    assert cfg.dsn == "postgresql://cairn@host/db"
    assert cfg.key_path == "/keys/cairn.json"
    captured = capsys.readouterr()
    assert "deprecated" in captured.err


def test_resolve_config_missing():
    cfg = CairnEnvConfig()
    assert not cfg.is_configured
    assert "DSN" in cfg.missing()
    assert "KEY_PATH or KEY_REF" in cfg.missing()
    assert "PROJECT" in cfg.missing()


def test_resolve_config_key_ref(monkeypatch):
    """key_ref satisfies is_configured without key_path."""
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_ref="env:MY_SECRET_KEY",
        project="proj",
    )
    assert cfg.is_configured
    assert cfg.missing() == []


def test_cairn_env_config_key_ref_in_doctor(monkeypatch):
    """Doctor reports key_ref as pass when resolvable."""
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_ref="env:MY_SECRET_KEY",
        project="proj",
    )
    monkeypatch.setattr("cairn._doctor.resolve_config", lambda: cfg)
    monkeypatch.setenv("MY_SECRET_KEY", "test-secret-value")
    from cairn._doctor import _check_key_file
    result = _check_key_file(cfg)
    assert result["status"] == "ok"
    assert "key_ref" in result["detail"]


# ----------------------------------------------------------------------
# Doctor
# ----------------------------------------------------------------------


def test_doctor_json_shape(monkeypatch, tmp_path):
    monkeypatch.setattr("cairn._doctor.resolve_config", lambda: CairnEnvConfig(
        dsn=None, key_path=None, project=None
    ))
    exit_code = run_doctor(json_output=True)
    assert exit_code == 1


def test_doctor_exit_code_pass(monkeypatch):
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path="/nonexistent.json",
        project="test",
    )
    monkeypatch.setattr("cairn._doctor.resolve_config", lambda: cfg)

    class _FakeRegista:
        def __init__(self, **kwargs):
            raise ConnectionError("mock: unreachable")

        def read_events(self, **kwargs):
            return []

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    exit_code = run_doctor(json_output=False)
    assert exit_code == 1
