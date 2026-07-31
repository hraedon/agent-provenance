"""Tests for ``cairn install-harness`` and ``cairn doctor`` (Plan 008 WI-1.2, WI-2.1)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cairn._config import CairnEnvConfig, resolve_config
from cairn._doctor import _check_opencode_harness_wired, run_doctor
from cairn._install import (
    CAIRN_CODEX_HOOK_COMMAND,
    ConfigLoadError,
    InstallResult,
    InstallStatus,
    _compute_entry_hash,
    _detect_harness_version,
    _find_opencode_plugin,
    _install_claude,
    _install_codex,
    _install_hermes,
    _install_opencode,
    _is_cairn_hook_entry,
    _load_json,
    _load_manifest,
    _uninstall_claude,
    _uninstall_codex,
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
        integrity_dir=str(tmp_path / "integrity"),
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
    # Isolate Codex hooks.json so tests never touch the host's real ~/.codex.
    monkeypatch.setenv("CAIRN_CODEX_HOOKS", str(tmp_path / "codex" / "hooks.json"))
    # Isolate the manifest so tests never touch the host's real ~/.cairn.
    monkeypatch.setenv("CAIRN_MANIFEST_PATH", str(tmp_path / "manifest.json"))
    monkeypatch.delenv("CODEX_HOME", raising=False)


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
# _is_cairn_hook_entry — hash-based ownership (Plan 011 WI-3.1)
# ----------------------------------------------------------------------


def test_is_cairn_hook_entry_detects_module():
    entry = {
        "matcher": "*",
        "hooks": [
            {"type": "command", "command": "python3 -m cairn._claude_hook pre"}
        ],
    }
    assert _is_cairn_hook_entry(entry, harness="claude", event="PreToolUse")


def test_is_cairn_hook_entry_detects_legacy():
    """Legacy ``cairn_hook.py`` script invocation is detected via the
    narrow token-based fallback (not the former broad substring match)."""
    entry = {
        "matcher": "*",
        "hooks": [
            {"type": "command", "command": "python3 /path/cairn_hook.py pre"}
        ],
    }
    assert _is_cairn_hook_entry(entry, harness="claude", event="PreToolUse")


def test_is_cairn_hook_entry_rejects_foreign():
    entry = {"matcher": "*", "hooks": [{"type": "command", "command": "echo other-hook"}]}
    assert not _is_cairn_hook_entry(entry, harness="claude", event="PreToolUse")


def test_is_cairn_hook_entry_rejects_cairn_substring_in_user_cmd():
    """A user hook that merely references 'cairn' in its command must NOT
    be identified as cairn-owned (the bug the substring match caused)."""
    entry = {
        "matcher": "Bash",
        "hooks": [
            {"type": "command", "command": "echo cairn._claude_hook && /bin/false"}
        ],
    }
    assert not _is_cairn_hook_entry(entry, harness="claude", event="PreToolUse")


def test_is_cairn_hook_entry_detects_via_manifest():
    """An entry that doesn't match current commands but is in the manifest
    is detected (handles version changes)."""
    entry = {
        "matcher": "*",
        "hooks": [
            {"type": "command", "command": "python3 -m cairn._old_hook pre", "timeout": 10}
        ],
    }
    manifest = {
        "version": 1,
        "installs": {
            "claude": {
                "hook_hashes": {
                    "PreToolUse": [_compute_entry_hash(entry)]
                }
            }
        },
    }
    assert _is_cairn_hook_entry(
        entry, harness="claude", event="PreToolUse", manifest=manifest
    )


# ----------------------------------------------------------------------
# install-harness hermes
# ----------------------------------------------------------------------


@pytest.fixture
def hermes_home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "hermes-home"
    monkeypatch.setenv("CAIRN_HERMES_HOME", str(home))
    return home


def test_install_hermes_writes_env_and_plugin(cfg, hermes_home):
    result = _install_hermes(cfg, dry_run=False, uninstall=False, user=None)

    assert not result.no_op
    env_path = hermes_home / ".env"
    assert env_path.is_file()
    content = env_path.read_text()
    assert "# BEGIN cairn-harness-managed" in content
    assert "# END cairn-harness-managed" in content
    assert "REGISTA_DSN=postgresql://user:pw@host/db" in content
    assert "CAIRN_PROJECT=test_project" in content
    assert "CAIRN_HARNESS_NAME=hermes" in content

    # Plugin files installed.
    plugin_dir = hermes_home / "plugins" / "observability" / "cairn"
    assert (plugin_dir / "plugin.yaml").is_file()
    assert (plugin_dir / "__init__.py").is_file()


def test_install_hermes_idempotent(cfg, hermes_home):
    _install_hermes(cfg, dry_run=False, uninstall=False, user=None)
    result = _install_hermes(cfg, dry_run=False, uninstall=False, user=None)

    assert result.no_op
    # All actions should be "skip" (already up-to-date).
    assert all(a.kind == "skip" for a in result.actions)


def test_install_hermes_dry_run_does_not_write(cfg, hermes_home):
    result = _install_hermes(cfg, dry_run=True, uninstall=False, user=None)

    assert not result.no_op
    assert len(result.actions) > 0
    assert not (hermes_home / ".env").exists()


def test_install_hermes_no_clobber_existing_env(cfg, hermes_home):
    env_path = hermes_home / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("REGISTA_DSN=postgresql://existing:secret@host/db\n")

    result = _install_hermes(cfg, dry_run=False, uninstall=False, user=None)

    content = env_path.read_text()
    assert "postgresql://existing:secret@host/db" in content
    skip_actions = [a for a in result.actions if a.kind == "skip"]
    assert any("REGISTA_DSN" in a.detail for a in skip_actions)


def test_install_hermes_with_user_principal(cfg, hermes_home):
    result = _install_hermes(cfg, dry_run=False, uninstall=False, user="human:bob")

    content = (hermes_home / ".env").read_text()
    assert "PRINCIPAL_ID=human:bob" in content
    assert result.user == "human:bob"


def test_uninstall_hermes_removes_managed_block(cfg, hermes_home):
    _install_hermes(cfg, dry_run=False, uninstall=False, user=None)

    env_path = hermes_home / ".env"
    # Add a user line outside the managed block.
    content = env_path.read_text()
    env_path.write_text("USER_VAR=keep\n" + content)

    result = _install_hermes(cfg, dry_run=False, uninstall=True, user=None)

    content = env_path.read_text()
    assert "cairn-harness-managed" not in content
    assert "USER_VAR=keep" in content
    assert not result.no_op


def test_uninstall_hermes_removes_plugin(cfg, hermes_home):
    _install_hermes(cfg, dry_run=False, uninstall=False, user=None)

    plugin_dir = hermes_home / "plugins" / "observability" / "cairn"
    assert plugin_dir.is_dir()

    _install_hermes(cfg, dry_run=False, uninstall=True, user=None)

    assert not (plugin_dir / "plugin.yaml").exists()
    assert not (plugin_dir / "__init__.py").exists()


def test_uninstall_hermes_noop_on_clean(cfg, hermes_home):
    result = _install_hermes(cfg, dry_run=False, uninstall=True, user=None)
    assert result.no_op


# ----------------------------------------------------------------------
# run_install_harness (all)
# ----------------------------------------------------------------------


def test_run_install_harness_all(cfg, monkeypatch):
    monkeypatch.setattr("cairn._install.resolve_config", lambda: cfg)
    results = run_install_harness("all", dry_run=True, uninstall=False, user=None)
    assert len(results) == 2
    assert results[0].harness == "claude"
    assert results[1].harness == "opencode"


def test_run_install_harness_all_excludes_private_hermes_target(cfg, monkeypatch):
    monkeypatch.setattr("cairn._install.resolve_config", lambda: cfg)

    results = run_install_harness("all", dry_run=True)

    assert [result.harness for result in results] == ["claude", "opencode"]


def _codex_hooks_file(tmp_path: Path) -> Path:
    return tmp_path / "codex" / "hooks.json"


def test_install_codex_wires_hooks_only_no_env(cfg, tmp_path, monkeypatch):
    from cairn._install import _install_codex

    result = _install_codex(cfg, dry_run=False, uninstall=False, user=None)

    assert result.status is InstallStatus.INSTALLED
    assert result.no_op is False
    data = json.loads(_codex_hooks_file(tmp_path).read_text())
    # All four attested events registered, pointing at cairn's hook entry point.
    assert set(data["hooks"]) == {"SessionStart", "PreToolUse", "PostToolUse", "Stop"}
    cmd = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd == f"{CAIRN_CODEX_HOOK_COMMAND} pre"
    # Tool events carry a matcher; SessionStart/Stop do not.
    assert data["hooks"]["PreToolUse"][0]["matcher"] == "*"
    assert "matcher" not in data["hooks"]["Stop"][0]
    # Decision 6: NO secrets/env are written into Codex config.
    assert "env" not in data


def test_install_codex_idempotent(cfg, tmp_path):
    from cairn._install import _install_codex

    _install_codex(cfg, dry_run=False, uninstall=False, user=None)
    result = _install_codex(cfg, dry_run=False, uninstall=False, user=None)
    assert result.no_op is True


def test_install_codex_dry_run_writes_nothing(cfg, tmp_path):
    from cairn._install import _install_codex

    result = _install_codex(cfg, dry_run=True, uninstall=False, user=None)
    assert result.no_op is False
    assert not _codex_hooks_file(tmp_path).exists()


def test_install_codex_preserves_user_hooks(cfg, tmp_path):
    from cairn._install import _install_codex

    hooks_file = _codex_hooks_file(tmp_path)
    hooks_file.parent.mkdir(parents=True)
    hooks_file.write_text(json.dumps({
        "hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "./scripts/mine.sh"}
        ]}]}
    }))

    _install_codex(cfg, dry_run=False, uninstall=False, user=None)
    data = json.loads(hooks_file.read_text())
    cmds = [h["command"] for e in data["hooks"]["PostToolUse"] for h in e["hooks"]]
    assert "./scripts/mine.sh" in cmds  # user hook preserved
    assert f"{CAIRN_CODEX_HOOK_COMMAND} post" in cmds  # cairn added alongside


def test_uninstall_codex_removes_only_cairn(cfg, tmp_path):
    from cairn._install import _install_codex

    hooks_file = _codex_hooks_file(tmp_path)
    hooks_file.parent.mkdir(parents=True)
    hooks_file.write_text(json.dumps({
        "hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "./scripts/mine.sh"}
        ]}]}
    }))
    _install_codex(cfg, dry_run=False, uninstall=False, user=None)
    result = _install_codex(cfg, dry_run=False, uninstall=True, user=None)

    assert result.no_op is False
    data = json.loads(hooks_file.read_text())
    cmds = [h["command"] for e in data["hooks"].get("PostToolUse", []) for h in e["hooks"]]
    assert cmds == ["./scripts/mine.sh"]  # user hook survives, cairn removed
    assert "SessionStart" not in data["hooks"]  # cairn-only event pruned


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


def test_format_results_unsupported_is_not_noop_success():
    result = InstallResult(harness="codex", status=InstallStatus.UNSUPPORTED)

    out = format_results_human([result], dry_run=False)

    assert "unsupported (not wired)" in out
    assert "no-op" not in out


def test_degraded_result_fails_closed_without_tier_policy():
    from cairn._install import results_succeeded

    result = InstallResult(harness="codex", status=InstallStatus.DEGRADED)

    assert results_succeeded([result]) is False


def test_install_harness_codex_cli_exits_zero_and_wires(cfg, monkeypatch):
    from click.testing import CliRunner

    from cairn._cli import main

    monkeypatch.setattr("cairn._install.resolve_config", lambda: cfg)
    result = CliRunner().invoke(main, ["install-harness", "codex", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["harness"] == "codex"
    assert payload[0]["status"] == "installed"


def test_codex_doctor_validates_direct_wiring(cfg, monkeypatch):
    from cairn._doctor import _check_codex_harness_wired

    _install_codex(cfg, dry_run=False, uninstall=False, user=None)
    monkeypatch.setattr("cairn._doctor._codex_plugin_state", lambda: ("absent", None))

    check = _check_codex_harness_wired(cfg)

    assert check["status"] == "ok"
    assert "direct Codex hooks" in check["detail"]


def test_codex_doctor_rejects_duplicate_direct_and_plugin_wiring(cfg, monkeypatch):
    from cairn._doctor import _check_codex_harness_wired

    _install_codex(cfg, dry_run=False, uninstall=False, user=None)
    monkeypatch.setattr(
        "cairn._doctor._codex_plugin_state", lambda: ("enabled", "0.1.0")
    )

    check = _check_codex_harness_wired(cfg)

    assert check["status"] == "fail"
    assert "duplicate attestations" in check["detail"]


def test_codex_doctor_plugin_ignores_unrelated_direct_hooks(cfg, monkeypatch, tmp_path):
    from cairn._doctor import _check_codex_harness_wired
    from cairn._install import _codex_hooks_path

    hooks_file = _codex_hooks_path()
    hooks_file.parent.mkdir(parents=True)
    hooks_file.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "./my-policy"}],
                        }
                    ]
                }
            }
        )
    )
    monkeypatch.setattr(
        "cairn._doctor._codex_plugin_state", lambda: ("enabled", "0.1.0")
    )

    check = _check_codex_harness_wired(cfg)

    assert check["status"] == "ok"
    assert "plugin" in check["detail"]


def test_codex_doctor_fails_closed_when_selected_but_unwired(monkeypatch):
    from cairn._doctor import _check_codex_harness_wired

    selected = CairnEnvConfig(harness_name="codex")
    monkeypatch.setattr("cairn._doctor._codex_plugin_state", lambda: ("absent", None))

    check = _check_codex_harness_wired(selected)

    assert check["status"] == "fail"
    assert "neither direct" in check["detail"]


def test_codex_doctor_never_claims_machine_readable_hook_trust() -> None:
    from cairn._doctor import _check_codex_hook_trust

    check = _check_codex_hook_trust(wired=True)

    assert check["status"] == "warn"
    assert "/hooks" in check["detail"]
    assert "not exposed" in check["detail"]


def test_codex_doctor_reports_disabled_hooks_feature(monkeypatch) -> None:
    from cairn._doctor import _check_codex_hook_policy

    monkeypatch.setattr("cairn._doctor._codex_hooks_feature_enabled", lambda: False)
    monkeypatch.setattr("cairn._doctor._managed_only_hooks_visible", lambda: False)

    check = _check_codex_hook_policy(wired=True)

    assert check["status"] == "fail"
    assert "disabled" in check["detail"]


def test_codex_doctor_activity_uses_digest_only_marker(monkeypatch, tmp_path):
    from cairn._codex_hook import _record_activity
    from cairn._doctor import _check_codex_activity

    monkeypatch.setenv("CAIRN_STATE_DIR", str(tmp_path / "state"))
    _record_activity("secret-session-id", "SessionStart")

    marker_text = (tmp_path / "state" / "codex-health.json").read_text()
    check = _check_codex_activity(wired=True)

    assert "secret-session-id" not in marker_text
    assert check["status"] == "ok"
    assert "SessionStart" in check["detail"]


def test_codex_doctor_activity_fails_on_degradation(monkeypatch, tmp_path):
    from cairn._claude_hook import _mark_degraded
    from cairn._doctor import _check_codex_activity

    state = tmp_path / "state"
    monkeypatch.setenv("CAIRN_STATE_DIR", str(state))
    _mark_degraded("session-digest", "codex:post", "bridge failure")

    check = _check_codex_activity(wired=True)

    assert check["status"] == "fail"
    assert "degradation" in check["detail"]


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


# ----------------------------------------------------------------------
# Plan 009 WI-1.3: harness version detection at install time
# ----------------------------------------------------------------------


def test_detect_harness_version_claude():
    """When claude is on PATH, _detect_harness_version returns a non-unknown version."""
    version = _detect_harness_version("claude")
    # On a machine with Claude Code installed, this should be a real version.
    # On CI without claude, it returns None — both are acceptable.
    if version is not None:
        assert version != "unknown"
        assert len(version) > 0


def test_detect_harness_version_unknown_harness():
    """An unsupported harness name returns None."""
    assert _detect_harness_version("aider") is None


def test_install_claude_detects_version_when_unknown(
    cfg: CairnEnvConfig, claude_settings: Path
) -> None:
    """WI-1.3: when harness_version is 'unknown', install-harness detects
    the real version and records it into the env block."""
    cfg_unknown = CairnEnvConfig(
        dsn=cfg.dsn,
        key_path=cfg.key_path,
        key_ref=None,
        project=cfg.project,
        harness_name="claude-code",
        harness_version="unknown",
        principal_id=cfg.principal_id,
        state_dir=cfg.state_dir,
        disabled=False,
    )
    _install_claude(cfg_unknown, dry_run=False, uninstall=False, user=None)
    data = json.loads(claude_settings.read_text())
    env = data.get("env", {})
    # If claude is installed, version should be detected and non-unknown.
    # If not installed, version stays absent (not set to "unknown").
    hv = env.get("CAIRN_HARNESS_VERSION")
    if hv is not None:
        assert hv != "unknown"


# ----------------------------------------------------------------------
# Plan 009 WI-4.1: attestation freshness — silence is a finding
# ----------------------------------------------------------------------


def _configured_cfg() -> CairnEnvConfig:
    return CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path="/nonexistent.json",
        project="test",
    )


def _doctor_module():
    import cairn._doctor as mod

    return mod


def _make_transcript(base, session_id: str, age_secs: float) -> None:
    """Write a fake session transcript with a given age."""
    import time

    proj = base / "-home-operator-work"
    proj.mkdir(parents=True, exist_ok=True)
    f = proj / f"{session_id}.jsonl"
    f.write_text("{}\n")
    ts = time.time() - age_secs
    os.utime(f, (ts, ts))


def _probe(
    *,
    session_attested: dict[str, object] | None = None,
    scoped: bool = True,
    newest_event_ts: object = None,
    unattributed_at: object = None,
):
    """Build a store probe the way ``_check_regista`` would."""
    from cairn._doctor import _StoreProbe

    return _StoreProbe(
        newest_event_ts=newest_event_ts,
        session_attested=dict(session_attested or {}),
        unattributed_at=unattributed_at,
        session_scoped=scoped,
    )


def _ago(**kwargs):
    import datetime

    return datetime.datetime.now(datetime.UTC) - datetime.timedelta(**kwargs)


def test_freshness_skips_when_not_configured(monkeypatch, tmp_path):
    from cairn._doctor import _check_attestation_freshness

    cfg = CairnEnvConfig(dsn=None, key_path=None, project=None)
    result = _check_attestation_freshness(
        cfg, _probe(), regista_ok=False, harnesses=["claude"]
    )
    assert result["status"] == "skip"


def test_freshness_skips_when_regista_unreachable(monkeypatch, tmp_path):
    """Regista down already reds out its own check — freshness must not
    pile a misleading 'silent' failure on top."""
    from cairn._doctor import _check_attestation_freshness

    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=False, harnesses=["claude"]
    )
    assert result["status"] == "skip"
    assert "unreachable" in result["detail"]


def test_freshness_skips_when_no_harness_is_wired(monkeypatch, tmp_path):
    """Nothing is expected to attest, so there is nothing to be silent about."""
    from cairn._doctor import _check_attestation_freshness

    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=[]
    )
    assert result["status"] == "skip"
    assert "no harness is wired" in result["detail"]


def test_freshness_skips_when_the_session_query_did_not_run(monkeypatch, tmp_path):
    """An unexamined store is not a fresh one (the WI-223 lesson)."""
    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=60)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(scoped=False), regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "skip"
    assert "unknown" in result["detail"]


def test_freshness_ok_when_no_recent_sessions(monkeypatch, tmp_path):
    """Old transcripts only (predating the window) — nothing demanded an
    attestation, so silence is fine."""
    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "old-session", age_secs=3 * 24 * 3600)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "ok"
    assert "no sessions ran" in result["detail"]


def test_freshness_ok_with_recent_session_attestation(monkeypatch, tmp_path):
    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=60)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))
    result = _check_attestation_freshness(
        _configured_cfg(),
        _probe(session_attested={"claude-code": _ago(minutes=5)}),
        regista_ok=True,
        harnesses=["claude"],
    )
    assert result["status"] == "ok"


def test_freshness_ignores_non_session_attestation(monkeypatch, tmp_path):
    """THE WI-034 REGRESSION.

    On the real estate the 400 most recent events were all
    ``entity_kind=work_item`` — ``tool_call_begin``/``end`` written in-process
    by agent-notes attesting its own operations — and ZERO were session events.
    That satisfied the old check, which asked only whether ANY attestation had
    landed, so "every Claude Code session on this host is unattested" read as
    ``ok``. A store full of work-item events must not satisfy freshness.
    """
    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=60)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))

    # Plenty of very recent activity in the store — none of it session-scoped.
    probe = _probe(newest_event_ts=_ago(seconds=30), session_attested={})

    result = _check_attestation_freshness(
        _configured_cfg(), probe, regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "fail", result
    assert "configured but silent" in result["detail"]


def test_freshness_is_scoped_per_harness(monkeypatch, tmp_path):
    """An unhooked Claude behind a working OpenCode must not read green.

    The old check aggregated across harnesses, so one harness's attestation
    covered for another's total silence (WI-034).
    """
    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=60)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))

    probe = _probe(session_attested={"opencode": _ago(minutes=2)})
    result = _check_attestation_freshness(
        _configured_cfg(), probe, regista_ok=True, harnesses=["claude", "opencode"]
    )
    assert result["status"] == "fail", result
    assert "claude" in result["detail"]


def test_freshness_does_not_credit_an_unattributed_attestation(monkeypatch, tmp_path):
    """A session attestation naming no harness cannot cover for one."""
    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=60)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))

    probe = _probe(unattributed_at=_ago(minutes=1))
    result = _check_attestation_freshness(
        _configured_cfg(), probe, regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "fail", result
    assert "names no harness" in result["detail"]


def test_freshness_warns_for_a_harness_with_no_local_signal(monkeypatch, tmp_path):
    """cairn cannot see whether OpenCode ran, so silence is a warning — not ok,
    which would be the same fail-open move, and not fail, which would cry wolf
    on a harness nobody used."""
    from cairn._doctor import _check_attestation_freshness

    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path / "empty"))
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["opencode"]
    )
    assert result["status"] == "warn"
    assert "no local signal" in result["detail"]


def test_freshness_ok_without_local_claude_transcripts(monkeypatch, tmp_path):
    """An existing but empty transcript store is what an unused Claude looks like."""
    from cairn._doctor import _check_attestation_freshness

    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(empty))
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "ok"
    assert "no sessions ran" in result["detail"]


def test_freshness_will_not_read_an_unreadable_store_as_disuse(monkeypatch, tmp_path):
    """WI-039: a RELOCATED transcript directory is a check that cannot look.

    Pre-fix, a ``~/.claude/projects`` that was not where cairn looked returned
    "no sessions ran" and the check reported ``ok`` — a verdict about input it
    never saw.  It must say it has no signal instead.
    """
    from cairn._doctor import _check_attestation_freshness

    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path / "moved-away"))
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "warn", result
    assert "could not read" in result["detail"]
    assert "has not established disuse" in result["detail"]
    assert "no sessions ran" not in result["detail"]


def test_freshness_names_the_blind_spot_for_harnesses_without_a_signal(monkeypatch, tmp_path):
    """The honest answer for OpenCode/Codex: say what cannot be distinguished.

    WI-039 accepts "the check admits its blind spot" as the fix.  What it must
    not do is imply it looked: the detail names the two cases it cannot tell
    apart, and how to give the check a signal.
    """
    from cairn._doctor import _check_attestation_freshness

    for harness, env_name in (("opencode", "CAIRN_OPENCODE_SESSIONS"),
                              ("codex", "CAIRN_CODEX_SESSIONS")):
        result = _check_attestation_freshness(
            _configured_cfg(), _probe(), regista_ok=True, harnesses=[harness]
        )
        assert result["status"] == "warn", result
        assert "no local signal" in result["detail"]
        assert "'ran and did not attest' from 'did not run'" in result["detail"]
        assert env_name in result["detail"]


def test_freshness_uses_an_operator_declared_signal_for_opencode(monkeypatch, tmp_path):
    """An operator who knows the layout can give the check eyes.

    With ``CAIRN_OPENCODE_SESSIONS`` pointing at OpenCode's own session store, a
    session that provably ran and did not attest becomes a FAIL rather than the
    warning cairn has to settle for when it cannot see anything.
    """
    from cairn._doctor import _check_attestation_freshness

    store = tmp_path / "opencode-sessions"
    _make_transcript(store, "recent-opencode-session", age_secs=60)
    monkeypatch.setenv("CAIRN_OPENCODE_SESSIONS", str(store))

    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["opencode"]
    )
    assert result["status"] == "fail", result
    assert "configured and silent" in result["detail"]

    # And an old session in that same store demands nothing.
    store2 = tmp_path / "opencode-old"
    _make_transcript(store2, "old-session", age_secs=3 * 24 * 3600)
    monkeypatch.setenv("CAIRN_OPENCODE_SESSIONS", str(store2))
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["opencode"]
    )
    assert result["status"] == "ok", result


def test_freshness_stale_session_attestation_is_not_fresh(monkeypatch, tmp_path):
    """An attestation older than the window is outside the probe's query, so
    the harness reads as silent."""
    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=60)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))
    # _probe_session_attestation only ever records events inside the window;
    # an empty map with a scoped query therefore means "nothing recent".
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "fail"


def test_freshness_window_configurable(monkeypatch, tmp_path):
    """CAIRN_MAX_ATTESTATION_AGE_HOURS narrows or widens the window."""
    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=2 * 3600)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))

    # Default 24h window: the session ran inside it and nothing attested.
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "fail"

    # 1h window: the session ran 2h ago, outside it — nothing to demand.
    monkeypatch.setenv("CAIRN_MAX_ATTESTATION_AGE_HOURS", "1")
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "ok"

    # An unparseable value falls back to the 24h default rather than 0.
    monkeypatch.setenv("CAIRN_MAX_ATTESTATION_AGE_HOURS", "not-a-number")
    result = _check_attestation_freshness(
        _configured_cfg(), _probe(), regista_ok=True, harnesses=["claude"]
    )
    assert result["status"] == "fail"


def test_session_probe_only_counts_session_entity_events():
    """``_probe_session_attestation`` must reject work-item events outright."""
    import datetime
    import uuid

    from cairn._doctor import _probe_session_attestation, _StoreProbe

    now = datetime.datetime.now(datetime.UTC)

    class _Ev:
        def __init__(self, entity_kind, payload):
            self.entity_kind = entity_kind
            self.payload = payload
            self.timestamp = now
            self.event_id = uuid.uuid4()

    class _Sub:
        def read_events(self, **kwargs):
            assert kwargs["transition"] == "session_attestation"
            assert kwargs["start"] is not None and kwargs["end"] is not None
            return [
                # A work-item event that happens to share the transition name.
                _Ev("work_item", {"harnesses": [{"name": "claude-code"}]}),
                _Ev("session", {"harnesses": [{"name": "OpenCode", "version": "1"}]}),
            ]

    probe = _StoreProbe()
    _probe_session_attestation(_Sub(), probe)
    assert probe.session_scoped is True
    assert set(probe.session_attested) == {"opencode"}


def test_session_probe_leaves_scope_false_when_the_query_fails():
    """A store that cannot answer the scoped query must not look attested."""
    from cairn._doctor import _probe_session_attestation, _StoreProbe

    class _Sub:
        def read_events(self, **kwargs):
            raise RuntimeError("filter not supported")

    probe = _StoreProbe()
    _probe_session_attestation(_Sub(), probe)
    assert probe.session_scoped is False
    assert probe.session_attested == {}


def test_doctor_includes_freshness_check(monkeypatch, tmp_path):
    """run_doctor emits the attestation_freshness check in its report."""
    import io
    import json as _json
    from contextlib import redirect_stdout

    monkeypatch.setattr(
        "cairn._doctor.resolve_config",
        lambda: CairnEnvConfig(dsn=None, key_path=None, project=None),
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_doctor(json_output=True)
    report = _json.loads(buf.getvalue())
    names = [c["name"] for c in report["checks"]]
    assert "attestation_freshness" in names


def test_install_wires_subagent_and_compact_hooks(tmp_path, monkeypatch):
    """Plan 009 WI-3.1: install-harness wires SubagentStart/SubagentStop/
    PostCompact (and NOT PostToolBatch — per-call attestation covers it)."""
    from cairn._install import HOOK_EVENTS

    assert HOOK_EVENTS["SubagentStart"] == "subagent-start"
    assert HOOK_EVENTS["SubagentStop"] == "subagent-stop"
    assert HOOK_EVENTS["PostCompact"] == "post-compact"
    assert "PostToolBatch" not in HOOK_EVENTS


# ----------------------------------------------------------------------
# ConfigLoadError — refuse to clobber unreadable/invalid JSON
# ----------------------------------------------------------------------


def test_load_json_returns_empty_for_missing_file(tmp_path: Path):
    assert _load_json(tmp_path / "nonexistent.json") == {}


def test_load_json_raises_on_invalid_json(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json")
    with pytest.raises(ConfigLoadError, match="invalid JSON"):
        _load_json(path)


def test_load_json_raises_on_non_dict_json(tmp_path: Path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]")
    with pytest.raises(ConfigLoadError, match="expected JSON object"):
        _load_json(path)


def test_install_claude_fails_on_invalid_json(cfg, claude_settings):
    """Install must NOT clobber a file with invalid JSON."""
    original_content = "{broken"
    claude_settings.write_text(original_content)

    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    assert result.status is InstallStatus.FAILED
    # File must be unchanged.
    assert claude_settings.read_text() == original_content


def test_install_codex_fails_on_invalid_json(cfg, tmp_path):
    """Codex install must NOT clobber a file with invalid JSON."""
    from cairn._install import _codex_hooks_path

    hooks_file = _codex_hooks_path()
    hooks_file.parent.mkdir(parents=True, exist_ok=True)
    original_content = "{broken"
    hooks_file.write_text(original_content)

    result = _install_codex(cfg, dry_run=False, uninstall=False, user=None)

    assert result.status is InstallStatus.FAILED
    assert hooks_file.read_text() == original_content


def test_install_claude_uninstall_fails_on_invalid_json(cfg, claude_settings):
    """Uninstall must also refuse to touch an unreadable config."""
    original_content = "{broken"
    claude_settings.write_text(original_content)

    result = _install_claude(cfg, dry_run=False, uninstall=True, user=None)

    assert result.status is InstallStatus.FAILED
    assert claude_settings.read_text() == original_content


# ----------------------------------------------------------------------
# Manifest — hash-based ownership (Plan 011 WI-3.1)
# ----------------------------------------------------------------------


def test_manifest_records_installed_hooks(cfg, claude_settings):
    """After install, the manifest contains hashes for every hook event."""
    _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    manifest = _load_manifest()
    claude_install = manifest["installs"]["claude"]
    hook_hashes = claude_install["hook_hashes"]
    for event in [
        "PreToolUse", "PostToolUse", "SessionStart", "SessionEnd",
        "Stop", "PostToolUseFailure", "MessageDisplay",
        "SubagentStart", "SubagentStop", "PostCompact",
    ]:
        assert event in hook_hashes
        assert len(hook_hashes[event]) == 1
        assert hook_hashes[event][0].startswith("sha256:")


def test_uninstall_via_manifest_removes_hook_after_command_change(
    cfg, claude_settings, monkeypatch
):
    """When cairn's command format changes between versions, uninstall
    still removes old hooks via the manifest — the old entry's hash is
    in the manifest even though the current expected entry differs."""
    _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    # Simulate a version change: cairn now generates a different command.
    monkeypatch.setattr("cairn._install.CAIRN_HOOK_COMMAND", "python3 -m cairn._new_hook")

    # Uninstall should still find and remove the old hooks via the manifest.
    result = _install_claude(cfg, dry_run=False, uninstall=True, user=None)

    assert not result.no_op
    data = json.loads(claude_settings.read_text()) if claude_settings.exists() else {}
    assert "hooks" not in data or not data.get("hooks")


def test_uninstall_preserves_hook_with_cairn_substring(cfg, claude_settings):
    """A user-authored hook that merely references 'cairn' in its command
    must survive uninstall (the substring match bug)."""
    user_hook = {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": "echo cairn._claude_hook && /bin/true",
                "timeout": 5,
            }
        ],
    }
    existing = {"hooks": {"PreToolUse": [user_hook]}}
    claude_settings.write_text(json.dumps(existing))

    result = _uninstall_claude(
        claude_settings, json.loads(claude_settings.read_text()),
        dry_run=False, result=InstallResult(harness="claude"),
    )
    assert result.no_op  # nothing to remove — user hook is not cairn-owned

    data = json.loads(claude_settings.read_text())
    pre_hooks = data.get("hooks", {}).get("PreToolUse", [])
    assert len(pre_hooks) == 1
    assert pre_hooks[0]["hooks"][0]["command"] == "echo cairn._claude_hook && /bin/true"


def test_uninstall_codex_preserves_hook_with_cairn_substring(cfg, tmp_path):
    """Same substring safety for Codex hooks."""
    hooks_file = _codex_hooks_file(tmp_path)
    hooks_file.parent.mkdir(parents=True)
    user_hook = {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": "echo cairn._codex_hook && /bin/true",
                "timeout": 5,
            }
        ],
    }
    hooks_file.write_text(json.dumps({"hooks": {"PreToolUse": [user_hook]}}))

    result = _uninstall_codex(
        hooks_file, json.loads(hooks_file.read_text()),
        dry_run=False, result=InstallResult(harness="codex"),
    )
    assert result.no_op

    data = json.loads(hooks_file.read_text())
    pre_hooks = data.get("hooks", {}).get("PreToolUse", [])
    assert len(pre_hooks) == 1
    assert "echo cairn._codex_hook" in pre_hooks[0]["hooks"][0]["command"]


# ----------------------------------------------------------------------
# Adversarial review round 1 hardening
# ----------------------------------------------------------------------


def test_load_manifest_treats_corrupt_installs_as_empty(tmp_path, monkeypatch):
    """A manifest with a non-dict 'installs' must be reset, not crash."""
    manifest_path = tmp_path / "manifest.json"
    monkeypatch.setenv("CAIRN_MANIFEST_PATH", str(manifest_path))
    manifest_path.write_text(json.dumps({"version": 1, "installs": "corrupt"}))

    manifest = _load_manifest()
    assert manifest == {"version": 1, "installs": {}}


def test_is_cairn_hook_entry_rejects_evil_cairn_hook_py():
    """A user script named evil_cairn_hook.py must NOT be detected as
    cairn-owned (the former endswith fallback was too broad)."""
    entry = {
        "matcher": "*",
        "hooks": [
            {"type": "command", "command": "python3 /home/user/evil_cairn_hook.py pre"}
        ],
    }
    assert not _is_cairn_hook_entry(entry, harness="claude", event="PreToolUse")


def test_is_cairn_hook_entry_returns_false_for_non_dict():
    """Defense-in-depth: non-dict entries don't crash."""
    assert not _is_cairn_hook_entry("not-a-dict", harness="claude", event="PreToolUse")  # type: ignore[arg-type]
    assert not _is_cairn_hook_entry(None, harness="claude", event="PreToolUse")  # type: ignore[arg-type]


def test_install_claude_handles_non_dict_hook_entries(cfg, claude_settings):
    """Claude install must not crash on malformed hook entries (non-dict)."""
    existing = {"hooks": {"PreToolUse": ["not-a-dict", 42]}}
    claude_settings.write_text(json.dumps(existing))

    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    assert result.status is InstallStatus.INSTALLED
    data = json.loads(claude_settings.read_text())
    pre_hooks = data["hooks"]["PreToolUse"]
    # Non-dict entries preserved, cairn hook appended.
    assert "not-a-dict" in pre_hooks
    assert any(
        isinstance(e, dict) and _is_cairn_hook_entry(e, harness="claude", event="PreToolUse")
        for e in pre_hooks
    )


def test_install_claude_coerces_non_dict_env_and_hooks(cfg, claude_settings):
    """Claude install must not crash when env/hooks are wrong type."""
    existing = {"env": "not-a-dict", "hooks": "also-not-a-dict"}
    claude_settings.write_text(json.dumps(existing))

    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    assert result.status is InstallStatus.INSTALLED
    data = json.loads(claude_settings.read_text())
    assert isinstance(data["env"], dict)
    assert isinstance(data["hooks"], dict)
    assert "REGISTA_DSN" in data["env"]


def test_install_opencode_fails_on_invalid_json(cfg, tmp_path, monkeypatch):
    """OpenCode install must NOT clobber a file with invalid JSON."""
    from cairn._install import _install_opencode

    path = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(path))
    original_content = "{broken"
    path.write_text(original_content)

    result = _install_opencode(cfg, dry_run=False, uninstall=False, user=None)

    assert result.status is InstallStatus.FAILED
    assert path.read_text() == original_content


# ----------------------------------------------------------------------
# Adversarial review round 2 hardening
# ----------------------------------------------------------------------


def test_install_claude_coerces_non_list_event_hooks(cfg, claude_settings):
    """Claude install must not crash when event hook list is wrong type."""
    existing = {"hooks": {"PreToolUse": "not-a-list"}}
    claude_settings.write_text(json.dumps(existing))

    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    assert result.status is InstallStatus.INSTALLED
    data = json.loads(claude_settings.read_text())
    assert isinstance(data["hooks"]["PreToolUse"], list)


def test_uninstall_claude_handles_non_dict_hooks_and_env(cfg, claude_settings):
    """Claude uninstall must not crash on non-dict hooks/env."""
    existing = {"hooks": "not-a-dict", "env": "also-not-a-dict"}
    claude_settings.write_text(json.dumps(existing))

    result = _uninstall_claude(
        claude_settings, json.loads(claude_settings.read_text()),
        dry_run=False, result=InstallResult(harness="claude"),
    )

    assert result.no_op  # nothing to remove in malformed config


def test_install_opencode_coerces_non_dict_env(cfg, tmp_path, monkeypatch):
    """OpenCode install must not crash when env is wrong type."""
    from cairn._install import _install_opencode

    path = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(path))
    path.write_text(json.dumps({"env": "not-a-dict"}))

    result = _install_opencode(cfg, dry_run=False, uninstall=False, user=None)

    assert result.status is InstallStatus.INSTALLED
    data = json.loads(path.read_text())
    assert isinstance(data["env"], dict)
    assert "REGISTA_DSN" in data["env"]


def test_load_manifest_validates_per_harness_structure(tmp_path, monkeypatch):
    """A manifest with a non-dict per-harness value is cleaned up, not crashed."""
    manifest_path = tmp_path / "manifest.json"
    monkeypatch.setenv("CAIRN_MANIFEST_PATH", str(manifest_path))
    manifest_path.write_text(json.dumps({
        "version": 1,
        "installs": {
            "claude": "corrupt",
            "codex": {"hook_hashes": "also-corrupt"},
        }
    }))

    manifest = _load_manifest()
    assert "claude" not in manifest["installs"]
    assert manifest["installs"]["codex"]["hook_hashes"] == {}


def test_doctor_handles_non_dict_hooks(monkeypatch, tmp_path):
    """Doctor must not crash on non-dict hooks in settings.json."""
    monkeypatch.setenv("CAIRN_CLAUDE_SETTINGS", str(tmp_path / "claude.json"))
    settings_path = tmp_path / "claude.json"
    settings_path.write_text(json.dumps({"hooks": "not-a-dict", "env": "also-not"}))
    monkeypatch.setattr(
        "cairn._doctor.resolve_config",
        lambda: CairnEnvConfig(dsn=None, key_path=None, project=None),
    )

    exit_code = run_doctor(json_output=True)
    assert exit_code == 1  # fails because config is not set up, but doesn't crash


def test_load_manifest_cleans_non_list_hook_hashes_event(tmp_path, monkeypatch):
    """A manifest with a non-list hook_hashes[event] value is cleaned up."""
    manifest_path = tmp_path / "manifest.json"
    monkeypatch.setenv("CAIRN_MANIFEST_PATH", str(manifest_path))
    manifest_path.write_text(json.dumps({
        "version": 1,
        "installs": {
            "claude": {
                "hook_hashes": {"PreToolUse": "not-a-list"}
            }
        }
    }))

    manifest = _load_manifest()
    hh = manifest["installs"]["claude"]["hook_hashes"]
    assert "PreToolUse" not in hh


def test_save_json_sets_restrictive_permissions(tmp_path):
    """_save_json creates files with 0o600 permissions."""
    import stat

    from cairn._install import _save_json

    path = tmp_path / "test.json"
    _save_json(path, {"key": "value"})
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_save_json_preserves_restrictive_permissions_on_overwrite(tmp_path):
    """_save_json maintains 0o600 on every write, not just new files."""
    import stat

    from cairn._install import _save_json

    path = tmp_path / "test.json"
    _save_json(path, {"key": "value1"})
    _save_json(path, {"key": "value2"})
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


# ----------------------------------------------------------------------
# Adversarial review round 5 hardening
# ----------------------------------------------------------------------


def test_load_json_raises_on_non_utf8_file(tmp_path):
    """Binary/non-UTF-8 config files must raise ConfigLoadError, not crash."""
    path = tmp_path / "bad.json"
    path.write_bytes(b"\xff\xfe{not valid")
    with pytest.raises(ConfigLoadError, match="unreadable"):
        _load_json(path)


def test_is_cairn_hook_entry_handles_malformed_hooks_field():
    """Entries with non-list hooks or non-dict hook items don't crash."""
    assert not _is_cairn_hook_entry(
        {"hooks": "not-a-list"}, harness="claude", event="PreToolUse"
    )
    assert not _is_cairn_hook_entry(
        {"hooks": None}, harness="claude", event="PreToolUse"
    )
    assert not _is_cairn_hook_entry(
        {"hooks": [None, "string", 42]}, harness="claude", event="PreToolUse"
    )


def test_load_manifest_normalizes_null_hook_hashes(tmp_path, monkeypatch):
    """A manifest with hook_hashes: null is normalized, not crashed."""
    manifest_path = tmp_path / "manifest.json"
    monkeypatch.setenv("CAIRN_MANIFEST_PATH", str(manifest_path))
    manifest_path.write_text(json.dumps({
        "version": 1,
        "installs": {"claude": {"hook_hashes": None}}
    }))

    manifest = _load_manifest()
    assert manifest["installs"]["claude"]["hook_hashes"] == {}


def test_parse_env_file_handles_unreadable_file(tmp_path):
    """Hermes .env read failures are swallowed, not crashed."""
    from cairn._install import _parse_env_file

    path = tmp_path / "unreadable.env"
    path.write_text("KEY=val\n")
    path.chmod(0o000)
    try:
        assert _parse_env_file(path) == []
    finally:
        path.chmod(0o600)


# ----------------------------------------------------------------------
# OpenCode plugin discovery + default-on session attestation
# ----------------------------------------------------------------------


def test_find_opencode_plugin_in_wheel_layout(monkeypatch, tmp_path):
    """In a built wheel, integrations/ lives inside the cairn package dir."""
    fake_pkg = tmp_path / "site" / "cairn"
    fake_pkg.mkdir(parents=True)
    plugin = fake_pkg / "integrations" / "opencode" / "index.js"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("// fake wheel-bundled plugin")
    monkeypatch.setattr("cairn._install.__file__", str(fake_pkg / "_install.py"))

    found = _find_opencode_plugin()
    assert found == plugin


def test_find_opencode_plugin_falls_back_to_repo_root(monkeypatch, tmp_path):
    """In a source checkout, integrations/ is at the repo root."""
    fake_pkg = tmp_path / "src" / "cairn"
    fake_pkg.mkdir(parents=True)
    repo_root = tmp_path
    plugin = repo_root / "integrations" / "opencode" / "index.js"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("// fake repo-root plugin")
    monkeypatch.setattr("cairn._install.__file__", str(fake_pkg / "_install.py"))

    found = _find_opencode_plugin()
    assert found == plugin


def test_find_opencode_plugin_returns_none_when_absent(monkeypatch, tmp_path):
    """When neither wheel nor repo-root layout has the plugin, report None."""
    fake_pkg = tmp_path / "src" / "cairn"
    fake_pkg.mkdir(parents=True)
    monkeypatch.setattr("cairn._install.__file__", str(fake_pkg / "_install.py"))
    assert _find_opencode_plugin() is None


def test_install_opencode_sets_attest_on_start_default(cfg, tmp_path, monkeypatch):
    """OpenCode session attestation is default-on (CAIRN_ATTEST_ON_START=1)."""
    path = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(path))

    result = _install_opencode(cfg, dry_run=False, uninstall=False, user=None)

    data = json.loads(path.read_text())
    assert data["env"]["CAIRN_ATTEST_ON_START"] == "1"
    assert result.status is InstallStatus.INSTALLED


def test_install_opencode_respects_explicit_attest_on_start(
    cfg, tmp_path, monkeypatch
):
    """An explicit CAIRN_ATTEST_ON_START value is not clobbered."""
    path = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(path))
    path.write_text(json.dumps({"env": {"CAIRN_ATTEST_ON_START": "0"}}))

    result = _install_opencode(cfg, dry_run=False, uninstall=False, user=None)

    data = json.loads(path.read_text())
    assert data["env"]["CAIRN_ATTEST_ON_START"] == "0"
    skip_actions = [a for a in result.actions if a.kind == "skip"]
    assert any("CAIRN_ATTEST_ON_START" in a.detail for a in skip_actions)


def test_uninstall_opencode_removes_attest_on_start(cfg, tmp_path, monkeypatch):
    """Uninstall removes the managed CAIRN_ATTEST_ON_START env var."""
    path = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(path))
    _install_opencode(cfg, dry_run=False, uninstall=False, user=None)

    result = _install_opencode(cfg, dry_run=False, uninstall=True, user=None)

    data = json.loads(path.read_text()) if path.exists() else {}
    assert "CAIRN_ATTEST_ON_START" not in data.get("env", {})
    assert not result.no_op


# ----------------------------------------------------------------------
# Doctor — OpenCode wiring and regista chain integrity
# ----------------------------------------------------------------------


def _doctor_report(monkeypatch, cfg: CairnEnvConfig) -> dict[str, object]:
    """Run doctor --json and return the parsed report."""
    import io
    from contextlib import redirect_stdout

    monkeypatch.setattr("cairn._doctor.resolve_config", lambda: cfg)
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_doctor(json_output=True)
    return json.loads(buf.getvalue())


def _record_integrity(monkeypatch, cfg: CairnEnvConfig) -> int:
    """Run ``cairn integrity`` so doctor has a recorded verdict (WI-030)."""
    import io
    from contextlib import redirect_stdout

    from cairn._doctor import run_integrity

    monkeypatch.setattr("cairn._doctor.resolve_config", lambda: cfg)
    buf = io.StringIO()
    with redirect_stdout(buf):
        return run_integrity(json_output=True)


def test_doctor_opencode_wired_ok(cfg, monkeypatch, tmp_path):
    """Doctor reports ok when OpenCode config has the cairn plugin + env."""
    path = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(path))
    _install_opencode(cfg, dry_run=False, uninstall=False, user=None)

    check = _check_opencode_harness_wired(cfg)

    assert check["status"] == "ok"
    assert "plugin + env configured" in check["detail"]


def test_doctor_opencode_selected_but_unwired(cfg, monkeypatch, tmp_path):
    """Doctor fails closed when OpenCode is selected but no config exists."""
    path = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(path))
    selected = CairnEnvConfig(
        dsn=cfg.dsn,
        key_path=cfg.key_path,
        project=cfg.project,
        harness_name="opencode",
    )

    check = _check_opencode_harness_wired(selected)

    assert check["status"] == "fail"
    assert "no config file" in check["detail"]


def test_doctor_opencode_config_exists_but_plugin_missing(
    cfg, monkeypatch, tmp_path
):
    """Doctor fails closed when config file exists but cairn plugin is absent."""
    path = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(path))
    path.write_text(json.dumps({"env": {"REGISTA_DSN": "x", "CAIRN_PROJECT": "p"}}))
    selected = CairnEnvConfig(
        dsn=cfg.dsn,
        key_path=cfg.key_path,
        project=cfg.project,
        harness_name="opencode",
    )

    check = _check_opencode_harness_wired(selected)

    assert check["status"] == "fail"
    assert "not registered" in check["detail"]


def test_doctor_opencode_skips_when_not_configured(cfg, monkeypatch, tmp_path):
    """Doctor skips the OpenCode check when no config file exists."""
    path = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(path))
    check = _check_opencode_harness_wired(cfg)
    assert check["status"] == "skip"


def test_doctor_chain_ok_verified_when_integrity_recorded_clean(monkeypatch, tmp_path):
    """regista.chain_ok is True when `cairn integrity` recorded a clean replay."""
    from regista import ReplayReport

    class _FakeRegista:
        def __init__(self, **kwargs):
            pass

        def read_events(self, **kwargs):
            return []

        def replay(self, **kwargs):
            # A clean replay that also VERIFIED principal binding: post-WI-036
            # cairn only records "verified" when the binding check actually ran.
            assert kwargs.get("verify_principal_binding") is True
            return ReplayReport(
                table_name="test",
                replayed_ok=1,
                replayed_drift=0,
                halted=0,
                warnings=0,
                principal_binding_verified=True,
            )

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path="/nonexistent.json",
        project="test",
        state_dir=str(tmp_path / "state"),
        integrity_dir=str(tmp_path / "integrity"),
    )
    assert _record_integrity(monkeypatch, cfg) == 0
    report = _doctor_report(monkeypatch, cfg)
    assert report["regista"]["reachable"] is True
    assert report["regista"]["chain_ok"] is True
    assert report["regista"]["chain_state"] == "verified"


def test_doctor_chain_ok_false_when_integrity_recorded_drift(monkeypatch, tmp_path):
    """regista.chain_ok is False when the recorded replay detected drift."""
    from regista import ReplayReport

    class _FakeRegista:
        def __init__(self, **kwargs):
            pass

        def read_events(self, **kwargs):
            return []

        def replay(self, **kwargs):
            return ReplayReport(
                table_name="test",
                replayed_ok=0,
                replayed_drift=1,
                halted=0,
                warnings=0,
            )

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path="/nonexistent.json",
        project="test",
        state_dir=str(tmp_path / "state"),
        integrity_dir=str(tmp_path / "integrity"),
    )
    assert _record_integrity(monkeypatch, cfg) == 1
    report = _doctor_report(monkeypatch, cfg)
    assert report["regista"]["chain_ok"] is False
    assert report["regista"]["chain_state"] == "drift"


def test_doctor_chain_state_unsupported_when_replay_missing(monkeypatch, tmp_path):
    """If regista has no replay API, the recorded state is unsupported."""
    class _FakeRegista:
        def __init__(self, **kwargs):
            pass

        def read_events(self, **kwargs):
            return []

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path="/nonexistent.json",
        project="test",
        state_dir=str(tmp_path / "state"),
        integrity_dir=str(tmp_path / "integrity"),
    )
    assert _record_integrity(monkeypatch, cfg) == 1
    report = _doctor_report(monkeypatch, cfg)
    assert report["regista"]["chain_ok"] is None
    assert report["regista"]["chain_state"] == "unsupported"


def test_doctor_chain_state_error_when_replay_raises(monkeypatch, tmp_path):
    """A replay exception records no verdict: integrity exits 1 and doctor
    honestly reports never_run rather than a chain verdict (WI-030 m4)."""
    class _FakeRegista:
        def __init__(self, **kwargs):
            pass

        def read_events(self, **kwargs):
            return []

        def replay(self, **kwargs):
            raise RuntimeError("replay unavailable")

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path="/nonexistent.json",
        project="test",
        state_dir=str(tmp_path / "state"),
        integrity_dir=str(tmp_path / "integrity"),
    )
    assert _record_integrity(monkeypatch, cfg) == 1
    report = _doctor_report(monkeypatch, cfg)
    assert report["regista"]["chain_ok"] is None
    assert report["regista"]["chain_state"] == "never_run"


@pytest.fixture
def doctor_ready_cfg(cfg, monkeypatch, tmp_path):
    """A config whose other doctor checks pass so chain behavior is isolated."""
    import sys

    key_path = Path(cfg.key_path)
    key_path.write_text(json.dumps({"keys": [{"key_id": "doctor-test"}]}))
    _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    # Put cairn's console scripts on PATH: doctor now warns when the hook it
    # found is runnable only via cairn's own entry-point directory, and a
    # real harness session has that directory on PATH (WI-033/WI-034).
    monkeypatch.setenv(
        "PATH", f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"
    )
    # No local session activity for any harness, deterministically: without this
    # the freshness check reads the OPERATOR's real ~/.claude/projects and these
    # chain-focused tests fail on whatever the host happened to be doing.
    monkeypatch.setattr(
        "cairn._doctor._harness_local_activity",
        lambda harness, window_secs: _doctor_module()._LocalActivity(
            False, f"{harness} test stub: no local sessions"
        ),
    )
    monkeypatch.setattr(
        "cairn._doctor._check_content_encryption",
        lambda cfg: {"name": "content_encryption", "status": "ok", "detail": "test"},
    )
    monkeypatch.setattr(
        "cairn._doctor._check_bridge",
        lambda: {"name": "bridge", "status": "ok", "detail": "test"},
    )
    monkeypatch.setattr(
        "cairn._doctor._check_codex_harness_wired",
        lambda cfg: {"name": "codex_harness_wired", "status": "skip", "detail": "test"},
    )
    monkeypatch.setattr(
        "cairn._doctor._check_codex_hook_policy",
        lambda *, wired: {"name": "codex_hook_policy", "status": "skip", "detail": "test"},
    )
    monkeypatch.setattr(
        "cairn._doctor._check_codex_hook_trust",
        lambda *, wired: {"name": "codex_hook_trust", "status": "skip", "detail": "test"},
    )
    monkeypatch.setattr(
        "cairn._doctor._check_codex_activity",
        lambda *, wired: {"name": "codex_hook_activity", "status": "skip", "detail": "test"},
    )
    return cfg


def _find_check(report: dict[str, object], name: str) -> dict[str, object]:
    return next(c for c in report["checks"] if c["name"] == name)


def _run_doctor_cli(monkeypatch, cfg, fake_regista):
    from click.testing import CliRunner

    from cairn._cli import main

    monkeypatch.setattr("regista.Regista", fake_regista)
    monkeypatch.setattr("cairn._doctor.resolve_config", lambda: cfg)
    result = CliRunner().invoke(main, ["doctor", "--json"])
    return result


def test_doctor_chain_integrity_verified_ok_and_exits_zero(
    doctor_ready_cfg, monkeypatch, tmp_path
):
    """Verified chain: chain_integrity ok, top-level ok, CLI exits 0."""
    from regista import ReplayReport

    class _FakeRegista:
        def __init__(self, **kwargs):
            pass

        def read_events(self, **kwargs):
            return []

        def replay(self, **kwargs):
            # A clean replay that also VERIFIED principal binding: post-WI-036
            # cairn only records "verified" when the binding check actually ran.
            assert kwargs.get("verify_principal_binding") is True
            return ReplayReport(
                table_name="test",
                replayed_ok=1,
                replayed_drift=0,
                halted=0,
                warnings=0,
                principal_binding_verified=True,
            )

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    assert _record_integrity(monkeypatch, doctor_ready_cfg) == 0
    report = _doctor_report(monkeypatch, doctor_ready_cfg)

    chain = _find_check(report, "chain_integrity")
    assert chain["status"] == "ok"
    assert report["regista"]["chain_ok"] is True
    assert report["regista"]["chain_state"] == "verified"
    assert report["ok"] is True
    assert report["degraded"] is False, [
        c for c in report["checks"] if c["status"] == "warn"
    ]

    result = _run_doctor_cli(monkeypatch, doctor_ready_cfg, _FakeRegista)
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["regista"]["chain_ok"] is True


def test_doctor_chain_integrity_drift_fails_and_exits_nonzero(
    doctor_ready_cfg, monkeypatch, tmp_path
):
    """Chain drift: chain_integrity fails, top-level ok false, CLI exits nonzero."""
    from regista import ReplayReport

    class _FakeRegista:
        def __init__(self, **kwargs):
            pass

        def read_events(self, **kwargs):
            return []

        def replay(self, **kwargs):
            return ReplayReport(
                table_name="test",
                replayed_ok=0,
                replayed_drift=1,
                halted=0,
                warnings=0,
            )

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    assert _record_integrity(monkeypatch, doctor_ready_cfg) == 1
    report = _doctor_report(monkeypatch, doctor_ready_cfg)

    chain = _find_check(report, "chain_integrity")
    assert chain["status"] == "fail"
    assert report["regista"]["chain_ok"] is False
    assert report["regista"]["chain_state"] == "drift"
    assert report["ok"] is False

    result = _run_doctor_cli(monkeypatch, doctor_ready_cfg, _FakeRegista)
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["regista"]["chain_ok"] is False


def test_doctor_chain_integrity_error_fails_and_exits_nonzero(
    doctor_ready_cfg, monkeypatch, tmp_path
):
    """Replay error: integrity exits 1 without recording; doctor reports the
    honest never_run skip (WI-030 m4 — an exception is not a verdict)."""

    class _FakeRegista:
        def __init__(self, **kwargs):
            pass

        def read_events(self, **kwargs):
            return []

        def replay(self, **kwargs):
            raise RuntimeError("replay unavailable")

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    assert _record_integrity(monkeypatch, doctor_ready_cfg) == 1
    report = _doctor_report(monkeypatch, doctor_ready_cfg)

    chain = _find_check(report, "chain_integrity")
    assert chain["status"] == "skip"
    assert report["regista"]["chain_ok"] is None
    assert report["regista"]["chain_state"] == "never_run"
    assert report["ok"] is True

    result = _run_doctor_cli(monkeypatch, doctor_ready_cfg, _FakeRegista)
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["regista"]["chain_ok"] is None


def test_doctor_chain_integrity_unsupported_warns_and_does_not_claim_ok(
    doctor_ready_cfg, monkeypatch, tmp_path
):
    """Unsupported replay API: chain_ok is None (never True) and check warns."""

    class _FakeRegista:
        def __init__(self, **kwargs):
            pass

        def read_events(self, **kwargs):
            return []

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    assert _record_integrity(monkeypatch, doctor_ready_cfg) == 1
    report = _doctor_report(monkeypatch, doctor_ready_cfg)

    chain = _find_check(report, "chain_integrity")
    assert chain["status"] == "warn"
    assert report["regista"]["chain_ok"] is None
    assert report["regista"]["chain_state"] == "unsupported"
    assert report["ok"] is True
    assert report["degraded"] is True

    result = _run_doctor_cli(monkeypatch, doctor_ready_cfg, _FakeRegista)
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["regista"]["chain_ok"] is None


def test_integrity_cli_verified_exits_zero(doctor_ready_cfg, monkeypatch):
    """`cairn integrity --json` exits 0 on a verified replay (WI-030)."""
    from click.testing import CliRunner
    from regista import ReplayReport

    from cairn._cli import main

    class _FakeRegista:
        def __init__(self, **kwargs):
            pass

        def read_events(self, **kwargs):
            return []

        def replay(self, **kwargs):
            # A clean replay that also VERIFIED principal binding: post-WI-036
            # cairn only records "verified" when the binding check actually ran.
            assert kwargs.get("verify_principal_binding") is True
            return ReplayReport(
                table_name="test",
                replayed_ok=1,
                replayed_drift=0,
                halted=0,
                warnings=0,
                principal_binding_verified=True,
            )

        def close(self):
            pass

    monkeypatch.setattr("regista.Regista", _FakeRegista)
    monkeypatch.setattr("cairn._doctor.resolve_config", lambda: doctor_ready_cfg)
    result = CliRunner().invoke(main, ["integrity", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["chain_state"] == "verified"


# ----------------------------------------------------------------------
# CLI contract — dry-run is success (exit 0)
# ----------------------------------------------------------------------


def test_install_harness_claude_dry_run_exits_zero(cfg, monkeypatch):
    """A successful dry-run exits 0 per CLI contract v1 §2."""
    from click.testing import CliRunner

    from cairn._cli import main

    monkeypatch.setattr("cairn._install.resolve_config", lambda: cfg)
    result = CliRunner().invoke(
        main, ["install-harness", "claude", "--dry-run", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["status"] == "installed"
    assert payload[0]["no_op"] is False


def test_uninstall_harness_claude_dry_run_exits_zero(cfg, monkeypatch):
    """A successful uninstall dry-run also exits 0."""
    from click.testing import CliRunner

    from cairn._cli import main

    monkeypatch.setattr("cairn._install.resolve_config", lambda: cfg)
    result = CliRunner().invoke(
        main, ["uninstall-harness", "claude", "--dry-run", "--json"]
    )
    assert result.exit_code == 0, result.output


def test_install_harness_opencode_dry_run_exits_zero(cfg, monkeypatch):
    """OpenCode dry-run exits 0 and reports the plugin would be registered."""
    from click.testing import CliRunner

    from cairn._cli import main

    monkeypatch.setattr("cairn._install.resolve_config", lambda: cfg)
    result = CliRunner().invoke(
        main, ["install-harness", "opencode", "--dry-run", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["status"] == "installed"


# ----------------------------------------------------------------------
# WI-033 — the generated hook must be RUNNABLE, not merely well-formed
# ----------------------------------------------------------------------


def _hook_entry_point_dir() -> Path:
    """Directory holding cairn's hook console scripts.

    This is the directory a harness session finds on PATH for a uv-tool,
    pipx or venv install (``~/.local/bin`` or ``<venv>/bin``).
    """
    import shutil as _shutil
    import sys as _sys

    candidate = Path(_sys.executable).parent
    if (candidate / "cairn-claude-hook").exists():
        return candidate
    found = _shutil.which("cairn-claude-hook")
    assert found, (
        "cairn-claude-hook console script is not installed — generated hooks "
        "would name an interpreter that may not be able to import cairn (WI-033)"
    )
    return Path(found).parent


def test_generated_claude_hook_executes_under_a_stripped_path(tmp_path):
    """Execute the generated command with PATH stripped to cairn's own bin dir.

    PATH deliberately excludes ``/usr/bin``, so no ``python3`` is resolvable at
    all.  A console script still runs there because its shebang names cairn's
    interpreter absolutely; the old ``python3 -m cairn._claude_hook`` form
    cannot even find an interpreter — which is how all ten hooks on a real host
    failed on every invocation while ``harness_wired`` reported ok (WI-033).

    Asserting the *string* appears in settings.json is exactly the check that
    let this run undetected, so this test runs the command.
    """
    import subprocess

    from cairn._install import _expected_hook_entry

    entry = _expected_hook_entry("claude", "SessionStart")
    assert entry is not None
    command = entry["hooks"][0]["command"]
    script_dir = _hook_entry_point_dir()

    proc = subprocess.run(
        command,
        shell=True,
        input="{}",
        capture_output=True,
        text=True,
        timeout=60,
        env={
            "PATH": str(script_dir),
            "HOME": str(tmp_path),
            # Keeps the probe side-effect free; the module still has to import
            # before main() can honour it.
            "CAIRN_DISABLE": "1",
        },
    )
    assert proc.returncode == 0, (
        f"generated hook command {command!r} is not runnable with PATH="
        f"{script_dir}: exit {proc.returncode}\n{proc.stderr}"
    )

    # And the same command answers the liveness probe used by install/doctor.
    probe = f"{command.rsplit(' ', 1)[0]} --selftest"
    proc = subprocess.run(
        probe,
        shell=True,
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": str(script_dir), "HOME": str(tmp_path)},
    )
    assert proc.returncode == 0, f"{probe!r} failed: {proc.stderr}"
    assert "cairn-hook-selftest ok" in proc.stdout


def test_generated_codex_hook_executes_under_a_stripped_path(tmp_path):
    """Same guarantee for the Codex hook command (WI-033)."""
    import subprocess

    from cairn._install import _expected_hook_entry

    entry = _expected_hook_entry("codex", "PostToolUse")
    assert entry is not None
    command = entry["hooks"][0]["command"]
    script_dir = _hook_entry_point_dir()

    probe = f"{command.rsplit(' ', 1)[0]} --selftest"
    proc = subprocess.run(
        probe,
        shell=True,
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": str(script_dir), "HOME": str(tmp_path)},
    )
    assert proc.returncode == 0, (
        f"generated Codex hook command {command!r} is not runnable with PATH="
        f"{script_dir}: exit {proc.returncode}\n{proc.stderr}"
    )
    assert "cairn-hook-selftest ok" in proc.stdout


def test_generated_hook_commands_do_not_name_a_bare_interpreter():
    """A bare ``python3``/``python`` resolves against the harness's PATH, which
    is not cairn's interpreter under any isolated install (WI-033)."""
    from cairn._install import (
        CAIRN_CODEX_HOOK_COMMAND,
        CAIRN_CODEX_HOOK_COMMAND_WINDOWS,
        CAIRN_HOOK_COMMAND,
    )

    for cmd in (
        CAIRN_HOOK_COMMAND,
        CAIRN_CODEX_HOOK_COMMAND,
        CAIRN_CODEX_HOOK_COMMAND_WINDOWS,
    ):
        assert not cmd.split()[0].startswith("python"), (
            f"hook command {cmd!r} depends on PATH module resolution"
        )


def test_legacy_bare_python_hooks_are_still_recognised_as_ours():
    """Upgrade path: hosts installed by an older version have bare-python
    hooks, and hosts mitigated by hand have absolute-interpreter ones.  If
    ownership detection stops recognising them, uninstall leaves them behind
    and install appends the console-script form alongside the broken old
    entry (WI-033)."""
    import sys as _sys

    legacy_claude = (
        "python3 -m cairn._claude_hook session-start",
        "python -m cairn._claude_hook session-start",
        f"{_sys.executable} -m cairn._claude_hook session-start",
    )
    for legacy_cmd in legacy_claude:
        entry = {
            "matcher": "*",
            "hooks": [{"type": "command", "command": legacy_cmd, "timeout": 10}],
        }
        assert _is_cairn_hook_entry(entry, harness="claude", event="SessionStart"), (
            f"legacy hook form not recognised: {legacy_cmd}"
        )

    for legacy_cmd in (
        "python3 -m cairn._codex_hook post",
        f"{_sys.executable} -m cairn._codex_hook post",
    ):
        entry = {
            "matcher": "*",
            "hooks": [{"type": "command", "command": legacy_cmd, "timeout": 10}],
        }
        assert _is_cairn_hook_entry(entry, harness="codex", event="PostToolUse"), (
            f"legacy Codex hook form not recognised: {legacy_cmd}"
        )

    # A user hook that merely mentions cairn is still not ours.
    foreign = {
        "matcher": "*",
        "hooks": [{"type": "command", "command": "python3 -m mycairn._claude_hook pre"}],
    }
    assert not _is_cairn_hook_entry(foreign, harness="claude", event="PreToolUse")


def test_upgrade_rewrites_legacy_hooks_in_place(cfg, claude_settings):
    """An upgrade must REWRITE deployed legacy hooks, not just recognise them.

    Found live on a uv-tool host: recognising the bare-python entries as
    cairn-owned made install-harness report "already wired (no-op)" and leave
    all ten broken hooks exactly as they were — so the fix never reached the
    deployed host. Recognition without rewriting is worse than not recognising:
    it is silence over a known-broken hook (WI-033).
    """
    from cairn._install import CAIRN_HOOK_COMMAND

    claude_settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        # A user hook cairn does not own, first in the list.
                        {
                            "matcher": "*",
                            "hooks": [{"type": "command", "command": "./mine.sh"}],
                        },
                        {
                            "matcher": "*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "python3 -m cairn._claude_hook session-start",
                                    "timeout": 10,
                                }
                            ],
                        },
                    ]
                }
            }
        )
    )
    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    assert not result.no_op, "an upgrade over broken hooks is not a no-op"

    entries = json.loads(claude_settings.read_text())["hooks"]["SessionStart"]
    commands = [h["command"] for e in entries for h in e.get("hooks", [])]
    assert "./mine.sh" in commands, "user hook was clobbered"
    assert f"{CAIRN_HOOK_COMMAND} session-start" in commands, (
        "legacy hook was recognised but never rewritten"
    )
    assert not any("python3 -m cairn._claude_hook" in c for c in commands), (
        f"the broken legacy hook survived the upgrade: {commands}"
    )
    assert len(entries) == 2, f"install duplicated an entry: {entries}"

    # And a second run is a genuine no-op.
    again = _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    assert again.no_op, [a.detail for a in again.actions]

    _uninstall_claude(
        claude_settings,
        json.loads(claude_settings.read_text()),
        dry_run=False,
        result=InstallResult(harness="claude"),
        manifest={},
    )


def test_upgrade_collapses_duplicate_cairn_hooks(cfg, claude_settings):
    """A host that already accumulated duplicates ends with exactly one."""
    from cairn._install import CAIRN_HOOK_COMMAND

    legacy = {
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": "python3 -m cairn._claude_hook pre",
                "timeout": 10,
            }
        ],
    }
    claude_settings.write_text(
        json.dumps({"hooks": {"PreToolUse": [legacy, dict(legacy)]}})
    )
    _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    entries = json.loads(claude_settings.read_text())["hooks"]["PreToolUse"]
    assert len(entries) == 1, entries
    assert entries[0]["hooks"][0]["command"] == f"{CAIRN_HOOK_COMMAND} pre"


def test_install_harness_degrades_when_the_hook_command_cannot_run(
    cfg, claude_settings, monkeypatch
):
    """install-harness must VERIFY the hook it writes, not merely record it.

    The WI-034 lesson applied to the installer: a hook that was written but
    never executed is not evidence of anything, and reporting ``installed`` on
    an unrunnable hook is how a total loss of session attestation went
    unnoticed (WI-033).
    """
    monkeypatch.setattr(
        "cairn._install.CAIRN_HOOK_COMMAND", "cairn-claude-hook-not-installed"
    )
    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)

    assert result.status is InstallStatus.FAILED or result.status.value == "degraded", (
        f"unrunnable hook reported as {result.status.value}"
    )
    assert any(
        a.kind == "error" and "not runnable" in a.detail for a in result.actions
    ), [a.detail for a in result.actions]

    from cairn._install import results_succeeded

    assert not results_succeeded([result])


def test_install_harness_reports_verified_hook_command(cfg, claude_settings):
    """The happy path records that the hook was executed, not just written."""
    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    assert result.status is InstallStatus.INSTALLED, [a.detail for a in result.actions]
    assert any(a.kind in ("verify", "warn") for a in result.actions), [
        a.detail for a in result.actions
    ]


def test_hook_verification_can_be_bypassed_explicitly(
    cfg, claude_settings, monkeypatch
):
    """An operator whose harness PATH differs from the installer's can opt out
    — loudly and on purpose, never by default."""
    from cairn._install import SKIP_HOOK_VERIFICATION_ENV

    monkeypatch.setattr(
        "cairn._install.CAIRN_HOOK_COMMAND", "cairn-claude-hook-not-installed"
    )
    monkeypatch.setenv(SKIP_HOOK_VERIFICATION_ENV, "1")
    result = _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    assert result.status is InstallStatus.INSTALLED


# ----------------------------------------------------------------------
# WI-034 — doctor checks must verify, not merely observe presence
# ----------------------------------------------------------------------


def test_harness_wired_fails_when_the_hook_is_present_but_not_executable(
    cfg, claude_settings, monkeypatch
):
    """THE WI-034 REGRESSION.

    ``harness_wired`` verified that hook entries were PRESENT and that env vars
    were SET.  It never checked that the command was executable or that the
    module it named was importable, so a hook failing on every invocation read
    ``ok`` — which is why a total loss of session attestation went unnoticed on
    a real host for as long as it did.
    """
    from cairn._doctor import _check_harness_wired
    from cairn._install import HOOK_EVENTS

    # Wire a complete, well-formed set of hooks whose command cannot run.
    broken = "cairn-claude-hook-not-installed"
    monkeypatch.setattr("cairn._install.CAIRN_HOOK_COMMAND", broken)
    claude_settings.write_text(
        json.dumps(
            {
                "env": {"REGISTA_DSN": cfg.dsn, "CAIRN_PROJECT": cfg.project},
                "hooks": {
                    event: [
                        {
                            "matcher": "*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": f"{broken} {action}",
                                    "timeout": 10,
                                }
                            ],
                        }
                    ]
                    for event, action in HOOK_EVENTS.items()
                },
            }
        )
    )

    result = _check_harness_wired(cfg)
    assert result["status"] == "fail", result
    assert "not runnable" in result["detail"]


def test_harness_wired_fails_when_the_named_module_is_not_importable(
    cfg, claude_settings, monkeypatch
):
    """The exact estate failure: hooks name a python that cannot import cairn.

    The command RESOLVES and EXECUTES — presence checks and even a naive
    ``which`` are satisfied — but the module it names is not importable under
    that interpreter, so every invocation fails (WI-033/WI-034).
    """
    import sys

    from cairn._doctor import _check_harness_wired
    from cairn._install import HOOK_EVENTS

    foreign = "/usr/bin/python3"
    if foreign == sys.executable:
        pytest.skip("system python is cairn's interpreter here")
    import subprocess

    probe = subprocess.run(
        [foreign, "-c", "import cairn"], capture_output=True, text=True
    )
    if probe.returncode == 0:
        pytest.skip(f"{foreign} can import cairn; no foreign interpreter available")

    command = f"{foreign} -m cairn._claude_hook"
    claude_settings.write_text(
        json.dumps(
            {
                "env": {"REGISTA_DSN": cfg.dsn, "CAIRN_PROJECT": cfg.project},
                "hooks": {
                    event: [
                        {
                            "matcher": "*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": f"{command} {action}",
                                    "timeout": 10,
                                }
                            ],
                        }
                    ]
                    for event, action in HOOK_EVENTS.items()
                },
            }
        )
    )

    result = _check_harness_wired(cfg)
    assert result["status"] == "fail", result
    assert "not runnable" in result["detail"]


def test_harness_wired_ok_for_the_hooks_install_harness_writes(cfg, claude_settings):
    """The installer's own output must pass its own executability check."""
    from cairn._doctor import _check_harness_wired

    _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    result = _check_harness_wired(cfg)
    assert result["status"] in {"ok", "warn"}, result
    assert "not runnable" not in result["detail"]


def test_content_encryption_fails_on_a_configured_but_unresolvable_key(tmp_path):
    """A configured key ref is not a resolvable one (agent-suite WI-041).

    The check reported ``ok`` because ``CAIRN_CONTENT_KEY_REF`` was SET, never
    resolving it — so content encryption could be reported ON while the key it
    names could not be fetched.
    """
    from cairn._doctor import _check_content_encryption

    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path=str(tmp_path / "keys.json"),
        project="test",
        content_key_path=str(tmp_path / "absent-content.key"),
    )
    result = _check_content_encryption(cfg)
    assert result["status"] == "fail", result
    assert "does not resolve" in result["detail"]


def test_content_encryption_ok_when_the_key_actually_resolves(tmp_path):
    from cairn._doctor import _check_content_encryption

    key = tmp_path / "content.key"
    key.write_bytes(b"0" * 32)
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path=str(tmp_path / "keys.json"),
        project="test",
        content_key_path=str(key),
    )
    result = _check_content_encryption(cfg)
    assert result["status"] == "ok", result
    assert "resolves" in result["detail"]
    # WI-040: ok means the cipher round-tripped, not merely that the fetch
    # worked — the detail says so.
    assert "encrypts" in result["detail"]


def test_content_encryption_fails_on_a_key_that_resolves_but_cannot_encrypt(tmp_path):
    """WI-040: the doctor said ok over a key every capture rejected.

    Wrong-size key material resolves fine; only exercising the cipher
    catches it. The check must report the state capture will actually hit:
    content withheld, not protected.
    """
    from cairn._doctor import _check_content_encryption

    key = tmp_path / "content.key"
    key.write_bytes(b"x" * 40)
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path=str(tmp_path / "keys.json"),
        project="test",
        content_key_path=str(key),
    )
    result = _check_content_encryption(cfg)
    assert result["status"] == "fail", result
    assert "cannot encrypt" in result["detail"]
    assert "withheld" in result["detail"]


def test_content_encryption_catches_the_vault_field_suffix_trap(tmp_path):
    """``vault:kv/a/b/regista#hmac_key`` parses to a DIFFERENT, neighbouring
    secret rather than erroring — the field is the last path segment."""
    from cairn._doctor import _check_content_encryption

    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path=str(tmp_path / "keys.json"),
        project="test",
        content_key_ref="vault:kv/agent-suite/cairn#content_key",
    )
    result = _check_content_encryption(cfg)
    assert result["status"] == "fail", result
    assert "LAST PATH SEGMENT" in result["detail"]


def test_secret_ref_static_problem_names_the_estate_traps():
    from cairn._doctor import _secret_ref_static_problem

    # Too few segments for regista's vault provider.
    assert "segment" in (_secret_ref_static_problem("vault:kv/only") or "")
    # A bare value silently resolves as a literal secret, not a reference.
    assert "literal" in (_secret_ref_static_problem("just-a-value") or "")
    # A well-shaped file ref has no static problem.
    assert _secret_ref_static_problem("file:/tmp/x.key") is None


def test_doctor_freshness_is_not_satisfied_by_work_item_events(monkeypatch, tmp_path):
    """End-to-end through run_doctor: a store whose only recent events are
    work-item attestations, with a wired Claude that ran, must exit nonzero."""
    import io
    from contextlib import redirect_stdout

    from cairn._install import HOOK_EVENTS

    settings = tmp_path / "claude.json"
    monkeypatch.setenv("CAIRN_CLAUDE_SETTINGS", str(settings))
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path / "projects"))
    _make_transcript(tmp_path / "projects", "recent", age_secs=60)

    key_path = tmp_path / "keys.json"
    key_path.write_text(json.dumps({"keys": [{"key_id": "k", "scheme": "hmac-sha256"}]}))
    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path=str(key_path),
        project="test",
        state_dir=str(tmp_path / "state"),
        integrity_dir=str(tmp_path / "integrity"),
    )
    monkeypatch.setattr("cairn._doctor.resolve_config", lambda: cfg)
    monkeypatch.setattr("cairn._install.resolve_config", lambda: cfg)
    _install_claude(cfg, dry_run=False, uninstall=False, user=None)
    assert set(json.loads(settings.read_text())["hooks"]) == set(HOOK_EVENTS)

    import datetime
    from contextlib import contextmanager

    class _Ev:
        entity_kind = "work_item"
        timestamp = datetime.datetime.now(datetime.UTC)

    class _Sub:
        def read_events(self, **kwargs):
            # 400/400 recent events are work items; zero session events.
            if kwargs.get("transition") == "session_attestation":
                return []
            return [_Ev()]

        def close(self):
            pass

    @contextmanager
    def _fake_open(_cfg):
        yield _Sub()

    monkeypatch.setattr("cairn._doctor._open_regista", _fake_open)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = run_doctor(json_output=True)
    report = json.loads(buf.getvalue())
    freshness = next(
        c for c in report["checks"] if c["name"] == "attestation_freshness"
    )
    assert freshness["status"] == "fail", report
    assert rc == 1
