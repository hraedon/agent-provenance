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
    InstallStatus,
    _detect_harness_version,
    _install_claude,
    _install_hermes,
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


def test_run_install_harness_codex_is_honestly_unsupported(cfg, monkeypatch):
    monkeypatch.setattr("cairn._install.resolve_config", lambda: cfg)

    [result] = run_install_harness("codex")

    assert result.status is InstallStatus.UNSUPPORTED
    assert result.no_op is False
    assert result.actions[0].kind == "unsupported"
    assert result.to_dict()["status"] == "unsupported"


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


def test_install_harness_codex_cli_exits_nonzero(monkeypatch):
    from click.testing import CliRunner

    from cairn._cli import main

    monkeypatch.setattr("cairn._install.resolve_config", lambda: object())
    result = CliRunner().invoke(main, ["install-harness", "codex", "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload[0]["status"] == "unsupported"
    assert payload[0]["no_op"] is False


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


def _make_transcript(base, session_id: str, age_secs: float) -> None:
    """Write a fake session transcript with a given age."""
    import time

    proj = base / "-home-operator-work"
    proj.mkdir(parents=True, exist_ok=True)
    f = proj / f"{session_id}.jsonl"
    f.write_text("{}\n")
    ts = time.time() - age_secs
    os.utime(f, (ts, ts))


def test_freshness_skips_when_not_configured(monkeypatch, tmp_path):
    from cairn._doctor import _check_attestation_freshness

    cfg = CairnEnvConfig(dsn=None, key_path=None, project=None)
    result = _check_attestation_freshness(cfg, None, regista_ok=False)
    assert result["status"] == "skip"


def test_freshness_skips_when_regista_unreachable(monkeypatch, tmp_path):
    """Regista down already reds out its own check — freshness must not
    pile a misleading 'silent' failure on top."""
    from cairn._doctor import _check_attestation_freshness

    result = _check_attestation_freshness(_configured_cfg(), None, regista_ok=False)
    assert result["status"] == "skip"
    assert "unreachable" in result["detail"]


def test_freshness_skips_without_local_transcripts(monkeypatch, tmp_path):
    from cairn._doctor import _check_attestation_freshness

    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path / "empty"))
    result = _check_attestation_freshness(_configured_cfg(), None, regista_ok=True)
    assert result["status"] == "skip"
    assert "no local session transcripts" in result["detail"]


def test_freshness_ok_when_no_recent_sessions(monkeypatch, tmp_path):
    """Old transcripts only (predating the window) — nothing demanded an
    attestation, so silence is fine."""
    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "old-session", age_secs=3 * 24 * 3600)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))
    result = _check_attestation_freshness(_configured_cfg(), None, regista_ok=True)
    assert result["status"] == "ok"
    assert "no sessions ran" in result["detail"]


def test_freshness_ok_with_recent_attestation(monkeypatch, tmp_path):
    import datetime

    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=60)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))
    recent = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=5)
    result = _check_attestation_freshness(_configured_cfg(), recent, regista_ok=True)
    assert result["status"] == "ok"


def test_freshness_fails_when_configured_but_silent(monkeypatch, tmp_path):
    """The WI-4.1 acceptance criterion: sessions ran within the window but
    the newest attestation predates it (or none exists) — doctor reds out."""
    import datetime

    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=60)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))

    # No attestation at all.
    result = _check_attestation_freshness(_configured_cfg(), None, regista_ok=True)
    assert result["status"] == "fail"
    assert "configured but silent" in result["detail"]
    assert "never" in result["detail"]

    # Stale attestation (outside the window).
    stale = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=3)
    result = _check_attestation_freshness(_configured_cfg(), stale, regista_ok=True)
    assert result["status"] == "fail"
    assert "configured but silent" in result["detail"]


def test_freshness_window_configurable(monkeypatch, tmp_path):
    """CAIRN_MAX_ATTESTATION_AGE_HOURS narrows or widens the window."""
    import datetime

    from cairn._doctor import _check_attestation_freshness

    _make_transcript(tmp_path, "recent-session", age_secs=2 * 3600)
    monkeypatch.setenv("CAIRN_CLAUDE_PROJECTS", str(tmp_path))
    stale = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2, minutes=30)

    # Default 24h window: the 2.5h-old attestation is fresh enough.
    result = _check_attestation_freshness(_configured_cfg(), stale, regista_ok=True)
    assert result["status"] == "ok"

    # 1h window: session ran 2h ago (outside window) — nothing to demand.
    monkeypatch.setenv("CAIRN_MAX_ATTESTATION_AGE_HOURS", "1")
    result = _check_attestation_freshness(_configured_cfg(), stale, regista_ok=True)
    assert result["status"] == "ok"

    # 3h window: session ran inside, attestation 2.5h old is also inside.
    monkeypatch.setenv("CAIRN_MAX_ATTESTATION_AGE_HOURS", "3")
    result = _check_attestation_freshness(_configured_cfg(), stale, regista_ok=True)
    assert result["status"] == "ok"

    # 2h window (as hours float): session 2h ago is borderline-outside;
    # use a fresher transcript to force the demand, stale attestation fails.
    _make_transcript(tmp_path, "fresher-session", age_secs=60)
    monkeypatch.setenv("CAIRN_MAX_ATTESTATION_AGE_HOURS", "2")
    result = _check_attestation_freshness(_configured_cfg(), stale, regista_ok=True)
    assert result["status"] == "fail"


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
