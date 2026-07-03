"""``cairn install-harness`` — idempotent harness wiring.

Implements the install-harness contract (``agent-suite/docs/install-harness-contract.md``):
one command that wires cairn's interception (hooks + default-on env) into a named
harness, re-runnable, with ``--dry-run`` and ``--uninstall``.

Claude Code target: ``~/.claude/settings.json`` (or ``$CAIRN_CLAUDE_SETTINGS``).
OpenCode target: ``~/.config/opencode/opencode.json`` (or ``$CAIRN_OPENCODE_CONFIG``).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._config import resolve_config


def _python_command() -> str:
    """Return the python command for the hook entry.

    Uses ``python3`` on Unix (where ``python`` may be Python 2) and
    ``python`` on Windows (where ``python3`` is often not on PATH).
    """
    if sys.platform == "win32":
        return "python"
    return "python3"

CAIRN_HOOK_COMMAND = f"{_python_command()} -m cairn._claude_hook"

# Note: CAIRN_HOOK_COMMAND is evaluated at import time on the machine
# running install-harness. If settings.json is synced across platforms,
# the user should manually adjust the command or use the cairn-hook
# entry point (planned for a future release).

HOOK_EVENTS: dict[str, str] = {
    "PreToolUse": "pre",
    "PostToolUse": "post",
    "PostToolUseFailure": "post-failure",
    "SessionStart": "session-start",
    "SessionEnd": "session-end",
}

_ENV_VARS = [
    "REGISTA_DSN",
    "REGISTA_KEY_PATH",
    "REGISTA_KEY_REF",
    "CAIRN_PROJECT",
    "CAIRN_HARNESS_NAME",
    "CAIRN_HARNESS_VERSION",
    "PRINCIPAL_ID",
]

CAIRN_SENTINEL = "// cairn-managed"


@dataclass
class InstallAction:
    kind: str
    path: str
    detail: str
    keys: list[str] | None = None


@dataclass
class InstallResult:
    tool: str = "cairn"
    harness: str = ""
    user: str | None = None
    actions: list[InstallAction] = field(default_factory=list)
    no_op: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "harness": self.harness,
            "user": self.user,
            "actions": [
                {
                    "kind": a.kind,
                    "path": a.path,
                    "detail": a.detail,
                    **({"keys": a.keys} if a.keys else {}),
                }
                for a in self.actions
            ],
            "no_op": self.no_op,
        }


def _claude_settings_path() -> Path:
    default = str(Path.home() / ".claude" / "settings.json")
    return Path(os.environ.get("CAIRN_CLAUDE_SETTINGS", default))


def _opencode_config_path() -> Path:
    return Path(
        os.environ.get(
            "CAIRN_OPENCODE_CONFIG",
            str(Path.home() / ".config" / "opencode" / "opencode.json"),
        )
    )


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_file():
        try:
            data: dict[str, Any] = json.loads(path.read_text())
            return data
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")


def _is_cairn_hook_entry(entry: dict[str, Any]) -> bool:
    for h in entry.get("hooks", []):
        cmd = h.get("command", "")
        if "cairn._claude_hook" in cmd or "cairn_hook" in cmd:
            return True
    return False


def _env_values(cfg: Any, harness: str) -> dict[str, str | None]:
    vals: dict[str, str | None] = {
        "REGISTA_DSN": cfg.dsn,
        "REGISTA_KEY_PATH": cfg.key_path,
        "REGISTA_KEY_REF": cfg.key_ref,
        "CAIRN_PROJECT": cfg.project,
        "CAIRN_HARNESS_NAME": harness,
        "CAIRN_HARNESS_VERSION": cfg.harness_version,
        "PRINCIPAL_ID": cfg.principal_id,
    }
    return vals


# ----------------------------------------------------------------------
# Claude Code
# ----------------------------------------------------------------------


def _install_claude(
    cfg: Any,
    *,
    dry_run: bool,
    uninstall: bool,
    user: str | None,
) -> InstallResult:
    path = _claude_settings_path()
    result = InstallResult(harness="claude", user=user)
    data = _load_json(path)

    if uninstall:
        return _uninstall_claude(path, data, dry_run=dry_run, result=result)

    env = data.setdefault("env", {})
    hooks = data.setdefault("hooks", {})
    changed = False

    desired_env = _env_values(cfg, "claude-code")
    if user:
        desired_env["PRINCIPAL_ID"] = user

    for key, val in desired_env.items():
        current = env.get(key)
        if current and current != val:
            result.actions.append(
                InstallAction(
                    "skip",
                    str(path),
                    f"{key} already set — keeping existing value (no clobber)",
                    keys=[f"env.{key}"],
                )
            )
            continue
        if not current and val:
            env[key] = val
            changed = True
            result.actions.append(
                InstallAction(
                    "merge_json",
                    str(path),
                    f"set {key}",
                    keys=[f"env.{key}"],
                )
            )

    for event, action in HOOK_EVENTS.items():
        event_hooks = hooks.setdefault(event, [])
        already = any(_is_cairn_hook_entry(e) for e in event_hooks)
        if already:
            continue
        new_entry = {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{CAIRN_HOOK_COMMAND} {action}",
                    "timeout": 10,
                }
            ],
        }
        event_hooks.append(new_entry)
        changed = True
        result.actions.append(
            InstallAction(
                "merge_json",
                str(path),
                f"register cairn {event} hook",
                keys=[f"hooks.{event}"],
            )
        )

    if not result.actions:
        result.no_op = True
    elif not dry_run and changed:
        _save_json(path, data)

    return result


def _uninstall_claude(
    path: Path,
    data: dict[str, Any],
    *,
    dry_run: bool,
    result: InstallResult,
) -> InstallResult:
    hooks = data.get("hooks", {})
    env = data.get("env", {})
    changed = False

    for event in HOOK_EVENTS:
        event_hooks = hooks.get(event, [])
        original_len = len(event_hooks)
        event_hooks = [e for e in event_hooks if not _is_cairn_hook_entry(e)]
        if len(event_hooks) < original_len:
            changed = True
            result.actions.append(
                InstallAction(
                    "merge_json",
                    str(path),
                    f"remove cairn {event} hook",
                    keys=[f"hooks.{event}"],
                )
            )
            if event_hooks:
                hooks[event] = event_hooks
            else:
                hooks.pop(event, None)

    for key in _ENV_VARS:
        if key in env:
            changed = True
            result.actions.append(
                InstallAction(
                    "merge_json",
                    str(path),
                    f"remove {key}",
                    keys=[f"env.{key}"],
                )
            )
            env.pop(key, None)

    if not result.actions:
        result.no_op = True
    elif not dry_run and changed:
        if not data.get("hooks"):
            data.pop("hooks", None)
        if not data.get("env"):
            data.pop("env", None)
        _save_json(path, data)

    return result


# ----------------------------------------------------------------------
# OpenCode
# ----------------------------------------------------------------------


def _install_opencode(
    cfg: Any,
    *,
    dry_run: bool,
    uninstall: bool,
    user: str | None,
) -> InstallResult:
    path = _opencode_config_path()
    result = InstallResult(harness="opencode", user=user)
    data = _load_json(path)

    if uninstall:
        return _uninstall_opencode(path, data, dry_run=dry_run, result=result)

    env = data.setdefault("env", {})
    desired_env = _env_values(cfg, "opencode")
    if user:
        desired_env["PRINCIPAL_ID"] = user

    changed = False
    for key, val in desired_env.items():
        current = env.get(key)
        if current and current != val:
            result.actions.append(
                InstallAction(
                    "skip", str(path),
                    f"{key} already set — keeping existing",
                    keys=[f"env.{key}"],
                )
            )
            continue
        if not current and val:
            env[key] = val
            changed = True
            result.actions.append(
                InstallAction("merge_json", str(path), f"set {key}", keys=[f"env.{key}"])
            )

    plugin_path = _find_opencode_plugin()
    if plugin_path:
        plugins = data.setdefault("plugin", {}).setdefault("sources", [])
        already = any(
            (isinstance(p, dict) and p.get("source", "") == str(plugin_path))
            or (isinstance(p, str) and p == str(plugin_path))
            for p in plugins
        )
        if not already:
            plugins.append({"source": str(plugin_path), "type": "local"})
            changed = True
            result.actions.append(
                InstallAction(
                    "create_file", str(path),
                    "register cairn opencode plugin",
                    keys=["plugin.sources"],
                )
            )
        result.actions.append(
            InstallAction("skip", str(plugin_path), "plugin already registered")
        )
    else:
        result.actions.append(
            InstallAction(
                "skip", "",
                "opencode plugin not found — env vars only",
            )
        )

    if not any(a.kind != "skip" for a in result.actions):
        result.no_op = True
    elif not dry_run and changed:
        _save_json(path, data)

    return result


def _uninstall_opencode(
    path: Path,
    data: dict[str, Any],
    *,
    dry_run: bool,
    result: InstallResult,
) -> InstallResult:
    env = data.get("env", {})
    changed = False

    for key in _ENV_VARS:
        if key in env:
            changed = True
            result.actions.append(
                InstallAction("merge_json", str(path), f"remove {key}", keys=[f"env.{key}"])
            )
            env.pop(key, None)

    plugin_path = _find_opencode_plugin()
    if plugin_path:
        plugin_data = data.get("plugin", {})
        sources = plugin_data.get("sources", [])
        original = len(sources)
        sources = [
            s
            for s in sources
            if not (
                (isinstance(s, dict) and s.get("source", "") == str(plugin_path))
                or (isinstance(s, str) and s == str(plugin_path))
            )
        ]
        if len(sources) < original:
            changed = True
            result.actions.append(
                InstallAction(
                    "merge_json", str(path), "remove cairn plugin",
                    keys=["plugin.sources"],
                )
            )
            plugin_data["sources"] = sources

    if not result.actions:
        result.no_op = True
    elif not dry_run and changed:
        _save_json(path, data)

    return result


def _find_opencode_plugin() -> Path | None:
    root = Path(__file__).resolve().parent.parent.parent
    repo_plugin = root / "integrations" / "opencode" / "index.js"
    if repo_plugin.is_file():
        return repo_plugin
    return None


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------


def run_install_harness(
    harness: str,
    *,
    dry_run: bool = False,
    uninstall: bool = False,
    user: str | None = None,
) -> list[InstallResult]:
    cfg = resolve_config()
    targets = ["claude", "opencode"] if harness == "all" else [harness]
    results: list[InstallResult] = []
    for t in targets:
        if t == "claude":
            results.append(_install_claude(cfg, dry_run=dry_run, uninstall=uninstall, user=user))
        elif t == "opencode":
            results.append(_install_opencode(cfg, dry_run=dry_run, uninstall=uninstall, user=user))
    return results


def format_results_human(
    results: list[InstallResult],
    *,
    dry_run: bool,
    uninstall: bool = False,
) -> str:
    lines: list[str] = []
    prefix = "[dry-run] " if dry_run else ""
    for r in results:
        if r.no_op:
            status = "already wired (no-op)" if not uninstall else "nothing to remove (no-op)"
        elif uninstall:
            status = "uninstalled"
        else:
            status = "wired"
        if dry_run:
            status = "would be " + status
        lines.append(f"{prefix}cairn → {r.harness}: {status}")
        for a in r.actions:
            tag = a.kind.upper()
            lines.append(f"  {tag:12s} {a.detail}")
    return "\n".join(lines)
