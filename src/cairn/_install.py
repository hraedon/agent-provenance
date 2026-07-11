"""``cairn install-harness`` — idempotent harness wiring.

Implements the install-harness contract (``agent-suite/docs/install-harness-contract.md``):
one command that wires cairn's interception (hooks + default-on env) into a named
harness, re-runnable, with ``--dry-run`` and ``--uninstall``.

Claude Code target: ``~/.claude/settings.json`` (or ``$CAIRN_CLAUDE_SETTINGS``).
OpenCode target: ``~/.config/opencode/opencode.json`` (or ``$CAIRN_OPENCODE_CONFIG``).
Hermes target: ``~/.hermes/.env`` + ``~/.hermes/plugins/observability/cairn/``
(or ``$CAIRN_HERMES_HOME``).
"""

from __future__ import annotations

import json
import os
import subprocess
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
    "MessageDisplay": "message-display",
    "Stop": "stop",
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


def _detect_harness_version(harness: str) -> str | None:
    """Detect the installed harness version (Plan 009 WI-1.3).

    Runs ``<harness> --version`` and parses the output. Returns the
    version string (e.g. ``"2.1.206"``) or ``None`` if the harness
    binary is not found or the version can't be parsed.

    This prevents the synthetic ``"unknown"`` / ``"1.0.42"`` pattern:
    the real version is resolved at install time and recorded into the
    wiring (settings.json env block), so every attestation carries the
    true harness identity.
    """
    commands: dict[str, list[str]] = {
        "claude": ["claude", "--version"],
        "claude-code": ["claude", "--version"],
        "opencode": ["opencode", "--version"],
        "hermes": ["hermes", "--version"],
    }
    cmd = commands.get(harness)
    if not cmd:
        return None
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None
        output = result.stdout.strip()
        if not output:
            return None
        # Claude Code: "2.1.206 (Claude Code)" → "2.1.206"
        # opencode: typically "opencode version X.Y.Z" or just "X.Y.Z"
        first_token = output.split()[0]
        return first_token
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


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


def _hermes_home() -> Path:
    """Return the Hermes home directory (``~/.hermes`` by default)."""
    return Path(os.environ.get("CAIRN_HERMES_HOME", str(Path.home() / ".hermes")))


def _hermes_env_path() -> Path:
    """Return the path to Hermes's ``.env`` file."""
    return _hermes_home() / ".env"


def _hermes_plugin_dir() -> Path:
    """Return the target directory for the cairn plugin."""
    return _hermes_home() / "plugins" / "observability" / "cairn"


def _hermes_source_plugin_dir() -> Path:
    """Return the source plugin directory in the repo or installed package."""
    # In an installed wheel, integrations/ is inside the package dir.
    pkg_path = Path(__file__).resolve().parent / "integrations" / "hermes"
    if pkg_path.is_dir():
        return pkg_path
    # In a source checkout, integrations/ is at the repo root.
    return Path(__file__).resolve().parent.parent.parent / "integrations" / "hermes"


# Sentinel comments for the managed env block in ~/.hermes/.env.
_HERMES_ENV_BEGIN = "# BEGIN cairn-harness-managed"
_HERMES_ENV_END = "# END cairn-harness-managed"


def _parse_env_file(path: Path) -> list[str]:
    """Read .env file lines, returning [] if missing."""
    if not path.is_file():
        return []
    return path.read_text().splitlines()


def _find_managed_block(lines: list[str]) -> tuple[int, int] | None:
    """Find the (begin_idx, end_idx) of the managed block, or None."""
    begin_idx = -1
    end_idx = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == _HERMES_ENV_BEGIN:
            begin_idx = i
        elif stripped == _HERMES_ENV_END:
            end_idx = i
            break
    if begin_idx >= 0 and end_idx > begin_idx:
        return (begin_idx, end_idx)
    return None


def _parse_env_entries(lines: list[str]) -> dict[str, str]:
    """Parse KEY=VALUE entries from a list of .env lines."""
    entries: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            k, v = stripped.split("=", 1)
            entries[k.strip()] = v.strip()
    return entries


def _build_managed_env_lines(
    env_vals: dict[str, str | None],
    user: str | None,
) -> list[str]:
    """Build the managed env block lines (including sentinels)."""
    lines = [_HERMES_ENV_BEGIN]
    for key in _ENV_VARS:
        val: str | None = None
        if key == "CAIRN_HARNESS_NAME":
            val = "hermes"
        elif key == "PRINCIPAL_ID" and user:
            val = user
        else:
            val = env_vals.get(key)
        if val is not None:
            lines.append(f"{key}={val}")
    lines.append(_HERMES_ENV_END)
    return lines


def _install_hermes(
    cfg: Any,
    *,
    dry_run: bool,
    uninstall: bool,
    user: str | None,
) -> InstallResult:
    result = InstallResult(harness="hermes", user=user)

    env_path = _hermes_env_path()
    plugin_target = _hermes_plugin_dir()
    plugin_source = _hermes_source_plugin_dir()

    if uninstall:
        return _uninstall_hermes(env_path, plugin_target, dry_run=dry_run, result=result)

    # --- Env wiring ---
    lines = _parse_env_file(env_path)
    desired_env = _env_values(cfg, "hermes")

    # WI-1.3: resolve the real harness version if not already configured.
    hv = desired_env.get("CAIRN_HARNESS_VERSION")
    if not hv or hv == "unknown":
        detected = _detect_harness_version("hermes")
        if detected:
            desired_env["CAIRN_HARNESS_VERSION"] = detected

    managed_block = _find_managed_block(lines)

    changed = False

    # Check for existing keys outside managed block (no clobber).
    unmanaged_entries: dict[str, str] = {}
    if managed_block is not None:
        begin, end = managed_block
        before = lines[:begin]
        after = lines[end + 1:]
        unmanaged_entries = _parse_env_entries(before + after)
    else:
        unmanaged_entries = _parse_env_entries(lines)

    # Build desired values, respecting no-clobber.
    final_vals: dict[str, str | None] = {}
    for key in _ENV_VARS:
        val: str | None
        if key == "CAIRN_HARNESS_NAME":
            val = "hermes"
        elif key == "PRINCIPAL_ID" and user:
            val = user
        else:
            val = desired_env.get(key)
        final_vals[key] = val

        if val is not None and key in unmanaged_entries:
            existing = unmanaged_entries[key]
            if existing != val:
                result.actions.append(
                    InstallAction(
                        "skip",
                        str(env_path),
                        f"{key} already set outside managed block — keeping existing (no clobber)",
                        keys=[f"env.{key}"],
                    )
                )
                final_vals[key] = existing  # keep existing

    managed_lines = _build_managed_env_lines(final_vals, user)

    if managed_block is not None:
        begin, end = managed_block
        existing_block = lines[begin : end + 1]
        if existing_block != managed_lines:
            lines[begin : end + 1] = managed_lines
            changed = True
            result.actions.append(
                InstallAction(
                    "update_file",
                    str(env_path),
                    "update cairn-managed env block",
                    keys=["env"],
                )
            )
        else:
            result.actions.append(
                InstallAction("skip", str(env_path), "env block already up-to-date")
            )
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend(managed_lines)
        changed = True
        result.actions.append(
            InstallAction(
                "create_file",
                str(env_path),
                "add cairn-managed env block",
                keys=["env"],
            )
        )

    # --- Plugin install ---
    if plugin_source.is_dir():
        plugin_files = ["plugin.yaml", "__init__.py"]
        plugin_changed = False
        plugin_target.mkdir(parents=True, exist_ok=True)

        for fname in plugin_files:
            src = plugin_source / fname
            dst = plugin_target / fname
            if not src.is_file():
                continue
            content = src.read_text()
            if not dst.is_file() or dst.read_text() != content:
                plugin_changed = True
                if not dry_run:
                    dst.write_text(content)
                result.actions.append(
                    InstallAction(
                        "create_file" if not dst.is_file() else "update_file",
                        str(dst),
                        f"install cairn Hermes plugin ({fname})",
                    )
                )

        if not plugin_changed:
            result.actions.append(
                InstallAction("skip", str(plugin_target), "plugin already installed")
            )
    else:
        result.actions.append(
            InstallAction(
                "skip",
                str(plugin_source),
                "plugin source not found in repo — skipping plugin install",
            )
        )

    if not any(a.kind != "skip" for a in result.actions):
        result.no_op = True
    elif not dry_run and changed:
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text("\n".join(lines) + "\n")

    return result


def _uninstall_hermes(
    env_path: Path,
    plugin_dir: Path,
    *,
    dry_run: bool,
    result: InstallResult,
) -> InstallResult:
    lines = _parse_env_file(env_path)
    changed = False

    # --- Remove managed env block ---
    managed_block = _find_managed_block(lines)
    if managed_block is not None:
        begin, end = managed_block
        del lines[begin : end + 1]
        # Clean up trailing blank lines left behind.
        while lines and not lines[-1].strip():
            lines.pop()
        changed = True
        result.actions.append(
            InstallAction(
                "update_file",
                str(env_path),
                "remove cairn-managed env block",
                keys=["env"],
            )
        )

    if not dry_run and changed:
        if lines:
            env_path.write_text("\n".join(lines) + "\n")
        elif env_path.is_file():
            env_path.unlink()

    # --- Remove plugin directory ---
    if plugin_dir.is_dir():
        plugin_files = ["plugin.yaml", "__init__.py"]
        for fname in plugin_files:
            f = plugin_dir / fname
            if f.is_file():
                if not dry_run:
                    f.unlink()
                result.actions.append(
                    InstallAction(
                        "delete_file",
                        str(f),
                        f"remove cairn Hermes plugin ({fname})",
                    )
                )
        # Try to remove now-empty directories.
        if not dry_run:
            for d in reversed([plugin_dir, plugin_dir.parent, plugin_dir.parent.parent]):
                try:
                    d.rmdir()
                except OSError:
                    break

    if not result.actions:
        result.no_op = True

    return result


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

    # WI-1.3: resolve the real harness version if not already configured.
    hv = desired_env.get("CAIRN_HARNESS_VERSION")
    if not hv or hv == "unknown":
        detected = _detect_harness_version("claude")
        if detected:
            desired_env["CAIRN_HARNESS_VERSION"] = detected
            result.actions.append(
                InstallAction(
                    "detected",
                    "claude --version",
                    f"resolved harness version: {detected}",
                    keys=["env.CAIRN_HARNESS_VERSION"],
                )
            )
        elif hv == "unknown":
            desired_env.pop("CAIRN_HARNESS_VERSION", None)

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

    # WI-1.3: resolve the real harness version if not already configured.
    hv = desired_env.get("CAIRN_HARNESS_VERSION")
    if not hv or hv == "unknown":
        detected = _detect_harness_version("opencode")
        if detected:
            desired_env["CAIRN_HARNESS_VERSION"] = detected

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
    if harness == "all":
        targets = ["claude", "opencode", "hermes"]
    else:
        targets = [harness]
    results: list[InstallResult] = []
    for t in targets:
        if t == "claude":
            results.append(_install_claude(cfg, dry_run=dry_run, uninstall=uninstall, user=user))
        elif t == "opencode":
            results.append(_install_opencode(cfg, dry_run=dry_run, uninstall=uninstall, user=user))
        elif t == "hermes":
            results.append(_install_hermes(cfg, dry_run=dry_run, uninstall=uninstall, user=user))
        elif t in ("agy", "codex"):
            results.append(InstallResult(
                harness=t,
                user=user,
                no_op=True,
                actions=[
                    InstallAction(
                        "skip",
                        "",
                        f"{t} adapter not yet implemented "
                        f"(Plan 010 WI-5.{'3' if t == 'agy' else '4'} deferred)",
                    )
                ],
            ))
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
