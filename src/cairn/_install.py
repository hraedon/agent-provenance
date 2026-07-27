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

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from enum import StrEnum
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
CAIRN_CODEX_HOOK_COMMAND = f"{_python_command()} -m cairn._codex_hook"
CAIRN_CODEX_HOOK_COMMAND_WINDOWS = "python -m cairn._codex_hook"

# Codex hook events Cairn handles (Plan 011). SessionStart and tool events
# attest; Stop performs state cleanup and emits Codex's required JSON response.
# Tool events carry a "*" matcher; SessionStart/Stop are not tool-matched.
CODEX_HOOK_EVENTS: dict[str, str] = {
    "SessionStart": "session-start",
    "PreToolUse": "pre",
    "PostToolUse": "post",
    "Stop": "stop",
}
_CODEX_TOOL_EVENTS = frozenset({"PreToolUse", "PostToolUse"})

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
    # Plan 009 WI-3.1 — subagent attribution + compaction attestation.
    # PostToolBatch is deliberately absent: per-call PostToolUse already
    # covers every batch member (same tool_use_ids; verified from real
    # 2.1.207 capture), so attesting the batch would double-count.
    "SubagentStart": "subagent-start",
    "SubagentStop": "subagent-stop",
    "PostCompact": "post-compact",
}

_ENV_VARS = [
    "REGISTA_DSN",
    "REGISTA_KEY_PATH",
    "REGISTA_KEY_REF",
    "CAIRN_PROJECT",
    "CAIRN_HARNESS_NAME",
    "CAIRN_HARNESS_VERSION",
    "PRINCIPAL_ID",
    "CAIRN_ATTEST_ON_START",
]

CAIRN_SENTINEL = "// cairn-managed"


class ConfigLoadError(Exception):
    """Raised when an existing config file cannot be read or parsed.

    The caller must NOT overwrite the file — doing so would clobber
    the user's content.  Instead, report a FAILED install result.
    """

    def __init__(self, path: Path, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"{path}: {reason}")


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


class InstallStatus(StrEnum):
    """Contract status for one harness installation result."""

    INSTALLED = "installed"
    DEGRADED = "degraded"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


@dataclass
class InstallResult:
    tool: str = "cairn"
    harness: str = ""
    user: str | None = None
    actions: list[InstallAction] = field(default_factory=list)
    no_op: bool = False
    status: InstallStatus = InstallStatus.INSTALLED

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
            "status": self.status.value,
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
    """Read .env file lines, returning [] if missing or unreadable."""
    if not path.is_file():
        return []
    try:
        return path.read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return []


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
        _save_text_file(env_path, "\n".join(lines) + "\n")

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
            _save_text_file(env_path, "\n".join(lines) + "\n")
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
    """Load JSON from *path*.

    Returns ``{}`` when the file does not exist (clean-slate install).

    Raises :class:`ConfigLoadError` when the file *exists* but cannot
    be read or parsed — the caller must refuse to write, preventing
    silent clobbering of user content.
    """
    if not path.is_file():
        return {}
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigLoadError(path, f"unreadable: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigLoadError(path, f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigLoadError(
            path, f"expected JSON object, got {type(data).__name__}"
        )
    return data


def _save_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically write JSON to *path* with owner-only permissions.

    Uses a temp file + ``os.replace`` so an interrupted write cannot
    corrupt the existing file.  Permissions are set to ``0o600`` on
    every write because these files contain DSNs and key paths.
    """
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2, sort_keys=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=".config-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except OSError:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _save_text_file(path: Path, content: str) -> None:
    """Atomically write text to *path* with owner-only permissions.

    Same atomic-write + ``0o600`` pattern as :func:`_save_json`, for
    non-JSON files that contain secrets (e.g. Hermes ``.env``).
    """
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=".config-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except OSError:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# ------------------------------------------------------------------
# Manifest — hash-based hook ownership (Plan 011 WI-3.1)
#
# The manifest records SHA-256 hashes of hook entries cairn has
# installed, so uninstall can identify them precisely — even across
# version changes that alter the command string.  This replaces the
# former substring match (``"cairn._claude_hook" in cmd``) which could
# falsely identify user-authored hooks that merely reference cairn.
# ------------------------------------------------------------------


def _manifest_path() -> Path:
    """Return the path to cairn's harness manifest.

    Override with ``CAIRN_MANIFEST_PATH`` for tests.
    """
    override = os.environ.get("CAIRN_MANIFEST_PATH")
    if override:
        return Path(override)
    return Path.home() / ".cairn" / "harness-manifest.json"


def _load_manifest() -> dict[str, Any]:
    """Load the manifest, returning an empty skeleton if missing or corrupt."""
    path = _manifest_path()
    if not path.is_file():
        return {"version": 1, "installs": {}}
    try:
        data = json.loads(path.read_text())
        if not (isinstance(data, dict) and isinstance(data.get("installs"), dict)):
            return {"version": 1, "installs": {}}
        # Validate per-harness sub-structure: each install must be a dict
        # with a dict ``hook_hashes`` (if present).  Each ``hook_hashes``
        # event value must be a list.
        installs = data["installs"]
        for harness, install in list(installs.items()):
            if not isinstance(install, dict):
                del installs[harness]
                continue
            hh = install.get("hook_hashes")
            if not isinstance(hh, dict):
                install["hook_hashes"] = {}
                hh = install["hook_hashes"]
            for event, hashes in list(hh.items()):
                if not isinstance(hashes, list):
                    del hh[event]
        return data
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        pass
    return {"version": 1, "installs": {}}


def _save_manifest(manifest: dict[str, Any]) -> None:
    """Persist the manifest.  Best-effort: failures are logged, not fatal.

    Uses an atomic write (temp file + ``os.replace``) so an interrupted
    write cannot corrupt the manifest.
    """
    import tempfile

    path = _manifest_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
        content = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=".manifest-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
    except OSError as exc:
        print(f"cairn: WARNING: could not save harness manifest: {exc}", file=sys.stderr)


def _compute_entry_hash(entry: dict[str, Any]) -> str:
    """Compute SHA-256 hash of canonical JSON representation of a hook entry."""
    canonical = json.dumps(entry, sort_keys=True)
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


def _expected_hook_entry(harness: str, event: str) -> dict[str, Any] | None:
    """Return the exact hook entry cairn would create for *harness*+*event*."""
    if harness == "claude":
        action = HOOK_EVENTS.get(event)
        if not action:
            return None
        return {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{CAIRN_HOOK_COMMAND} {action}",
                    "timeout": 10,
                }
            ],
        }
    if harness == "codex":
        action = CODEX_HOOK_EVENTS.get(event)
        if not action:
            return None
        inner = {
            "type": "command",
            "command": f"{CAIRN_CODEX_HOOK_COMMAND} {action}",
            "commandWindows": f"{CAIRN_CODEX_HOOK_COMMAND_WINDOWS} {action}",
            "timeout": 10,
        }
        if event in _CODEX_TOOL_EVENTS:
            return {"matcher": "*", "hooks": [inner]}
        return {"hooks": [inner]}
    return None


def _expected_entry_hash(harness: str, event: str) -> str | None:
    """Return the hash of the entry cairn would create, or ``None``."""
    entry = _expected_hook_entry(harness, event)
    if entry is None:
        return None
    return _compute_entry_hash(entry)


def _cairn_hook_commands(harness: str) -> frozenset[str]:
    """Return the set of exact command strings cairn generates for *harness*.

    Used as a fallback for ownership detection when the manifest is
    unavailable (pre-manifest installs).  This is **exact** match, NOT
    substring — a user hook that merely references cairn will not match.
    """
    cmds: set[str] = set()
    if harness == "claude":
        for action in HOOK_EVENTS.values():
            cmds.add(f"{CAIRN_HOOK_COMMAND} {action}")
    elif harness == "codex":
        for action in CODEX_HOOK_EVENTS.values():
            cmds.add(f"{CAIRN_CODEX_HOOK_COMMAND} {action}")
    return frozenset(cmds)


def _manifest_hashes(
    manifest: dict[str, Any], harness: str, event: str
) -> set[str]:
    """Return the set of recorded hashes for *harness*+*event*."""
    install = manifest.get("installs", {}).get(harness, {})
    return set(install.get("hook_hashes", {}).get(event, []))


def _record_manifest(
    manifest: dict[str, Any],
    harness: str,
    event: str,
    entry: dict[str, Any],
) -> None:
    """Record a hook entry's hash in the manifest."""
    installs = manifest.setdefault("installs", {})
    install = installs.setdefault(harness, {})
    hook_hashes = install.setdefault("hook_hashes", {})
    hashes = hook_hashes.setdefault(event, [])
    h = _compute_entry_hash(entry)
    if h not in hashes:
        hashes.append(h)


def _clear_manifest_event(
    manifest: dict[str, Any], harness: str, event: str
) -> None:
    """Remove all recorded hashes for *harness*+*event*."""
    install = manifest.get("installs", {}).get(harness, {})
    install.get("hook_hashes", {}).pop(event, None)


def _is_cairn_hook_entry(
    entry: dict[str, Any],
    *,
    harness: str = "",
    event: str = "",
    manifest: dict[str, Any] | None = None,
) -> bool:
    """Check if *entry* is a hook cairn owns.

    Ownership is determined by (in order):

    1. **Manifest hash match** — the entry's SHA-256 is in the manifest
       for this *harness*+*event*.  This catches entries from previous
       cairn versions whose command string may have changed.
    2. **Expected entry hash match** — the entry exactly matches what
       cairn would create right now for *harness*+*event*.
    3. **Exact command fallback** — the entry's command string is one
       of the known cairn commands (exact match, not substring).
    4. **Legacy script fallback** — ``python[3] /path/cairn_hook.py``,
       gated on *harness* being specified.

    This replaces the former substring check
    (``"cairn._claude_hook" in cmd``) which could falsely identify
    user-authored hooks that merely reference cairn.
    """
    if not isinstance(entry, dict):
        return False

    raw_hooks = entry.get("hooks", [])
    if not isinstance(raw_hooks, list):
        return False
    hook_list = [h for h in raw_hooks if isinstance(h, dict)]

    entry_hash = _compute_entry_hash(entry)

    # 1. Manifest match (handles version changes)
    if manifest is not None and harness:
        if entry_hash in _manifest_hashes(manifest, harness, event):
            return True

    # 2. Expected entry match (current version)
    if harness and event:
        expected_hash = _expected_entry_hash(harness, event)
        if expected_hash is not None and entry_hash == expected_hash:
            return True

    # 3. Fallback: exact command match (not substring)
    if harness:
        known_cmds = _cairn_hook_commands(harness)
        for h in hook_list:
            cmd = h.get("command", "")
            if cmd in known_cmds:
                return True

    # 4. Legacy script fallback (pre-module invocation).
    # Catches old-format installs: ``python[3] /path/cairn_hook.py <action>``.
    # Gated on *harness* to avoid false positives when called without
    # context.  Uses exact basename match (``Path(t).name == "cairn_hook.py"``)
    # — a user script named ``evil_cairn_hook.py`` will NOT match.
    if harness:
        for h in hook_list:
            cmd = h.get("command", "")
            tokens = cmd.split()
            if len(tokens) >= 2 and tokens[0] in ("python", "python3"):
                if any(Path(t).name == "cairn_hook.py" for t in tokens[1:]):
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
    # OpenCode session attestation is default-on (Plan 008/009). The plugin
    # gates the session.started attestation on CAIRN_ATTEST_ON_START; leaving
    # it unset would make session attestation silently off. We write "1" so
    # the default install is default-on, while the no-clobber loop below
    # respects an explicit existing value (including "0" / "false").
    if harness == "opencode":
        vals["CAIRN_ATTEST_ON_START"] = "1"
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
    try:
        data = _load_json(path)
    except ConfigLoadError as exc:
        result.status = InstallStatus.FAILED
        result.actions.append(
            InstallAction(
                "error",
                str(path),
                f"refused to clobber unreadable config: {exc.reason}",
            )
        )
        return result

    manifest = _load_manifest()

    if uninstall:
        result = _uninstall_claude(
            path, data, dry_run=dry_run, result=result, manifest=manifest
        )
        if not dry_run and not result.no_op:
            _save_manifest(manifest)
        return result

    env = data.setdefault("env", {})
    if not isinstance(env, dict):
        env = {}
        data["env"] = env
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        data["hooks"] = hooks
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
        if not isinstance(event_hooks, list):
            event_hooks = []
            hooks[event] = event_hooks
        already = any(
            _is_cairn_hook_entry(
                e, harness="claude", event=event, manifest=manifest
            )
            for e in event_hooks
            if isinstance(e, dict)
        )
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
        _record_manifest(manifest, "claude", event, new_entry)
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
        _save_manifest(manifest)

    return result


def _uninstall_claude(
    path: Path,
    data: dict[str, Any],
    *,
    dry_run: bool,
    result: InstallResult,
    manifest: dict[str, Any] | None = None,
) -> InstallResult:
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
    env = data.get("env", {})
    if not isinstance(env, dict):
        env = {}
    changed = False

    for event in HOOK_EVENTS:
        event_hooks = hooks.get(event, [])
        if not isinstance(event_hooks, list):
            continue
        original_len = len(event_hooks)
        event_hooks = [
            e
            for e in event_hooks
            if not (
                isinstance(e, dict)
                and _is_cairn_hook_entry(
                    e, harness="claude", event=event, manifest=manifest
                )
            )
        ]
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
            if manifest is not None and not dry_run:
                _clear_manifest_event(manifest, "claude", event)

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
# Codex (Plan 011)
# ----------------------------------------------------------------------


def _codex_hooks_path() -> Path:
    """Where cairn writes Codex hook registrations: ``$CODEX_HOME/hooks.json``
    (``~/.codex/hooks.json`` when ``CODEX_HOME`` is unset).  ``$CAIRN_CODEX_HOOKS``
    overrides it for tests/isolation."""
    override = os.environ.get("CAIRN_CODEX_HOOKS")
    if override:
        return Path(override)
    home = os.environ.get("CODEX_HOME")
    base = Path(home) if home else Path.home() / ".codex"
    return base / "hooks.json"


def _install_codex(
    cfg: Any,
    *,
    dry_run: bool,
    uninstall: bool,
    user: str | None,
) -> InstallResult:
    """Merge cairn's hook group into Codex's ``hooks.json``.

    Hooks-only: unlike Claude, **no env vars or secrets are written into Codex
    config** (Plan 007 Decision 3 / Plan 011 Decision 6). The hook processes read
    REGISTA_DSN / PRINCIPAL_ID / harness identity from the ambient environment,
    and the adapter detects the live Codex version at attestation time. Existing
    user hooks and unrelated config are preserved (surgical merge).
    """
    path = _codex_hooks_path()
    result = InstallResult(harness="codex", user=user)
    try:
        data = _load_json(path)
    except ConfigLoadError as exc:
        result.status = InstallStatus.FAILED
        result.actions.append(
            InstallAction(
                "error",
                str(path),
                f"refused to clobber unreadable config: {exc.reason}",
            )
        )
        return result

    manifest = _load_manifest()

    if uninstall:
        result = _uninstall_codex(
            path, data, dry_run=dry_run, result=result, manifest=manifest
        )
        if not dry_run and not result.no_op:
            _save_manifest(manifest)
        return result

    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        data["hooks"] = hooks
    changed = False

    for event, action in CODEX_HOOK_EVENTS.items():
        event_hooks = hooks.setdefault(event, [])
        if not isinstance(event_hooks, list):
            event_hooks = []
            hooks[event] = event_hooks
        if any(
            _is_cairn_hook_entry(e, harness="codex", event=event, manifest=manifest)
            for e in event_hooks
            if isinstance(e, dict)
        ):
            continue
        inner = {
            "type": "command",
            "command": f"{CAIRN_CODEX_HOOK_COMMAND} {action}",
            "commandWindows": f"{CAIRN_CODEX_HOOK_COMMAND_WINDOWS} {action}",
            "timeout": 10,
        }
        new_entry: dict[str, Any] = {"hooks": [inner]}
        if event in _CODEX_TOOL_EVENTS:
            new_entry = {"matcher": "*", "hooks": [inner]}
        event_hooks.append(new_entry)
        changed = True
        _record_manifest(manifest, "codex", event, new_entry)
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
        _save_manifest(manifest)

    return result


def _uninstall_codex(
    path: Path,
    data: dict[str, Any],
    *,
    dry_run: bool,
    result: InstallResult,
    manifest: dict[str, Any] | None = None,
) -> InstallResult:
    hooks = data.get("hooks", {})
    changed = False
    if isinstance(hooks, dict):
        for event in CODEX_HOOK_EVENTS:
            event_hooks = hooks.get(event, [])
            if not isinstance(event_hooks, list):
                continue
            kept = [
                e
                for e in event_hooks
                if not (
                    isinstance(e, dict)
                    and _is_cairn_hook_entry(
                        e, harness="codex", event=event, manifest=manifest
                    )
                )
            ]
            if len(kept) < len(event_hooks):
                changed = True
                result.actions.append(
                    InstallAction(
                        "merge_json",
                        str(path),
                        f"remove cairn {event} hook",
                        keys=[f"hooks.{event}"],
                    )
                )
                if kept:
                    hooks[event] = kept
                else:
                    hooks.pop(event, None)
                if manifest is not None and not dry_run:
                    _clear_manifest_event(manifest, "codex", event)

    if not result.actions:
        result.no_op = True
    elif not dry_run and changed:
        if not data.get("hooks"):
            data.pop("hooks", None)
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
    try:
        data = _load_json(path)
    except ConfigLoadError as exc:
        result.status = InstallStatus.FAILED
        result.actions.append(
            InstallAction(
                "error",
                str(path),
                f"refused to clobber unreadable config: {exc.reason}",
            )
        )
        return result

    if uninstall:
        return _uninstall_opencode(path, data, dry_run=dry_run, result=result)

    env = data.setdefault("env", {})
    if not isinstance(env, dict):
        env = {}
        data["env"] = env
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
        plugin_data = data.setdefault("plugin", {})
        if not isinstance(plugin_data, dict):
            plugin_data = {}
            data["plugin"] = plugin_data
        plugins = plugin_data.setdefault("sources", [])
        if not isinstance(plugins, list):
            plugins = []
            plugin_data["sources"] = plugins
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
        else:
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
    if not isinstance(env, dict):
        env = {}
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
        if not isinstance(plugin_data, dict):
            plugin_data = {}
        sources = plugin_data.get("sources", [])
        if not isinstance(sources, list):
            sources = []
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
    """Return the path to the packaged OpenCode plugin.

    In a built wheel, hatchling's ``force-include`` places ``integrations/``
    inside the ``cairn`` package directory, so the plugin lives next to the
    Python modules. In a source checkout, ``integrations/`` is at the repo
    root. This mirrors the hermes plugin discovery path.
    """
    pkg_path = Path(__file__).resolve().parent / "integrations" / "opencode" / "index.js"
    if pkg_path.is_file():
        return pkg_path
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
        # ``all`` is the stable suite set.  Component-private targets such as
        # Hermes remain explicitly selectable but never enter this expansion.
        targets = ["claude", "opencode"]
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
        elif t == "codex":
            results.append(_install_codex(cfg, dry_run=dry_run, uninstall=uninstall, user=user))
        elif t == "agy":
            results.append(InstallResult(
                harness=t,
                user=user,
                status=InstallStatus.UNSUPPORTED,
                actions=[
                    InstallAction(
                        "unsupported",
                        "",
                        f"{t} adapter is not implemented; no harness wiring was changed",
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
        if r.status is InstallStatus.UNSUPPORTED:
            status = "unsupported (not wired)"
        elif r.status is InstallStatus.DEGRADED:
            status = "degraded"
        elif r.status is InstallStatus.FAILED:
            status = "failed"
        elif r.no_op:
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


def results_succeeded(results: list[InstallResult]) -> bool:
    """Return whether every result represents a successful installation state."""

    # Cairn has no suite-tier context here. Degraded therefore fails closed;
    # only a caller with an explicit tier policy may choose to permit it.
    return all(result.status is InstallStatus.INSTALLED for result in results)
