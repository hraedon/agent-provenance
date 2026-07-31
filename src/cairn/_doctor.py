"""``cairn doctor`` — health check conforming to the suite shape.

Emits ``{component, version, ok, degraded, regista:{reachable, project,
chain_ok}, checks:[…]}`` so the suite-doctor umbrella (which reads the top-level
``ok`` boolean) can aggregate it alongside the other components. Check status
follows regista's canonical vocabulary: ``ok``/``warn``/``fail``/``skip``.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.CRITICAL)
try:
    import structlog

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
except ImportError:
    pass

from . import __version__ as _cairn_version  # noqa: E402
from ._config import resolve_config  # noqa: E402
from ._install import (  # noqa: E402
    CODEX_HOOK_EVENTS,
    HOOK_EVENTS,
    _claude_settings_path,
    _codex_hooks_path,
    _find_opencode_plugin,
    _is_cairn_hook_entry,
    _load_manifest,
    _opencode_config_path,
)


def _check_config(cfg: Any) -> dict[str, Any]:
    missing = cfg.missing()
    detail = (
        "all required config present"
        if not missing
        else f"missing: {', '.join(missing)}"
    )
    return {
        "name": "config",
        "status": "ok" if not missing else "fail",
        "detail": detail,
    }


def _check_key_file(cfg: Any) -> dict[str, Any]:
    if cfg.key_ref:
        try:
            from regista._secrets import resolve as resolve_secret
            resolve_secret(cfg.key_ref)
            return {
                "name": "key_file",
                "status": "ok",
                "detail": f"key_ref: {cfg.key_ref} (resolvable)",
            }
        except Exception as exc:
            return {
                "name": "key_file",
                "status": "fail",
                "detail": f"key_ref {cfg.key_ref!r} not resolvable: {exc}",
            }
    if not cfg.key_path:
        return {"name": "key_file", "status": "fail", "detail": "no key path configured"}
    path = cfg.key_path
    if not os.path.isfile(path):
        return {"name": "key_file", "status": "fail", "detail": f"key file not found: {path}"}
    try:
        data = json.loads(open(path).read())
        keys = data.get("keys", [])
        if not keys:
            return {"name": "key_file", "status": "fail", "detail": "key file has no keys"}
        return {
            "name": "key_file",
            "status": "ok",
            "detail": f"{len(keys)} key(s), active={keys[0].get('key_id', '?')}",
        }
    except Exception as exc:
        return {"name": "key_file", "status": "fail", "detail": f"cannot read key file: {exc}"}


def _verify_chain(sub: Any) -> tuple[str, bool | None]:
    """Use regista's canonical replay API to determine chain integrity.

    Returns ``(chain_state, chain_ok)``. ``chain_ok`` is ``True`` when the
    replay reports no drift and no halted events, ``False`` when drift or
    a halt is detected, and ``None`` when the verification API is unavailable
    or an error prevented a verdict. ``chain_state`` is an honest string label
    (``verified``, ``drift``, ``unsupported``, ``error``) for callers and
    reports.
    """
    if not hasattr(sub, "replay"):
        return "unsupported", None
    try:
        report = sub.replay()
    except Exception:
        return "error", None
    if report.replayed_drift > 0 or report.halted > 0:
        return "drift", False
    return "verified", True


@contextlib.contextmanager
def _open_regista(cfg: Any) -> Any:
    """Open a regista client for the configured store, handling key-ref keys.

    Yields the client; closes it (and removes any temp key file) on exit.
    """
    from regista import Regista

    key_path = cfg.key_path
    temp_key: str | None = None
    if not key_path and cfg.key_ref:
        fd, key_path = tempfile.mkstemp(suffix=".json", prefix="cairn-doctor-")
        temp_key = key_path
        os.chmod(key_path, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({
                "keys": [{
                    "key_id": "cairn-doctor",
                    "scheme": "hmac-sha256",
                    "secret_ref": cfg.key_ref,
                }]
            }, f)
    try:
        sub = Regista(dsn=cfg.dsn, project=cfg.project, hmac_key_path=key_path)
        try:
            yield sub
        finally:
            sub.close()
    finally:
        if temp_key is not None:
            os.unlink(temp_key)


def _check_regista(cfg: Any) -> tuple[dict[str, Any], Any]:
    """Probe the regista store for availability.

    Returns ``(check, newest_event_ts)``. This is a bounded, read-only
    reachability probe — it must complete within the suite umbrella's
    per-probe timeout, so it never replays the chain (WI-030). The chain
    verdict comes from the last recorded ``cairn integrity`` run instead
    (see ``_check_chain_integrity``).
    """
    if not cfg.is_configured:
        return (
            {"name": "regista", "status": "skip", "detail": "not configured"},
            None,
        )
    try:
        with _open_regista(cfg) as sub:
            events = sub.read_events(limit=1)
            newest_ts = events[0].timestamp if events else None
            return (
                {
                    "name": "regista",
                    "status": "ok",
                    "detail": f"reachable, {len(events)} event(s) in project '{cfg.project}'",
                },
                newest_ts,
            )
    except Exception as exc:
        return (
            {"name": "regista", "status": "fail", "detail": f"unreachable: {exc}"},
            None,
        )


def _check_harness_wired(cfg: Any, *, required: bool = True) -> dict[str, Any]:
    path = _claude_settings_path()
    if not path.is_file():
        return {
            "name": "harness_wired",
            "status": "fail" if required else "skip",
            "detail": f"Claude Code not configured (no settings.json at {path})",
        }
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {"name": "harness_wired", "status": "fail", "detail": f"cannot parse {path}"}

    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
    manifest = _load_manifest()
    missing_events: list[str] = []
    for event in HOOK_EVENTS:
        event_hooks = hooks.get(event, [])
        if not isinstance(event_hooks, list):
            event_hooks = []
        if not any(
            _is_cairn_hook_entry(
                e, harness="claude", event=event, manifest=manifest
            )
            for e in event_hooks
            if isinstance(e, dict)
        ):
            missing_events.append(event)

    env = data.get("env", {})
    if not isinstance(env, dict):
        env = {}
    has_dsn = bool(env.get("REGISTA_DSN") or env.get("CAIRN_DSN"))
    has_project = bool(env.get("CAIRN_PROJECT"))

    if missing_events:
        return {
            "name": "harness_wired",
            "status": "fail",
            "detail": f"missing hooks: {', '.join(missing_events)}",
        }
    if not has_dsn or not has_project:
        missing = []
        if not has_dsn:
            missing.append("DSN")
        if not has_project:
            missing.append("PROJECT")
        return {
            "name": "harness_wired",
            "status": "warn",
            "detail": f"hooks present but env missing: {', '.join(missing)}",
        }
    return {
        "name": "harness_wired",
        "status": "ok",
        "detail": f"hooks + env configured in {path}",
    }


def _check_opencode_harness_wired(cfg: Any) -> dict[str, Any]:
    """Validate OpenCode wiring: plugin source registered + env present."""
    configured_for_opencode = str(getattr(cfg, "harness_name", "")).lower() == "opencode"
    path = _opencode_config_path()
    if not path.is_file():
        if configured_for_opencode:
            return {
                "name": "opencode_harness_wired",
                "status": "fail",
                "detail": f"OpenCode selected but no config file at {path}",
            }
        return {
            "name": "opencode_harness_wired",
            "status": "skip",
            "detail": f"OpenCode not configured (no config at {path})",
        }
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {
            "name": "opencode_harness_wired",
            "status": "fail",
            "detail": f"cannot parse {path}",
        }

    env = data.get("env", {}) if isinstance(data, dict) else {}
    if not isinstance(env, dict):
        env = {}
    has_dsn = bool(env.get("REGISTA_DSN") or env.get("CAIRN_DSN"))
    has_project = bool(env.get("CAIRN_PROJECT"))

    plugin_data = data.get("plugin", {}) if isinstance(data, dict) else {}
    if not isinstance(plugin_data, dict):
        plugin_data = {}
    sources = plugin_data.get("sources", [])
    if not isinstance(sources, list):
        sources = []

    plugin_path = _find_opencode_plugin()
    plugin_registered = False
    if plugin_path is not None:
        plugin_str = str(plugin_path)
        for s in sources:
            if isinstance(s, dict) and s.get("source") == plugin_str:
                plugin_registered = True
            elif isinstance(s, str) and s == plugin_str:
                plugin_registered = True

    if plugin_path is None:
        if configured_for_opencode:
            return {
                "name": "opencode_harness_wired",
                "status": "fail",
                "detail": "cairn OpenCode plugin cannot be located in the installed package",
            }
        return {
            "name": "opencode_harness_wired",
            "status": "skip",
            "detail": "cairn OpenCode plugin not found in package",
        }

    if plugin_registered and has_dsn and has_project:
        return {
            "name": "opencode_harness_wired",
            "status": "ok",
            "detail": f"cairn plugin + env configured in {path}",
        }
    if plugin_registered:
        missing = []
        if not has_dsn:
            missing.append("DSN")
        if not has_project:
            missing.append("PROJECT")
        return {
            "name": "opencode_harness_wired",
            "status": "warn",
            "detail": f"plugin registered but env missing: {', '.join(missing)}",
        }
    if configured_for_opencode:
        return {
            "name": "opencode_harness_wired",
            "status": "fail",
            "detail": f"OpenCode selected but cairn plugin not registered in {path}",
        }
    return {
        "name": "opencode_harness_wired",
        "status": "skip",
        "detail": "OpenCode integration not configured",
    }


def _codex_plugin_state() -> tuple[str, str | None]:
    """Return ``(state, version)`` for the component-owned ``cairn`` plugin.

    Codex's stable machine-readable surface is ``plugin list --json``.  Hook
    trust is deliberately not inferred here because Codex exposes that only
    through the interactive ``/hooks`` browser.
    """
    if shutil.which("codex") is None:
        return "cli_absent", None
    try:
        result = subprocess.run(
            ["codex", "plugin", "list", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown", None
    if result.returncode != 0:
        return "unknown", None
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return "unknown", None
    installed = payload.get("installed", []) if isinstance(payload, dict) else []
    if not isinstance(installed, list):
        return "unknown", None
    for entry in installed:
        if not isinstance(entry, dict) or entry.get("name") != "cairn":
            continue
        version = entry.get("version")
        if entry.get("enabled") is False:
            return "disabled", version if isinstance(version, str) else None
        return "enabled", version if isinstance(version, str) else None
    return "absent", None


def _check_codex_harness_wired(cfg: Any) -> dict[str, Any]:
    """Validate direct or plugin-owned Codex hook wiring without false trust.

    Direct ``hooks.json`` installation and plugin installation are alternative
    delivery paths.  Having both active would execute Cairn twice for each
    matching event, so doctor treats that as a configuration error.
    """
    path = _codex_hooks_path()
    direct_present = path.is_file()
    direct_cairn_present = False
    direct_ok = False
    missing_events: list[str] = []
    if direct_present:
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return {
                "name": "codex_harness_wired",
                "status": "fail",
                "detail": f"cannot parse {path}",
            }
        hooks = data.get("hooks", {}) if isinstance(data, dict) else {}
        if not isinstance(hooks, dict):
            hooks = {}
        manifest = _load_manifest()
        for event in CODEX_HOOK_EVENTS:
            entries = hooks.get(event, [])
            found = isinstance(entries, list) and any(
                _is_cairn_hook_entry(
                    entry,
                    harness="codex",
                    event=event,
                    manifest=manifest,
                )
                for entry in entries
                if isinstance(entry, dict)
            )
            direct_cairn_present = direct_cairn_present or found
            if not found:
                missing_events.append(event)
        direct_ok = direct_cairn_present and not missing_events

    plugin_state, plugin_version = _codex_plugin_state()
    plugin_enabled = plugin_state == "enabled"
    configured_for_codex = str(getattr(cfg, "harness_name", "")).lower() == "codex"

    if direct_ok and plugin_enabled:
        return {
            "name": "codex_harness_wired",
            "status": "fail",
            "detail": (
                "Cairn is configured through both direct hooks.json and the enabled "
                "plugin; remove one path to prevent duplicate attestations"
            ),
        }
    if direct_cairn_present and missing_events:
        return {
            "name": "codex_harness_wired",
            "status": "fail",
            "detail": f"direct Codex wiring missing hooks: {', '.join(missing_events)}",
        }
    if plugin_state == "disabled":
        return {
            "name": "codex_harness_wired",
            "status": "fail",
            "detail": f"Cairn Codex plugin v{plugin_version or '?'} is installed but disabled",
        }
    if direct_ok:
        return {
            "name": "codex_harness_wired",
            "status": "ok",
            "detail": f"direct Codex hooks configured in {path}",
        }
    if plugin_enabled:
        return {
            "name": "codex_harness_wired",
            "status": "ok",
            "detail": f"Cairn Codex plugin v{plugin_version or '?'} installed and enabled",
        }
    if configured_for_codex:
        detail = "Codex selected but neither direct Cairn hooks nor the Cairn plugin are active"
        if plugin_state == "unknown":
            detail += " (plugin state could not be read)"
        return {"name": "codex_harness_wired", "status": "fail", "detail": detail}
    return {
        "name": "codex_harness_wired",
        "status": "skip",
        "detail": "Codex integration not configured",
    }


def _codex_hooks_feature_enabled() -> bool | None:
    """Read Codex's effective public feature listing for the ``hooks`` flag."""
    if shutil.which("codex") is None:
        return None
    try:
        result = subprocess.run(
            ["codex", "features", "list"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields and fields[0] == "hooks" and fields[-1] in {"true", "false"}:
            return fields[-1] == "true"
    return None


def _managed_only_hooks_visible() -> bool:
    """Detect visible local policy that suppresses user/plugin hooks.

    Cloud/MDM policy is not guaranteed to be readable as a local file, so this
    check is intentionally narrow and the trust check retains an uncertainty
    warning even when this returns false.
    """
    codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    candidates = [codex_home / "requirements.toml"]
    if os.name != "nt":
        candidates.append(Path("/etc/codex/requirements.toml"))
    for path in candidates:
        if not path.is_file():
            continue
        try:
            data = tomllib.loads(path.read_text())
        except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
            continue
        if data.get("allow_managed_hooks_only") is True:
            return True
    return False


def _check_codex_hook_policy(*, wired: bool) -> dict[str, Any]:
    if not wired:
        return {
            "name": "codex_hook_policy",
            "status": "skip",
            "detail": "Codex integration not wired",
        }
    enabled = _codex_hooks_feature_enabled()
    if enabled is False:
        return {
            "name": "codex_hook_policy",
            "status": "fail",
            "detail": "Codex hooks feature is disabled by effective configuration",
        }
    if _managed_only_hooks_visible():
        return {
            "name": "codex_hook_policy",
            "status": "fail",
            "detail": "visible Codex policy allows managed hooks only; Cairn hooks are skipped",
        }
    if enabled is None:
        return {
            "name": "codex_hook_policy",
            "status": "warn",
            "detail": "could not verify the effective Codex hooks feature state",
        }
    return {
        "name": "codex_hook_policy",
        "status": "ok",
        "detail": "Codex hooks feature is enabled",
    }


def _check_codex_hook_trust(*, wired: bool) -> dict[str, Any]:
    if not wired:
        return {
            "name": "codex_hook_trust",
            "status": "skip",
            "detail": "Codex integration not wired",
        }
    return {
        "name": "codex_hook_trust",
        "status": "warn",
        "detail": (
            "hook trust is not exposed by the Codex CLI; review the exact Cairn "
            "definitions with /hooks before relying on capture"
        ),
    }


def _check_codex_activity(*, wired: bool) -> dict[str, Any]:
    """Report local, non-secret proof of successful hook-to-bridge activity."""
    if not wired:
        return {
            "name": "codex_hook_activity",
            "status": "skip",
            "detail": "Codex integration not wired",
        }
    cfg = resolve_config()
    base = Path(cfg.state_dir)
    degradation_count = 0
    try:
        for path in base.glob("*/degradation.log"):
            if not path.is_file():
                continue
            try:
                for line in path.read_text().splitlines():
                    record = json.loads(line)
                    if isinstance(record, dict) and str(record.get("action", "")).startswith(
                        "codex:"
                    ):
                        degradation_count += 1
                        break
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                continue
    except OSError:
        degradation_count = 0
    if degradation_count:
        return {
            "name": "codex_hook_activity",
            "status": "fail",
            "detail": f"{degradation_count} session degradation log(s) require review",
        }

    marker = base / "codex-health.json"
    if not marker.is_file():
        return {
            "name": "codex_hook_activity",
            "status": "warn",
            "detail": "wired but no successful Codex hook activity has been observed locally",
        }
    try:
        payload = json.loads(marker.read_text())
        timestamp = payload.get("last_success_at")
        event = payload.get("event")
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {
            "name": "codex_hook_activity",
            "status": "warn",
            "detail": "Codex activity marker is unreadable",
        }
    if not isinstance(timestamp, str) or not isinstance(event, str):
        return {
            "name": "codex_hook_activity",
            "status": "warn",
            "detail": "Codex activity marker is malformed",
        }
    return {
        "name": "codex_hook_activity",
        "status": "ok",
        "detail": f"successful {event} bridge activity observed at {timestamp}",
    }


_INTEGRITY_VERDICT_FILENAME = "integrity-verdict.json"


def _integrity_verdict_path(cfg: Any) -> Path:
    # Durable state dir, not the tmp-backed session state_dir — a recorded
    # drift FAIL must survive reboot (WI-030 review M2).
    return Path(cfg.integrity_dir) / _INTEGRITY_VERDICT_FILENAME


def _store_binding(cfg: Any) -> str:
    """Digest binding a verdict to the store it certified (WI-030 review M1).

    A verdict recorded against one DSN/project must never be reported for
    another. The digest avoids persisting the raw DSN (it may embed
    credentials); collision resistance beyond accidental mismatch is not the
    goal — the marker is operator-trusted state, not an attestation.
    """
    material = f"{cfg.dsn or ''}\n{cfg.project or ''}".encode()
    return hashlib.sha256(material).hexdigest()[:16]


def _load_integrity_verdict(cfg: Any) -> dict[str, Any] | None:
    """Read the verdict recorded by the last ``cairn integrity`` run.

    Returns ``None`` when no verdict has been recorded. A malformed file
    returns ``{"chain_state": "unreadable"}`` so doctor can surface it.
    """
    path = _integrity_verdict_path(cfg)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or "chain_state" not in data:
            return {"chain_state": "unreadable"}
        return data
    except Exception:
        return {"chain_state": "unreadable"}


def _check_chain_integrity(cfg: Any) -> tuple[dict[str, Any], str | None, bool | None]:
    """Honest health for the canonical replay chain verdict — without replaying.

    Doctor is a bounded availability probe; the full-chain replay is owned by
    ``cairn integrity`` (WI-030), which records its verdict in the state dir.
    This check reports that recorded verdict: drift or replay error is a fail
    (top-level ``ok`` false, CLI exits nonzero), a verdict older than
    ``integrity_max_age_hours`` is a warning, and a never-run replay is an
    honest skip — never a claimed pass.

    Returns ``(check, chain_state, chain_ok)`` where the latter two feed the
    report's ``regista`` block.
    """
    verdict = _load_integrity_verdict(cfg)
    if verdict is None:
        return (
            {
                "name": "chain_integrity",
                "status": "skip",
                "detail": (
                    "full chain replay is not part of routine health (WI-030); "
                    "no verdict recorded yet — run `cairn integrity` or schedule it"
                ),
            },
            "never_run",
            None,
        )

    chain_state = verdict.get("chain_state")
    checked_at = verdict.get("checked_at")

    # A verdict certifies exactly one store+project; never report it for
    # another (WI-030 review M1). Markers predating the binding field are
    # treated as unbound and must be re-recorded.
    if chain_state in ("verified", "drift", "error") and verdict.get(
        "store_binding"
    ) != _store_binding(cfg):
        return (
            {
                "name": "chain_integrity",
                "status": "skip",
                "detail": (
                    "recorded verdict is for a different store or project "
                    "(or predates store binding); run `cairn integrity` "
                    "against this configuration"
                ),
            },
            "unbound",
            None,
        )

    if chain_state == "verified":
        age_hours: float | None = None
        if isinstance(checked_at, str):
            try:
                checked_dt = datetime.datetime.fromisoformat(checked_at)
                if checked_dt.tzinfo is None:
                    checked_dt = checked_dt.replace(tzinfo=datetime.UTC)
                age_hours = (
                    datetime.datetime.now(datetime.UTC) - checked_dt
                ).total_seconds() / 3600.0
            except ValueError:
                age_hours = None
        max_age = cfg.integrity_max_age_hours
        if age_hours is None:
            return (
                {
                    "name": "chain_integrity",
                    "status": "warn",
                    "detail": (
                        "recorded integrity verdict has no readable timestamp; "
                        "re-run `cairn integrity`"
                    ),
                },
                "verified",
                True,
            )
        if age_hours < 0:
            return (
                {
                    "name": "chain_integrity",
                    "status": "warn",
                    "detail": (
                        f"recorded integrity verdict is timestamped in the future "
                        f"({checked_at}) — clock skew or a hand-edited marker; "
                        "re-run `cairn integrity`"
                    ),
                },
                "verified",
                None,
            )
        if max_age > 0 and age_hours > max_age:
            return (
                {
                    "name": "chain_integrity",
                    "status": "warn",
                    "detail": (
                        f"last full replay verified at {checked_at} — older than "
                        f"{max_age:g}h; re-run `cairn integrity` or schedule it"
                    ),
                },
                "verified",
                True,
            )
        return (
            {
                "name": "chain_integrity",
                "status": "ok",
                "detail": (
                    f"canonical replay verified no drift or halted events "
                    f"at {checked_at} (cairn integrity)"
                ),
            },
            "verified",
            True,
        )
    if chain_state == "drift":
        return (
            {
                "name": "chain_integrity",
                "status": "fail",
                "detail": (
                    f"canonical replay detected chain drift or halted events "
                    f"at {checked_at or 'unknown time'} (cairn integrity)"
                ),
            },
            "drift",
            False,
        )
    if chain_state == "error":
        return (
            {
                "name": "chain_integrity",
                "status": "fail",
                "detail": (
                    f"chain replay failed at {checked_at or 'unknown time'}; "
                    "integrity verdict is unknown (cairn integrity)"
                ),
            },
            "error",
            None,
        )
    if chain_state == "unsupported":
        return (
            {
                "name": "chain_integrity",
                "status": "warn",
                "detail": "regista version does not expose the canonical replay API",
            },
            "unsupported",
            None,
        )
    return (
        {
            "name": "chain_integrity",
            "status": "warn",
            "detail": "recorded integrity verdict is unreadable; re-run `cairn integrity`",
        },
        "unreadable",
        None,
    )


def _check_bridge() -> dict[str, Any]:
    bridge = shutil.which("cairn-bridge")
    if bridge:
        return {"name": "bridge", "status": "ok", "detail": f"cairn-bridge at {bridge}"}
    return {
        "name": "bridge",
        "status": "warn",
        "detail": "cairn-bridge not on PATH (hooks use python3 -m cairn hook modules)",
    }


def _check_content_encryption(cfg: Any) -> dict[str, Any]:
    """Check content-encryption stance (Plan 010 WI-3.1).

    When content encryption is off, emit a WARNING — the log now holds
    every secret/PII that passed through the session.
    """
    stance = getattr(cfg, "content_encryption", "on")
    if stance == "off":
        return {
            "name": "content_encryption",
            "status": "warn",
            "detail": (
                "Content encryption is OFF — session content is stored in "
                "plaintext. The log itself is now a sensitive artifact."
            ),
        }
    if stance == "external":
        return {
            "name": "content_encryption",
            "status": "ok",
            "detail": "Content encryption delegated to lower layer (external)",
        }
    key_ref = getattr(cfg, "content_key_ref", None) or getattr(cfg, "content_key_path", None)
    if not key_ref:
        return {
            "name": "content_encryption",
            "status": "warn",
            "detail": (
                "Content encryption is ON but no content key configured "
                "(CAIRN_CONTENT_KEY_REF / CAIRN_CONTENT_KEY_PATH). "
                "Content capture will store plaintext until a key is set."
            ),
        }
    return {
        "name": "content_encryption",
        "status": "ok",
        "detail": f"Content encryption ON (key: {key_ref[:40]}...)",
    }


def _newest_local_session_activity() -> float | None:
    """Newest mtime among local Claude Code session transcripts.

    Claude Code writes one ``<session-uuid>.jsonl`` per session under
    ``~/.claude/projects/<encoded-cwd>/``.  The newest mtime is evidence
    that sessions ran, independent of whether anything attested.
    ``CAIRN_CLAUDE_PROJECTS`` overrides the base directory (tests, or a
    non-default harness home).
    """
    base = os.environ.get("CAIRN_CLAUDE_PROJECTS") or os.path.join(
        os.path.expanduser("~"), ".claude", "projects"
    )
    newest: float | None = None
    try:
        with os.scandir(base) as projects:
            for proj in projects:
                if not proj.is_dir():
                    continue
                try:
                    with os.scandir(proj.path) as files:
                        for f in files:
                            if not f.name.endswith(".jsonl"):
                                continue
                            mtime = f.stat().st_mtime
                            if newest is None or mtime > newest:
                                newest = mtime
                except OSError:
                    continue
    except OSError:
        return None
    return newest


def _check_attestation_freshness(
    cfg: Any, newest_event_ts: Any, *, regista_ok: bool
) -> dict[str, Any]:
    """WI-4.1 — silence is a finding.

    "Wired but not attesting" must be detectable by doctor, not discovered
    by querying the store by hand a week later.  Sessions ran locally
    within the window (transcript mtimes) but no attestation landed in the
    store within the window → fail.  The umbrella already reds out on
    unconfigured cairn; this makes "configured but silent" equally loud.
    """
    name = "attestation_freshness"
    if not cfg.is_configured:
        return {"name": name, "status": "skip", "detail": "not configured"}
    if not regista_ok:
        return {
            "name": name,
            "status": "skip",
            "detail": "regista unreachable — cannot read last attestation",
        }

    raw_window = os.environ.get("CAIRN_MAX_ATTESTATION_AGE_HOURS", "24")
    try:
        window_hours = float(raw_window)
    except ValueError:
        window_hours = 24.0
    window_secs = window_hours * 3600

    newest_local = _newest_local_session_activity()
    if newest_local is None:
        return {
            "name": name,
            "status": "skip",
            "detail": "no local session transcripts found — nothing to correlate",
        }

    now = datetime.datetime.now(datetime.UTC).timestamp()
    if newest_local < now - window_secs:
        return {
            "name": name,
            "status": "ok",
            "detail": f"no sessions ran within the last {window_hours:g}h",
        }

    event_epoch: float | None = None
    if newest_event_ts is not None:
        ts = newest_event_ts
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=datetime.UTC)
        event_epoch = ts.timestamp()

    if event_epoch is not None and event_epoch >= now - window_secs:
        return {
            "name": name,
            "status": "ok",
            "detail": f"attestation within the last {window_hours:g}h",
        }

    local_iso = datetime.datetime.fromtimestamp(newest_local, tz=datetime.UTC).isoformat()
    last_att = (
        datetime.datetime.fromtimestamp(event_epoch, tz=datetime.UTC).isoformat()
        if event_epoch is not None
        else "never"
    )
    return {
        "name": name,
        "status": "fail",
        "detail": (
            f"configured but silent: local session activity at {local_iso} "
            f"but last attestation {last_att} (window {window_hours:g}h) — "
            "the harness may be unhooked while config is in place"
        ),
    }


def run_doctor(*, json_output: bool = False) -> int:
    cfg = resolve_config()

    regista_check, newest_event_ts = _check_regista(cfg)
    chain_check, chain_state, chain_ok = _check_chain_integrity(cfg)
    codex_wired = _check_codex_harness_wired(cfg)
    codex_active = codex_wired["status"] in {"ok", "warn"}
    checks = [
        _check_config(cfg),
        _check_key_file(cfg),
        regista_check,
        chain_check,
        _check_harness_wired(cfg, required=not codex_active),
        _check_opencode_harness_wired(cfg),
        codex_wired,
        _check_codex_hook_policy(wired=codex_active),
        _check_codex_hook_trust(wired=codex_active),
        _check_codex_activity(wired=codex_active),
        _check_bridge(),
        _check_content_encryption(cfg),
        _check_attestation_freshness(
            cfg, newest_event_ts, regista_ok=regista_check["status"] == "ok"
        ),
    ]

    regista_reachable = regista_check["status"] == "ok"

    has_fail = any(c["status"] == "fail" for c in checks)
    has_warn = any(c["status"] == "warn" for c in checks)
    ok = not has_fail
    degraded = ok and has_warn

    report: dict[str, Any] = {
        "component": "cairn",
        "version": _cairn_version,
        "ok": ok,
        "degraded": degraded,
        "regista": {
            "reachable": regista_reachable,
            "project": cfg.project or None,
            "chain_ok": chain_ok,
            "chain_state": chain_state,
        },
        "checks": checks,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print(f"cairn doctor — v{_cairn_version}")
        regista_status = "reachable" if regista_reachable else "unreachable"
        print(f"  regista: {regista_status}, project={cfg.project or '(unset)'}")
        print()
        for c in checks:
            status = c["status"].upper()
            print(f"  [{status:4s}] {c['name']:16s} {c['detail']}")
        print()
        if ok and not degraded:
            print("  All checks passed.")
        elif degraded:
            print("  Healthy, with warnings — see above.")
        else:
            print("  Some checks failed — see above.")

    return 0 if ok else 1


def run_integrity(*, json_output: bool = False) -> int:
    """Full canonical chain replay, separated from routine health (WI-030).

    Replays the complete chain via regista's canonical ``replay`` API and
    records the verdict (bound to the configured store+project) in the
    durable integrity dir, where ``cairn doctor`` reports it without
    re-replaying. Intended for scheduled runs (e.g. alongside backups) or
    on demand — its runtime grows with production history, so it must never
    sit on the routine health path.

    Exit codes: 0 verified, 1 otherwise (drift, replay error, unsupported
    replay API, store unreachable, not configured). Only verified/drift/
    unsupported are recorded; a replay exception or unreachable store exits
    nonzero without overwriting the last real verdict, so schedulers must
    alert on this command's exit code rather than relying on doctor alone.
    """
    cfg = resolve_config()

    if not cfg.is_configured:
        report = {
            "component": "cairn",
            "version": _cairn_version,
            "ok": False,
            "chain_state": "unconfigured",
            "chain_ok": None,
            "detail": f"not configured (missing: {', '.join(cfg.missing())})",
        }
        if json_output:
            print(json.dumps(report, indent=2))
        else:
            print(f"cairn integrity — v{_cairn_version}")
            print(f"  [FAIL] {report['detail']}")
        return 1

    started = time.monotonic()
    try:
        with _open_regista(cfg) as sub:
            chain_state, chain_ok = _verify_chain(sub)
    except Exception as exc:
        report = {
            "component": "cairn",
            "version": _cairn_version,
            "ok": False,
            "chain_state": "unreachable",
            "chain_ok": None,
            "detail": f"unreachable: {exc}",
        }
        if json_output:
            print(json.dumps(report, indent=2))
        else:
            print(f"cairn integrity — v{_cairn_version}")
            print(f"  [FAIL] {report['detail']}")
        return 1
    duration = time.monotonic() - started

    checked_at = datetime.datetime.now(datetime.UTC).isoformat()
    verdict = {
        "checked_at": checked_at,
        "chain_state": chain_state,
        "chain_ok": chain_ok,
        "duration_seconds": round(duration, 3),
        "cairn_version": _cairn_version,
        "project": cfg.project,
        "store_binding": _store_binding(cfg),
    }

    # Record the verdict for doctor — atomically (and fsynced, so a crash
    # cannot leave an empty marker), so a concurrent doctor never reads a
    # half-written file. Only real chain verdicts are recorded:
    # verified/drift are verdicts, unsupported is a durable capability fact,
    # but a replay *exception* is the absence of a verdict — like an
    # unreachable store, it exits nonzero without clobbering the last real
    # verdict (WI-030 review m4). The marker is not secret; leave it
    # world-readable so a doctor running as a different user can report it.
    if chain_state in ("verified", "drift", "unsupported"):
        path = _integrity_verdict_path(cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".integrity-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(verdict, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise

    ok = chain_state == "verified" and chain_ok is True
    report = {
        "component": "cairn",
        "version": _cairn_version,
        "ok": ok,
        **verdict,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print(f"cairn integrity — v{_cairn_version}")
        detail = {
            "verified": "canonical replay verified no drift or halted events",
            "drift": "canonical replay detected chain drift or halted events",
            "error": "chain replay failed; integrity verdict is unknown",
            "unsupported": "regista version does not expose the canonical replay API",
        }.get(chain_state, chain_state)
        status = "OK" if ok else "FAIL"
        print(f"  [{status:4s}] chain_integrity   {detail}")
        if chain_state in ("verified", "drift", "unsupported"):
            print(f"  replayed in {duration:.1f}s; verdict recorded for doctor")
        else:
            print(
                f"  replay attempt took {duration:.1f}s; no verdict recorded — "
                "the last real verdict is preserved"
            )

    return 0 if ok else 1
