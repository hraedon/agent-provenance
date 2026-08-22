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
import hmac
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass, field
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
from ._config import ContentSettings, resolve_config  # noqa: E402
from ._content_crypto import content_encryption_status_for  # noqa: E402
from ._install import (  # noqa: E402
    CODEX_HOOK_EVENTS,
    HOOK_EVENTS,
    HOOK_VERIFY_FAIL,
    HOOK_VERIFY_OFF_PATH,
    HOOK_VERIFY_OK,
    _claude_settings_path,
    _codex_hooks_path,
    _find_opencode_plugin,
    _is_cairn_hook_entry,
    _load_manifest,
    _opencode_config_path,
    verify_hook_command,
)
from ._secretrefs import (  # noqa: E402
    KNOWN_SECRET_SCHEMES,
    VAULT_MIN_SEGMENTS,
    secret_ref_static_problem,
    verify_secret_ref,
)

# ---------------------------------------------------------------------------
# Secret references: resolve them, do not merely observe that they are set
#
# The standing Plan 020 question is "does this check verify, or merely observe
# presence?".  A configured-but-unresolvable ref reads green under every
# presence check, which is how a host whose only ``vault:`` ref was provably
# 403 kept reporting a reachable secret backend (agent-suite WI-041).
#
# The judgement itself lives in ``_secretrefs`` (WI-037) because the RUNTIME
# needs the same verdict this module publishes, and cannot import this one.
# ---------------------------------------------------------------------------

#: Kept as module-private aliases: these names are the doctor's vocabulary and
#: are referenced by name in its tests.
_KNOWN_SECRET_SCHEMES = KNOWN_SECRET_SCHEMES
_VAULT_MIN_SEGMENTS = VAULT_MIN_SEGMENTS
_secret_ref_static_problem = secret_ref_static_problem
_verify_secret_ref = verify_secret_ref


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


def _signing_key_id(keys: list[dict[str, Any]]) -> str | None:
    """The key the SIGNER would actually pick, per regista's own rule.

    This check used to name ``keys[0]`` as "active", which is not the signer's
    selection rule at all — the signer takes the last active *asymmetric* entry
    (falling back to the last active entry).  On a real key file that named the
    bootstrap HMAC key while every event was signed by something else (WI-036).
    regista exports the rule as a pure function precisely so consumers cannot
    re-derive it and drift (WI-223); use it rather than guessing.

    Entry defaults mirror regista's key-file parsing: absent ``status`` is
    ``active``, absent ``scheme`` is ``hmac-sha256``.
    """
    try:
        from regista._keys import select_signing_key_id
    except ImportError:
        first = keys[0].get("key_id") if keys else None
        return str(first) if first is not None else None
    candidates = [
        (
            str(entry.get("key_id", "?")),
            str(entry.get("scheme", "hmac-sha256")),
            str(entry.get("status", "active")),
        )
        for entry in keys
        if isinstance(entry, dict)
    ]
    chosen: str | None = select_signing_key_id(candidates)
    return chosen


def _check_key_file(cfg: Any) -> dict[str, Any]:
    if cfg.key_ref:
        ok, detail = _verify_secret_ref(cfg.key_ref)
        if ok:
            return {
                "name": "key_file",
                "status": "ok",
                "detail": f"key_ref: {cfg.key_ref} (resolvable)",
            }
        return {
            "name": "key_file",
            "status": "fail",
            "detail": f"key_ref {cfg.key_ref!r} {detail}",
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
        signing = _signing_key_id(keys)
        if signing is None:
            return {
                "name": "key_file",
                "status": "fail",
                "detail": (
                    f"{len(keys)} key(s), none active — the signer has no key to "
                    "select for this principal"
                ),
            }
        return {
            "name": "key_file",
            "status": "ok",
            "detail": f"{len(keys)} key(s), signing={signing}",
        }
    except Exception as exc:
        return {"name": "key_file", "status": "fail", "detail": f"cannot read key file: {exc}"}


def _replay_accepts_binding_check(sub: Any) -> bool:
    """Whether this regista's ``replay`` accepts ``verify_principal_binding``.

    A ``**kwargs`` signature accepts it, and so does anything not introspectable
    (C implementation, proxy, mock) — in both cases the honest move is to try
    the kwarg and let the ``TypeError`` fallback in :func:`_verify_chain` decide.
    Only an explicit signature that lacks the parameter is a definite "no".
    """
    try:
        import inspect

        params = inspect.signature(sub.replay).parameters
    except (TypeError, ValueError):
        return True
    if "verify_principal_binding" in params:
        return True
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _verify_chain(sub: Any) -> tuple[str, bool | None, dict[str, Any]]:
    """Use regista's canonical replay API to determine chain integrity.

    Returns ``(chain_state, chain_ok, binding)``, where ``chain_ok`` is ``True`` only
    when the replay established every property this verdict claims, ``False``
    when it found a violation, and ``None`` when no verdict could be reached.

    Principal binding is requested EXPLICITLY. regista's ``replay()`` Python
    API keeps ``verify_principal_binding=False`` for backward compatibility
    (only the CLI defaults it on), and this function used to read
    ``replayed_drift``/``halted`` alone — so ``chain_integrity`` reported
    "canonical replay verified no drift or halted events" for a chain signed by
    a key the project never registered, which the offline verifier
    (``regista bundle verify``) rejected outright. The wording was narrowly
    true and the surface was read as "the chain is sound" (WI-036).

    Two honest states beyond verified/drift follow from WI-223:

    * ``unattributable`` — the binding check RAN and found failures. The chain
      is cryptographically unattributable: a failure, never a warning.
    * ``unverified_binding`` — the check did not run (older regista, or a
      client that would not accept the kwarg). ``principal_binding_failures``
      is then 0 because nothing looked, and publishing that zero as an
      affirmative claim is precisely the defect WI-223 named. The honest
      verdict is "not verified", which is not "verified".
    """
    no_binding: dict[str, Any] = {
        "principal_binding_verified": False,
        "principal_binding_failures": None,
        "replayed_ok": None,
    }
    if not hasattr(sub, "replay"):
        return "unsupported", None, no_binding
    supported = _replay_accepts_binding_check(sub)
    try:
        report = sub.replay(verify_principal_binding=True) if supported else sub.replay()
    except TypeError:
        # The kwarg was rejected after all: fall back, but never claim the
        # binding was verified.
        try:
            report = sub.replay()
        except Exception:
            return "error", None, no_binding
        supported = False
    except Exception:
        return "error", None, no_binding

    failures = int(getattr(report, "principal_binding_failures", 0) or 0)
    verified = supported and bool(getattr(report, "principal_binding_verified", False))
    # Mirror ``ReplayReport.to_dict``: the failure count is only meaningful when
    # the check ran, so it is omitted (None) rather than recorded as zero.
    binding: dict[str, Any] = {
        "principal_binding_verified": verified,
        "principal_binding_failures": failures if (verified or failures) else None,
        # The count of events the replay established (WI-031 m5): recorded so
        # doctor can later report events-since-verdict, not only verdict age.
        "replayed_ok": int(getattr(report, "replayed_ok", 0) or 0),
    }

    if report.replayed_drift > 0 or report.halted > 0:
        return "drift", False, binding
    if failures > 0:
        return "unattributable", False, binding
    if not verified:
        return "unverified_binding", None, binding
    return "verified", True, binding


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


#: Transition that carries a session's harness identity. Session-entity events
#: also include ``user_message``/``assistant_message``/``transcript_attestation``
#: /``subagent_start``/``subagent_stop``/``compaction``, but only the
#: attestation names the harness, and every harness adapter emits it at
#: SessionStart — so it is the one event that answers "did THIS harness attest".
_SESSION_ATTESTATION_TRANSITION = "session_attestation"

#: Harness names as recorded in a session attestation payload, per harness the
#: doctor knows how to wire. The adapters default to these
#: (``cairn._claude_hook`` → ``claude-code``, ``cairn._codex_hook`` → ``codex``,
#: the OpenCode plugin → ``opencode``); ``CAIRN_HARNESS_NAME`` may override
#: them, so the configured value is accepted as well.
_HARNESS_ATTESTATION_NAMES: dict[str, frozenset[str]] = {
    "claude": frozenset({"claude", "claude-code", "claudecode"}),
    "opencode": frozenset({"opencode", "open-code"}),
    "codex": frozenset({"codex"}),
    "hermes": frozenset({"hermes"}),
}


@dataclass
class _StoreProbe:
    """What the bounded regista probe learned, for the freshness check.

    ``session_scoped`` records whether the session-entity query actually ran.
    A empty ``session_attested`` is only meaningful when it did — the same
    reasoning as regista's ``principal_binding_verified`` (WI-223): an
    unexamined zero must never be published as an affirmative claim.
    """

    newest_event_ts: Any = None
    #: recorded harness name (lowercased) -> newest session attestation ts
    session_attested: dict[str, Any] = field(default_factory=dict)
    #: newest session attestation whose harness could not be read at all
    unattributed_at: Any = None
    session_scoped: bool = False


def _attestation_window_hours() -> float:
    raw_window = os.environ.get("CAIRN_MAX_ATTESTATION_AGE_HOURS", "24")
    try:
        return float(raw_window)
    except ValueError:
        return 24.0


def _attested_harness_names(event: Any) -> list[str]:
    """Harness names recorded in a session-attestation event's payload."""
    payload = getattr(event, "payload", None)
    if not isinstance(payload, dict):
        return []
    harnesses = payload.get("harnesses")
    names: list[str] = []
    if isinstance(harnesses, list):
        for entry in harnesses:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                names.append(entry["name"].strip().lower())
            elif isinstance(entry, str):
                names.append(entry.strip().lower())
    return [n for n in names if n]


def _probe_session_attestation(sub: Any, probe: _StoreProbe) -> None:
    """Record which harnesses attested a SESSION inside the freshness window.

    WI-034: the old freshness check asked whether ANY attestation landed. On
    the real estate 400/400 recent events were ``entity_kind=work_item``
    written in-process by agent-notes, which satisfied the check while ZERO
    session events existed. Scoping the query to the session attestation the
    HARNESS is supposed to produce is what makes "configured but silent"
    detectable, which the docstring already claimed.
    """
    now = datetime.datetime.now(datetime.UTC)
    start = now - datetime.timedelta(hours=max(_attestation_window_hours(), 0.0))
    try:
        events = sub.read_events(
            transition=_SESSION_ATTESTATION_TRANSITION,
            start=start,
            end=now,
            limit=200,
        )
    except Exception:
        # Older regista, a store that rejects the filter, anything: we do not
        # know, and "do not know" is not "nothing attested".
        return
    probe.session_scoped = True
    for event in events or []:
        # "note" is the v6 entity kind for session-scoped events (regista 0.7's
        # closed registry); "session" is the pre-v6 spelling, still produced by
        # older stores.
        if getattr(event, "entity_kind", "work_item") not in ("session", "note"):
            continue
        ts = getattr(event, "timestamp", None)
        if ts is None:
            continue
        if getattr(ts, "tzinfo", None) is None:
            ts = ts.replace(tzinfo=datetime.UTC)
        names = _attested_harness_names(event)
        if not names:
            if probe.unattributed_at is None or ts > probe.unattributed_at:
                probe.unattributed_at = ts
            continue
        for name in names:
            current = probe.session_attested.get(name)
            if current is None or ts > current:
                probe.session_attested[name] = ts


def _check_regista(cfg: Any) -> tuple[dict[str, Any], _StoreProbe]:
    """Probe the regista store for availability.

    Returns ``(check, probe)``. This is a bounded, read-only reachability probe
    — it must complete within the suite umbrella's per-probe timeout, so it
    never replays the chain (WI-030). The chain verdict comes from the last
    recorded ``cairn integrity`` run instead (see ``_check_chain_integrity``).
    The session-attestation query rides along on the same connection: it is a
    single indexed, time-bounded, limited read.
    """
    if not cfg.is_configured:
        return (
            {"name": "regista", "status": "skip", "detail": "not configured"},
            _StoreProbe(),
        )
    try:
        with _open_regista(cfg) as sub:
            events = sub.read_events(limit=1)
            probe = _StoreProbe(
                newest_event_ts=events[0].timestamp if events else None
            )
            _probe_session_attestation(sub, probe)
            return (
                {
                    "name": "regista",
                    "status": "ok",
                    "detail": f"reachable, {len(events)} event(s) in project '{cfg.project}'",
                },
                probe,
            )
    except Exception as exc:
        return (
            {"name": "regista", "status": "fail", "detail": f"unreachable: {exc}"},
            _StoreProbe(),
        )


def _entry_commands(entries: list[dict[str, Any]]) -> list[str]:
    """The command strings inside cairn-owned hook *entries*."""
    commands: list[str] = []
    for entry in entries:
        raw = entry.get("hooks", [])
        if not isinstance(raw, list):
            continue
        for hook in raw:
            if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                commands.append(hook["command"])
    return commands


def _verify_wired_commands(commands: list[str]) -> tuple[str, str]:
    """Execute the hook commands found in a harness config.

    WI-034: ``harness_wired`` verified that entries were PRESENT and that env
    vars were SET; it never checked that the command was executable or that the
    module it named was importable.  A hook failing on every invocation
    therefore read ``ok``, and that is why a total loss of session attestation
    went unnoticed.  This resolves each distinct command and runs its
    side-effect-free ``--selftest`` under the interpreter that would actually
    run it.
    """
    if not commands:
        return HOOK_VERIFY_FAIL, "no hook command found to verify"
    worst = HOOK_VERIFY_OK
    detail = ""
    for command in dict.fromkeys(commands):
        outcome, command_detail = verify_hook_command(command)
        if outcome == HOOK_VERIFY_FAIL:
            return outcome, command_detail
        if worst == HOOK_VERIFY_OK:
            worst, detail = outcome, command_detail
    return worst, detail or "hook command verified executable"


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
    found_commands: list[str] = []
    for event in HOOK_EVENTS:
        event_hooks = hooks.get(event, [])
        if not isinstance(event_hooks, list):
            event_hooks = []
        owned = [
            e
            for e in event_hooks
            if isinstance(e, dict)
            and _is_cairn_hook_entry(e, harness="claude", event=event, manifest=manifest)
        ]
        if not owned:
            missing_events.append(event)
            continue
        found_commands.extend(_entry_commands(owned))

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

    runnable, run_detail = _verify_wired_commands(found_commands)
    if runnable == HOOK_VERIFY_FAIL:
        return {
            "name": "harness_wired",
            "status": "fail",
            "detail": (
                f"hooks are present in {path} but not runnable — {run_detail}. "
                "Every invocation would fail and nothing would attest; "
                "re-run `cairn install-harness claude`"
            ),
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
    if runnable == HOOK_VERIFY_OFF_PATH:
        return {
            "name": "harness_wired",
            "status": "warn",
            "detail": f"hooks + env configured in {path}, but {run_detail}",
        }
    return {
        "name": "harness_wired",
        "status": "ok",
        "detail": f"hooks + env configured in {path}; {run_detail}",
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
        direct_commands: list[str] = []
        for event in CODEX_HOOK_EVENTS:
            entries = hooks.get(event, [])
            owned = (
                [
                    entry
                    for entry in entries
                    if isinstance(entry, dict)
                    and _is_cairn_hook_entry(
                        entry, harness="codex", event=event, manifest=manifest
                    )
                ]
                if isinstance(entries, list)
                else []
            )
            direct_cairn_present = direct_cairn_present or bool(owned)
            direct_commands.extend(_entry_commands(owned))
            if not owned:
                missing_events.append(event)
        direct_ok = direct_cairn_present and not missing_events
        if direct_ok:
            # Same lesson as harness_wired (WI-034): present is not runnable.
            outcome, run_detail = _verify_wired_commands(direct_commands)
            if outcome == HOOK_VERIFY_FAIL:
                return {
                    "name": "codex_harness_wired",
                    "status": "fail",
                    "detail": (
                        f"direct Codex hooks are present in {path} but not "
                        f"runnable — {run_detail}; re-run "
                        "`cairn install-harness codex`"
                    ),
                }

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

#: Chain states that are real verdicts and therefore recorded for doctor.
#: ``verified``/``drift``/``unattributable`` are findings about the chain,
#: ``unverified_binding`` is a finding about what was NOT established, and
#: ``unsupported`` is a durable capability fact.  A replay *exception* is the
#: absence of a verdict and is never recorded (WI-030 review m4).
_RECORDED_CHAIN_STATES = (
    "verified",
    "drift",
    "unattributable",
    "unverified_binding",
    "unsupported",
)

#: One-line operator-facing meaning per chain state. Also used as the ``detail``
#: on ``cairn integrity``'s JSON body so an ``ok: false`` result always names
#: its reason.
_CHAIN_STATE_DETAIL = {
    "verified": (
        "canonical replay verified no drift or halted events, and every event's "
        "signature binds to a key this project registered"
    ),
    "drift": "canonical replay detected chain drift or halted events",
    "unattributable": (
        "canonical replay found event(s) whose signature does not bind to a key "
        "this project registered — the chain is cryptographically unattributable"
    ),
    "unverified_binding": (
        "canonical replay found no drift, but principal binding was NOT "
        "verified — nothing here claims the chain is attributable"
    ),
    "error": "chain replay failed; integrity verdict is unknown",
    "unsupported": "regista version does not expose the canonical replay API",
}


def _record_failed_attempt(cfg: Any, state: str) -> None:
    """Note a failed replay attempt so doctor can see it (WI-032).

    When a verdict already exists, annotate it with ``last_attempt`` without
    touching the verdict itself. When NO verdict exists yet — a never-verified
    store whose scheduled replay keeps failing — record a chain_state-less marker
    holding only ``last_attempt`` and the store binding, so doctor can warn that
    the store was never verified instead of showing a green ``never_run`` skip
    forever (WI-032).

    Best-effort: failure to note the attempt must never mask the command's exit
    code. A re-stat CAS guards the load-modify-write: if the marker changes
    between read and replace (a concurrent successful replay landed a fresh
    verdict), the annotation is dropped rather than clobbering it (WI-031 r3).
    Only a marker bound to the current store is annotated.
    """
    try:
        path = _integrity_verdict_path(cfg)
        binding = _store_binding(cfg)
        try:
            before = os.stat(path)
            fingerprint: tuple[int, int] | None = (before.st_mtime_ns, before.st_size)
        except OSError:
            fingerprint = None

        verdict = _load_integrity_verdict(cfg)
        if verdict and "chain_state" in verdict:
            # Annotate an existing real verdict; leave its verdict fields alone.
            if verdict.get("store_binding") != binding:
                return
        elif verdict is None:
            # Never verified: seed a chain_state-less marker (WI-032) so the
            # failing attempts are visible to doctor.
            verdict = {"store_binding": binding}
        else:
            # Unreadable / malformed marker — do not build on top of it.
            return

        verdict["last_attempt"] = {
            "checked_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "chain_state": state,
        }
        # Re-MAC so the annotation does not invalidate the marker (WI-031). A
        # marker that carried no MAC (no resolvable key) stays un-MAC'd.
        if isinstance(verdict.get("mac"), str):
            mac = _compute_verdict_mac(cfg, verdict)
            if mac is not None:
                verdict["mac"] = mac

        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".integrity-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(verdict, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o644)
            # Re-stat CAS: abort if the live marker changed under us.
            try:
                now = os.stat(path)
                current: tuple[int, int] | None = (now.st_mtime_ns, now.st_size)
            except OSError:
                current = None
            if current != fingerprint:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp)
                return
            os.replace(tmp, path)
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
    except Exception as exc:
        # Persistently failing annotation (e.g. broken marker-dir perms) must
        # not be invisible (WI-031 r3) — but never mask the caller's exit code.
        print(
            f"cairn: WARNING: could not record integrity attempt: "
            f"{type(exc).__name__}",
            file=sys.stderr,
        )
        return


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


# ---------------------------------------------------------------------------
# Verdict-marker MAC (WI-031)
#
# The marker is operator-trusted plain JSON in the user state home, readable by
# any local user (0o644, so a doctor running as another user can report it).
# Left plain, a same-host writer can flip ``drift`` to ``verified`` and doctor —
# which deliberately never replays — would report the forgery as a clean chain.
# MACing the body with the configured store signing key closes that: forging a
# green verdict now requires the key that signs the chain itself. The MAC covers
# every field except itself, over canonical JSON, so any edit — including the
# last-verified position — invalidates it. When no key can be resolved the
# marker is written un-MAC'd and doctor reports it as unverified rather than
# trusted: absence of a MAC is never a pass.
# ---------------------------------------------------------------------------

_VERDICT_MAC_SCHEME = "hmac-sha256"


def _store_mac_key(cfg: Any) -> bytes | None:
    """Raw bytes of the configured store signing key, for MACing the marker.

    Resolves the same key the bridge signs events with: ``key_ref`` directly, or
    the first key in ``key_path`` (via its ``secret_ref`` or inline ``secret``).
    Returns ``None`` when nothing is configured or resolution fails — the caller
    then writes/reads the marker without a MAC and reports it as unverified.
    Never raises: a MAC is an integrity hardening, not a reason to fail replay.
    """
    try:
        from regista._secrets import resolve as resolve_secret

        def _to_bytes(raw: object) -> bytes | None:
            if isinstance(raw, bytes):
                return raw
            if isinstance(raw, str):
                return raw.encode()
            return None

        if cfg.key_ref:
            return _to_bytes(resolve_secret(cfg.key_ref))
        if cfg.key_path:
            data = json.loads(Path(cfg.key_path).read_text())
            keys = data.get("keys") if isinstance(data, dict) else None
            if isinstance(keys, list) and keys and isinstance(keys[0], dict):
                key = keys[0]
                ref = key.get("secret_ref")
                if isinstance(ref, str) and ref:
                    return _to_bytes(resolve_secret(ref))
                secret = key.get("secret")
                if isinstance(secret, str) and secret:
                    return secret.encode()
    except Exception:
        return None
    return None


def _canonical_verdict_bytes(body: dict[str, Any]) -> bytes:
    """Canonical bytes of a verdict body for MACing (every field but ``mac``)."""
    payload = {k: v for k, v in body.items() if k != "mac"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _compute_verdict_mac(cfg: Any, body: dict[str, Any]) -> str | None:
    """MAC over the verdict body, or ``None`` when no store key is available."""
    key = _store_mac_key(cfg)
    if key is None:
        return None
    digest = hmac.new(key, _canonical_verdict_bytes(body), hashlib.sha256).hexdigest()
    return f"{_VERDICT_MAC_SCHEME}:{digest}"


def _verdict_mac_state(cfg: Any, verdict: dict[str, Any]) -> str:
    """Classify a marker's MAC: ``valid``, ``invalid``, ``unkeyed``, ``stripped``, ``legacy``.

    * ``valid``    — a MAC is present and matches the body under the store key.
    * ``invalid``  — a MAC is present but does not match (tampered, or the store
                     key changed since it was written).
    * ``unkeyed``  — a MAC is present but no store key can be resolved now, so it
                     cannot be checked. Not trusted.
    * ``stripped`` — no MAC field but a store key CAN be resolved: the MAC was
                     never written or was deleted (WI-031 fail-open). Not trusted.
    * ``legacy``   — no MAC field and no store key resolvable (a pre-WI-031
                     marker, or a store with no key configured). Tolerated.
    """
    stored = verdict.get("mac")
    if not isinstance(stored, str) or not stored:
        if _store_mac_key(cfg) is None:
            return "legacy"
        return "stripped"
    key = _store_mac_key(cfg)
    if key is None:
        return "unkeyed"
    expected = _compute_verdict_mac(cfg, verdict)
    if expected is not None and hmac.compare_digest(stored, expected):
        return "valid"
    return "invalid"


def _parse_utc(value: Any) -> datetime.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    return parsed


def _newer_failed_attempt(verdict: dict[str, Any]) -> str | None:
    """Timestamp of a failed replay attempt newer than the verdict, if any.

    ``cairn integrity`` never overwrites a real verdict with an exception
    (m4), but it does note the attempt so a *persistently failing* replay
    escalates in doctor instead of hiding behind an old green verdict.
    """
    attempt = verdict.get("last_attempt")
    if not isinstance(attempt, dict) or attempt.get("chain_state") == "verified":
        return None
    attempt_dt = _parse_utc(attempt.get("checked_at"))
    verdict_dt = _parse_utc(verdict.get("checked_at"))
    if attempt_dt is None:
        return None
    if verdict_dt is None or attempt_dt > verdict_dt:
        return attempt.get("checked_at")
    return None


def _load_integrity_verdict(cfg: Any) -> dict[str, Any] | None:
    """Read the verdict recorded by the last ``cairn integrity`` run.

    Returns ``None`` when no verdict has been recorded. A malformed file
    returns ``{"chain_state": "unreadable"}`` so doctor can surface it.

    A chain_state-less marker holding only ``last_attempt`` + ``store_binding``
    is a valid WI-032 record (a never-verified store whose replay keeps failing)
    and is returned as-is, distinct from a malformed file.
    """
    path = _integrity_verdict_path(cfg)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            return {"chain_state": "unreadable"}
        if "chain_state" in data:
            return data
        if isinstance(data.get("last_attempt"), dict):
            return data
        return {"chain_state": "unreadable"}
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

    # WI-032: a chain_state-less marker holds only ``last_attempt`` — a store that
    # was never verified but whose scheduled replay keeps failing. Without this it
    # would show a green ``never_run`` skip forever. Report it honestly as a warn.
    # Recognized BEFORE the MAC check: the marker is intentionally MAC-less (an
    # attempt annotation, not a verdict), so it must never be mistaken for a
    # stripped verdict below.
    if "chain_state" not in verdict:
        if verdict.get("store_binding") != _store_binding(cfg):
            return (
                {
                    "name": "chain_integrity",
                    "status": "skip",
                    "detail": (
                        "recorded attempt marker is for a different store or "
                        "project; run `cairn integrity` against this configuration"
                    ),
                },
                "unbound",
                None,
            )
        attempt = verdict.get("last_attempt")
        attempt_at = attempt.get("checked_at") if isinstance(attempt, dict) else None
        return (
            {
                "name": "chain_integrity",
                "status": "warn",
                "detail": (
                    "store was never verified, and the most recent replay attempt "
                    f"({attempt_at or 'unknown time'}) failed — run "
                    "`cairn integrity` and investigate the failure"
                ),
            },
            "never_run",
            None,
        )

    # WI-031: the marker is operator-trusted plain JSON; its MAC is what keeps a
    # same-host writer from flipping drift->verified. A marker that carries a MAC
    # which does not verify is never trusted: a mismatch is reported as a fail
    # (tampering, or the store key rotated), a MAC cairn cannot check for want of
    # a key is reported as unverified, and a verdict marker with NO mac field
    # while a store key IS configured was stripped (or never written) and is
    # reported as unverified rather than trusted. Only a marker with no mac field
    # AND no resolvable key (pre-WI-031, or an un-keyed store) is tolerated.
    mac_state = _verdict_mac_state(cfg, verdict)
    if mac_state == "invalid":
        return (
            {
                "name": "chain_integrity",
                "status": "fail",
                "detail": (
                    "integrity verdict marker failed its MAC check — the file was "
                    "modified without the store key (possible tampering) or the "
                    "store key changed since it was written; re-run "
                    "`cairn integrity` to re-record a trusted verdict"
                ),
            },
            "tampered",
            False,
        )
    if mac_state == "unkeyed":
        return (
            {
                "name": "chain_integrity",
                "status": "warn",
                "detail": (
                    "integrity verdict marker carries a MAC but no store key is "
                    "configured to verify it — treating the verdict as unverified; "
                    "re-run `cairn integrity` with the store key available"
                ),
            },
            "unverified_marker",
            None,
        )
    if mac_state == "stripped":
        return (
            {
                "name": "chain_integrity",
                "status": "warn",
                "detail": (
                    "integrity verdict marker carries no MAC but a store key is "
                    "configured — the MAC was stripped or never written; treating "
                    "the verdict as unverified. Re-run `cairn integrity` to record "
                    "a MAC'd verdict (WI-031)"
                ),
            },
            "unverified_marker",
            None,
        )

    chain_state = verdict.get("chain_state")
    checked_at = verdict.get("checked_at")
    failed_attempt_at = _newer_failed_attempt(verdict)

    # A verdict certifies exactly one store+project; never report it for
    # another (WI-030 review M1) — including "unsupported", which is a claim
    # about a specific store's regista. Markers predating the binding field
    # are treated as unbound and must be re-recorded.
    if chain_state in _RECORDED_CHAIN_STATES and verdict.get(
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

    # Forward/backward compatibility, same reasoning as the store_binding guard
    # above: a "verified" marker written before cairn consumed regista's binding
    # fields carries no evidence that the chain is attributable, so it must not
    # be replayed as a pass (WI-036). Absence of the field is not a zero.
    if chain_state == "verified" and verdict.get("principal_binding_verified") is not True:
        return (
            {
                "name": "chain_integrity",
                "status": "warn",
                "detail": (
                    f"recorded verdict from {checked_at or 'unknown time'} predates "
                    "principal-binding verification, so the chain's "
                    "attributability was never checked; re-run `cairn integrity`"
                ),
            },
            "unverified_binding",
            None,
        )

    if chain_state == "unattributable":
        failures = verdict.get("principal_binding_failures")
        count = f"{failures} " if isinstance(failures, int) else ""
        return (
            {
                "name": "chain_integrity",
                "status": "fail",
                "detail": (
                    f"canonical replay found {count}event(s) whose signature does "
                    f"not bind to a key this project registered, at "
                    f"{checked_at or 'unknown time'} — the chain is "
                    "cryptographically unattributable and the offline verifier "
                    "rejects it (cairn integrity)"
                ),
            },
            "unattributable",
            False,
        )

    if chain_state == "unverified_binding":
        return (
            {
                "name": "chain_integrity",
                "status": "warn",
                "detail": (
                    f"canonical replay at {checked_at or 'unknown time'} found no "
                    "drift, but principal binding was NOT verified — this regista "
                    "did not run the check, so nothing here claims the chain is "
                    "attributable"
                ),
            },
            "unverified_binding",
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
            if failed_attempt_at is not None:
                # Stale AND newer attempts are failing: the verdict is not
                # merely old, it is unrefreshable — escalate to fail so a
                # replay-breaking condition cannot hide behind warn forever.
                return (
                    {
                        "name": "chain_integrity",
                        "status": "fail",
                        "detail": (
                            f"verified verdict from {checked_at} is older than "
                            f"{max_age:g}h and the most recent replay attempt "
                            f"({failed_attempt_at}) failed — investigate "
                            "`cairn integrity`"
                        ),
                    },
                    "verified",
                    None,
                )
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
        if failed_attempt_at is not None:
            return (
                {
                    "name": "chain_integrity",
                    "status": "warn",
                    "detail": (
                        f"verified at {checked_at}, but the most recent replay "
                        f"attempt ({failed_attempt_at}) failed; investigate "
                        "`cairn integrity`"
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

    Rendered from the RUNTIME's own verdict (``_content_crypto``), not from a
    second implementation of the same question.  Resolve the ref, do not merely
    note that it is set: a configured-but-unresolvable key means content
    encryption is reported ON while the key it names cannot be fetched
    (agent-suite WI-041; cairn WI-034).  Since WI-037 the runtime refuses to
    store plaintext in that state and records the refusal per event, so this
    check and what capture actually does cannot disagree.

    When content encryption is off, emit a WARNING — the log now holds
    every secret/PII that passed through the session.
    """
    settings = ContentSettings(
        encryption=str(getattr(cfg, "content_encryption", "on")),
        key_ref=getattr(cfg, "content_key_ref", None),
        key_path=getattr(cfg, "content_key_path", None),
    )
    status = content_encryption_status_for(settings)
    if status.stance == "off":
        return {
            "name": "content_encryption",
            "status": "warn",
            "detail": (
                "Content encryption is OFF — session content is stored in "
                "plaintext. The log itself is now a sensitive artifact."
            ),
        }
    if status.stance == "external":
        return {
            "name": "content_encryption",
            "status": "ok",
            "detail": "Content encryption delegated to lower layer (external)",
        }
    if not status.configured:
        return {
            "name": "content_encryption",
            "status": "warn",
            "detail": (
                "Content encryption is ON but no content key configured "
                "(CAIRN_CONTENT_KEY_REF / CAIRN_CONTENT_KEY_PATH). "
                "Content capture will store plaintext until a key is set, and "
                "attestations will record content_encryption=off accordingly."
            ),
        }
    key_ref = status.key_ref or ""
    if not status.usable:
        # ``detail`` already names the ref when the problem is its shape; only
        # add the ref when the resolver's reason does not carry it.
        subject = "its key" if key_ref in status.detail else f"its key {key_ref!r}"
        return {
            "name": "content_encryption",
            "status": "fail",
            "detail": (
                f"Content encryption is ON but {subject} {status.detail} — "
                "session content will be withheld from capture (digest only) "
                "rather than stored in plaintext"
            ),
        }
    return {
        "name": "content_encryption",
        "status": "ok",
        "detail": f"Content encryption ON (key {key_ref} {status.detail})",
    }


#: Where cairn may look for local evidence that a harness ran a session.
#:
#: Claude Code has a layout cairn knows (one ``<session-uuid>.jsonl`` per session
#: under ``~/.claude/projects/<encoded-cwd>/``).  OpenCode and Codex do not have
#: one cairn can claim to know, and a GUESSED default would be worse than none:
#: a wrong path holds no files, which reads as "the harness did not run" — the
#: fail-open answer, dressed as evidence (WI-039).  So there is no default for
#: them; an operator who knows their layout can point the check at it, and until
#: they do the check says plainly that it cannot tell.
_HARNESS_ACTIVITY_DIR_ENV: dict[str, str] = {
    "claude": "CAIRN_CLAUDE_PROJECTS",
    "opencode": "CAIRN_OPENCODE_SESSIONS",
    "codex": "CAIRN_CODEX_SESSIONS",
}

#: Bounds on the activity scan — this runs inside ``cairn doctor``, not a batch job.
_ACTIVITY_SCAN_MAX_DEPTH = 3
_ACTIVITY_SCAN_MAX_FILES = 5000


@dataclass(frozen=True)
class _LocalActivity:
    """Whether a harness provably ran locally, and what cairn consulted.

    ``ran`` is deliberately tri-state.  ``None`` means *cairn has no evidence*,
    which is a different statement from ``False`` ("it did not run") and must
    never be reported as the latter: that is the difference between a check that
    verifies and one that merely looks like it did.
    """

    ran: bool | None
    detail: str


def _harness_activity_dir(harness: str) -> tuple[str | None, str]:
    """``(directory, how it was chosen)`` for *harness*'s local session store."""
    env_name = _HARNESS_ACTIVITY_DIR_ENV.get(harness)
    if env_name:
        declared = os.environ.get(env_name)
        if declared and declared.strip():
            return declared.strip(), env_name
    if harness == "claude":
        return os.path.join(os.path.expanduser("~"), ".claude", "projects"), "default"
    return None, ""


def _newest_activity_mtime(base: str) -> tuple[bool, float | None]:
    """``(readable, newest mtime)`` for a local session store.

    ``readable`` is False when the directory is absent or cannot be scanned —
    the case a caller must NOT read as disuse.
    """
    if not os.path.isdir(base):
        return False, None
    newest: float | None = None
    seen = 0
    try:
        for root, dirs, files in os.walk(base):
            if root[len(base) :].count(os.sep) >= _ACTIVITY_SCAN_MAX_DEPTH:
                dirs[:] = []
            for name in files:
                if name.startswith("."):
                    continue
                try:
                    mtime = os.stat(os.path.join(root, name)).st_mtime
                except OSError:
                    continue
                seen += 1
                if newest is None or mtime > newest:
                    newest = mtime
                if seen >= _ACTIVITY_SCAN_MAX_FILES:
                    return True, newest
    except OSError:
        return newest is not None, newest
    return True, newest


def _newest_local_session_activity() -> float | None:
    """Newest mtime among local Claude Code session transcripts, or None."""
    base, _source = _harness_activity_dir("claude")
    if base is None:  # pragma: no cover - claude always has a default
        return None
    _readable, newest = _newest_activity_mtime(base)
    return newest


def _harness_local_activity(harness: str, window_secs: float) -> _LocalActivity:
    """What cairn can locally establish about *harness* running a session.

    Three outcomes, and the check must report which one it got:

    * ``True``  — files in the harness's own session store were written inside
      the window, so a session provably ran.
    * ``False`` — the store was readable and holds nothing that recent.  Genuine
      evidence of disuse.
    * ``None``  — cairn has no signal: either the harness has no session store
      cairn knows (OpenCode, Codex), or the one it knows is not where it looked
      (a *relocated* ``~/.claude/projects``).  Before WI-039 a missing directory
      returned ``False`` and was reported as "no sessions ran" — a check that
      could not see its input, publishing a verdict about the input.
    """
    base, source = _harness_activity_dir(harness)
    if base is None:
        env_name = _HARNESS_ACTIVITY_DIR_ENV.get(harness, "")
        hint = (
            f"; set {env_name} to a directory whose file mtimes track its "
            "sessions to give this check a signal"
            if env_name
            else ""
        )
        return _LocalActivity(
            None,
            f"cairn has no local signal for {harness}, so it cannot distinguish "
            f"'ran and did not attest' from 'did not run'{hint}",
        )
    readable, newest = _newest_activity_mtime(base)
    if not readable:
        where = f"{base} ({source})" if source != "default" else base
        return _LocalActivity(
            None,
            f"cairn could not read {harness}'s local session store at {where}, so "
            "it has no signal here — a check that cannot see its input has not "
            "established disuse",
        )
    if newest is None:
        return _LocalActivity(False, f"{harness}'s local session store {base} is empty")
    now = datetime.datetime.now(datetime.UTC).timestamp()
    age_hours = (now - newest) / 3600
    if newest >= now - window_secs:
        return _LocalActivity(True, f"{harness} wrote a session file {age_hours:.1f}h ago")
    return _LocalActivity(
        False, f"{harness}'s newest local session file is {age_hours:.1f}h old"
    )


def _check_attestation_freshness(
    cfg: Any,
    probe: _StoreProbe,
    *,
    regista_ok: bool,
    harnesses: list[str],
) -> dict[str, Any]:
    """WI-4.1 — silence is a finding. WI-034 — per harness, and session-scoped.

    "Wired but not attesting" must be detectable by doctor, not discovered by
    querying the store by hand a week later.  Two blind spots made this check
    fail open, both in the same direction:

    * It asked whether ANY attestation landed in the window.  On the real
      estate 400/400 recent events were ``entity_kind=work_item`` written
      in-process by agent-notes; that satisfied the check while ZERO session
      events existed and every Claude Code session went unattested.
    * It aggregated across harnesses, so an unhooked Claude read green behind a
      working OpenCode.

    So the question is now asked once per *configured* harness, against session
    attestation attributed to that harness.  A harness whose sessions provably
    ran locally but did not attest fails; one with no local signal warns
    (silence and disuse are indistinguishable, and claiming ok would be the
    same fail-open move); and a store we could not scope the query against is
    an honest skip, never a pass.

    WI-039 — what this check does NOT verify, stated in its own output.  The
    local signal exists only where cairn can read the harness's own session
    store: Claude Code's ``~/.claude/projects``, or a directory the operator
    names for OpenCode/Codex (``CAIRN_OPENCODE_SESSIONS`` /
    ``CAIRN_CODEX_SESSIONS``).  Without one, "attested nothing" cannot be told
    from "ran nothing", and the warning says exactly that instead of implying a
    look was taken.  The same applies when the directory cairn knows about is
    not there: that is a check that could not see its input, reported as such,
    where it used to be reported as disuse.  Whether the hooks would fire at all
    is covered by the executability check on ``harness_wired``, not here.
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
    if not harnesses:
        return {
            "name": name,
            "status": "skip",
            "detail": "no harness is wired — nothing is expected to attest",
        }
    if not probe.session_scoped:
        return {
            "name": name,
            "status": "skip",
            "detail": (
                "could not query session-entity attestation in this store, so "
                "freshness is unknown — an unexamined store is not a fresh one"
            ),
        }

    window_hours = _attestation_window_hours()
    window_secs = window_hours * 3600
    configured_name = str(getattr(cfg, "harness_name", "") or "").strip().lower()

    fails: list[str] = []
    warns: list[str] = []
    oks: list[str] = []
    for harness in harnesses:
        accepted = set(_HARNESS_ATTESTATION_NAMES.get(harness, frozenset({harness})))
        if configured_name and harness in configured_name:
            accepted.add(configured_name)
        newest = None
        for recorded, ts in probe.session_attested.items():
            if recorded in accepted and (newest is None or ts > newest):
                newest = ts
        if newest is not None:
            oks.append(f"{harness} attested a session at {newest.isoformat()}")
            continue
        activity = _harness_local_activity(harness, window_secs)
        if activity.ran is False:
            oks.append(
                f"{harness}: no sessions ran within the last {window_hours:g}h "
                f"({activity.detail})"
            )
        elif activity.ran is True:
            fails.append(
                f"{harness} ran a session within the last {window_hours:g}h but "
                f"attested none — the harness is configured and silent "
                f"({activity.detail})"
            )
        else:
            # Name the blind spot rather than implying the absence of an
            # attestation was checked against anything (WI-039).
            warns.append(
                f"{harness} is wired but attested no session in the last "
                f"{window_hours:g}h, and {activity.detail}"
            )

    unattributed = ""
    if probe.unattributed_at is not None and (fails or warns):
        unattributed = (
            f"; a session was attested at {probe.unattributed_at.isoformat()} "
            "but names no harness, so it cannot cover for any of them"
        )

    if fails:
        return {
            "name": name,
            "status": "fail",
            "detail": "configured but silent: " + "; ".join(fails + warns) + unattributed,
        }
    if warns:
        return {
            "name": name,
            "status": "warn",
            "detail": "; ".join(warns + oks) + unattributed,
        }
    return {
        "name": name,
        "status": "ok",
        "detail": "; ".join(oks),
    }


def run_doctor(*, json_output: bool = False) -> int:
    cfg = resolve_config()

    regista_check, store_probe = _check_regista(cfg)
    chain_check, chain_state, chain_ok = _check_chain_integrity(cfg)
    codex_wired = _check_codex_harness_wired(cfg)
    codex_active = codex_wired["status"] in {"ok", "warn"}
    claude_wired = _check_harness_wired(cfg, required=not codex_active)
    opencode_wired = _check_opencode_harness_wired(cfg)

    # A harness counts as *configured* for freshness purposes whenever its
    # wiring check is anything but "skip" — including "fail". A harness whose
    # hooks are broken is exactly the one whose silence must be reported, so
    # excluding it here would restore the fail-open path WI-034 closed.
    configured_harnesses = [
        harness
        for harness, check in (
            ("claude", claude_wired),
            ("opencode", opencode_wired),
            ("codex", codex_wired),
        )
        if check["status"] != "skip"
    ]

    checks = [
        _check_config(cfg),
        _check_key_file(cfg),
        regista_check,
        chain_check,
        claude_wired,
        opencode_wired,
        codex_wired,
        _check_codex_hook_policy(wired=codex_active),
        _check_codex_hook_trust(wired=codex_active),
        _check_codex_activity(wired=codex_active),
        _check_bridge(),
        _check_content_encryption(cfg),
        _check_attestation_freshness(
            cfg,
            store_probe,
            regista_ok=regista_check["status"] == "ok",
            harnesses=configured_harnesses,
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
    replay API, store unreachable, not configured, principal binding failed or
    unverified). Only real verdicts are recorded (see
    :data:`_RECORDED_CHAIN_STATES`); a replay exception or unreachable store
    exits nonzero without overwriting the last real verdict, so schedulers must
    alert on this command's exit code rather than relying on doctor alone.

    Every nonzero exit carries a ``detail`` string alongside ``ok: false``, so
    the suite umbrella's envelope reader (which treats ``ok: false`` as failure
    regardless of exit code) always has a reason to report and never has to
    read fields off a failed result.
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
            chain_state, chain_ok, binding = _verify_chain(sub)
    except Exception as exc:
        _record_failed_attempt(cfg, "unreachable")
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
    verdict: dict[str, Any] = {
        "checked_at": checked_at,
        "chain_state": chain_state,
        "chain_ok": chain_ok,
        "duration_seconds": round(duration, 3),
        "cairn_version": _cairn_version,
        "project": cfg.project,
        "store_binding": _store_binding(cfg),
        # Recorded so doctor can tell "checked and clean" from "never checked".
        # Mirrors ``ReplayReport.to_dict``: the failure count is omitted when
        # the check did not run, so a reader cannot mistake an unexamined chain
        # for a clean one (WI-223/WI-036).
        "principal_binding_verified": binding["principal_binding_verified"],
    }
    if binding["principal_binding_failures"] is not None:
        verdict["principal_binding_failures"] = binding["principal_binding_failures"]
    # Last-verified position (WI-031 m5): how many events the replay established,
    # so doctor can later report events-since-verdict rather than only verdict age.
    replayed_ok = binding.get("replayed_ok")
    if isinstance(replayed_ok, int):
        verdict["verified_event_count"] = replayed_ok

    # Record the verdict for doctor — atomically (and fsynced, so a crash
    # cannot leave an empty marker), so a concurrent doctor never reads a
    # half-written file. Only real chain verdicts are recorded:
    # verified/drift are verdicts, unsupported is a durable capability fact,
    # but a replay *exception* is the absence of a verdict — like an
    # unreachable store, it exits nonzero without clobbering the last real
    # verdict (WI-030 review m4). The marker is not secret; leave it
    # world-readable so a doctor running as a different user can report it.
    if chain_state in _RECORDED_CHAIN_STATES:
        # MAC the body with the store key (WI-031) so a same-host writer cannot
        # flip drift->verified in this world-readable file. Computed last, over
        # the final body; absent (and reported as unverified by doctor) when no
        # store key can be resolved.
        mac = _compute_verdict_mac(cfg, verdict)
        if mac is not None:
            verdict["mac"] = mac
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
    elif chain_state == "error":
        # An exception is not a verdict (m4) — but note the failed attempt so
        # doctor escalates if attempts keep failing behind an old verdict.
        _record_failed_attempt(cfg, "error")

    ok = chain_state == "verified" and chain_ok is True
    report = {
        "component": "cairn",
        "version": _cairn_version,
        "ok": ok,
        "detail": _CHAIN_STATE_DETAIL.get(chain_state, chain_state),
        **verdict,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print(f"cairn integrity — v{_cairn_version}")
        detail = _CHAIN_STATE_DETAIL.get(chain_state, chain_state)
        status = "OK" if ok else "FAIL"
        print(f"  [{status:4s}] chain_integrity   {detail}")
        if chain_state in _RECORDED_CHAIN_STATES:
            print(f"  replayed in {duration:.1f}s; verdict recorded for doctor")
        else:
            print(
                f"  replay attempt took {duration:.1f}s; no verdict recorded — "
                "the last real verdict is preserved"
            )

    return 0 if ok else 1
