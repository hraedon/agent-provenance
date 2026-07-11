"""``cairn doctor`` — health check conforming to the suite shape.

Emits ``{component, version, ok, degraded, regista:{reachable, project,
chain_ok}, checks:[…]}`` so the suite-doctor umbrella (which reads the top-level
``ok`` boolean) can aggregate it alongside the other components. Check status
follows regista's canonical vocabulary: ``ok``/``warn``/``fail``/``skip``.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
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
from ._install import HOOK_EVENTS, _claude_settings_path, _is_cairn_hook_entry  # noqa: E402


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


def _check_regista(cfg: Any) -> tuple[dict[str, Any], Any]:
    """Probe the regista store.

    Returns ``(check, newest_event_ts)`` where ``newest_event_ts`` is the
    timestamp of the most recent event in the project (``read_events``
    without filters orders newest-first), or ``None`` when the store is
    unreachable or empty.  The freshness check (WI-4.1) consumes the
    timestamp so doctor opens only one connection.
    """
    if not cfg.is_configured:
        return {"name": "regista", "status": "skip", "detail": "not configured"}, None
    try:
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
                events = sub.read_events(limit=1)
                newest_ts = events[0].timestamp if events else None
                return {
                    "name": "regista",
                    "status": "ok",
                    "detail": f"reachable, {len(events)} event(s) in project '{cfg.project}'",
                }, newest_ts
            finally:
                sub.close()
        finally:
            if temp_key is not None:
                os.unlink(temp_key)
    except Exception as exc:
        return {"name": "regista", "status": "fail", "detail": f"unreachable: {exc}"}, None


def _check_harness_wired(cfg: Any) -> dict[str, Any]:
    path = _claude_settings_path()
    if not path.is_file():
        return {"name": "harness_wired", "status": "fail", "detail": f"no settings.json at {path}"}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {"name": "harness_wired", "status": "fail", "detail": f"cannot parse {path}"}

    hooks = data.get("hooks", {})
    missing_events: list[str] = []
    for event in HOOK_EVENTS:
        event_hooks = hooks.get(event, [])
        if not any(_is_cairn_hook_entry(e) for e in event_hooks):
            missing_events.append(event)

    env = data.get("env", {})
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


def _check_bridge() -> dict[str, Any]:
    import shutil

    bridge = shutil.which("cairn-bridge")
    if bridge:
        return {"name": "bridge", "status": "ok", "detail": f"cairn-bridge at {bridge}"}
    return {
        "name": "bridge",
        "status": "warn",
        "detail": "cairn-bridge not on PATH (hooks use python3 -m cairn._claude_hook)",
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
    import datetime

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
    checks = [
        _check_config(cfg),
        _check_key_file(cfg),
        regista_check,
        _check_harness_wired(cfg),
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
            "chain_ok": regista_reachable,
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
