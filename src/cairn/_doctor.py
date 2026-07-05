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


def _check_regista(cfg: Any) -> dict[str, Any]:
    if not cfg.is_configured:
        return {"name": "regista", "status": "skip", "detail": "not configured"}
    try:
        from regista import Regista

        key_path = cfg.key_path
        if not key_path and cfg.key_ref:
            fd, key_path = tempfile.mkstemp(suffix=".json", prefix="cairn-doctor-")
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
                    return {
                        "name": "regista",
                        "status": "ok",
                        "detail": f"reachable, {len(events)} event(s) in project '{cfg.project}'",
                    }
                finally:
                    sub.close()
            finally:
                os.unlink(key_path)

        sub = Regista(dsn=cfg.dsn, project=cfg.project, hmac_key_path=key_path)
        try:
            events = sub.read_events(limit=1)
            return {
                "name": "regista",
                "status": "ok",
                "detail": f"reachable, {len(events)} event(s) in project '{cfg.project}'",
            }
        finally:
            sub.close()
    except Exception as exc:
        return {"name": "regista", "status": "fail", "detail": f"unreachable: {exc}"}


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


def run_doctor(*, json_output: bool = False) -> int:
    cfg = resolve_config()

    checks = [
        _check_config(cfg),
        _check_key_file(cfg),
        _check_regista(cfg),
        _check_harness_wired(cfg),
        _check_bridge(),
    ]

    regista_check = next((c for c in checks if c["name"] == "regista"), None)
    regista_reachable = regista_check["status"] == "ok" if regista_check else False

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
