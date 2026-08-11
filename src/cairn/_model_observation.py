from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ObservedModel:
    provider_id: str | None
    model_id: str
    source: str


def model_family(provider_id: str | None, model_id: str | None) -> str | None:
    if not isinstance(model_id, str) or not model_id.strip():
        return None
    model = model_id.strip().lower().rsplit("/", 1)[-1]
    if "claude-opus" in model or model.startswith("opus-"):
        return "claude-opus"
    if "claude-sonnet" in model or model.startswith("sonnet-"):
        return "claude-sonnet"
    if "claude-haiku" in model or model.startswith("haiku-"):
        return "claude-haiku"
    if "fable" in model:
        return "fable"
    if "nemotron" in model:
        return "nemotron"
    if "deepseek" in model:
        return "deepseek"
    if "longcat" in model:
        return "longcat"
    if "qwen" in model:
        return "qwen"
    if "kimi" in model:
        return "kimi"
    if model.startswith("glm-") or model == "glm":
        return "glm"
    if "codex" in model:
        return "gpt-codex"
    if model.endswith("-luna") or model == "luna":
        return "gpt-luna"
    if model.endswith("-sol") or model == "sol":
        return "gpt-sol"
    return None


def submit_model_observation(
    session_id: str,
    payload: dict[str, Any],
    run_bridge: Callable[[dict[str, Any]], dict[str, Any] | None],
    state_dir: Callable[[str], Path],
    mark_degraded: Callable[[str, str, str], None],
    *,
    action: str,
) -> None:
    request = {"action": "model_observation", "session_id": session_id, **payload}
    fingerprint = json.dumps(request, separators=(",", ":"), sort_keys=True)
    try:
        marker = state_dir(session_id) / "model-observation.state"
        if marker.is_file() and marker.read_text() == fingerprint:
            return
        reply = run_bridge(request)
        if not reply or reply.get("status") != "ok":
            mark_degraded(session_id, action, "model observation bridge call failed")
            return
        marker.write_text(fingerprint)
        if reply.get("observation_status") == "unavailable":
            mark_degraded(session_id, action, "runtime model metadata unavailable")
    except Exception as exc:
        try:
            mark_degraded(
                session_id,
                action,
                f"model observation state failed: {type(exc).__name__}",
            )
        except Exception:
            pass


def observe_claude_transcript(path: str, session_id: str | None = None) -> ObservedModel | None:
    candidate = Path(path)
    if not candidate.is_file():
        return None
    latest: ObservedModel | None = None
    try:
        with candidate.open(encoding="utf-8") as handle:
            for raw in handle:
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict) or entry.get("type") != "assistant":
                    continue
                entry_session = entry.get("sessionId") or entry.get("session_id")
                if session_id and entry_session and entry_session != session_id:
                    continue
                message = entry.get("message")
                model = message.get("model") if isinstance(message, dict) else None
                if isinstance(model, str) and model:
                    provider = message.get("provider") if isinstance(message, dict) else None
                    latest = ObservedModel(
                        provider_id=provider if isinstance(provider, str) else "anthropic",
                        model_id=model,
                        source="claude.transcript.assistant",
                    )
    except (OSError, UnicodeDecodeError):
        return None
    return latest


def observe_codex_rollout(
    root: str,
    session_id: str,
    turn_id: str | None = None,
    *,
    max_files: int = 100,
) -> ObservedModel | None:
    base = Path(root)
    if not base.is_dir():
        return None
    try:
        files = sorted(
            base.rglob("*.jsonl"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )[:max_files]
    except OSError:
        return None
    for candidate in files:
        provider: str | None = None
        matched_session = False
        latest: ObservedModel | None = None
        try:
            with candidate.open(encoding="utf-8") as handle:
                for raw in handle:
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(entry, dict):
                        continue
                    payload = entry.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    if entry.get("type") == "session_meta":
                        recorded_session = payload.get("id") or payload.get("session_id")
                        matched_session = recorded_session == session_id
                        raw_provider = payload.get("model_provider")
                        provider = raw_provider if isinstance(raw_provider, str) else None
                    elif entry.get("type") == "turn_context" and matched_session:
                        recorded_turn = payload.get("turn_id")
                        if turn_id and recorded_turn != turn_id:
                            continue
                        model = payload.get("model")
                        if isinstance(model, str) and model:
                            latest = ObservedModel(
                                provider_id=provider,
                                model_id=model,
                                source="codex.rollout.turn_context",
                            )
        except (OSError, UnicodeDecodeError):
            continue
        if latest is not None:
            return latest
    return None
