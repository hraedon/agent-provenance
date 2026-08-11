from __future__ import annotations

import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cairn import CairnAdapter, CairnConfig
from cairn._model_observation import (
    model_family,
    observe_claude_transcript,
    observe_codex_rollout,
    submit_model_observation,
)


class RecordingStore:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def append_event(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return SimpleNamespace(event_id=uuid.uuid4(), payload=kwargs["payload"])


def test_model_family_uses_observed_identifier() -> None:
    assert model_family("provider-b", "glm-5.2") == "glm"
    assert model_family("provider-a", "nemotron-3-ultra") == "nemotron"
    assert model_family("provider", "adversarial-reviewer-glm") is None


def test_adapter_records_requested_observed_mismatch() -> None:
    store = RecordingStore()
    adapter = CairnAdapter(store, config=CairnConfig("opencode", "1"))

    event = adapter.record_model_observation(
        str(uuid.uuid4()),
        source="opencode.message.updated",
        observed_provider_id="provider-b",
        observed_model_id="glm-5.2",
        requested_provider_id="provider-a",
        requested_model_id="nemotron-3-ultra",
    )

    assert event.payload["observed_model_lineage"] == "glm"
    assert event.payload["observation_basis"] == "runtime_metadata"
    assert event.payload["declared_model_lineage"] == "nemotron"
    assert event.payload["status"] == "mismatch"
    assert event.payload["finding"] == "declared_observed_lineage_mismatch"


def test_claude_observer_reads_assistant_transcript_model(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    transcript.write_text(
        "not json\n"
        + json.dumps(
            {
                "type": "assistant",
                "sessionId": "session-1",
                "message": {"model": "claude-sonnet-4-5-20250929"},
            }
        )
        + "\n"
    )

    observed = observe_claude_transcript(str(transcript), "session-1")

    assert observed is not None
    assert observed.model_id == "claude-sonnet-4-5-20250929"
    assert model_family(observed.provider_id, observed.model_id) == "claude-sonnet"


def test_codex_observer_reads_runtime_turn_context(tmp_path: Path) -> None:
    rollout = tmp_path / "2026" / "08" / "rollout.jsonl"
    rollout.parent.mkdir(parents=True)
    rollout.write_text(
        json.dumps(
            {
                "type": "session_meta",
                "payload": {"id": "session-1", "model_provider": "openai"},
            }
        )
        + "\n"
        + json.dumps(
            {
                "type": "turn_context",
                "payload": {"turn_id": "turn-2", "model": "gpt-5.3-codex"},
            }
        )
        + "\n"
    )

    observed = observe_codex_rollout(str(tmp_path), "session-1", "turn-2")

    assert observed is not None
    assert observed.provider_id == "openai"
    assert observed.model_id == "gpt-5.3-codex"
    assert model_family(observed.provider_id, observed.model_id) == "gpt-codex"


def test_observation_bridge_exception_never_blocks(tmp_path: Path) -> None:
    degradation: list[str] = []

    submit_model_observation(
        "session",
        {"source": "probe"},
        lambda _payload: (_ for _ in ()).throw(RuntimeError("bridge failed")),
        lambda _session_id: tmp_path,
        lambda _session_id, _action, detail: degradation.append(detail),
        action="model_observation",
    )

    assert degradation == ["model observation state failed: RuntimeError"]


def test_single_model_service_is_named_as_declaration_not_observation() -> None:
    store = RecordingStore()
    adapter = CairnAdapter(store, config=CairnConfig("hermes", "1"))

    event = adapter.record_model_observation(
        str(uuid.uuid4()),
        source="hermes.single_model_service_environment",
        observation_basis="single_model_service_declaration",
        observed_provider_id="provider",
        observed_model_id="deepseek-v4-flash",
        declared_model_lineage="deepseek",
    )

    assert event.payload["status"] == "declared"
    assert event.payload["finding"] == "model_identity_declared_not_observed"
