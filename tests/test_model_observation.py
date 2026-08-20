from __future__ import annotations

import ast
import inspect
import json
import textwrap
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

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
    # "codex" is a harness, not a model line: the id does not say which of the
    # gpt siblings ran, so the family is honestly unresolvable rather than an
    # invented "gpt-codex" (owner decision 2026-08-10).
    assert model_family(observed.provider_id, observed.model_id) is None


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


@pytest.mark.parametrize(
    ("model_id", "expected"),
    [
        ("gpt-5.6-sol", "gpt-sol"),
        ("gpt-5.6-luna", "gpt-luna"),
        ("gpt-5.6-terra", "gpt-terra"),
        ("sol", "gpt-sol"),
        ("terra", "gpt-terra"),
        ("openai/gpt-5.6-terra", "gpt-terra"),
        # Harness-qualified: the sibling name still identifies the model.
        ("gpt-5.6-codex-sol", "gpt-sol"),
        # Harness only — does not say which sibling ran.
        ("gpt-5.6-codex", None),
        ("codex", None),
        ("minimax-m3", "minimax"),
        ("MiniMax-M3", "minimax"),
    ],
)
def test_gpt_siblings_and_minimax_map_to_registry_families(
    model_id: str, expected: str | None
) -> None:
    assert model_family(None, model_id) == expected


#: A hand transcription of regista 0.6.0's ``MODEL_LINEAGE_FAMILIES``
#: (``src/regista/_lineage.py``, 14 families) — the closed vocabulary regista
#: validates ``model_lineage`` against at ingress via ``validate_model_lineage``.
#:
#: Transcribed rather than imported, and the reason is not a style preference:
#: the dev spine this repo installs is regista **0.5.5**, which has no
#: ``regista._lineage`` module at all, and ``pyproject.toml``'s deliberate
#: ``regista-hraedon>=0.5.1,<0.6`` cap forbids installing the version that does
#: (the cap holds until cairn's ``on_behalf_of`` port). So there is no import
#: available to compare against, here or in CI.
#:
#: The consequence is worth stating plainly: **a transcription cannot see
#: registry-side drift.** If regista renames ``glm``, drops ``longcat``, or
#: narrows the set, this file keeps asserting against the stale copy and stays
#: green while cairn mints a lineage the store would now refuse. Only cairn-side
#: drift — the mapper growing a family that is not in this copy — is caught. The
#: cross-repo direction is covered by re-transcribing this set when the cap
#: lifts and the import becomes possible; until then it is an accepted gap, not
#: a guarded one.
REGISTA_MODEL_LINEAGE_FAMILIES = frozenset(
    {
        "claude-haiku", "claude-opus", "claude-sonnet", "deepseek", "fable",
        "glm", "gpt-luna", "gpt-sol", "gpt-terra", "kimi", "longcat",
        "minimax", "nemotron", "qwen",
    }
)


def test_every_mapped_family_is_a_regista_registry_family() -> None:
    """Sample check: representative ids all map into the registry vocabulary.

    This is deliberately *sample*-based — 18 probe ids exercising every branch
    of the mapper that a real harness has been seen to emit. It proves those
    ids resolve, and resolve to something regista accepts. It does **not**
    bound the mapper's range: an added branch returning an invented family goes
    unnoticed here as long as no probe id reaches it. The range is bounded by
    ``test_model_family_range_is_bounded_by_the_registry_vocabulary`` below;
    the two are complements, not duplicates.
    """
    probes = [
        "claude-opus-5", "claude-sonnet-4-8", "claude-haiku-4-5", "opus-5",
        "sonnet-4", "haiku-4-5", "claude-fable-5", "nemotron-3-ultra",
        "deepseek-v4-flash", "longcat-2", "qwen3.8-max-preview", "kimi-k3",
        "glm-5.2", "gpt-5.6-sol", "gpt-5.6-luna", "gpt-5.6-terra",
        "minimax-m3", "opencode-deepseek-v4-flash",
    ]
    mapped = {model_family(None, p) for p in probes}
    assert None not in mapped, "a probe id failed to map"
    assert mapped <= REGISTA_MODEL_LINEAGE_FAMILIES, mapped - REGISTA_MODEL_LINEAGE_FAMILIES


def _model_family_returns() -> tuple[set[str], list[ast.expr]]:
    """Every ``return`` in ``model_family``, split into literals and the rest.

    Reads the mapper's own source (``inspect.getsource`` + ``ast``) rather than
    calling it, so the assertion covers the function's whole *range* instead of
    whatever a list of probe ids happens to reach.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(model_family)))
    outer = tree.body[0]
    assert isinstance(outer, ast.FunctionDef)
    # A nested def/lambda would put returns from another scope into the walk
    # below, making the result ambiguous. There are none today; if one lands,
    # this guard says so instead of silently mis-attributing its returns.
    scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
    nested = [
        node for node in ast.walk(outer) if node is not outer and isinstance(node, scopes)
    ]
    assert not nested, "model_family gained a nested scope; the range walk needs rework"

    literals: set[str] = set()
    dynamic: list[ast.expr] = []
    for node in ast.walk(outer):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        value = node.value
        if isinstance(value, ast.Constant):
            if value.value is None:
                continue  # honest "unresolvable"; not a family
            assert isinstance(value.value, str), f"non-str constant returned: {value.value!r}"
            literals.add(value.value)
        else:
            dynamic.append(value)
    return literals, dynamic


def test_model_family_range_is_bounded_by_the_registry_vocabulary() -> None:
    """No branch of the mapper can return a family regista would refuse.

    Closes the sample-vs-range gap the test above cannot: adding
    ``if "grok" in model: return "grok"`` to ``model_family`` passes every
    sample assertion in this file (no probe id contains "grok") but reddens
    here, because ``"grok"`` is not in the transcribed vocabulary.
    """
    literals, dynamic = _model_family_returns()

    assert literals, "found no string-literal returns; the AST walk is not reaching them"
    outside = literals - REGISTA_MODEL_LINEAGE_FAMILIES
    assert not outside, (
        f"model_family can return {sorted(outside)}, which regista's "
        f"MODEL_LINEAGE_FAMILIES does not contain — the store would refuse it at ingress"
    )

    # Dynamically constructed returns are outside a static check's reach: today
    # the only one is `f"gpt-{sibling}"` over a literal sibling tuple, and all
    # three of its results are pinned by
    # `test_gpt_siblings_and_minimax_map_to_registry_families` above. Pinning
    # the count means a *new* computed return cannot slip in unexamined — it
    # reddens here and has to be either rewritten as literals or covered by an
    # explicit sample probe.
    assert len(dynamic) == 1, (
        f"model_family has {len(dynamic)} computed return(s), expected 1 "
        f"(f\"gpt-{{sibling}}\"). A computed return is invisible to this range "
        f"check: rewrite it as string literals, or add sample probes for every "
        f"value it can produce and update this count."
    )
