from __future__ import annotations

import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ._model_observation import submit_model_observation
from .adapter import CairnAdapter, CairnConfig


class _RecordingStore:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def append_event(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return SimpleNamespace(event_id=uuid.uuid4(), payload=kwargs["payload"])


# Machine-readable evidence-basis marker for every check this probe emits.
# All three checks here exercise the capture *code path*
# (CairnAdapter.record_model_observation / submit_model_observation) against
# hardcoded synthetic inputs constructed in-process — they never read an
# installed harness's runtime metadata (no OpenCode message.updated event, no
# Claude transcript, no Codex rollout). That is a genuine gap: a check can
# pass here on a box where the OpenCode plugin is not installed at all, even
# though agent-suite's genesis gate treats these as required, gating checks.
# This field lets a consumer (or a human reading `cairn invariants probe
# --json`) tell fixture-backed evidence apart from a live measurement without
# us renaming the frozen check ids agent-suite already depends on
# (cairn.runtime_model_observed, cairn.unavailable_model_named,
# cairn.observation_failure_nonblocking).
PROBE_EVIDENCE_BASIS = "fixture"


def evaluate_runtime_dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    passed = (
        payload.get("observed_provider_id") == "provider-b"
        and payload.get("observed_model_id") == "glm-5.2"
        and payload.get("observed_model_lineage") == "glm"
        and payload.get("requested_provider_id") == "provider-a"
        and payload.get("requested_model_id") == "nemotron-3-ultra"
        and payload.get("declared_model_lineage") == "nemotron"
        and payload.get("status") == "mismatch"
        and payload.get("finding") == "declared_observed_lineage_mismatch"
        and payload.get("observation_basis") == "runtime_metadata"
    )
    return {
        "id": "cairn.runtime_model_observed",
        "status": "pass" if passed else "fail",
        "detail": (
            "synthetic fixture (provider-a/nemotron-3-ultra dispatching to "
            "provider-b/glm-5.2) run through the capture code path; this "
            "does not observe an installed harness"
        ),
        "basis": PROBE_EVIDENCE_BASIS,
    }


def evaluate_unavailable_observation(payload: dict[str, Any]) -> dict[str, Any]:
    passed = (
        payload.get("status") == "unavailable"
        and payload.get("finding") == "model_observation_unavailable"
        and payload.get("observed_model_id") is None
        and payload.get("observed_model_lineage") is None
        and payload.get("observation_basis") == "unavailable"
    )
    return {
        "id": "cairn.unavailable_model_named",
        "status": "pass" if passed else "fail",
        "detail": (
            "synthetic fixture with no observed model metadata run through "
            "the capture code path; this does not observe an installed "
            "harness"
        ),
        "basis": PROBE_EVIDENCE_BASIS,
    }


def _fail_open_check() -> dict[str, Any]:
    degradation: list[tuple[str, str, str]] = []
    with tempfile.TemporaryDirectory(prefix="cairn-invariant-") as directory:
        submit_model_observation(
            "probe-session",
            {
                "source": "probe",
                "observed_provider_id": None,
                "observed_model_id": None,
            },
            lambda _payload: None,
            lambda session_id: Path(directory) / session_id,
            lambda session_id, action, detail: degradation.append(
                (session_id, action, detail)
            ),
            action="probe:model_observation",
        )
    passed = bool(degradation) and degradation[0][1] == "probe:model_observation"
    return {
        "id": "cairn.observation_failure_nonblocking",
        "status": "pass" if passed else "fail",
        "detail": (
            "synthetic fixture with no bridge/harness run through the "
            "capture code path to confirm it returns normally and records "
            "degradation; this does not observe an installed harness"
        ),
        "basis": PROBE_EVIDENCE_BASIS,
    }


def invariant_probe_report() -> dict[str, Any]:
    store = _RecordingStore()
    adapter = CairnAdapter(store, config=CairnConfig("probe", "1"))
    session_id = str(uuid.uuid4())
    mismatch = adapter.record_model_observation(
        session_id,
        source="opencode.message.updated",
        observed_provider_id="provider-b",
        observed_model_id="glm-5.2",
        requested_provider_id="provider-a",
        requested_model_id="nemotron-3-ultra",
    )
    unavailable = adapter.record_model_observation(
        session_id,
        source="claude.transcript.assistant",
    )
    checks = [
        evaluate_runtime_dispatch(mismatch.payload),
        evaluate_unavailable_observation(unavailable.payload),
        _fail_open_check(),
    ]
    return {
        "component": "cairn",
        "probe_version": 1,
        "ok": all(check["status"] == "pass" for check in checks),
        "checks": checks,
    }
