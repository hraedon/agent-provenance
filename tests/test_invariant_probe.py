from __future__ import annotations

from cairn._invariant_probe import (
    evaluate_runtime_dispatch,
    evaluate_unavailable_observation,
    invariant_probe_report,
)


def test_behavioral_probe_passes() -> None:
    report = invariant_probe_report()

    assert report["ok"] is True
    assert {check["status"] for check in report["checks"]} == {"pass"}


def test_runtime_dispatch_probe_fails_on_requested_model_laundering() -> None:
    check = evaluate_runtime_dispatch(
        {
            "observed_provider_id": "provider-a",
            "observed_model_id": "nemotron-3-ultra",
            "observed_model_lineage": "nemotron",
            "requested_provider_id": "provider-a",
            "requested_model_id": "nemotron-3-ultra",
            "declared_model_lineage": "nemotron",
            "status": "matched",
        }
    )

    assert check["status"] == "fail"


def test_unavailable_probe_fails_if_missing_model_reads_as_observed() -> None:
    check = evaluate_unavailable_observation(
        {
            "status": "observed",
            "observed_model_id": None,
            "observed_model_lineage": None,
        }
    )

    assert check["status"] == "fail"
