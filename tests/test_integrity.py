"""Tests for WI-030: doctor must not replay; ``cairn integrity`` owns replay.

``cairn doctor`` is a bounded, read-only availability probe that runs inside
the suite umbrella's per-probe timeout. On a production store the canonical
full-chain replay grows without bound (>180s observed on mvmcc03), so the
replay lives in the separate ``cairn integrity`` command, which records its
verdict for doctor to report honestly.
"""

from __future__ import annotations

import datetime
import json
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest
from regista import ReplayReport

import cairn._doctor as doctor_mod
from cairn._config import CairnEnvConfig, resolve_config
from cairn._doctor import (
    _check_chain_integrity,
    _integrity_verdict_path,
    _store_binding,
    run_doctor,
    run_integrity,
)

HMAC_KEYS = {
    "keys": [
        {
            "key_id": "test-key",
            "scheme": "hmac-sha256",
            "secret_ref": "env:CAIRN_TEST_SECRET",
        }
    ]
}


@pytest.fixture
def cfg(tmp_path: Path) -> CairnEnvConfig:
    key_path = tmp_path / "keys.json"
    key_path.write_text(json.dumps(HMAC_KEYS))
    return CairnEnvConfig(
        dsn="postgresql://user:pw@host/db",
        key_path=str(key_path),
        key_ref=None,
        project="test_project",
        state_dir=str(tmp_path / "state"),
        integrity_dir=str(tmp_path / "integrity"),
    )


class _StubRegista:
    """Regista stand-in that records whether replay was attempted."""

    def __init__(
        self,
        replay_report: ReplayReport | None = None,
        replay_exc: Exception | None = None,
        replay_delay: float = 0.0,
    ) -> None:
        self.replay_called = False
        self._report = replay_report or ReplayReport(
            table_name="events", replayed_ok=1, replayed_drift=0, halted=0
        )
        self._exc = replay_exc
        self._delay = replay_delay

    def read_events(self, limit: int = 1) -> list:
        return []

    def replay(self) -> ReplayReport:
        self.replay_called = True
        if self._delay:
            time.sleep(self._delay)
        if self._exc is not None:
            raise self._exc
        return self._report

    def close(self) -> None:
        pass


def _patch_regista(monkeypatch, cfg: CairnEnvConfig, stub: _StubRegista) -> None:
    @contextmanager
    def _fake_open(_cfg):
        yield stub

    monkeypatch.setattr(doctor_mod, "_open_regista", _fake_open)
    monkeypatch.setattr(doctor_mod, "resolve_config", lambda: cfg)


def _doctor_report(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def _find_check(report: dict, name: str) -> dict:
    return next(c for c in report["checks"] if c["name"] == name)


# ---------------------------------------------------------------------------
# doctor never replays
# ---------------------------------------------------------------------------


def test_doctor_does_not_replay(monkeypatch, cfg, capsys):
    """Routine health must not touch the replay path at all (WI-030)."""
    stub = _StubRegista(replay_exc=AssertionError("doctor must not replay"))
    _patch_regista(monkeypatch, cfg, stub)

    run_doctor(json_output=True)

    assert stub.replay_called is False
    report = _doctor_report(capsys)
    assert _find_check(report, "regista")["status"] == "ok"


def test_doctor_stays_bounded_when_replay_is_production_scale(monkeypatch, cfg, capsys):
    """Even a replay that would take minutes cannot slow doctor down."""
    stub = _StubRegista(replay_delay=30.0)
    _patch_regista(monkeypatch, cfg, stub)

    started = time.monotonic()
    run_doctor(json_output=True)
    elapsed = time.monotonic() - started

    assert stub.replay_called is False
    assert elapsed < 10.0, f"doctor took {elapsed:.1f}s — replay leaked into health path"


def test_doctor_skips_chain_when_never_verified(monkeypatch, cfg, capsys):
    _patch_regista(monkeypatch, cfg, _StubRegista())

    run_doctor(json_output=True)

    report = _doctor_report(capsys)
    check = _find_check(report, "chain_integrity")
    assert check["status"] == "skip"
    assert "cairn integrity" in check["detail"]
    assert report["regista"]["chain_state"] == "never_run"
    assert report["regista"]["chain_ok"] is None


# ---------------------------------------------------------------------------
# cairn integrity — the replay command
# ---------------------------------------------------------------------------


def test_integrity_verified_records_verdict_and_doctor_reports_ok(
    monkeypatch, cfg, capsys
):
    stub = _StubRegista()
    _patch_regista(monkeypatch, cfg, stub)

    rc = run_integrity(json_output=True)

    assert rc == 0
    assert stub.replay_called is True
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["chain_state"] == "verified"

    verdict = json.loads(_integrity_verdict_path(cfg).read_text())
    assert verdict["chain_state"] == "verified"
    assert verdict["chain_ok"] is True

    run_doctor(json_output=True)
    report = _doctor_report(capsys)
    check = _find_check(report, "chain_integrity")
    assert check["status"] == "ok"
    assert report["regista"]["chain_state"] == "verified"
    assert report["regista"]["chain_ok"] is True


def test_integrity_drift_fails_and_doctor_goes_red(monkeypatch, cfg, capsys):
    stub = _StubRegista(
        replay_report=ReplayReport(
            table_name="events", replayed_ok=5, replayed_drift=2, halted=0
        )
    )
    _patch_regista(monkeypatch, cfg, stub)

    rc = run_integrity(json_output=True)
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["chain_state"] == "drift"

    rc = run_doctor(json_output=True)
    assert rc == 1
    report = _doctor_report(capsys)
    assert _find_check(report, "chain_integrity")["status"] == "fail"
    assert report["regista"]["chain_ok"] is False


def test_integrity_replay_error_exits_nonzero_and_preserves_verdict(
    monkeypatch, cfg, capsys
):
    """A replay exception is the absence of a verdict, not a verdict: the
    command exits 1 but the last real verdict stays on disk (review m4)."""
    _patch_regista(monkeypatch, cfg, _StubRegista())
    assert run_integrity(json_output=True) == 0
    capsys.readouterr()

    stub = _StubRegista(replay_exc=RuntimeError("boom"))
    _patch_regista(monkeypatch, cfg, stub)
    rc = run_integrity(json_output=True)
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["chain_state"] == "error"

    verdict = json.loads(_integrity_verdict_path(cfg).read_text())
    assert verdict["chain_state"] == "verified"
    assert verdict["last_attempt"]["chain_state"] == "error"

    # the verdict survives, but the failed attempt is escalated as a warning
    run_doctor(json_output=True)
    report = _doctor_report(capsys)
    check = _find_check(report, "chain_integrity")
    assert check["status"] == "warn"
    assert "failed" in check["detail"]
    assert report["regista"]["chain_state"] == "verified"


def test_integrity_replay_error_with_no_prior_verdict_leaves_never_run(
    monkeypatch, cfg, capsys
):
    stub = _StubRegista(replay_exc=RuntimeError("boom"))
    _patch_regista(monkeypatch, cfg, stub)
    assert run_integrity(json_output=True) == 1
    capsys.readouterr()
    assert not _integrity_verdict_path(cfg).exists()

    run_doctor(json_output=True)
    report = _doctor_report(capsys)
    assert _find_check(report, "chain_integrity")["status"] == "skip"
    assert report["regista"]["chain_state"] == "never_run"


def test_integrity_unconfigured_fails_without_marker(monkeypatch, tmp_path, capsys):
    cfg = CairnEnvConfig(
        state_dir=str(tmp_path / "state"),
        integrity_dir=str(tmp_path / "integrity"),
    )
    monkeypatch.setattr(doctor_mod, "resolve_config", lambda: cfg)

    rc = run_integrity(json_output=True)
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["chain_state"] == "unconfigured"
    assert not _integrity_verdict_path(cfg).exists()


def test_integrity_unreachable_preserves_previous_verdict(monkeypatch, cfg, capsys):
    stub = _StubRegista()
    _patch_regista(monkeypatch, cfg, stub)
    assert run_integrity(json_output=True) == 0
    capsys.readouterr()

    @contextmanager
    def _fail_open(_cfg):
        raise ConnectionError("store down")
        yield  # pragma: no cover

    monkeypatch.setattr(doctor_mod, "_open_regista", _fail_open)
    rc = run_integrity(json_output=True)
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["chain_state"] == "unreachable"

    # the last good verdict is still on disk for doctor
    verdict = json.loads(_integrity_verdict_path(cfg).read_text())
    assert verdict["chain_state"] == "verified"


# ---------------------------------------------------------------------------
# verdict staleness and corruption
# ---------------------------------------------------------------------------


def _write_verdict(
    cfg: CairnEnvConfig,
    *,
    age_hours: float,
    state: str = "verified",
    binding: str | None = None,
):
    path = _integrity_verdict_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    checked = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=age_hours)
    path.write_text(
        json.dumps(
            {
                "checked_at": checked.isoformat(),
                "chain_state": state,
                "chain_ok": state == "verified",
                "store_binding": binding if binding is not None else _store_binding(cfg),
            }
        )
    )


def test_stale_verified_verdict_warns(cfg):
    _write_verdict(cfg, age_hours=200.0)
    check, chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "warn"
    assert "older than" in check["detail"]
    assert chain_state == "verified"
    assert chain_ok is True


def test_fresh_verified_verdict_is_ok(cfg):
    _write_verdict(cfg, age_hours=1.0)
    check, _chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "ok"
    assert chain_ok is True


def test_old_drift_verdict_stays_red_regardless_of_age(cfg):
    _write_verdict(cfg, age_hours=500.0, state="drift")
    check, _chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "fail"
    assert chain_ok is False


def test_unreadable_verdict_warns(cfg):
    path = _integrity_verdict_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json")
    check, chain_state, _chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "warn"
    assert chain_state == "unreadable"


def test_staleness_window_disabled_with_zero(tmp_path):
    key_path = tmp_path / "keys.json"
    key_path.write_text(json.dumps(HMAC_KEYS))
    cfg = CairnEnvConfig(
        dsn="postgresql://user:pw@host/db",
        key_path=str(key_path),
        project="test_project",
        state_dir=str(tmp_path / "state"),
        integrity_dir=str(tmp_path / "integrity"),
        integrity_max_age_hours=0.0,
    )
    _write_verdict(cfg, age_hours=10_000.0)
    check, _, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "ok"
    assert chain_ok is True


def test_verdict_from_other_store_or_project_is_not_reported(cfg, tmp_path):
    """A verdict certifies one store+project; doctor must not reuse it for
    another configuration sharing the integrity dir (review M1)."""
    other = CairnEnvConfig(
        dsn=cfg.dsn,
        key_path=cfg.key_path,
        project="other_project",
        state_dir=cfg.state_dir,
        integrity_dir=cfg.integrity_dir,
    )
    _write_verdict(other, age_hours=1.0)  # verified, bound to other_project

    check, chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "skip"
    assert chain_state == "unbound"
    assert chain_ok is None
    assert "different store or project" in check["detail"]


def test_unbound_legacy_verdict_is_not_reported(cfg):
    """Markers written before store binding existed must be re-recorded."""
    _write_verdict(cfg, age_hours=1.0, binding="")
    check, chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "skip"
    assert chain_state == "unbound"
    assert chain_ok is None


def test_future_timestamp_verdict_warns(cfg):
    _write_verdict(cfg, age_hours=-6.0)
    check, _chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "warn"
    assert "future" in check["detail"]
    assert chain_ok is None


def test_never_run_is_skip_and_doctor_can_stay_green(monkeypatch, cfg, capsys):
    """Documented behavior: a fresh install with no recorded verdict is an
    honest skip — it does not red or degrade the umbrella by itself."""
    _patch_regista(monkeypatch, cfg, _StubRegista())
    run_doctor(json_output=True)
    report = _doctor_report(capsys)
    check = _find_check(report, "chain_integrity")
    assert check["status"] == "skip"
    assert report["regista"]["chain_state"] == "never_run"


def test_max_age_env_parsing_rejects_invalid(monkeypatch, tmp_path):
    for raw, expected in (("nope", 168.0), ("-5", 168.0), ("nan", 168.0), ("0", 0.0)):
        monkeypatch.setenv("CAIRN_INTEGRITY_MAX_AGE_HOURS", raw)
        assert resolve_config().integrity_max_age_hours == expected, raw


def test_unsupported_verdict_from_other_store_is_unbound(cfg):
    """'unsupported' is a claim about a specific store's regista — it must
    not be reported for a different store (review round 2)."""
    other = CairnEnvConfig(
        dsn=cfg.dsn,
        key_path=cfg.key_path,
        project="other_project",
        state_dir=cfg.state_dir,
        integrity_dir=cfg.integrity_dir,
    )
    _write_verdict(other, age_hours=1.0, state="unsupported")
    check, chain_state, _chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "skip"
    assert chain_state == "unbound"


def test_integrity_dir_defaults_to_durable_state_home():
    """A directly constructed config must not yield a CWD-relative marker."""
    cfg = CairnEnvConfig()
    assert cfg.integrity_dir
    assert Path(cfg.integrity_dir).is_absolute()


# ---------------------------------------------------------------------------
# failed-attempt escalation (review round 2 medium: a persistently failing
# replay must not hide behind an old green verdict)
# ---------------------------------------------------------------------------


def test_failed_attempt_after_fresh_verdict_warns(monkeypatch, cfg, capsys):
    _patch_regista(monkeypatch, cfg, _StubRegista())
    assert run_integrity(json_output=True) == 0
    capsys.readouterr()

    _patch_regista(monkeypatch, cfg, _StubRegista(replay_exc=RuntimeError("boom")))
    assert run_integrity(json_output=True) == 1
    capsys.readouterr()

    check, chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "warn"
    assert "failed" in check["detail"]
    assert chain_state == "verified"
    assert chain_ok is True


def test_failed_attempt_behind_stale_verdict_fails(monkeypatch, cfg):
    _write_verdict(cfg, age_hours=200.0)
    marker = json.loads(_integrity_verdict_path(cfg).read_text())
    marker["last_attempt"] = {
        "checked_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "chain_state": "error",
    }
    _integrity_verdict_path(cfg).write_text(json.dumps(marker))

    check, _chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "fail"
    assert "failed" in check["detail"]
    assert chain_ok is None


def test_successful_rerun_clears_failed_attempt(monkeypatch, cfg, capsys):
    _patch_regista(monkeypatch, cfg, _StubRegista(replay_exc=RuntimeError("boom")))
    _write_verdict(cfg, age_hours=1.0)
    assert run_integrity(json_output=True) == 1
    capsys.readouterr()
    assert "last_attempt" in json.loads(_integrity_verdict_path(cfg).read_text())

    _patch_regista(monkeypatch, cfg, _StubRegista())
    assert run_integrity(json_output=True) == 0
    capsys.readouterr()
    marker = json.loads(_integrity_verdict_path(cfg).read_text())
    assert "last_attempt" not in marker

    check, _chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "ok"
    assert chain_ok is True


def test_failed_attempt_never_annotates_foreign_marker(monkeypatch, cfg, capsys):
    other = CairnEnvConfig(
        dsn=cfg.dsn,
        key_path=cfg.key_path,
        project="other_project",
        state_dir=cfg.state_dir,
        integrity_dir=cfg.integrity_dir,
    )
    _write_verdict(other, age_hours=1.0)

    _patch_regista(monkeypatch, cfg, _StubRegista(replay_exc=RuntimeError("boom")))
    assert run_integrity(json_output=True) == 1
    capsys.readouterr()
    marker = json.loads(_integrity_verdict_path(cfg).read_text())
    assert "last_attempt" not in marker


# ---------------------------------------------------------------------------
# production-scale chain fixture (real replay through InMemoryRegista)
# ---------------------------------------------------------------------------


def test_integrity_verifies_production_scale_chain(monkeypatch, cfg, capsys):
    """End-to-end: a chain with thousands of signed events replays and
    verifies through ``cairn integrity``, while doctor never pays that cost."""
    from regista.testing import InMemoryRegista

    from cairn import CairnAdapter, CairnConfig

    monkeypatch.setenv("CAIRN_TEST_SECRET", "0" * 64)
    sub = InMemoryRegista(project="cairn_scale", hmac_key_path=cfg.key_path)
    adapter = CairnAdapter(
        sub,
        config=CairnConfig("test-harness", "0.0"),
        on_behalf_of={
            "principal_id": "human:test",
            "session_id": str(uuid.uuid4()),
        },
    )
    for _ in range(2000):
        adapter.attest_session(
            principal_id="human:test",
            session_id=str(uuid.uuid4()),
            harnesses=[{"name": "test-harness", "version": "0.0"}],
            scope_statement="scale fixture",
            harness_config_digests={"test-harness": "sha256:0"},
        )

    @contextmanager
    def _fake_open(_cfg):
        yield sub

    monkeypatch.setattr(doctor_mod, "_open_regista", _fake_open)
    monkeypatch.setattr(doctor_mod, "resolve_config", lambda: cfg)

    rc = run_integrity(json_output=True)
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["chain_state"] == "verified"

    started = time.monotonic()
    run_doctor(json_output=True)
    elapsed = time.monotonic() - started
    report = _doctor_report(capsys)
    assert _find_check(report, "chain_integrity")["status"] == "ok"
    assert elapsed < 10.0
