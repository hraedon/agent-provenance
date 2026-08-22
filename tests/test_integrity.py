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
from _dbutil import postgres_reachable, resolve_test_dsn
from regista import ReplayReport

import cairn._doctor as doctor_mod
from cairn._config import CairnEnvConfig, resolve_config
from cairn._doctor import (
    _check_chain_integrity,
    _compute_verdict_mac,
    _integrity_verdict_path,
    _load_integrity_verdict,
    _record_failed_attempt,
    _store_binding,
    _store_mac_key,
    _verdict_mac_state,
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
    """Regista stand-in that records whether replay was attempted.

    Models a *current* regista: ``replay`` accepts ``verify_principal_binding``
    and the default report says the check ran and found nothing. WI-036: cairn
    must request the check explicitly, so ``binding_requested`` records what it
    asked for.
    """

    def __init__(
        self,
        replay_report: ReplayReport | None = None,
        replay_exc: Exception | None = None,
        replay_delay: float = 0.0,
    ) -> None:
        self.replay_called = False
        self.binding_requested: bool | None = None
        self._report = replay_report
        self._exc = replay_exc
        self._delay = replay_delay

    def read_events(self, limit: int = 1, **kwargs) -> list:
        return []

    def replay(self, *, verify_principal_binding: bool = False, **kwargs) -> ReplayReport:
        self.replay_called = True
        self.binding_requested = verify_principal_binding
        if self._delay:
            time.sleep(self._delay)
        if self._exc is not None:
            raise self._exc
        if self._report is None:
            self._report = ReplayReport(
                table_name="events",
                replayed_ok=1,
                replayed_drift=0,
                halted=0,
                principal_binding_verified=True,
            )
        return self._report

    def close(self) -> None:
        pass


class _LegacyStubRegista(_StubRegista):
    """A regista whose ``replay`` predates ``verify_principal_binding``."""

    def replay(self) -> ReplayReport:  # type: ignore[override]
        self.replay_called = True
        self.binding_requested = None
        if self._exc is not None:
            raise self._exc
        return ReplayReport(
            table_name="events", replayed_ok=1, replayed_drift=0, halted=0
        )


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

    # WI-032: a never-verified store whose scheduled replay keeps failing is
    # annotated with a chain_state-less marker (``last_attempt`` only), so
    # doctor can warn instead of showing a green ``never_run`` skip forever.
    # The marker exists but carries no verdict — an exception is not a verdict.
    marker = json.loads(_integrity_verdict_path(cfg).read_text())
    assert "chain_state" not in marker
    assert marker["last_attempt"]["chain_state"] == "error"

    run_doctor(json_output=True)
    report = _doctor_report(capsys)
    assert _find_check(report, "chain_integrity")["status"] == "warn"
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
    principal_binding_verified: bool | None = True,
):
    path = _integrity_verdict_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    checked = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=age_hours)
    verdict = {
        "checked_at": checked.isoformat(),
        "chain_state": state,
        "chain_ok": state == "verified",
        "store_binding": binding if binding is not None else _store_binding(cfg),
    }
    # ``None`` writes a pre-WI-036 marker, which carried no binding field at all.
    if principal_binding_verified is not None:
        verdict["principal_binding_verified"] = principal_binding_verified
        if principal_binding_verified:
            verdict["principal_binding_failures"] = 0
    path.write_text(json.dumps(verdict))


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


def test_integrity_verifies_production_scale_chain(monkeypatch, cfg, capsys, tmp_path):
    """End-to-end: a chain with thousands of signed events replays and
    verifies through ``cairn integrity``, while doctor never pays that cost."""
    from conftest import CAIRN_TEST_PRINCIPALS
    from regista.testing import InMemoryRegista, make_v6_keyset, open_v6_epoch

    from cairn import CairnAdapter, CairnConfig

    monkeypatch.setenv("CAIRN_TEST_SECRET", "0" * 64)
    keyset = make_v6_keyset(tmp_path, principals=CAIRN_TEST_PRINCIPALS)
    sub = InMemoryRegista(project="cairn_scale", hmac_key_path=keyset.path)
    open_v6_epoch(sub, keyset, principals=CAIRN_TEST_PRINCIPALS)
    sub.register_workflow_file("workflows/cairn_agent_actions.yaml")
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

    # The in-memory backend documents its principal-binding check as a no-op
    # and reports ``principal_binding_verified=False``. Post-WI-036 cairn does
    # not launder that into "verified": the honest verdict is that binding was
    # not verified, which is a nonzero exit and a doctor warning — not green.
    rc = run_integrity(json_output=True)
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["chain_state"] == "unverified_binding"
    assert out["principal_binding_verified"] is False
    assert "principal_binding_failures" not in out

    started = time.monotonic()
    run_doctor(json_output=True)
    elapsed = time.monotonic() - started
    report = _doctor_report(capsys)
    chain = _find_check(report, "chain_integrity")
    assert chain["status"] == "warn"
    assert "NOT verified" in chain["detail"]
    assert elapsed < 10.0


# ---------------------------------------------------------------------------
# WI-036 — a chain the offline verifier rejects must not read [OK]
# ---------------------------------------------------------------------------


def test_integrity_requests_the_binding_check_explicitly(monkeypatch, cfg, capsys):
    """regista's ``replay()`` Python API defaults ``verify_principal_binding``
    OFF for backward compatibility (only the CLI defaults it on), so cairn must
    ask. Reading ``replayed_drift``/``halted`` off an unasked replay is how
    ``chain_integrity`` reported OK on an unattributable chain (WI-036)."""
    stub = _StubRegista()
    _patch_regista(monkeypatch, cfg, stub)

    assert run_integrity(json_output=True) == 0
    capsys.readouterr()
    assert stub.binding_requested is True


def test_integrity_binding_failure_exits_nonzero_and_doctor_reports_it(
    monkeypatch, cfg, capsys
):
    """THE WI-036 REGRESSION.

    A chain whose every event is signed by a key the project never registered:
    ``regista bundle verify`` rejects all of it ("No public key for key_id …"),
    while replay reports zero drift and zero halted events. cairn read only
    those two counters, so ``cairn integrity`` printed ``[OK] chain_integrity``
    and doctor republished it into ``suite: OK``.
    """
    stub = _StubRegista(
        replay_report=ReplayReport(
            table_name="events",
            replayed_ok=4,
            replayed_drift=0,
            halted=0,
            principal_binding_failures=4,
            principal_binding_verified=True,
        )
    )
    _patch_regista(monkeypatch, cfg, stub)

    rc = run_integrity(json_output=True)
    assert rc == 1, "an unattributable chain must not exit 0"
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert out["chain_state"] == "unattributable"
    assert out["principal_binding_failures"] == 4
    # ok:false bodies must name their reason (suite envelope contract).
    assert "unattributable" in out["detail"]

    # The recorded verdict is a failure doctor reports, not a warning.
    verdict = json.loads(_integrity_verdict_path(cfg).read_text())
    assert verdict["chain_state"] == "unattributable"
    assert verdict["chain_ok"] is False

    rc = run_doctor(json_output=True)
    assert rc == 1
    report = _doctor_report(capsys)
    check = _find_check(report, "chain_integrity")
    assert check["status"] == "fail"
    assert "unattributable" in check["detail"]
    assert report["regista"]["chain_ok"] is False
    assert report["regista"]["chain_state"] == "unattributable"


def test_integrity_not_verified_is_not_reported_as_verified(monkeypatch, cfg, capsys):
    """The WI-223 lesson: an unexamined zero is not an affirmative claim.

    A replay that did not run the binding check reports
    ``principal_binding_failures=0`` because nothing looked. Publishing that as
    "verified" is exactly the defect. Honest verdict: not verified.
    """
    stub = _StubRegista(
        replay_report=ReplayReport(
            table_name="events",
            replayed_ok=4,
            replayed_drift=0,
            halted=0,
            principal_binding_failures=0,
            principal_binding_verified=False,
        )
    )
    _patch_regista(monkeypatch, cfg, stub)

    rc = run_integrity(json_output=True)
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["chain_state"] == "unverified_binding"
    assert out["principal_binding_verified"] is False
    # The count is omitted, not recorded as zero — mirrors ReplayReport.to_dict.
    assert "principal_binding_failures" not in out

    run_doctor(json_output=True)
    report = _doctor_report(capsys)
    check = _find_check(report, "chain_integrity")
    assert check["status"] == "warn"
    assert "NOT verified" in check["detail"]
    assert report["regista"]["chain_ok"] is None


def test_integrity_with_a_regista_too_old_for_the_kwarg(monkeypatch, cfg, capsys):
    """An older regista whose ``replay`` rejects the kwarg must degrade to
    "not verified", never to "verified" (the loose-pin case named in WI-036)."""
    stub = _LegacyStubRegista()
    _patch_regista(monkeypatch, cfg, stub)

    rc = run_integrity(json_output=True)
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["chain_state"] == "unverified_binding"
    assert stub.binding_requested is None


def test_pre_wi036_verdict_marker_is_not_replayed_as_a_pass(cfg):
    """A recorded "verified" from a cairn that never checked binding carries no
    evidence of attributability — the same reasoning as the store_binding
    guard, and it must not be reported as ok."""
    _write_verdict(cfg, age_hours=1.0, principal_binding_verified=None)
    check, chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "warn"
    assert "predates principal-binding verification" in check["detail"]
    assert chain_state == "unverified_binding"
    assert chain_ok is None


def test_unattributable_verdict_from_another_store_is_not_reported(cfg):
    """A finding certifies one store+project, like every other verdict."""
    _write_verdict(cfg, age_hours=1.0, state="unattributable", binding="deadbeefdeadbeef")
    check, chain_state, _chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "skip"
    assert chain_state == "unbound"


def test_key_file_names_the_key_the_signer_would_pick(cfg, tmp_path):
    """``keys[0]`` is not the signer's rule.

    On the real key file the bootstrap HMAC entry came first, so doctor named it
    "active" while every event was signed by the last active Ed25519 entry
    (WI-036). regista exports the rule; use it.
    """
    from cairn._doctor import _check_key_file

    key_path = tmp_path / "multi-keys.json"
    key_path.write_text(
        json.dumps(
            {
                "keys": [
                    {"key_id": "bootstrap-hmac", "scheme": "hmac-sha256", "status": "active"},
                    {"key_id": "pk_old", "scheme": "ed25519", "status": "deprecated"},
                    {"key_id": "pk_current", "scheme": "ed25519", "status": "active"},
                ]
            }
        )
    )
    check = _check_key_file(
        CairnEnvConfig(dsn=cfg.dsn, key_path=str(key_path), project=cfg.project)
    )
    assert check["status"] == "ok"
    assert "pk_current" in check["detail"]
    assert "bootstrap-hmac" not in check["detail"]


def test_key_file_with_no_active_key_fails(cfg, tmp_path):
    from cairn._doctor import _check_key_file

    key_path = tmp_path / "revoked-keys.json"
    key_path.write_text(
        json.dumps({"keys": [{"key_id": "pk_dead", "scheme": "ed25519", "status": "revoked"}]})
    )
    check = _check_key_file(
        CairnEnvConfig(dsn=cfg.dsn, key_path=str(key_path), project=cfg.project)
    )
    assert check["status"] == "fail"
    assert "none active" in check["detail"]


# ---------------------------------------------------------------------------
# WI-036, end to end against Postgres: the chain the offline verifier rejects
# ---------------------------------------------------------------------------


@pytest.fixture
def v6_postgres_store(tmp_path):
    """A real Postgres-backed v6 project with a healthy attributable chain.

    Provisioned exactly as the suite bootstrap would: a v6 keyset, an opened
    epoch accepting the cairn test principals, cairn's workflow registered as
    a signed event, and a tool-call chain written through the adapter.

    WI-036 history: this replaces the ``unattributable_store`` fixture, which
    built a chain signed by an Ed25519 key the project never registered — a
    real pre-v6 defect (reached by provisioning the principal in a different
    project against the same key file, regista WI-223). regista's v6 epoch
    makes that state unwritable: every append must resolve a preceding
    key-binding anchor (``KEY_BINDING_UNRESOLVED`` refusal at write time), and
    a v6 event's principal binding is established by the acceptance chain,
    never by the ``principal_keys`` projection. The write-refusal half is
    pinned by ``test_integrity_unaccepted_principal_is_refused_at_write_time``
    below; this fixture pins the positive half — a legitimately written v6
    chain verifies end to end.
    """
    from conftest import CAIRN_TEST_PRINCIPALS
    from regista import Regista
    from regista.testing import (
        drop_project_schema,
        make_v6_keyset,
        open_v6_epoch,
    )

    from cairn import CairnAdapter, CairnConfig

    dsn = resolve_test_dsn()
    if not postgres_reachable(dsn):
        pytest.skip("Postgres not available; set REGISTA_TEST_DSN to run")

    keyset = make_v6_keyset(tmp_path, principals=CAIRN_TEST_PRINCIPALS)
    project = f"cairn_v6_{uuid.uuid4().hex[:8]}"
    Regista.create_project(dsn=dsn, project=project, hmac_key_path=keyset.path)
    sub = Regista(dsn=dsn, project=project, hmac_key_path=keyset.path)
    try:
        open_v6_epoch(sub, keyset, principals=CAIRN_TEST_PRINCIPALS)
        sub.register_workflow_file("workflows/cairn_agent_actions.yaml")
        adapter = CairnAdapter(
            sub,
            config=CairnConfig("test-harness", "0.0"),
            on_behalf_of={
                "principal_id": "human:test",
                "session_id": str(uuid.uuid4()),
            },
        )
        wi = adapter.begin_tool_call(tool="Read", tool_args={"path": "/tmp/x"})
        adapter.end_tool_call(wi.work_item_id, result_summary={"exit_code": 0})
    finally:
        sub.close()

    cfg = CairnEnvConfig(
        dsn=dsn,
        key_path=keyset.path,
        key_ref=None,
        project=project,
        state_dir=str(tmp_path / "state"),
        integrity_dir=str(tmp_path / "integrity"),
    )
    try:
        yield cfg
    finally:
        drop_project_schema(dsn, project)


def test_integrity_unaccepted_principal_is_refused_at_write_time(tmp_path):
    """The WI-036 defect class is unwritable in a v6 epoch.

    Pre-v6, a key this project never registered could sign a durable chain
    that every verifier then rejected as unattributable. The v6 writer refuses
    the append itself when no preceding key-binding anchor accepts the
    (principal, key) pair — the unattributable chain can no longer exist.
    """
    from regista import ErrorCode, Regista, RegistaError
    from regista.testing import drop_project_schema, make_v6_keyset, open_v6_epoch

    dsn = resolve_test_dsn()
    if not postgres_reachable(dsn):
        pytest.skip("Postgres not available; set REGISTA_TEST_DSN to run")

    # A keyset whose "agent:rogue" principal was NEVER accepted by the project.
    keyset = make_v6_keyset(tmp_path, principals=("agent:rogue",))
    project = f"cairn_v6_{uuid.uuid4().hex[:8]}"
    Regista.create_project(dsn=dsn, project=project, hmac_key_path=keyset.path)
    sub = Regista(dsn=dsn, project=project, hmac_key_path=keyset.path)
    try:
        open_v6_epoch(sub, keyset, principals=())  # genesis, no acceptances
        sub.register_workflow_file("workflows/cairn_agent_actions.yaml")
        with pytest.raises(RegistaError) as excinfo:
            sub.create_work_item(
                workflow_name="cairn_agent_actions",
                work_item_type="tool_call",
                actor_id="agent:rogue",
                actor_metadata={"role": "agent"},
                custom_fields={"tool": "Bash", "status": "running"},
            )
        assert excinfo.value.code == ErrorCode.KEY_BINDING_UNRESOLVED
    finally:
        sub.close()
        drop_project_schema(dsn, project)


def test_integrity_verifies_a_healthy_v6_postgres_chain(
    monkeypatch, v6_postgres_store, capsys
):
    """End to end, no stubs: `cairn integrity` against a real v6 chain exits
    zero with binding verified through the acceptance chain, and `cairn
    doctor` reports the recorded verdict without replaying."""
    cfg = v6_postgres_store
    monkeypatch.setattr(doctor_mod, "resolve_config", lambda: cfg)

    rc = run_integrity(json_output=True)
    out = json.loads(capsys.readouterr().out)
    assert rc == 0, out
    assert out["chain_state"] == "verified", out
    assert out["principal_binding_verified"] is True

    # Doctor's overall exit aggregates unrelated environment checks (harness
    # wiring, hook self-tests), so this test pins the chain verdict itself.
    run_doctor(json_output=True)
    report = _doctor_report(capsys)
    check = _find_check(report, "chain_integrity")
    assert check["status"] == "ok", report
    assert report["regista"]["chain_ok"] is True


# ---------------------------------------------------------------------------
# Verdict-marker MAC (WI-031) + never-verified failed-attempt marker (WI-032)
#
# These tests exercise the marker hardening directly (helpers + doctor's read
# path) and via run_integrity with _verify_chain stubbed, so they do NOT depend
# on regista 0.5.4's ReplayReport shape (the pre-existing WI-057 drift that
# breaks the stub-based tests above).
# ---------------------------------------------------------------------------

MAC_SECRET = "cairn-mac-test-secret"


@pytest.fixture
def keyed_cfg(cfg, monkeypatch):
    """A cfg whose store MAC key actually resolves (the key file's secret_ref
    points at CAIRN_TEST_SECRET, so set it)."""
    monkeypatch.setenv("CAIRN_TEST_SECRET", MAC_SECRET)
    return cfg


def _write_raw_verdict(cfg, body: dict) -> None:
    path = _integrity_verdict_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body))


def _fresh_verified_body(cfg, **over) -> dict:
    body = {
        "checked_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "chain_state": "verified",
        "chain_ok": True,
        "store_binding": _store_binding(cfg),
        "principal_binding_verified": True,
        "principal_binding_failures": 0,
    }
    body.update(over)
    return body


def test_store_mac_key_resolves_from_key_path_secret_ref(keyed_cfg):
    assert _store_mac_key(keyed_cfg) == MAC_SECRET.encode()


def test_store_mac_key_is_none_when_unresolvable(cfg, monkeypatch):
    monkeypatch.delenv("CAIRN_TEST_SECRET", raising=False)
    assert _store_mac_key(cfg) is None


def test_compute_verdict_mac_is_deterministic_and_body_sensitive(keyed_cfg):
    body = _fresh_verified_body(keyed_cfg)
    mac1 = _compute_verdict_mac(keyed_cfg, body)
    mac2 = _compute_verdict_mac(keyed_cfg, dict(body))
    assert mac1 is not None
    assert mac1 == mac2  # deterministic
    assert mac1.startswith("hmac-sha256:")
    # The MAC field itself is excluded, so adding it does not change the MAC.
    with_mac = dict(body, mac=mac1)
    assert _compute_verdict_mac(keyed_cfg, with_mac) == mac1
    # Any field change invalidates it.
    tampered = dict(body, chain_state="drift")
    assert _compute_verdict_mac(keyed_cfg, tampered) != mac1


def test_compute_verdict_mac_is_none_without_a_key(cfg, monkeypatch):
    monkeypatch.delenv("CAIRN_TEST_SECRET", raising=False)
    assert _compute_verdict_mac(cfg, _fresh_verified_body(cfg)) is None


def test_verdict_mac_state_classifications(keyed_cfg, cfg, monkeypatch):
    body = _fresh_verified_body(keyed_cfg)
    mac = _compute_verdict_mac(keyed_cfg, body)
    assert mac is not None

    # stripped: no mac field but a store key IS resolvable (WI-031 fail-open fix
    # — a same-host writer deleting the mac no longer earns silent trust)
    assert _verdict_mac_state(keyed_cfg, dict(body)) == "stripped"
    # valid: mac matches
    assert _verdict_mac_state(keyed_cfg, dict(body, mac=mac)) == "valid"
    # invalid: body tampered, mac stale
    assert _verdict_mac_state(keyed_cfg, dict(body, chain_state="drift", mac=mac)) == "invalid"
    # unkeyed: mac present but no key to check it
    monkeypatch.delenv("CAIRN_TEST_SECRET", raising=False)
    assert _verdict_mac_state(cfg, dict(body, mac=mac)) == "unkeyed"
    # legacy: no mac field AND no key resolvable (pre-WI-031 / un-keyed store)
    assert _verdict_mac_state(cfg, dict(body)) == "legacy"


def test_doctor_accepts_a_valid_mac(keyed_cfg):
    body = _fresh_verified_body(keyed_cfg)
    body["mac"] = _compute_verdict_mac(keyed_cfg, body)
    _write_raw_verdict(keyed_cfg, body)

    check, chain_state, chain_ok = _check_chain_integrity(keyed_cfg)
    assert check["status"] == "ok"
    assert chain_state == "verified"
    assert chain_ok is True


def test_doctor_rejects_a_tampered_verdict_marker(keyed_cfg):
    """A drift verdict re-labelled 'verified' without the key must fail closed."""
    body = _fresh_verified_body(keyed_cfg, chain_state="drift", chain_ok=False)
    body["mac"] = _compute_verdict_mac(keyed_cfg, body)  # MAC over the drift body
    body["chain_state"] = "verified"  # forge a green verdict
    body["chain_ok"] = True
    _write_raw_verdict(keyed_cfg, body)

    check, chain_state, chain_ok = _check_chain_integrity(keyed_cfg)
    assert check["status"] == "fail"
    assert chain_state == "tampered"
    assert chain_ok is False
    assert "MAC" in check["detail"]


def test_doctor_treats_an_unkeyed_mac_as_unverified(cfg, keyed_cfg, monkeypatch):
    body = _fresh_verified_body(keyed_cfg)
    body["mac"] = _compute_verdict_mac(keyed_cfg, body)
    _write_raw_verdict(cfg, body)
    monkeypatch.delenv("CAIRN_TEST_SECRET", raising=False)  # key now unavailable

    check, chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "warn"
    assert chain_state == "unverified_marker"
    assert chain_ok is None


def test_doctor_tolerates_a_legacy_unmacd_marker(cfg, monkeypatch):
    """Pre-WI-031 markers carry no MAC and are still evaluated on chain_state."""
    monkeypatch.delenv("CAIRN_TEST_SECRET", raising=False)
    _write_raw_verdict(cfg, _fresh_verified_body(cfg))

    check, chain_state, chain_ok = _check_chain_integrity(cfg)
    assert check["status"] == "ok"
    assert chain_state == "verified"
    assert chain_ok is True


def test_doctor_warns_on_a_stripped_mac_when_a_key_is_configured(keyed_cfg):
    """WI-031 fail-open fix: with a store key configured, a verdict marker whose
    MAC field was deleted (or never written) must NOT be silently trusted — a
    same-host writer stripping the mac to flip drift->verified is caught."""
    _write_raw_verdict(keyed_cfg, _fresh_verified_body(keyed_cfg))  # no mac field

    check, chain_state, chain_ok = _check_chain_integrity(keyed_cfg)
    assert check["status"] == "warn"
    assert chain_state == "unverified_marker"
    assert chain_ok is None
    assert "MAC" in check["detail"]


def _patch_regista_no_replay(monkeypatch, cfg) -> None:
    """Yield an inert client; _verify_chain is stubbed separately, so no replay
    runs and the broken 0.5.4 ReplayReport default is never constructed."""
    @contextmanager
    def _fake_open(_cfg):
        yield object()

    monkeypatch.setattr(doctor_mod, "_open_regista", _fake_open)
    monkeypatch.setattr(doctor_mod, "resolve_config", lambda: cfg)


def test_run_integrity_stamps_a_valid_mac_and_event_count(keyed_cfg, monkeypatch, capsys):
    """run_integrity records verified_event_count and a MAC doctor can verify."""
    binding = {
        "principal_binding_verified": True,
        "principal_binding_failures": None,
        "replayed_ok": 42,
    }
    monkeypatch.setattr(doctor_mod, "_verify_chain", lambda sub: ("verified", True, binding))
    _patch_regista_no_replay(monkeypatch, keyed_cfg)

    rc = run_integrity(json_output=True)
    assert rc == 0
    capsys.readouterr()  # drain the integrity output before doctor runs

    marker = json.loads(_integrity_verdict_path(keyed_cfg).read_text())
    assert marker["verified_event_count"] == 42
    assert isinstance(marker.get("mac"), str)
    # The recorded MAC verifies against the stored body.
    assert _verdict_mac_state(keyed_cfg, marker) == "valid"

    # And doctor trusts it end to end.
    run_doctor(json_output=True)
    report = _doctor_report(capsys)
    assert _find_check(report, "chain_integrity")["status"] == "ok"


def test_run_integrity_writes_no_mac_when_key_unavailable(cfg, monkeypatch, capsys):
    monkeypatch.delenv("CAIRN_TEST_SECRET", raising=False)
    binding = {
        "principal_binding_verified": True,
        "principal_binding_failures": None,
        "replayed_ok": 7,
    }
    monkeypatch.setattr(doctor_mod, "_verify_chain", lambda sub: ("verified", True, binding))
    _patch_regista_no_replay(monkeypatch, cfg)

    rc = run_integrity(json_output=True)
    assert rc == 0
    marker = json.loads(_integrity_verdict_path(cfg).read_text())
    assert "mac" not in marker  # honest: un-MAC'd rather than a broken MAC
    assert marker["verified_event_count"] == 7


# --- WI-032: never-verified store with a persistently failing replay ---


def test_record_failed_attempt_seeds_a_marker_when_none_exists(keyed_cfg):
    """A never-verified store gets a chain_state-less marker holding the attempt."""
    assert _load_integrity_verdict(keyed_cfg) is None

    _record_failed_attempt(keyed_cfg, "unreachable")

    marker = json.loads(_integrity_verdict_path(keyed_cfg).read_text())
    assert "chain_state" not in marker  # no verdict was ever reached
    assert marker["store_binding"] == _store_binding(keyed_cfg)
    assert marker["last_attempt"]["chain_state"] == "unreachable"


def test_doctor_warns_on_never_verified_with_failing_attempts(keyed_cfg):
    _record_failed_attempt(keyed_cfg, "error")

    check, chain_state, chain_ok = _check_chain_integrity(keyed_cfg)
    assert check["status"] == "warn"
    assert chain_state == "never_run"
    assert chain_ok is None
    assert "never verified" in check["detail"]


def test_record_failed_attempt_still_annotates_an_existing_verdict(keyed_cfg):
    """With a real verdict present, the attempt is annotated and re-MAC'd."""
    body = _fresh_verified_body(keyed_cfg)
    body["mac"] = _compute_verdict_mac(keyed_cfg, body)
    _write_raw_verdict(keyed_cfg, body)

    _record_failed_attempt(keyed_cfg, "error")

    marker = json.loads(_integrity_verdict_path(keyed_cfg).read_text())
    assert marker["chain_state"] == "verified"  # verdict untouched
    assert marker["last_attempt"]["chain_state"] == "error"
    assert _verdict_mac_state(keyed_cfg, marker) == "valid"  # re-MAC'd


def test_record_failed_attempt_ignores_a_foreign_store(keyed_cfg):
    body = _fresh_verified_body(keyed_cfg, store_binding="deadbeefdeadbeef")
    body["mac"] = _compute_verdict_mac(keyed_cfg, body)
    _write_raw_verdict(keyed_cfg, body)

    _record_failed_attempt(keyed_cfg, "error")

    marker = json.loads(_integrity_verdict_path(keyed_cfg).read_text())
    assert "last_attempt" not in marker  # foreign marker left alone
