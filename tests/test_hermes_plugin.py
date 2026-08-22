"""Tests for the Hermes cairn plugin hook callbacks (Plan 010 WI-5.2).

``tests/test_install_doctor.py`` only covers the file-copy wiring
(``_install_hermes``/``_uninstall_hermes``). This module exercises the hook
logic itself: the session lifecycle, pre/post tool-call attestation (and
crucially that the *real* ``session_id`` — not a ``"pending"`` placeholder —
threads into the persisted delegation chain), ``_normalize_session_id``,
``_resolve_key_path`` (including the keyset-JSON branch), and
``reset_for_tests``.

The plugin is wired to an :class:`~regista.testing.InMemoryRegista`-backed
:class:`~cairn.adapter.CairnAdapter` (injected straight into the module
globals so ``_get_adapter`` returns it without touching ``resolve_config``
or a live ``Regista``), mirroring the in-memory adapter pattern in
``tests/test_cairn.py``.
"""

from __future__ import annotations

import json
import os
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import integrations.hermes as hermes

# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_plugin(monkeypatch):
    """Reset module state + ensure CAIRN_DISABLE is unset for every test."""
    monkeypatch.delenv("CAIRN_DISABLE", raising=False)
    hermes.reset_for_tests()
    yield
    hermes.reset_for_tests()


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """Wire the plugin to an InMemoryRegista-backed adapter.

    Injects ``_ADAPTER`` / ``_REGISTA`` / ``_CFG`` directly into the module
    so ``_get_adapter()`` returns them (its fast path) without calling
    ``resolve_config`` or constructing a live ``Regista``.
    """
    from conftest import CAIRN_TEST_PRINCIPALS
    from regista.testing import InMemoryRegista, make_v6_keyset, open_v6_epoch

    from cairn import CairnAdapter, CairnConfig
    from cairn._config import CairnEnvConfig

    hermes.reset_for_tests()
    monkeypatch.delenv("CAIRN_DISABLE", raising=False)

    # Provisioned exactly like the Postgres fixture: v6 keyset, opened epoch
    # (accepting the test principals), signed workflow registration. The v6
    # writer refuses unprovisioned writes by design.
    keyset = make_v6_keyset(tmp_path, principals=CAIRN_TEST_PRINCIPALS)
    sub = InMemoryRegista(project="cairn_hermes_test", hmac_key_path=keyset.path)
    open_v6_epoch(sub, keyset, principals=CAIRN_TEST_PRINCIPALS)
    sub.register_workflow_file("workflows/cairn_agent_actions.yaml")

    cfg = CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path="/tmp/nonexistent-keys.json",
        key_ref=None,
        project="cairn_hermes_test",
        harness_name="hermes",
        harness_version="0.1.0",
        principal_id="human:test",
    )
    adapter = CairnAdapter(
        sub,
        config=CairnConfig("hermes", "0.1.0"),
        # Adapter default carries principal_id only — the real session_id is
        # threaded per-event by the plugin (mirrors opencode parity).
        on_behalf_of={"principal_id": "human:test"},
    )

    monkeypatch.setattr(hermes, "_ADAPTER", adapter)
    monkeypatch.setattr(hermes, "_REGISTA", sub)
    monkeypatch.setattr(hermes, "_CFG", cfg)

    return SimpleNamespace(adapter=adapter, sub=sub, cfg=cfg)


# ----------------------------------------------------------------------
# _normalize_session_id
# ----------------------------------------------------------------------


def test_normalize_session_id_passthrough_valid_uuid():
    sid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert hermes._normalize_session_id(sid) == sid


def test_normalize_session_id_derives_deterministic_v5_for_non_uuid():
    derived = hermes._normalize_session_id("hermes-session-42")
    # Must be a valid UUID.
    uuid.UUID(derived)
    # Deterministic: same input → same output.
    assert hermes._normalize_session_id("hermes-session-42") == derived
    # Different input → different output.
    assert hermes._normalize_session_id("hermes-session-43") != derived
    # And it is a v5 (namespace-derived) UUID, not random.
    assert uuid.UUID(derived).version == 5


# ----------------------------------------------------------------------
# _extract_files
# ----------------------------------------------------------------------


def test_extract_files_single_path_keys():
    files = hermes._extract_files({"filePath": "/a", "file": "/b", "path": "/c"})
    # Order follows the key tuple (filePath, file_path, path, file); assert
    # membership + count rather than coupling to that internal order.
    assert set(files) == {"/a", "/b", "/c"}
    assert len(files) == 3


def test_extract_files_list_keys():
    files = hermes._extract_files({"files": ["/x", "/y"], "paths": "/z"})
    assert files == ["/x", "/y", "/z"]


def test_extract_files_ignores_non_string_and_missing():
    files = hermes._extract_files({"filePath": 123, "files": "not-a-list"})
    # 123 is ignored; a string under "files" is treated as a single path.
    assert files == ["not-a-list"]


def test_extract_files_empty_args():
    assert hermes._extract_files({}) == []


# ----------------------------------------------------------------------
# register(ctx)
# ----------------------------------------------------------------------


class _FakeCtx:
    def __init__(self):
        self.hooks: list[tuple[str, object]] = []

    def register_hook(self, name, fn):
        self.hooks.append((name, fn))


def test_register_wires_all_four_hooks():
    ctx = _FakeCtx()
    hermes.register(ctx)

    names = [name for name, _ in ctx.hooks]
    assert names == [
        "pre_tool_call",
        "post_tool_call",
        "on_session_start",
        "on_session_end",
    ]
    # Each registered callback is the module-level function.
    assert ctx.hooks[0][1] is hermes.on_pre_tool_call
    assert ctx.hooks[1][1] is hermes.on_post_tool_call
    assert ctx.hooks[2][1] is hermes.on_session_start
    assert ctx.hooks[3][1] is hermes.on_session_end


# ----------------------------------------------------------------------
# reset_for_tests
# ----------------------------------------------------------------------


def test_reset_for_tests_clears_state(monkeypatch):
    # Populate module state as if a session + tool call were in flight.
    monkeypatch.setattr(hermes, "_ADAPTER", object())
    monkeypatch.setattr(hermes, "_REGISTA", object())
    monkeypatch.setattr(hermes, "_CFG", object())
    monkeypatch.setattr(hermes, "_WORK_ITEMS", {"tc-1": uuid.uuid4()})
    monkeypatch.setattr(hermes, "_SESSION_ID", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    hermes.reset_for_tests()

    assert hermes._ADAPTER is None
    assert hermes._REGISTA is None
    assert hermes._CFG is None
    assert hermes._WORK_ITEMS == {}
    assert hermes._SESSION_ID is None


# ----------------------------------------------------------------------
# CAIRN_DISABLE fail-open
# ----------------------------------------------------------------------


def test_disabled_makes_hooks_noop(monkeypatch, wired):
    monkeypatch.setenv("CAIRN_DISABLE", "1")

    hermes.on_pre_tool_call(tool_name="Read", args={}, tool_call_id="tc-1",
                            session_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    hermes.on_session_start(session_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    # Nothing recorded — adapter never reached.
    assert hermes._WORK_ITEMS == {}
    assert hermes._SESSION_ID is None
    # No events of any kind were appended.
    assert wired.sub.query_work_items().items == []  # no work items created


# ----------------------------------------------------------------------
# Session lifecycle
# ----------------------------------------------------------------------


def test_session_start_attests_and_captures_session_id(wired):
    sid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    hermes.on_session_start(session_id=sid)

    # Captured for use by later tool-call events that lack their own session_id.
    assert hermes._SESSION_ID == sid

    events = wired.sub.read_events(work_item_id=uuid.UUID(sid))
    assert len(events) == 1
    ev = events[0]
    assert ev.transition == "session_attestation"
    assert ev.entity_kind == "note"
    payload = ev.payload or {}
    assert payload["session_id"] == sid
    assert payload["principal_id"] == "human:test"
    assert payload["scope_statement"] == "In scope: hermes."
    # The session attestation's delegation chain carries the real session_id
    # (built inside the adapter), never a placeholder.
    obo = (ev.payload or {}).get("on_behalf_of") or {}
    assert obo["session_id"] == sid
    assert obo.get("session_id") != "pending"


def test_session_start_normalizes_non_uuid_session_id(wired):
    raw = "hermes-run-99"
    hermes.on_session_start(session_id=raw)

    normalized = hermes._SESSION_ID
    assert normalized is not None
    assert normalized != raw
    uuid.UUID(normalized)  # valid UUID

    # The persisted attestation uses the normalized id.
    events = wired.sub.read_events(work_item_id=uuid.UUID(normalized))
    assert len(events) == 1
    assert (events[0].payload or {})["session_id"] == normalized


def test_session_end_clears_work_items_and_session_id(wired, monkeypatch):
    # Simulate in-flight state from a session + a tool call.
    monkeypatch.setattr(hermes, "_SESSION_ID", "cccccccc-cccc-cccc-cccc-cccccccccccc")
    monkeypatch.setattr(hermes, "_WORK_ITEMS", {"tc-1": uuid.uuid4(), "tc-2": uuid.uuid4()})

    hermes.on_session_end(session_id="cccccccc-cccc-cccc-cccc-cccccccccccc")

    assert hermes._WORK_ITEMS == {}
    assert hermes._SESSION_ID is None


def test_session_end_without_session_id_is_noop(wired):
    # No session_id kwarg → _cleanup does nothing (no crash, no state change).
    monkeypatch_session = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    # Set state directly to prove it is untouched.
    hermes._SESSION_ID = monkeypatch_session  # type: ignore[misc]
    hermes._WORK_ITEMS = {"tc-1": uuid.uuid4()}  # type: ignore[misc]

    hermes.on_session_end()

    assert hermes._SESSION_ID == monkeypatch_session
    assert "tc-1" in hermes._WORK_ITEMS


# ----------------------------------------------------------------------
# Pre / post tool call attestation
# ----------------------------------------------------------------------


def test_pre_post_tool_call_threads_real_session_id_from_kwargs(wired):
    """The begin event's delegation chain carries the real session_id from
    the hook kwargs — not the adapter default, and never 'pending'."""
    sid = "dddddddd-dddd-dddd-dddd-dddddddddddd"

    hermes.on_pre_tool_call(
        tool_name="Read",
        args={"filePath": "/tmp/secret.txt"},
        tool_call_id="tc-1",
        session_id=sid,
    )

    # The work item was registered for later end_tool_call matching.
    assert "tc-1" in hermes._WORK_ITEMS
    work_item_id = hermes._WORK_ITEMS["tc-1"]

    begin_events = wired.sub.read_events(
        work_item_id=work_item_id, transition="tool_call_begin"
    )
    assert len(begin_events) == 1
    begin = begin_events[0]
    # THE bug being fixed: session_id must be the real id, not "pending".
    obo = (begin.payload or {}).get("on_behalf_of") or {}
    assert obo["session_id"] == sid
    assert obo.get("session_id") != "pending"
    # And the payload's copy agrees.
    assert (begin.payload or {})["on_behalf_of"]["session_id"] == sid

    hermes.on_post_tool_call(
        tool_name="Read",
        tool_call_id="tc-1",
        result="ok",
        status="ok",
        session_id=sid,
    )

    # The matching begin was consumed.
    assert "tc-1" not in hermes._WORK_ITEMS
    end_events = wired.sub.read_events(
        work_item_id=work_item_id, transition="tool_call_end"
    )
    assert len(end_events) == 1
    end = end_events[0]
    obo = (end.payload or {}).get("on_behalf_of") or {}
    assert obo["session_id"] == sid
    assert obo.get("session_id") != "pending"


def test_pre_post_tool_call_uses_captured_session_id_when_kwarg_absent(wired):
    """When a tool-call event omits session_id, fall back to the id captured
    on session start (mirrors opencode threading session_id on every event)."""
    sid = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
    hermes.on_session_start(session_id=sid)
    assert hermes._SESSION_ID == sid

    # Note: no session_id kwarg on the tool-call events.
    hermes.on_pre_tool_call(
        tool_name="Write",
        args={"filePath": "/tmp/out.txt"},
        tool_call_id="tc-2",
    )
    work_item_id = hermes._WORK_ITEMS["tc-2"]

    begin = wired.sub.read_events(
        work_item_id=work_item_id, transition="tool_call_begin"
    )[0]
    assert (begin.payload or {})["on_behalf_of"]["session_id"] == sid

    hermes.on_post_tool_call(
        tool_name="Write",
        tool_call_id="tc-2",
        result={"wrote": 42},
        status="ok",
    )
    end = wired.sub.read_events(
        work_item_id=work_item_id, transition="tool_call_end"
    )[0]
    assert (end.payload or {})["on_behalf_of"]["session_id"] == sid


def test_no_pending_session_id_escapes_full_lifecycle(wired):
    """Across a full session→tool-call→end lifecycle, no persisted event
    ever carries session_id == 'pending' (the bug being fixed)."""
    sid = "11111111-1111-1111-1111-111111111111"

    hermes.on_session_start(session_id=sid)
    hermes.on_pre_tool_call(
        tool_name="Edit",
        args={"filePath": "/tmp/f.txt", "old": "a", "new": "b"},
        tool_call_id="tc-3",
        session_id=sid,
    )
    work_item_id = hermes._WORK_ITEMS["tc-3"]
    hermes.on_post_tool_call(
        tool_name="Edit",
        tool_call_id="tc-3",
        result="done",
        status="ok",
        session_id=sid,
    )
    hermes.on_session_end(session_id=sid)

    # Inspect every persisted event on both entities.
    checked: list[str] = []
    for entity_id in (uuid.UUID(sid), work_item_id):
        for ev in wired.sub.read_events(work_item_id=entity_id):
            obo = ev.on_behalf_of or {}
            assert obo.get("session_id") != "pending", (
                f"event {ev.transition} on {entity_id} carries session_id='pending'"
            )
            payload_obo = (ev.payload or {}).get("on_behalf_of") or {}
            assert payload_obo.get("session_id") != "pending", (
                f"payload of {ev.transition} carries session_id='pending'"
            )
            checked.append(ev.transition)
    # Sanity: we did inspect real events.
    assert "session_attestation" in checked
    assert "tool_call_begin" in checked
    assert "tool_call_end" in checked


def test_post_tool_call_without_matching_pre_is_noop(wired):
    """A post with no matching begin is a debug-log no-op, not a crash."""
    hermes.on_post_tool_call(
        tool_name="Read",
        tool_call_id="never-began",
        result="x",
        status="ok",
        session_id="22222222-2222-2222-2222-222222222222",
    )
    # No work item was created; the in-flight map is untouched.
    assert "never-began" not in hermes._WORK_ITEMS


def test_post_tool_call_failure_status_records_error(wired):
    """status != 'ok' produces a tool_call_fail transition carrying the error."""
    sid = "33333333-3333-3333-3333-333333333333"
    hermes.on_pre_tool_call(
        tool_name="Bash",
        args={"command": "false"},
        tool_call_id="tc-4",
        session_id=sid,
    )
    work_item_id = hermes._WORK_ITEMS["tc-4"]

    hermes.on_post_tool_call(
        tool_name="Bash",
        tool_call_id="tc-4",
        result="non-zero exit",
        status="error",
        error_message="exit code 1",
        session_id=sid,
    )

    fail_events = wired.sub.read_events(
        work_item_id=work_item_id, transition="tool_call_fail"
    )
    assert len(fail_events) == 1
    fail = fail_events[0]
    assert (fail.payload or {})["on_behalf_of"]["session_id"] == sid
    summary = (fail.payload or {}).get("result_summary") or {}
    assert summary["exit_code"] == 1


def test_post_tool_call_serializes_dict_result(wired):
    """A dict result is JSON-serialized into the stdout digest (v1 hashes
    outputs rather than storing them raw); the digest must be present."""
    sid = "44444444-4444-4444-4444-444444444444"
    hermes.on_pre_tool_call(
        tool_name="Search",
        args={"query": "x"},
        tool_call_id="tc-5",
        session_id=sid,
    )
    work_item_id = hermes._WORK_ITEMS["tc-5"]

    hermes.on_post_tool_call(
        tool_name="Search",
        tool_call_id="tc-5",
        result={"hits": [1, 2, 3]},
        status="ok",
        session_id=sid,
    )

    end = wired.sub.read_events(
        work_item_id=work_item_id, transition="tool_call_end"
    )[0]
    summary = (end.payload or {}).get("result_summary") or {}
    # v1 hashes stdout (digest-only); the dict was serialized without crashing
    # and produced a real sha256 digest (bare hex, 64 chars).
    assert len(summary["stdout_digest"]) == 64
    assert all(c in "0123456789abcdef" for c in summary["stdout_digest"])
    assert summary["exit_code"] == 0


# ----------------------------------------------------------------------
# _resolve_key_path
# ----------------------------------------------------------------------


def _cfg(key_path=None, key_ref=None):
    from cairn._config import CairnEnvConfig

    return CairnEnvConfig(
        dsn="postgresql://x@h/db",
        key_path=key_path,
        key_ref=key_ref,
        project="cairn_hermes_test",
    )


def test_resolve_key_path_returns_key_path_directly(tmp_path):
    key_file = tmp_path / "keys.json"
    key_file.write_text("{}")
    cfg = _cfg(key_path=str(key_file))

    assert hermes._resolve_key_path(cfg) == str(key_file)


def test_resolve_key_path_raises_when_neither_configured():
    with pytest.raises(RuntimeError, match="neither key_path nor key_ref"):
        hermes._resolve_key_path(_cfg())


def test_resolve_key_path_key_ref_keyset_json(monkeypatch):
    """When key_ref resolves to a JSON keyset, that keyset is written verbatim."""
    keyset = {
        "keys": [
            {
                "key_id": "k1",
                "scheme": "hmac-sha256",
                "secret": "actual-key-material",
            }
        ]
    }

    def fake_resolve(ref):
        assert ref == "env:MY_KEYSET"
        return json.dumps(keyset)

    monkeypatch.setattr("regista._secrets.resolve", fake_resolve)

    tmp_path = hermes._resolve_key_path(_cfg(key_ref="env:MY_KEYSET"))
    try:
        assert tmp_path != "env:MY_KEYSET"
        assert os.path.exists(tmp_path)
        # 0o600 permissions (fail-closed key hygiene).
        mode = stat.S_IMODE(os.stat(tmp_path).st_mode)
        assert mode == 0o600
        # The resolved keyset is written verbatim.
        assert json.loads(Path(tmp_path).read_text()) == keyset
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def test_resolve_key_path_key_ref_plain_secret(monkeypatch):
    """When key_ref resolves to a non-JSON secret, a wrapping keyset is built."""
    def fake_resolve(ref):
        assert ref == "vault:secret/data/cairn/key"
        return "plain-not-json-secret-value"

    monkeypatch.setattr("regista._secrets.resolve", fake_resolve)

    tmp_path = hermes._resolve_key_path(_cfg(key_ref="vault:secret/data/cairn/key"))
    try:
        assert os.path.exists(tmp_path)
        mode = stat.S_IMODE(os.stat(tmp_path).st_mode)
        assert mode == 0o600
        key_set = json.loads(Path(tmp_path).read_text())
        assert key_set["keys"][0]["key_id"] == "cairn-resolved"
        assert key_set["keys"][0]["scheme"] == "hmac-sha256"
        assert key_set["keys"][0]["secret_ref"] == "vault:secret/data/cairn/key"
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def test_resolve_key_path_key_ref_json_but_not_keyset(monkeypatch):
    """A key_ref that resolves to valid JSON but not a {keys:...} dict is
    wrapped into a keyset (the else branch)."""
    def fake_resolve(ref):
        return json.dumps("just-a-string")

    monkeypatch.setattr("regista._secrets.resolve", fake_resolve)

    tmp_path = hermes._resolve_key_path(_cfg(key_ref="env:STR"))
    try:
        key_set = json.loads(Path(tmp_path).read_text())
        assert key_set["keys"][0]["secret_ref"] == "env:STR"
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
