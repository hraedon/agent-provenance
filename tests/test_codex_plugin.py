"""Component-owned Codex plugin bundle contract (suite Plan 007)."""

from __future__ import annotations

import json
from pathlib import Path

from cairn._install import CODEX_HOOK_EVENTS, _expected_hook_entry

PLUGIN_ROOT = Path(__file__).resolve().parents[1] / "plugins" / "cairn"


def test_plugin_manifest_matches_suite_pin() -> None:
    manifest = json.loads((PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text())

    assert manifest["name"] == "cairn"
    assert manifest["version"] == "0.1.0"
    assert "hooks" not in manifest  # Codex discovers hooks/hooks.json by default.


def test_plugin_hooks_match_direct_installer_canonical_entries() -> None:
    payload = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text())

    assert set(payload["hooks"]) == set(CODEX_HOOK_EVENTS)
    for event in CODEX_HOOK_EVENTS:
        assert payload["hooks"][event] == [_expected_hook_entry("codex", event)]


def test_plugin_contains_no_credentials_or_secret_configuration() -> None:
    serialized = "\n".join(
        path.read_text()
        for path in (
            PLUGIN_ROOT / ".codex-plugin" / "plugin.json",
            PLUGIN_ROOT / "hooks" / "hooks.json",
        )
    )

    for forbidden in (
        "REGISTA_DSN",
        "REGISTA_KEY_PATH",
        "REGISTA_KEY_REF",
        "CAIRN_DSN",
        "CAIRN_KEY_PATH",
        "PRINCIPAL_ID",
        "auth.json",
    ):
        assert forbidden not in serialized
