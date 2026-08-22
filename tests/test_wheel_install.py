"""Wheel-installed cairn regression tests.

These tests verify that the built wheel (not just the editable source checkout)
contains the OpenCode plugin, that ``cairn install-harness opencode`` can locate
and register the packaged integration, and that the CLI conformance cases pass
against the installed wheel rather than silently skipping. Editable-source
coverage is not sufficient: a packaging or force-include mistake can leave the
wheel pluginless while local tests still pass.

They also pin the WI-038 decision that the Codex plugin bundle (``plugins/cairn``)
is deliberately *not* shipped, so its absence reads as a decision rather than an
oversight.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Summary-line parser for the conformance proof; copied from
# test_conformance_meta_guard.py so this file stands alone.
_SUMMARY_LINE_RE = re.compile(r"^(?P<line>.*?\bin \d+(?:\.\d+)?s)\s*$", re.MULTILINE)
_COUNT_RE = {
    "passed": re.compile(r"(\d+)\s+passed"),
    "skipped": re.compile(r"(\d+)\s+skipped"),
}


def _has_pip() -> bool:
    return (
        subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


def _builder() -> str:
    """Which tool can build/install here: ``pip``, ``uv``, or ``""``.

    A uv-created venv has no ``pip`` module, which is how this whole file failed
    with "No module named pip" — i.e. the wheel gate could not run at all, and a
    gate that cannot run verifies nothing.  uv itself builds and installs the
    same wheel, so prefer pip when present and fall back to uv.
    """
    if _has_pip():
        return "pip"
    if shutil.which("uv"):
        return "uv"
    return ""


def _require_builder() -> str:
    builder = _builder()
    if not builder:
        pytest.skip("neither pip nor uv is available to build/install a wheel")
    return builder


def _build_wheel(tmp_path: Path) -> Path:
    """Build a cairn wheel into *tmp_path*/wheels and return its path."""
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    if _require_builder() == "pip":
        cmd = [
            sys.executable, "-m", "pip", "wheel",
            str(REPO_ROOT), "--no-deps", "-w", str(wheel_dir),
        ]
    else:
        cmd = ["uv", "build", "--wheel", "--out-dir", str(wheel_dir), str(REPO_ROOT)]
    subprocess.run(cmd, check=True, cwd=str(REPO_ROOT))
    wheels = list(wheel_dir.glob("cairn-*.whl"))
    assert wheels, "no cairn wheel built"
    return wheels[0]


def _install_wheel(
    wheel: Path, target: Path, *, with_deps: bool, extra_sources: tuple[str, ...] = ()
) -> None:
    """Install *wheel* into *target*, with or without its declared deps.

    ``extra_sources`` are appended as explicit requirement specs (e.g. the
    sibling regista checkout with its extras) so the install resolves them
    locally instead of from the index.
    """
    specs = [str(wheel), *extra_sources]
    if _require_builder() == "pip":
        cmd = [sys.executable, "-m", "pip", "install", "--target", str(target), *specs]
        if not with_deps:
            cmd.insert(4, "--no-deps")
    else:
        cmd = ["uv", "pip", "install", "--target", str(target), *specs]
        if not with_deps:
            cmd.insert(3, "--no-deps")
    subprocess.run(cmd, check=True)


@pytest.mark.slow
def test_wheel_ships_integrations_but_not_the_codex_plugin_bundle(tmp_path: Path) -> None:
    """The packaging decision of WI-038, asserted against the artifact.

    ``integrations/`` must be inside the wheel because installed cairn reads it
    by path.  ``plugins/cairn/`` must NOT be: it is the Codex marketplace form,
    built by ``agent-suite codex-plugins build-marketplace`` from the workspace
    checkout, and no installed-cairn code path opens it.  Both halves are
    asserted so neither can change by accident — see the comment on
    ``[tool.hatch.build.targets.wheel.force-include]`` in pyproject.toml.
    """
    import zipfile

    wheel = _build_wheel(tmp_path)
    names = zipfile.ZipFile(wheel).namelist()

    assert "cairn/integrations/opencode/index.js" in names
    shipped_plugin_bundle = [
        n for n in names if n.startswith("plugins/") or "/plugins/cairn/" in n
    ]
    assert not shipped_plugin_bundle, (
        "the Codex plugin bundle is in the wheel; if that is now intended, update "
        f"the force-include comment in pyproject.toml: {shipped_plugin_bundle}"
    )

    # And the reason it need not ship: Codex wiring is generated from code.
    from cairn._install import CODEX_HOOK_EVENTS, _expected_hook_entry

    assert CODEX_HOOK_EVENTS
    for event in CODEX_HOOK_EVENTS:
        entry = _expected_hook_entry("codex", event)
        assert entry["hooks"][0]["command"].startswith("cairn-codex-hook")


@pytest.mark.slow
def test_wheel_install_opencode_finds_plugin(tmp_path: Path, monkeypatch) -> None:
    """A released-wheel install must register the packaged OpenCode plugin."""
    wheel = _build_wheel(tmp_path)
    target = tmp_path / "installed"
    _install_wheel(wheel, target, with_deps=False)

    # Verify the plugin file is inside the installed wheel layout.
    plugin = target / "cairn" / "integrations" / "opencode" / "index.js"
    assert plugin.is_file(), "OpenCode plugin missing from wheel layout"

    opencode_config = tmp_path / "opencode.json"
    monkeypatch.setenv("CAIRN_OPENCODE_CONFIG", str(opencode_config))

    env = os.environ.copy()
    pythonpath = str(target)
    if "PYTHONPATH" in env:
        pythonpath = pythonpath + os.pathsep + env["PYTHONPATH"]
    env["PYTHONPATH"] = pythonpath

    proc = subprocess.run(
        [
            sys.executable, "-m", "cairn._cli",
            "install-harness", "opencode", "--json",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"
    payload = json.loads(proc.stdout)
    assert payload[0]["status"] == "installed"
    assert payload[0]["harness"] == "opencode"
    assert payload[0]["no_op"] is False

    data = json.loads(opencode_config.read_text())
    sources = data.get("plugin", {}).get("sources", [])
    assert any(
        (isinstance(s, dict) and s.get("source") == str(plugin))
        or (isinstance(s, str) and s == str(plugin))
        for s in sources
    ), f"cairn plugin source not registered in {opencode_config}"


@pytest.mark.slow
def test_wheel_install_conformance_cases_pass(tmp_path: Path) -> None:
    """A clean target install resolves deps and conformance cases actually run."""
    wheel = _build_wheel(tmp_path)
    target = tmp_path / "installed"
    # Install the wheel and its declared runtime dependencies into a clean target
    # directory. This proves the wheel metadata is sufficient for resolution and
    # that the conformance gate does not depend on the editable source layout.
    #
    _install_wheel(wheel, target, with_deps=True)

    # cairn + its runtime dependencies landed in the target directory.
    assert (target / "cairn" / "__init__.py").is_file()
    assert (target / "regista" / "__init__.py").is_file()
    assert (target / "click" / "__init__.py").is_file()

    env = os.environ.copy()
    pythonpath = str(target)
    if "PYTHONPATH" in env:
        pythonpath = pythonpath + os.pathsep + env["PYTHONPATH"]
    env["PYTHONPATH"] = pythonpath

    conformance_test = REPO_ROOT / "tests" / "test_cli_conformance.py"
    proc = subprocess.run(
        [
            sys.executable, "-m", "pytest", str(conformance_test),
            "-q", "-p", "no:cacheprovider", "--no-header", "--color=no",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"

    summary_matches = list(_SUMMARY_LINE_RE.finditer(output))
    line = summary_matches[-1].group("line") if summary_matches else ""
    passed_match = _COUNT_RE["passed"].search(line)
    skipped_match = _COUNT_RE["skipped"].search(line)
    passed = int(passed_match.group(1)) if passed_match else 0
    skipped = int(skipped_match.group(1)) if skipped_match else 0
    assert passed >= 1, f"conformance cases did not run: {output}"
    assert skipped == 0, f"conformance cases skipped against wheel install: {output}"
