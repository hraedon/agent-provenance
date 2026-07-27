"""Wheel-installed cairn regression tests.

These tests verify that the built wheel (not just the editable source checkout)
contains the OpenCode plugin, that ``cairn install-harness opencode`` can locate
and register the packaged integration, and that the CLI conformance cases pass
against the installed wheel rather than silently skipping. Editable-source
coverage is not sufficient: a packaging or force-include mistake can leave the
wheel pluginless while local tests still pass.
"""

from __future__ import annotations

import json
import os
import re
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


def _build_wheel(tmp_path: Path) -> Path:
    """Build a cairn wheel into *tmp_path*/wheels and return its path."""
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    subprocess.run(
        [
            sys.executable, "-m", "pip", "wheel",
            str(REPO_ROOT), "--no-deps", "-w", str(wheel_dir),
        ],
        check=True,
        cwd=str(REPO_ROOT),
    )
    wheels = list(wheel_dir.glob("cairn-*.whl"))
    assert wheels, "no cairn wheel built"
    return wheels[0]


@pytest.mark.slow
def test_wheel_install_opencode_finds_plugin(tmp_path: Path, monkeypatch) -> None:
    """A released-wheel install must register the packaged OpenCode plugin."""
    wheel = _build_wheel(tmp_path)
    target = tmp_path / "installed"
    subprocess.run(
        [
            sys.executable, "-m", "pip", "install",
            "--no-deps", "--target", str(target), str(wheel),
        ],
        check=True,
    )

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
    subprocess.run(
        [
            sys.executable, "-m", "pip", "install",
            "--target", str(target), str(wheel),
        ],
        check=True,
    )

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
