"""Control narratives must come only from section 4.2 and its descendants."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from cairn._cli import TRUST_MODEL_CAVEAT, _extract_readme_sections, cli_entry


@pytest.mark.parametrize(
    "readme,expected",
    [
        ("# Other section\n> unrelated quotation\n", None),
        ("### 4.20 Other section\n> unrelated quotation\n", None),
        ("### 4.21 Other section\n> unrelated quotation\n", None),
        ("#### 4.20.1 Other child\n> unrelated quotation\n", None),
        ("### 4.2 Control\n> selected control\n", "selected control"),
        (
            "### 4.2 Control\n> selected control\n### 4.3 Next\n> unrelated quotation\n",
            "selected control",
        ),
        (
            "### 4.2 Control\n> selected control\n## 5 Next\n> unrelated quotation\n",
            "selected control",
        ),
        (
            "### 4.2 Control\n> selected control\n### 4.1 Previous\n> unrelated quotation\n",
            "selected control",
        ),
        (
            "### 4.2 Control\n> selected control\n### 4.20 Other\n> unrelated quotation\n",
            "selected control",
        ),
        (
            "### 4.2 Control\n> selected control\n### 4.21 Other\n> unrelated quotation\n",
            "selected control",
        ),
        (
            "### 4.2 Control\n> selected control\n#### 4.2.1 Child\n> child control\n"
            "##### 4.2.1.1 Grandchild\n> grandchild control\n## 5 Next\n> unrelated quotation\n",
            "selected control\nchild control\ngrandchild control",
        ),
        (
            "### 4.2 Control\n> selected control\n#### 4.2.10 Child\n> child control\n"
            "### 4.3 Next\n> unrelated quotation\n",
            "selected control\nchild control",
        ),
    ],
)
def test_control_section_boundaries(readme: str, expected: str | None) -> None:
    description, caveat = _extract_readme_sections(readme)
    assert description == expected
    assert caveat == TRUST_MODEL_CAVEAT


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize(
    "readme,expected",
    [
        ("### 4.20 Other\n> unrelated quotation\n", None),
        (
            "### 4.2 Control\n> selected control\n## 5 Next\n> unrelated quotation\n",
            "selected control",
        ),
        (
            "### 4.2 Control\n> selected control\n#### 4.2.1 Child\n> child control\n"
            "### 4.3 Next\n> unrelated quotation\n",
            "selected control\nchild control",
        ),
    ],
)
def test_extract_control_cli_keeps_source_attribution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fmt: str,
    readme: str,
    expected: str | None,
) -> None:
    path = tmp_path / "README.md"
    path.write_text(readme, encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["cairn", "extract-control", "--readme", str(path), "--format", fmt],
    )
    assert cli_entry() == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "unrelated quotation" not in captured.out
    if fmt == "json":
        payload = json.loads(captured.out)
        assert payload["control_description"] == expected
        assert payload["trust_model_caveat"] == TRUST_MODEL_CAVEAT
        assert payload["source_section"] == "§4.2"
        assert payload["source_path"] == str(path)
        assert payload["source_digest"] == "sha256:" + hashlib.sha256(readme.encode()).hexdigest()
    elif expected is None:
        assert "(No control description found in README §4.2)" in captured.out
    else:
        assert expected in captured.out
