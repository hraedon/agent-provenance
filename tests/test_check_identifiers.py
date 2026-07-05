"""Tests for the committed-identifier gate."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from subprocess import CompletedProcess
from types import ModuleType

import pytest


def _load_checker() -> ModuleType:
    repo_root = Path(__file__).resolve().parent.parent
    path = repo_root / "scripts" / "check_committed_identifiers.py"
    spec = importlib.util.spec_from_file_location("check_committed_identifiers", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_committed_identifiers"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def checker() -> ModuleType:
    return _load_checker()


def test_parse_identifiers_filters_short_and_empty_tokens(checker: ModuleType) -> None:
    raw = "   abc  WORK-DOMAIN.local  \n   x   FAKEDOM  "
    identifiers = checker.parse_identifier_set(raw)
    assert identifiers == frozenset({"work-domain.local", "fakedom"})


def test_parse_identifiers_strips_comments(checker: ModuleType) -> None:
    raw = "# this is a comment\nFAKEDOM  # trailing comment\n   # full line comment\nREAL-TOKEN"
    identifiers = checker.parse_identifier_set(raw)
    assert identifiers == frozenset({"fakedom", "real-token"})


def test_parse_identifiers_normalizes_case(checker: ModuleType) -> None:
    identifiers = checker.parse_identifier_set("SYNTHETIC-DOMAIN synthetic.example.com")
    assert identifiers == frozenset({"synthetic-domain", "synthetic.example.com"})


def test_scan_text_no_identifiers_yields_nothing(checker: ModuleType) -> None:
    assert list(checker.scan_text("contains SYNTHETIC-DOMAIN", frozenset())) == []


def test_scan_text_finds_identifier_with_line_details(checker: ModuleType) -> None:
    text = "first line\nThis mentions SYNTHETIC-DOMAIN here.\nthird line"
    identifiers = frozenset({"synthetic-domain"})
    violations = list(checker.scan_text(text, identifiers))
    assert len(violations) == 1
    v = violations[0]
    assert v.identifier == "synthetic-domain"
    assert v.line_number == 2
    assert v.line == "This mentions SYNTHETIC-DOMAIN here."


def test_scan_text_is_case_insensitive(checker: ModuleType) -> None:
    text = "upper SYNTHETIC-DOMAIN lower synthetic-domain mixed SyNtHeTiC-dOmAiN"
    identifiers = frozenset({"synthetic-domain"})
    violations = list(checker.scan_text(text, identifiers))
    assert len(violations) == 3
    assert {v.line_number for v in violations} == {1}


def test_scan_text_matches_substring(checker: ModuleType) -> None:
    text = "prefix-SYNTHETIC-DOMAIN-suffix"
    identifiers = frozenset({"synthetic-domain"})
    violations = list(checker.scan_text(text, identifiers))
    assert len(violations) == 1


def test_scan_text_absent_identifier_yields_nothing(checker: ModuleType) -> None:
    text = "Nowhere in this text is the magic word."
    identifiers = frozenset({"synthetic-domain"})
    assert list(checker.scan_text(text, identifiers)) == []


def test_scan_files_finds_violation_in_text_file(checker: ModuleType, tmp_path: Path) -> None:
    file_path = tmp_path / "notes.md"
    file_path.write_text("Data from SYNTHETIC-DOMAIN\nMore data\n", encoding="utf-8")
    identifiers = frozenset({"synthetic-domain"})
    violations = checker.scan_files(identifiers, [file_path])
    assert len(violations) == 1
    assert violations[0].path == file_path


def test_scan_files_skips_binary_files(checker: ModuleType, tmp_path: Path) -> None:
    file_path = tmp_path / "binary.bin"
    file_path.write_bytes(b"\x00\x01\x02SYNTHETIC-DOMAIN\x00")
    identifiers = frozenset({"synthetic-domain"})
    assert checker.scan_files(identifiers, [file_path]) == []


def test_scan_files_handles_utf16_bom(checker: ModuleType, tmp_path: Path) -> None:
    file_path = tmp_path / "utf16.txt"
    file_path.write_bytes(
        b"\xff\xfe" + "SYNTHETIC-DOMAIN".encode("utf-16-le")
    )
    identifiers = frozenset({"synthetic-domain"})
    violations = checker.scan_files(identifiers, [file_path])
    assert len(violations) == 1


# --- Always-on samples/ guard ---


def test_leaked_tracked_files_detects_root_samples(checker: ModuleType) -> None:
    paths = [Path("samples/calibration.json"), Path("src/cairn/verifier.py")]
    leaked = checker.leaked_tracked_files(paths, checker._GUARDED_DIRS)
    assert leaked == [Path("samples/calibration.json")]


def test_leaked_tracked_files_ignores_nested_samples(checker: ModuleType) -> None:
    paths = [Path("tests/samples/test_data.json"), Path("src/main.py")]
    leaked = checker.leaked_tracked_files(paths, checker._GUARDED_DIRS)
    assert leaked == []


def test_main_blocks_tracked_file_under_samples(
    monkeypatch: pytest.MonkeyPatch, checker: ModuleType
) -> None:
    monkeypatch.setenv("CAIRN_FORBIDDEN_IDENTIFIERS", "")

    def fake_run(args: list[str], **kwargs: object) -> CompletedProcess[str]:
        return CompletedProcess(args=args, returncode=0, stdout="samples/data.json\0")

    monkeypatch.setattr(checker.subprocess, "run", fake_run)
    assert checker.main([]) == 1


# --- Secret-driven identifier scan ---


def test_main_exits_zero_when_env_var_empty(
    monkeypatch: pytest.MonkeyPatch, checker: ModuleType
) -> None:
    monkeypatch.setenv("CAIRN_FORBIDDEN_IDENTIFIERS", "")

    def fake_run(*args: object, **kwargs: object) -> CompletedProcess[str]:
        return CompletedProcess(args=[], returncode=0, stdout="")

    monkeypatch.setattr(checker.subprocess, "run", fake_run)
    assert checker.main([]) == 0


def test_main_exits_one_on_violation(
    monkeypatch: pytest.MonkeyPatch, checker: ModuleType, tmp_path: Path
) -> None:
    file_path = tmp_path / "leaked.txt"
    file_path.write_text("Secret FAKEDOM value\n", encoding="utf-8")
    monkeypatch.setenv("CAIRN_FORBIDDEN_IDENTIFIERS", "FAKEDOM")

    def fake_run(args: list[str], **kwargs: object) -> CompletedProcess[str]:
        return CompletedProcess(args=args, returncode=0, stdout=f"{file_path}\0")

    monkeypatch.setattr(checker.subprocess, "run", fake_run)
    assert checker.main([]) == 1


def test_main_exits_zero_when_no_violation(
    monkeypatch: pytest.MonkeyPatch, checker: ModuleType, tmp_path: Path
) -> None:
    file_path = tmp_path / "clean.txt"
    file_path.write_text("Nothing sensitive here.\n", encoding="utf-8")
    monkeypatch.setenv("CAIRN_FORBIDDEN_IDENTIFIERS", "FAKEDOM")

    def fake_run(args: list[str], **kwargs: object) -> CompletedProcess[str]:
        return CompletedProcess(args=args, returncode=0, stdout=f"{file_path}\0")

    monkeypatch.setattr(checker.subprocess, "run", fake_run)
    assert checker.main([]) == 0


def test_staged_mode_scans_staged_diff(
    monkeypatch: pytest.MonkeyPatch, checker: ModuleType, tmp_path: Path
) -> None:
    file_path = tmp_path / "staged.txt"
    file_path.write_text("Secret FAKEDOM value\n", encoding="utf-8")
    monkeypatch.setenv("CAIRN_FORBIDDEN_IDENTIFIERS", "FAKEDOM")

    seen: dict[str, list[str]] = {}

    def fake_run(args: list[str], **kwargs: object) -> CompletedProcess[str]:
        seen["args"] = args
        return CompletedProcess(args=args, returncode=0, stdout=f"{file_path}\0")

    monkeypatch.setattr(checker.subprocess, "run", fake_run)
    assert checker.main(["--staged"]) == 1
    assert seen["args"] == [
        "git", "diff", "--cached", "--name-only",
        "--diff-filter=ACM", "--no-renames", "-z",
    ]


def test_main_scans_nested_samples_dir(
    monkeypatch: pytest.MonkeyPatch, checker: ModuleType, tmp_path: Path
) -> None:
    """Nested tests/samples/ is NOT blocked by the root-only guard and should
    be scanned by the identifier check (only .venv is skipped)."""
    nested_file = tmp_path / "tests" / "samples" / "data.txt"
    nested_file.parent.mkdir(parents=True)
    nested_file.write_text("Secret FAKEDOM value\n", encoding="utf-8")

    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("Nothing here\n", encoding="utf-8")

    monkeypatch.setenv("CAIRN_FORBIDDEN_IDENTIFIERS", "FAKEDOM")

    def fake_run(args: list[str], **kwargs: object) -> CompletedProcess[str]:
        return CompletedProcess(
            args=args, returncode=0,
            stdout=f"{nested_file}\0{clean_file}\0",
        )

    monkeypatch.setattr(checker.subprocess, "run", fake_run)
    # The nested samples file should be scanned (not skipped), finding the violation
    assert checker.main([]) == 1
