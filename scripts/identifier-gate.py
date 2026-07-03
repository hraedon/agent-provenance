#!/usr/bin/env python3
"""CI identifier-gate: fail if known personal/internal identifiers appear in tracked files.

Run as a pre-publication gate and in CI to prevent re-introduction of
identifiers that were scrubbed before the repo went public.

Usage::

    python3 scripts/identifier-gate.py [--fix]

Exit 0 if clean, 1 if identifiers found.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

IDENTIFIERS: list[tuple[str, str]] = [
    ("human:plm", "personal principal_id handle"),
    ("human:itadmin", "OS username as principal_id"),
    ("plm@hraedon.com", "personal email"),
    ("Paul Merritt", "real name"),
    ("regista_app", "internal DB service account"),
    ("agent_notes_app", "internal DB service account"),
    ("mvmpostgres01", "internal hostname"),
    ("hraedon.com", "internal domain (non-GitHub)"),
]

EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".mypy_cache", ".claude"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}


def check_file(path: Path) -> list[tuple[str, int, str, str]]:
    findings: list[tuple[str, int, str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    for line_no, line in enumerate(text.splitlines(), 1):
        lower_line = line.lower()
        for pattern, description in IDENTIFIERS:
            if pattern.lower() in lower_line:
                findings.append((str(path), line_no, pattern, description))
    return findings


def main() -> int:
    all_findings: list[tuple[str, int, str, str]] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if path.suffix in EXCLUDE_SUFFIXES:
            continue
        rel = path.relative_to(REPO_ROOT)
        if str(rel) == "scripts/identifier-gate.py":
            continue
        all_findings.extend(check_file(path))

    if all_findings:
        print("IDENTIFIER GATE FAILED — personal/internal identifiers found:\n")
        for file_path, line_no, pattern, desc in all_findings:
            try:
                rel = Path(file_path).relative_to(REPO_ROOT)
            except ValueError:
                rel = file_path
            print(f"  {rel}:{line_no}  '{pattern}' ({desc})")
        print(f"\n{len(all_findings)} finding(s). Fix before publishing.")
        return 1

    print("Identifier gate: clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
