#!/usr/bin/env python3
"""Read-only audit of git history for forbidden identifier leaks.

This is the dry-run / report-only companion to the identifier gate.
It scans ALL of git history (every commit's diff content + commit messages
+ author/committer identity) for denylist identifiers and reports every
occurrence with commit hash, file, and line. It does NOT modify the repository.

Usage:
    python3 scripts/audit_history_identifiers.py [--output <path>]

The denylist defaults to .identifiers-denylist.local (gitignored). In CI
the identifiers come from $CAIRN_FORBIDDEN_IDENTIFIERS.

Output is written to the output file (default: docs/history-identifier-audit.md,
gitignored) and stderr.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_committed_identifiers import parse_identifier_set


@dataclass(frozen=True)
class HistoryLeak:
    commit: str
    identifier: str
    file: str
    line_number: int
    line: str
    context: str  # commit subject


def load_denylist() -> frozenset[str]:
    raw = os.environ.get("CAIRN_FORBIDDEN_IDENTIFIERS", "")
    if not raw.strip():
        denylist_path = Path(__file__).resolve().parent.parent / ".identifiers-denylist.local"
        if denylist_path.exists():
            raw = denylist_path.read_text()
    if not raw.strip():
        print(
            "No denylist found. Set $CAIRN_FORBIDDEN_IDENTIFIERS or create "
            ".identifiers-denylist.local",
            file=sys.stderr,
        )
        sys.exit(1)
    return parse_identifier_set(raw)


def get_all_commits() -> list[str]:
    result = subprocess.run(
        ["git", "log", "--all", "--format=%H"],
        capture_output=True, text=True, check=True,
    )
    return [h for h in result.stdout.strip().splitlines() if h]


def audit_commit(commit: str, identifiers: frozenset[str]) -> list[HistoryLeak]:
    leaks: list[HistoryLeak] = []
    subject_result = subprocess.run(
        ["git", "log", "-1", "--format=%s", commit],
        capture_output=True, text=True, check=True,
    )
    subject = subject_result.stdout.strip()

    diff_result = subprocess.run(
        ["git", "show", "--format=", "--unified=0", commit],
        capture_output=True, text=True, check=True,
    )
    current_file = ""
    line_number = 0
    for line in diff_result.stdout.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            line_number = 0
            continue
        if line.startswith("@@"):
            try:
                line_number = int(line.split("+")[1].split(",")[0]) - 1
            except (IndexError, ValueError):
                line_number = 0
            continue
        if line.startswith("+") and not line.startswith("+++"):
            line_number += 1
            content = line[1:]
            lower = content.lower()
            for identifier in identifiers:
                if identifier in lower:
                    leaks.append(HistoryLeak(
                        commit=commit[:12],
                        identifier=identifier,
                        file=current_file,
                        line_number=line_number,
                        line=content,
                        context=subject,
                    ))
        elif line.startswith(" "):
            line_number += 1

    msg_result = subprocess.run(
        ["git", "log", "-1", "--format=%B", commit],
        capture_output=True, text=True, check=True,
    )
    msg = msg_result.stdout
    for i, msg_line in enumerate(msg.splitlines(), 1):
        lower = msg_line.lower()
        for identifier in identifiers:
            if identifier in lower:
                leaks.append(HistoryLeak(
                    commit=commit[:12],
                    identifier=identifier,
                    file="<commit-message>",
                    line_number=i,
                    line=msg_line,
                    context=subject,
                ))

    # Check author/committer identity (name + email)
    identity_result = subprocess.run(
        ["git", "log", "-1", "--format=%an%n%ae%n%cn%n%ce", commit],
        capture_output=True, text=True, check=True,
    )
    for i, id_line in enumerate(identity_result.stdout.splitlines(), 1):
        lower = id_line.lower()
        for identifier in identifiers:
            if identifier in lower:
                role = (
                    "author-name" if i == 1
                    else "author-email" if i == 2
                    else "committer-name" if i == 3
                    else "committer-email"
                )
                leaks.append(HistoryLeak(
                    commit=commit[:12],
                    identifier=identifier,
                    file=f"<{role}>",
                    line_number=0,
                    line=id_line,
                    context=subject,
                ))
    return leaks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only audit of git history for forbidden identifier leaks.",
    )
    parser.add_argument(
        "--output", default="docs/history-identifier-audit.md",
        help="Output report file (default: docs/history-identifier-audit.md)",
    )
    args = parser.parse_args(argv)

    identifiers = load_denylist()
    print(
        f"Auditing git history against {len(identifiers)} forbidden identifiers...",
        file=sys.stderr,
    )

    commits = get_all_commits()
    print(f"Scanning {len(commits)} commits...", file=sys.stderr)

    all_leaks: list[HistoryLeak] = []
    for commit in commits:
        leaks = audit_commit(commit, identifiers)
        all_leaks.extend(leaks)

    all_leaks.sort(key=lambda lk: (lk.identifier, lk.commit, lk.file, lk.line_number))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    with output_path.open("w") as f:
        f.write("# Git History Identifier Audit\n\n")
        f.write(f"**Generated:** {now} (dry-run, read-only — no history was modified)\n\n")
        f.write(f"**Commits scanned:** {len(commits)}\n\n")
        f.write(f"**Identifiers checked:** {len(identifiers)}\n\n")
        f.write(f"**Leaks found:** {len(all_leaks)}\n\n")
        f.write("---\n\n")

        if not all_leaks:
            f.write("No leaks found. Git history is clean against the denylist.\n")
            print("\nNo leaks found. Git history is clean.", file=sys.stderr)
            return 0

        by_id: dict[str, list[HistoryLeak]] = {}
        for leak in all_leaks:
            by_id.setdefault(leak.identifier, []).append(leak)

        f.write("## Leaks by identifier\n\n")
        for identifier in sorted(by_id):
            leaks = by_id[identifier]
            f.write(f"### `{identifier}` ({len(leaks)} occurrence(s))\n\n")
            f.write("| Commit | File | Line | Content |\n")
            f.write("|--------|------|------|---------|\n")
            for leak in leaks:
                content = leak.line.replace("|", "\\|").replace("\n", "")[:120]
                f.write(f"| `{leak.commit}` | {leak.file} | {leak.line_number} | {content} |\n")
            f.write("\n")

        f.write("## Summary\n\n")
        f.write("| Identifier | Occurrences |\n")
        f.write("|------------|-------------|\n")
        for identifier in sorted(by_id):
            f.write(f"| `{identifier}` | {len(by_id[identifier])} |\n")
        f.write(f"| **Total** | **{len(all_leaks)}** |\n\n")

        f.write("---\n\n")
        f.write("## Remediation\n\n")
        f.write("This is a **dry-run report only**. No history was modified.\n\n")
        f.write("To remediate, a `git filter-repo` pass with `--replace-text` would be needed,\n")
        f.write("followed by a force-push and GitHub repo delete+recreate (per adcs-lens WI-010\n")
        f.write("lesson: force-push alone leaves pushed refs cached on GitHub's side).\n\n")
        f.write("The scrub must cover ALL identifier forms found above, not just hostnames.\n")

    print(f"\n{len(all_leaks)} leak(s) found across {len(by_id)} identifier(s).", file=sys.stderr)
    print(f"Report written to {output_path}", file=sys.stderr)
    for identifier in sorted(by_id):
        print(f"  {identifier}: {len(by_id[identifier])} occurrence(s)", file=sys.stderr)
    return 0 if not all_leaks else 2


if __name__ == "__main__":
    sys.exit(main())
