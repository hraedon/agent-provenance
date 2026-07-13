"""I/O helpers for the live end-to-end proof script.

Extracted from ``scripts/e2e_proof.py`` (WI-028) so the proof I/O path
is testable and importable without the ``importlib.util`` hack the tests
previously used.

These functions bridge the pure proof logic in :mod:`cairn.proof` to the
real regista store and the canonical cairn verifier CLI.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cairn.proof import ProofEvent
from cairn.verifier_types import VerificationReport

if TYPE_CHECKING:
    import psycopg


def get_baseline_seq(conn: psycopg.Connection, project: str) -> int:
    """Return the current ``MAX(global_seq)`` for *project*.

    Events inserted after this point are the proof window.
    """
    from psycopg.sql import SQL, Identifier

    cur = conn.cursor()
    cur.execute(
        SQL("SELECT COALESCE(MAX(global_seq), 0) FROM {}.events").format(
            Identifier(project)
        )
    )
    row = cur.fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def query_events(
    conn: psycopg.Connection,
    project: str,
    baseline_seq: int,
) -> list[ProofEvent]:
    """Query all events after *baseline_seq* and build :class:`ProofEvent` rows."""
    from psycopg.sql import SQL, Identifier

    cur = conn.cursor()
    cur.execute(
        SQL(
            "SELECT transition, global_seq, entity_id::text, entity_kind, "
            "payload::text, on_behalf_of::text "
            "FROM {}.events WHERE global_seq > %s ORDER BY global_seq"
        ).format(Identifier(project)),
        (baseline_seq,),
    )
    rows = cur.fetchall()
    events: list[ProofEvent] = []
    for row in rows:
        transition = row[0]
        global_seq = row[1]
        entity_id = row[2]
        entity_kind = row[3] if row[3] else "work_item"
        payload = json.loads(row[4]) if row[4] else None
        on_behalf_of = json.loads(row[5]) if row[5] else None
        events.append(
            ProofEvent(
                transition=transition,
                global_seq=global_seq,
                entity_id=entity_id,
                entity_kind=entity_kind,
                payload=payload,
                on_behalf_of=on_behalf_of,
            )
        )
    return events


def parse_verifier_report(report_path: Path) -> VerificationReport | None:
    """Parse the JSON verifier report into a :class:`VerificationReport`.

    The canonical verifier's JSON output nests summary fields under a
    ``summary`` key (see :func:`cairn.verifier_report.format_report_json`).
    List fields like ``chain_contiguity_violations`` are at the top level.
    """
    from cairn.verifier_types import ChainContiguityViolation

    if not report_path.is_file():
        return None
    data = json.loads(report_path.read_text())
    summary = data.get("summary", {})
    report = VerificationReport()
    report.signature_failed = summary.get("signature_failed", 0)
    report.hash_mismatch = summary.get("hash_mismatch", 0)
    report.revoked_key = summary.get("revoked_key", 0)
    report.bundle_hash_ok = summary.get("bundle_hash_ok")
    report.chain_integrity_ok = summary.get("chain_integrity_ok")
    chain_violations = data.get("chain_contiguity_violations", [])
    for v in chain_violations:
        report.chain_contiguity_violations.append(
            ChainContiguityViolation(
                kind=v.get("kind", "unknown"),
                detail=v.get("detail", ""),
                event_id=v.get("event_id"),
                work_item_id=v.get("work_item_id"),
            )
        )
    return report


def run_canonical_verifier(
    dsn: str,
    project: str,
    key_path: str,
    tmpdir: Path,
    since: str,
) -> tuple[VerificationReport | None, str]:
    """Export events to a bundle and verify with the canonical cairn verifier.

    Returns ``(report, detail)``.  *report* is the parsed
    :class:`VerificationReport` on success, or ``None`` on failure (export
    crash, verify crash, missing report file).  *detail* is a human-readable
    status string.

    The export is scoped to events at or after *since* (the timestamp
    recorded just before launching the session) so the verifier checks only
    the proof window, not the entire project history (B2).

    Uses the public CLI (``cairn export`` + ``cairn verify``) rather than
    SQL chain checks, per the F-2 review's secondary observation that proofs
    should call public or auditor-facing verification APIs.
    """
    bundle_path = tmpdir / "proof-bundle.json"
    report_path = tmpdir / "verify-report.json"

    export_result = subprocess.run(
        [
            sys.executable, "-m", "cairn._cli", "export",
            "--dsn", dsn,
            "--project", project,
            "--keys", key_path,
            "--output", str(bundle_path),
            "--since", since,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if export_result.returncode != 0:
        return None, f"cairn export failed: {export_result.stderr.strip()}"

    verify_result = subprocess.run(
        [
            sys.executable, "-m", "cairn._cli", "verify",
            "--bundle-path", str(bundle_path),
            "--keys", key_path,
            "--format", "json",
            "--output", str(report_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if verify_result.returncode not in (0, 1):
        return None, f"cairn verify crashed: {verify_result.stderr.strip()}"

    if not report_path.is_file():
        return None, "cairn verify produced no report file"

    report = parse_verifier_report(report_path)
    if report is None:
        return None, "cairn verify produced an unparseable report"

    if report.all_ok:
        return report, "canonical verifier: all checks passed"
    return report, "canonical verifier: report not all_ok"
