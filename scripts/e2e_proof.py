#!/usr/bin/env python3
"""Plan 009 WI-2.2 — Live end-to-end provenance proof (F-2 fix).

Drives a real Claude Code session with a unique correlation marker, then
verifies:

1. The session_attestation event was created **after** the baseline sequence
   and is bound to the session the script launched (not a concurrent or
   stale session).
2. tool_call_end events belong to **this** session (via ``on_behalf_of``)
   and reference the correlation marker.
3. Attested digests match independently computed sha256 of real outputs.
4. The harness version is the real installed version (not "unknown").
5. The canonical cairn verifier (not a SQL NULL-count approximation) reports
   the hash chain intact.

Usage::

    python3 scripts/e2e_proof.py

Prerequisites:
  - cairn hooks wired (``cairn install-harness claude``)
  - regista reachable (``cairn doctor --json`` → ok)
  - ``claude`` on PATH

Exit code 0 = proof passed; non-zero = proof failed.
"""

from __future__ import annotations

import datetime
import json
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

try:
    import psycopg
    from psycopg.sql import SQL, Identifier
except ImportError:
    print("ERROR: psycopg3 not installed", file=sys.stderr)
    sys.exit(2)

from cairn.proof import ProofEvent, ProofFailure, run_proof
from cairn.verifier_types import VerificationReport


def _get_config() -> dict[str, str]:
    """Resolve regista config from suite.env or Claude Code settings."""
    suite_env_path = Path.home() / ".config" / "agent-suite" / "suite.env"
    if suite_env_path.is_file():
        vals: dict[str, str] = {}
        for line in suite_env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                vals[k.strip()] = v.strip()
        return vals

    settings_path = Path.home() / ".claude" / "settings.json"
    if settings_path.is_file():
        data = json.loads(settings_path.read_text())
        env = data.get("env", {})
        return {
            "REGISTA_DSN": env.get("AGENT_NOTES_REGISTA_DSN", ""),
            "REGISTA_KEY_PATH": env.get("AGENT_NOTES_REGISTA_HMAC_KEY_PATH", ""),
            "CAIRN_PROJECT": "agent_provenance",
        }

    print("ERROR: no config found (suite.env or Claude settings.json)", file=sys.stderr)
    sys.exit(2)


def _detect_claude_version() -> str:
    result = subprocess.run(
        ["claude", "--version"], capture_output=True, text=True, timeout=5
    )
    raw = result.stdout.strip()
    if result.returncode != 0 or not raw:
        return "unknown"
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", raw)
    if m:
        return m.group(1)
    return "unknown"


def _get_baseline_seq(conn: psycopg.Connection, project: str) -> int:
    cur = conn.cursor()
    cur.execute(
        SQL("SELECT COALESCE(MAX(global_seq), 0) FROM {}.events").format(
            Identifier(project)
        )
    )
    row = cur.fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _query_events(
    conn: psycopg.Connection,
    project: str,
    baseline_seq: int,
) -> list[ProofEvent]:
    """Query all events after baseline and build ProofEvent rows."""
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


def _run_canonical_verifier(
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

    The JSON report is parsed once and the resulting
    :class:`VerificationReport` is the single source of truth for both the
    ``all_ok`` check and the chain-integrity check (B3).
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

    report = _parse_verifier_report(report_path)
    if report is None:
        return None, "cairn verify produced an unparseable report"

    if report.all_ok:
        return report, "canonical verifier: all checks passed"
    return report, "canonical verifier: report not all_ok"


def _parse_verifier_report(report_path: Path) -> VerificationReport | None:
    """Parse the JSON verifier report into a VerificationReport for chain checks.

    The canonical verifier's JSON output nests summary fields under a
    ``summary`` key (see :func:`cairn.verifier_report.format_report_json`).
    List fields like ``chain_contiguity_violations`` are at the top level.
    """
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
    from cairn.verifier_types import ChainContiguityViolation

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


def main() -> int:
    config = _get_config()
    dsn = config["REGISTA_DSN"]
    key_path = config.get("REGISTA_KEY_PATH", "")
    project = config.get("CAIRN_PROJECT", "agent_provenance")
    expected_hv = _detect_claude_version()

    correlation_id = str(uuid.uuid4())

    print("=== Cairn E2E Proof ===")
    print(f"Harness version: {expected_hv}")
    print(f"Project: {project}")
    print(f"Correlation ID: {correlation_id}")
    print()

    test_file_content = f"cairn e2e proof {correlation_id}\nline 2 of proof\n"
    test_bash_output = correlation_id

    expected_outputs = {
        "Read": test_file_content,
        "Bash": test_bash_output,
    }

    with tempfile.TemporaryDirectory(prefix="cairn-e2e-") as tmpdir_str:
        tmpdir = Path(tmpdir_str)

        proof_dir = tmpdir / "proof"
        proof_dir.mkdir()
        test_file = proof_dir / f"{correlation_id}.txt"
        test_file.write_text(test_file_content)

        conn = psycopg.connect(dsn)
        baseline_seq = _get_baseline_seq(conn, project)
        print(f"Baseline global_seq: {baseline_seq}")
        conn.close()

        # Record timestamp before launching the session so the canonical
        # verifier can be scoped to the proof window (B2).
        since_timestamp = datetime.datetime.now(datetime.UTC).isoformat()

        print("[1/4] Driving Claude Code session...")
        result = subprocess.run(
            [
                "claude", "-p",
                (
                    f"Read the file {test_file} and confirm its contents. "
                    f"Then run the bash command: echo {test_bash_output}"
                ),
                "--allowedTools", "Read,Bash",
                "--max-turns", "5",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(tmpdir),
        )
        if result.returncode != 0:
            print(f"FAIL: claude -p exited {result.returncode}", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return 1
        print("  Session completed (exit 0)")

        print()
        print("[2/4] Verifying session-bound events in regista store...")
        conn = psycopg.connect(dsn)
        events = _query_events(conn, project, baseline_seq)
        conn.close()

        print(f"  Events after baseline: {len(events)}")
        if not events:
            print(
                "FAIL: no new events — hooks may not be wired or bridge failed",
                file=sys.stderr,
            )
            return 1

        print()
        print("[3/4] Running canonical verifier (cairn export + verify)...")
        verifier_report, verifier_detail = _run_canonical_verifier(
            dsn, project, key_path, tmpdir, since_timestamp
        )
        print(f"  {verifier_detail}")

        proof = run_proof(
            events=events,
            baseline_seq=baseline_seq,
            expected_harness_version=expected_hv,
            expected_outputs=expected_outputs,
            expected_file_name=f"{correlation_id}.txt",
            verifier_report=verifier_report,
        )

        if proof.session_entity_id:
            print(f"  Session entity_id: {proof.session_entity_id}")
        print(f"  Tool call events: {len(proof.tool_call_events)}")

        print()
        print("[4/4] Evaluating proof results...")

        all_failures: list[ProofFailure] = list(proof.failures)
        if verifier_report is None or not verifier_report.all_ok:
            all_failures.append(
                ProofFailure(check="verifier", detail=verifier_detail)
            )

    print()
    if all_failures:
        print(f"=== PROOF FAILED ({len(all_failures)} failure(s)) ===")
        for f in all_failures:
            print(f"  - [{f.check}] {f.detail}")
        return 1
    else:
        print("=== PROOF PASSED ===")
        print("  - Session attestation bound to launched session (post-baseline)")
        print("  - Tool call events bound to this session via on_behalf_of")
        print("  - Correlation marker verified in tool call payloads")
        print("  - Harness version is the real installed version")
        print("  - All digests match independently computed sha256")
        print("  - Canonical verifier reports chain intact")
        return 0


if __name__ == "__main__":
    sys.exit(main())
