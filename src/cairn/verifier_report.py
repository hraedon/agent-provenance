"""Report formatting functions for Cairn verification reports.

These functions were previously static methods on :class:`~cairn.verifier.Verifier`.
They are now module-level functions, re-exported from :mod:`cairn.verifier`
for backward compatibility.
"""

from __future__ import annotations

from typing import Any

from cairn.verifier_types import BundleDiff, VerificationReport

__all__ = [
    "format_diff",
    "format_diff_json",
    "format_report",
    "format_report_html",
    "format_report_json",
]


def _bundle_status(ok: bool | None) -> str:
    if ok is True:
        return "OK"
    if ok is False:
        return "FAILED"
    return "NOT VERIFIED (missing)"


def _chain_status(ok: bool | None, prev_hash: str | None) -> str:
    if ok is True:
        return f"OK ({prev_hash[:24]}...)" if prev_hash else "OK"
    if ok is False:
        return "BROKEN"
    if prev_hash:
        return "PRESENT (not validated \u2014 run verify-chain)"
    return "NOT VERIFIED (no previous hash)"


def format_report(report: VerificationReport) -> str:
    """Return a human-readable auditor-ready text report."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("CAIRN VERIFICATION REPORT")
    lines.append("=" * 60)
    lines.append(f"Total events examined     : {report.total_events}")
    lines.append(f"  Signatures OK           : {report.ok}")
    lines.append(f"  Signature failures      : {report.signature_failed}")
    lines.append(f"  Hash mismatches         : {report.hash_mismatch}")
    lines.append(f"  Revoked / unknown keys  : {report.revoked_key}")
    if report.scheme_counts:
        for scheme, count in sorted(report.scheme_counts.items()):
            lines.append(f"  Scheme {scheme:20s}: {count}")
    if report.bundle_hash_ok is not None:
        status = "OK" if report.bundle_hash_ok else "FAILED"
        lines.append(f"  Bundle integrity hash   : {status}")
    else:
        lines.append("  Bundle integrity hash   : NOT VERIFIED (missing)")
    if report.chain_integrity_ok is not None:
        chain_status = "OK" if report.chain_integrity_ok else "BROKEN"
        lines.append(f"  Chain integrity         : {chain_status}")
        if report.previous_bundle_hash:
            lines.append(f"    previous_bundle_hash  : {report.previous_bundle_hash[:24]}...")
    elif report.previous_bundle_hash:
        lines.append(
            "  Chain integrity         : PRESENT (link not validated \u2014 run verify-chain)"
        )
        lines.append(f"    previous_bundle_hash  : {report.previous_bundle_hash[:24]}...")
    else:
        lines.append("  Chain integrity         : NOT VERIFIED (no previous hash)")
    if report.key_rotations:
        kr_failures = report.key_rotation_failures
        lines.append(
            f"  Key rotations           : {len(report.key_rotations)} ({kr_failures} failed)"
        )
    lines.append("")

    # Surface control narrative from the bundle manifest
    manifest = report.key_chain.get("bundle", {})
    control_desc = manifest.get("control_description")
    caveat = manifest.get("trust_model_caveat")
    if control_desc or caveat:
        lines.append("CONTROL NARRATIVE")
        lines.append("-" * 40)
        if control_desc:
            for para in control_desc.splitlines():
                lines.append(f"  {para}")
            lines.append("")
        if caveat:
            lines.append(f"  CAUTION: {caveat}")
        lines.append("")

    if report.bundle_hash_ok is False:
        lines.append("BUNDLE INTEGRITY FAILURE")
        lines.append("-" * 40)
        lines.append(f"  {report.bundle_hash_detail}")
        lines.append("  Events were NOT verified (bundle may be tampered).")
        lines.append("")

    if report.signature_failed or report.hash_mismatch or report.revoked_key:
        lines.append("FAILED EVENTS")
        lines.append("-" * 40)
        for entry in report.entries:
            if entry.result != "ok":
                lines.append(
                    f"  event {entry.event_id} ({entry.transition}) "
                    f"seq={entry.event_seq}: {entry.result}"
                )
                if entry.detail:
                    lines.append(f"    -> {entry.detail}")
        lines.append("")

    if report.sequence_gaps:
        lines.append("SEQUENCE GAPS / ORDERING VIOLATIONS")
        lines.append("-" * 40)
        for gap in report.sequence_gaps:
            lines.append(f"  [{gap.kind}] work_item={gap.work_item_id}")
            lines.append(f"    {gap.detail}")
        lines.append("")

    lines.append("FILE PROVENANCE")
    lines.append("-" * 40)
    for fp in report.file_provenance:
        if fp.digest_match:
            status = "OK"
        elif fp.current_digest is None:
            status = "MISSING"
        else:
            status = "MODIFIED"
        lines.append(f"  [{fp.work_item_id}] {fp.path}: {status}")
        if fp.pre_digest:
            lines.append(f"    pre :  {fp.pre_digest[:16]}...")
        if fp.post_digest:
            lines.append(f"    post:  {fp.post_digest[:16]}...")
        if fp.current_digest:
            lines.append(f"    now :  {fp.current_digest[:16]}...")
    lines.append("")

    if report.scope_attestations:
        lines.append("SCOPE ATTESTATIONS")
        lines.append("-" * 40)
        for sa in report.scope_attestations:
            lines.append(f"  event {sa.event_id}")
            lines.append(f"    principal_id : {sa.principal_id}")
            lines.append(f"    attested_at  : {sa.attested_at}")
            lines.append(f"    scope        : {sa.scope_statement}")
            harness_names = ", ".join(h.get("name", "?") for h in sa.harnesses)
            lines.append(f"    harnesses    : {harness_names}")
            if sa.harness_config_digests:
                for name, digest in sa.harness_config_digests.items():
                    lines.append(f"      {name}: {digest[:16]}...")
        lines.append("")

    if report.key_rotations:
        lines.append("KEY ROTATIONS")
        lines.append("-" * 40)
        for kr in report.key_rotations:
            status = "OK" if kr.signature_valid else "FAILED"
            lines.append(f"  event {kr.event_id}")
            lines.append(
                f"    predecessor: {kr.predecessor_key_id} -> successor: {kr.successor_key_id}"
            )
            if kr.rotated_at:
                lines.append(f"    rotated_at  : {kr.rotated_at}")
            lines.append(f"    signature   : {status}")
            if kr.detail:
                lines.append(f"    -> {kr.detail}")
        lines.append("")

    if report.delegation_chains:
        dc_failures = report.delegation_chain_failures
        lines.append(
            f"DELEGATION CHAINS ({len(report.delegation_chains)} total, {dc_failures} invalid)"
        )
        lines.append("-" * 40)
        for dc in report.delegation_chains:
            status = "OK" if dc.validation_ok else "INVALID"
            lines.append(f"  event {dc.event_id}")
            lines.append(f"    principal_id     : {dc.principal_id}")
            if dc.session_id:
                lines.append(f"    session_id       : {dc.session_id}")
            if dc.authenticated_at:
                lines.append(f"    authenticated_at : {dc.authenticated_at}")
            if dc.scope:
                lines.append(f"    scope            : {dc.scope}")
            if dc.expires_at:
                lines.append(f"    expires_at       : {dc.expires_at}")
            lines.append(f"    validation       : {status}")
            if dc.validation_detail:
                lines.append(f"    -> {dc.validation_detail}")
        lines.append("")

    if report.timestamp_batches:
        lines.append("TIMESTAMP BATCHES (TSA)")
        lines.append("-" * 40)
        for tb in report.timestamp_batches:
            status = tb.status
            lines.append(f"  batch {tb.batch_id[:8]}...")
            lines.append(f"    events    : {tb.event_count}")
            lines.append(f"    status    : {status}")
            if tb.tsa_timestamp:
                lines.append(f"    TSA time  : {tb.tsa_timestamp}")
            if tb.merkle_root:
                lines.append(f"    merkle    : {tb.merkle_root[:32]}...")
            if tb.verified is True:
                lines.append("    signature : VERIFIED")
                if tb.verification_detail:
                    lines.append(f"    detail    : {tb.verification_detail}")
            elif tb.verified is False:
                lines.append("    signature : FAILED")
                if tb.verification_detail:
                    lines.append(f"    -> {tb.verification_detail}")
            elif tb.verified is None and tb.status == "confirmed":
                lines.append("    signature : NOT CHECKED (no --tsa-cert)")
        lines.append("")

    if report.witness_registrations:
        w_count = len(report.witness_registrations)
        r_count = len(report.witness_receipts)
        v_count = len(report.witness_coverage_violations)
        lines.append(
            f"WITNESS FEDERATION ({w_count} witnesses, {r_count} receipts, {v_count} violations)"
        )
        lines.append("-" * 40)
        for w in report.witness_registrations:
            lines.append(f"  witness {w.witness_id[:8]}...")
            lines.append(f"    url     : {w.url}")
            lines.append(f"    status  : {w.status}")
            lines.append(f"    mode    : {w.mode}")
        if report.witness_coverage_violations:
            lines.append("")
            for v in report.witness_coverage_violations:
                lines.append(f"  event {v.event_id[:8]}.. MISSING COVERAGE")
                lines.append(f"    -> {v.detail}")
        lines.append("")

    if report.scope_violations:
        lines.append("SCOPE VIOLATIONS")
        lines.append("-" * 40)
        for sv in report.scope_violations:
            lines.append(f"  event {sv.event_id} ({sv.transition})")
            lines.append(f"    harness: {sv.harness}")
            lines.append(f"    -> {sv.detail}")
        lines.append("")

    if report.key_revocations:
        rev_failures = report.key_revocation_failures
        lines.append(
            f"KEY REVOCATIONS ({len(report.key_revocations)} total, {rev_failures} violations)"
        )
        lines.append("-" * 40)
        for kr in report.key_revocations:
            lines.append(f"  event {kr.event_id}")
            lines.append(f"    key_id    : {kr.key_id}")
            if kr.revoked_at:
                lines.append(f"    revoked_at: {kr.revoked_at}")
            if kr.detail:
                lines.append(f"    -> {kr.detail}")
        lines.append("")

    if report.temporal_violations:
        lines.append("TEMPORAL ORDERING VIOLATIONS")
        lines.append("-" * 40)
        for tv in report.temporal_violations:
            lines.append(f"  event {tv.event_id} [{tv.kind}]")
            lines.append(f"    -> {tv.detail}")
        lines.append("")

    if report.role_gate_violations:
        lines.append("ROLE GATE VIOLATIONS")
        lines.append("-" * 40)
        for rv in report.role_gate_violations:
            lines.append(
                f"  event {rv.event_id} key={rv.key_id} role={rv.role}"
                f" transition={rv.transition}"
            )
            lines.append(f"    -> {rv.detail}")
        lines.append("")

    if report.chain_contiguity_violations:
        lines.append("CHAIN CONTIGUITY VIOLATIONS")
        lines.append("-" * 40)
        for cv in report.chain_contiguity_violations:
            loc = f" event {cv.event_id}" if cv.event_id else ""
            lines.append(f"  [{cv.kind}]{loc}")
            lines.append(f"    -> {cv.detail}")
        lines.append("")

    if report.principal_binding_violations:
        lines.append("PRINCIPAL BINDING VIOLATIONS")
        lines.append("-" * 40)
        for pv in report.principal_binding_violations:
            lines.append(f"  event {pv.event_id} ({pv.transition}) [{pv.kind}]")
            lines.append(f"    -> {pv.detail}")
        lines.append("")

    lines.append("VERIFICATION NOTE")
    lines.append("-" * 40)
    has_ed25519 = "ed25519" in report.scheme_counts
    if has_ed25519:
        lines.append(
            "  Ed25519 (asymmetric) signatures were found.  Auditors can"
            " verify these events using only the public key \u2014 no signing"
            " secret is required.  This provides operator-forgery"
            " resistance: an operator cannot forge Ed25519-signed events"
            " without the private key."
        )
    else:
        lines.append(
            "  Only HMAC-SHA256 (symmetric) signatures found."
            "  HMAC verification confirms record authenticity and"
            " integrity but does NOT provide operator-forgery resistance."
            "  An operator who holds the signing key can forge or reorder"
            " events undetectably."
        )
    lines.append(
        "  Auditors should also check for degradation.log files in the"
        " session state directory \u2014 their presence indicates periods"
        " where the audit hook could not reach regista and coverage"
        " gaps may exist."
    )
    lines.append("")

    lines.append("=" * 60)
    summary = "ALL CHECKS PASSED" if report.all_ok else "VERIFICATION FAILED"
    lines.append("Summary: " + summary)
    lines.append("=" * 60)
    return "\n".join(lines) + "\n"


def format_report_json(report: VerificationReport) -> dict[str, Any]:
    """Return a structured JSON-serializable dict for programmatic consumption."""
    manifest = report.key_chain.get("bundle", {})
    return {
        "summary": {
            "total_events": report.total_events,
            "ok": report.ok,
            "signature_failed": report.signature_failed,
            "hash_mismatch": report.hash_mismatch,
            "revoked_key": report.revoked_key,
            "bundle_hash_ok": report.bundle_hash_ok,
            "chain_integrity_ok": report.chain_integrity_ok,
            "all_ok": report.all_ok,
        },
        "entries": [
            {
                "event_id": e.event_id,
                "work_item_id": e.work_item_id,
                "event_seq": e.event_seq,
                "timestamp": e.timestamp,
                "transition": e.transition,
                "result": e.result,
                "detail": e.detail,
            }
            for e in report.entries
        ],
        "sequence_gaps": [
            {
                "work_item_id": g.work_item_id,
                "kind": g.kind,
                "detail": g.detail,
                "expected_seq": g.expected_seq,
                "actual_seq": g.actual_seq,
            }
            for g in report.sequence_gaps
        ],
        "file_provenance": [
            {
                "work_item_id": f.work_item_id,
                "event_id": f.event_id,
                "path": f.path,
                "pre_digest": f.pre_digest,
                "post_digest": f.post_digest,
                "current_digest": f.current_digest,
                "digest_match": f.digest_match,
            }
            for f in report.file_provenance
        ],
        "scope_attestations": [
            {
                "event_id": s.event_id,
                "work_item_id": s.work_item_id,
                "version": s.version,
                "principal_id": s.principal_id,
                "attested_at": s.attested_at,
                "harnesses": s.harnesses,
                "scope_statement": s.scope_statement,
                "harness_config_digests": s.harness_config_digests,
            }
            for s in report.scope_attestations
        ],
        "key_rotations": [
            {
                "event_id": kr.event_id,
                "work_item_id": kr.work_item_id,
                "predecessor_key_id": kr.predecessor_key_id,
                "successor_key_id": kr.successor_key_id,
                "rotated_at": kr.rotated_at,
                "signature_valid": kr.signature_valid,
                "detail": kr.detail,
            }
            for kr in report.key_rotations
        ],
        "bundle": {
            "hash_ok": report.bundle_hash_ok,
            "hash_detail": report.bundle_hash_detail,
            "previous_bundle_hash": report.previous_bundle_hash,
            "control_description": manifest.get("control_description"),
            "trust_model_caveat": manifest.get("trust_model_caveat"),
        },
        "delegation_chains": [
            {
                "event_id": dc.event_id,
                "work_item_id": dc.work_item_id,
                "principal_id": dc.principal_id,
                "session_id": dc.session_id,
                "authenticated_at": dc.authenticated_at,
                "scope": dc.scope,
                "expires_at": dc.expires_at,
                "validation_ok": dc.validation_ok,
                "validation_detail": dc.validation_detail,
            }
            for dc in report.delegation_chains
        ],
        "timestamp_batches": [
            {
                "batch_id": tb.batch_id,
                "merkle_root": tb.merkle_root,
                "event_count": tb.event_count,
                "event_ids": tb.event_ids,
                "status": tb.status,
                "tsa_timestamp": tb.tsa_timestamp,
                "verified": tb.verified,
                "verification_detail": tb.verification_detail,
            }
            for tb in report.timestamp_batches
        ],
        "witness_registrations": [
            {
                "witness_id": w.witness_id,
                "url": w.url,
                "status": w.status,
                "mode": w.mode,
            }
            for w in report.witness_registrations
        ],
        "witness_coverage_violations": [
            {
                "event_id": v.event_id,
                "work_item_id": v.work_item_id,
                "missing_witnesses": v.missing_witnesses,
                "detail": v.detail,
            }
            for v in report.witness_coverage_violations
        ],
        "scope_violations": [
            {
                "event_id": sv.event_id,
                "work_item_id": sv.work_item_id,
                "transition": sv.transition,
                "harness": sv.harness,
                "detail": sv.detail,
            }
            for sv in report.scope_violations
        ],
        "key_revocations": [
            {
                "event_id": kr.event_id,
                "work_item_id": kr.work_item_id,
                "key_id": kr.key_id,
                "revoked_at": kr.revoked_at,
                "detail": kr.detail,
            }
            for kr in report.key_revocations
        ],
        "temporal_violations": [
            {
                "event_id": tv.event_id,
                "work_item_id": tv.work_item_id,
                "kind": tv.kind,
                "detail": tv.detail,
            }
            for tv in report.temporal_violations
        ],
        "role_gate_violations": [
            {
                "event_id": rv.event_id,
                "work_item_id": rv.work_item_id,
                "key_id": rv.key_id,
                "role": rv.role,
                "transition": rv.transition,
                "detail": rv.detail,
            }
            for rv in report.role_gate_violations
        ],
        "chain_contiguity_violations": [
            {
                "kind": cv.kind,
                "detail": cv.detail,
                "event_id": cv.event_id,
                "work_item_id": cv.work_item_id,
                "expected": cv.expected,
                "actual": cv.actual,
            }
            for cv in report.chain_contiguity_violations
        ],
        "principal_binding_violations": [
            {
                "kind": pv.kind,
                "event_id": pv.event_id,
                "work_item_id": pv.work_item_id,
                "transition": pv.transition,
                "detail": pv.detail,
                "principal_id": pv.principal_id,
                "expected_principal_id": pv.expected_principal_id,
            }
            for pv in report.principal_binding_violations
        ],
        "scheme_counts": report.scheme_counts,
        "verification_note": (
            "Ed25519 (asymmetric) signatures provide operator-forgery resistance. "
            "HMAC-SHA256 (symmetric) confirms authenticity and integrity only."
            if "ed25519" in report.scheme_counts
            else "HMAC-SHA256 verification confirms record authenticity and "
            "integrity but does NOT provide operator-forgery resistance."
        ),
    }


def format_diff(diff: BundleDiff) -> str:
    """Return a human-readable diff report."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("CAIRN BUNDLE DIFF")
    lines.append("=" * 60)
    lines.append(f"Older: {diff.older_bundle}")
    lines.append(f"Newer: {diff.newer_bundle}")
    lines.append(f"Older event count: {diff.older_event_count}")
    lines.append(f"Newer event count: {diff.newer_event_count}")
    lines.append(f"Total changes: {len(diff.entries)}")
    lines.append("")

    if not diff.has_changes:
        lines.append("No differences found.")
        lines.append("=" * 60)
        return "\n".join(lines) + "\n"

    # Group by kind
    event_changes = [e for e in diff.entries if e.kind.startswith("event_")]
    file_changes = [e for e in diff.entries if e.kind.startswith("file_")]
    scope_changes = [e for e in diff.entries if e.kind == "scope_changed"]
    manifest_changes = [e for e in diff.entries if e.kind == "manifest_changed"]

    if event_changes:
        lines.append("EVENTS")
        lines.append("-" * 40)
        for entry in event_changes:
            prefix = "+" if entry.kind == "event_added" else "-"
            lines.append(f"  {prefix} {entry.detail}")
        lines.append("")

    if file_changes:
        lines.append("FILE PROVENANCE")
        lines.append("-" * 40)
        for entry in file_changes:
            if entry.kind == "file_new":
                prefix = "+"
            elif entry.kind == "file_removed":
                prefix = "-"
            else:
                prefix = "~"
            lines.append(f"  {prefix} {entry.detail}")
        lines.append("")

    if scope_changes:
        lines.append("SCOPE ATTESTATIONS")
        lines.append("-" * 40)
        for entry in scope_changes:
            lines.append(f"  ~ {entry.detail}")
        lines.append("")

    if manifest_changes:
        lines.append("MANIFEST")
        lines.append("-" * 40)
        for entry in manifest_changes:
            lines.append(f"  ~ {entry.detail}")
        lines.append("")

    lines.append("=" * 60)
    lines.append(
        f"Summary: {diff.events_added} events added, "
        f"{diff.events_removed} removed, "
        f"{diff.files_changed} files changed"
    )
    lines.append("=" * 60)
    return "\n".join(lines) + "\n"


def format_diff_json(diff: BundleDiff) -> dict[str, Any]:
    """Return a structured JSON-serializable dict for the diff."""
    return {
        "older_bundle": diff.older_bundle,
        "newer_bundle": diff.newer_bundle,
        "older_event_count": diff.older_event_count,
        "newer_event_count": diff.newer_event_count,
        "has_changes": diff.has_changes,
        "events_added": diff.events_added,
        "events_removed": diff.events_removed,
        "files_changed": diff.files_changed,
        "entries": [
            {
                "kind": e.kind,
                "detail": e.detail,
                "event_id": e.event_id,
                "path": e.path,
            }
            for e in diff.entries
        ],
    }


def format_report_html(report: VerificationReport) -> str:
    """Return a self-contained HTML verification report.

    All CSS is inlined; no external dependencies.  Suitable for
    opening in any browser \u2014 auditors can save the file and view
    offline.
    """
    import datetime as _dt

    manifest = report.key_chain.get("bundle", {})
    control_desc = manifest.get("control_description", "")
    caveat = manifest.get("trust_model_caveat", "")

    ok = report.all_ok
    summary_text = "ALL CHECKS PASSED" if ok else "VERIFICATION FAILED"
    summary_color = "#16a34a" if ok else "#dc2626"
    bg_color = "#f0fdf4" if ok else "#fef2f2"

    def _esc(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

    def _val_color(val: int) -> str:
        return "#dc2626" if val else "#16a34a"

    def _row(label: str, value: str) -> str:
        td = "padding:4px 16px 4px 0"
        return (
            f'<tr><td style="{td}">{label}</td><td style="font-weight:bold">{value}</td></tr>'
        )

    def _row_color(label: str, val: int) -> str:
        td = "padding:4px 16px 4px 0"
        color = _val_color(val)
        return (
            f"<tr>"
            f'<td style="{td}">{label}</td>'
            f'<td style="font-weight:bold;color:{color}">{val}</td>'
            f"</tr>"
        )

    sections: list[str] = []

    # Summary section
    div_style = (
        f"background:{bg_color};border-left:4px solid {summary_color};"
        "padding:16px;margin-bottom:24px;border-radius:4px"
    )
    h2_style = f"margin:0 0 8px;color:{summary_color}"
    summary_rows = "\n".join(
        [
            _row("Total events", str(report.total_events)),
            _row("Signatures OK", str(report.ok)),
            _row_color("Signature failures", report.signature_failed),
            _row_color("Hash mismatches", report.hash_mismatch),
            _row_color("Revoked / unknown keys", report.revoked_key),
            _row("Bundle integrity", _bundle_status(report.bundle_hash_ok)),
            _row(
                "Chain integrity",
                _chain_status(report.chain_integrity_ok, report.previous_bundle_hash),
            ),
        ]
    )
    sections.append(
        f'<div class="summary" style="{div_style}">'
        f'<h2 style="{h2_style}">{summary_text}</h2>'
        f'<table style="border-collapse:collapse">'
        f"{summary_rows}"
        f"</table></div>"
    )

    # Control narrative
    if control_desc or caveat:
        ctrl_html = '<div class="section"><h2>Control Narrative</h2>'
        if control_desc:
            cd_style = (
                "background:#f8fafc;padding:12px;border-radius:4px;"
                "white-space:pre-wrap;font-size:14px;"
                "border:1px solid #e2e8f0"
            )
            ctrl_html += (
                f'<div class="control-desc" style="{cd_style}">{_esc(control_desc)}</div>'
            )
        if caveat:
            cv_style = (
                "color:#b45309;background:#fffbeb;padding:8px;"
                "border-radius:4px;border:1px solid #fbbf24"
            )
            ctrl_html += f'<p style="{cv_style}"><strong>Caution:</strong> {_esc(caveat)}</p>'
        ctrl_html += "</div>"
        sections.append(ctrl_html)

    # Failed events
    failed = [e for e in report.entries if e.result != "ok"]
    if failed:
        rows = ""
        cell = "padding:4px 8px"
        mono = f"{cell};font-family:monospace;font-size:12px"
        for e in failed:
            detail = _esc(e.detail) if e.detail else ""
            eid = _esc(e.event_id[:16])
            trans = _esc(e.transition or "")
            result = _esc(e.result)
            rows += (
                f"<tr>"
                f'<td style="{mono}">{eid}...</td>'
                f'<td style="{cell}">{trans}</td>'
                f'<td style="{cell};color:#dc2626">{result}</td>'
                f'<td style="{cell};font-size:12px">{detail}</td>'
                f"</tr>"
            )
        th_style = f"{cell};text-align:left"
        hdr = (
            '<thead><tr style="background:#f1f5f9">'
            f'<th style="{th_style}">Event ID</th>'
            f'<th style="{th_style}">Transition</th>'
            f'<th style="{th_style}">Result</th>'
            f'<th style="{th_style}">Detail</th>'
            "</tr></thead>"
        )
        sections.append(
            '<div class="section"><h2>Failed Events</h2>'
            '<table style="border-collapse:collapse;width:100%">'
            f"{hdr}<tbody>{rows}</tbody></table></div>"
        )

    # Sequence gaps
    if report.sequence_gaps:
        rows = ""
        cell = "padding:4px 8px"
        mono = f"{cell};font-family:monospace;font-size:12px"
        for g in report.sequence_gaps:
            rows += (
                f"<tr>"
                f'<td style="{cell}">{_esc(g.kind)}</td>'
                f'<td style="{mono}">{_esc(g.work_item_id[:16])}...</td>'
                f'<td style="{cell}">{_esc(g.detail)}</td>'
                f"</tr>"
            )
        th_style = f"{cell};text-align:left"
        hdr = (
            '<thead><tr style="background:#f1f5f9">'
            f'<th style="{th_style}">Kind</th>'
            f'<th style="{th_style}">Work Item</th>'
            f'<th style="{th_style}">Detail</th>'
            "</tr></thead>"
        )
        sections.append(
            '<div class="section">'
            "<h2>Sequence Gaps / Ordering Violations</h2>"
            '<table style="border-collapse:collapse;width:100%">'
            f"{hdr}<tbody>{rows}</tbody></table></div>"
        )

    # File provenance
    if report.file_provenance:
        rows = ""
        cell = "padding:4px 8px"
        mono = f"{cell};font-family:monospace;font-size:11px"
        mono12 = f"{cell};font-family:monospace;font-size:12px;word-break:break-all"
        for fp in report.file_provenance:
            if fp.digest_match:
                st = '<span style="color:#16a34a;font-weight:bold">OK</span>'
            elif fp.current_digest is None:
                st = '<span style="color:#6b7280;font-weight:bold">MISSING</span>'
            else:
                st = '<span style="color:#dc2626;font-weight:bold">MODIFIED</span>'
            pre = (fp.pre_digest or "")[:16]
            post = (fp.post_digest or "")[:16]
            cur = (fp.current_digest or "")[:16]
            rows += (
                f"<tr>"
                f'<td style="{mono12}">{_esc(fp.path)}</td>'
                f'<td style="{cell};text-align:center">{st}</td>'
                f'<td style="{mono}">{pre}</td>'
                f'<td style="{mono}">{post}</td>'
                f'<td style="{mono}">{cur}</td>'
                f"</tr>"
            )
        th_style = f"{cell};text-align:left"
        th_center = f"{cell};text-align:center"
        hdr = (
            '<thead><tr style="background:#f1f5f9">'
            f'<th style="{th_style}">Path</th>'
            f'<th style="{th_center}">Status</th>'
            f'<th style="{th_style}">Pre</th>'
            f'<th style="{th_style}">Post</th>'
            f'<th style="{th_style}">Current</th>'
            "</tr></thead>"
        )
        sections.append(
            '<div class="section"><h2>File Provenance</h2>'
            '<table style="border-collapse:collapse;width:100%">'
            f"{hdr}<tbody>{rows}</tbody></table></div>"
        )

    # Scope attestations
    if report.scope_attestations:
        for sa in report.scope_attestations:
            names = ", ".join(_esc(h.get("name", "?")) for h in sa.harnesses)
            box_style = (
                "background:#f8fafc;padding:12px;border-radius:4px;border:1px solid #e2e8f0"
            )
            sections.append(
                '<div class="section"><h2>Scope Attestation</h2>'
                f'<div style="{box_style}">'
                f"<p><strong>Event:</strong> "
                f"<code>{_esc(sa.event_id)}</code></p>"
                f"<p><strong>Principal:</strong> "
                f"{_esc(sa.principal_id)}</p>"
                f"<p><strong>Attested:</strong> "
                f"{_esc(sa.attested_at)}</p>"
                f"<p><strong>Scope:</strong> "
                f"{_esc(sa.scope_statement)}</p>"
                f"<p><strong>Harnesses:</strong> {names}</p>"
                "</div></div>"
            )

    # Delegation chains
    if report.delegation_chains:
        dc_failures = report.delegation_chain_failures
        dc_header = (
            f"Delegation Chains ({len(report.delegation_chains)} total, {dc_failures} invalid)"
        )
        rows = ""
        cell = "padding:4px 8px"
        mono = f"{cell};font-family:monospace;font-size:12px"
        for dc in report.delegation_chains:
            status_html = (
                '<span style="color:#16a34a;font-weight:bold">OK</span>'
                if dc.validation_ok
                else '<span style="color:#dc2626;font-weight:bold">INVALID</span>'
            )
            detail = _esc(dc.validation_detail or "")
            rows += (
                f"<tr>"
                f'<td style="{mono}">{_esc(dc.event_id[:16])}...</td>'
                f'<td style="{cell}">{_esc(dc.principal_id)}</td>'
                f'<td style="{cell}">{_esc(dc.session_id or "")}</td>'
                f'<td style="{cell};text-align:center">{status_html}</td>'
                f'<td style="{cell};font-size:12px">{detail}</td>'
                f"</tr>"
            )
        th_style = f"{cell};text-align:left"
        hdr = (
            '<thead><tr style="background:#f1f5f9">'
            f'<th style="{th_style}">Event ID</th>'
            f'<th style="{th_style}">Principal</th>'
            f'<th style="{th_style}">Session</th>'
            f'<th style="{th_style};text-align:center">Status</th>'
            f'<th style="{th_style}">Detail</th>'
            "</tr></thead>"
        )
        sections.append(
            f'<div class="section"><h2>{_esc(dc_header)}</h2>'
            '<table style="border-collapse:collapse;width:100%">'
            f"{hdr}<tbody>{rows}</tbody></table></div>"
        )

    # Key rotations
    if report.key_rotations:
        rows = ""
        cell = "padding:4px 8px"
        mono = f"{cell};font-family:monospace;font-size:12px"
        for kr in report.key_rotations:
            sig_html = (
                '<span style="color:#16a34a;font-weight:bold">OK</span>'
                if kr.signature_valid
                else '<span style="color:#dc2626;font-weight:bold">FAILED</span>'
            )
            detail = _esc(kr.detail or "")
            rows += (
                f"<tr>"
                f'<td style="{mono}">{_esc(kr.event_id[:16])}...</td>'
                f'<td style="{mono}">{_esc(kr.predecessor_key_id[:16])}...</td>'
                f'<td style="{mono}">{_esc(kr.successor_key_id[:16])}...</td>'
                f'<td style="{cell};text-align:center">{sig_html}</td>'
                f'<td style="{cell};font-size:12px">{detail}</td>'
                f"</tr>"
            )
        th_style = f"{cell};text-align:left"
        hdr = (
            '<thead><tr style="background:#f1f5f9">'
            f'<th style="{th_style}">Event</th>'
            f'<th style="{th_style}">From Key</th>'
            f'<th style="{th_style}">To Key</th>'
            f'<th style="{th_style};text-align:center">Signature</th>'
            f'<th style="{th_style}">Detail</th>'
            "</tr></thead>"
        )
        sections.append(
            '<div class="section"><h2>Key Rotations</h2>'
            '<table style="border-collapse:collapse;width:100%">'
            f"{hdr}<tbody>{rows}</tbody></table></div>"
        )

    # Key revocations
    if report.key_revocations:
        rows = ""
        cell = "padding:4px 8px"
        mono = f"{cell};font-family:monospace;font-size:12px"
        for kr in report.key_revocations:
            detail = _esc(kr.detail or "")
            rows += (
                f"<tr>"
                f'<td style="{mono}">{_esc(kr.event_id[:16])}...</td>'
                f'<td style="{mono}">{_esc(kr.key_id[:16])}...</td>'
                f'<td style="{cell}">{_esc(kr.revoked_at or "")}</td>'
                f'<td style="{cell};font-size:12px">{detail}</td>'
                f"</tr>"
            )
        th_style = f"{cell};text-align:left"
        hdr = (
            '<thead><tr style="background:#f1f5f9">'
            f'<th style="{th_style}">Event</th>'
            f'<th style="{th_style}">Key ID</th>'
            f'<th style="{th_style}">Revoked At</th>'
            f'<th style="{th_style}">Detail</th>'
            "</tr></thead>"
        )
        sections.append(
            '<div class="section"><h2>Key Revocations</h2>'
            '<table style="border-collapse:collapse;width:100%">'
            f"{hdr}<tbody>{rows}</tbody></table></div>"
        )

    # Timestamp batches
    if report.timestamp_batches:
        rows = ""
        cell = "padding:4px 8px"
        mono = f"{cell};font-family:monospace;font-size:12px"
        for tb in report.timestamp_batches:
            if tb.verified is True:
                sig_html = '<span style="color:#16a34a;font-weight:bold">VERIFIED</span>'
            elif tb.verified is False:
                sig_html = '<span style="color:#dc2626;font-weight:bold">FAILED</span>'
            elif tb.verified is None and tb.status == "confirmed":
                sig_html = '<span style="color:#6b7280">NOT CHECKED</span>'
            else:
                sig_html = ""
            detail = _esc(tb.verification_detail or "")
            tsa_time = _esc(tb.tsa_timestamp or "")
            rows += (
                f"<tr>"
                f'<td style="{mono}">{_esc(tb.batch_id[:16])}...</td>'
                f'<td style="{cell}">{tb.event_count}</td>'
                f'<td style="{cell}">{_esc(tb.status)}</td>'
                f'<td style="{cell}">{tsa_time}</td>'
                f'<td style="{cell};text-align:center">{sig_html}</td>'
                f'<td style="{cell};font-size:12px">{detail}</td>'
                f"</tr>"
            )
        th_style = f"{cell};text-align:left"
        hdr = (
            '<thead><tr style="background:#f1f5f9">'
            f'<th style="{th_style}">Batch ID</th>'
            f'<th style="{th_style}">Events</th>'
            f'<th style="{th_style}">Status</th>'
            f'<th style="{th_style}">TSA Time</th>'
            f'<th style="{th_style};text-align:center">Signature</th>'
            f'<th style="{th_style}">Detail</th>'
            "</tr></thead>"
        )
        sections.append(
            '<div class="section"><h2>Timestamp Batches (TSA)</h2>'
            '<table style="border-collapse:collapse;width:100%">'
            f"{hdr}<tbody>{rows}</tbody></table></div>"
        )

    # Witness federation
    if report.witness_registrations:
        w_count = len(report.witness_registrations)
        r_count = len(report.witness_receipts)
        v_count = len(report.witness_coverage_violations)
        w_header = (
            f"Witness Federation ({w_count} witnesses, "
            f"{r_count} receipts, {v_count} violations)"
        )
        rows = ""
        cell = "padding:4px 8px"
        mono = f"{cell};font-family:monospace;font-size:12px"
        for w in report.witness_registrations:
            rows += (
                f"<tr>"
                f'<td style="{mono}">{_esc(w.witness_id[:16])}...</td>'
                f'<td style="{cell}">{_esc(w.url)}</td>'
                f'<td style="{cell}">{_esc(w.status)}</td>'
                f'<td style="{cell}">{_esc(w.mode)}</td>'
                f"</tr>"
            )
        th_style = f"{cell};text-align:left"
        hdr = (
            '<thead><tr style="background:#f1f5f9">'
            f'<th style="{th_style}">Witness ID</th>'
            f'<th style="{th_style}">URL</th>'
            f'<th style="{th_style}">Status</th>'
            f'<th style="{th_style}">Mode</th>'
            "</tr></thead>"
        )
        w_html = (
            f'<div class="section"><h2>{_esc(w_header)}</h2>'
            '<table style="border-collapse:collapse;width:100%">'
            f"{hdr}<tbody>{rows}</tbody></table></div>"
        )
        if report.witness_coverage_violations:
            v_rows = ""
            for v in report.witness_coverage_violations:
                v_rows += (
                    f"<tr>"
                    f'<td style="{mono}">{_esc(v.event_id[:16])}...</td>'
                    f'<td style="{cell};font-size:12px">{_esc(v.detail)}</td>'
                    f"</tr>"
                )
            v_hdr = (
                '<thead><tr style="background:#fef2f2">'
                f'<th style="{th_style}">Event ID</th>'
                f'<th style="{th_style}">Detail</th>'
                "</tr></thead>"
            )
            w_html += (
                '<h3 style="color:#dc2626">Coverage Violations</h3>'
                '<table style="border-collapse:collapse;width:100%">'
                f"{v_hdr}<tbody>{v_rows}</tbody></table>"
            )
        sections.append(w_html)

    # Verification note
    note_style = (
        "background:#fffbeb;padding:12px;border-radius:4px;"
        "border:1px solid #fbbf24;margin-top:24px"
    )
    note_p = "margin:0;font-size:14px;color:#78350f"
    note_p2 = "margin:8px 0 0;font-size:14px;color:#78350f"
    sections.append(
        f'<div class="section" style="{note_style}">'
        '<h3 style="margin:0 0 8px;color:#92400e">'
        "Verification Note</h3>"
        + (
            f'<p style="{note_p}">'
            "Ed25519 (asymmetric) signatures were found. Auditors can "
            "verify these events using <strong>only the public key</strong> "
            "&mdash; no signing secret is required. This provides "
            "operator-forgery resistance.</p>"
            if "ed25519" in report.scheme_counts
            else f'<p style="{note_p}">'
            "Only HMAC-SHA256 (symmetric) signatures found. "
            "HMAC verification confirms record authenticity "
            "and integrity but does <strong>NOT</strong> provide "
            "operator-forgery resistance. An operator who holds the "
            "signing key can forge or reorder events undetectably.</p>"
        )
        + f'<p style="{note_p2}">'
        "Auditors should also check for "
        "<code>degradation.log</code> files in the session state "
        "directory &mdash; their presence indicates periods where "
        "the audit hook could not reach regista and coverage "
        "gaps may exist.</p></div>"
    )

    body = "\n".join(sections)
    now = _dt.datetime.now(_dt.UTC).isoformat()
    css = (
        "body { font-family: -apple-system, BlinkMacSystemFont,"
        ' "Segoe UI", Roboto, sans-serif;'
        " margin: 0; padding: 24px; background: #fff;"
        " color: #1e293b; line-height: 1.5; }"
        " h1 { font-size: 24px; margin: 0 0 4px; }"
        " h2 { font-size: 18px; margin: 24px 0 12px; color: #334155; }"
        " h3 { font-size: 16px; }"
        " .section { margin-bottom: 24px; }"
        " table { border: 1px solid #e2e8f0;"
        " border-radius: 4px; overflow: hidden; }"
        " th { font-weight: 600; }"
        " tr:nth-child(even) { background: #f8fafc; }"
        " code { background: #f1f5f9; padding: 2px 4px;"
        " border-radius: 2px; font-size: 13px; }"
        " .footer { margin-top: 32px; padding-top: 16px;"
        " border-top: 1px solid #e2e8f0; font-size: 12px;"
        " color: #94a3b8; text-align: center; }"
    )
    version = __import__("cairn", fromlist=["__version__"]).__version__
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport"'
        ' content="width=device-width, initial-scale=1">\n'
        "  <title>Cairn Verification Report</title>\n"
        f"  <style>\n{css}\n  </style>\n"
        "</head>\n<body>\n"
        "  <h1>Cairn Verification Report</h1>\n"
        '  <p style="color:#64748b;font-size:14px">'
        f"Generated {_esc(now)}</p>\n"
        f"  {body}\n"
        '  <div class="footer">\n'
        f"    Cairn v{_esc(version)} &mdash; Cryptographic provenance "
        "for agentic workflows\n"
        "  </div>\n</body>\n</html>"
    )
