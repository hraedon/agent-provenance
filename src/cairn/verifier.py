"""Offline verifier for Cairn event logs.

Reads substrate events (from a signed bundle or directly from substrate)
and produces an auditor-ready report.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
from substrate._signing import verify_event as _verify_event_impl
from substrate._types import Event

log = structlog.get_logger()


@dataclass(frozen=True)
class VerificationEntry:
    event_id: str
    work_item_id: str
    event_seq: int
    timestamp: str
    transition: str | None
    result: str  # "ok" | "signature_failed" | "hash_mismatch" | "revoked_key"
    detail: str | None = None


@dataclass(frozen=True)
class FileProvenanceEntry:
    work_item_id: str
    event_id: str
    path: str
    pre_digest: str | None
    post_digest: str | None
    current_digest: str | None
    digest_match: bool | None  # None if file not found


@dataclass(frozen=True)
class ScopeAttestationEntry:
    event_id: str
    work_item_id: str
    version: str
    principal_id: str
    attested_at: str
    harnesses: list[dict[str, Any]]
    scope_statement: str
    harness_config_digests: dict[str, str] | None = None


@dataclass
class VerificationReport:
    total_events: int = 0
    ok: int = 0
    signature_failed: int = 0
    hash_mismatch: int = 0
    revoked_key: int = 0
    entries: list[VerificationEntry] = field(default_factory=list)
    file_provenance: list[FileProvenanceEntry] = field(default_factory=list)
    scope_attestations: list[ScopeAttestationEntry] = field(default_factory=list)
    key_chain: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def all_ok(self) -> bool:
        return self.signature_failed == 0 and self.hash_mismatch == 0 and self.revoked_key == 0


class Verifier:
    """Verify Cairn events for an auditor."""

    def __init__(self, key_set: dict[str, bytes]) -> None:
        """
        Args:
            key_set: Mapping ``key_id → signing_secret_bytes`` for every key
                that may have signed events in the log.
        """
        self._keys = key_set

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify_events(self, events: list[Event]) -> VerificationReport:
        """Verify a list of substrate events and produce a report."""
        report = VerificationReport()
        report.total_events = len(events)

        for ev in events:
            entry = self._verify_single(ev)
            report.entries.append(entry)

            if entry.result == "ok":
                report.ok += 1
            elif entry.result == "signature_failed":
                report.signature_failed += 1
            elif entry.result == "hash_mismatch":
                report.hash_mismatch += 1
            elif entry.result == "revoked_key":
                report.revoked_key += 1

            # Derive file provenance for tool call events
            self._accumulate_file_provenance(report, ev)

            # Collect scope attestations
            self._accumulate_scope_attestations(report, ev)

        return report

    def verify_bundle(self, bundle_path: str | Path) -> VerificationReport:
        """Load a JSON bundle and verify every event inside.

        Expected bundle shape (as emitted by export tooling)::

            {
              "manifest": {
                "events_count": 3,
                "bundle_hash": "sha256:...",
                "previous_bundle_hash": "sha256:..."  // optional
              },
              "events": [
                { /* Event as dict */ },
                ...
              ]
            }
        """
        path = Path(bundle_path)
        raw = json.loads(path.read_text())
        events = [Event.from_dict(e) for e in raw["events"]]
        report = self.verify_events(events)

        # Record manifest info for the report
        manifest = raw.get("manifest", {})
        report.key_chain["bundle"] = manifest

        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _verify_single(self, ev: Event) -> VerificationEntry:
        key = self._keys.get(ev.key_id)
        if key is None:
            return VerificationEntry(
                event_id=str(ev.event_id),
                work_item_id=str(ev.work_item_id),
                event_seq=ev.event_seq,
                timestamp=ev.timestamp.isoformat(),
                transition=ev.transition,
                result="revoked_key",
                detail=f"Unknown key_id: {ev.key_id}",
            )

        ok = _verify_event_impl(
            event_id=ev.event_id,
            work_item_id=ev.work_item_id,
            actor_id=ev.actor_id,
            key_id=ev.key_id,
            event_seq=ev.event_seq,
            workflow_name=ev.workflow_name,
            workflow_version=ev.workflow_version,
            timestamp=ev.timestamp,
            transition=ev.transition,
            payload=ev.payload,
            signature=ev.signature,
            canonical_hash=ev.payload_canonical_hash,
            key=key,
            stored_envelope=ev.canonical_envelope,
            on_behalf_of=ev.on_behalf_of,
        )

        if ok:
            return VerificationEntry(
                event_id=str(ev.event_id),
                work_item_id=str(ev.work_item_id),
                event_seq=ev.event_seq,
                timestamp=ev.timestamp.isoformat(),
                transition=ev.transition,
                result="ok",
            )

        return VerificationEntry(
            event_id=str(ev.event_id),
            work_item_id=str(ev.work_item_id),
            event_seq=ev.event_seq,
            timestamp=ev.timestamp.isoformat(),
            transition=ev.transition,
            result="signature_failed",
            detail="HMAC signature does not verify",
        )

    def _accumulate_file_provenance(self, report: VerificationReport, ev: Event) -> None:
        """Re-derive file-content provenance for any action that touches files."""
        payload = ev.payload or {}
        transition = ev.transition or ""
        if not transition.startswith("tool_call"):
            return

        files = payload.get("files")
        if not files:
            return

        for f in files:
            path = f.get("path", "")
            pre = f.get("pre_digest")
            post = f.get("post_digest")

            current: str | None = None
            match: bool | None = None
            try:
                current = hashlib.sha256(Path(path).read_bytes()).hexdigest()
                # Compare against post_digest if present, else pre_digest
                target = post if post is not None else pre
                if target is not None:
                    match = current == target
            except OSError:
                pass

            report.file_provenance.append(
                FileProvenanceEntry(
                    work_item_id=str(ev.work_item_id),
                    event_id=str(ev.event_id),
                    path=path,
                    pre_digest=pre,
                    post_digest=post,
                    current_digest=current,
                    digest_match=match,
                )
            )

    def _accumulate_scope_attestations(self, report: VerificationReport, ev: Event) -> None:
        """Collect scope-attestation payloads from scope events."""
        payload = ev.payload or {}
        if "harnesses" not in payload or "scope_statement" not in payload:
            return
        report.scope_attestations.append(
            ScopeAttestationEntry(
                event_id=str(ev.event_id),
                work_item_id=str(ev.work_item_id),
                version=payload.get("version", "?"),
                principal_id=payload.get("principal_id", "?"),
                attested_at=payload.get("attested_at", "?"),
                harnesses=payload.get("harnesses", []),
                scope_statement=payload.get("scope_statement", ""),
                harness_config_digests=payload.get("harness_config_digests"),
            )
        )

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------

    @staticmethod
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

        lines.append("FILE PROVENANCE")
        lines.append("-" * 40)
        for fp in report.file_provenance:
            if fp.digest_match:
                status = "OK"
            elif fp.current_digest is None:
                status = "MISSING"
            else:
                status = "MODIFIED"
            lines.append(
                f"  [{fp.work_item_id}] {fp.path}: {status}"
            )
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

        lines.append("=" * 60)
        summary = "ALL CHECKS PASSED" if report.all_ok else "VERIFICATION FAILED"
        lines.append("Summary: " + summary)
        lines.append("=" * 60)
        return "\n".join(lines) + "\n"
