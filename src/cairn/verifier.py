"""Offline verifier for Cairn event logs.

Reads regista events (from a signed bundle or directly from regista)
and produces an auditor-ready report.

Supports both HMAC-SHA256 and Ed25519 signing schemes.  The verifier
dispatches per-event based on the ``scheme_id`` field (added in regista
Plan 011).  For Ed25519, the key_set should contain the **public key**
bytes (not the signing secret).

Report dataclasses live in :mod:`cairn.verifier_types`; report formatters
live in :mod:`cairn.verifier_report`.  This module re-exports both for
backward compatibility.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import structlog
from regista._errors import RegistaError
from regista._signing import verify_event as _verify_event_impl
from regista._signing_scheme import get_scheme
from regista._types import Event

from cairn.verifier_report import (
    format_diff,
    format_diff_json,
    format_report,
    format_report_html,
    format_report_json,
)
from cairn.verifier_types import (
    AssuranceEntry,
    AssuranceLevel,
    AttestationGap,
    BundleDiff,
    BundleDiffEntry,
    ChainContiguityViolation,
    ContentCoverageGap,
    DelegationChainEntry,
    FileProvenanceEntry,
    KeyRevocationEntry,
    KeyRotationEntry,
    PrincipalBindingViolation,
    RoleGateViolation,
    ScopeAttestationEntry,
    ScopeViolation,
    SequenceGap,
    SessionAttestationEntry,
    SilenceGap,
    TemporalOrderingViolation,
    TimestampBatchEntry,
    VerificationEntry,
    VerificationReport,
    WitnessCoverageViolation,
    WitnessReceiptEntry,
    WitnessRegistrationEntry,
)

_DEFAULT_SCHEME_ID = "hmac-sha256"
_TSA_TOLERANCE_SECONDS = 300  # 5-minute tolerance for TSA temporal checks

log = structlog.get_logger()


__all__ = [
    "AssuranceEntry",
    "AssuranceLevel",
    "AttestationGap",
    "BundleDiff",
    "BundleDiffEntry",
    "ChainContiguityViolation",
    "ContentCoverageGap",
    "DelegationChainEntry",
    "FileProvenanceEntry",
    "KeyRevocationEntry",
    "KeyRotationEntry",
    "PrincipalBindingViolation",
    "RoleGateViolation",
    "ScopeAttestationEntry",
    "ScopeViolation",
    "SequenceGap",
    "SessionAttestationEntry",
    "SilenceGap",
    "TemporalOrderingViolation",
    "TimestampBatchEntry",
    "VerificationEntry",
    "VerificationReport",
    "Verifier",
    "WitnessCoverageViolation",
    "WitnessReceiptEntry",
    "WitnessRegistrationEntry",
    "format_diff",
    "format_diff_json",
    "format_report",
    "format_report_html",
    "format_report_json",
]


class Verifier:
    """Verify Cairn events for an auditor.

    Supports both HMAC-SHA256 and Ed25519 signing schemes.  The verifier
    dispatches per-event based on the ``scheme_id`` field on each event.

    For HMAC-SHA256 events, the key_set entry should contain the signing
    secret bytes.  For Ed25519 events, the key_set entry should contain
    the **public key** bytes (32 bytes, base64-decoded from the key file).

    Example key_set construction::

        # HMAC key (secret)
        key_set["hmac-key-001"] = b"my-secret-key-bytes"

        # Ed25519 key (public key only — no secret needed for verification)
        key_set["ed25519-key-001"] = base64.b64decode("abc123...")
    """

    # Transition types that require role="actor" to sign.
    _ACTOR_ONLY_TRANSITIONS: ClassVar[set[str]] = {
        "tool_call",
        "scope_attestation",
        "key_declaration",
        "session_grant",
        "session_revocation",
        "heartbeat",
    }

    # Transition types that require role="auditor" to sign.
    _AUDITOR_ONLY_TRANSITIONS: ClassVar[set[str]] = {
        "auditor_attestation",
    }

    # Default size limits to defend against OOM / zip-bomb bundles (WI-021).
    # 512 MB max bundle file size; 1_000_000 max events per bundle.
    _DEFAULT_MAX_BUNDLE_BYTES: ClassVar[int] = 512 * 1024 * 1024
    _DEFAULT_MAX_EVENTS: ClassVar[int] = 1_000_000

    def __init__(
        self,
        key_set: dict[str, bytes],
        key_metadata: dict[str, dict[str, Any]] | None = None,
        tsa_cert_path: str | None = None,
        witness_keys: dict[str, bytes] | None = None,
        max_bundle_size_bytes: int | None = None,
        max_events: int | None = None,
    ) -> None:
        """
        Args:
            key_set: Mapping ``key_id → key_material_bytes`` for every key
                that may have signed events in the log.  For HMAC-SHA256
                this is the signing secret itself; for Ed25519 this is
                the public key only (no secret needed for verification).
            key_metadata: Optional mapping ``key_id → {role, revoked_at, ...}``
                for key lifecycle enforcement.  When provided, the verifier
                checks role gates and revocation timestamps.
            tsa_cert_path: Path to a trusted TSA certificate (PEM or DER).
                When provided, the verifier will verify CMS signatures on
                TSA timestamp tokens against this trust anchor (BC-229).
            witness_keys: Optional mapping ``witness_id → Ed25519 public
                key bytes`` for verifying witness receipt signatures
                (BC-016).  When provided, witness receipt signatures are
                cryptographically verified; receipts with invalid
                signatures do not count toward witness coverage.  When
                omitted, receipt signatures are not checked (a warning is
                emitted if any receipts have signatures).
            max_bundle_size_bytes: Maximum bundle file size in bytes.
                Bundles exceeding this are rejected before parsing to
                prevent OOM (WI-021).  ``None`` uses the default (512 MB).
            max_events: Maximum number of events per bundle.  Bundles
                with more events are rejected after loading (WI-021).
                ``None`` uses the default (1 000 000).
        """
        self._keys = key_set
        self._key_meta = key_metadata or {}
        self._tsa_cert_path = tsa_cert_path
        self._witness_keys = witness_keys or {}
        self._max_bundle_bytes = (
            max_bundle_size_bytes
            if max_bundle_size_bytes is not None
            else self._DEFAULT_MAX_BUNDLE_BYTES
        )
        self._max_events = (
            max_events if max_events is not None else self._DEFAULT_MAX_EVENTS
        )
        if self._max_bundle_bytes < 0:
            raise ValueError("max_bundle_size_bytes must be non-negative")
        if self._max_events < 0:
            raise ValueError("max_events must be non-negative")
        # Per-batch claimed event_ids, captured during _accumulate_timestamp_batches
        # so _verify_timestamp_signatures can recompute Merkle roots (BC-015).
        self._batch_claimed_ids: dict[str, list[str]] = {}
        # Raw witness signatures from the bundle, keyed by (event_id, witness_id).
        # Populated in _accumulate_witness_data, consumed in _verify_witness_signatures.
        self._witness_sig_cache: dict[tuple[str, str], bytes | None] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify_events(self, events: list[Event]) -> VerificationReport:
        """Verify a list of regista events and produce a report."""
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
            elif entry.result in ("revoked_key", "unknown_key"):
                report.revoked_key += 1

            # Track signing scheme usage
            scheme = getattr(ev, "scheme_id", _DEFAULT_SCHEME_ID)
            report.scheme_counts[scheme] = report.scheme_counts.get(scheme, 0) + 1

            # Derive file provenance for tool call events
            self._accumulate_file_provenance(report, ev)

            # Collect scope attestations
            self._accumulate_scope_attestations(report, ev)

            # Collect session attestations
            self._accumulate_session_attestations(report, ev)

            # Detect and verify key rotation events
            self._accumulate_key_rotations(report, ev)

            # Detect key revocation events
            self._accumulate_key_revocations(report, ev)

            # Validate delegation chains
            self._accumulate_delegation_chains(report, ev)

            # Check role gate (scaffolded — uses key_metadata if provided)
            self._check_role_gate(report, ev)

        self._check_event_sequence(events, report)
        self._check_chain_contiguity(events, report)
        self._check_scope_coverage(events, report)
        self._check_principal_binding(events, report)
        self._check_attestation_gaps(events, report)
        self._check_content_coverage_gaps(events, report)
        self._check_temporal_ordering(events, report)
        self._compute_assurance_levels(events, report)

        return report

    def verify_bundle(
        self,
        bundle_path: str | Path,
        *,
        harness_sessions: dict[str, dict[str, str | None]] | None = None,
    ) -> VerificationReport:
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

        When ``harness_sessions`` is provided (session_id → evidence from
        the harness's local transcripts), sessions that ran but produced no
        events are reported as silence gaps (Plan 009 WI-4.1).
        """
        path = Path(bundle_path)
        raw, events, manifest, error_report = self._load_bundle(path)
        if error_report is not None:
            return error_report
        report = self._verify_loaded_bundle(raw, events, manifest)
        if harness_sessions:
            self.check_silence_gaps(events, report, harness_sessions)
        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_bundle(
        self, path: Path
    ) -> tuple[dict[str, Any], list[Event], dict[str, Any], VerificationReport | None]:
        """Read and parse a bundle file once.

        Returns a tuple of ``(raw_dict, parsed_events, manifest, error_report)``.
        When ``error_report`` is not ``None`` the bundle could not be loaded and
        should be returned as the verification result.
        """
        try:
            file_size = path.stat().st_size
        except OSError as exc:
            report = VerificationReport()
            report.bundle_hash_ok = False
            report.bundle_hash_detail = f"Cannot stat bundle: {exc}"
            return {}, [], {}, report

        if file_size > self._max_bundle_bytes:
            report = VerificationReport()
            report.bundle_hash_ok = False
            report.bundle_hash_detail = (
                f"Bundle file size ({file_size} bytes) exceeds maximum "
                f"({self._max_bundle_bytes} bytes). "
                f"Adjust max_bundle_size_bytes if this is expected (WI-021)."
            )
            return {}, [], {}, report

        try:
            with open(path, "rb") as f:
                raw = json.loads(f.read())
        except (json.JSONDecodeError, OSError) as exc:
            report = VerificationReport()
            report.bundle_hash_ok = False
            report.bundle_hash_detail = f"Malformed bundle: {exc}"
            return {}, [], {}, report

        if not isinstance(raw, dict) or not isinstance(raw.get("events"), list):
            report = VerificationReport()
            report.bundle_hash_ok = False
            report.bundle_hash_detail = (
                "Malformed bundle: expected a JSON object with an 'events' list"
            )
            return {}, [], {}, report

        if len(raw["events"]) > self._max_events:
            report = VerificationReport()
            report.bundle_hash_ok = False
            report.bundle_hash_detail = (
                f"Bundle contains {len(raw['events'])} events, exceeding the "
                f"maximum ({self._max_events}). "
                f"Adjust max_events if this is expected (WI-021)."
            )
            return {}, [], {}, report

        manifest = raw.get("manifest", {})
        if not isinstance(manifest, dict):
            manifest = {}

        try:
            events = [Event.from_dict(e) for e in raw["events"]]
        except (KeyError, TypeError, ValueError) as exc:
            report = VerificationReport()
            report.bundle_hash_ok = self._verify_bundle_hash(raw, manifest)
            report.bundle_hash_detail = f"Malformed event in bundle: {exc}"
            return raw, [], manifest, report

        return raw, events, manifest, None

    def verify_bundle_filtered(
        self,
        bundle_path: str | Path,
        *,
        since: str | None = None,
        until: str | None = None,
    ) -> VerificationReport:
        """Verify a bundle with temporal filtering (Plan 008 WI-3.1).

        Loads the bundle, filters events to those within the ``[since, until)``
        window, and verifies only the filtered subset.  The bundle hash is
        verified against the *full* bundle (not the filtered subset) so that
        tamper-evidence is not lost.

        Attestation gaps are computed over the filtered events but use
        attestation info from the **full** event list — this prevents
        false positives when a session attestation falls outside the filter
        window but its tool calls fall inside it.

        Timestamp-batch signature verification is **skipped** in filtered
        mode because the Merkle root covers the full batch, not the filtered
        subset.  TSA temporal ordering is still checked for covered events.

        ``global_seq`` gap violations are suppressed because temporal
        filtering creates expected gaps in the cross-work-item sequence.

        ``since`` and ``until`` are ISO 8601 timestamp strings.  ``since`` is
        inclusive, ``until`` is exclusive.
        """
        path = Path(bundle_path)
        raw, events, manifest, error_report = self._load_bundle(path)
        if error_report is not None:
            return error_report

        hash_verified = self._verify_bundle_hash(raw, manifest)
        if hash_verified is False:
            report = VerificationReport()
            report.bundle_hash_ok = False
            report.bundle_hash_detail = "Bundle integrity hash mismatch (see log)"
            report.key_chain["bundle"] = manifest
            return report

        since_dt = _parse_iso(since) if since else None
        until_dt = _parse_iso(until) if until else None

        filtered = []
        for ev in events:
            ev_ts = ev.timestamp
            if since_dt is not None and ev_ts < since_dt:
                continue
            if until_dt is not None and ev_ts >= until_dt:
                continue
            filtered.append(ev)

        report = self.verify_events(filtered)
        report.bundle_hash_ok = True if hash_verified else None
        report.key_chain["bundle"] = manifest
        report.key_chain["filtered"] = {
            "since": since,
            "until": until,
            "total_in_bundle": len(events),
            "verified": len(filtered),
        }

        prev_hash = manifest.get("previous_bundle_hash")
        if prev_hash:
            report.previous_bundle_hash = prev_hash
        report.chain_integrity_ok = None

        # Suppress global_seq gap violations — temporal filtering creates
        # expected gaps in the cross-work-item sequence.
        report.chain_contiguity_violations = [
            v for v in report.chain_contiguity_violations
            if v.kind != "global_seq_gap"
        ]

        # Re-run attestation gap check with attested sessions from the FULL
        # event list, not just the filtered subset.  This prevents false
        # positives when the session attestation is outside the filter window.
        all_attested = self._collect_attested_session_ids(events)
        report.attestation_gaps.clear()
        self._check_attestation_gaps(filtered, report, attested_sessions=all_attested)

        # Timestamp batches: accumulate for coverage info but mark
        # signature verification as not-checked — the Merkle root covers
        # the full batch, not the filtered subset, so a filtered bundle's
        # TSA tokens cannot be cryptographically bound to its events
        # (WI-020). Use verified=None (not checked) rather than False
        # (failed) to distinguish "skipped" from "attempted and failed."
        self._accumulate_timestamp_batches(raw, filtered, report)
        _detail = (
            "TSA signature verification skipped in filtered mode: "
            "the Merkle root covers the full batch, not the filtered "
            "subset. Re-verify with an unfiltered bundle to check TSA "
            "signatures (WI-020)."
        )
        updated_batches = [
            replace(e, verified=None, verification_detail=_detail)
            if e.status == "confirmed"
            else e
            for e in report.timestamp_batches
        ]
        report.timestamp_batches.clear()
        report.timestamp_batches.extend(updated_batches)

        self._accumulate_witness_data(raw, filtered, report)
        self._verify_witness_signatures(filtered, report)
        self._check_witness_coverage(filtered, report)

        self._check_tsa_temporal_ordering(filtered, report)

        return report

    def _verify_loaded_bundle(
        self,
        raw: dict[str, Any],
        events: list[Event],
        manifest: dict[str, Any],
    ) -> VerificationReport:
        """Verify an already-loaded bundle."""
        hash_verified = self._verify_bundle_hash(raw, manifest)
        if hash_verified is False:
            report = VerificationReport()
            report.bundle_hash_ok = False
            report.bundle_hash_detail = "Bundle integrity hash mismatch (see log)"
            report.key_chain["bundle"] = manifest
            return report

        report = self.verify_events(events)
        report.bundle_hash_ok = True if hash_verified else None
        report.key_chain["bundle"] = manifest

        prev_hash = manifest.get("previous_bundle_hash")
        if prev_hash:
            report.previous_bundle_hash = prev_hash
            report.chain_integrity_ok = None
            log.info(
                "cairn.chain_link_present_unverified",
                previous=prev_hash,
                note="Link present but not validated — run verify-chain",
            )
        else:
            report.chain_integrity_ok = None
            log.warning("cairn.chain_link_missing")

        raw_tokens = self._accumulate_timestamp_batches(raw, events, report)
        self._verify_timestamp_signatures(raw_tokens, events, report)

        self._accumulate_witness_data(raw, events, report)
        self._verify_witness_signatures(events, report)
        self._check_witness_coverage(events, report)

        # TSA temporal ordering must run after timestamp batches are loaded
        # (BC-020 — only covered events should be checked).
        self._check_tsa_temporal_ordering(events, report)

        return report

    @staticmethod
    def _compute_bundle_hash(raw: dict[str, Any], manifest: dict[str, Any]) -> str:
        """Compute the canonical SHA-256 hash of a bundle (manifest + events)."""
        exclude = ("bundle_hash", "bundle_hash_covers")
        redacted_manifest = {k: v for k, v in manifest.items() if k not in exclude}
        redacted = {k: v for k, v in raw.items() if k != "manifest"}
        canonical_payload = {"manifest": redacted_manifest, **redacted}
        canonical = json.dumps(canonical_payload, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def _verify_bundle_hash(self, raw: dict[str, Any], manifest: dict[str, Any]) -> bool | None:
        """Return True if hash matches, False if mismatch, None if no hash present."""
        stored_hash = manifest.get("bundle_hash")
        if not stored_hash:
            log.warning("cairn.bundle_hash_missing")
            return None

        computed = self._compute_bundle_hash(raw, manifest)

        if computed == stored_hash:
            log.info("cairn.bundle_hash_ok")
            return True

        log.error("cairn.bundle_hash_mismatch", stored=stored_hash, computed=computed)
        return False

    def _verify_single(self, ev: Event) -> VerificationEntry:
        key = self._keys.get(ev.key_id)
        if key is None:
            return VerificationEntry(
                event_id=str(ev.event_id),
                work_item_id=str(ev.work_item_id),
                event_seq=ev.event_seq,
                timestamp=ev.timestamp.isoformat(),
                transition=ev.transition,
                result="unknown_key",
                detail=f"Unknown key_id: {ev.key_id}",
            )

        scheme_id = getattr(ev, "scheme_id", _DEFAULT_SCHEME_ID)
        try:
            scheme = get_scheme(scheme_id)
        except RegistaError:
            return VerificationEntry(
                event_id=str(ev.event_id),
                work_item_id=str(ev.work_item_id),
                event_seq=ev.event_seq,
                timestamp=ev.timestamp.isoformat(),
                transition=ev.transition,
                result="signature_failed",
                detail=f"Unknown signing scheme: {scheme_id}",
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
            scheme=scheme,
            prev_event_hash=ev.prev_event_hash,
            global_seq=ev.global_seq,
            entity_kind=getattr(ev, "entity_kind", "work_item"),
            hash_alg=getattr(ev, "hash_alg", "sha-256"),
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

        scheme_label = scheme_id.upper()
        return VerificationEntry(
            event_id=str(ev.event_id),
            work_item_id=str(ev.work_item_id),
            event_seq=ev.event_seq,
            timestamp=ev.timestamp.isoformat(),
            transition=ev.transition,
            result="signature_failed",
            detail=f"{scheme_label} signature does not verify",
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
                h = hashlib.sha256()
                with open(path, "rb") as fh:
                    while chunk := fh.read(65536):
                        h.update(chunk)
                current = h.hexdigest()
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
        entity_kind = getattr(ev, "entity_kind", "work_item")
        if entity_kind != "work_item":
            return
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
                harnesses=tuple(payload.get("harnesses", [])),
                scope_statement=payload.get("scope_statement", ""),
                harness_config_digests=payload.get("harness_config_digests"),
                content_capture=payload.get("content_capture", False),
                content_encryption=payload.get("content_encryption", "off"),
                redaction_policy=payload.get("redaction_policy"),
            )
        )

    def _accumulate_session_attestations(self, report: VerificationReport, ev: Event) -> None:
        """Collect session-attestation payloads from session-entity events."""
        entity_kind = getattr(ev, "entity_kind", "work_item")
        if entity_kind != "session":
            return
        payload = ev.payload or {}
        if "harnesses" not in payload or "scope_statement" not in payload:
            return
        report.session_attestations.append(
            SessionAttestationEntry(
                event_id=str(ev.event_id),
                entity_id=str(getattr(ev, "effective_entity_id", ev.work_item_id)),
                version=payload.get("version", "?"),
                principal_id=payload.get("principal_id", "?"),
                session_id=payload.get("session_id", "?"),
                attested_at=payload.get("attested_at", "?"),
                harnesses=tuple(payload.get("harnesses", [])),
                scope_statement=payload.get("scope_statement", ""),
                harness_config_digests=payload.get("harness_config_digests"),
                content_capture=payload.get("content_capture", False),
                content_encryption=payload.get("content_encryption", "off"),
                redaction_policy=payload.get("redaction_policy"),
            )
        )

    def _accumulate_key_rotations(self, report: VerificationReport, ev: Event) -> None:
        """Detect key_rotation events and verify predecessor-signed rotation.

        A key rotation event has ``tool == "key_rotation"`` in its payload.
        The event must be signed by the predecessor key (which is the key
        that was active before the rotation).  The verifier checks:

        1. The predecessor key is known (in the key set).
        2. The event's signature verifies against the predecessor key.
        3. The ``predecessor_key_id`` in the payload matches the event's
           ``key_id`` (the key that actually signed it).
        """
        payload = ev.payload or {}
        if payload.get("tool") != "key_rotation":
            return

        pred_id = payload.get("predecessor_key_id", "")
        succ_id = payload.get("successor_key_id", "")
        rotated_at = payload.get("rotated_at")

        # Check that the event was signed by the predecessor key
        signed_by = ev.key_id
        sig_valid = signed_by == pred_id

        detail = None
        if not sig_valid:
            detail = (
                f"Rotation claims predecessor={pred_id} but event was signed by key_id={signed_by}"
            )

        # If we have the predecessor key in our key set, also verify
        # the cryptographic signature.  If the predecessor key is NOT
        # available, mark as unverified — we cannot trust the rotation
        # without cryptographic proof.
        if sig_valid and pred_id in self._keys:
            scheme_id = getattr(ev, "scheme_id", _DEFAULT_SCHEME_ID)
            try:
                scheme = get_scheme(scheme_id)
            except RegistaError:
                scheme = None

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
                key=self._keys[pred_id],
                stored_envelope=ev.canonical_envelope,
                on_behalf_of=ev.on_behalf_of,
                scheme=scheme,
                prev_event_hash=ev.prev_event_hash,
                global_seq=ev.global_seq,
            )
            if not ok:
                sig_valid = False
                detail = (
                    f"Rotation event signature does not verify against predecessor key {pred_id}"
                )
        elif sig_valid:
            sig_valid = False
            detail = (
                f"Rotation claims predecessor={pred_id} but predecessor "
                f"key is not in the verifier's key set — cannot verify"
            )

        report.key_rotations.append(
            KeyRotationEntry(
                event_id=str(ev.event_id),
                work_item_id=str(ev.work_item_id),
                predecessor_key_id=pred_id,
                successor_key_id=succ_id,
                rotated_at=rotated_at,
                signature_valid=sig_valid,
                detail=detail,
            )
        )

    def _accumulate_delegation_chains(self, report: VerificationReport, ev: Event) -> None:
        """Validate on_behalf_of delegation chains using regista's DelegationChain."""
        if ev.on_behalf_of is None:
            return

        principal_id = ev.on_behalf_of.get("principal_id", "")
        session_id = ev.on_behalf_of.get("session_id")
        authenticated_at = ev.on_behalf_of.get("authenticated_at")
        scope = ev.on_behalf_of.get("scope")
        expires_at = ev.on_behalf_of.get("expires_at")

        validation_ok = True
        validation_detail = None

        # Validate using regista's delegation chain contract
        try:
            from regista._contract import validate_delegation_chain

            validate_delegation_chain(
                ev.on_behalf_of,
                event_timestamp=ev.timestamp.isoformat(),
            )
        except (ValueError, TypeError, KeyError, RegistaError) as exc:
            validation_ok = False
            validation_detail = str(exc)[:500]
            log.debug(
                "delegation_chain_validation_failed",
                event_id=str(ev.event_id),
                exc_type=type(exc).__name__,
                exc_msg=str(exc),
            )

        report.delegation_chains.append(
            DelegationChainEntry(
                event_id=str(ev.event_id),
                work_item_id=str(ev.work_item_id),
                principal_id=principal_id,
                session_id=session_id,
                authenticated_at=authenticated_at,
                scope=tuple(scope) if scope is not None else None,
                expires_at=expires_at,
                validation_ok=validation_ok,
                validation_detail=validation_detail,
            )
        )

    def _accumulate_timestamp_batches(
        self,
        raw_bundle: dict[str, Any],
        events: list[Event],
        report: VerificationReport,
    ) -> dict[str, bytes]:
        """Load TSA timestamp batches from the bundle and check event coverage.

        Returns a mapping ``batch_id → tsa_token_bytes`` for confirmed batches
        so that ``_verify_timestamp_signatures`` can verify them.

        Also records, per confirmed batch, the list of event UUIDs the batch
        claims to cover that are actually present in the bundle, so that
        ``_verify_timestamp_signatures`` can recompute the Merkle root from the
        bundle's own events (BC-015) rather than trusting the bundle-supplied
        ``merkle_root``.
        """
        raw_batches = raw_bundle.get("timestamp_batches")
        if not raw_batches:
            return {}

        exported_ids = {str(ev.event_id) for ev in events}
        covered_ids: set[str] = set()
        raw_tokens: dict[str, bytes] = {}

        for raw in raw_batches:
            batch_id = raw.get("batch_id", "unknown")
            entry = TimestampBatchEntry(
                batch_id=batch_id,
                merkle_root=raw.get("merkle_root", ""),
                event_count=len(raw.get("event_ids", [])),
                event_ids=tuple(str(eid) for eid in raw.get("event_ids", [])),
                status=raw.get("status", "unknown"),
                tsa_timestamp=raw.get("tsa_timestamp"),
            )
            report.timestamp_batches.append(entry)

            if raw.get("status") == "confirmed":
                batch_ids = {str(eid) for eid in raw.get("event_ids", [])}
                covered_ids.update(batch_ids & exported_ids)
                # Record the claimed coverage and present coverage for this
                # batch so the root can be recomputed against bundle events.
                self._batch_claimed_ids[batch_id] = [
                    str(eid) for eid in raw.get("event_ids", [])
                ]
                token_hex = raw.get("tsa_token")
                if token_hex:
                    raw_tokens[batch_id] = bytes.fromhex(token_hex)

        uncovered = exported_ids - covered_ids
        if uncovered:
            log.warning(
                "cairn.events_not_timestamped",
                count=len(uncovered),
                sample=sorted(uncovered)[:5],
            )
        return raw_tokens

    def _verify_timestamp_signatures(
        self,
        raw_tokens: dict[str, bytes],
        events: list[Event],
        report: VerificationReport,
    ) -> None:
        """Verify TSA tokens against a Merkle root recomputed from bundle events.

        BC-015: the TSA token must be bound to the *actual* event content in the
        bundle, not to a bundle-supplied ``merkle_root`` an operator can copy
        from an unrelated honest batch.  For each confirmed batch we:

        1. Recompute the Merkle root from the UUIDs of the batch's claimed
           events that are present in the bundle (``compute_merkle_root`` — the
           same construction regista's timestamping uses).
        2. Reject the batch if the recomputed root differs from the bundle's
           stated ``merkle_root`` (the operator altered/added/removed events
           but kept an old root and token).
        3. When a trust anchor is configured, verify the TSA token's CMS
           signature and message imprint against the **recomputed** root.

        Without a trust anchor (no ``--tsa-cert``) the CMS signature cannot be
        checked, but the recomputed-vs-stated root binding (step 2) is still
        enforced so a copied token over a different root is caught.
        """
        if not raw_tokens:
            return

        try:
            from regista._timestamping import (
                TSAConfig,
                compute_merkle_root,
                verify_tsa_token_full,
            )
        except ImportError:
            log.warning("cairn.tsa_verify_import_failed")
            return

        import uuid as _uuid

        config = (
            TSAConfig(tsa_url="", tsa_cert_path=self._tsa_cert_path)
            if self._tsa_cert_path
            else None
        )

        events_by_id = {str(ev.event_id): ev for ev in events}

        updated: list[TimestampBatchEntry] = []
        for entry in report.timestamp_batches:
            token = raw_tokens.get(entry.batch_id)
            if token is None or entry.status != "confirmed":
                updated.append(entry)
                continue

            # (1) Recompute the Merkle root from the bundle's own events.
            claimed_ids = self._batch_claimed_ids.get(entry.batch_id, [])
            present_uuids: list[_uuid.UUID] = []
            for eid in claimed_ids:
                if eid in events_by_id:
                    try:
                        present_uuids.append(_uuid.UUID(eid))
                    except ValueError:
                        pass

            verified: bool | None
            detail: str
            if not present_uuids:
                # The batch claims to cover events, none of which are in the
                # bundle.  The token proves nothing about this bundle.
                verified = False
                detail = (
                    "Timestamp batch covers no events present in the bundle; "
                    "the TSA token is not bound to any bundle event (BC-015)."
                )
            else:
                recomputed = compute_merkle_root(present_uuids)
                recomputed_hex = recomputed.hex()
                stated_hex = (entry.merkle_root or "").lower()

                if stated_hex and recomputed_hex != stated_hex:
                    # (2) Root recomputed from bundle events disagrees with the
                    # bundle-stated root: the events were altered/reordered or
                    # the token belongs to a different batch.
                    verified = False
                    detail = (
                        "Recomputed Merkle root over bundle events "
                        f"({recomputed_hex[:16]}...) does not match the "
                        f"bundle-stated merkle_root ({stated_hex[:16]}...). "
                        "The TSA token is not bound to the events in this "
                        "bundle (BC-015 — backdating / token-reuse defense)."
                    )
                elif config is None:
                    # No trust anchor: cannot check the CMS signature, but the
                    # recomputed root matched the stated root.  Leave the
                    # signature unverified (None) as before, without claiming
                    # cryptographic verification.
                    verified = None
                    detail = (
                        "Recomputed Merkle root matches stated root; CMS "
                        "signature NOT checked (no --tsa-cert)."
                    )
                else:
                    # (3) Verify the token against the recomputed root.
                    ok, sig_detail = verify_tsa_token_full(token, recomputed, config)
                    verified = ok
                    detail = sig_detail

            updated.append(
                TimestampBatchEntry(
                    batch_id=entry.batch_id,
                    merkle_root=entry.merkle_root,
                    first_global_seq=entry.first_global_seq,
                    last_global_seq=entry.last_global_seq,
                    event_count=entry.event_count,
                    event_ids=entry.event_ids,
                    status=entry.status,
                    tsa_timestamp=entry.tsa_timestamp,
                    verified=verified,
                    verification_detail=detail,
                )
            )
            if verified is True:
                log.info("cairn.tsa_signature_verified", batch_id=entry.batch_id[:8])
            elif verified is False:
                log.warning(
                    "cairn.tsa_signature_failed",
                    batch_id=entry.batch_id[:8],
                    detail=detail,
                )

        # Replace the list contents in-place
        report.timestamp_batches.clear()
        report.timestamp_batches.extend(updated)

    def _accumulate_witness_data(
        self,
        raw_bundle: dict[str, Any],
        events: list[Event],
        report: VerificationReport,
    ) -> None:
        """Load witness registrations and receipts from the bundle.

        Also collects witness public keys from registrations when present,
        so that _verify_witness_signatures can cryptographically verify
        receipt signatures (BC-016).
        """
        raw_witnesses = raw_bundle.get("witness_registrations")
        if raw_witnesses:
            for w in raw_witnesses:
                pubkey_hex = w.get("public_key")
                key_scheme = w.get("key_scheme")
                report.witness_registrations.append(
                    WitnessRegistrationEntry(
                        witness_id=str(w.get("witness_id", "")),
                        url=w.get("url", ""),
                        status=w.get("status", "active"),
                        mode=w.get("mode", "witness"),
                        public_key=pubkey_hex if isinstance(pubkey_hex, str) else None,
                        key_scheme=key_scheme if isinstance(key_scheme, str) else None,
                    )
                )
                # Collect Ed25519 public keys from registrations
                if pubkey_hex and key_scheme == "ed25519":
                    try:
                        wid = str(w.get("witness_id", ""))
                        self._witness_keys.setdefault(
                            wid, bytes.fromhex(pubkey_hex)
                        )
                    except (ValueError, TypeError):
                        pass

        raw_receipts = raw_bundle.get("witness_receipts")
        if raw_receipts:
            for r in raw_receipts:
                sig_hex = r.get("witness_signature")
                ev_id = str(r.get("event_id", ""))
                wid = str(r.get("witness_id", ""))
                sig_bytes = None
                if sig_hex:
                    try:
                        sig_bytes = bytes.fromhex(sig_hex)
                    except (ValueError, TypeError):
                        pass
                self._witness_sig_cache[(ev_id, wid)] = sig_bytes
                report.witness_receipts.append(
                    WitnessReceiptEntry(
                        event_id=ev_id,
                        witness_id=wid,
                        confirmed_at=r.get("confirmed_at"),
                        has_signature=sig_hex is not None,
                    )
                )

    def _verify_witness_signatures(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Cryptographically verify witness receipt signatures (BC-016).

        For each witness receipt:
        - If the witness has an Ed25519 public key (from ``witness_keys``
          parameter or bundle registrations), verify the receipt's
          signature against the event's canonical envelope.
        - If the witness key scheme is ``hmac-sha256`` (or unknown and no
          key is available), the receipt is accepted without cryptographic
          verification (backward-compatible — regista's own delivery layer
          already verified HMAC witnesses).

        Receipts with invalid Ed25519 signatures are marked
        ``signature_valid=False`` and will not count toward witness
        coverage in ``_check_witness_coverage``.
        """
        if not report.witness_receipts:
            return

        # Build event lookup: event_id → canonical_envelope bytes
        env_by_event: dict[str, bytes] = {}
        for ev in events:
            if ev.canonical_envelope is not None:
                env_by_event[str(ev.event_id)] = ev.canonical_envelope

        # Build witness_id → key_scheme lookup from registrations
        scheme_by_witness: dict[str, str] = {}
        for reg in report.witness_registrations:
            if reg.key_scheme:
                scheme_by_witness[reg.witness_id] = reg.key_scheme

        has_any_keys = bool(self._witness_keys)
        updated_receipts: list[WitnessReceiptEntry] = []

        for receipt in report.witness_receipts:
            wid = receipt.witness_id
            ev_id = receipt.event_id
            key_scheme = scheme_by_witness.get(wid)

            # Determine if this witness requires Ed25519 signature verification
            needs_ed25519 = key_scheme == "ed25519" or (
                key_scheme is None and wid in self._witness_keys
            )

            if needs_ed25519:
                pub_key = self._witness_keys.get(wid)
                sig_bytes = self._witness_sig_cache.get((ev_id, wid))

                if pub_key is None:
                    updated_receipts.append(replace(
                        receipt,
                        signature_valid=None,
                        verification_detail=(
                            "Witness uses Ed25519 but no public key "
                            "available — signature NOT verified"
                        ),
                    ))
                elif sig_bytes is None:
                    updated_receipts.append(replace(
                        receipt,
                        signature_valid=False,
                        verification_detail="Missing witness signature",
                    ))
                else:
                    envelope = env_by_event.get(ev_id)
                    if envelope is None:
                        updated_receipts.append(replace(
                            receipt,
                            signature_valid=None,
                            verification_detail=(
                                "Event canonical envelope not available "
                                "in bundle — cannot verify"
                            ),
                        ))
                    else:
                        try:
                            from regista._signing_scheme import Ed25519Scheme

                            verified = Ed25519Scheme().verify(
                                envelope, sig_bytes,
                                hashlib.sha256(envelope).digest(),
                                pub_key,
                            )
                            updated_receipts.append(replace(
                                receipt,
                                signature_valid=verified,
                                verification_detail=(
                                    "Ed25519 signature verified"
                                    if verified
                                    else "Ed25519 signature verification FAILED"
                                ),
                            ))
                        except Exception as exc:
                            updated_receipts.append(replace(
                                receipt,
                                signature_valid=False,
                                verification_detail=f"Verification error: {exc}",
                            ))
            else:
                # HMAC witness or legacy — no signature verification needed
                updated_receipts.append(replace(
                    receipt,
                    signature_valid=None,
                    verification_detail=(
                        "HMAC witness — signature not checked"
                        if key_scheme == "hmac-sha256"
                        else "No key scheme — signature not checked"
                    ),
                ))

        report.witness_receipts = updated_receipts

        if has_any_keys:
            failed = sum(1 for r in updated_receipts if r.signature_valid is False)
            if failed:
                log.warning(
                    "cairn.witness_signature_failed",
                    failed_count=failed,
                    total_receipts=len(updated_receipts),
                )
        else:
            sig_receipts = sum(1 for r in updated_receipts if r.has_signature)
            if sig_receipts:
                log.warning(
                    "cairn.witness_signatures_not_checked",
                    signed_receipts=sig_receipts,
                    note="No witness public keys provided — "
                    "receipt signatures not verified",
                )

    def _check_witness_coverage(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Check that every event has confirmed receipts from all active witnesses.

        Only checks witnesses whose ``event_filter`` matches the event.
        When no witnesses are registered, this is a no-op.

        BC-016: receipts with ``signature_valid=False`` do not count as
        confirmed — a forged receipt is not coverage.
        """
        if not report.witness_registrations:
            return

        active_witnesses = [
            w for w in report.witness_registrations if w.status == "active"
        ]
        if not active_witnesses:
            return

        # Build lookup: witness_id → key_scheme from registrations.
        scheme_by_witness: dict[str, str] = {}
        for reg in active_witnesses:
            if reg.key_scheme:
                scheme_by_witness[reg.witness_id] = reg.key_scheme

        # Build lookup: event_id → set of witness_ids with confirmed receipts.
        # A receipt counts as confirmed only if its signature was verified
        # (signature_valid is True).  For HMAC witnesses, signature_valid is
        # None (not checked) and the receipt still counts — regista's delivery
        # layer already verified HMAC.  For Ed25519 witnesses, None means the
        # public key was unavailable, so the receipt does NOT count.
        receipts_by_event: dict[str, set[str]] = {}
        for r in report.witness_receipts:
            if r.signature_valid is False:
                continue
            wid_scheme = scheme_by_witness.get(r.witness_id)
            if r.signature_valid is None and wid_scheme == "ed25519":
                continue
            if r.event_id not in receipts_by_event:
                receipts_by_event[r.event_id] = set()
            receipts_by_event[r.event_id].add(r.witness_id)

        witness_ids = {w.witness_id for w in active_witnesses}

        for ev in events:
            ev_id = str(ev.event_id)
            confirmed_witnesses = receipts_by_event.get(ev_id, set())
            missing = witness_ids - confirmed_witnesses
            if missing:
                missing_urls = [
                    w.url for w in active_witnesses if w.witness_id in missing
                ]
                report.witness_coverage_violations.append(
                    WitnessCoverageViolation(
                        event_id=ev_id,
                        work_item_id=str(ev.work_item_id),
                        missing_witnesses=tuple(missing_urls),
                        detail=(
                            f"Event {ev_id[:8]}.. missing confirmed receipts "
                            f"from {len(missing)} witness(es): "
                            + ", ".join(missing_urls[:3])
                        ),
                    )
                )

    def _check_event_sequence(self, events: list[Event], report: VerificationReport) -> None:
        """Detect gaps and ordering violations in event sequences.

        Groups events by (entity_kind, entity_id), checks that event_seq
        values are contiguous within each entity and that timestamps are
        non-decreasing.
        """
        from collections import defaultdict

        by_entity: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in events:
            ek = getattr(ev, "entity_kind", "work_item")
            eid = str(ev.effective_entity_id)
            by_entity[(ek, eid)].append(ev)

        for (ek, eid), entity_events in by_entity.items():
            # NOTE: single-event entities are intentionally NOT skipped here
            # (BC-010).  A lone event still has its ordering examined, and
            # cross-entity deletion of single-event entities is caught by
            # _check_chain_contiguity via the global_seq gap check.

            # Sort by event_seq to detect gaps
            sorted_events = sorted(entity_events, key=lambda e: e.event_seq)
            expected_seq = sorted_events[0].event_seq
            prev_ts = None
            for ev in sorted_events:
                if ev.event_seq != expected_seq:
                    if ev.event_seq > expected_seq:
                        report.sequence_gaps.append(
                            SequenceGap(
                                work_item_id=eid,
                                kind="missing_seq",
                                detail=(
                                    f"Expected seq {expected_seq}, got {ev.event_seq}. "
                                    f"Events may have been deleted from the log."
                                ),
                                expected_seq=expected_seq,
                                actual_seq=ev.event_seq,
                            )
                        )
                    else:
                        report.sequence_gaps.append(
                            SequenceGap(
                                work_item_id=eid,
                                kind="duplicate_seq",
                                detail=(
                                    f"Duplicate seq {ev.event_seq} (expected {expected_seq}). "
                                    f"Events may have been duplicated or replayed."
                                ),
                                expected_seq=expected_seq,
                                actual_seq=ev.event_seq,
                            )
                        )
                expected_seq = ev.event_seq + 1

                if prev_ts is not None and ev.timestamp < prev_ts:
                    report.sequence_gaps.append(
                        SequenceGap(
                            work_item_id=eid,
                            kind="timestamp_regression",
                            detail=(
                                f"Event {ev.event_id} seq {ev.event_seq} timestamp "
                                f"{ev.timestamp.isoformat()} is before previous "
                                f"event timestamp {prev_ts.isoformat()}."
                            ),
                        )
                    )
                prev_ts = ev.timestamp

    def _check_chain_contiguity(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Verify the event-level hash chain and global ordering (BC-010).

        regista binds two independent ordering structures into every event's
        signed envelope:

        * ``global_seq`` — the cross-work-item total order of the log.
        * ``prev_event_hash`` — ``sha256(prev.canonical_envelope + prev.signature)``
          of the event at ``(work_item_id, event_seq - 1)`` (a per-work-item
          hash chain; see ``regista._events`` / ``_in_memory_replay``).

        The signature merely binds these fields; it does not prove the chain is
        *contiguous*.  Without an independent walk an operator can delete whole
        work items, truncate the genesis prefix, or splice in foreign events and
        every remaining per-event signature still verifies.  This method closes
        that gap:

        1. Walk the global hash chain (``prev_global_event_hash``, migration 030):
           every event chains to ``sha256(prev.canonical_envelope +
           prev.signature)`` of the event appended immediately before it across
           all work items. This is the only signal that detects deletion of a
           whole work item or truncation of the genesis prefix. It is gap-immune;
           ``global_seq`` is ``CACHE 100`` and non-contiguous by design (AP-012),
           so numeric contiguity is NOT used (legacy pre-030 bundles excepted).
        2. For every event carrying ``prev_event_hash`` (event_seq > 1), locate
           the predecessor at ``event_seq - 1`` in the same work item; recompute
           ``sha256(envelope + signature)`` and require it to equal the stored
           ``prev_event_hash``.  A missing predecessor (deletion/truncation) or a
           mismatch (splice) is a violation.
        3. Refuse a downgraded envelope: if an event carries ``global_seq`` it is
           a v3-chained event and must also carry ``prev_event_hash`` for
           event_seq > 1 (a v2 envelope that drops the chain field is rejected).
        """
        # --- (1) global completeness across work items ---
        # regista binds prev_global_event_hash = sha256(prev.canonical_envelope +
        # prev.signature) of the immediately preceding event in append order
        # (migration 030). global_seq is declared CACHE 100 and is therefore
        # non-contiguous by design under a connection pool, so numeric contiguity
        # is NOT a completeness signal (AP-012). We walk the signed hash links
        # instead: gap-immune, and global_seq sort order need not equal chain
        # order (cross-connection cache blocks), so we follow hashes, not numbers.
        #
        # Duplicate global_seq is still anomalous (the UNIQUE constraint should
        # make it impossible) and is reported regardless.
        seq_events = [ev for ev in events if ev.global_seq is not None]
        seen_seq: dict[int, Event] = {}
        for ev in seq_events:
            dup = seen_seq.get(ev.global_seq)
            if dup is not None:
                report.chain_contiguity_violations.append(
                    ChainContiguityViolation(
                        kind="global_seq_gap",
                        detail=(
                            f"Duplicate global_seq {ev.global_seq}: events "
                            f"{dup.event_id} and {ev.event_id} share the same "
                            "total-order position."
                        ),
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                        actual=str(ev.global_seq),
                    )
                )
            else:
                seen_seq[ev.global_seq] = ev

        use_global_chain = any(
            ev.prev_global_event_hash is not None for ev in events
        )
        if use_global_chain:
            own_hash: dict[bytes, Event] = {}
            for ev in events:
                if ev.canonical_envelope and ev.signature:
                    h = hashlib.sha256(
                        bytes(ev.canonical_envelope) + bytes(ev.signature)
                    ).digest()
                    own_hash[h] = ev

            # A "root" is an event whose global predecessor is absent from the
            # bundle: either the true genesis (prev is None) or the first event of
            # a windowed export (prev points outside the window). Exactly one root
            # is expected. Additional roots mean the event that linked back into
            # the chain was deleted — an interior break across work items, which
            # the per-work-item prev_event_hash walk cannot see.
            roots = [
                ev
                for ev in events
                if ev.prev_global_event_hash is None
                or bytes(ev.prev_global_event_hash) not in own_hash
            ]
            roots.sort(key=lambda e: e.global_seq if e.global_seq is not None else 0)
            for extra in roots[1:]:
                report.chain_contiguity_violations.append(
                    ChainContiguityViolation(
                        kind="global_seq_gap",
                        detail=(
                            f"Global hash chain broken: event {extra.event_id} "
                            "chains to a global predecessor absent from the bundle, "
                            "but it is not the bundle's first event. An event was "
                            "deleted or the log truncated between work items."
                        ),
                        event_id=str(extra.event_id),
                        work_item_id=str(extra.work_item_id),
                    )
                )

            # A fork — two events chaining to the same in-bundle predecessor —
            # means an event was spliced in or duplicated.
            successor_of: dict[bytes, str] = {}
            for ev in events:
                if ev.prev_global_event_hash is None:
                    continue
                pb = bytes(ev.prev_global_event_hash)
                if pb not in own_hash:
                    continue
                if pb in successor_of:
                    report.chain_contiguity_violations.append(
                        ChainContiguityViolation(
                            kind="prev_hash_mismatch",
                            detail=(
                                "Global hash chain fork: events "
                                f"{successor_of[pb]} and {ev.event_id} both chain to "
                                "the same predecessor — an event was spliced in or "
                                "duplicated."
                            ),
                            event_id=str(ev.event_id),
                            work_item_id=str(ev.work_item_id),
                        )
                    )
                else:
                    successor_of[pb] = str(ev.event_id)
        elif seq_events:
            # Legacy bundles predating the global chain (migration 030) carry no
            # prev_global_event_hash; fall back to numeric global_seq contiguity.
            ordered = sorted(seq_events, key=lambda e: e.global_seq)
            for prev, ev in itertools.pairwise(ordered):
                gap = ev.global_seq - prev.global_seq
                if gap > 1:
                    report.chain_contiguity_violations.append(
                        ChainContiguityViolation(
                            kind="global_seq_gap",
                            detail=(
                                f"global_seq jumps from {prev.global_seq} to "
                                f"{ev.global_seq} ({gap - 1} event(s) missing). "
                                "Events may have been deleted or truncated from "
                                "the log."
                            ),
                            event_id=str(ev.event_id),
                            work_item_id=str(ev.work_item_id),
                            expected=str(prev.global_seq + 1),
                            actual=str(ev.global_seq),
                        )
                    )

        # --- (2)/(3) prev_event_hash chain walk + downgrade refusal ---
        # Index events by (entity_kind, entity_id, event_seq) for predecessor lookup.
        by_entity_seq: dict[tuple[str, str, int], Event] = {}
        for ev in events:
            ek = getattr(ev, "entity_kind", "work_item")
            eid = str(ev.effective_entity_id)
            by_entity_seq[(ek, eid, ev.event_seq)] = ev

        for ev in events:
            # An event with global_seq set is a v3-chained event.  For
            # event_seq > 1 it MUST carry prev_event_hash; a v2 envelope that
            # drops the chain field is a downgrade and is refused.
            is_chained = ev.global_seq is not None
            if (
                is_chained
                and ev.event_seq > 1
                and ev.prev_event_hash is None
            ):
                report.chain_contiguity_violations.append(
                    ChainContiguityViolation(
                        kind="v2_downgrade",
                        detail=(
                            f"Event {ev.event_id} carries global_seq "
                            f"{ev.global_seq} (v3-chained) but no prev_event_hash. "
                            "A v3-chained event presented without its chain field "
                            "is a downgraded (v2) envelope and is rejected."
                        ),
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                    )
                )

            if ev.prev_event_hash is None:
                continue

            ek = getattr(ev, "entity_kind", "work_item")
            eid = str(ev.effective_entity_id)
            predecessor = by_entity_seq.get((ek, eid, ev.event_seq - 1))
            if predecessor is None:
                report.chain_contiguity_violations.append(
                    ChainContiguityViolation(
                        kind="missing_predecessor",
                        detail=(
                            f"Event {ev.event_id} (seq {ev.event_seq}) carries "
                            "prev_event_hash but its predecessor (seq "
                            f"{ev.event_seq - 1}) is absent from the bundle. "
                            "The preceding event was deleted or the log was "
                            "truncated."
                        ),
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                    )
                )
                continue

            prev_env = predecessor.canonical_envelope
            prev_sig = predecessor.signature
            if not prev_env or not prev_sig:
                report.chain_contiguity_violations.append(
                    ChainContiguityViolation(
                        kind="prev_hash_mismatch",
                        detail=(
                            f"Predecessor of event {ev.event_id} is missing its "
                            "canonical_envelope or signature; the hash chain "
                            "cannot be verified."
                        ),
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                    )
                )
                continue

            computed = hashlib.sha256(bytes(prev_env) + bytes(prev_sig)).digest()
            if computed != bytes(ev.prev_event_hash):
                report.chain_contiguity_violations.append(
                    ChainContiguityViolation(
                        kind="prev_hash_mismatch",
                        detail=(
                            f"Event {ev.event_id} prev_event_hash does not match "
                            "the canonical hash of its predecessor. The preceding "
                            "event was altered or substituted (splice)."
                        ),
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                        expected=bytes(ev.prev_event_hash).hex(),
                        actual=computed.hex(),
                    )
                )

    def _collect_attestations(
        self, report: VerificationReport
    ) -> list[tuple[str, str, tuple[dict[str, Any], ...], str]]:
        """Build a unified, time-sorted list of attestation entries.

        Combines scope_attestations and session_attestations into a single
        list of (attested_at, principal_id, harnesses, event_id) tuples so
        that _check_principal_binding and _check_scope_coverage can consult
        both sources.
        """
        entries: list[tuple[str, str, tuple[dict[str, Any], ...], str]] = []
        for sa in report.scope_attestations:
            entries.append((sa.attested_at, sa.principal_id, sa.harnesses, sa.event_id))
        for sess_sa in report.session_attestations:
            entries.append((
                sess_sa.attested_at, sess_sa.principal_id,
                sess_sa.harnesses, sess_sa.event_id,
            ))
        entries.sort(key=lambda e: _parse_iso(e[0]) or datetime.min.replace(tzinfo=UTC))
        return entries

    def _check_principal_binding(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Require every tool call to be bound to an authenticated principal (BC-013).

        README §1 names the in-scope guarantee as a record of every tool call
        "bound to an authenticated human principal."  This method enforces it:

        1. Every ``tool_call`` event must carry ``on_behalf_of.principal_id``;
           absence is a ``missing_principal`` violation.
        2. When an active scope attestation exists for the event, the tool
           call's ``principal_id`` must match the scope attestation's declared
           ``principal_id``; a mismatch is a ``principal_mismatch`` violation.

        The active scope attestation for an event is the latest attestation with
        ``attested_at <= event.timestamp`` (same selection rule as
        ``_check_scope_coverage``).

        "Tool call" here means an adapter-emitted audited action: a
        ``tool_call`` transition whose payload carries a ``harness`` field — the
        same boundary ``_check_scope_coverage`` uses.  Key-lifecycle events
        (rotation, revocation, scope attestation) ride the same transition names
        but are not principal-attributed actions and are excluded.
        """
        tool_calls = [
            ev
            for ev in events
            if (ev.transition or "").startswith("tool_call")
            and (ev.payload or {}).get("harness")
        ]
        if not tool_calls:
            return

        sorted_attestations = self._collect_attestations(report)

        def active_principal(ev_dt: datetime) -> str | None:
            chosen_pid: str | None = None
            for attested_at, pid, _harnesses, _eid in sorted_attestations:
                sa_dt = _parse_iso(attested_at)
                if sa_dt is not None and sa_dt <= ev_dt:
                    chosen_pid = pid
                else:
                    break
            return chosen_pid

        for ev in tool_calls:
            principal_id = None
            if ev.on_behalf_of is not None:
                principal_id = ev.on_behalf_of.get("principal_id") or None

            if not principal_id:
                report.principal_binding_violations.append(
                    PrincipalBindingViolation(
                        kind="missing_principal",
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                        transition=ev.transition,
                        detail=(
                            f"Tool call {ev.event_id} ({ev.transition}) has no "
                            "on_behalf_of.principal_id. Every tool call must be "
                            "bound to an authenticated principal (README §1)."
                        ),
                    )
                )
                continue

            expected = active_principal(ev.timestamp)
            if expected is not None and expected != principal_id:
                report.principal_binding_violations.append(
                    PrincipalBindingViolation(
                        kind="principal_mismatch",
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                        transition=ev.transition,
                        detail=(
                            f"Tool call {ev.event_id} is attributed to principal "
                            f"'{principal_id}' but the active scope attestation "
                            f"declares principal '{expected}'."
                        ),
                        principal_id=principal_id,
                        expected_principal_id=expected,
                    )
                    )

    def _collect_attested_session_ids(self, events: list[Event]) -> set[str]:
        """Collect all attested session IDs from a full event list.

        Used by ``verify_bundle_filtered`` to avoid false-positive
        attestation gaps when the session attestation falls outside the
        filter window but the tool calls fall inside it.
        """
        attested: set[str] = set()
        for ev in events:
            transition = ev.transition or ""
            if transition == "session_attestation":
                payload = ev.payload or {}
                sid = payload.get("session_id")
                if sid and sid != "?":
                    attested.add(sid)
            elif transition == "scope_statement" and ev.on_behalf_of is not None:
                sid = ev.on_behalf_of.get("session_id")
                if sid:
                    attested.add(sid)
        return attested

    def _check_attestation_gaps(
        self,
        events: list[Event],
        report: VerificationReport,
        *,
        attested_sessions: set[str] | None = None,
    ) -> None:
        """Detect sessions that produced tool-call events without a session
        attestation (Plan 008 WI-3.1).

        A session attestation (``cairn.session_attestation`` transition) is
        the harness's signed declaration that a session started under a
        known scope.  When tool-call events carry a ``session_id`` that has
        no matching session attestation, that session ran **unscoped** — a
        completeness defect an auditor must see named explicitly.

        This check is complementary to ``_check_scope_coverage``: scope
        coverage flags *individual events* whose harness is not listed in
        any active attestation; attestation gaps flag *whole sessions* that
        never attested at all.

        A session is considered "attested" if it has a session attestation
        event OR a scope attestation event (the legacy path) whose
        ``on_behalf_of.session_id`` matches.

        When ``attested_sessions`` is provided (filtered-verification
        mode), the method uses that set instead of collecting from the
        report — this prevents false positives when the session
        attestation falls outside the filter window but the tool calls
        fall inside it.
        """
        if attested_sessions is None:
            # Collect attested session IDs from session attestations
            attested_sessions = set()
            for sa in report.session_attestations:
                if sa.session_id and sa.session_id != "?":
                    attested_sessions.add(sa.session_id)

            # Also collect session IDs from scope attestation events (legacy path).
            sa_event_ids = {sa.event_id for sa in report.scope_attestations}
            for ev in events:
                if str(ev.event_id) in sa_event_ids and ev.on_behalf_of is not None:
                    sid = ev.on_behalf_of.get("session_id")
                    if sid:
                        attested_sessions.add(sid)

        # Group tool-call events by session_id
        session_tool_calls: dict[str, list[Event]] = {}
        for ev in events:
            transition = ev.transition or ""
            if not transition.startswith("tool_call"):
                continue
            payload = ev.payload or {}
            if not payload.get("harness"):
                continue
            session_id = None
            if ev.on_behalf_of is not None:
                session_id = ev.on_behalf_of.get("session_id")
            if not session_id or session_id == "?":
                continue
            session_tool_calls.setdefault(session_id, []).append(ev)

        # Flag sessions with tool calls but no attestation
        for session_id, tool_call_events in session_tool_calls.items():
            if session_id in attested_sessions:
                continue

            sorted_calls = sorted(tool_call_events, key=lambda e: e.timestamp)
            first_ev = sorted_calls[0]
            last_ev = sorted_calls[-1]
            first_payload = first_ev.payload or {}
            h_raw = first_payload.get("harness", "")
            if isinstance(h_raw, dict):
                harness = h_raw.get("name")
            elif isinstance(h_raw, str):
                harness = h_raw
            else:
                harness = None

            report.attestation_gaps.append(
                AttestationGap(
                    session_id=session_id,
                    tool_call_count=len(tool_call_events),
                    first_tool_call=first_ev.timestamp.isoformat()
                    if first_ev.timestamp
                    else None,
                    last_tool_call=last_ev.timestamp.isoformat()
                    if last_ev.timestamp
                    else None,
                    harness=harness,
                    event_ids=tuple(str(ev.event_id) for ev in sorted_calls),
                    detail=(
                        f"Session {session_id} produced {len(tool_call_events)} "
                        f"tool-call event(s) but has no session attestation. "
                        f"The session ran unscoped — its provenance is "
                        f"uncovered by any signed scope declaration."
                    ),
                )
            )

    def check_silence_gaps(
        self,
        events: list[Event],
        report: VerificationReport,
        harness_sessions: dict[str, dict[str, str | None]],
    ) -> None:
        """Detect harness sessions that produced no events at all
        (Plan 009 WI-4.1 — silence is a finding).

        ``harness_sessions`` maps session_id → evidence dict with optional
        ``last_activity`` (ISO timestamp) and ``transcript_path``.  The
        caller gathers it from the harness's local session transcripts
        (``cairn verify --harness-sessions``); an offline bundle alone
        cannot see what never entered it.

        A session counts as "present in the log" if *any* event binds to
        it — session attestation, ``on_behalf_of.session_id``, or a
        session-entity event keyed by the session UUID.  A harness session
        with zero such events means the recorder was wired but recorded
        nothing for it — the gap an auditor must see named explicitly.
        """
        seen: set[str] = set(self._collect_attested_session_ids(events))
        for ev in events:
            if ev.on_behalf_of is not None:
                sid = ev.on_behalf_of.get("session_id")
                if sid:
                    seen.add(sid)
            payload = ev.payload or {}
            psid = payload.get("session_id")
            if isinstance(psid, str) and psid:
                seen.add(psid)
            wid = getattr(ev, "work_item_id", None)
            if wid is not None:
                seen.add(str(wid))

        for session_id, evidence in sorted(harness_sessions.items()):
            if session_id in seen:
                continue
            last_activity = evidence.get("last_activity")
            report.silence_gaps.append(
                SilenceGap(
                    session_id=session_id,
                    last_activity=last_activity,
                    transcript_path=evidence.get("transcript_path"),
                    detail=(
                        f"Harness session {session_id} ran locally "
                        f"(last activity {last_activity or 'unknown'}) but produced "
                        "no events in the log — the recorder was configured "
                        "but silent for this session."
                    ),
                )
            )

    def _check_content_coverage_gaps(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Detect sessions that declared content capture but have digest-only events.

        Plan 010 WI-6.1: a session attested as ``content_capture=true`` but
        missing content fields on events that should have them (prompt/response
        events with only digests).  This is the content-layer analogue of
        Plan 009's "wired but not attesting."
        """
        content_sessions: dict[str, bool] = {}
        for sess_sa in report.session_attestations:
            if sess_sa.content_capture:
                content_sessions[sess_sa.session_id] = True

        if not content_sessions:
            return

        content_transitions = {
            "user_message",
            "assistant_message",
            "transcript_attestation",
        }
        for ev in events:
            transition = ev.transition or ""
            if transition not in content_transitions:
                continue
            payload = ev.payload or {}
            session_id = payload.get("session_id")
            if not session_id:
                if ev.on_behalf_of:
                    session_id = ev.on_behalf_of.get("session_id")
            if not session_id or session_id not in content_sessions:
                continue

            has_digest = "message_digest" in payload or "transcript_digest" in payload
            has_content = (
                "message_content" in payload
                or "transcript_content" in payload
            )
            if has_digest and not has_content:
                report.content_coverage_gaps.append(
                    ContentCoverageGap(
                        session_id=str(session_id),
                        event_id=str(ev.event_id),
                        transition=transition,
                        detail=(
                            f"Session {session_id} declared content_capture=true "
                            f"but event {ev.event_id} ({transition}) has only a "
                            f"digest — content field is missing. The session "
                            f"declared content capture but this event was "
                            f"recorded digest-only."
                        ),
                    )
                )

    def _accumulate_key_revocations(self, report: VerificationReport, ev: Event) -> None:
        """Detect key_revocation events and flag events signed after revocation.

        A key revocation event has ``tool == "key_revocation"`` in its payload.
        For events signed by a key that has a ``revoked_at`` timestamp in
        key_metadata, the verifier checks that the event's timestamp predates
        the revocation.  Events signed after revocation are flagged.
        """
        payload = ev.payload or {}
        if payload.get("tool") == "key_revocation":
            revoked_key_id = payload.get("revoked_key_id", "")
            revoked_at = payload.get("revoked_at")
            report.key_revocations.append(
                KeyRevocationEntry(
                    event_id=str(ev.event_id),
                    work_item_id=str(ev.work_item_id),
                    key_id=revoked_key_id,
                    revoked_at=revoked_at,
                )
            )

        # Check if this event was signed by a revoked key
        meta = self._key_meta.get(ev.key_id)
        if meta is None:
            return
        revoked_at = meta.get("revoked_at")
        if revoked_at is None:
            return

        ev_ts = ev.timestamp.isoformat()
        if ev_ts >= revoked_at:
            report.key_revocations.append(
                KeyRevocationEntry(
                    event_id=str(ev.event_id),
                    work_item_id=str(ev.work_item_id),
                    key_id=ev.key_id,
                    revoked_at=revoked_at,
                    detail=(
                        f"Event signed at {ev_ts} by key {ev.key_id} "
                        f"which was revoked at {revoked_at}"
                    ),
                )
            )

    def _check_scope_coverage(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Cross-check tool-call events against active scope attestations.

        For each tool_call event, find the latest scope attestation with
        ``attested_at <= event.timestamp``.  If the event's harness is not
        listed in that scope attestation, flag it as a scope violation.
        If no scope attestations exist at all, all tool_call events are
        flagged.
        """
        # Collect all tool_call events with a harness field
        tool_calls: list[Event] = []
        for ev in events:
            transition = ev.transition or ""
            if transition.startswith("tool_call"):
                payload = ev.payload or {}
                if payload.get("harness"):
                    tool_calls.append(ev)

        if not tool_calls:
            return

        if not report.scope_attestations and not report.session_attestations:
            # No attestations at all — flag every tool call
            for ev in tool_calls:
                payload = ev.payload or {}
                h_raw = payload.get("harness", "")
                h_name = h_raw.get("name", "") if isinstance(h_raw, dict) else h_raw
                report.scope_violations.append(
                    ScopeViolation(
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                        transition=ev.transition,
                        harness=h_name,
                        detail=(
                            "No attestation found in the log. "
                            f"Tool call from harness '{h_name}' "
                            "has no covering scope."
                        ),
                    )
                )
            return

        sorted_attestations = self._collect_attestations(report)

        for ev in tool_calls:
            payload = ev.payload or {}
            harness_raw = payload.get("harness", "")
            harness = harness_raw.get("name", "") if isinstance(harness_raw, dict) else harness_raw
            ev_dt = ev.timestamp

            active_harnesses: tuple[dict[str, Any], ...] = ()
            active_event_id = ""
            for attested_at, _pid, harnesses, eid in sorted_attestations:
                sa_dt = _parse_iso(attested_at)
                if sa_dt is not None and sa_dt <= ev_dt:
                    active_harnesses = harnesses
                    active_event_id = eid
                else:
                    break

            if not active_harnesses:
                report.scope_violations.append(
                    ScopeViolation(
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                        transition=ev.transition,
                        harness=harness,
                        detail=(
                            f"No attestation predates event at {ev_dt.isoformat()}. "
                            f"Tool call from harness '{harness}' has no covering scope."
                        ),
                    )
                )
                continue

            # Check if the harness is listed in the active attestation
            harness_names = {h.get("name", "") for h in active_harnesses}
            if harness not in harness_names:
                report.scope_violations.append(
                    ScopeViolation(
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                        transition=ev.transition,
                        harness=harness,
                        detail=(
                            f"Harness '{harness}' not in active attestation "
                            f"(event {active_event_id}). "
                            f"Covered harnesses: {sorted(harness_names)}"
                        ),
                    )
                )

    def _check_temporal_ordering(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Cross-field temporal ordering validation per v1 spec §4 item 8.

        Checks ``authenticated_at <= event.timestamp`` for delegation chains.
        TSA temporal ordering is handled separately by
        :meth:`_check_tsa_temporal_ordering`, which must be called *after*
        timestamp batches have been loaded (i.e. from ``verify_bundle``).
        """
        # Build event lookup for delegation chain checks
        event_by_id: dict[str, Event] = {str(ev.event_id): ev for ev in events}

        # Check delegation chain temporal ordering
        for dc in report.delegation_chains:
            if not dc.authenticated_at:
                continue

            # Find the corresponding event
            ev = event_by_id.get(dc.event_id)
            if ev is None:
                continue

            ev_ts = ev.timestamp.isoformat()
            if dc.authenticated_at > ev_ts:
                report.temporal_violations.append(
                    TemporalOrderingViolation(
                        event_id=dc.event_id,
                        work_item_id=dc.work_item_id,
                        kind="authenticated_after_event",
                        detail=(
                            f"authenticated_at ({dc.authenticated_at}) is after "
                            f"event.timestamp ({ev_ts}). "
                            f"Per spec, authenticated_at <= event.timestamp is required."
                        ),
                    )
                )

    def _check_tsa_temporal_ordering(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Check that TSA-covered events are not backdated relative to the TSA timestamp.

        Only events whose ``event_id`` appears in a batch's ``event_ids`` list
        are checked against that batch's temporal bounds (BC-020).  Events not
        covered by any TSA batch are not checked.
        """
        event_by_id: dict[str, Event] = {str(ev.event_id): ev for ev in events}

        for tb in report.timestamp_batches:
            if tb.status != "confirmed" or not tb.tsa_timestamp:
                continue

            try:
                tsa_dt = datetime.fromisoformat(tb.tsa_timestamp)
                if tsa_dt.tzinfo is None:
                    tsa_dt = tsa_dt.replace(tzinfo=UTC)
                tolerance = timedelta(seconds=_TSA_TOLERANCE_SECONDS)
                deadline = tsa_dt + tolerance
            except (ValueError, TypeError):
                log.warning(
                    "cairn.invalid_tsa_timestamp",
                    batch_id=tb.batch_id,
                    tsa_timestamp=tb.tsa_timestamp,
                )
                continue

            # Only check events covered by this batch (BC-020).
            for eid in tb.event_ids:
                ev = event_by_id.get(eid)
                if ev is None:
                    continue
                if ev.timestamp > deadline:
                    report.temporal_violations.append(
                        TemporalOrderingViolation(
                            event_id=str(ev.event_id),
                            work_item_id=str(ev.work_item_id),
                            kind="event_after_tsa",
                            detail=(
                                f"event.timestamp ({ev.timestamp.isoformat()}) exceeds "
                                f"TSA timestamp + tolerance ({deadline.isoformat()}). "
                                f"Batch {tb.batch_id[:8]}..."
                            ),
                        )
                    )

    def _check_role_gate(self, report: VerificationReport, ev: Event) -> None:
        """Check that the signing key's role is permitted for this transition.

        Uses ``key_metadata`` if provided.  When no metadata is present for
        a key, the check is skipped (backward-compatible with pre-BC-218
        key sets).
        """
        meta = self._key_meta.get(ev.key_id)
        if meta is None:
            return

        role = meta.get("role", "actor")
        transition = ev.transition or ""

        # Auditor keys can only sign auditor-only transitions
        if role == "auditor" and transition not in self._AUDITOR_ONLY_TRANSITIONS:
            report.role_gate_violations.append(
                RoleGateViolation(
                    event_id=str(ev.event_id),
                    work_item_id=str(ev.work_item_id),
                    key_id=ev.key_id,
                    role=role,
                    transition=transition,
                    detail=(
                        f"Key {ev.key_id} has role '{role}' but signed "
                        f"transition '{transition}' which requires role 'actor'."
                    ),
                )
            )

        # Actor keys cannot sign auditor-only transitions
        if role == "actor" and transition in self._AUDITOR_ONLY_TRANSITIONS:
            report.role_gate_violations.append(
                RoleGateViolation(
                    event_id=str(ev.event_id),
                    work_item_id=str(ev.work_item_id),
                    key_id=ev.key_id,
                    role=role,
                    transition=transition,
                    detail=(
                        f"Key {ev.key_id} has role '{role}' but signed "
                        f"transition '{transition}' which requires role 'auditor'."
                    ),
                )
            )

    def _compute_assurance_levels(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Compute review assurance levels from the signed event log.

        Implements regista Plan 027 WI-1.2 — the ``AssuranceLevel`` closed
        set as a derived property of the item's signed events.  The level is
        surfaced, never stored mutably, so it can never disagree with the
        record.

        For each work item with review-related transitions, this method:
        1.  Extracts author lineages from ``actor_metadata["model_lineage"]``
            on authoring events (mirrors regista's ``derive_authors``).
        2.  Extracts the reviewer lineage from the ``adversarial_pass`` event.
        3.  Computes ``same_lineage`` — a pure comparison of signed values.
        4.  Determines the ``AssuranceLevel`` from the combination of
            same/cross-lineage review and human accept.

        Lineage source is ``"asserted"`` in the HMAC-era interim posture.
        When per-actor Ed25519 lands (regista Plan 026), the verifier will
        check the actor↔signer binding and flip the source to ``"verified"``
        — no schema migration required.
        """
        from collections import defaultdict

        review_verdicts = frozenset(
            {"accept", "request_changes", "adversarial_pass", "reject"}
        )
        non_author = review_verdicts | {"comment"}
        review_transitions = review_verdicts | {
            "close_from_open",
            "submit_for_review",
        }

        by_wi: dict[str, list[Event]] = defaultdict(list)
        for ev in events:
            ek = getattr(ev, "entity_kind", "work_item")
            if ek != "work_item":
                continue
            by_wi[str(ev.work_item_id)].append(ev)

        for wi_id, wi_events in by_wi.items():
            wi_events.sort(key=lambda e: e.event_seq)
            transitions_seen = {ev.transition for ev in wi_events if ev.transition}
            if not (transitions_seen & review_transitions):
                continue

            has_adversarial_pass = "adversarial_pass" in transitions_seen
            has_accept = "accept" in transitions_seen
            has_close_from_open = "close_from_open" in transitions_seen

            author_lineages: set[str] = set()
            for ev in wi_events:
                if ev.transition in non_author:
                    continue
                meta = ev.actor_metadata or {}
                lineage = meta.get("model_lineage")
                if lineage:
                    author_lineages.add(str(lineage))
                delegation = ev.on_behalf_of
                if isinstance(delegation, dict):
                    p_lineage = delegation.get("principal_lineage")
                    if p_lineage:
                        author_lineages.add(str(p_lineage))

            reviewer_lineage: str | None = None
            if has_adversarial_pass:
                for ev in wi_events:
                    if ev.transition == "adversarial_pass":
                        meta = ev.actor_metadata or {}
                        lineage = meta.get("model_lineage")
                        if lineage:
                            reviewer_lineage = str(lineage)
                        break

            if reviewer_lineage and author_lineages:
                same_lineage = reviewer_lineage in author_lineages
            else:
                same_lineage = None

            if has_close_from_open and not has_adversarial_pass:
                level = AssuranceLevel.NONE
                detail = "Closed without review (close_from_open)."
            elif has_adversarial_pass:
                if same_lineage is False:
                    if has_accept:
                        level = AssuranceLevel.INDEPENDENT_AND_ACCEPTED
                        detail = (
                            "Cross-lineage adversarial review followed by "
                            "human accept — highest assurance."
                        )
                    else:
                        level = AssuranceLevel.INDEPENDENTLY_REVIEWED
                        detail = (
                            "Cross-lineage adversarial review — independent "
                            "reviewer model."
                        )
                elif same_lineage is True:
                    if has_accept:
                        level = AssuranceLevel.HUMAN_ACCEPTED
                        detail = (
                            "Same-lineage review compensated by human accept "
                            "(degraded review, compensating control applied)."
                        )
                    else:
                        level = AssuranceLevel.SELF_REVIEWED
                        detail = (
                            "Same-lineage review without human accept — "
                            "degraded assurance. Under the strict gate "
                            "profile this item cannot reach done without "
                            "a human accept."
                        )
                else:
                    if has_accept:
                        level = AssuranceLevel.HUMAN_ACCEPTED
                        detail = (
                            "Human accept (lineage comparison unavailable — "
                            "undeclared lineage)."
                        )
                    else:
                        level = AssuranceLevel.SELF_REVIEWED
                        detail = (
                            "Review without lineage declaration — assurance "
                            "unverifiable from the signed record."
                        )
            elif has_accept:
                level = AssuranceLevel.HUMAN_ACCEPTED
                detail = "Human accept without adversarial review."
            else:
                level = AssuranceLevel.NONE
                detail = "No review transitions."

            report.assurance_entries.append(
                AssuranceEntry(
                    work_item_id=wi_id,
                    assurance_level=level,
                    author_lineages=tuple(sorted(author_lineages)),
                    reviewer_lineage=reviewer_lineage,
                    same_lineage=same_lineage,
                    has_adversarial_pass=has_adversarial_pass,
                    has_human_accept=has_accept,
                    lineage_source="asserted",
                    detail=detail,
                )
            )

    def verify_bundle_chain(self, bundle_paths: list[str | Path]) -> VerificationReport:
        """Verify a chain of bundles linked by previous_bundle_hash.

        Bundles must be ordered oldest-first.  Verifies that each bundle's
        ``previous_bundle_hash`` matches the computed hash of the preceding
        bundle, and that all events within each bundle verify.

        Additionally verifies the cross-bundle *event-level* hash chain
        (WI-022): the first event in bundle N+1 that carries
        ``prev_global_event_hash`` must chain to the last event in bundle N
        via ``sha256(prev.canonical_envelope + prev.signature)``.  This
        prevents an attacker from creating a bundle with a valid
        ``previous_bundle_hash`` but events that don't actually chain at
        the event level.
        """
        if not bundle_paths:
            report = VerificationReport()
            report.chain_integrity_ok = None
            return report

        reports: list[VerificationReport] = []
        prev_hash: str | None = None
        # Last event's hash from the previous bundle, for cross-bundle
        # event-level chain verification (WI-022).
        prev_last_event_hash: bytes | None = None
        # Whether the previous bundle used the global hash chain at all.
        prev_used_global_chain: bool = False

        for path in bundle_paths:
            raw, events, manifest, error_report = self._load_bundle(Path(path))
            if error_report is not None:
                reports.append(error_report)
                prev_hash = None
                prev_last_event_hash = None
                continue

            computed_hash = self._compute_bundle_hash(raw, manifest)

            report = self._verify_loaded_bundle(raw, events, manifest)
            reports.append(report)

            # Check manifest-level chain link
            claimed_prev = manifest.get("previous_bundle_hash")
            if prev_hash is not None and claimed_prev != prev_hash:
                report.chain_integrity_ok = False
                log.error(
                    "cairn.chain_link_broken",
                    bundle=str(path),
                    expected_prev=prev_hash,
                    claimed_prev=claimed_prev,
                )

            # Check cross-bundle event-level hash chain (WI-022).
            if prev_last_event_hash is not None and events:
                first_ev = events[0]
                if first_ev.prev_global_event_hash is None:
                    # Only flag as a violation if the previous bundle used
                    # the global hash chain. Events from older regista
                    # versions may not have prev_global_event_hash.
                    if prev_used_global_chain:
                        report.chain_integrity_ok = False
                        report.chain_contiguity_violations.append(
                            ChainContiguityViolation(
                                kind="cross_bundle_missing_link",
                                detail=(
                                    f"First event {first_ev.event_id} in {path} "
                                    "lacks prev_global_event_hash — cannot verify "
                                    "cross-bundle event chain (WI-022)."
                                ),
                                event_id=str(first_ev.event_id),
                                work_item_id=str(first_ev.work_item_id),
                            )
                        )
                else:
                    actual = bytes(first_ev.prev_global_event_hash)
                    if actual != prev_last_event_hash:
                        report.chain_integrity_ok = False
                        report.chain_contiguity_violations.append(
                            ChainContiguityViolation(
                                kind="cross_bundle_hash_mismatch",
                                detail=(
                                    f"Cross-bundle event hash chain broken: "
                                    f"first event {first_ev.event_id} in "
                                    f"{path} chains to "
                                    f"{actual.hex()[:16]}... but the last "
                                    f"event in the preceding bundle hashes to "
                                    f"{prev_last_event_hash.hex()[:16]}... "
                                    f"(WI-022)."
                                ),
                                event_id=str(first_ev.event_id),
                                work_item_id=str(first_ev.work_item_id),
                                expected=prev_last_event_hash.hex(),
                                actual=actual.hex(),
                            )
                        )
                        log.error(
                            "cairn.cross_bundle_chain_broken",
                            bundle=str(path),
                            event_id=str(first_ev.event_id),
                            expected=prev_last_event_hash.hex()[:16],
                            actual=actual.hex()[:16],
                        )

            # Track whether this bundle uses the global hash chain.
            used_global_chain = any(
                ev.prev_global_event_hash is not None for ev in events
            )

            # Capture the last event's hash for the next bundle's chain check.
            if events:
                last_ev = events[-1]
                if last_ev.canonical_envelope and last_ev.signature:
                    prev_last_event_hash = hashlib.sha256(
                        bytes(last_ev.canonical_envelope) + bytes(last_ev.signature)
                    ).digest()
                else:
                    prev_last_event_hash = None
                prev_used_global_chain = used_global_chain
            # Empty bundle: carry forward prev_last_event_hash unchanged.
            # An empty bundle contributes no events to the global chain.

            prev_hash = computed_hash

        # Merge into a single report
        merged = VerificationReport()
        for r in reports:
            merged.total_events += r.total_events
            merged.ok += r.ok
            merged.signature_failed += r.signature_failed
            merged.hash_mismatch += r.hash_mismatch
            merged.revoked_key += r.revoked_key
            merged.entries.extend(r.entries)
            merged.file_provenance.extend(r.file_provenance)
            merged.scope_attestations.extend(r.scope_attestations)
            merged.session_attestations.extend(r.session_attestations)
            merged.sequence_gaps.extend(r.sequence_gaps)
            merged.scope_violations.extend(r.scope_violations)
            merged.temporal_violations.extend(r.temporal_violations)
            merged.role_gate_violations.extend(r.role_gate_violations)
            merged.chain_contiguity_violations.extend(r.chain_contiguity_violations)
            merged.principal_binding_violations.extend(r.principal_binding_violations)
            merged.attestation_gaps.extend(r.attestation_gaps)
            merged.assurance_entries.extend(r.assurance_entries)
            merged.key_revocations.extend(r.key_revocations)
            merged.delegation_chains.extend(r.delegation_chains)
            merged.key_rotations.extend(r.key_rotations)
            merged.timestamp_batches.extend(r.timestamp_batches)
            merged.witness_coverage_violations.extend(r.witness_coverage_violations)
            merged.key_chain.update(r.key_chain)
            for scheme, count in r.scheme_counts.items():
                merged.scheme_counts[scheme] = merged.scheme_counts.get(scheme, 0) + count
            seen_regs = {(w.witness_id, w.url) for w in merged.witness_registrations}
            for reg in r.witness_registrations:
                key = (reg.witness_id, reg.url)
                if key not in seen_regs:
                    merged.witness_registrations.append(reg)
                    seen_regs.add(key)
            seen_rcpts = {(rc.event_id, rc.witness_id) for rc in merged.witness_receipts}
            for rcpt in r.witness_receipts:
                key = (rcpt.event_id, rcpt.witness_id)
                if key not in seen_rcpts:
                    merged.witness_receipts.append(rcpt)
                    seen_rcpts.add(key)
            if r.bundle_hash_ok is False:
                merged.bundle_hash_ok = False
                merged.bundle_hash_detail = r.bundle_hash_detail
            elif merged.bundle_hash_ok is None and r.bundle_hash_ok is True:
                merged.bundle_hash_ok = True
            if r.chain_integrity_ok is False:
                merged.chain_integrity_ok = False
            elif merged.chain_integrity_ok is None and r.chain_integrity_ok is True:
                merged.chain_integrity_ok = True

        # Cross-bundle attestation gap deduplication: a session attested in
        # one bundle should not be flagged as a gap in another bundle.
        all_attested_session_ids: set[str] = set()
        for sa in merged.session_attestations:
            if sa.session_id and sa.session_id != "?":
                all_attested_session_ids.add(sa.session_id)
        if all_attested_session_ids:
            merged.attestation_gaps = [
                gap for gap in merged.attestation_gaps
                if gap.session_id not in all_attested_session_ids
            ]

        # Set chain_integrity_ok to True if chain was verified and passed.
        if (
            merged.chain_integrity_ok is None
            and len(bundle_paths) > 1
            and not any(
                v.kind.startswith("cross_bundle")
                for v in merged.chain_contiguity_violations
            )
        ):
            merged.chain_integrity_ok = True

        return merged

    # ------------------------------------------------------------------
    # Bundle diff
    # ------------------------------------------------------------------

    def diff_bundles(
        self,
        older_path: str | Path,
        newer_path: str | Path,
    ) -> BundleDiff:
        """Compare two bundles and return a structured diff.

        Bundles are compared by event_id (set difference), file provenance,
        scope attestations, and manifest metadata.
        """
        older_raw, _older_events, older_manifest, older_err = self._load_bundle(
            Path(older_path)
        )
        newer_raw, _newer_events, newer_manifest, newer_err = self._load_bundle(
            Path(newer_path)
        )
        if older_err is not None:
            raise ValueError(f"Cannot load older bundle: {older_err.bundle_hash_detail}")
        if newer_err is not None:
            raise ValueError(f"Cannot load newer bundle: {newer_err.bundle_hash_detail}")

        older_events = older_raw.get("events", [])
        newer_events = newer_raw.get("events", [])
        older_manifest = older_raw.get("manifest", {})
        newer_manifest = newer_raw.get("manifest", {})

        diff = BundleDiff(
            older_bundle=str(older_path),
            newer_bundle=str(newer_path),
            older_event_count=len(older_events),
            newer_event_count=len(newer_events),
        )

        # --- Event set diff ---
        older_ids = {e.get("event_id") for e in older_events}
        newer_ids = {e.get("event_id") for e in newer_events}

        for eid in sorted(newer_ids - older_ids):
            ev = next((e for e in newer_events if e.get("event_id") == eid), None)
            tool = (ev or {}).get("payload", {}).get("tool", "?")
            diff.entries.append(
                BundleDiffEntry(
                    kind="event_added",
                    detail=f"New event: {eid} (tool={tool})",
                    event_id=eid,
                )
            )

        for eid in sorted(older_ids - newer_ids):
            ev = next((e for e in older_events if e.get("event_id") == eid), None)
            tool = (ev or {}).get("payload", {}).get("tool", "?")
            diff.entries.append(
                BundleDiffEntry(
                    kind="event_removed",
                    detail=f"Removed event: {eid} (tool={tool})",
                    event_id=eid,
                )
            )

        # --- File provenance diff ---
        older_files = self._extract_file_map(older_events)
        newer_files = self._extract_file_map(newer_events)

        all_paths = sorted(set(older_files) | set(newer_files))
        for path in all_paths:
            old_digest = older_files.get(path)
            new_digest = newer_files.get(path)
            if old_digest is None and new_digest is not None:
                diff.entries.append(
                    BundleDiffEntry(
                        kind="file_new",
                        detail=f"New file touched: {path}",
                        path=path,
                    )
                )
            elif old_digest is not None and new_digest is None:
                diff.entries.append(
                    BundleDiffEntry(
                        kind="file_removed",
                        detail=f"File no longer touched: {path}",
                        path=path,
                    )
                )
            elif old_digest != new_digest:
                old_short = old_digest[:16] if old_digest else "?"
                new_short = new_digest[:16] if new_digest else "?"
                diff.entries.append(
                    BundleDiffEntry(
                        kind="file_changed",
                        detail=(f"File digest changed: {path} ({old_short}... -> {new_short}...)"),
                        path=path,
                    )
                )

        # --- Scope attestation diff ---
        older_scopes = self._extract_scope_statements(older_events)
        newer_scopes = self._extract_scope_statements(newer_events)
        if older_scopes != newer_scopes:
            diff.entries.append(
                BundleDiffEntry(
                    kind="scope_changed",
                    detail=(f"Scope attestation changed: {older_scopes!r} → {newer_scopes!r}"),
                )
            )

        # --- Manifest metadata diff ---
        for key in ("events_count", "source_project", "exported_at"):
            old_val = older_manifest.get(key)
            new_val = newer_manifest.get(key)
            if old_val != new_val:
                diff.entries.append(
                    BundleDiffEntry(
                        kind="manifest_changed",
                        detail=f"manifest.{key}: {old_val!r} → {new_val!r}",
                    )
                )

        return diff

    @staticmethod
    def _extract_file_map(events: list[dict[str, Any]]) -> dict[str, str]:
        """Build a map of file_path → latest post_digest (or pre_digest) from events."""
        file_map: dict[str, str] = {}
        for ev in events:
            payload = ev.get("payload", {})
            for f in payload.get("files", []):
                path = f.get("path", "")
                digest = f.get("post_digest") or f.get("pre_digest")
                if path and digest:
                    file_map[path] = digest
        return file_map

    @staticmethod
    def _extract_scope_statements(events: list[dict[str, Any]]) -> list[str]:
        """Extract sorted list of scope_statement values from events."""
        statements: list[str] = []
        for ev in events:
            payload = ev.get("payload", {})
            if "scope_statement" in payload and "harnesses" in payload:
                statements.append(payload["scope_statement"])
        return sorted(statements)

    # ------------------------------------------------------------------
    # Report formatters (delegated to cairn.verifier_report for backward compat)
    # ------------------------------------------------------------------

    format_report = staticmethod(format_report)
    format_report_json = staticmethod(format_report_json)
    format_report_html = staticmethod(format_report_html)
    format_diff = staticmethod(format_diff)
    format_diff_json = staticmethod(format_diff_json)


def _parse_iso(ts: str) -> datetime | None:
    """Parse an ISO-8601 timestamp string to a timezone-aware datetime.

    Handles both trailing-Z and +00:00 forms, with or without microseconds.
    Returns None on parse failure.
    """
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError):
        return None
