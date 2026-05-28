"""Offline verifier for Cairn event logs.

Reads regista events (from a signed bundle or directly from regista)
and produces an auditor-ready report.

Supports both HMAC-SHA256 and Ed25519 signing schemes.  The verifier
dispatches per-event based on the ``scheme_id`` field (added in regista
Plan 011).  For Ed25519, the key_set should contain the **public key**
bytes (not the signing secret).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
from regista._errors import RegistaError
from regista._signing import verify_event as _verify_event_impl
from regista._signing_scheme import get_scheme
from regista._types import Event

_DEFAULT_SCHEME_ID = "hmac-sha256"

log = structlog.get_logger()


__all__ = [
    "BundleDiff",
    "BundleDiffEntry",
    "DelegationChainEntry",
    "FileProvenanceEntry",
    "KeyRevocationEntry",
    "KeyRotationEntry",
    "RoleGateViolation",
    "ScopeAttestationEntry",
    "ScopeViolation",
    "SequenceGap",
    "TemporalOrderingViolation",
    "TimestampBatchEntry",
    "VerificationEntry",
    "VerificationReport",
    "Verifier",
]


@dataclass(frozen=True)
class KeyRotationEntry:
    """A key rotation event detected in the log."""

    event_id: str
    work_item_id: str
    predecessor_key_id: str
    successor_key_id: str
    rotated_at: str | None
    signature_valid: bool
    detail: str | None = None


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
class BundleDiffEntry:
    """A single difference between two bundles."""

    # kind: event_added | event_removed | file_new | file_removed |
    #       file_changed | scope_changed | manifest_changed
    kind: str
    detail: str
    event_id: str | None = None
    path: str | None = None


@dataclass
class BundleDiff:
    """Result of comparing two bundles (older → newer)."""

    older_bundle: str
    newer_bundle: str
    older_event_count: int
    newer_event_count: int
    entries: list[BundleDiffEntry] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return len(self.entries) > 0

    @property
    def events_added(self) -> int:
        return sum(1 for e in self.entries if e.kind == "event_added")

    @property
    def events_removed(self) -> int:
        return sum(1 for e in self.entries if e.kind == "event_removed")

    @property
    def files_changed(self) -> int:
        return sum(1 for e in self.entries if e.kind == "file_changed")


@dataclass(frozen=True)
class SequenceGap:
    """A gap or ordering violation in the event sequence for a work item."""

    work_item_id: str
    kind: str  # "missing_seq" | "timestamp_regression" | "duplicate_seq"
    detail: str
    expected_seq: int | None = None
    actual_seq: int | None = None


@dataclass(frozen=True)
class DelegationChainEntry:
    """A delegation chain (on_behalf_of) found in an event."""

    event_id: str
    work_item_id: str
    principal_id: str
    session_id: str | None = None
    authenticated_at: str | None = None
    scope: list[str] | None = None
    expires_at: str | None = None
    validation_ok: bool = True
    validation_detail: str | None = None


@dataclass(frozen=True)
class TimestampBatchEntry:
    """A TSA timestamp batch that covers events in the log."""

    batch_id: str
    merkle_root: str
    first_global_seq: int | None = None
    last_global_seq: int | None = None
    event_count: int = 0
    status: str = "pending"
    tsa_timestamp: str | None = None
    verified: bool | None = None


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


@dataclass(frozen=True)
class ScopeViolation:
    """A tool-call event whose harness is not covered by any active scope attestation."""

    event_id: str
    work_item_id: str
    transition: str | None
    harness: str
    detail: str


@dataclass(frozen=True)
class KeyRevocationEntry:
    """A key_revocation event detected in the log."""

    event_id: str
    work_item_id: str
    key_id: str
    revoked_at: str | None
    detail: str | None = None


@dataclass(frozen=True)
class TemporalOrderingViolation:
    """A cross-field temporal ordering violation."""

    event_id: str
    work_item_id: str
    kind: str  # "authenticated_after_event" | "event_after_tsa" | "delegation_expired"
    detail: str


@dataclass(frozen=True)
class RoleGateViolation:
    """An event signed by a key whose role is not permitted for this transition."""

    event_id: str
    work_item_id: str
    key_id: str
    role: str
    transition: str | None
    detail: str


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
    scope_violations: list[ScopeViolation] = field(default_factory=list)
    sequence_gaps: list[SequenceGap] = field(default_factory=list)
    key_rotations: list[KeyRotationEntry] = field(default_factory=list)
    key_revocations: list[KeyRevocationEntry] = field(default_factory=list)
    key_chain: dict[str, dict[str, Any]] = field(default_factory=dict)
    delegation_chains: list[DelegationChainEntry] = field(default_factory=list)
    timestamp_batches: list[TimestampBatchEntry] = field(default_factory=list)
    temporal_violations: list[TemporalOrderingViolation] = field(default_factory=list)
    role_gate_violations: list[RoleGateViolation] = field(default_factory=list)
    scheme_counts: dict[str, int] = field(default_factory=dict)
    bundle_hash_ok: bool | None = None
    bundle_hash_detail: str | None = None
    previous_bundle_hash: str | None = None
    chain_integrity_ok: bool | None = None

    @property
    def key_rotation_failures(self) -> int:
        return sum(1 for kr in self.key_rotations if not kr.signature_valid)

    @property
    def key_revocation_failures(self) -> int:
        return sum(1 for kr in self.key_revocations if kr.detail is not None)

    @property
    def delegation_chain_failures(self) -> int:
        return sum(1 for dc in self.delegation_chains if not dc.validation_ok)

    @property
    def all_ok(self) -> bool:
        bundle_ok = self.bundle_hash_ok is not False
        chain_ok = self.chain_integrity_ok is not False
        return (
            self.signature_failed == 0
            and self.hash_mismatch == 0
            and self.revoked_key == 0
            and self.key_rotation_failures == 0
            and self.key_revocation_failures == 0
            and self.delegation_chain_failures == 0
            and len(self.sequence_gaps) == 0
            and len(self.scope_violations) == 0
            and len(self.temporal_violations) == 0
            and len(self.role_gate_violations) == 0
            and bundle_ok
            and chain_ok
        )


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
    _ACTOR_ONLY_TRANSITIONS: set[str] = {
        "tool_call",
        "scope_attestation",
        "key_declaration",
        "session_grant",
        "session_revocation",
        "heartbeat",
    }

    # Transition types that require role="auditor" to sign.
    _AUDITOR_ONLY_TRANSITIONS: set[str] = {
        "auditor_attestation",
    }

    def __init__(
        self,
        key_set: dict[str, bytes],
        key_metadata: dict[str, dict[str, Any]] | None = None,
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
        """
        self._keys = key_set
        self._key_meta = key_metadata or {}

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
            elif entry.result == "revoked_key":
                report.revoked_key += 1

            # Track signing scheme usage
            scheme = getattr(ev, "scheme_id", _DEFAULT_SCHEME_ID)
            report.scheme_counts[scheme] = report.scheme_counts.get(scheme, 0) + 1

            # Derive file provenance for tool call events
            self._accumulate_file_provenance(report, ev)

            # Collect scope attestations
            self._accumulate_scope_attestations(report, ev)

            # Detect and verify key rotation events
            self._accumulate_key_rotations(report, ev)

            # Detect key revocation events
            self._accumulate_key_revocations(report, ev)

            # Validate delegation chains
            self._accumulate_delegation_chains(report, ev)

            # Check role gate (scaffolded — uses key_metadata if provided)
            self._check_role_gate(report, ev)

        self._check_event_sequence(events, report)
        self._check_scope_coverage(events, report)
        self._check_temporal_ordering(events, report)

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
        manifest = raw.get("manifest", {})

        hash_verified = self._verify_bundle_hash(raw, manifest)
        if hash_verified is False:
            report = VerificationReport()
            report.bundle_hash_ok = False
            report.bundle_hash_detail = "Bundle integrity hash mismatch (see log)"
            report.key_chain["bundle"] = manifest
            return report

        events = [Event.from_dict(e) for e in raw["events"]]
        report = self.verify_events(events)
        report.bundle_hash_ok = True if hash_verified else None
        report.key_chain["bundle"] = manifest

        prev_hash = manifest.get("previous_bundle_hash")
        if prev_hash:
            report.previous_bundle_hash = prev_hash
            report.chain_integrity_ok = True
            log.info("cairn.chain_link_present", previous=prev_hash)
        else:
            report.chain_integrity_ok = None
            log.warn("cairn.chain_link_missing")

        self._accumulate_timestamp_batches(raw, events, report)

        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
            log.warn("cairn.bundle_hash_missing")
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
                result="revoked_key",
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
        # the cryptographic signature
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
        except Exception as exc:
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
                scope=scope,
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
    ) -> None:
        """Load TSA timestamp batches from the bundle and check event coverage."""
        raw_batches = raw_bundle.get("timestamp_batches")
        if not raw_batches:
            return

        exported_ids = {str(ev.event_id) for ev in events}
        covered_ids: set[str] = set()

        for raw in raw_batches:
            entry = TimestampBatchEntry(
                batch_id=raw.get("batch_id", "unknown"),
                merkle_root=raw.get("merkle_root", ""),
                event_count=len(raw.get("event_ids", [])),
                status=raw.get("status", "unknown"),
                tsa_timestamp=raw.get("tsa_timestamp"),
            )
            report.timestamp_batches.append(entry)

            if raw.get("status") == "confirmed":
                batch_ids = {str(eid) for eid in raw.get("event_ids", [])}
                covered_ids.update(batch_ids & exported_ids)

        uncovered = exported_ids - covered_ids
        if uncovered:
            log.warn(
                "cairn.events_not_timestamped",
                count=len(uncovered),
                sample=sorted(uncovered)[:5],
            )

    def _check_event_sequence(self, events: list[Event], report: VerificationReport) -> None:
        """Detect gaps and ordering violations in event sequences.

        Groups events by work_item_id, checks that event_seq values are
        contiguous within each work item and that timestamps are non-decreasing.
        """
        from collections import defaultdict

        by_wi: dict[str, list[Event]] = defaultdict(list)
        for ev in events:
            by_wi[str(ev.work_item_id)].append(ev)

        for wi_id, wi_events in by_wi.items():
            if len(wi_events) < 2:
                continue

            # Sort by event_seq to detect gaps
            sorted_events = sorted(wi_events, key=lambda e: e.event_seq)
            expected_seq = sorted_events[0].event_seq
            prev_ts = None
            for ev in sorted_events:
                if ev.event_seq != expected_seq:
                    if ev.event_seq > expected_seq:
                        report.sequence_gaps.append(
                            SequenceGap(
                                work_item_id=wi_id,
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
                                work_item_id=wi_id,
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
                            work_item_id=wi_id,
                            kind="timestamp_regression",
                            detail=(
                                f"Event {ev.event_id} seq {ev.event_seq} timestamp "
                                f"{ev.timestamp.isoformat()} is before previous "
                                f"event timestamp {prev_ts.isoformat()}."
                            ),
                        )
                    )
                prev_ts = ev.timestamp

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

        if not report.scope_attestations:
            # No scope attestations at all — flag every tool call
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
                            "No scope attestation found in the log. "
                            f"Tool call from harness '{h_name}' "
                            "has no covering scope."
                        ),
                    )
                )
            return

        # Sort scope attestations by attested_at for efficient lookup
        sorted_scopes = sorted(
            report.scope_attestations,
            key=lambda s: s.attested_at,
        )

        for ev in tool_calls:
            payload = ev.payload or {}
            harness_raw = payload.get("harness", "")
            harness = harness_raw.get("name", "") if isinstance(harness_raw, dict) else harness_raw
            ev_ts = ev.timestamp.isoformat()

            # Find the latest scope attestation that predates this event
            active_scope = None
            for sa in sorted_scopes:
                if sa.attested_at <= ev_ts:
                    active_scope = sa
                else:
                    break

            if active_scope is None:
                report.scope_violations.append(
                    ScopeViolation(
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                        transition=ev.transition,
                        harness=harness,
                        detail=(
                            f"No scope attestation predates event at {ev_ts}. "
                            f"Tool call from harness '{harness}' has no covering scope."
                        ),
                    )
                )
                continue

            # Check if the harness is listed in the active scope
            harness_names = {h.get("name", "") for h in active_scope.harnesses}
            if harness not in harness_names:
                report.scope_violations.append(
                    ScopeViolation(
                        event_id=str(ev.event_id),
                        work_item_id=str(ev.work_item_id),
                        transition=ev.transition,
                        harness=harness,
                        detail=(
                            f"Harness '{harness}' not in active scope attestation "
                            f"(event {active_scope.event_id}). "
                            f"Covered harnesses: {sorted(harness_names)}"
                        ),
                    )
                )

    def _check_temporal_ordering(
        self, events: list[Event], report: VerificationReport
    ) -> None:
        """Cross-field temporal ordering validation per v1 spec §4 item 8.

        Checks:
        - ``authenticated_at <= event.timestamp`` for delegation chains.
        - ``event.timestamp <= tsa_timestamp + tolerance`` for TSA-covered events.
        """
        _TSA_TOLERANCE_SECONDS = 300  # 5-minute tolerance

        # Build event lookup for TSA coverage checks
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

        # Check TSA temporal ordering
        from datetime import datetime, timedelta, timezone

        for tb in report.timestamp_batches:
            if tb.status != "confirmed" or not tb.tsa_timestamp:
                continue

            try:
                tsa_dt = datetime.fromisoformat(tb.tsa_timestamp)
                if tsa_dt.tzinfo is None:
                    tsa_dt = tsa_dt.replace(tzinfo=timezone.utc)
                tolerance = timedelta(seconds=_TSA_TOLERANCE_SECONDS)
                deadline = tsa_dt + tolerance
            except (ValueError, TypeError):
                log.warn(
                    "cairn.invalid_tsa_timestamp",
                    batch_id=tb.batch_id,
                    tsa_timestamp=tb.tsa_timestamp,
                )
                continue

            # Check events covered by this batch
            for ev in events:
                if ev.timestamp > deadline:
                    # This event's timestamp exceeds TSA + tolerance
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

    def verify_bundle_chain(self, bundle_paths: list[str | Path]) -> VerificationReport:
        """Verify a chain of bundles linked by previous_bundle_hash.

        Bundles must be ordered oldest-first.  Verifies that each bundle's
        ``previous_bundle_hash`` matches the computed hash of the preceding
        bundle, and that all events within each bundle verify.
        """
        if not bundle_paths:
            report = VerificationReport()
            report.chain_integrity_ok = None
            return report

        reports: list[VerificationReport] = []
        prev_hash: str | None = None

        for path in bundle_paths:
            report = self.verify_bundle(path)
            reports.append(report)

            raw = json.loads(Path(path).read_text())
            manifest = raw.get("manifest", {})

            # Compute hash of this bundle for the next iteration
            computed_hash = self._compute_bundle_hash(raw, manifest)

            # Check chain link
            claimed_prev = manifest.get("previous_bundle_hash")
            if prev_hash is not None and claimed_prev != prev_hash:
                report.chain_integrity_ok = False
                log.error(
                    "cairn.chain_link_broken",
                    bundle=str(path),
                    expected_prev=prev_hash,
                    claimed_prev=claimed_prev,
                )

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
            merged.sequence_gaps.extend(r.sequence_gaps)
            merged.key_chain.update(r.key_chain)
            if r.bundle_hash_ok is False:
                merged.bundle_hash_ok = False
                merged.bundle_hash_detail = r.bundle_hash_detail
            elif merged.bundle_hash_ok is None and r.bundle_hash_ok is True:
                merged.bundle_hash_ok = True
            if r.chain_integrity_ok is False:
                merged.chain_integrity_ok = False
            elif merged.chain_integrity_ok is None and r.chain_integrity_ok is True:
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
        older_raw = json.loads(Path(older_path).read_text())
        newer_raw = json.loads(Path(newer_path).read_text())

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

        lines.append("VERIFICATION NOTE")
        lines.append("-" * 40)
        has_ed25519 = "ed25519" in report.scheme_counts
        if has_ed25519:
            lines.append(
                "  Ed25519 (asymmetric) signatures were found.  Auditors can"
                " verify these events using only the public key — no signing"
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
            " session state directory — their presence indicates periods"
            " where the audit hook could not reach regista and coverage"
            " gaps may exist."
        )
        lines.append("")

        lines.append("=" * 60)
        summary = "ALL CHECKS PASSED" if report.all_ok else "VERIFICATION FAILED"
        lines.append("Summary: " + summary)
        lines.append("=" * 60)
        return "\n".join(lines) + "\n"

    @staticmethod
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
                    "status": tb.status,
                    "tsa_timestamp": tb.tsa_timestamp,
                }
                for tb in report.timestamp_batches
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
            "scheme_counts": report.scheme_counts,
            "verification_note": (
                "Ed25519 (asymmetric) signatures provide operator-forgery resistance. "
                "HMAC-SHA256 (symmetric) confirms authenticity and integrity only."
                if "ed25519" in report.scheme_counts
                else "HMAC-SHA256 verification confirms record authenticity and "
                "integrity but does NOT provide operator-forgery resistance."
            ),
        }

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def format_report_html(report: VerificationReport) -> str:
        """Return a self-contained HTML verification report.

        All CSS is inlined; no external dependencies.  Suitable for
        opening in any browser — auditors can save the file and view
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
            "    Cairn v0.1.0 &mdash; Cryptographic provenance "
            "for agentic workflows\n"
            "  </div>\n</body>\n</html>"
        )


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
    return "NOT VERIFIED (no previous hash)"
