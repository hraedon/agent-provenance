"""Dataclass definitions for the Cairn verification report.

These types are used by both :mod:`cairn.verifier` (core verification
logic) and :mod:`cairn.verifier_report` (report formatting).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "AssuranceEntry",
    "AssuranceLevel",
    "BundleDiff",
    "BundleDiffEntry",
    "ChainContiguityViolation",
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
    "TemporalOrderingViolation",
    "TimestampBatchEntry",
    "VerificationEntry",
    "VerificationReport",
    "WitnessCoverageViolation",
    "WitnessReceiptEntry",
    "WitnessRegistrationEntry",
]


class AssuranceLevel:
    """Closed set of review assurance levels (regista Plan 027 WI-1.2).

    Computed deterministically from the item's signed events — a view over
    the history, stored nowhere mutable, so it can never disagree with the
    record.  An auditor reads the level; they do not infer it.

    In the interim (HMAC-era, pre-Plan-026) posture, lineage is *asserted*
    by the actor_metadata, not cryptographically bound.  When per-actor
    Ed25519 lands (Plan 026), the verifier checks the actor↔signer binding
    and flips ``lineage_source`` from ``"asserted"`` to ``"verified"``
    automatically — no schema migration.
    """

    NONE = "none"
    SELF_REVIEWED = "self_reviewed"
    INDEPENDENTLY_REVIEWED = "independently_reviewed"
    HUMAN_ACCEPTED = "human_accepted"
    INDEPENDENT_AND_ACCEPTED = "independently_and_accepted"

    ALL: tuple[str, ...] = (
        NONE,
        SELF_REVIEWED,
        INDEPENDENTLY_REVIEWED,
        HUMAN_ACCEPTED,
        INDEPENDENT_AND_ACCEPTED,
    )


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
    """Result of comparing two bundles (older -> newer)."""

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
    scope: tuple[str, ...] | None = None
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
    event_ids: tuple[str, ...] = field(default_factory=tuple)
    status: str = "pending"
    tsa_timestamp: str | None = None
    verified: bool | None = None
    verification_detail: str | None = None


@dataclass(frozen=True)
class ScopeAttestationEntry:
    event_id: str
    work_item_id: str
    version: str
    principal_id: str
    attested_at: str
    harnesses: tuple[dict[str, Any], ...]
    scope_statement: str
    harness_config_digests: dict[str, str] | None = None


@dataclass(frozen=True)
class SessionAttestationEntry:
    event_id: str
    entity_id: str
    version: str
    principal_id: str
    session_id: str
    attested_at: str
    harnesses: tuple[dict[str, Any], ...]
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
class WitnessRegistrationEntry:
    """A witness registration from the bundle."""

    witness_id: str
    url: str
    status: str = "active"
    mode: str = "witness"
    public_key: str | None = None
    key_scheme: str | None = None


@dataclass(frozen=True)
class WitnessReceiptEntry:
    """A confirmed witness receipt from the bundle.

    ``signature_valid`` is ``None`` when no witness public key was available
    to verify the signature (backward-compatible mode — a warning is emitted).
    When a key is available, it is ``True`` (verified) or ``False`` (failed).
    """

    event_id: str
    witness_id: str
    confirmed_at: str | None = None
    has_signature: bool = False
    signature_valid: bool | None = None
    verification_detail: str | None = None


@dataclass(frozen=True)
class WitnessCoverageViolation:
    """An event that lacks confirmed receipts from all expected witnesses."""

    event_id: str
    work_item_id: str
    missing_witnesses: tuple[str, ...]
    detail: str


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


@dataclass(frozen=True)
class ChainContiguityViolation:
    """A break in the event-level hash chain (BC-010).

    Either a ``global_seq`` gap (cross-work-item total order is not
    contiguous), or a ``prev_event_hash`` link that does not match the
    canonical hash of the preceding event in the work item, or a v3-chained
    event that was presented in a downgraded (v2) envelope.
    """

    kind: str  # "global_seq_gap" | "prev_hash_mismatch" | "missing_predecessor" | "v2_downgrade"
    detail: str
    event_id: str | None = None
    work_item_id: str | None = None
    expected: str | None = None
    actual: str | None = None


@dataclass(frozen=True)
class PrincipalBindingViolation:
    """A tool-call event that is not bound to an authenticated principal (BC-013).

    Either no ``on_behalf_of.principal_id`` is present, or the principal does
    not match the principal declared by the active scope attestation.
    """

    kind: str  # "missing_principal" | "principal_mismatch"
    event_id: str
    work_item_id: str
    transition: str | None
    detail: str
    principal_id: str | None = None
    expected_principal_id: str | None = None


@dataclass(frozen=True)
class AssuranceEntry:
    """Review assurance level for a work item (regista Plan 027 WI-1.2).

    The assurance level is a pure function of the item's signed events,
    computed by the verifier — never stored mutably.  This is the honest
    answer to "one model weakens review": we cannot manufacture a second
    lineage, but we refuse to let the record pretend there was one.
    """

    work_item_id: str
    assurance_level: str
    author_lineages: tuple[str, ...]
    reviewer_lineage: str | None
    same_lineage: bool | None
    has_adversarial_pass: bool
    has_human_accept: bool
    lineage_source: str
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
    session_attestations: list[SessionAttestationEntry] = field(default_factory=list)
    scope_violations: list[ScopeViolation] = field(default_factory=list)
    sequence_gaps: list[SequenceGap] = field(default_factory=list)
    key_rotations: list[KeyRotationEntry] = field(default_factory=list)
    key_revocations: list[KeyRevocationEntry] = field(default_factory=list)
    key_chain: dict[str, dict[str, Any]] = field(default_factory=dict)
    delegation_chains: list[DelegationChainEntry] = field(default_factory=list)
    timestamp_batches: list[TimestampBatchEntry] = field(default_factory=list)
    witness_registrations: list[WitnessRegistrationEntry] = field(default_factory=list)
    witness_receipts: list[WitnessReceiptEntry] = field(default_factory=list)
    witness_coverage_violations: list[WitnessCoverageViolation] = field(default_factory=list)
    temporal_violations: list[TemporalOrderingViolation] = field(default_factory=list)
    role_gate_violations: list[RoleGateViolation] = field(default_factory=list)
    chain_contiguity_violations: list[ChainContiguityViolation] = field(default_factory=list)
    principal_binding_violations: list[PrincipalBindingViolation] = field(default_factory=list)
    assurance_entries: list[AssuranceEntry] = field(default_factory=list)
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
    def tsa_signature_failures(self) -> int:
        return sum(1 for tb in self.timestamp_batches if tb.verified is False)

    @property
    def witness_signature_failures(self) -> int:
        return sum(1 for r in self.witness_receipts if r.signature_valid is False)

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
            and self.tsa_signature_failures == 0
            and self.witness_signature_failures == 0
            and len(self.witness_coverage_violations) == 0
            and len(self.sequence_gaps) == 0
            and len(self.scope_violations) == 0
            and len(self.temporal_violations) == 0
            and len(self.role_gate_violations) == 0
            and len(self.chain_contiguity_violations) == 0
            and len(self.principal_binding_violations) == 0
            and bundle_ok
            and chain_ok
        )
