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
    """A key rotation event detected in the log.

    ``signature_valid`` is ``True`` (verified under the predecessor key),
    ``False`` (proven not to verify — a forged rotation claim), or ``None``
    (the verdict could not be established from the presented material, e.g. a
    v6 event whose referents the verifier was not handed — an evidentiary
    gap, never reported as a forgery).
    """

    event_id: str
    work_item_id: str
    predecessor_key_id: str
    successor_key_id: str
    rotated_at: str | None
    signature_valid: bool | None
    detail: str | None = None


@dataclass(frozen=True)
class VerificationEntry:
    event_id: str
    work_item_id: str
    event_seq: int
    timestamp: str
    transition: str | None
    # "ok" | "signature_failed" | "hash_mismatch" | "revoked_key" |
    # "unknown_key" | "unverified" (cryptographically intact but the verdict is
    # not established from the presented material — e.g. a v6 event whose
    # key-binding referents are not in the bundle; an evidentiary gap, not a
    # proven forgery)
    result: str
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
    content_capture: bool = False
    content_encryption: str = "off"
    redaction_policy: str | None = None


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
    content_capture: bool = False
    content_encryption: str = "off"
    redaction_policy: str | None = None


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

    ``signature_valid`` is ``True`` (verified), ``False`` (the signature is
    present but does not check — a forgery), or ``None`` (cairn did not
    independently verify it).  ``None`` covers two HONEST and distinct cases
    that the verdict must not conflate with "verified":

    * a *delegated* receipt — a signature-less legacy receipt (no key the
      operator pinned, no signature to check), and
    * an *unverified* receipt — a signature is present but cairn could not
      check it (unknown/unsupported scheme, an Ed25519 witness whose public
      key / event envelope is unavailable, or an HMAC witness the operator did
      not pin — WI-043: absence of a pinned key means unverified, not
      delegated).

    ``unverified`` marks the second case (BC-016): a receipt carrying a
    signature cairn could not verify.  Such a receipt is excluded from witness
    coverage and surfaced in the report — it is never silently treated as
    confirmed.  See ``docs/witness-signature-verification.md``.
    """

    event_id: str
    witness_id: str
    confirmed_at: str | None = None
    has_signature: bool = False
    signature_valid: bool | None = None
    verification_detail: str | None = None
    unverified: bool = False


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
class AttestationGap:
    """A session that produced tool-call events but never sent a session
    attestation (Plan 008 WI-3.1).

    This is the auditor-visible "missing attestation" finding: the session
    ran agent actions that were recorded in the log, but no session-start
    attestation event covers it.  An auditor treats each gap as a
    completeness defect — the session's provenance is unscoped.
    """

    session_id: str
    tool_call_count: int
    first_tool_call: str | None = None
    last_tool_call: str | None = None
    harness: str | None = None
    event_ids: tuple[str, ...] = field(default_factory=tuple)
    detail: str = ""


@dataclass(frozen=True)
class SilenceGap:
    """A session that ran on the harness but produced no events at all
    (Plan 009 WI-4.1 — silence is a finding).

    Complementary to :class:`AttestationGap`: an attestation gap is a
    session *visible in the log* without a session attestation; a silence
    gap is a session the harness ran (evidenced by its local transcript)
    that never reached the log — the recorder was wired but recorded
    nothing, or was unhooked while config stayed in place.

    Populated only when the caller supplies harness session evidence
    (``cairn verify --harness-sessions``); an offline bundle alone cannot
    see what never entered it.
    """

    session_id: str
    last_activity: str | None = None
    transcript_path: str | None = None
    detail: str = ""


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


@dataclass(frozen=True)
class ContentCoverageGap:
    """A session that declared content capture but has digest-only events.

    Plan 010 WI-6.1: a session attested as ``content_capture=true`` but
    missing content fields on events that should have them (prompt/response
    events with only digests).  This is the content-layer analogue of
    Plan 009's "wired but not attesting."
    """

    session_id: str
    event_id: str
    transition: str
    detail: str


@dataclass
class VerificationReport:
    total_events: int = 0
    ok: int = 0
    #: Events whose signatures verified but whose full verdict could not be
    #: established from the presented material (v6 referent gaps offline).
    #: Counted separately from failures: not proven is not proven false.
    unverified_events: int = 0
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
    attestation_gaps: list[AttestationGap] = field(default_factory=list)
    silence_gaps: list[SilenceGap] = field(default_factory=list)
    assurance_entries: list[AssuranceEntry] = field(default_factory=list)
    content_coverage_gaps: list[ContentCoverageGap] = field(default_factory=list)
    scheme_counts: dict[str, int] = field(default_factory=dict)
    bundle_hash_ok: bool | None = None
    bundle_hash_detail: str | None = None
    previous_bundle_hash: str | None = None
    chain_integrity_ok: bool | None = None
    # Values emitted by the canonical verifier and preserved by proof-runner
    # parsing.  They are separate from the locally reconstructed counters:
    # a lossy consumer must never turn a canonical exit-1 into a pass.
    canonical_all_ok: bool | None = None
    canonical_aggregate_verdict: str | None = None

    @property
    def key_rotation_failures(self) -> int:
        return sum(1 for kr in self.key_rotations if kr.signature_valid is False)

    @property
    def unverified_key_rotations(self) -> int:
        """Rotations whose signature could not be established from this material.

        Distinct from :attr:`key_rotation_failures` (a proven forgery): an
        unverified rotation is an evidentiary gap, reported by name.
        """
        return sum(1 for kr in self.key_rotations if kr.signature_valid is None)

    @property
    def key_revocation_failures(self) -> int:
        return sum(1 for kr in self.key_revocations if kr.detail is not None)

    @property
    def delegation_chain_failures(self) -> int:
        return sum(1 for dc in self.delegation_chains if not dc.validation_ok)

    @property
    def witness_signature_failures(self) -> int:
        return sum(1 for r in self.witness_receipts if r.signature_valid is False)

    @property
    def unverified_witness_receipts(self) -> int:
        """Receipts carrying a signature cairn could not verify (BC-016).

        Distinct from :attr:`witness_signature_failures` (a proven forgery):
        these are *not proven* — the witness's corroboration is absent, so the
        verdict must not claim it.
        """
        return sum(1 for r in self.witness_receipts if r.unverified)

    @property
    def all_ok(self) -> bool:
        # An unverified event fails the aggregate. This is deliberately
        # fail-closed: "not proven" is not "ok", and an audit gate that
        # reports success while part of the log was never established would
        # be the exact smoothing this verdict exists to prevent. The report
        # names every unverified event and why, so the nonzero exit is a
        # decision an operator can act on, not a mystery.
        # A canonical failure is authoritative even when this consumer did
        # not reconstruct the finding family that caused it.  A canonical
        # ``True`` remains subject to locally reconstructed checks so an
        # inconsistent or older report cannot hide a finding this consumer
        # does understand.
        if self.canonical_all_ok is False:
            return False

        bundle_ok = self.bundle_hash_ok is not False
        chain_ok = self.chain_integrity_ok is not False
        return (
            self.unverified_events == 0
            # An unestablished rotation is not a proven forgery, but the
            # aggregate gate does not pass on it either: the rotation claim
            # was never verified, and the old boolean path counted exactly
            # this case as a failure. Same strictness, honest classification.
            and self.unverified_key_rotations == 0
            and self.signature_failed == 0
            and self.hash_mismatch == 0
            and self.revoked_key == 0
            and self.key_rotation_failures == 0
            and self.key_revocation_failures == 0
            and self.delegation_chain_failures == 0
            and self.witness_signature_failures == 0
            and self.unverified_witness_receipts == 0
            and len(self.witness_coverage_violations) == 0
            and len(self.sequence_gaps) == 0
            and len(self.scope_violations) == 0
            and len(self.temporal_violations) == 0
            and len(self.role_gate_violations) == 0
            and len(self.chain_contiguity_violations) == 0
            and len(self.principal_binding_violations) == 0
            and len(self.attestation_gaps) == 0
            and len(self.silence_gaps) == 0
            and len(self.content_coverage_gaps) == 0
            and bundle_ok
            and chain_ok
        )

    @property
    def aggregate_verdict(self) -> str:
        """The explicit aggregate verdict used by the proof gate."""

        if self.canonical_aggregate_verdict is not None:
            return self.canonical_aggregate_verdict
        return "pass" if self.all_ok else "fail"
