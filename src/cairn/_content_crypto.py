"""Content encryption for session-content capture (Plan 010 WI-3.1/WI-3.2).

Reuses regista Plan 030's ``encrypt_fields``/``decrypt_fields``/
``verify_encrypted_integrity`` primitive — cairn does not roll its own
crypto.  The content-encryption key resolves via ``regista._secrets.resolve``
(same path as the signing key, Plan 029).

Encryption is **on by default**.  A deployment may opt out via
``CAIRN_CONTENT_ENCRYPTION=off``; the opt-out is loud (doctor WARNING,
scope attestation records the stance, verifier report surfaces it).

WI-037 — where the resolve belongs
----------------------------------
``is_content_encryption_active`` used to answer "is a key ref *set*?" and call
that active.  Presence is not resolution: cairn could record
``content_encryption="on"`` in a session attestation and then be unable to
fetch the key at the moment it needed it, which is plaintext capture with the
operator told the opposite — the worst shape this bug has.

The fix does **not** put a secret resolve in front of every hook invocation.
Cairn runs as a short-lived process per event (``cairn-claude-hook`` →
``cairn-bridge``), so "resolve once at startup" would mean once per *event*,
including the pre/post tool events that carry no content at all.  Instead the
resolve is placed where the CLAIM is made and nowhere else:

* :func:`content_encryption_status` resolves the configured ref and is called
  when cairn records what it is doing — the scope/session attestation stance,
  once per session — and by ``cairn doctor``.  Positive verdicts are memoised
  for the life of the process; negative ones are re-probed, so a transient
  outage self-heals and a stale verdict can never read greener than reality.
* :func:`encrypt_content_fields` adds no probe at all.  The encryption itself
  resolves the key, so success *is* the proof; failure raises
  :class:`ContentEncryptionUnavailableError` rather than handing back plaintext.

The two cannot disagree with the doctor because ``cairn doctor`` renders its
content-encryption check from :func:`content_encryption_status_for`, this
module's verdict, over settings read by one resolver
(:func:`cairn._config.resolve_content_settings`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._config import ContentSettings, resolve_content_settings
from ._secretrefs import verify_secret_ref
from .schema import (
    CONTENT_ENCRYPTION_EXTERNAL,
    CONTENT_ENCRYPTION_OFF,
    CONTENT_ENCRYPTION_ON,
)

CONTENT_KEY_REF_ENV = "CAIRN_CONTENT_KEY_REF"
CONTENT_KEY_PATH_ENV = "CAIRN_CONTENT_KEY_PATH"
CONTENT_ENCRYPTION_ENV = "CAIRN_CONTENT_ENCRYPTION"

CONTENT_FIELD_NAMES = frozenset({
    "message_content",
    "transcript_content",
    "compact_summary_content",
})

#: Payload key naming why an event that *should* carry content does not.  It is
#: signed with the event, so the reason survives in the store even when the
#: local degradation log does not (WI-037).
CONTENT_ENCRYPTION_ERROR_FIELD = "content_encryption_error"

_DEFAULT_KEY_ID = "cairn-content-001"


class ContentEncryptionUnavailableError(RuntimeError):
    """Content encryption was configured and its key could not be used.

    Raised instead of returning the payload unencrypted: a caller that asked
    for encryption must never receive plaintext back and believe it succeeded.
    Callers that capture provenance translate this into a digest-only event
    carrying :data:`CONTENT_ENCRYPTION_ERROR_FIELD`; callers that do not, fail.
    """

    def __init__(self, key_ref: str, reason: str) -> None:
        super().__init__(
            f"content encryption is ON but its key {key_ref!r} {reason}; "
            "content was withheld rather than stored in plaintext"
        )
        self.key_ref = key_ref
        self.reason = reason


@dataclass(frozen=True)
class ContentEncryptionStatus:
    """What cairn will actually do with session content, resolved.

    ``stance`` is the operator's intent; ``usable`` is the verdict after the
    configured key was really resolved.  ``recorded_stance`` is what goes into
    an attestation — it is never ``"on"`` unless encryption provably works, so
    the record cannot claim protection the runtime did not apply.
    """

    stance: str
    key_ref: str | None
    usable: bool
    detail: str

    @property
    def configured(self) -> bool:
        """Whether the operator named a content key at all."""
        return self.key_ref is not None

    @property
    def recorded_stance(self) -> str:
        if self.usable:
            return CONTENT_ENCRYPTION_ON
        if self.stance == CONTENT_ENCRYPTION_EXTERNAL:
            return CONTENT_ENCRYPTION_EXTERNAL
        # Intent was "on" but cairn is not encrypting: recording "on" here is
        # exactly the lie WI-037 exists to remove.  "off" is what the store,
        # the portal banner and the verifier report will all say, and it is
        # true — whether the content lands in plaintext (no key configured) or
        # is withheld (key configured, unusable) is carried per event.
        return CONTENT_ENCRYPTION_OFF


def resolve_content_encryption_stance() -> str:
    """The operator's configured content-encryption *intent*.

    Returns ``"on"``, ``"off"``, or ``"external"``.  This reads configuration
    and nothing else: it says what was asked for, never whether it works.  Use
    :func:`content_encryption_status` (or
    :func:`recorded_content_encryption_stance`) for anything cairn publishes.

    - ``on`` (default)
    - ``off`` when ``CAIRN_CONTENT_ENCRYPTION=off``
    - ``external`` when ``CAIRN_CONTENT_ENCRYPTION=external`` (lower-layer
      encryption such as TDE / encrypted volume, documented by the operator)
    """
    return resolve_content_settings().encryption


def resolve_content_key_ref() -> str | None:
    """The content-encryption key reference, as configured.

    ``CAIRN_CONTENT_KEY_REF`` then ``CAIRN_CONTENT_KEY_PATH`` (file-based),
    from the process environment or ``suite.env`` — the same precedence, and
    the same source, that ``cairn doctor`` reads.  Returns a secret-ref string
    suitable for ``regista._secrets.resolve``, or ``None`` if no key is
    configured.  Being configured is not being resolvable.
    """
    return resolve_content_settings().configured_key_ref


def content_encryption_status_for(settings: ContentSettings) -> ContentEncryptionStatus:
    """Resolve *settings* into a verdict. Pure with respect to caching.

    This is the single judgement shared by the runtime and ``cairn doctor``.
    It resolves the configured ref and discards the value: nothing here returns,
    logs or prints secret material.
    """
    stance = settings.encryption
    key_ref = settings.configured_key_ref
    if stance == CONTENT_ENCRYPTION_OFF:
        return ContentEncryptionStatus(
            stance=stance,
            key_ref=key_ref,
            usable=False,
            detail=(
                "content encryption is OFF — session content is stored in "
                "plaintext, and the log itself is a sensitive artifact"
            ),
        )
    if stance == CONTENT_ENCRYPTION_EXTERNAL:
        return ContentEncryptionStatus(
            stance=stance,
            key_ref=key_ref,
            usable=False,
            detail="content encryption delegated to a lower layer (external)",
        )
    if key_ref is None:
        return ContentEncryptionStatus(
            stance=stance,
            key_ref=None,
            usable=False,
            detail=(
                f"no content key configured ({CONTENT_KEY_REF_ENV} / "
                f"{CONTENT_KEY_PATH_ENV}); content capture stores plaintext "
                "until a key is set"
            ),
        )
    ok, detail = verify_secret_ref(key_ref)
    return ContentEncryptionStatus(
        stance=stance, key_ref=key_ref, usable=ok, detail=detail
    )


#: Memoised *positive* verdicts, keyed by the settings that produced them.
#:
#: Only positives: a key that resolved will keep resolving, and re-probing it
#: per event would put a Vault round trip on the capture path.  A negative is
#: re-probed every time, so a key that becomes available is picked up and a
#: cached verdict can never read greener than reality.
_STATUS_CACHE: dict[tuple[str, str | None], ContentEncryptionStatus] = {}


def content_encryption_status() -> ContentEncryptionStatus:
    """The resolved verdict for this process's configuration."""
    settings = resolve_content_settings()
    cache_key = (settings.encryption, settings.configured_key_ref)
    cached = _STATUS_CACHE.get(cache_key)
    if cached is not None:
        return cached
    status = content_encryption_status_for(settings)
    if status.usable:
        _STATUS_CACHE[cache_key] = status
    return status


def reset_content_encryption_status_cache() -> None:
    """Forget memoised verdicts (tests, and long-lived embedders on rotation)."""
    _STATUS_CACHE.clear()


def is_content_encryption_active() -> bool:
    """True when content encryption is on and its key really resolves.

    Before WI-037 this returned True for a key ref that was merely *set*.
    """
    return content_encryption_status().usable


def recorded_content_encryption_stance() -> str:
    """The stance to record in an attestation: verified, not merely intended."""
    return content_encryption_status().recorded_stance


def encrypt_content_fields(
    payload: dict[str, Any],
    *,
    key_ref: str | None = None,
    key_id: str = _DEFAULT_KEY_ID,
) -> dict[str, Any]:
    """Encrypt content fields in a payload using regista Plan 030's primitive.

    Replaces ``message_content`` / ``transcript_content`` with encrypted
    blobs: ``{encrypted: true, alg, key_id, nonce, ciphertext, digest}``.
    The digest (SHA-256 of plaintext) is stored *outside* the ciphertext
    so an auditor verifies integrity without the key.

    When no key is configured at all, the payload is returned unchanged — the
    content is stored in plaintext, and every place cairn reports its stance
    says ``off`` (see :meth:`ContentEncryptionStatus.recorded_stance`), so the
    plaintext is recorded rather than concealed.

    When a key IS configured but cannot be used, this raises
    :class:`ContentEncryptionUnavailableError`.  It never falls back to plaintext:
    an explicit instruction that cannot be honoured must fail, not degrade
    quietly (WI-037).  No extra secret resolve is performed to decide this —
    the encryption below resolves the key, so its success is the proof.
    """
    effective_ref = key_ref or resolve_content_key_ref()
    if effective_ref is None:
        return payload

    field_paths = [f for f in CONTENT_FIELD_NAMES if f in payload]
    if not field_paths:
        return payload

    from regista._encryption import encrypt_fields

    try:
        result: dict[str, Any] = encrypt_fields(
            payload,
            field_paths=field_paths,
            key_ref=effective_ref,
            key_id=key_id,
        )
    except Exception as exc:
        raise ContentEncryptionUnavailableError(effective_ref, f"could not be used: {exc}") from exc
    return result


def withhold_content_fields(payload: dict[str, Any], reason: str) -> dict[str, Any]:
    """Drop content fields from *payload* and record why, in the payload.

    The digests stay: integrity and the chain are unaffected, only the
    plaintext is refused.  The reason is signed with the event, so an auditor
    reading the store learns that content was withheld because encryption was
    unavailable — as distinct from a session that never captured content.
    """
    result = dict(payload)
    for field_name in CONTENT_FIELD_NAMES:
        result.pop(field_name, None)
    result[CONTENT_ENCRYPTION_ERROR_FIELD] = reason
    return result


def decrypt_content_fields(
    payload: dict[str, Any],
    *,
    key_ref: str | None = None,
) -> dict[str, Any]:
    """Decrypt content fields in a payload using regista Plan 030's primitive.

    When no key is available, encrypted fields are left in place (the
    caller sees the encrypted blob, not the plaintext).  This is the
    auditor-without-key posture: integrity is authenticated by the
    signature, but plaintext is not verifiable.
    """
    effective_ref = key_ref or resolve_content_key_ref()
    if effective_ref is None:
        return payload

    from regista._encryption import decrypt_fields

    result: dict[str, Any] = decrypt_fields(payload, key_source=effective_ref)
    return result


def verify_content_integrity(
    payload: dict[str, Any],
    *,
    key_ref: str | None = None,
) -> list[dict[str, Any]]:
    """Verify encrypted content field integrity using regista Plan 030.

    Returns a list of per-field verification result dicts.  Without a key,
    fields are reported as ``"not_decrypted"`` (warning, not failure).
    """
    effective_ref = key_ref or resolve_content_key_ref()

    from regista._encryption import verify_encrypted_integrity

    results = verify_encrypted_integrity(
        payload,
        key_source=effective_ref,
    )
    return [r.to_dict() for r in results]
