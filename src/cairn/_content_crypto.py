"""Content encryption for session-content capture (Plan 010 WI-3.1/WI-3.2).

Reuses regista Plan 030's ``encrypt_fields``/``decrypt_fields``/
``verify_encrypted_integrity`` primitive — cairn does not roll its own
crypto.  The content-encryption key resolves via ``regista._secrets.resolve``
(same path as the signing key, Plan 029).

Encryption is **on by default**.  A deployment may opt out via
``CAIRN_CONTENT_ENCRYPTION=off``; the opt-out is loud (doctor WARNING,
scope attestation records the stance, verifier report surfaces it).
"""

from __future__ import annotations

import os
from typing import Any

from .schema import (
    CONTENT_ENCRYPTION_EXTERNAL,
    CONTENT_ENCRYPTION_OFF,
    CONTENT_ENCRYPTION_ON,
)

CONTENT_KEY_REF_ENV = "CAIRN_CONTENT_KEY_REF"
CONTENT_KEY_PATH_ENV = "CAIRN_CONTENT_KEY_PATH"
CONTENT_ENCRYPTION_ENV = "CAIRN_CONTENT_ENCRYPTION"

_CONTENT_FIELD_NAMES = frozenset({
    "message_content",
    "transcript_content",
})

_DEFAULT_KEY_ID = "cairn-content-001"


def resolve_content_encryption_stance() -> str:
    """Determine the content-encryption stance from the environment.

    Returns ``"on"``, ``"off"``, or ``"external"``.

    - ``on`` (default when content capture is active and a key is available)
    - ``off`` when ``CAIRN_CONTENT_ENCRYPTION=off``
    - ``external`` when ``CAIRN_CONTENT_ENCRYPTION=external`` (lower-layer
      encryption such as TDE / encrypted volume, documented by the operator)
    """
    val = os.environ.get(CONTENT_ENCRYPTION_ENV, "").strip().lower()
    if val == "off":
        return CONTENT_ENCRYPTION_OFF
    if val == "external":
        return CONTENT_ENCRYPTION_EXTERNAL
    return CONTENT_ENCRYPTION_ON


def resolve_content_key_ref() -> str | None:
    """Resolve the content-encryption key reference.

    Checks ``CAIRN_CONTENT_KEY_REF`` then ``CAIRN_CONTENT_KEY_PATH``
    (file-based).  Returns a secret-ref string suitable for
    ``regista._secrets.resolve``, or ``None`` if no key is configured.
    """
    ref = os.environ.get(CONTENT_KEY_REF_ENV)
    if ref:
        return ref
    path = os.environ.get(CONTENT_KEY_PATH_ENV)
    if path:
        return f"file:{path}"
    return None


def is_content_encryption_active() -> bool:
    """True when content encryption is on and a key is resolvable."""
    stance = resolve_content_encryption_stance()
    if stance != CONTENT_ENCRYPTION_ON:
        return False
    return resolve_content_key_ref() is not None


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

    When no key is available (encryption off), the payload is returned
    unchanged — the content is stored in plaintext and the scope
    attestation records ``content_encryption="off"``.
    """
    effective_ref = key_ref or resolve_content_key_ref()
    if effective_ref is None:
        return payload

    field_paths = [f for f in _CONTENT_FIELD_NAMES if f in payload]
    if not field_paths:
        return payload

    from regista._encryption import encrypt_fields

    result: dict[str, Any] = encrypt_fields(
        payload,
        field_paths=field_paths,
        key_ref=effective_ref,
        key_id=key_id,
    )
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
