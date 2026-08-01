# Witness signature verification (BC-016)

> **SECURITY.** This note describes a cryptographic trust boundary. A reviewer
> changing witness handling must preserve the invariant in §5: *a witness
> receipt that cairn cannot verify is never reported as confirmed.*

## 1. What a witness receipt is

A *witness* is an independent party that co-signs events as they are appended,
so that later deletion or rewriting of the log is detectable by someone other
than the store operator. When a witness accepts an event it returns a *receipt*
carrying a `witness_signature` over the event's canonical envelope. The bundle
export collects:

- `witness_registrations` — who the witnesses are, their `key_scheme`
  (`ed25519` or `hmac-sha256`) and, when published, their `public_key`.
- `witness_receipts` — per `(event_id, witness_id)`, a `confirmed_at` and the
  `witness_signature` (hex).

## 2. Threat model

| Asset | The cairn event log and its witness receipts. |
|-------|-----------------------------------------------|
| **Attacker** | A same-host or store-side adversary who can edit the bundle or the log: forge a receipt, replace a `witness_signature`, drop the witness public key, **substitute the witness public key carried in the bundle and re-sign**, or relabel a key scheme. |
| **Goal** | Make a forged or unverifiable receipt read as a *confirmed* witness, so a tampered log appears independently corroborated. |
| **Out of scope** | Compromise of the witness's own signing key; compromise of the store's event-signing key (that is the event-signature check, not the witness check). |

The historical defect (BC-016): *any non-null `witness_signature` counted as a
valid confirmed receipt.* The signature was never checked, so a forged receipt
was indistinguishable from a real one.

The key-substitution threat (WI-043): a public key carried *inside* the bundle
is itself attacker-controlled (the same adversary who edits the bundle can
replace it). If cairn verified a receipt against the bundle-carried key, the
attacker simply substitutes their own key and re-signs — corroboration from a
witness of the attacker's choice. cairn therefore treats bundle-carried keys as
**display-only**: they appear for attribution, but a receipt is never VERIFIED
against one, never counts toward coverage, and never makes the verdict pass.

## 3. What is signed, by whom

- **The witness** signs the event's `canonical_envelope` bytes with its own key.
  For an `ed25519` witness this is an Ed25519 signature
  (`Ed25519Scheme().verify(envelope, signature, sha256(envelope), public_key)`).
  The signature binds the receipt to the exact event bytes: editing the event
  invalidates every witness signature over it.
- **An HMAC witness** (`key_scheme: hmac-sha256`) shares a symmetric key with
  the store. cairn holds no HMAC key (holding it would put a shared secret in
  the verifier), so it cannot independently re-check the MAC. Per WI-043,
  *absence of a pinned key means unverified, not delegated*: cairn does not
  claim regista's delivery layer vouches for a witness the operator never
  pinned, so a signature-bearing HMAC receipt whose witness is not a trust root
  is reported **unverified** and excluded from coverage.
- **RFC 3161 timestamp tokens** are a *separate* corroboration path (BC-229 /
  `_verify_tsa_tokens`): a TSA signs a Merkle root over the bundle's events,
  checked against a `--tsa-cert` trust anchor. A timestamp token is not a
  witness receipt; where both exist they reinforce each other, but a missing or
  failed TSA token does not change a witness receipt's verification state.

## 4. Verification steps (per receipt)

**Trust roots** are operator-pinned keys (the verifier's `witness_keys`) and
regista-enrolled/anchored keys — never a key carried inside the bundle, which
is display-only (WI-043).

1. Resolve the witness's `key_scheme` from its registration.
2. **`ed25519`**, or any witness that is an operator-pinned trust root — cairn
   forces Ed25519 verification against the pinned key regardless of the scheme
   the bundle claims, so relabeling an Ed25519 witness as `hmac-sha256` cannot
   skip verification.
   - pinned key + valid signature → `signature_valid = True`.
   - pinned key + bad signature → `signature_valid = False` (failed).
   - signature absent on a pinned witness → **failed** (a pinned witness must sign).
   - envelope absent from the bundle → **unverified** (nothing to check against).
   - not pinned, scheme `ed25519`, but only a bundle-carried key → **unverified**
     (the bundle key is display-only, not a trust root).
3. **`hmac-sha256`** (not pinned) — cairn cannot re-check the MAC, and an
   unpinned witness is not a trust root, so a signature-bearing receipt is
   **unverified** and excluded from coverage.
4. **unknown / unsupported scheme** — cairn has no rule to verify it.
   - signature present → **unverified** (this is the BC-016 hole closed here:
     previously this counted as confirmed).
   - no signature → `None`, a legacy receipt with nothing to check.

## 5. Failure modes and the verdict

The honest-state invariant: **a receipt that carries a signature cairn could
not verify is `unverified`, is excluded from witness coverage, and is surfaced
in the report — it is never silently treated as confirmed.**

| State | `signature_valid` | `unverified` | Counts as coverage? | Effect on verdict |
|-------|-------------------|--------------|---------------------|-------------------|
| verified | `True` | no | yes | none |
| failed / forged | `False` | no | **no** | `all_ok` false (signature failure) |
| **unverified** | `None` | **yes** | **no** | reported as unverified; coverage missing |
| no signature (legacy) | `None` | no | per scheme | labelled |

`unverified` covers **every** path where a signature is present but not
verified: an Ed25519 witness with no pinned key (bundle key is display-only),
an Ed25519 witness whose envelope is unavailable, an unpinned HMAC receipt, and
any unknown/unsupported scheme. A failed signature is positive evidence of
forgery (the verdict goes red), whereas `unverified` means "cairn could not
establish this receipt" — the witness's corroboration is simply *not proven*,
and the report says so plainly rather than claiming it.

## 6. What a human reviewer must check

- A new code path that sets `signature_valid = None` for a signed receipt must
  also set `unverified`.
- `_check_witness_coverage` excludes both `signature_valid is False` and
  `unverified` receipts. Do not let an unverifiable receipt back into coverage.
- Trust roots are operator-pinned keys (`witness_keys`) and regista-enrolled /
  anchored keys **only**. A `public_key` carried in the bundle registration is
  display-only — never used to verify, never counts as coverage, never makes the
  verdict pass (WI-043). A registration that *omits* its public key, or carries
  one cairn must not trust, leaves its receipts unverified — that is correct,
  fail-closed behaviour, not a bug.
- Verify the key-substitution resistance holds: a receipt must never be
  VERIFIED against a bundle-carried key. If a change makes a bundle key feed
  `_verify_witness_signatures`, it reopens the BC-016 / WI-043 hole.
