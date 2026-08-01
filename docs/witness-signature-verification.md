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
| **Attacker** | A same-host or store-side adversary who can edit the bundle or the log: forge a receipt, replace a `witness_signature`, drop the witness public key, or relabel a key scheme. |
| **Goal** | Make a forged or unverifiable receipt read as a *confirmed* witness, so a tampered log appears independently corroborated. |
| **Out of scope** | Compromise of the witness's own signing key; compromise of the store's event-signing key (that is the event-signature check, not the witness check). |

The historical defect (BC-016): *any non-null `witness_signature` counted as a
valid confirmed receipt.* The signature was never checked, so a forged receipt
was indistinguishable from a real one.

## 3. What is signed, by whom

- **The witness** signs the event's `canonical_envelope` bytes with its own key.
  For an `ed25519` witness this is an Ed25519 signature
  (`Ed25519Scheme().verify(envelope, signature, sha256(envelope), public_key)`).
  The signature binds the receipt to the exact event bytes: editing the event
  invalidates every witness signature over it.
- **An HMAC witness** (`key_scheme: hmac-sha256`) shares a symmetric key with
  the store; the receipt is authenticated *by regista's delivery layer* at the
  moment it is obtained. cairn does not hold the HMAC key (holding it would put
  a shared secret in the verifier), so it cannot re-check the MAC and instead
  relies on regista having verified it. This is a **documented trust delegation**,
  reported as such — not an independent cryptographic check by cairn.
- **RFC 3161 timestamp tokens** are a *separate* corroboration path (BC-229 /
  `_verify_tsa_tokens`): a TSA signs a Merkle root over the bundle's events,
  checked against a `--tsa-cert` trust anchor. A timestamp token is not a
  witness receipt; where both exist they reinforce each other, but a missing or
  failed TSA token does not change a witness receipt's verification state.

## 4. Verification steps (per receipt)

1. Resolve the witness's `key_scheme` from its registration.
2. **`ed25519`** — obtain the public key (constructor `witness_keys`, else the
   registration's `public_key`). Verify the signature over the event envelope.
   - key + signature present → `signature_valid = True` / `False`.
   - key absent → **unverified** (cannot check).
   - signature absent → **failed** (an Ed25519 witness must sign).
   - envelope absent from the bundle → **unverified** (nothing to check against).
3. **`hmac-sha256`** — `signature_valid = None`, labelled *delegated*: verified
   by regista's delivery layer; cairn does not re-check. Counts as coverage.
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
| delegated (HMAC) | `None` | no | yes (regista checked) | labelled, not a pass claim by cairn |
| failed / forged | `False` | no | **no** | `all_ok` false (signature failure) |
| **unverified** | `None` | **yes** | **no** | reported as unverified; coverage missing |
| no signature (legacy) | `None` | no | per scheme | labelled |

`unverified` is deliberately *not* the same as `failed`: a failed signature is
positive evidence of forgery (the verdict goes red), whereas `unverified` means
"cairn could not establish this receipt" — the witness's corroboration is simply
*not proven*, and the report says so plainly rather than claiming it.

## 6. What a human reviewer must check

- The `unverified` classification covers **every** path where a signature is
  present but not verified (ed25519-no-key, ed25519-no-envelope, unknown
  scheme). A new code path that sets `signature_valid = None` for a signed
  receipt must also set `unverified`.
- `_check_witness_coverage` excludes both `signature_valid is False` and
  `unverified` receipts; an HMAC-delegated receipt (`None`, hmac scheme) still
  counts. Do not let an unverifiable receipt back into coverage.
- The HMAC delegation is a trust assumption in regista's delivery layer. If that
  ever changes, the "delegated counts as coverage" rule must be revisited.
- Witness public keys come from the bundle registration or the operator's
  `witness_keys`. A registration that *omits* its public key makes its Ed25519
  receipts unverified — that is the correct, fail-closed behaviour, not a bug.
