# AP-001: Key rotation event support in verifier

**Kind:** gap  
**Status:** partial  
**Severity:** medium  
**Component:** verifier  
**Blocked on:** substrate BC-196

## Description

The verifier treats unknown key_ids as `revoked_key` but doesn't distinguish
"rotated to new key" from "unknown key". The README §4.2 describes
`key_rotation` and `key_revocation` events. An auditor seeing a key change
mid-log needs to verify the rotation chain.

## Implementation needed

1. Recognize key_rotation events in the payload
2. Build a key chain graph
3. Verify predecessor-signed rotation
4. Surface in the verification report

## What's done

- Steps 1-4 implemented: verifier detects `tool == "key_rotation"` events,
  verifies the predecessor key signed the rotation, and surfaces key rotations
  in both text and JSON reports.
- Structural verification (predecessor key_id matches signer) is working.
- Cryptographic verification against the predecessor key material is working.

## What remains

- Full Ed25519 asymmetric key support (blocked on substrate BC-196).
- `key_revocation` event handling (distinct from rotation).
