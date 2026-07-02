# Plan 007 — Session/Agent-Run Entity-Kind Attestation

**Status:** Implemented 2026-06-23. Additive, no envelope bump needed.
**Owner:** agent-provenance
**Depends on:** regista Plan 022 P1 (entity generalization + envelope v4)
**Resolves:** BC-005 (scope attestation structurally indistinct from tool events)

## 1. Motivation

The existing scope attestation (`CairnAdapter.attest_scope()`) is implemented
using work-item transitions (`tool_call_begin`/`tool_call_end`), making it
structurally indistinct from tool-call events. An auditor cannot reliably
distinguish a scope declaration from an ordinary tool call by examining the
event log — both share the same `entity_kind`, same transition names, and
same workflow binding.

Regista Plan 022 P1 introduced entity generalization: events now bind to
`(entity_kind, entity_id)` instead of just `work_item_id`. The `work_item`
kind is the first; `session`/`agent-run` is an additive kind that needs no
further envelope bump. This plan uses that primitive to make attestations
structurally distinct.

## 2. What was built

### Regista changes

- `append_event` API (all layers: `_event_store`, `_events_api`, `_ops`,
  `__init__`, `_in_memory_events`, `_in_memory`, sidecar) accepts
  `entity_kind` parameter (default `"work_item"`).
- Non-work-item entities skip work-item lookup, workflow validation, and
  `work_items_current` UPDATE.
- `InMemoryEventStore` tracks non-work-item entity seqs via `_entity_seqs`
  dict; `PostgresEventStore.allocate_seq` queries events table.
- `entity_kind` allow-list (`"work_item"`, `"session"`) rejects typos.

### Agent-provenance changes

- `SessionAttestationPayload` schema dataclass.
- `CairnAdapter.attest_session()` — creates a `entity_kind="session"`,
  `transition="session_attestation"` event. No work item created.
- `CairnClient.attest_session()` — high-level SDK method.
- `SessionAttestationEntry` verifier type; `session_attestations` field on
  `VerificationReport`.
- Verifier detects session attestations, passes `entity_kind`/`hash_alg` to
  signature verification, and treats session attestations as authoritative
  for scope coverage and principal binding (alongside scope attestations).
- Text/JSON/HTML reports surface session attestations.
- 9 tests covering schema, verifier detection, structural distinctness,
  report formats, and InMemory adapter integration.

## 3. Design decisions

- **Additive, not replacement.** `attest_scope()` remains for backward
  compatibility. New code should use `attest_session()`. The verifier
  consults both attestation sources for coverage and principal binding.
- **`event_seq` starts at 1** for non-work-item entities, matching the
  work-item convention.
- **Session attestations count for scope coverage.** A log containing only
  a session attestation (no `attest_scope`) will not flag tool calls as
  uncovered, provided the session attestation's harnesses include the
  tool call's harness.

## 4. Remaining gaps (filed as breadcrumbs)

- **Postgres `allocate_seq` race**: `SELECT MAX(event_seq)` without `FOR UPDATE`
  for non-work-item entities. UNIQUE constraint prevents corruption; loser
  gets misleading error.
- **Divergent append paths in regista**: `_events.py:append_event` (used by
  internal callers) still hardcodes `entity_kind="work_item"`.
- **Verifier groups by `work_item_id`**: chain/sequence checks should key by
  `(entity_kind, entity_id)` for conceptual correctness.
- **`verify_event_with_public_key` missing `global_seq`**: pre-existing regista
  bug.
- **OpenCode plugin/bridge**: does not call `attest_session()` at session start.
