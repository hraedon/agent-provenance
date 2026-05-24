# Plan 001 — Minimal End-to-End Skeleton

## Status

Completed 2026-05-24. Skeleton end-to-end + scope attestation both delivered.

## What this plan covers

The smallest credible end-to-end: a harness adapter that normalizes tool-call
metadata into substrate events, and an offline verifier that replays those events
and produces an auditor-ready report.

## What is NOT in this plan

- Real harness hook integration (Claude Code PreToolUse / PostToolUse, OpenCode
  skills). The adapter API is ready, but nothing intercepts actual tool calls yet.
- SDK wrapper (out of scope per AGENTS.md).
- UI / web report (CLI only).
- Asymmetric signing (blocked on BC-196 in substrate).

## Deliverables

| File | Purpose |
|------|---------|
| `src/cairn/__init__.py` | Package exports |
| `src/cairn/schema.py` | Canonical event schema (FileDigest, ToolCallBegin, ToolCallEnd, hash helpers) |
| `src/cairn/adapter.py` | Harness adapter — `CairnAdapter.begin_tool_call / end_tool_call` |
| `src/cairn/verifier.py` | Offline verifier — `Verifier.verify_events / verify_bundle` |
| `src/cairn/_cli.py` | CLI entrypoints `cairn verify` and `cairn export` |
| `workflows/cairn_agent_actions.yaml` | Substrate workflow for tool-call state transitions |
| `tests/test_cairn.py` | Unit tests (schema roundtrip, adapter begin/end, verifier ok/fail, bundle) |

## What moved in

- Scope attestation (`CairnAdapter.attest_scope`) — originally listed as a gap,
  delivered during plan closure.

## What moved out

- Nothing removed.

## Key design decisions

1. **State machine**: `new → running → completed | failed`.  The adapter uses
   `transition()` (not `append_event()`) so substrate validates state changes.

2. **Tool-call events are workflow transitions**, not free-form append events.
   This gives us role gating and validation for free.

3. **File digests only** — we do not store file contents in substrate payload.
   The verifier re-derives provenance by reading the actual file on the
   auditor's machine and comparing digests.

4. **Delegation stubbed** — `on_behalf_of` is passed through to substrate; real
   IdP integration (OIDC/SAML) is a v2 question.

5. **Scope attestation is a substrate work-item** — created as `new`, transitioned
   to `running` via `tool_call_begin`, then to `completed` via `tool_call_end`
   with the scope payload.  This makes the attestation a signed, replay-verifiable
   event in the same log as tool calls, not a separate sidecar.

## Verification

```bash
# Lint
python3 -m ruff check src/ tests/

# Tests (requires Postgres)
python3 -m pytest tests/ -v
```

## Closed gaps

- ~~BC-TBD: scope attestation as signed first-class event~~ (done in 001)

## Gaps to close

- **BC-TBD**: harness-level interception for Claude Code
- **BC-TBD**: harness-level interception for OpenCode
- **BC-196 dependency**: asymmetric signing (Ed25519) — verifier ready, substrate
  needs to emit it
- **BC-197 dependency**: delegation chain validation — verifier ready, substrate
  enforces it today but no IdP origin yet
