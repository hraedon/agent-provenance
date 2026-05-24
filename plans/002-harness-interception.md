# Plan 002 — Harness-Level Interception

## Status

In progress 2026-05-24.  OpenCode integration designed; bridge script
(`cairn-bridge`) and TypeScript plugin skeleton created.

## Goal

Move from "API exists" to "the adapter actually captures the tools you use."
This means writing small, low-footprint harness integrations for **Claude Code**
and **OpenCode** so that every tool call in a session is logged to substrate
without manual adapter calls.

## Design constraints

- **Non-invasive.**  We do not vendor or fork the harness.  Integration is via
  public hooks / plugin API only.
- **Graceful degradation.**  If the harness hook API changes, or substrate is
  unreachable, the agent must still work — logging is audit-layer, not
  enforcement-layer (README §2).
- **Minimal config.**  One env var or one JSON config file to enable.

## What's in scope for this plan

1. **OpenCode skill hook** — OpenCode exposes `tool.execute.before` and
   `tool.execute.after` hooks via the `@opencode-ai/plugin` API. We will ship a
   thin TypeScript plugin that delegates to the Python `cairn-bridge` script,
   keeping Cairn as the single source of truth.
2. **Claude Code `PreToolUse` / `PostToolUse`** — Anthropic's Claude Code
   exposes lifecycle hooks.  We will ship a small Python module that registers
   callbacks with the adapter.
3. **Configuration discovery** — Environment variables (`CAIRN_DSN`,
   `CAIRN_PROJECT`, `CAIRN_KEY_PATH`) or a JSON config file.
4. **Initialization / scope attestation on startup** — When the harness hook
   loads, it calls `adapter.attest_scope()` once with the harness name, version,
   and config digest.  This gives every session a signed scope boundary.

## OpenCode integration design

OpenCode is a Node.js/Bun application.  The `@opencode-ai/plugin` package exposes
TypeScript hooks.  We use a **bridge pattern** so we do not re-implement Cairn
logic in TypeScript:

```
OpenCode process
    └── TypeScript plugin (integrations/opencode/index.js)
            └── Bun.$`echo '{...}' | python3 -m cairn._bridge`
                    └── CairnAdapter (Python)
                            └── substrate (PostgreSQL)
```

Files created:
- `src/cairn/_bridge.py` — Python bridge script (reads JSON from stdin)
- `integrations/opencode/index.js` — TypeScript plugin wrapping the bridge

The bridge handles three actions:
- `attest_scope` — records session scope attestation
- `begin` — records `tool_call_begin` with file digests
- `end` — records `tool_call_end` with result summary

## What's NOT in this plan

- Cursor, Aider, or other harnesses (v2).
- SDK wrapper (still v1.5 at earliest).
- Web UI / HTML report.
- Asymmetric signing (blocked on substrate BC-196).

## Open questions

- Does Claude Code's `PreToolUse` / `PostToolUse` hook pass the full file list
  before/after, or only the tool arguments?  The adapter needs the file paths
  to compute digests.
- OpenCode plugin architecture: confirm the `Bun.$` shell invocation does not
  cause performance issues for high-frequency tool calls.
- Should we auto-detect the harness name/version, or require explicit config?

## Verification

- New tests that mock the harness hook and assert substrate events are created.
- Manual dogfooding: run the agent with the hook enabled, then run
  `cairn verify` on the exported bundle and confirm the tool calls you just
  performed appear in the report.

## Gaps to close after this plan

- **BC-TBD**: SDK wrapper (v1.5)
- **BC-TBD**: Cursor / Aider harness hooks
- **BC-196 dependency**: asymmetric signing (Ed25519)
- **BC-197 dependency**: delegation chain validation with real IdP
