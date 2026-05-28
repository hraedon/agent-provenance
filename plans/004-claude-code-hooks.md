# Plan 004 — Claude Code Hooks

## Status

Implemented 2026-05-25. Hook script, state management, degradation logging,
settings digest, and session cleanup all done. Mock tests passing. Not yet
tested in a live Claude Code session.

## Goal

Implement harness-level interception for Claude Code via its `PreToolUse` /
`PostToolUse` hook API, mirroring the OpenCode integration from Plan 002/003.

## Motivation

AGENTS.md lists Claude Code hooks as an open gap. The adapter and bridge
are ready; what's missing is the thin integration layer that converts Claude
Code's hook JSON into bridge calls.

## Design constraints

Same as Plan 002:

- **Non-invasive.** Public hooks only; no fork, no vendor.
- **Graceful degradation.** If regista is down or the hook crashes, the
  agent continues. Audit-layer, not enforcement-layer.
- **Minimal config.** One `.claude/settings.json` entry + env vars.

## Architecture

Claude Code hooks run as separate processes per event. Unlike OpenCode's
in-process plugin (which can hold a `Map` in memory), we need external state
to pass the `work_item_id` from `PreToolUse` to `PostToolUse`.

```
Claude Code
    └── PreToolUse hook → cairn_hook.py pre
    │       └── cairn-bridge begin
    │       └── writes work_item_id to /tmp/cairn-sessions/{session_id}/
    └── PostToolUse hook → cairn_hook.py post
            └── reads work_item_id from /tmp/cairn-sessions/{session_id}/
            └── cairn-bridge end
            └── cleans up state file
```

State management:
- State dir: `${CAIRN_STATE_DIR:-/tmp/cairn-sessions}/{session_id}/`
- Each pending call is a file: `{tool_name}:{args_hash_short}.json`
- File contains `{"work_item_id": "...", "session_id": "..."}`
- PostToolUse reads the file, calls bridge end, removes the file

This handles parallel tool batches correctly: each call gets its own file
keyed by tool name + args hash.

## Files to create

1. `integrations/claude-code/cairn_hook.py` — Main hook script (single entry
   point, dispatches on `sys.argv[1]`: `pre`, `post`, `session-start`)
2. `integrations/claude-code/settings.example.json` — Example `.claude/settings.json`
3. Tests for the hook script

## What's NOT in scope

- OpenCode (done in Plan 002/003)
- Cursor, Aider (Plan 005+)
- SDK wrapper
- Blocking enforcement (audit-only)

## Verification

- Unit tests with mocked bridge calls
- Manual dogfood: enable hooks, perform tool calls, run `cairn verify`
