# Interception-surface research: Hermes, Agy, Codex

Plan 010 WI-5.1 — design notes for each new harness's hook/plugin/skill
interception surface.

## Hermes (Nous Research)

**Status:** Provisional plugin already merged (`integrations/hermes/`).
`cairn install-harness hermes` wires env + plugin.

**Lifecycle events available:**
- Tool/skill hooks: Hermes's CLI dispatcher instruments tool calls before
  and after execution, analogous to Claude Code's `PreToolUse`/`PostToolUse`.
- Session lifecycle: Hermes maintains persistent memory across sessions;
  session start/stop hooks are available via the plugin system.
- Delegation: Hermes delegates to Claude Code and Codex as sub-agents.
  The delegation chain (`on_behalf_of`) must thread the full chain:
  `principal_id` (human) → `session_id` (Hermes) → `session_id` (Claude
  Code, child) → tool call.

**Bridge pattern:** Python-native (Hermes is Python-based). The Hermes
adapter reuses the existing `CairnAdapter` core; the bridge is a new
variant that threads the delegation chain.

**Chosen approach:** The Hermes plugin (`integrations/hermes/plugin.yaml`)
is a PROVISIONAL skeleton. Full implementation (WI-5.2) extends it to:
1. Instrument tool/skill calls (begin/end).
2. Thread the delegation chain for sub-agent calls.
3. Capture session lifecycle events (start/stop/transcript).

**Reference:** Hermes CLI dispatcher in `cli.py`; tool/skill system.

## Agy (Google Antigravity CLI)

**Status:** Deferred (Plan 010 WI-5.3).

**Lifecycle events available:**
- Agy is Go-based with a plugin/skill system.
- Tool-call interception: Agy's plugin system supports pre/post tool
  hooks, analogous to Claude Code's `PreToolUse`/`PostToolUse`.
- Subagent capability: Agy can spawn subagents; attribution must
  thread the delegation chain.

**Bridge pattern:** Shell-out pattern (Agy plugin → Python bridge),
mirroring the opencode Node→Python bridge. A Go-native bridge is
possible if Agy's plugin system supports it, but the shell-out pattern
is lower-risk and proven by the opencode integration.

**Chosen approach:** Deferred. The Agy adapter will mirror the opencode
bridge pattern: a thin Agy plugin that shells out to `cairn-bridge` for
each tool call. `cairn install-harness agy` will wire the plugin + env.

**Reference:** Agy plugin/skill system (research needed — Agy is the
least documented of the three).

## Codex (OpenAI)

**Status:** Deferred (Plan 010 WI-5.4).

**Lifecycle events available:**
- Codex is an open-source terminal coding agent with sandboxed multi-step
  execution.
- Plugin/extension API: Codex's sandbox complicates interception — the
  bridge must reach regista from outside the sandbox, or the sandbox
  must allow the bridge's network egress.
- Codex is the least mature interception surface of the five.

**Bridge pattern:** Sidecar bridge pattern. The bridge runs outside the
sandbox and communicates via a Unix socket or HTTP endpoint that the
sandbox allows. Alternatively, if Codex's plugin system supports
network egress, a direct bridge call is possible.

**Chosen approach:** Deferred. The Codex adapter requires research into
the sandbox's network egress policy. A sidecar bridge pattern is the
most likely approach. `cairn install-harness codex` will wire the
sidecar + env.

**Reference:** Codex sandbox hook surface (research needed).
