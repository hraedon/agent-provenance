# Plan 011 — Codex lifecycle provenance

**Status:** Core adapter, direct installer, component-owned plugin, and honest
Codex doctor landed 2026-07-18. `cairn._codex_hook` attests SessionStart and
Pre/PostToolUse; Stop safely cleans correlation state and emits the required
non-blocking JSON response. `install-harness codex` merges the hook group
into `$CODEX_HOME/hooks.json`, while `plugins/cairn` provides the suite-owned
marketplace path. The two delivery paths are alternatives; doctor fails when
both are active because Codex would run both copies. Plugin add/list/remove and
cache contents are verified with the real Codex 0.144.5 CLI under an isolated
`CODEX_HOME`. **Deferred:** SubagentStart/Stop delegation lifecycle (WI-2.3 —
subagent *tool* activity IS attributed via `agent_id`/`agent_type`),
concurrency-stress hardening (WI-2.4), and the full live adversarial session
(WI-4.1, billable). Hook trust remains an operator `/hooks` check because Codex
does not expose persisted trust through a machine-readable CLI.
**Original status:** Proposed 2026-07-10.
**Author:** GPT-5.6 Sol, from the suite Codex integration audit.

**Packaging gate:** Cairn now declares the Regista 0.5.1 public-facade range
and uses the sibling checkout as uv's development source, matching the suite
constellation. A standalone uv checkout remains gated on publishing or pushing
that Regista facade, after which the source override should become a pinned
tag, commit, or package release.

## Implementation notes (2026-07-17)

- **Reuses the Claude adapter's machinery** (`_run_bridge`, `_state_dir`,
  `_compute_output_digest`, `_extract_files`, `_mark_degraded`, `_capture_raw`)
  — only the Codex-specific field names, the explicit `tool_use_id` correlation
  (Decision 3), and the Stop JSON-output contract (Decision 5) are new.
- **Hooks-only install — NO secrets/env in Codex config** (Decision 6 / Plan 007
  Decision 3). The hook processes read `REGISTA_DSN`/`PRINCIPAL_ID`/harness
  identity from the ambient environment; the adapter detects the live Codex
  version at attestation time. This differs from the Claude installer, which
  writes an `env` block into `settings.json`.
- **Only the four handled events are registered** — no false "wired" signal for
  events the adapter does not attest. Existing user hooks and unrelated config
  are preserved (surgical merge; uninstall removes only cairn entries).
- **No raw Codex response is persisted.** Tool output contributes a full
  SHA-256 digest and byte count; non-zero failures store a digest-only error
  summary. The optional raw-fixture capture path used by the Claude adapter is
  not invoked by the Codex adapter. The local activity marker contains only a
  timestamp, event name, and one-way session-id digest.
- **Current tool coverage follows Codex 0.144.5 documentation.** Local function
  tools—including unified exec, apply_patch, MCP, and subagent dispatch—use the
  Pre/PostToolUse path. Hosted tools such as WebSearch and specialized paths
  that opt out remain explicitly outside Cairn's capture claim.
- **Doctor separates observable states.** It validates direct/plugin wiring,
  rejects duplicate paths, checks the effective hooks feature and visible
  managed-only policy, reports named degradation, and records recent successful
  bridge activity. Trust is always reported as unverified until the operator
  reviews `/hooks`; no unsupported internal Codex state is inspected.
- **Codex stays out of the stable `all`** expansion (still `claude`, `opencode`),
  consistent with the hardened suite Plan 007 (atomic cross-component promotion).
- Authoritative Codex hook schema confirmed against
  https://learn.chatgpt.com/docs/hooks (fields: `session_id`, `turn_id`,
  `tool_name`/`tool_use_id`/`tool_input`/`tool_response`, `agent_id`/`agent_type`,
  `hook_event_name`; Stop requires JSON on stdout; `$CODEX_HOME/hooks.json`;
  plugin default `hooks/hooks.json`; `commandWindows` override supported).
**Strategic role:** Add honest tool-call, session, and subagent provenance for
local Codex using the now-documented lifecycle hook protocol.

This plan supersedes only the Codex portions of Plan 010 WI-5.1, WI-5.4, and
WI-5.5. It does not depend on Plan 010's content-capture portal. Plan 009
capture correctness remains a prerequisite.

## Ground truth

- Codex command hooks receive JSON on stdin with stable session, turn, model,
  cwd, event, tool, and subagent fields.
- `PreToolUse` and `PostToolUse` cover Bash, `apply_patch`, and MCP tool
  calls and expose a correlating `tool_use_id`.
- Coverage includes the documented local function-tool path (including unified
  exec) but remains explicitly incomplete for hosted WebSearch and specialized
  paths that opt out. Cairn attests this limitation instead of claiming
  complete capture.
- Session/subagent hooks expose `session_id`, `turn_id`, `agent_id`, and
  `agent_type`. Subagent hooks use the parent session id.
- Transcript paths are convenient but explicitly unstable. This plan does not
  parse transcripts.
- Hook commands require review/trust and multiple matching hooks run
  concurrently.
- `Stop` and `SubagentStop` require valid JSON on successful stdout.

Authoritative reference: https://learn.chatgpt.com/docs/hooks

## Decisions

1. Implement a Python-native `cairn._codex_hook` adapter over the existing
   bridge/event model.
2. Capture v1 digests and metadata, not prompt/response content. Do not register
   `UserPromptSubmit` in this plan.
3. Pair tool begin/end by `(session_id, turn_id, tool_use_id)`; never infer
   ordering from process timing.
4. Represent Codex subagents as child sessions/delegations with their
   `agent_id` and parent session, preserving the full chain available from
   hooks.
5. Hook failure is recorded durably in a bounded degradation log and returns a
   non-blocking, event-valid response. Provenance must not accidentally stop or
   rewrite the user's Codex turn.
6. Install into the user Codex hook layer by surgical merge plus an ownership
   manifest. Managed enterprise hooks are documented, not modified.
7. Scope attestations name both captured and uncaptured tool paths and the
   running Codex version.
8. Follow agent-suite Plan 007 for stable `all` semantics and positional
   installer invocation.

## Phase 1 — Contract fixtures

### WI-1.1 — Freeze hook input fixtures

Commit synthetic fixtures for SessionStart, PreToolUse, PostToolUse,
SubagentStart, SubagentStop, and Stop, including malformed and version-drift
cases.

**AC:**

- Fixtures contain no real prompts, paths, hosts, identities, or secrets.
- Parser rejects missing correlation fields with named degradation.
- Additive unknown fields are tolerated.
- Tests encode `tool_response`, not legacy harness field names.

### WI-1.2 — Map Codex events to cairn events

Document the mapping for session attestation, scope attestation, tool begin/end,
subagent delegation, compaction/resume, and stop.

**AC:** every emitted cairn field has one named Codex source or an explicit
derived rule; unavailable fields are absent rather than fabricated.

## Phase 2 — Adapter

### WI-2.1 — Session lifecycle

Handle SessionStart sources (`startup`, `resume`, `clear`, `compact`) and
Stop idempotently.

**AC:**

- Start/resume does not duplicate a session founding event.
- Model slug, cwd/project binding, permission mode, and harness version are
  recorded under the existing privacy rules.
- Stop writes valid JSON and never requests continuation.
- Bridge failure leaves a durable degradation record and does not break Codex.

### WI-2.2 — Tool-call capture

Handle PreToolUse/PostToolUse for Bash, apply_patch, and MCP calls.

**AC:**

- Begin/end correlate by hook identifiers under concurrent hook processes.
- Success, non-zero shell exit, malformed output, and missing begin/end each
  produce deterministic verifier behavior.
- Arguments and outputs follow existing digest/redaction/truncation semantics.
- No secret-bearing raw config or environment is logged.
- Coverage metadata explicitly lists unsupported paths.

### WI-2.3 — Subagent attribution

Handle SubagentStart/SubagentStop as a delegation edge and child lifecycle.

**AC:**

- Two concurrent subagents remain distinct.
- Parent session, turn, agent id/type, principal, and lineage are preserved.
- Nested delegation is rendered by the verifier without flattening to the
  parent.
- Orphan stop/start events become named gaps.

### WI-2.4 — Concurrency and degradation

Use atomic state writes/locks appropriate to multiple concurrently launched
hooks, with bounded cleanup for abandoned tool calls and sessions.

**AC:** stress tests run interleaved hooks without lost ends, duplicate
sequences, corrupt state, or unbounded files.

## Phase 3 — Installation and health

### WI-3.1 — `cairn install-harness codex`

Surgically merge owned hook groups into `$CODEX_HOME/hooks.json`, preserving
all unrelated hooks/config. Support dry-run, JSON, uninstall, Windows command
override, user overlay, and hash-based ownership.

**AC:**

- Clean install, existing-hook merge, re-run, changed-hook conflict, and
  uninstall tests pass.
- Re-run is a no-op.
- Uninstall removes only cairn definitions.
- `all` follows suite Plan 006 stable-target semantics.

### WI-3.2 — Trust and doctor

Doctor verifies files, hook definitions, feature enablement/policy visibility,
ownership, recent attestation, and degradation state. Document `/hooks`
review/trust and managed-only policy.

**AC:**

- Installed-but-untrusted, disabled, managed-only, stale, and actively
  attesting states are distinguishable.
- “Wired but silent” turns doctor red after the documented window.
- Doctor never claims full tool coverage.

## Phase 4 — Live adversarial proof

### WI-4.1 — Local Codex proof

In a clean profile, run a session containing Bash success/failure, apply_patch,
an MCP call, parallel subagents, compaction/resume, and a deliberate bridge
outage.

**AC:**

- Expected events verify as one chain with correct session/delegation identity.
- Unsupported tool paths appear as explicit scope gaps.
- Outage produces degradation evidence and recovery resumes without corrupting
  the chain.
- Install/uninstall restores the profile's unrelated content.

### WI-4.2 — Documentation and claim review

Update interception research, README scope language, doctor docs, and the
security/residual-risk section.

**AC:** no document describes Codex capture as complete; the supported event and
tool matrix is versioned and linked to the proof.

## Out of scope

- Prompt/assistant transcript capture and portal display (Plan 010).
- Using unstable transcript files as an API.
- Enforcing Codex permissions or rewriting tools.
- External wake/turn injection (agent-wake 006).
- Hosted Codex tasks until their hook/config/network contract is separately
  proven.
