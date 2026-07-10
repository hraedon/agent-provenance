# Plan 010 — Session-content capture and the authorized-viewer portal

**Status:** Proposed 2026-07-08.
**Author:** GLM-5.2, from a scope-expansion conversation with the project owner.
**Strategic role:** v1 is *tool-call provenance* (what the agent did, hashed).
This plan is v2: *session provenance* — what the agent and user said and did, as
content — plus the authorized web portal that makes that content viewable. The
two are coupled: the only reason to capture content (vs digests) is so
authorized users can view it; the only reason to build a portal is to surface
that content. They are one feature with a write side and a read side.

This plan **re-attests the scope statement** (README §2). The out-of-scope
claim in v1 is signed as a first-class event precisely so scope cannot drift in
prose. Expanding scope requires a new signed attestation — the mechanism
exists; this plan uses it.

## Ground truth at time of writing

1. **Capture is tool-call-only.** `schema.py` defines `ToolCallBegin` /
   `ToolCallEnd` / `ScopeAttestationPayload` / `SessionAttestationPayload`.
   Arguments are hashed (`tool_args_hash`), outputs are digested
   (`stdout_digest`/`stderr_digest`), files are digested. No prompt, response,
   or transcript content enters the log. This is a deliberate security property
   (README §4 "missing events" residual), not an omission.
2. **v1 capture is currently broken/unwired.** Plan 009 ground truth #1–4:
   nothing attests live; the Claude hook reads a field the harness doesn't
   send; tests encode the wrong assumption; digest semantics are undefined
   under truncation. **This plan hard-depends on Plan 009.** Expanding a
   recorder that records nothing records more nothing.
3. **No viewer surface exists.** `cairn verify --format html` produces a static
   single-file verification report — not a browseable portal. There is no
   authenticated web UI, no browse-by-session/principal/time, no live query.
   README §9 names this as an open question.
4. **dossier is the suite's human web face over regista.** Server-rendered
   FastAPI + Jinja + patina; LDAP-pluggable auth (signed session + CSRF +
   principal→actor); a `RegistaGateway` choke point; a verified-history view
   (the integrity-checked event chain rendered for humans). dossier Plan 011
   (multi-project fronting) and Plan 017 (agent-activity window) are the
   intended vehicles for surfacing cairn's data to humans. This plan does not
   build a new portal project — it extends dossier.
5. **regista has no encryption-at-rest and no content-addressed blob store.**
   The event envelope (`_events.py:22`) stores `payload` as JSONB. The
   secrets module (`_secrets.py`) resolves *signing keys* from backends (env,
   vault, DPAPI) but does not encrypt event payloads. A content-capturing log
   is a new risk surface (secrets, PII, internal data in the log) requiring
   encryption at rest and access controls. This plan depends on a regista
   encryption-at-rest primitive (regista Plan 030, cross-filed below).
6. **Hermes, Agy, Codex are external CLI coding agents** (not in this
   workspace):
   - **Hermes** (Nous Research) — autonomous orchestration agent with
     persistent memory; can delegate to Claude Code / Codex as sub-agents.
     CLI dispatcher in `cli.py`; tool/skill system.
   - **Agy** (Google Antigravity CLI) — Go-based terminal coding agent,
     replaced Gemini CLI; subagent-capable, plugin/skill system.
   - **Codex** (OpenAI) — open-source terminal coding agent; sandboxed
     multi-step execution; the most actively developed terminal agent
     outside Claude Code.
   All three expose hook/plugin/skill interception points analogous to
   Claude Code's `PreToolUse`/`PostToolUse` and opencode's
   `tool.execute.before`/`after`. None ship a provenance/audit layer.

## Clients in scope

All existing harnesses plus three new ones. Five total:

| Harness | Status | Interception surface |
|---------|--------|---------------------|
| Claude Code | existing (Plan 004/008/009) | `PreToolUse`/`PostToolUse` + lifecycle hooks (`Stop`, `SessionEnd`, `SubagentStart/Stop`, `PostCompact`, `MessageDisplay`) |
| OpenCode | existing (Plan 003/008) | `tool.execute.before`/`after` + `event` (`session.started`, message events) |
| Cursor | planned (WI-014, not started) | TBD — Cursor's hook extension surface; research item |
| **Hermes** (new) | this plan | Hermes skill/tool hooks; CLI dispatcher instrumentation; delegation-aware (Hermes→Claude/Codex sub-agent calls must attribute correctly) |
| **Agy** (new) | this plan | Agy plugin/skill system; Go-plugin or shell-out bridge pattern (mirror the opencode Node→Python bridge) |
| **Codex** (new) | this plan | Codex sandbox hook surface; plugin/extension API (research — Codex is the least mature interception surface of the five) |

**Delegation depth is a new concern.** Hermes delegates to Claude Code and
Codex as sub-agents. A session where Hermes→Claude Code→`Edit` must not flatten
the Claude `Edit` into "Hermes did it" nor orphan it as "Claude did it
unsanctioned." The delegation chain (`on_behalf_of`) already exists in regista
(BC-197); this plan extends the adapter to thread the full delegation depth
(parent session → child session → tool call), not just one level.

## Encryption stance (the owner's call: opt-out with warning)

**Default: session content is encrypted at rest.** The log holds every secret,
PII string, and internal datum that passed through the session. That is a new
risk surface v1 did not have. Encryption at rest is therefore **on by default**.

**Opt-out is permitted, with a loud warning.** A deployment may set
`CAIRN_CONTENT_ENCRYPTION=off` (or omit the content-encryption key). When
encryption is off:

- `cairn doctor` emits a **WARNING**, not a silent pass.
- The scope attestation records `"content_encryption": "off"` as a signed
  field, so an auditor sees the deployment's stance and can judge it.
- The verifier report surfaces the stance prominently (a finding, not a
  footnote): "Content captured without encryption at rest — the log itself
  is now a sensitive artifact."
- The portal renders unencrypted-content deployments with a visible banner
  on every session view.

**The opt-out exists for** (a) local development, (b) deployments where
encryption at rest is provided by a lower layer (encrypted Postgres volumes,
TDE) *and* the operator has documented that control, and (c) performance
testing. It is never the silent default.

**Key custody:** the content-encryption key is resolved via the same
`regista._secrets.resolve` path as the signing key (env, vault, DPAPI) — no
plaintext key on disk. regista Plan 029 (backend-aware key custody) already
landed; this plan reuses it.

## Principles

- **Content capture is a v2 scope change, re-attested.** README §2's
  out-of-scope claim is signed. This plan re-attests the scope as a new signed
  event; the old claim remains in the chain (append-only) and the verifier
  reports the scope expansion with its effective timestamp.
- **The portal extends dossier, not a new project.** dossier is the suite's
  human face. A new cairn-specific portal would duplicate auth, gateway,
  templates, and design system — the divergence the suite cohesion work
  exists to prevent. The portal is dossier Plan 017 (agent-activity window)
  extended to render session content.
- **Hash-or-content is per-field, not global.** v1 fields (tool args, stdout,
  files) stay hashed. v2 adds content fields (prompt, response, transcript)
  as content. The schema distinguishes `*_digest` (integrity, always) from
  `*_content` (the bytes, v2, encrypted). An auditor can verify integrity
  without decrypting content.
- **The residual "missing events" problem (README §4) is unchanged.** Content
  capture widens *what's captured when configured*; it does not fix the
  structural "operator chose silence" problem. Plan 009 WI-4.1 (silence is a
  finding) is the defense there, and this plan extends it to content fields.
- **Redaction is a deployment policy, not a cryptographic guarantee.** The log
  captures what flowed through the session. A deployment may configure
  redaction rules (regex-based, applied before encryption); the scope
  attestation records whether redaction is active. Redaction is best-effort
  and explicitly *not* a guarantee that all sensitive content was stripped —
  the honest stance is "captured + encrypted; review the redaction policy
  if you need to know what was stripped."

---

## Phase 1 — The v2 scope attestation (do this before anything else)

### WI-1.1 — New scope-attestation schema with content-encryption stance
- Extend `SessionAttestationPayload` (and `ScopeAttestationPayload`) with:
  - `content_capture: bool` — whether this session captures content (v2)
    or only digests (v1).
  - `content_encryption: str` — `"on"` | `"off"` | `"external"` (external
    = lower-layer encryption, e.g. TDE/encrypted volume, documented).
  - `redaction_policy: str | None` — name/digest of the active redaction
    policy, or `null` if none.
- The adapter records these on session start; the verifier reads them and
  reports the stance. An auditor sees, per session, exactly what was
  captured and how it was protected.
- **AC:** a v2 session attestation carries `content_capture=true,
  content_encryption="on"`; a v1 session (or a v2 deployment with content
  off) carries `content_capture=false`; the verifier distinguishes them and
  the report names the stance.

### WI-1.2 — Backward compatibility
- v1 attestations (no `content_capture` field) are read as
  `content_capture=false`. No migration. The verifier reports "v1 scope
  (digests only)" vs "v2 scope (content captured, encrypted)" clearly.
- **AC:** an existing v1 bundle verifies under the new verifier with no
  behavior change; the report labels it v1 scope.

---

## Phase 2 — Session-content schema (the write side)

### WI-2.1 — Content payloads: prompt, response, transcript
- New payload types alongside `ToolCallBegin`/`End`:
  - `UserMessagePayload` — the human's prompt/message to the agent.
  - `AssistantMessagePayload` — the model's response/reasoning.
  - `TranscriptAttestationPayload` — a whole-session or segment digest +
    optional content (WI-3.2 from Plan 009, upgraded from digest-only to
    content-optional).
- Each content field is paired with its digest: `prompt_digest` +
  `prompt_content` (encrypted), `response_digest` + `response_content`
  (encrypted). The digest is always present (integrity); the content is
  present only when `content_capture=true` (v2).
- Content fields are stored encrypted (WI-4.1); the digest is computed
  *before* encryption so an auditor verifies integrity without the key.
- **AC:** a v2 session event carries both `*_digest` (always) and
  `*_content` (encrypted, when content capture is on); the digest of the
  decrypted content equals the `*_digest` field.

### WI-2.2 — Lifecycle event coverage (the harness surface that moved)
- Implement interception for the lifecycle events Plan 009 WI-3.1/3.2 named:
  `Stop`/`SessionEnd` (transcript attestation), `SubagentStart`/`Stop`
  (attribution), `PostCompact` (context loss is provenance-relevant),
  `MessageDisplay` (assistant output). Per-harness:
  - **Claude Code:** the hook already receives these; extend the dispatcher.
  - **OpenCode:** the `event` hook already receives `session.started`;
    extend to message/stop events.
  - **Hermes/Agy/Codex:** research the equivalent lifecycle hooks per
    harness (WI-5.1).
- **AC:** a session that includes a user prompt, a model response, a
  subagent spawn, and a compaction yields all four as distinct signed
  events with correct attribution.

### WI-2.3 — Delegation depth (Hermes→sub-agent→tool call)
- Extend the adapter to thread a multi-level delegation chain
  (`on_behalf_of` already supports it structurally; populate the full
  chain). A Hermes session that delegates to Claude Code records:
  `principal_id` (human) → `session_id` (Hermes) → `session_id` (Claude
  Code, child) → tool call. The chain is signed on each event.
- **AC:** a Hermes→Claude Code→`Edit` session records the `Edit` with a
  delegation chain of depth 2; the verifier renders the full chain; a
  flat "Hermes did it" or orphaned "Claude did it" is impossible.

---

## Phase 3 — Encryption at rest (depends on regista Plan 030)

### WI-3.1 — Content-encryption key resolution
- Resolve the content-encryption key via `regista._secrets.resolve`
  (same path as the signing key). A new config var
  `CAIRN_CONTENT_KEY_REF` (or `CAIRN_CONTENT_KEY_PATH` for file-based).
- When `CAIRN_CONTENT_ENCRYPTION=off`, no key is required; the scope
  attestation records `"off"` and the doctor/verifier/portal warn.
- **AC:** a v2 deployment with encryption on resolves the key from
  vault/env/DPAPI; a deployment with encryption off starts without a key
  and shows the warning.

### WI-3.2 — Encrypt content fields before write
- In the adapter/bridge, encrypt `*_content` fields before writing to
  regista. Algorithm: AES-256-GCM (authenticated encryption; the digest
  + the GCM tag provide double integrity). Store the nonce + ciphertext
  in the payload; the digest is the digest of the plaintext.
- This requires regista to accept opaque encrypted blobs in the payload
  JSONB (it does — payloads are free-form JSONB). The encryption happens
  in cairn, not regista — regista remains content-agnostic. *If* regista
  Plan 030 ships a native encryption-at-rest primitive, cairn uses it;
  otherwise cairn encrypts at the application layer.
- **AC:** content fields in a v2 session are ciphertext in the database;
  decryption with the content key yields plaintext whose digest matches
  the `*_digest` field; decryption without the key fails.

---

## Phase 4 — The portal (extends dossier Plan 017)

### WI-4.1 — dossier: front the cairn project read-only
- dossier Plan 011 (multi-project fronting) already supports per-project
  routing. This plan adds the cairn provenance project as a frontable
  project — **read-only**: cairn's project has no work items a human
  transitions; it has tool-call events, session attestations, and (v2)
  content events.
- The dossier `RegistaGateway` gains a read-only mode for the cairn
  project (no mutation surface).
- **AC:** an authenticated dossier user can navigate to the cairn
  provenance project and see sessions + tool-call trails; no mutation
  action is offered.

### WI-4.2 — dossier: session-content view (the portal's reason)
- Extend dossier Plan 017's session-detail view to render v2 content:
  the prompt/response transcript, interleaved with tool calls, with
  file provenance and attestation gaps visible inline. This is the
  thing a regulated reviewer opens first.
- Decryption happens in the portal (the user's session has the content
  key via the same `regista._secrets.resolve` path, or a per-user key
  — TBD, depends on dossier's auth/key model). For an external
  auditor, the offline bundle + `cairn verify` remains the artifact;
  the portal is for authorized internal users.
- **AC:** an authorized user sees the full session transcript with
  decrypted content, tool calls, file provenance, and verification
  status; an unauthorized user sees nothing; the verification stamp
  (Plan 017 WI-2.2) is visible.

### WI-4.3 — dossier: content-encryption stance banner
- When the cairn project is fronted and content encryption is off, a
  visible banner on every session view: "Content captured without
  encryption at rest." When redaction is active, a note: "Redaction
  policy: `<name>` (best-effort)."
- **AC:** an unencrypted-content deployment shows the banner; an
  encrypted-content deployment does not.

---

## Phase 5 — New harness adapters (Hermes, Agy, Codex)

> **Codex scope moved 2026-07-10:** Plan 011 owns Codex lifecycle/tool-call
> provenance now that Codex has a documented hook protocol. Its focused work is
> independent of this plan's prompt/response content capture and portal. The
> Codex portions of WI-5.1, WI-5.4, and WI-5.5 below are superseded by Plan 011;
> they remain here as historical planning context. Hermes and Agy remain in
> this phase.

### WI-5.1 — Interception-surface research (one WI per harness)
- For each of Hermes, Agy, Codex: research and document the hook/plugin/
  skill interception surface. Produce a short design note (in `docs/`)
  per harness covering: lifecycle events available, tool-call
  interception points, transcript/session-end surface, delegation
  semantics (does it spawn sub-agents? how are they attributed?),
  and the chosen bridge pattern (Python-native, shell-out like the
  opencode Node→Python bridge, or Go-plugin for Agy).
- **AC:** three design notes committed; each names the interception
  points and the bridge pattern chosen, with a reference to the
  harness's own docs/source confirming the surface.

### WI-5.2 — Hermes adapter
- Implement the Hermes adapter. Key concern: delegation depth (WI-2.3).
  Hermes delegates to Claude Code / Codex as sub-agents; the adapter
  must thread the full delegation chain so a sub-agent's tool calls
  attribute correctly to both the Hermes session and the human
  principal. Reuse the existing bridge/adapter pattern; the Hermes
  adapter is a new bridge variant, not a new adapter core.
- **AC:** a Hermes session that delegates a tool call to Claude Code
  produces a delegation chain of depth 2 in the signed event; the
  verifier renders it; `cairn doctor` reports the Hermes harness as
  wired.

### WI-5.3 — Agy adapter
- Implement the Agy adapter. Agy is Go-based; the bridge is likely a
  shell-out pattern (Agy plugin → Python bridge) mirroring the opencode
  Node→Python bridge, or a Go-native bridge if Agy's plugin system
  supports it. Decide in WI-5.1.
- **AC:** an Agy session produces the same attestation shape as a
  Claude Code / opencode session; the adapter is wired via
  `cairn install-harness agy`.

### WI-5.4 — Codex adapter
- Implement the Codex adapter. Codex's sandbox complicates
  interception (the bridge must reach regista from outside the sandbox,
  or the sandbox must allow the bridge's network egress). Research in
  WI-5.1; the adapter may need a sidecar bridge pattern.
- **AC:** a Codex session attests; sandbox egress for the bridge is
  documented; `cairn install-harness codex` wires it.

### WI-5.5 — `cairn install-harness` extended
- Extend `install-harness` (Plan 008 WI-1.2) to accept `hermes`, `agy`,
  `codex` in addition to `claude`, `opencode`, `all`. One idempotent
  command per harness; `all` wires every known harness.
- **AC:** `cairn install-harness hermes` wires the Hermes adapter on a
  clean profile; re-run is a no-op; `uninstall-harness hermes` reverses.

---

## Phase 6 — Silence is a finding (extends Plan 009 WI-4.1)

### WI-6.1 — Content-coverage gap detection
- `cairn doctor` and the verifier detect: a session attested as
  `content_capture=true` but missing content fields on events that
  should have them (prompt/response events with only digests). This is
  the content-layer analogue of Plan 009's "wired but not attesting."
- **AC:** a session that declared content capture but has digest-only
  events shows as a named gap in the verifier report and turns doctor
  red within the window.

---

## Dependencies (cross-project)

| Dependency | Plan | Status | Blocks |
|------------|------|--------|--------|
| v1 capture actually works | agent-provenance Plan 009 | Proposed | All of this plan |
| Encryption-at-rest primitive | **regista Plan 030 (new, cross-filed)** | Proposed | WI-3.2 (or cairn encrypts at app layer) |
| Multi-project fronting | dossier Plan 011 | Implemented | WI-4.1 |
| Agent-activity window | **dossier Plan 017 (exists, extend)** | Proposed | WI-4.2 |
| Per-actor Ed25519 (delegation depth binding) | regista Plan 026 | Proposed | WI-2.3 (cryptographic binding) |
| Backend-aware key custody | regista Plan 029 | Landed | WI-3.1 |
| Canonical config/secrets | regista Plan 025 | Landed | WI-3.1, WI-5.5 |

## Sequencing

1. **Plan 009 first** — do not touch this plan until v1 capture is correct and
   proven live (009 WI-2.2 live proof). This is non-negotiable.
2. **Phase 1 (scope attestation)** — can land in parallel with 009; it's
   additive schema. But the scope attestation is only *true* once content
   capture actually works, so it ships with Phase 2/3, not before.
3. **Phase 2 (schema) + Phase 3 (encryption)** — together; content without
   encryption is a regression in security posture.
4. **Phase 5 (new harnesses)** — can start in parallel with 2/3 (the
   interception-surface research, WI-5.1, is independent), but adapters
   land only after 2/3.
5. **Phase 4 (portal)** — rides on 2/3; dossier Plan 017 must land its
   session/trail views (WI-1.1/1.2) before the content view (WI-4.2).
6. **Phase 6 (gap detection)** — last; closes the honesty loop.

## What this plan does *not* do

- **Does not weaken v1's hash-don't-store guarantee for v1 fields.** Tool
  args, stdout, and file contents stay hashed. v2 adds content fields for
  prompts/responses/transcripts; it does not retrofit content into v1
  fields.
- **Does not replace the offline bundle + `cairn verify` HTML report.**
  That remains the external auditor's artifact. The portal is for
  authorized internal users browsing live.
- **Does not build a new portal project.** dossier is the portal. The
  suite posture is "fewer faces, one spine."
- **Does not claim to fix the "missing events" residual.** Content
  capture widens what's captured when configured; the operator-can-still-
  choose-silence problem (README §4) is structural and unchanged.
- **Does not make redaction a guarantee.** Redaction is best-effort
  policy; the honest stance is "captured + encrypted; review the policy."
