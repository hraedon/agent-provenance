# Plan 006 — Live Dogfood and Committed Bundle (the deliverable)

**Status:** proposed 2026-05-28
**Author:** Opus 4.8 (portfolio review)
**Supersedes the open work in:** Plan 003 WI-6 (opencode dogfood) and Plan 004 (Claude Code hooks live test).
**Strategic role:** This is Track 1 of the 3-week grant plan — the vertical
slice that turns built infrastructure into a thing the operator can hand to a
compliance reviewer.

## Why this plan exists

Per AGENTS.md "Current status (2026-05-28)", everything needed for the bundle
is already built and tested: Ed25519 verifier, delegation-chain validation, TSA
verification (BC-229), witness-federation coverage, `cairn export`/`verify`
with the control narrative, the opencode plugin live-wired, and Claude Code
hooks. 132 tests pass.

But the three named open gaps are *all validation, not construction*:

1. Project not registered with agent-notes.
2. **Live opencode dogfood bundle not yet committed to the repo.**
3. **Claude Code hooks not yet tested in a live Claude Code session (mock tests only).**

The honest read: this project has been built well past the point of being
demonstrated. The single highest-value move is to **run it for real and keep
the artifact.** No new capability is required to produce the deliverable the
operator's whole portfolio is pointed at.

## Goal

A committed, signed, externally-verifiable bundle — produced from at least one
real opencode session **and** one real Claude Code session — that a compliance
reviewer could read top to bottom. The bundle includes the trust-model caveat
on its face and at least one attested cross-project action (an `agent-notes`
CLI call).

## Scope

### WI-1 — Register and wire prerequisites
- Register `agent-provenance` with agent-notes so breadcrumbs route here.
- Confirm `pipx install .` / project venv produces a working `cairn` from a
  clean shell (Plan 003 WI-1 — verify it still holds post-rename).
- Generate a **dedicated demo key** documented as "demo key, do not reuse."
  Use Ed25519 (not HMAC) so the committed bundle is externally verifiable with
  only the public key — this is the point of the slice.

### WI-2 — opencode live dogfood
- Load the plugin into a live opencode session.
- Perform 3–5 real file edits **plus at least one `agent-notes` CLI invocation**
  (file a breadcrumb or list memories) so the bundle attests a cross-project
  action.
- `cairn export` → `cairn verify`. Read the bundle end to end.
- Commit the bundle (or its hash + the demo public key) under
  `docs/bundles/2026-05-DD-opencode/`.

### WI-3 — Claude Code live dogfood
- Install the PreToolUse/PostToolUse hooks against a real `claude` session
  (this is the gap Plan 004 left — mock tests only).
- Same exercise: 3–5 edits + one cross-project call.
- Watch for the three things mock tests can't catch: hook payload-format drift,
  per-hook latency / degradation.log entries, session_id grouping correctness.
- Commit the second bundle under `docs/bundles/2026-05-DD-claude/`.

### WI-4 — Bundle quality pass
- Verify the trust-model caveat is present and accurate in **both** bundles. If
  regista Plan 019 (transparency-log anchoring) has landed, update the caveat to
  cite the anchor and downgrade the "not auditor-validated" language accordingly.
- Confirm `cairn verify --tsa-cert ...` reports per-batch timestamp status and
  that the HTML report renders the control narrative prominently.

### WI-5 — Document the result
- Update README "Quickstart" and AGENTS.md "Current status" to say the dogfood
  is done and point to the committed bundles.
- Write a one-page `docs/READING-THE-BUNDLE.md` aimed at a non-technical
  reviewer: what each section proves, what the caveat means, what it does not
  claim.

## Acceptance

- Two bundles committed (opencode + Claude Code), each from a real session.
- Each verifies clean with `cairn verify` using **only the public key** (no DB,
  no signing secret) on a fresh checkout.
- Each contains ≥1 attested `agent-notes` CLI action.
- Each carries an accurate, embedded trust-model caveat.
- `docs/READING-THE-BUNDLE.md` exists and a non-technical reader can follow it.

## Sequencing & dependencies

- **Independent of everything except regista Plan 019 for the caveat wording** —
  and even that is optional (the bundle ships with the stronger or weaker caveat
  depending on whether 019 has landed). Do not block this plan on 019.
- agent-notes must be reachable for the cross-project call (it is — daily-used).
- This is the **critical-path deliverable.** Start it first; it is days, not weeks.

## Explicit non-goals

- No new verifier capability. No SDK work. No UI beyond the existing HTML report.
- No second-IdP / real principal_id integration (separate, later).
- Resist any "while we're here, also detect unsanctioned harness usage" creep —
  AGENTS.md "What not to do" stands.
