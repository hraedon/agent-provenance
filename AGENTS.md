# agent-provenance — Agent Guide

> **Upstream renamed 2026-05-27:** the coordination spine was previously `substrate`; it is now `regista` (Plan 005 consumer migration here, regista Plan 018 upstream). Note: `compliance-substrate` (the dormant ancestor referenced below) is a *different* project and keeps its name. Older breadcrumbs and reflections that still say "substrate" are intentional historical record.

## Status

**Skeleton complete.** Adapter, verifier, CLI, and scope attestation are in.
The next phase is harness-level interception.

If you (an agent) are picking this up, **read `README.md` first, end-to-end,
before touching anything.** The README is doing the work of a design doc; it
is not boilerplate.

## Cross-project context

This project is part of a constellation:

- **`../regista`** — the event-sourced, signed, replay-verifiable
  foundation. agent-provenance is a *consumer* of regista, not a fork.
  Trust-model improvements (asymmetric signing, delegation chain, timestamp
  anchoring) live in regista; this project tracks them as dependencies.
- **`../compliance-substrate`** — the immediate ancestor. Tabled, not
  deleted. The motivation pivot (compliance workflows → agent provenance)
  is documented in `README.md §12`.
- **`../agent-notes`** — used to file breadcrumbs (see §"Filing
  breadcrumbs" below). Has its own active gaps (BC-006 projection path,
  BC-007 query bugs) that affect agents working in this repo.
- **`../agent-wake`** — sibling project for external-to-session
  signaling. Shares the identity / multi-user design problem; joint
  open questions captured in
  `../agent-wake/design/identity-and-multi-user.md`. The user-identity
  primitive should be shared between the two (initial take: lives in
  regista, extends BC-196 asymmetric signing).

## Conventions (planned; enforce as the project takes shape)

- **Regista is the system of record.** Any state worth keeping is a
  regista event. No sidecar tables, no "convenience" mutable state in
  application Postgres or SQLite.
- **The scope statement is signed.** README §2 is load-bearing — the
  out-of-scope claim must itself be a signed first-class event in the log.
  Do not let the scope drift into README prose only.
- **Adapter, not harness.** This project integrates with existing agent
  harnesses; it does not ship its own. Resist scope creep toward becoming
  a harness.
- **MIT license, single-person OSS posture.** See README §8. Architectural
  choices should not encode a hypothetical commercial future.

## Filing breadcrumbs

Use the agent-notes `mcp__breadcrumb__file_breadcrumb` tool with
`project="agent-provenance"` (once the project is registered there — it
likely isn't yet, since the project is brand new). Known issues with the
MCP at time of writing:

- BC-006 (agent-notes): if the project doesn't have a `breadcrumbs_dir`
  configured, projections silently land in `/tmp/active/`. Until that's
  fixed, **verify the projection landed under
  `/projects/agent-provenance/breadcrumbs/` before assuming the BC is
  filed correctly.**
- BC-007 (agent-notes): `find_breadcrumbs` has a SQL parameter-binding
  bug; `query_breadcrumbs` may return empty for unregistered projects.
  Read on-disk breadcrumbs directly when in doubt.

## Regista breadcrumbs this project depends on

- **BC-196** — asymmetric signing / external verifiability. **Landed**
  (Plan 011). Ed25519 support integrated into verifier and CLI.
- **BC-197** — delegation chain (`on_behalf_of`). **Landed** (Plan 010).
  Delegation chain validation integrated into verifier.
- **BC-229** — TSA signature verification against a trust anchor. **Open.**
  Blocks full RFC 3161 timestamp verification.
- (to file) — operator-forgery defense at regista layer (RFC 3161
  timestamping — **Plan 012 landed**; witness federation — **Plan 013
  landed**; OpenTimestamps anchoring — **not yet**).

When these land in regista, revisit `README.md §4` (trust model) and the
event schema in §7.

## What to do first (when this becomes an active project)

In rough order. Do not assume any of these are done; check on entry.

1. Confirm the project owner has done the employer IP/moonlighting check
   (README §8). **Not yet confirmed — conversation pending.**
2. Pick a name. `product-concepts/001-naming.md` has the shortlist.
   **Done: using `cairn` as working name.**
3. Register the project with agent-notes (so breadcrumbs route here).
   **Not done yet; project registration blocked on agent-notes-mCP server.**
4. Sketch the v1 harness adapter for Claude Code and OpenCode as the smallest
   credible end-to-end.
   **Done: `src/cairn/adapter.py` implements `CairnAdapter.begin_tool_call` /
   `end_tool_call`, with file digests and canonical schema. Still needs actual
   harness-level interception.**
5. Write the first plan in `plans/`.
   **Done: `plans/001-skeleton.md`.**
6. Implement minimal verifier that reads a regista event log and produces
   an auditor-ready report.
   **Done: `src/cairn/verifier.py` + CLI `cairn verify`.**

## Current status (last updated 2026-05-26)

- **Tests**: 114 passing (CI depends on Postgres).
- **Lint**: ruff clean.
- **Gaps closed**: scope attestation as signed first-class event (README §2);
  opencode plugin + bridge end-to-end functional; bundle export/verify with
  control narrative; Claude Code hooks (Plan 004); session_id passthrough
  from harness to bridge (fixes audit grouping bug); `cairn diff` command
  (AP-008); self-contained HTML verification report (AP-006); FIM-class
  positioning technical report published (AP-007); SDK wrapper (`CairnClient`);
  `cairn extract-control` CLI command; key rotation event support in verifier
  (partial AP-001 — structural verification, not yet Ed25519);
  streaming file digest (hashlib chunked reads for large files);
  key file permission checker (`check_key_file_permissions`);
  Claude Code hook degradation logging (`_mark_degraded`);
  Claude Code hook settings digest in scope attestation;
  bridge `session_id` now required (no silent UUID fallback);
  `__main__.py` for `python3 -m cairn._bridge` invocation;
  Claude Code hook state dir permissions restricted to 0o700;
  **Ed25519 asymmetric signing support** (AP-001 completed, regista BC-196);
  **Delegation chain validation** (AP-003 partial, regista BC-197);
  **`cairn timestamp` CLI command** (AP-004 partial, regista Plan 012);
  **Scheme-aware verifier** (dispatches HMAC/Ed25519 per event `scheme_id`);
  **Scheme-aware reports** (text/JSON/HTML show scheme usage and delegation chains).
- **Open gaps**: project not registered with agent-notes yet; live
  opencode dogfood bundle not yet committed to repo; Claude Code hooks not
  yet tested in a live Claude Code session (mock tests only);
  TSA signature verification (BC-229); witness federation integration;
  real IdP integration for principal_id.

## What not to do

- Do not start with the SDK wrapper. Harness-level interception is v1 because
  it dogfoods on Claude Code and OpenCode; SDK is v1.5 at earliest.
- Do not build a UI in v1. Verification is CLI / static report.
- Do not implement witness federation or OpenTimestamps anchoring here.
  Those belong in regista. This project tracks them as dependencies.
- Do not let the README's §2 scope statement weaken under pressure. If
  someone — including a future agent — argues "we should also detect
  unsanctioned harness usage in v1," the answer is "that's a different
  project; this one stays narrow."

## License

MIT (planned).
