# agent-provenance — Agent Guide

## Status

**Skeleton complete.** Adapter, verifier, CLI, and scope attestation are in.
The next phase is harness-level interception.

If you (an agent) are picking this up, **read `README.md` first, end-to-end,
before touching anything.** The README is doing the work of a design doc; it
is not boilerplate.

## Cross-project context

This project is part of a constellation:

- **`../substrate`** — the event-sourced, signed, replay-verifiable
  foundation. agent-provenance is a *consumer* of substrate, not a fork.
  Trust-model improvements (asymmetric signing, delegation chain, timestamp
  anchoring) live in substrate; this project tracks them as dependencies.
- **`../compliance-substrate`** — the immediate ancestor. Tabled, not
  deleted. The motivation pivot (compliance workflows → agent provenance)
  is documented in `README.md §12`.
- **`../agent-notes-mcp`** — used to file breadcrumbs (see §"Filing
  breadcrumbs" below). Has its own active gaps (BC-006 projection path,
  BC-007 query bugs) that affect agents working in this repo.
- **`../agent-wake`** — sibling project for external-to-session
  signaling. Shares the identity / multi-user design problem; joint
  open questions captured in
  `../agent-wake/design/identity-and-multi-user.md`. The user-identity
  primitive should be shared between the two (initial take: lives in
  substrate, extends BC-196 asymmetric signing).

## Conventions (planned; enforce as the project takes shape)

- **Substrate is the system of record.** Any state worth keeping is a
  substrate event. No sidecar tables, no "convenience" mutable state in
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

Use the agent-notes-mcp `mcp__breadcrumb__file_breadcrumb` tool with
`project="agent-provenance"` (once the project is registered there — it
likely isn't yet, since the project is brand new). Known issues with the
MCP at time of writing:

- BC-006 (agent-notes-mcp): if the project doesn't have a `breadcrumbs_dir`
  configured, projections silently land in `/tmp/active/`. Until that's
  fixed, **verify the projection landed under
  `/projects/agent-provenance/breadcrumbs/` before assuming the BC is
  filed correctly.**
- BC-007 (agent-notes-mcp): `find_breadcrumbs` has a SQL parameter-binding
  bug; `query_breadcrumbs` may return empty for unregistered projects.
  Read on-disk breadcrumbs directly when in doubt.

## Substrate breadcrumbs this project depends on

- **BC-196** — asymmetric signing / external verifiability. v2 trust-model
  layers require this.
- **BC-197** — delegation chain (`on_behalf_of`). v1 event schema depends
  on this; without it, v1 falls back to self-attested `actor_metadata` and
  the audit story is materially weaker.
- (to file) — operator-forgery defense at substrate layer (RFC 3161
  timestamping + witness federation + optional OpenTimestamps).

When these land in substrate, revisit `README.md §4` (trust model) and the
event schema in §7.

## What to do first (when this becomes an active project)

In rough order. Do not assume any of these are done; check on entry.

1. Confirm the project owner has done the employer IP/moonlighting check
   (README §8). **Not yet confirmed — conversation pending.**
2. Pick a name. `product-concepts/001-naming.md` has the shortlist.
   **Done: using `cairn` as working name.**
3. Register the project with agent-notes-mcp (so breadcrumbs route here).
   **Not done yet; project registration blocked on agent-notes-mCP server.**
4. Sketch the v1 harness adapter for Claude Code and OpenCode as the smallest
   credible end-to-end.
   **Done: `src/cairn/adapter.py` implements `CairnAdapter.begin_tool_call` /
   `end_tool_call`, with file digests and canonical schema. Still needs actual
   harness-level interception.**
5. Write the first plan in `plans/`.
   **Done: `plans/001-skeleton.md`.**
6. Implement minimal verifier that reads a substrate event log and produces
   an auditor-ready report.
   **Done: `src/cairn/verifier.py` + CLI `cairn verify`.**

## Current status (last updated 2026-05-25)

- **Tests**: 36 passing (CI depends on Postgres).
- **Lint**: ruff clean.
- **Gaps closed**: scope attestation as signed first-class event (README §2);
  opencode plugin + bridge end-to-end functional; bundle export/verify with
  control narrative; Claude Code hooks (Plan 004); session_id passthrough
  from harness to bridge (fixes audit grouping bug).
- **Open gaps**: project not registered with agent-notes-mcp yet; live
  opencode dogfood bundle not yet committed to repo; Claude Code hooks not
  yet tested in a live Claude Code session (mock tests only).

## What not to do

- Do not start with the SDK wrapper. Harness-level interception is v1 because
  it dogfoods on Claude Code and OpenCode; SDK is v1.5 at earliest.
- Do not build a UI in v1. Verification is CLI / static report.
- Do not implement asymmetric signing or transparency-log anchoring here.
  Those belong in substrate. This project tracks them as dependencies.
- Do not let the README's §2 scope statement weaken under pressure. If
  someone — including a future agent — argues "we should also detect
  unsanctioned harness usage in v1," the answer is "that's a different
  project; this one stays narrow."

## License

MIT (planned).
