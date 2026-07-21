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
- **`../agent-notes`** — the agent face for filing work items (see §"Work
  tracking (issues)" below).
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

## Build / test / lint

```bash
make dev            # install deps against the SUITE.lock-locked substrate (Plan 019 B2)
make test           # pytest (Postgres-dependent tests skip without a DSN)
make lint           # ruff check src tests
make typecheck      # mypy src
```

**Develop against the locked substrate.** `SUITE.lock` is the single source of
truth for *what to develop against*: `make dev` (and CI) install regista at the
released version it pins, not `main`/an editable checkout, so integration skew
surfaces before interop time. For deliberate cross-member work, set
`DEV_AGAINST=main|<ref>|sibling`. See `docs/develop-against-lock.md`.

## Work tracking (issues)

Work-items for this project live in **regista** — the single source of truth. regista is the authoritative, signed, hash-chained event log; the local agent-notes store is a read projection of it. **Do not create physical breadcrumb files** (`breadcrumbs/`, `*.breadcrumb.md`) — those are retired. (This also retires the old `mcp__breadcrumb__file_breadcrumb` MCP tool and the `breadcrumbs_dir`/`/tmp/active/` projection expectation — file via the CLI instead.)

**Agent face — the `agent-notes` CLI (and the `/file-breadcrumb` etc. skills).** Run from the project root so `--path .` resolves this project; the CLI routes to this project's regista schema automatically (you never set the schema). If the project isn't registered with agent-notes yet, run `agent-notes init .` first (idempotent).

```
# File an issue
agent-notes breadcrumb file --path . --title "<short title>" \
    --type <kind> [--severity low|medium|high|critical] [--body "<details>"]

# Find / show / update
agent-notes breadcrumb find  --path . [--status open] [--type bug] [--text "<q>"]
agent-notes breadcrumb get   --path . <WI-id>
agent-notes breadcrumb update --path . <WI-id> [--status <state>] [--title ...] [--body ...]
```

- **`--type` (kind):** todo, observation, decision, risk, task, bug, feature, improvement, question, experiment, spike, refactor, docs, ci, job.
- **`--severity`:** low, medium, high, critical.

**Lifecycle (canonical workflow):** `open → in_progress → (blocked | deferred) → in_review → in_human_review → done`. `done` is reachable only through the two-stage review gate (a cross-lineage adversarial-review pass, then accept), except a pre-work `close_from_open` dismissal (won't-fix / duplicate). "Who's working this" is a regista **claim** (a separate liveness axis), not a lifecycle state.

**Human face:** dossier — the web window onto these same items (when deployed).

## Regista breadcrumbs this project depends on

- **BC-196** — asymmetric signing / external verifiability. **Landed**
  (Plan 011). Ed25519 support integrated into verifier and CLI.
- **BC-197** — delegation chain (`on_behalf_of`). **Landed** (Plan 010).
  Delegation chain validation integrated into verifier.
- **BC-229** — TSA signature verification against a trust anchor. **Landed.**
  CMS signature + certificate chain verification in regista; cairn
  verifier accepts `--tsa-cert` for trust anchor, reports verified/failed
  status per batch.
- (to file) — operator-forgery defense at regista layer (RFC 3161
  timestamping — **Plan 012 landed**; witness federation — **Plan 013
  landed**; witness coverage check in cairn — **done**; OpenTimestamps
  anchoring — **not yet**).

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

## Current status (last updated 2026-07-04)

- **Tests**: 217 Python passing (12 skipped — Postgres-dependent)
  + 27 Bun tests for the OpenCode plugin (helpers + BC-022 integration +
  WI-024 in-flight persistence/recovery coverage).
  asn1crypto + pynacl in dev dependencies.
- **Lint**: ruff clean; mypy clean (pre-existing regista import-untyped errors only).
- **CI**: `.github/workflows/ci.yml` — Python job (ruff + mypy + pytest + identifier-gate)
  and a Bun job (`bun test` in `integrations/opencode`) + `Makefile`.
- **Gaps closed this session**: WI-001 (test hangs — regista pool retries auth
  failures indefinitely; added `_postgres_reachable` pre-check with one-shot
  `psycopg.connect(connect_timeout=2)` so fixtures skip fast; helpers
  centralized in `tests/_dbutil.py`, conftest is single source for
  `regista_instance`/`dsn`/`project`); WI-024 (OpenCode plugin in-flight work
  items lost on restart — persisted to per-session `inflight/<sha256(key)>.json`
  files, recovered on startup with staleness sweep; collision-free filenames,
  failed-end entries kept for recovery; 3 new JS tests).
- **Adversarial review this session**: two parallel reviewers (kimi + glm)
  on WI-024 + test-hang fix. Findings addressed: collision-free SHA-256
  filenames (was lossy `safeName`), failed-end file retention (was
  unconditionally deleted breaking recovery), sessionId validation against
  directory, fixture dedup (removed 3 duplicate `regista_instance` overrides),
  import fragility (`from tests.conftest` → `tests/_dbutil.py` plain module),
  persistence-failure degradation logging, config whitespace robustness.
- **Verified in_review**: WI-013/WI-016/WI-018/WI-020/WI-021/WI-022/WI-023
  implementation confirmed present; remain in_review for cross-lineage
  adversarial accept (strict gate blocks same-actor self-review).
- **Plan 008 status**: All WIs complete. WI-1.1 (Claude Code hook parity),
  WI-1.2 (install-harness/uninstall-harness CLI), WI-2.1 (REGISTA_*/CAIRN_* config
  precedence + doctor --json), WI-3.1 (attestation gap detection + verify_bundle_filtered
  with --since/--until), WI-3.2 (SUITE.lock), WI-4.1 (secrets resolution via
  regista._secrets.resolve + Windows compatibility), WI-4.2 (publication gate —
  identifier scrub, CI identifier-gate, publication checklist, git history scrub).
- **Gaps closed this session**: Plan 008 WI-1.2/2.1/3.1/3.2/4.1/4.2; BC-018
  (global_seq gap false positives in filtered bundles — resolved);
  pre-existing test failures (installed asn1crypto + pynacl);
  identifier scrub (personal handles→generic, internal service accounts→generic,
  absolute paths→relative, git history rewritten).
- **Gaps closed this session**: BC-022 (OpenCode plugin no longer silently loses tool-call end
  events on bridge failure — durable per-session `degradation.log` mirroring the Claude Code
  hook's `_mark_degraded`; bounded FIFO session map with eviction-recorded orphans; begin
  failures also recorded; 24 Bun tests incl. two integration tests that drive the real plugin
  through a fake bridge; CI now gates the JS suite). Verified-stale this session: BC-019
  (scheme_counts merge across `verify_bundle_chain` — already implemented at
  `verifier.py:1597`); WI-001 (tests-hang — 154 Python tests pass). Verified-still-blocked:
  BC-016 (witness signature verification — regista registers no witness public key, so there is
  nothing to verify against; blocked on regista asymmetric witness signing).
- **Gaps closed this session**: WI-004 (PostgresEventStore allocate_seq race
  for non-work-item entities — advisory lock with signed int64 key);
  WI-005/WI-006 (_events.py append_event diverges from _events_api.py —
  entity_kind parameter, global chain head wired through EventStore);
  WI-007 (verifier chain/sequence checks group by (entity_kind, entity_id));
  WI-008 (verify_event_with_public_key omits global_seq);
  WI-009 (OpenCode plugin calls attest_session on session start);
  WI-003 (duplicate of WI-004, closed);
  InMemory _entity_seqs keyed by (entity_kind, entity_id) instead of UUID only;
  advisory lock signed int64 conversion (prevents bigint overflow);
  global hash chain head management moved into PostgresEventStore.append and
  InMemoryEventStore.append (closes the tamper-evidence gap for non-work-item
  entities); OpenCode plugin session-start degradation uses real session ID.
- **Gaps closed previously**: BC-020 (temporal ordering only checks TSA-covered
  events); BC-021 (export warns on timestamp/witness load failure); BC-003
  (bundle chain-linking via `--previous-bundle` + auto-linking state file);
  AP-010 (CLI test coverage: 9 new tests for verify, verify-chain, diff,
  extract-control, error paths, Ed25519 key loading);
  WI-001 partial (CI pipeline added, but Postgres-dependent tests still skip);
  verifier.py split into verifier_types.py (339 lines), verifier_report.py
  (1126 lines), verifier.py (1749 lines);
  frozen dataclass mutable fields changed to tuples;
  verify_bundle_chain TOCTOU fixed (single file read);
  symlink detection + fail-closed key permission enforcement;
  atomic state file writes; encoding validation; log.warn→warning.
- **Gaps closed previously**: BC-012 (malformed attested_at timestamp);
  BC-011 (uncaught exceptions on malformed bundles); BC-014 (chain integrity
  over-claiming for single bundles); AP-009 (single source of truth for version);
  AP-011 (HTML report missing key rotations and key revocations);
  scheme_counts + witness fields merge in verify_bundle_chain.
- **Gaps closed earlier**: scope attestation as signed first-class event (README §2);
  opencode plugin + bridge end-to-end functional; bundle export/verify with
  control narrative; Claude Code hooks (Plan 004); session_id passthrough
  from harness to bridge (fixes audit grouping bug); `cairn diff` command
  (AP-008); self-contained HTML verification report (AP-006); FIM-class
  positioning technical report published (AP-007); SDK wrapper (`CairnClient`);
  `cairn extract-control` CLI command; key rotation event support in verifier
  (AP-001 completed, Ed25519);
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
  **Scheme-aware reports** (text/JSON/HTML show scheme usage and delegation chains);
  **TSA signature verification against trust anchor** (BC-229 completed);
  **Witness federation coverage check** (bundle export + verifier);
  **OpenCode plugin live end-to-end** (Node.js bridge, UUID v5 session IDs).
  **Claude Code hook parity** (Plan 008 W-1.1 — hook now calls attest_session,
  matching the opencode plugin's structurally distinct session entity path);
  **Review assurance levels** (Plan 027 WI-1.2 — AssuranceLevel closed set
  computed from signed events, surfaced in text/JSON/HTML reports).
- **Open gaps**: live opencode dogfood bundle not yet committed to repo;
  Claude Code hooks not yet tested in a live Claude Code session (mock tests only);
  real IdP integration for principal_id; BC-016 (witness signatures not
  cryptographically verified — blocked on regista asymmetric witness signing);
  BC-005 (scope attestation uses tool_call transitions — Claude Code hook
  now uses attest_session; attest_scope method still exists, blocked on
  regista Plan 016); BC-019 (verify_bundle_chain scheme_counts merge — stale,
  already implemented);
  WI-001 remaining (test_client.py hangs — test_cairn.py now passes);
  WI-002 (cross-component meaning contracts as conformance-tested artifacts);
  WI-010 (PostgresEventStore.append returns Event without DB-assigned
  global_seq/prev_global_event_hash — pre-existing, exposed by session work);
  WI-011 (missing test coverage for session entity paths: concurrency,
  event handler, mixed entity kinds);
  WI-012 (CAIRN_ATTEST_ON_START env check treats any non-empty string as true);
  WI-018 (opencode plugin attest_session omits harness_config_digests —
  parity gap with Claude Code hook).

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
