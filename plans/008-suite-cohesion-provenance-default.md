# Plan 008 — Suite cohesion: provenance on by default

**Status:** Proposed 2026-07-02
**Author:** Claude (Fable 5), from the 2026-07-02 agent-suite deployment review
**Strategic role:** agent-provenance (`cairn`) is the compliance keystone — the
reason a regulated shop can adopt the suite at all. For that value to be real in
a deployment, attestation has to be **on by default**, wired at install time
across the sanctioned harness(es), not an opt-in a busy operator forgets. That
means finishing the Claude Code hooks that Plan 004 left open, adopting the shared
config/doctor contracts, and making "every agent action is attested" a property of
the suite install rather than a manual step. See `/projects/agent-suite-blueprint.md`
(Phase C).

## Ground truth at time of writing

- agent-provenance is private (`hraedon/agent-provenance`), built on regista.
  Skeleton + adapter (`CairnAdapter`) + verifier (`cairn verify`/`export`) +
  regista workflow are in place; scope attestation is a signed first-class event;
  the **opencode plugin + Python bridge are end-to-end functional**.
- **Claude Code hooks remain open** (Plan 004) — so on the harness most likely to
  be sanctioned at work, attestation is not yet wired by default. A working
  branch `fix/verifier-global-hash-chain` is ahead of origin (verifier walks the
  global hash chain, session attestation in bridge/plugin).
- Config uses cairn-private names: `CAIRN_DSN`, `CAIRN_KEY_PATH`, `CAIRN_PROJECT`,
  `CAIRN_HARNESS_NAME`/`_VERSION`, `CAIRN_DISABLE` — the same three shared facts
  as the rest, under private names.
- Per memory: acb's `exec` path is already attested via cairn's harness
  interception bound to the ambient work_item_id — so the provenance/capability
  composition is proven; it just isn't uniformly wired.

## Principles this plan must hold

- **Default-on, explicit-off.** Attestation is the point; the install turns it on.
  `CAIRN_DISABLE` remains the deliberate, audit-visible escape hatch — off is a
  choice someone makes and it's recorded, not the accidental default.
- **Attest the action, don't gate it.** cairn observes and records; it must not
  become a bottleneck that blocks the agent if regista is briefly unreachable —
  it queues/flags and the verifier surfaces any gap, the same flag-don't-block
  discipline the family holds. A gap in the chain is a *finding*, never silent.
- **Adopt the shared facts.** Converge `CAIRN_DSN`/`CAIRN_KEY_PATH` onto
  `REGISTA_DSN`/`REGISTA_KEY_PATH` (regista Plan 025), one-release alias;
  `CAIRN_PROJECT` and the harness identity vars stay cairn's.

---

## Phase 1 — Finish the Claude Code hooks (close Plan 004)

### WI-1.1 — Claude Code interception at parity with opencode
- Implement the Claude Code hook path so agent actions attest into regista the way
  the opencode plugin already does — session start/stop, tool invocations, the
  ambient work_item_id binding. Bring the working-branch session-attestation work
  to a reviewed, merged state.
- **AC:** a Claude Code session produces the same signed attestation events an
  opencode session does; `cairn verify` walks the resulting chain clean; the
  binding to the ambient work_item_id is present in both harnesses.

### WI-1.2 — `cairn install-harness <claude|opencode>`
- One idempotent command that wires cairn's interception into a named harness
  (hooks/plugin + the default-on env), mirroring agent-notes Plan 017 WI-2.1 so
  the suite has *one* harness-install idiom. Re-runnable; `--dry-run`;
  `uninstall-harness` reverses.
- **AC:** on a clean profile, `install-harness claude` yields a session whose
  actions attest by default; re-run is a no-op; disabling requires an explicit,
  logged `CAIRN_DISABLE`.

## Phase 2 — Adopt the suite contracts

### WI-2.1 — Canonical `REGISTA_*` + `doctor --json`
- Read DSN/key via the suite precedence (prefer `REGISTA_*`, fall back to
  `CAIRN_*` with a deprecation warning). Conform `doctor` to the suite shape:
  `{component:"cairn", version, regista:{reachable, project, chain_ok},
  checks:[harness wired, interception active, key present, verifier chain intact,
  …]}`.
- **AC:** operates reading only `suite.env`; legacy vars warn; `doctor --json`
  validates against the suite shape; an unreachable regista is a clean status.

## Phase 3 — The audit-story closeout

### WI-3.1 — Verifier gap-report for the deployment
- `cairn verify --since DATE --json`: a deployment-level integrity report the
  suite-doctor and an auditor consume — chain intact / N attestations / any gaps
  (sessions that ran without attesting) named explicitly. A gap is the exact
  failure a regulated audit cares about; it must be surfaced, not smoothed.
- **AC:** a clean run reports intact; a deliberately un-attested action shows as a
  named gap; the report runs offline against the store with no live harness.

### WI-3.2 — Pin + package
- Pin regista to the `SUITE.lock` SHA; document the install so a fresh sanctioned
  machine ends with attestation-on across the chosen harness(es).
- **AC:** fresh install resolves the locked regista; the documented flow yields a
  machine where a new agent session attests by default.

## Phase 4 — Cross-platform, secrets, publication

### WI-4.1 — Resolve secrets through the backend; Windows hooks
- Resolve DSN password / signing key via `regista.secrets.resolve` (Plan 025
  WI-1.2). Ensure the harness interception works on **Windows** as well as Linux —
  the Claude Code hook path (WI-1.1) and the opencode plugin must both attest from
  a Windows host, since a Windows/Entra estate is a live deployment target.
- **AC:** cairn resolves its signing key from each backend (gated tests); a
  Windows Claude Code session attests the same as a Linux one; no plaintext key on
  disk.

### WI-4.2 — Publication gate (sanitize before flipping public)
- Before agent-provenance flips public (blueprint §3): filter-repo scrub, CI
  identifier-gate, publication-review checklist, and finalize the working-name /
  `cairn` naming so the public repo is coherent.
- **AC:** history clean of work-domain identifiers (verified); identifier gate
  green; checklist complete before the flip.

## Sequencing & notes

- **Harness note (2026-07-02, revised):** work deployment is Claude-first, which
  makes WI-1.1 (finish the **Claude Code** hooks) the priority — but the operator
  runs **both harnesses locally**, and the opencode plugin already works, so it is
  **kept at parity, not sidelined**: a dual-harness validation confirms the cohesion
  changes (config vocabulary, secret resolution) don't regress the existing opencode
  attestation path. Both testable locally, so keeping opencode green is cheap.
- Depends on regista Plan 025 (config + secrets + `provision` + doctor contract).
- **WI-1.1 (Claude hooks) is the gating item** — attestation on the likely-
  sanctioned harness is the difference between the suite *having* a compliance
  story and *claiming* one. Do it first.
- Coordinate the `install-harness` idiom with agent-notes Plan 017 WI-2.1 and acb
  Plan 005 so the three harness-wiring commands share one shape (ideally one
  suite-level `install-harness` that calls each) rather than three dialects — a
  detail for the suite repo (blueprint Phase E) to unify.
- The working name is still "agent-provenance"; the tool is `cairn`. A rename
  decision is orthogonal to this plan.
