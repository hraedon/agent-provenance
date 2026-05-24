# Plan 003 — Opencode End-to-End Demo Bundle

## Status

Draft 2026-05-24.

## Goal

Produce the first real artifact a compliance reviewer could examine: a
signed bundle of tool-call events captured from a live opencode session
where the agent operated on real files, exported via `cairn export`,
and verified via `cairn verify` with the §4.2 key-management control
narrative and the §4.1 working-hypothesis caveat embedded in the
bundle itself.

This plan deliberately narrows Plan 002. Claude Code hooks move to
Plan 004. The reason is sequencing, not preference: the opencode bridge
is 60% built, in-process, and one plugin file. Finishing it produces
the demo faster than starting Claude Code from zero.

## Motivation

Plan 002 set out two-harness coverage and is half-built on both. The
2026-05-24 reflection flags the bridge as untested, the plugin as not
installable, and Claude Code as unstarted. Single-person OSS projects
die from scope sprawl, not from missing a second harness. The user's
stated goal is one real attested action defensible to their compliance
team. That goal is satisfied by one harness end-to-end with the
control narrative attached.

## What's in scope

1. **Make `cairn` installable.** Resolve the externally-managed-Python
   issue. Project-local venv documented in README; `pyproject.toml`
   exposes `cairn` and `cairn-bridge` entry points; `pipx install`
   path verified.
2. **Finish the opencode plugin.** `integrations/opencode/package.json`,
   real `@opencode-ai/plugin` dependency, installation instructions,
   loaded into a live opencode session, observed via `client.app.log`
   that tool.execute.before/after hooks fire and the bridge invokes
   without crashing.
3. **Unit test the bridge.** Mock stdin/stdout, assert correct adapter
   calls for `attest_scope`, `begin`, `end`, and error paths. Close
   the test-gap from the 2026-05-24 reflection.
4. **Bundle the control narrative.** Extend `cairn export` to embed
   the README §4.2 control description and the §4.1 working-
   hypothesis caveat as a `manifest.control_description` field in the
   bundle JSON. The string is signed as part of the bundle hash. The
   verify report surfaces both prominently.
5. **End-to-end dogfood.** Run a real opencode session that performs
   3–5 file edits, exports, verifies, and produces a bundle the user
   can read top-to-bottom. The bundle is the deliverable.
6. **First attested cross-project action.** Drive at least one
   `agent-notes-mcp` CLI invocation through opencode during the
   dogfood session so the bundle shows attestation of a sibling
   project's tool. Validates the cross-project audit story.

## What's NOT in scope

- Claude Code PreToolUse / PostToolUse hooks. Moves to Plan 004.
- Cursor, Aider, SDK wrapper. Plan 005+.
- Asymmetric signing (Ed25519). Tracked as substrate Plan 011
  dependency; verify report labels HMAC-only bundles with a working-
  hypothesis caveat.
- RFC 3161 timestamping. Substrate Plan 012 dependency.
- Delegation chain with real IdP. Substrate Plan 010 dependency.
  `principal_id` continues to stub from OS user.
- Wake-event attestation (`agent-wake` integration). Becomes a real
  plan once agent-wake has a stable signal source the bridge can
  receive; until then noted as future work.
- UI / web report. CLI bundle remains the artifact.
- Auditor validation of the bundle (README §9 open question).
  Highest-leverage research item, but a research interview is not
  this plan. Surface the unvalidated-hypothesis label in the bundle
  so the user does not accidentally over-claim during dogfooding.

## Design

### Installation surface

- `pyproject.toml` declares `cairn-bridge` console script.
- `integrations/opencode/package.json` declares the plugin module and
  installation steps.
- README "Quickstart" section: venv, env vars, opencode config edit.

### Plugin → bridge contract

Already defined in `_bridge.py`. This plan adds:
- `args` hash returned to plugin so the plugin can log it via
  `client.app.log` for in-session visibility.
- Explicit timeout on `Bun.$` invocation; on timeout, log warning
  via `client.app.log` and proceed (graceful degradation per
  Plan 002 constraint).

### Bundle control narrative embedding

`cairn export` reads `README.md §4.1` and `§4.2` at export time, hashes
the source, and embeds:

```json
{
  "manifest": {
    "control_description": "...verbatim text...",
    "control_description_source_digest": "sha256:...",
    "trust_model_caveat": "HMAC-SHA256 only; Ed25519 + RFC 3161 + witness federation are tracked as substrate Plan 011/012/013 dependencies. FIM-class positioning is a working hypothesis (README §4.1), not auditor-validated."
  }
}
```

The caveat string is mandatory until substrate plans 011/012 land and
until the auditor-validation open question (README §9) is closed.

### Cross-project attestation: agent-notes-mcp CLI

Plan 003 demo includes at least one tool call where opencode invokes
the `agent-notes` CLI (filing a breadcrumb, listing notes). This
confirms the bundle attests actions across the project boundary and
gives `agent-notes-mcp`'s CLI refactor a concrete first integration
consumer.

## Work items

1. **WI-1.** Resolve cairn install path; document venv setup;
   `pipx install .` succeeds from a clean shell.
2. **WI-2.** Write unit tests for `_bridge.py` covering all three
   actions plus error paths.
3. **WI-3.** Add `package.json` to `integrations/opencode/`; declare
   real `@opencode-ai/plugin` dependency; document install steps.
4. **WI-4.** Load plugin into live opencode session; observe hooks
   fire; iterate until the bridge invocation works.
5. **WI-5.** Extend `cairn export` to embed control_description and
   trust_model_caveat. Update `verify` to surface both.
6. **WI-6.** Run the dogfood session: 3–5 file edits + 1
   agent-notes CLI call. Export. Verify. Read the bundle top to
   bottom. Iterate until the bundle is something the user would
   hand to a compliance reviewer.
7. **WI-7.** Update README "Quickstart" and AGENTS.md "Current
   status" to reflect the dogfood result.

## Acceptance

- `pipx install .` from a clean shell produces a working `cairn`
  command.
- `pytest tests/` passes, including new bridge tests.
- An opencode session with the plugin loaded produces substrate
  events for every tool call in that session.
- `cairn export` produces a bundle containing the control
  description and the trust-model caveat.
- `cairn verify` on that bundle reports all events verifying and
  surfaces both the control description and the caveat.
- The bundle from the dogfood session is committed (or its hash
  is) so future agents can compare regressions.

## Risks

- **Opencode plugin API drift.** The plugin docs are recent.
  Mitigation: pin opencode version in the package.json and
  document tested-against version.
- **Bun.$ per-tool-call fork latency.** Acknowledged in Plan 002.
  Demo session is low-frequency enough to be unaffected; production
  consideration is deferred.
- **`getlogin()` failing in non-tty contexts.** Already a known
  failure mode of `_bridge.py`. Add a `PRINCIPAL_ID` fallback
  in the bridge and document it.
- **User over-claims during the dogfood demo.** The trust_model_caveat
  in the bundle is the structural defense against this; the user
  must show the bundle, not a screenshot of the verify summary.

## Cross-project dependencies

- **substrate**: HMAC signing (have); Plan 010 delegation chain,
  Plan 011 Ed25519 signing, Plan 012 RFC 3161 timestamping all
  drafted RFCs and *not blocking this plan* — they upgrade the
  bundle's guarantees when they land. Track as substrate breadcrumbs
  if not already filed: operator-forgery defense (witness federation)
  is BC-TBD.
- **agent-notes-mcp**: this plan is the first downstream consumer of
  the CLI refactor. Need at least one CLI subcommand stable enough
  for opencode to invoke. Coordinate timing.
- **agent-wake**: out of scope for this plan. Open future-work plan
  when agent-wake has a stable emit-event API.
- **software-factory-2**: out of scope; same pattern as agent-wake.

## Open questions

- Does the bundle's `control_description` need to be a separate
  signed substrate event (parallel to the scope attestation in
  Plan 001) rather than just a manifest field? Lean yes — it's
  the same "load-bearing claim must be a signed event" pattern
  README §2 already establishes. If yes, lift into WI-5 scope
  or split to Plan 003.5.
- Should the dogfood bundle be committed to the repo, or held
  out of band? Committing it gives reviewers something concrete;
  it also bakes in a key that should not be reused. Recommendation:
  commit with a per-demo key documented as "demo key, do not use
  for any other purpose."
