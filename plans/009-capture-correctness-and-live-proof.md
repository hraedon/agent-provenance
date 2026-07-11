# Plan 009 — Capture correctness: attest what the harness actually emits

**Status:** Complete 2026-07-11. Phases 1–2 landed 2026-07-07/08 (WI-1.1/1.2/1.3
capture correctness; WI-2.1 operator install; WI-2.2 live proof). Phases 3–4
landed 2026-07-11: WI-3.1 subagent attribution (per-call `agent_id` from the
payload, verified from real 2.1.207 capture; `subagent_start`/`subagent_stop`/
`compaction` session events; PostToolBatch documented as covered by per-call
attestation — same `tool_use_id`s, attesting it would double-count) and WI-4.1
(doctor `attestation_freshness` check + verifier `SilenceGap` finding via
`cairn verify --harness-sessions`; live run surfaced 105 real pre-wiring
silent sessions and zero post-wiring ones). WI-3.2 (assistant-output/transcript
attestation) was delivered by Plan 010's `MessageDisplay`/`Stop` handlers.
Note for operators: existing installs red-out on the three new hooks until
`cairn install-harness claude` is re-run (idempotent merge).
**Author:** Claude (Fable 5), from the 2026-07-07 suite v2 gaps review
**Strategic role:** Plan 008 made attestation *installable*; this plan makes it
*true*. A verification pass on 2026-07-07 found that cairn is not capturing
harness output — not on the operator's box (hooks not wired), and not even in
principle (the Claude hook parses a field the harness does not send). The suite's
pitch is "here is the signed record of what the agents did"; today that record
would be empty or wrong. This plan fixes capture against *recorded reality*,
wires it for real, and proves it with a live session — the provenance analogue of
dossier Plan 010's §6 end-to-end proof.

## Ground truth (verified 2026-07-07)

1. **Nothing attests today.** `cairn doctor` on the operator box: config missing
   (no DSN/KEY/PROJECT), all five hooks missing from the harness settings. The
   live store confirms it: 121 events total in the provenance project, the last
   from 2026-07-04, and the only `tool_call_*` events come from a synthetic
   `human:dogfood-test` principal with harness version `"1.0.42"` — the real
   installed harness is 2.1.200. No real session has ever attested.
2. **The Claude hook reads a field that does not exist.** `_claude_hook.handle_post`
   reads `hook_input["tool_output"]`; Claude Code 2.1.200 sends `tool_response`
   (verified by `strings` on the harness binary: 16 hits for `tool_response`,
   zero for `tool_output`). Wired as-is, every attestation would carry the digest
   of an empty string, and every failure would say "tool call failed" with no
   detail.
3. **The tests encode the same wrong assumption.** `test_claude_code_hook.py`
   hand-feeds `tool_output` payloads, so CI validates the hook against its own
   fiction. This is the fixture-echoes-assumption failure mode — the same class
   the family has hit before (unit suites testing each face in isolation hid the
   workflow divergence; agent-notes' CI caught an undeclared dep that local runs
   never did).
4. **Digest semantics are undefined under truncation.** The hook truncates stdout
   to 2000 chars before bridging; the digest covers the truncated stream with no
   truncation marker. An auditor holding the real output of a long Bash run
   cannot reproduce the attested digest — the digest is unverifiable exactly when
   the output is big enough to matter.
5. **The harness surface moved under us.** Claude Code now emits far more
   lifecycle events than the five cairn handles — `PostToolBatch`,
   `SubagentStart`/`SubagentStop`, `MessageDisplay`, `Stop`/`StopFailure`,
   `PostCompact`, among others. Assistant output (what the model *said*, not just
   what tools returned) is not attested at all.

## Principles

- **Test against recorded reality, not hand-written payloads.** Every parser fix
  in this plan lands with fixtures captured from a real harness. A hand-written
  fixture may motivate a test but can never be the only one.
- **A digest an auditor cannot reproduce is not evidence.** Preimage semantics
  (what bytes, what alg, truncated or not) are part of the attestation contract.
- **Silence is a finding.** "Wired but not attesting" must be detectable by
  doctor/verifier, not discovered by querying the store by hand a week later.

---

## Phase 1 — Fix capture against recorded reality

### WI-1.1 — Real-payload fixtures + field-name fixes
- Add a capture mode to the hook (`CAIRN_CAPTURE_DIR`): when set, the raw stdin
  of every hook invocation is written verbatim to the capture dir. Run a real
  Claude Code session with capture on; sanitize; commit the payloads as fixtures.
- Fix `handle_post`/`handle_post(failure=True)` to read `tool_response` (keep
  `tool_output` as a fallback for older harnesses, one release). Verify from the
  captured payloads what `PostToolUseFailure` actually carries and parse that —
  do not guess.
- Rewrite the hook tests to run against the recorded payloads; keep synthetic
  cases only for edge conditions capture can't produce.
- **AC:** a test feeds a recorded real `PostToolUse` payload and the attested
  digest equals an independently computed sha256 of the real tool output; a
  recorded `PostToolUseFailure` payload yields an error attestation with the
  real failure detail; CI runs these fixtures.

### WI-1.2 — Digest semantics that a third party can verify
- Digest the **full** output stream (digest before truncating for transport);
  record `bytes_total`, `truncated: bool`, and the digest algorithm alongside
  `stdout_digest`. Document the preimage definition (exact bytes, encoding) in
  `docs/` so an external auditor can re-derive it.
- **AC:** for an output larger than the transport cap, the attested digest
  matches the sha256 of the complete real output; the envelope says how many
  bytes and which algorithm.

### WI-1.3 — Attest the real harness identity
- Stop defaulting the harness version to `unknown`/whatever the env says:
  resolve the actual version (from the hook payload if present, else
  `claude --version` at install time, recorded into the wiring) and attest it.
- **AC:** a live session attests the true harness version string; the synthetic
  `"1.0.42"` pattern can no longer occur silently.

## Phase 2 — Wire it and prove it live

### WI-2.1 — Actually install on the operator box
- Run `cairn install-harness claude` (and `opencode`) on the operator's machine,
  config resolved from `suite.env` per the Plan 008 contract. This is the suite's
  first real provenance deployment; it is also agent-suite Plan 004 WI-1.4 —
  coordinate, don't duplicate.
- **AC:** `cairn doctor --json` reports ok on the operator box; a fresh
  interactive session produces `session_attestation` + `tool_call_begin`/`end`
  events attributed to the real principal with the real harness version.

### WI-2.2 — Live end-to-end proof (the §6 analogue)
- A committed proof script (manual, like dossier's convergence proof): drive a
  scripted `claude -p` session that runs known tools with known outputs; then
  `cairn verify` walks the chain clean and the script compares every attested
  digest against the independently captured real outputs.
- **AC:** proof passes on the operator box and is documented as a runbook;
  failure modes (regista unreachable mid-session) show up as degradation
  markers, not silent gaps.

## Phase 3 — Cover the harness surface that moved

### WI-3.1 — Subagents, batches, compaction
- Decide and implement coverage for `SubagentStart`/`SubagentStop` (attribution:
  a subagent's tool calls must not masquerade as the parent's), `PostToolBatch`
  (document whether per-call attestation already covers it), and `PostCompact`
  (context loss is provenance-relevant: attest that compaction occurred).
- **AC:** a session that spawns a subagent yields attestations distinguishing
  parent from subagent actions; a compaction event appears in the chain.

### WI-3.2 — Assistant-output attestation (the other half of "harness output")
- Tool I/O is half the record; what the model said is the other half. On `Stop`
  (and `SessionEnd`), digest the session transcript (the harness exposes a
  transcript path) and attest it — digest-only by default, with a documented
  decision on optional content-addressed archival (size caps, redaction stance).
- **AC:** after a session, the chain contains a transcript attestation whose
  digest matches the transcript file on disk at that moment.

## Phase 4 — Silence is a finding

### WI-4.1 — Last-attestation-age check
- `cairn doctor` gains a check: harness wired but no attestation events within
  a configurable window while sessions ran → warn/fail (correlate with harness
  session logs where available). The suite umbrella already reds out on
  unconfigured cairn — keep that, and make "configured but silent" equally loud.
- **AC:** unhooking the harness while leaving config in place turns doctor red
  within the window; the verifier reports the gap as a named finding.

---

## Sequencing

WI-1.1 → 1.2 → 1.3 first (correctness before wiring — do not deploy a recorder
that records nothing). Then 2.1 → 2.2 (wire + prove). Phase 3 and 4 follow and
can interleave with agent-suite Plan 004. The live proof (2.2) is the exit
criterion: until it passes, the suite's provenance claim stays "asserted".
