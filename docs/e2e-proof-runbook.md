# Live end-to-end provenance proof — runbook (Plan 009 WI-2.2)

This is the provenance analogue of dossier Plan 006's convergence proof.
It demonstrates that cairn captures what the harness actually emits and
that an independent party can reproduce the attested digests.

## Prerequisites

1. **Claude Code installed** and on PATH (`claude --version` works).
2. **Cairn hooks wired**: `cairn install-harness claude` (run once).
3. **Regista reachable**: `cairn doctor --json` reports `"ok": true`.
4. **Config resolved**: `~/.config/agent-suite/suite.env` or Claude Code
   `settings.json` env block with `REGISTA_DSN`, `REGISTA_KEY_PATH`,
   `CAIRN_PROJECT`.

## Running the proof

```bash
python3 scripts/e2e_proof.py
```

The script:

1. **Drives a real `claude -p` session** that reads a known file and
   runs a known Bash command (known content, known output).
2. **Queries the regista store** for the session_attestation and
   tool_call_end events from that session.
3. **Verifies the harness version** is the real installed version (not
   the synthetic `"unknown"` / `"1.0.42"`).
4. **Compares attested digests** against independently computed
   `sha256` of the real tool output (file content for Read, stdout for
   Bash).
5. **Checks the hash chain** has no broken links.

Exit code 0 = proof passed; non-zero = proof failed.

## What the proof demonstrates

- **Capture correctness (WI-1.1)**: the hook reads `tool_response`
  (the field Claude Code 2.1.200+ actually sends) and normalizes the
  real shapes (Read's nested `file.content`, Bash's `stdout`).
- **Digest reproducibility (WI-1.2)**: an auditor holding the real
  tool output can reproduce the attested digest by computing
  `sha256(output.encode("utf-8"))`.
- **Harness identity (WI-1.3)**: the attested harness version is the
  real `claude --version` output, recorded at install time.
- **Live wiring (WI-2.1)**: hooks are wired, bridge reaches regista,
  events flow end-to-end.

## Failure modes

### Regista unreachable mid-session

If regista becomes unreachable during a session (network partition,
database restart), the hook records a **degradation marker** in the
session-scoped `degradation.log` file (under `CAIRN_STATE_DIR`). The
hook does not silently drop events — the degradation log is the audit
trail for what was attempted but could not be attested.

To simulate:

```bash
# Temporarily point the bridge at an unreachable DSN
export REGISTA_DSN=postgresql://nobody@nowhere:5432/none
# Run a Claude session — degradation markers should appear
claude -p "echo test" --allowedTools Bash --max-turns 2
# Check for degradation
cat /tmp/cairn-sessions/*/degradation.log
```

### Hooks not wired, or wired but not runnable

If the hooks are missing from `settings.json`, `cairn doctor` reports
`harness_wired: fail`. No events will be attested. Run
`cairn install-harness claude` to wire them.

`harness_wired` also **executes** the hook command it finds (WI-034), so a
hook that is present but cannot run — the classic case being a bare
`python3 -m cairn._claude_hook` under an isolated install, where `python3`
resolves to an interpreter with no cairn on its import path — reports
`fail` naming the reason, instead of the `ok` it used to report while every
invocation failed. `cairn install-harness` runs the same check on the hooks
it writes and reports `degraded` (nonzero exit) rather than claiming success
for a hook nobody executed.

### Wrong field name (pre-Plan-009)

Before Plan 009, the hook read `tool_output` (which Claude Code 2.1.200+
does not send). Every attestation carried the digest of an empty string.
The proof catches this: the attested Read digest would not match the
sha256 of the real file content.

## Recorded-reality fixtures

Real Claude Code 2.1.206 hook payloads are committed in
`tests/fixtures/hook_payloads/`. These are sanitized captures from live
sessions (session IDs and paths replaced with generic values). CI runs
fixture-driven tests that verify digest reproducibility against these
recorded payloads — the tests cannot regress without a visible failure.
