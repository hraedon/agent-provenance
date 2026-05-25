---
model: deepseek-v4-pro
datetime: 2026-05-25T16:30UTC
project: agent-provenance
---

# Session Reflection — 2026-05-25

**Work summary:** Adversarial review of the full codebase (schema, adapter,
verifier, bridge, CLI, Claude Code hook, OpenCode plugin). Found and fixed 4
bugs: a critical verifier integrity pass-through, a hash canonicalization
mismatch between bridge and adapter, a silent fallback returning an empty hash,
and a file-handle lifecycle bug in the bridge.

---

## On the project

The project's scope discipline is its strongest asset: it knows exactly what it
is (an audit layer) and loudly states what it is not (an enforcement layer, a
harness, a transparency log). The code reflects that clarity — it's lean, the
schema is straightforward, and the substrate dependency is used as a
system-of-record rather than a crutch.

The trust-model stack (HMAC → delegation → timestamp → Ed25519 → witness →
OpenTimestamps) is well-reasoned, but the codebase is currently pinned at layer
1. This is fine — the README is honest about it — but every audit-facing
component (verifier, export, report) carries a caveat that will need updating
when layers 2–6 land in substrate.

The decision to keep the OpenCode plugin as a thin TypeScript wrapper around
the Python bridge is the right one for a small project. Duplicating hashing,
canonicalization, and signing logic in JS would be a maintenance nightmare.

## On the work done

Found four bugs of varying severity through adversarial reading rather than
automation:

1. **BC-001 (critical, pre-existing):** `verify_bundle()` set `bundle_hash_ok =
   True` unconditionally after `_verify_bundle_hash()` returned `None`. A
   bundle without a hash field passed integrity verification. The fix
   introduces a tristate return (`True | False | None`) so the verifier can
   distinguish "hash OK", "hash mismatch", and "no hash present."

2. **BC-007 (high):** Bridge used `json.dumps` → `sha256` for args hash; adapter
   used RFC 8785 `canonicalize()` → `sha256`. Different digests for same
   input. Replaced with shared `hash_payload()`.

3. **BC-008 (medium):** `_resolve_begin_payload()` fallback returned
   `tool_args_hash: ""` — a silent corruption of the end event. Changed to
   `"sha256:undefined"`.

4. **BC-009 (low):** Module-level `/dev/null` handle closed in `finally`, breaking
   multi-invoke in-process (tests). Removed the close.

All 39 tests still pass, ruff clean. I'm confident in fixes 2–4. Fix 1 required
a judgment call — `all_ok` now treats absent hash as non-blocking but surfaces
it in the report. This preserves the existing API (`verify_events()` doesn't
deal with bundles) while making the failure mode visible and the report
accurate.

## On what remains

**Needed before shipping:**
- BC-002, BC-004, BC-005 (open security breadcrumbs) — these are the audit
  credibility blockers. BC-002 (HMAC secret required for verification) is the
  hardest; it depends on substrate BC-196 (asymmetric signing).
- BC-003 — bundle chain-linking (`previous_bundle_hash`) is missing from
  export. Without it, an attacker can substitute an older clean bundle.
- BC-006 — `config_digest` in Claude Code scope attestation was claimed in
  README but never implemented.

**Sequencing:** BC-003 is the easiest to fix and would close the most
egregious integrity gap. BC-002 requires substrate changes. BC-004 and BC-005
are design choices masquerading as bugs — decide whether they're acceptable v1
behavior and document the decision.

**Nice to have:**
- Live Claude Code session test (Plan 004 says hook tests are mock-only).
- CI pipeline (Postgres-dependent, like substrate's pattern).
- `integration/opencode/` has a `BRIDGE_TIMEOUT_MS` env var that's defined but
  never used — dead code.

## Gaps to flag

- `src/cairn/verifier.py:163` — The tristate fix is correct but `_verify_bundle_hash` still uses `json.dumps(sort_keys=True)` for the bundle hash, while other hashing uses RFC 8785 canonicalize. These are conceptually the same for the bundle manifest structure (all string/primitive values), but it's a consistency gap worth noting.
- `integrations/opencode/index.js:26` — `BRIDGE_TIMEOUT_MS` is parsed but never passed to `Bun.spawn()` or any timeout mechanism. The bridge call can hang indefinitely.
- `integrations/opencode/index.js:71` — `const sessionMap = new Map()` is allocated per-plugin-instantiation. If `tool.execute.after` is never called (e.g., harness crash), stale entries accumulate indefinitely — no TTL or cleanup.
- `tests/test_bridge.py` — All bridge tests mock Substrate and CairnAdapter at the class level. No integration test verifies that the bridge's canonicalization, env-var parsing, and JSON I/O work end-to-end against real substrate.
