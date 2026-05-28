# Plan 005 — Consumer migration: substrate → regista

**Status:** Phase 2 of the cross-project rename. **Blocked until regista Plan 018 completes** and `v0.4.0` is tagged.
**Scope:** agent-provenance specifically. See `/projects/RENAME-substrate-to-regista.md` for orchestration.
**Regista refs in this repo:** 31.

---

## Pre-flight

- [ ] Regista has tagged `v0.4.0` with the rename complete.
- [ ] Tests pass on current main: `pytest -q`.
- [ ] Fresh branch: `git checkout -b rename/substrate-to-regista`.

## Why this one needs more care than other consumers

agent-provenance is the project where regista's identity / signing / attestation primitives are most tightly coupled. The `principal_id` model, the `on_behalf_of` delegation field, the `key_rotation` event flow — all of these live in regista but are *named* in agent-provenance's design docs as regista features the project relies on. Renaming will touch design docs that explicitly cite "regista's signing envelope" or "regista's event log."

Read the AGENTS.md and Plan 003 (`opencode-end-to-end-demo.md`) first to understand the framing, then sed.

## Where regista appears

- `AGENTS.md` — names regista as the cryptographic-event-log dependency
- `plans/003-opencode-end-to-end-demo.md` — references regista's signing envelope and KeyEntry model
- `plans/004-claude-code-hooks.md` — regista adapter hooks
- `reflections/*.md` — historical; do not touch

## Steps

### 1. Inventory

```bash
grep -rln '\bsubstrate\b\|\bSUBSTRATE\b\|\bSubstrate\b' \
  --include='*.py' --include='*.md' --include='*.toml' --include='*.yaml' \
  . \
  | grep -v -E 'reflections/|\.venv/|\.git/|node_modules/'
```

### 2. Update dependency declarations

`grep -n 'regista' pyproject.toml requirements*.txt 2>/dev/null` — if regista is a direct dependency, change to `regista` pinned `>=0.4.0`.

### 3. Sed pass over live files

```bash
sed -i \
  -e 's/\bsubstrate\b/regista/g' \
  -e 's/\bSUBSTRATE\b/REGISTA/g' \
  -e 's/\bSubstrate\b/Regista/g' \
  $(grep -rln '\bsubstrate\b\|\bSUBSTRATE\b\|\bSubstrate\b' \
      --include='*.py' --include='*.md' --include='*.toml' --include='*.yaml' \
      . \
      | grep -v -E 'reflections/|\.venv/|\.git/|node_modules/')
```

### 4. Code-path imports

```bash
grep -rn 'import regista\|from regista' \
  src/ tests/ 2>/dev/null \
  | grep -v -E 'node_modules/|\.venv/'
```

For each hit: `substrate` → `regista`. If imports exist (likely yes — provenance reads regista's event log), also update test fixtures that mock regista's API.

### 5. Hand-review substantive prose

Read `AGENTS.md` and active plans after sed. Provenance docs frequently use phrasing like *"regista provides X, provenance attests Y."* After rename: *"regista provides X, provenance attests Y."* Verify the sentences still parse cleanly — provenance's pairing argument with regista is load-bearing rhetoric that should survive the rename intact.

### 6. Tests

```bash
.venv/bin/pytest -q
```

If integration tests spin up regista (`from regista import Regista` or similar), they're now spinning up `regista`. Pin regista (regista) version in test dependencies to `>=0.4.0`.

### 7. Commit

```bash
git add -A
git commit -m "rename: substrate → regista (Plan 005)"
git push -u origin rename/substrate-to-regista
```

## Exit criteria

- [ ] Inventory grep returns 0 hits across live files.
- [ ] Tests green.
- [ ] Provenance's "we attest regista's events" rhetoric in docs reads as "we attest regista's events" sensibly.
- [ ] PR merged.

## Intentionally not touched

- `reflections/*.md` — historical (5+ reflections reference regista; all dated, all leave-as-is)
- `plans/001-002` — early skeleton plans, historical

## Rollback

`git revert <commit>` if needed.
