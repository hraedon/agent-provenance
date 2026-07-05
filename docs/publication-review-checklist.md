# Publication-Review Checklist

Before flipping the repository from private to public, verify each item.

**Status legend:**
- `[x]` — verified clean
- `[ ]` — not yet verified / action needed
- `[~]` — partially verified, caveat noted

---

## 1. Identifier scrub

- [x] `CAIRN_FORBIDDEN_IDENTIFIERS="$(cat .identifiers-denylist.local)" python3 scripts/check_committed_identifiers.py` exits 0 (denylist is never committed — gpo-lens pattern; set the repo secret in CI and run `scripts/install-git-hooks.sh` for the local pre-commit gate)
- [x] Always-on `samples/` guard active — no tracked file under `samples/` (catches `git add -f` bypass of `.gitignore`)
- [~] Git history rewritten via `git filter-repo` to scrub author/committer identity — **author/committer identity is already generic** (`cairn@users.noreply.github.com`), but **23 identifier leaks remain in git history** (commit messages, reflection files, deleted `identifier-gate.py`). See `docs/history-identifier-audit.md` for the full dry-run report. **Destructive scrub NOT yet run** (per task instructions — dry-run + report only). The `scripts/filter-repo-replacements.txt` file is prepared for the future scrub.
- [x] No work-domain email addresses in git log (`git log --format='%ae %ce' | sort -u` → `cairn@users.noreply.github.com` only)
- [~] No internal hostnames in git history — **working tree is clean**, but one internal DB hostname appears in 1 historical commit. See audit report.
- [~] No personal principal handles in git history — **working tree is clean**, but real principal_id handles and the personal email appear in historical commits. See audit report.
- [~] Denylist covers ALL identifier forms per adcs-lens WI-010 lesson — **yes**: hostnames (FQDN + NetBIOS + short), AD domain, email, personal name (surname), principal_id handles, DB service accounts, internal DB hostname. 18 identifiers total.

## 2. Secrets

- [x] No API keys, tokens, or passwords in tracked files
- [x] `.claude/settings.json` is gitignored and never committed (verified: `git ls-files .claude/` returns nothing)
- [x] Test fixtures use only placeholder credentials (`regista_test:regista_test@localhost`)
- [x] No real DSNs or connection strings in code or docs (`.claude/settings.json` has a real DSN but is gitignored)

## 3. Naming coherence

- [x] Package name `cairn` is consistent across `pyproject.toml`, CLI, and docs
- [x] `README.md` references `cairn` as the working name
- [~] `SUITE.lock` references the correct GitHub org and repo — **but the GitHub org name (which also matches the internal domain) appears in `SUITE.lock` and `pyproject.toml`**. When the repo flips public, the GitHub URL will expose the org name anyway. Consider migrating to a generic org name before the flip.
- [x] `AGENTS.md` is up to date with current status

## 4. License and authorship

- [x] MIT license file present
- [x] `pyproject.toml` author is generic (`Project Owner`)
- [x] No employer-proprietary code or references

## 5. Dependencies

- [x] `pyproject.toml` lists all runtime dependencies
- [x] Dev dependencies include `asn1crypto`, `pynacl`, `pytest`, `ruff`, `mypy`
- [x] `SUITE.lock` pins regista to a specific commit SHA
- [~] No dependency on private/internal packages — **regista is a sibling private repo** (`github.com/hraedon/regista`). It must flip public before or simultaneously with agent-provenance, or the CI `pip install` will fail.

## 6. CI

- [x] `.github/workflows/ci.yml` runs ruff + mypy + pytest
- [x] Identifier gate runs in CI (with always-on `samples/` guard)
- [~] All tests pass on a clean checkout — **verified locally** (217 Python + 27 Bun); CI green pending push

## 7. Documentation

- [x] README is coherent as a public-facing document
- [~] No references to internal systems, employer, or internal projects — **the GitHub org name (which matches the internal domain) appears in `pyproject.toml`, `SUITE.lock`, and `plans/008`**. This is the GitHub org name, which will be public in the URL anyway, but it correlates with the internal domain.
- [~] Cross-project references (regista, agent-notes) use public URLs — **regista is still private**; URLs will resolve once regista flips public.
- [x] Reflections directory is clean of personal identifiers (verified by identifier gate)

---

## Remaining blockers before public flip

1. **Git history scrub** — 23 identifier leaks in history (see `docs/history-identifier-audit.md`, gitignored). Run `git filter-repo --replace-text scripts/filter-repo-replacements.txt` (also gitignored) followed by GitHub repo delete+recreate (per adcs-lens WI-010 lesson: force-push alone leaves pushed refs).
2. **regista repo** — must flip public before or simultaneously with agent-provenance (CI depends on `pip install` from the regista git URL). regista has 1632 identifier leaks in its own history (see the audit report in the regista repo).
3. **GitHub org name** — the org name correlates with the internal domain. Consider migrating to a generic org name before the flip.
4. **Employer IP/moonlighting check** — README §8. Not yet confirmed.