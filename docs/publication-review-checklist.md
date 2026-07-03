# Publication-Review Checklist

Before flipping the repository from private to public, verify each item.

## 1. Identifier scrub

- [ ] `scripts/identifier-gate.py` exits 0 (no personal/internal identifiers in tracked files)
- [ ] Git history rewritten via `git filter-repo` to scrub author/committer identity
- [ ] No work-domain email addresses in git log (`git log --format='%ae %ce' | sort -u`)
- [ ] No internal hostnames in git history (search for known internal hostnames)
- [ ] No personal principal handles in git history (search for known handles)

## 2. Secrets

- [ ] No API keys, tokens, or passwords in tracked files
- [ ] `.claude/settings.json` is gitignored and never committed
- [ ] Test fixtures use only placeholder credentials (`regista_test:regista_test@localhost`)
- [ ] No real DSNs or connection strings in code or docs

## 3. Naming coherence

- [ ] Package name `cairn` is consistent across `pyproject.toml`, CLI, and docs
- [ ] `README.md` references `cairn` as the working name
- [ ] `SUITE.lock` references the correct GitHub org and repo
- [ ] `AGENTS.md` is up to date with current status

## 4. License and authorship

- [ ] MIT license file present
- [ ] `pyproject.toml` author is generic (`Project Owner`)
- [ ] No employer-proprietary code or references

## 5. Dependencies

- [ ] `pyproject.toml` lists all runtime dependencies
- [ ] Dev dependencies include `asn1crypto`, `pynacl`, `pytest`, `ruff`, `mypy`
- [ ] `SUITE.lock` pins regista to a specific commit SHA
- [ ] No dependency on private/internal packages

## 6. CI

- [ ] `.github/workflows/ci.yml` runs ruff + mypy + pytest
- [ ] Identifier gate runs in CI (add as a CI step)
- [ ] All tests pass on a clean checkout

## 7. Documentation

- [ ] README is coherent as a public-facing document
- [ ] No references to internal systems, employer, or internal projects
- [ ] Cross-project references (regista, agent-notes) use public URLs
- [ ] Reflections directory is clean of personal identifiers
