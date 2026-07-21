.PHONY: dev lint typecheck test test-all all

## Install deps against the SUITE.lock-locked substrate (Plan 019 B2)
# Installs regista at the released version pinned in SUITE.lock (the single
# source of truth for what to develop against), then `-e .[dev]`. Same install
# shape CI uses. Override the substrate deliberately with
# DEV_AGAINST=main|<ref>|sibling (see docs/develop-against-lock.md).
dev:
	python scripts/dev-install.py

## Lint with ruff
lint:
	ruff check src tests

## Type check with mypy (strict, configured in pyproject.toml)
typecheck:
	mypy src

## Run tests (Postgres-dependent tests skip automatically)
test:
	pytest --tb=short -q

## Run OpenCode plugin (Bun) tests
test-js:
	cd integrations/opencode && bun test

## Run all tests including Postgres-dependent ones (requires a running Postgres)
test-all:
	@command -v pg_isready >/dev/null 2>&1 || echo "WARNING: pg_isready not found — Postgres tests will skip."
	REGISTA_TEST_DSN=$${REGISTA_TEST_DSN:-postgresql://regista_test:regista_test@localhost/regista_test} pytest --tb=short -q

## Lint, type-check, and run tests
all: lint typecheck test test-js
