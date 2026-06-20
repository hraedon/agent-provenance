.PHONY: lint typecheck test test-all all

## Lint with ruff
lint:
	ruff check src tests

## Type check with mypy (strict, configured in pyproject.toml)
typecheck:
	mypy src

## Run tests (Postgres-dependent tests skip automatically)
test:
	pytest --tb=short -q

## Run all tests including Postgres-dependent ones (requires a running Postgres)
test-all:
	@command -v pg_isready >/dev/null 2>&1 || echo "WARNING: pg_isready not found — Postgres tests will skip."
	REGISTA_TEST_DSN=$${REGISTA_TEST_DSN:-postgresql://regista_test:regista_test@localhost/regista_test} pytest --tb=short -q

## Lint, type-check, and run tests
all: lint typecheck test
