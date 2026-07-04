"""Shared DB test helpers for cairn.

Lives in a plain module (not conftest) so test files import it without the
``tests.conftest`` vs ``conftest`` module-identity ambiguity that mypy/pytest
import-mode flags (adversarial review T1).
"""

from __future__ import annotations

import os

# Default DSN used when ``REGISTA_TEST_DSN`` is unset. ``connect_timeout`` keeps
# the connection attempt short so test collection does not stall when no
# Postgres is reachable or the role's password is wrong.
DEFAULT_TEST_DSN = (
    "postgresql://regista_test:regista_test@localhost/regista_test"
    "?connect_timeout=2"
)


def _ensure_connect_timeout(dsn: str) -> str:
    """Inject ``connect_timeout`` into *dsn* if absent.

    regista's connection pool retries connection/auth failures indefinitely.
    The pre-check below bounds the *probe*, but ``Regista.create_project`` also
    opens a pool against the same DSN; ensuring a ``connect_timeout`` in the
    DSN itself prevents that pool from hanging on a slow/firewalled host
    (adversarial review T2).
    """
    if "connect_timeout" in dsn:
        return dsn
    sep = "&" if "?" in dsn else "?"
    return f"{dsn}{sep}connect_timeout=5"


def postgres_reachable(dsn: str) -> bool:
    """Return True if a one-shot connection to *dsn* succeeds.

    regista's connection pool retries auth/connection failures indefinitely,
    which makes ``Regista.create_project`` hang when the database is up but
    the role/credentials are wrong. We probe with a single short-lived
    connection first so the fixture can skip fast instead of stalling.
    """
    try:
        import psycopg
    except ImportError:
        # A broken install is not the same as "Postgres unavailable" —
        # surface it rather than silently skipping every DB test (review T7).
        raise RuntimeError(
            "psycopg is not installed; test dependencies are broken"
        )
    try:
        with psycopg.connect(dsn, connect_timeout=2):
            return True
    except Exception:
        return False


def resolve_test_dsn() -> str:
    return os.environ.get("REGISTA_TEST_DSN", DEFAULT_TEST_DSN)
