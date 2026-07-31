"""Side-effect-free liveness probe shared by the hooks, install and doctor.

A hook entry present in a harness config is not evidence that the hook
*runs*.  On a real deployment all ten generated Claude hooks named a bare
``python3`` that could not import cairn; every invocation failed, session
attestation was absent indefinitely, and ``harness_wired`` still reported
``ok`` because it only checked that the entries existed (WI-033, WI-034).

Every hook entry point therefore answers ``--selftest`` by printing
:data:`HOOK_SELFTEST_MARKER` and exiting 0, *before* any environment
handling, stdin read, or store contact.  Reaching that print proves three
things at once: argv[0] resolved to an executable, the interpreter behind it
started, and it could import cairn.  ``cairn install-harness`` runs the probe
against every command it writes, and ``cairn doctor`` runs it against every
command it finds, so neither surface reports on a hook it has not executed.
"""

from __future__ import annotations

HOOK_SELFTEST_ARG = "--selftest"

#: Stable marker the probe looks for on stdout.  Checked in addition to the
#: exit status so a command that resolves to some *other* program which happens
#: to exit 0 cannot be mistaken for a working cairn hook.
HOOK_SELFTEST_MARKER = "cairn-hook-selftest ok"


def is_selftest(argv: list[str]) -> bool:
    """Whether *argv* (a hook's arguments, excluding argv[0]) is the probe."""
    return bool(argv) and argv[0] == HOOK_SELFTEST_ARG


def selftest_line(harness: str) -> str:
    """The line a hook prints in response to ``--selftest``."""
    from . import __version__

    return f"{HOOK_SELFTEST_MARKER} {harness} {__version__}"
