# Develop against the locked substrate (Plan 019 B2)

**`SUITE.lock` is the single source of truth for what to develop against.**

cairn (agent-provenance) is one member of a polyrepo suite held compatible by
version contracts. Its one real substrate sibling is **regista** (the spine).
Feature work on cairn should happen against the regista the suite *ships* — the
released version pinned in `SUITE.lock` — not against regista's `main` or an
editable checkout that has drifted ahead. Developing against `main` is how
integration skew hides until interop time: on 2026-07-21 an agent-suite smoke
suite developed against a newer sibling than the lock pinned, and the break only
surfaced at interop. B2 removes that failure mode by making "install the locked
substrate" the default for both local dev and CI.

## The default

```bash
make dev            # or: python scripts/dev-install.py
```

installs `regista-hraedon==<SUITE.lock [spine].version>` from PyPI (today
`0.5.4`), then `ruff` and `-e ".[dev]"` (pytest, mypy, the crypto libs, and the
pinned `agent-suite-conformance` kit). CI runs the **same**
`scripts/dev-install.py` in the `lint-and-test` lane, so "works on my machine"
means "works in CI".

`SUITE.lock`'s `[spine]` section is the vendored, in-repo copy of the umbrella
`agent-suite/SUITE.lock` pin — it **must agree** with that umbrella's
`[components.regista]` `version` + `revision` (the umbrella is the generated
authority). Vendoring it here means CI resolves the spine without cloning
agent-suite.

## The escape hatch — `DEV_AGAINST`

Cross-member work is not forbidden; it is channeled to one obvious switch so the
coupling is always visible:

| `DEV_AGAINST` | installs regista from | when |
| --- | --- | --- |
| *unset* / `lock` | `regista-hraedon==<locked version>` (PyPI) | **default** — feature work on cairn alone |
| `sibling` | `-e ../regista` (editable working tree) | local co-development of regista + cairn together |
| `main` | `git+…/regista.git@main` | deliberately testing against regista's tip |
| `<ref>` | `git+…/regista.git@<ref>` | a specific regista branch / tag / SHA |

```bash
DEV_AGAINST=main    python scripts/dev-install.py    # test against regista tip
DEV_AGAINST=sibling python scripts/dev-install.py    # local co-dev (canonical clone)
python scripts/suite_lock.py describe                 # what am I developing against?
python scripts/suite_lock.py requirement --dev-against main
```

> `DEV_AGAINST=sibling` resolves `../regista`, which only exists in the
> constellation clone layout (`/projects/{regista,agent-provenance}`), not inside
> a `git worktree`. Use it from the canonical clone.

Note: `pyproject.toml` carries a `[tool.uv.sources]` mapping that points
`regista-hraedon` at the local `../regista` working tree. That override only
applies under `uv` (`uv lock` / `uv run`) — it is the `uv`-native equivalent of
`DEV_AGAINST=sibling`. The pip-based paved path (`make dev`) ignores it and
installs the locked release; reach for the `uv` sibling override deliberately
when co-developing the spine.

## Two places the sibling override bites

### In a `git worktree` — a hard failure

`[tool.uv.sources]` resolves `../regista` **relative to the checkout**, so in a
worktree (`~/wt/<name>`) it points at a sibling that does not exist and every
`uv` project command fails before it resolves anything:

```
$ uv sync --frozen --extra dev
error: Failed to determine installation plan
  Caused by: Distribution not found at: file:///home/itadmin/wt/regista
```

Use the pip-based paved path instead — it ignores `[tool.uv.sources]` entirely,
so it works unchanged in a worktree:

```bash
uv venv --seed                      # system python3 is PEP 668 externally-managed
./.venv/bin/python scripts/dev-install.py
```

### Installing the `cairn` tool — a *silent* cap violation

The genesis gate invokes `cairn` from `PATH`, i.e. the uv **tool** venv at
`~/.local/share/uv/tools/cairn`. Upgrading it with the obvious command is a
trap:

```bash
uv tool install --force .           # DO NOT: ignores the <0.6 cap
```

From the canonical clone, `[tool.uv.sources]` makes uv install whatever version
`../regista`'s working tree happens to be — **with no error and no warning**,
even when that version violates the `regista-hraedon>=0.5.1,<0.6` cap in
`pyproject.toml`. Verified 2026-08-20 against stand-in siblings: a `0.6.0`
sibling installed as `0.6.0`, and a deliberately absurd `9.9.9` sibling
installed as `9.9.9`. The cap is deliberate (it holds until cairn's
`on_behalf_of` port), so this quietly produces a tool venv the cap exists to
prevent.

Upgrade the installed tool by building a wheel and installing *that* — wheel
metadata carries the cap but not the `[tool.uv.sources]` override, so the spine
resolves from PyPI. Safe to run from inside the project directory:

```bash
uv build --wheel
uv tool install --force dist/cairn-0.1.0-py3-none-any.whl
```

To pin the spine to `SUITE.lock`'s `[spine].version` rather than letting the
resolver take the newest release under the cap (they coincide at `0.5.5` today,
but would diverge the moment a `0.5.6` publishes):

```bash
uv tool install --force --with 'regista-hraedon[encryption]==0.5.5' \
  dist/cairn-0.1.0-py3-none-any.whl
```

`uv tool install --force --no-sources .` also honors the cap and needs no wheel;
prefer the wheel form when you want the installed artifact to be the same one
CI gates. Verify afterwards, since the gate depends on it:

```bash
cairn invariants probe --json && echo "exit=$?"
```

Rehearse any of this against a throwaway location before touching the live tool:

```bash
UV_TOOL_DIR=/tmp/t/tools UV_TOOL_BIN_DIR=/tmp/t/bin uv tool install --force <wheel>
```

## Enforcement

`tests/test_develop_against_lock.py` is the mechanical control: it fails if CI
hardcodes a regista version (the `0.5.1`-vs-`0.5.3` drift class) or installs the
spine from `git+…@ref` without going through the `DEV_AGAINST` hatch, and it
pins the resolver's default to `SUITE.lock`'s `[spine].version`. Convention plus
CI, not a doc sentence.

## Related

- `plans/019-…` (in agent-suite) — the coupling-tax initiative; B2 is this.
- `scripts/suite_lock.py` — the resolver (reads `SUITE.lock`).
- `docs/develop-against-lock.md` in `../agent-notes` — the pilot this port
  replicates.
