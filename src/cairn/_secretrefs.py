"""Secret-reference judgement shared by the doctor and the runtime.

Extracted from ``_doctor`` (WI-037) so the *runtime* can reach the same verdict
the doctor publishes.  It cannot live in ``_doctor``: importing that module
reconfigures structlog to CRITICAL and pulls in the whole installer, neither of
which belongs on a hook's execution path.  Two implementations of "does this ref
resolve?" would be free to drift, and a doctor that says the key resolves while
the runtime writes plaintext is the same defect wearing a different hat.

Nothing here ever returns, logs or prints a resolved secret VALUE — only whether
resolution succeeded and, on failure, the resolver's reason.
"""

from __future__ import annotations

#: regista's canonical provider names (``regista._secrets``). Note ``azure``
#: and ``windows`` — not ``akv``/``wincred``, which several docs print and no
#: resolver accepts.
KNOWN_SECRET_SCHEMES = frozenset({"file", "env", "literal", "vault", "azure", "windows"})

#: ``vault:mount/path…/field`` — regista's provider requires at least four
#: segments and takes the field from the LAST one.
VAULT_MIN_SEGMENTS = 4


def secret_ref_static_problem(ref: str) -> str | None:
    """Why *ref* can never resolve, judged without touching any backend.

    Three ref-shape traps this estate actually hit (agent-suite WI-041):

    1. The mount is ``kv/``, not the ``secret/`` the install docs print.  A
       wrong mount is a runtime 403 rather than a parse error, so only
       resolution catches it — which is why this is paired with a real resolve.
    2. **The field is the LAST PATH SEGMENT.**  The documented ``#field``
       suffix has never resolved, and it fails worse than cleanly:
       ``vault:kv/a/b/regista#hmac_key`` parses to field
       ``regista#hmac_key`` — a *different, neighbouring* secret.
    3. ``vault:`` refs resolve only where ``hvac`` is importable in the
       resolving component's OWN environment.  Each suite CLI is its own uv
       tool venv, so ``vault`` in regista's provider list says nothing about
       cairn's; without ``hvac`` the ref fails with "Unknown secret provider".
    """
    if not ref:
        return "empty secret reference"
    scheme, sep, rest = ref.partition(":")
    if not sep or scheme not in KNOWN_SECRET_SCHEMES:
        return (
            f"{ref!r} names no known backend scheme, so it resolves as a literal "
            f"secret value rather than a reference "
            f"(known: {', '.join(sorted(KNOWN_SECRET_SCHEMES))})"
        )
    if scheme == "vault":
        if "#" in ref:
            return (
                f"vault ref {ref!r} uses '#field'; the field is the LAST PATH "
                "SEGMENT (vault:mount/path/field). This form does not error "
                "cleanly — it addresses a different, neighbouring secret"
            )
        segments = rest.split("/")
        if len(segments) < VAULT_MIN_SEGMENTS:
            return (
                f"vault ref {ref!r} has {len(segments)} segment(s); regista "
                f"requires mount/path…/field (at least {VAULT_MIN_SEGMENTS})"
            )
        import importlib.util

        if importlib.util.find_spec("hvac") is None:
            return (
                f"vault ref {ref!r} cannot resolve in cairn's environment: "
                "hvac is not importable here, so regista registers no vault "
                "provider and the ref fails with 'Unknown secret provider'. "
                "Reinstall cairn with the vault extra (uv tool install "
                "'cairn[vault]', pipx install 'cairn[vault]')"
            )
    return None


def verify_secret_ref(ref: str) -> tuple[bool, str]:
    """Actually resolve *ref*. Returns ``(ok, detail)``.

    The resolved value is discarded immediately and never returned, logged or
    printed — only whether resolution succeeded, and on failure the resolver's
    reason.
    """
    static = secret_ref_static_problem(ref)
    if static is not None:
        return False, static
    try:
        from regista._secrets import resolve as resolve_secret
    except Exception as exc:  # pragma: no cover - regista always present
        return False, f"regista secret resolver unavailable: {exc}"
    try:
        resolve_secret(ref)
    except Exception as exc:
        return False, f"does not resolve: {exc}"
    return True, "resolves"
