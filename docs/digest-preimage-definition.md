# Output digest preimage definition (Plan 009 WI-1.2)

> **Principle:** A digest an auditor cannot reproduce is not evidence.
> Preimage semantics (what bytes, what encoding, truncated or not) are part
> of the attestation contract.

## What the digest covers

The `stdout_digest` field in a `tool_call_end` event is the **SHA-256 of the
full, untruncated tool output**, encoded as UTF-8 bytes.

Specifically:

1. The Claude Code hook reads the `tool_response` field from the harness's
   `PostToolUse` / `PostToolUseFailure` hook input (canonical field for
   Claude Code 2.1.200+).
2. The value is normalized to a text string (see *Normalization* below).
3. The text is encoded as UTF-8.
4. `stdout_digest = sha256(utf8_bytes).hexdigest()` (bare hex, no prefix).
5. `stdout_bytes_total = len(utf8_bytes)` (the number of UTF-8 bytes in the
   full output, **not** the truncated transport text).
6. `stdout_digest_alg = "sha256"`.
7. `stdout_truncated = true` when the full output exceeded the transport cap
   (2000 characters); `false` otherwise.

The truncated text (`stdout`, capped at 2000 characters) is transported to
the bridge for human review only. It is **not** part of the digest preimage.

## How an auditor reproduces the digest

Given the real tool output (e.g. the stdout of a Bash command), the auditor:

1. Applies the same normalization (see below) to obtain a text string.
2. Encodes the string as UTF-8.
3. Computes `sha256(bytes).hexdigest()`.
4. Compares against the `stdout_digest` field in the signed event.
5. Verifies `stdout_bytes_total` matches `len(utf8_bytes)`.
6. If `stdout_truncated` is true, confirms the real output exceeds 2000
   characters (the transport cap) — this explains why the `stdout` text in
   the event differs from the full output.

```python
import hashlib
real_output = "..."  # the full, real tool output
normalized = normalize(real_output)  # see below
digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
assert digest == event["result_summary"]["stdout_digest"]
```

## Normalization

The `tool_response` field can arrive in several shapes depending on the
tool. Normalization extracts a plain text string:

| Shape | Normalization |
|-------|--------------|
| `str` | Used directly. |
| `{"content": [{"type":"text","text":"..."}, ...]}` | Text blocks joined with `"\n"`. |
| `{"file": {"content": "..."}}` (Read tool) | The nested `file.content` value. |
| `{"stdout": "..."}` (Bash-style) | The `stdout` value. |
| `{"content": "..."}` (string, Write tool) | That field's value. |
| `{"output": "..."}` / `{"result": "..."}` / `{"text": "..."}` | That field's value. |
| Other `dict` | Canonical JSON (`json.dumps(..., sort_keys=True, ensure_ascii=False)`). |
| `list` | Canonical JSON. |
| `None` / absent | Empty string `""`. |

PostToolUseFailure payloads carry the error detail in a top-level `error`
field (no `tool_response`). The hook uses this as the digest preimage so
the attested digest and error detail reflect the real failure.

The normalization function is `cairn._claude_hook._normalize_response`. An
auditor re-implementing reproduction should apply the equivalent logic.

These shapes were verified from real Claude Code 2.1.206 captures
(Plan 009 WI-1.1). Sanitized payloads are committed in
`tests/fixtures/hook_payloads/`.

## Legacy fallback

If the `tool_response` field is absent (older Claude Code releases that
sent `tool_output`), the hook falls back to reading `tool_output` with the
same normalization. The digest contract is identical — the field name
differs, not the preimage.

## Legacy digest path (OpenCode / pre-Plan-009)

When the bridge payload does not include a pre-computed `stdout_digest`
(the OpenCode plugin and pre-Plan-009 callers), the adapter falls back to
computing `digest_string(stdout)` over the transported (possibly truncated)
text. This path has the truncation-reproducibility gap that Plan 009
WI-1.2 fixes; the OpenCode plugin will adopt the pre-computed digest in a
follow-up to reach parity.
