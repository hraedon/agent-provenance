"""``cairn portal`` — render session content from a signed bundle.

Plan 010 WI-4.1-4.3: the portal's reason is to surface session content
(prompt/response transcript, interleaved with tool calls, file provenance,
and attestation gaps) to authorized internal users.

The plan says the portal extends dossier (the suite's human web face).
dossier is a separate project; this module provides the cairn-native
read-side support that dossier would consume, plus a CLI-renderable
text/HTML portal for offline use.

For an external auditor, the offline bundle + ``cairn verify`` remains
the artifact; the portal is for authorized internal users browsing live
or from an exported bundle.

Content decryption happens here when a content key is available (via
``regista._secrets.resolve``).  Without the key, encrypted fields are
shown as ``[encrypted — content key not available]``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ._content_crypto import decrypt_content_fields, resolve_content_key_ref


def render_portal(
    bundle_path: str | Path,
    *,
    key_set: dict[str, bytes] | None = None,
    content_key_ref: str | None = None,
    fmt: str = "text",
) -> str:
    """Render a session-content portal view from a signed bundle.

    Args:
        bundle_path: Path to the signed bundle JSON file.
        key_set: Signing key set for verification (optional for portal view).
        content_key_ref: Secret-ref for the content-encryption key.  When
            omitted, resolves from the environment.
        fmt: ``"text"`` or ``"html"``.

    Returns:
        The rendered portal as a string.
    """
    path = Path(bundle_path)
    raw = json.loads(path.read_text())
    events = raw.get("events", [])
    manifest = raw.get("manifest", {})

    effective_content_key = content_key_ref or resolve_content_key_ref()

    sessions: dict[str, dict[str, Any]] = {}
    for ev_dict in events:
        payload = ev_dict.get("payload") or {}
        transition = ev_dict.get("transition", "")
        on_behalf_of = ev_dict.get("on_behalf_of") or {}

        session_id = payload.get("session_id") or on_behalf_of.get("session_id", "_unknown")

        if session_id not in sessions:
            sessions[session_id] = {
                "session_id": session_id,
                "attestations": [],
                "messages": [],
                "tool_calls": [],
                "content_encryption": "off",
                "content_capture": False,
            }

        sess = sessions[session_id]

        if transition in ("session_attestation", "scope_attestation"):
            sess["content_capture"] = payload.get("content_capture", False)
            sess["content_encryption"] = payload.get("content_encryption", "off")
            sess["attestations"].append({
                "event_id": ev_dict.get("event_id"),
                "transition": transition,
                "principal_id": payload.get("principal_id"),
                "attested_at": payload.get("attested_at"),
                "harnesses": payload.get("harnesses", []),
                "content_capture": payload.get("content_capture", False),
                "content_encryption": payload.get("content_encryption", "off"),
            })
        elif transition in ("user_message", "assistant_message"):
            decrypted_payload = dict(payload)
            if effective_content_key:
                try:
                    decrypted_payload = decrypt_content_fields(
                        payload, key_ref=effective_content_key
                    )
                except Exception:
                    pass
            sess["messages"].append({
                "event_id": ev_dict.get("event_id"),
                "role": decrypted_payload.get("role", transition),
                "digest": decrypted_payload.get("message_digest"),
                "content": decrypted_payload.get("message_content"),
                "sequence": decrypted_payload.get("sequence"),
                "timestamp": ev_dict.get("timestamp"),
            })
        elif transition in ("transcript_attestation",):
            decrypted_payload = dict(payload)
            if effective_content_key:
                try:
                    decrypted_payload = decrypt_content_fields(
                        payload, key_ref=effective_content_key
                    )
                except Exception:
                    pass
            sess["messages"].append({
                "event_id": ev_dict.get("event_id"),
                "role": "transcript",
                "digest": decrypted_payload.get("transcript_digest"),
                "content": decrypted_payload.get("transcript_content"),
                "timestamp": ev_dict.get("timestamp"),
            })
        elif transition.startswith("tool_call"):
            sess["tool_calls"].append({
                "event_id": ev_dict.get("event_id"),
                "transition": transition,
                "tool": payload.get("tool"),
                "tool_args_hash": payload.get("tool_args_hash"),
                "files": payload.get("files", []),
                "result_summary": payload.get("result_summary", {}),
                "timestamp": ev_dict.get("timestamp"),
            })

    if fmt == "html":
        return _render_html(sessions, manifest, effective_content_key)
    return _render_text(sessions, manifest, effective_content_key)


def _render_text(
    sessions: dict[str, dict[str, Any]],
    manifest: dict[str, Any],
    content_key_ref: str | None,
) -> str:
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("CAIRN SESSION PORTAL")
    lines.append("=" * 60)
    lines.append(f"Bundle: {manifest.get('events_count', 0)} events")
    lines.append(f"Content key: {'available' if content_key_ref else 'not available'}")
    lines.append("")

    for session_id, sess in sessions.items():
        lines.append("-" * 60)
        lines.append(f"Session: {session_id}")
        lines.append(f"  Content capture: {sess['content_capture']}")
        lines.append(f"  Content encryption: {sess['content_encryption']}")

        if sess["content_capture"] and sess["content_encryption"] == "off":
            lines.append(
                "  WARNING: Content captured without encryption at rest —"
                " the log itself is now a sensitive artifact."
            )

        if sess["attestations"]:
            lines.append(f"  Attestations: {len(sess['attestations'])}")
            for att in sess["attestations"]:
                lines.append(f"    {att['transition']} at {att.get('attested_at', '?')}")

        if sess["messages"]:
            lines.append(f"  Messages: {len(sess['messages'])}")
            for msg in sess["messages"]:
                role = msg["role"]
                content = msg.get("content")
                if content is None:
                    content = "[encrypted — content key not available]"
                elif not isinstance(content, str):
                    content = json.dumps(content, indent=2, ensure_ascii=False)
                lines.append(f"    [{role}] {content[:200]}...")

        if sess["tool_calls"]:
            lines.append(f"  Tool calls: {len(sess['tool_calls'])}")
            for tc in sess["tool_calls"]:
                lines.append(f"    {tc['transition']}: {tc.get('tool', '?')}")

        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines) + "\n"


def _render_html(
    sessions: dict[str, dict[str, Any]],
    manifest: dict[str, Any],
    content_key_ref: str | None,
) -> str:
    def _esc(text: str) -> str:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

    sections: list[str] = []

    for session_id, sess in sessions.items():
        has_banner = sess["content_capture"] and sess["content_encryption"] == "off"
        banner = ""
        if has_banner:
            banner = (
                '<div style="background:#fef3c7;border:2px solid #f59e0b;'
                'padding:12px;margin-bottom:16px;border-radius:4px">'
                "<strong>WARNING:</strong> Content captured without encryption"
                " at rest — the log itself is now a sensitive artifact."
                "</div>"
            )

        msgs_html = ""
        for msg in sess["messages"]:
            role = msg["role"]
            content = msg.get("content")
            if content is None:
                content_display = '<em>[encrypted — content key not available]</em>'
            elif not isinstance(content, str):
                content_display = f"<pre>{_esc(json.dumps(content, indent=2))}</pre>"
            else:
                content_display = f"<pre>{_esc(content)}</pre>"
            bg = "#f0f9ff" if role == "user" else "#f0fdf4" if role == "assistant" else "#f8fafc"
            msgs_html += (
                f'<div style="background:{bg};padding:8px;margin:4px 0;border-radius:4px">'
                f'<strong>{_esc(role)}</strong> '
                f'<span style="color:#6b7280;font-size:12px">'
                f'{_esc(msg.get("timestamp", ""))}</span>'
                f"{content_display}"
                "</div>"
            )

        tcs_html = ""
        for tc in sess["tool_calls"]:
            tcs_html += (
                f'<div style="padding:4px 8px;margin:2px 0;font-family:monospace;font-size:12px">'
                f'{_esc(tc["transition"])}: {_esc(tc.get("tool", "?"))}'
                "</div>"
            )

        sections.append(
            f'<div class="session" style="margin-bottom:32px">'
            f"<h2>Session: <code>{_esc(session_id)}</code></h2>"
            f"{banner}"
            f'<p>Content capture: <strong>{sess["content_capture"]}</strong> | '
            f'Content encryption: <strong>{sess["content_encryption"]}</strong></p>'
            f"<h3>Messages ({len(sess['messages'])})</h3>"
            f"{msgs_html}"
            f"<h3>Tool calls ({len(sess['tool_calls'])})</h3>"
            f"{tcs_html}"
            "</div>"
        )

    key_status = "available" if content_key_ref else "not available"
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        "<title>Cairn Session Portal</title>"
        '<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:0 auto;padding:20px}'
        "h2{color:#1e293b}code{background:#f1f5f9;padding:2px 4px;border-radius:3px}"
        "pre{white-space:pre-wrap;word-wrap:break-word}</style></head><body>"
        "<h1>Cairn Session Portal</h1>"
        f'<p>Bundle: {manifest.get("events_count", 0)} events | '
        f"Content key: {key_status}</p>"
        + "\n".join(sections)
        + "</body></html>"
    )
