"""Command-line interface for Cairn.

Usage::

    cairn verify --bundle-path audit-bundle.json --keys /secrets/keys.json
    cairn export --dsn $DSN --project $PROJECT --keys /secrets/keys.json --output bundle.json
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import click

from . import __version__ as _cairn_version
from .schema import check_key_file_permissions
from .verifier import Verifier

TRUST_MODEL_CAVEAT = (
    "Ed25519 and HMAC-SHA256 supported; RFC 3161 timestamping available via "
    "'cairn timestamp'. FIM-class positioning is a working hypothesis "
    "(README §4.1), not auditor-validated."
)

README_PATH = Path(__file__).resolve().parent.parent.parent / "README.md"


def _check_key_permissions_strict(keys_path: Path) -> None:
    """Warn about readable permissions and refuse writable permissions.

    Signing operations should not proceed if the key file can be modified by
    group or others, if it is a symlink, or if permissions cannot be checked.
    Verification may continue to warn because auditors may not control the
    filesystem where keys are stored.
    """
    for w in check_key_file_permissions(str(keys_path)):
        if "writable" in w or "symlink" in w or "stat failed" in w:
            raise click.ClickException(f"Refusing to use signing key: {w}")
        click.echo(f"WARNING: {w}", err=True)


def _load_key_set(keys_path: Path) -> dict[str, bytes]:
    """Load a key set from a JSON key file.

    Supports both HMAC-SHA256 (``secret`` field) and Ed25519
    (``public_key`` field for verification, ``secret`` for signing).
    For Ed25519 verification, only the public key is needed.
    """
    key_data = json.loads(keys_path.read_text())
    key_set: dict[str, bytes] = {}
    for entry in key_data["keys"]:
        key_id: str = entry["key_id"]
        scheme = entry.get("scheme", "hmac-sha256")

        if scheme == "ed25519":
            # For verification, use the public key
            public_key_raw = entry.get("public_key")
            if public_key_raw is None:
                click.echo(
                    f"WARNING: Ed25519 key {key_id!r} has no public_key; "
                    "verification will fail for events signed by this key.",
                    err=True,
                )
                continue
            encoding = entry.get("encoding", "base64")
            if encoding == "base64":
                public_key = base64.b64decode(public_key_raw)
            elif encoding == "utf8":
                public_key = public_key_raw.encode("utf-8")
            else:
                raise click.BadParameter(
                    f"Ed25519 key {key_id!r}: unsupported encoding {encoding!r}"
                )
            if len(public_key) != 32:
                raise click.BadParameter(
                    f"Ed25519 public key {key_id!r} must be 32 bytes, got {len(public_key)}"
                )
            if "secret" in entry:
                secret_raw = entry["secret"]
                if encoding == "base64":
                    ed25519_secret = base64.b64decode(secret_raw)
                elif encoding == "utf8":
                    ed25519_secret = secret_raw.encode("utf-8")
                else:
                    raise click.BadParameter(
                        f"Ed25519 key {key_id!r}: unsupported encoding {encoding!r}"
                    )
                if len(ed25519_secret) not in (32, 64):
                    raise click.BadParameter(
                        f"Ed25519 secret {key_id!r} must be 32 or 64 bytes, "
                        f"got {len(ed25519_secret)}"
                    )
            key_set[key_id] = public_key
        else:
            # HMAC-SHA256: use the secret
            secret_raw = entry["secret"]
            encoding = entry.get("encoding", "utf8")
            if encoding == "base64":
                secret: bytes = base64.b64decode(secret_raw)
            elif encoding == "utf8":
                secret = secret_raw.encode("utf-8")
            else:
                raise click.BadParameter(
                    f"HMAC key {key_id!r}: unsupported encoding {encoding!r}"
                )
            if len(secret) < 32:
                click.echo(
                    f"WARNING: HMAC-SHA256 key {key_id!r} is {len(secret)} bytes; "
                    "regista recommends at least 32 bytes.",
                    err=True,
                )
            key_set[key_id] = secret

    return key_set


def _load_key_metadata(keys_path: Path) -> dict[str, dict[str, Any]]:
    """Build per-key metadata (``role``, ``revoked_at``) from the key file.

    BC-017: ``_check_role_gate`` and the post-revocation enforcement in
    ``_accumulate_key_revocations`` both short-circuit when there is no
    metadata for a key.  The CLI is the only documented auditor entry point,
    so without this the role-gate and revocation-timestamp checks are dead
    code through ``cairn verify``.  Here we surface the optional ``role`` and
    ``revoked_at`` fields from each key entry so those checks actually run.

    Only keys that declare at least one lifecycle field produce metadata; keys
    with neither field are omitted, preserving the backward-compatible
    "no metadata → check skipped" behavior for legacy key files.
    """
    key_data = json.loads(keys_path.read_text())
    key_metadata: dict[str, dict[str, Any]] = {}
    for entry in key_data["keys"]:
        key_id: str = entry["key_id"]
        meta: dict[str, Any] = {}
        if "role" in entry and entry["role"] is not None:
            meta["role"] = entry["role"]
        if "revoked_at" in entry and entry["revoked_at"] is not None:
            meta["revoked_at"] = entry["revoked_at"]
        if meta:
            key_metadata[key_id] = meta
    return key_metadata


_LAST_BUNDLE_HASH_FILE = ".cairn_last_bundle_hash"


def _load_witness_keys(path: Path) -> dict[str, bytes]:
    """Load witness public keys from a JSON file (BC-016).

    Expected format::

        {
          "witness-001": {
            "public_key": "<hex-encoded Ed25519 public key>",
            "key_scheme": "ed25519"
          },
          ...
        }

    Only Ed25519 keys are supported for witness signature verification.
    """
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise click.ClickException(f"Cannot read witness keys {path}: {exc}")

    if not isinstance(data, dict):
        raise click.ClickException(
            f"Witness keys file {path} must be a JSON object"
        )

    result: dict[str, bytes] = {}
    for wid, entry in data.items():
        if not isinstance(entry, dict):
            continue
        scheme = entry.get("key_scheme", "ed25519")
        if scheme != "ed25519":
            continue
        pk_hex = entry.get("public_key")
        if not pk_hex:
            continue
        try:
            result[wid] = bytes.fromhex(pk_hex)
        except (ValueError, TypeError):
            raise click.BadParameter(
                f"Witness {wid!r}: invalid hex public_key"
            )
        if len(result[wid]) != 32:
            raise click.BadParameter(
                f"Witness {wid!r}: Ed25519 public key must be 32 bytes, "
                f"got {len(result[wid])}"
            )

    return result


def _read_previous_bundle_hash(path: Path) -> str:
    """Extract the bundle hash from a previous bundle file for chain linking."""
    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise click.ClickException(f"Cannot read previous bundle {path}: {exc}")
    manifest = raw.get("manifest", {})
    h: str = manifest.get("bundle_hash")
    if not h:
        raise click.ClickException(
            f"Previous bundle {path} has no manifest.bundle_hash"
        )
    return h


def _load_last_bundle_hash(directory: Path) -> str | None:
    """Read the cached hash of the most recently exported bundle in a directory."""
    path = directory / _LAST_BUNDLE_HASH_FILE
    if not path.exists():
        return None
    return path.read_text().strip() or None


def _save_last_bundle_hash(directory: Path, bundle_hash: str) -> None:
    """Cache the hash of the just-exported bundle for the next export.

    Uses an atomic write (write to temp, then rename) to prevent partial
    reads if the process is interrupted.
    """
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / _LAST_BUNDLE_HASH_FILE
    tmp = target.with_suffix(".tmp")
    try:
        tmp.write_text(bundle_hash)
        os.replace(str(tmp), str(target))
    except OSError:
        # Best-effort: if the state file can't be written, the next export
        # simply won't have auto-linking.  Clean up the temp file.
        try:
            tmp.unlink()
        except OSError:
            pass
        click.echo(
            f"Warning: could not write bundle hash state file {target}",
            err=True,
        )


_SECTION_RE = re.compile(r"^#+\s+(\d+(?:\.\d+)?)")


def _extract_readme_sections(readme_text: str) -> tuple[str | None, str | None]:
    """Return control description and caveat from README §4.2.

    Uses regex to match section headings like ``## 4.2`` or ``### 4.2.1``.
    """
    control_lines: list[str] = []
    in_control = False
    for raw in readme_text.splitlines():
        line = raw.rstrip()
        m = _SECTION_RE.match(line)
        if m:
            section = m.group(1)
            if section.startswith("4.2"):
                in_control = True
                continue
            elif section.startswith("4.3"):
                in_control = False
        if in_control:
            if line.startswith("> "):
                control_lines.append(line[2:])
            elif line.startswith(">"):
                control_lines.append(line[1:].strip())
            elif control_lines and not line:
                control_lines.append("")
    control_text = "\n".join(control_lines).strip() if control_lines else None
    return control_text, TRUST_MODEL_CAVEAT


@click.group()
@click.version_option(version=_cairn_version, prog_name="cairn")
def main() -> None:
    """Cairn — Cryptographic provenance for agentic workflows."""


@main.command()
@click.option("--bundle-path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--keys", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "html"]),
    default="text",
    help="Report format: text (human-readable), JSON, or self-contained HTML",
)
@click.option(
    "--tsa-cert",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Trusted TSA certificate (PEM or DER) for timestamp signature verification (BC-229).",
)
@click.option(
    "--witness-keys",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="JSON file mapping witness_id → {public_key (hex), key_scheme} "
    "for verifying witness receipt signatures (BC-016). "
    "When omitted, witness keys from bundle registrations are used.",
)
@click.option(
    "--since",
    default=None,
    help="ISO timestamp — only verify events at or after this time (Plan 008 WI-3.1).",
)
@click.option(
    "--until",
    default=None,
    help="ISO timestamp — only verify events before this time (Plan 008 WI-3.1).",
)
def verify(
    bundle_path: Path,
    keys: Path,
    output: Path | None,
    fmt: str,
    tsa_cert: Path | None,
    witness_keys: Path | None,
    since: str | None,
    until: str | None,
) -> None:
    """Verify a signed Cairn bundle and emit an auditor-ready report."""
    for w in check_key_file_permissions(str(keys)):
        click.echo(f"WARNING: {w}", err=True)

    key_set = _load_key_set(keys)
    key_metadata = _load_key_metadata(keys)

    witness_key_set: dict[str, bytes] | None = None
    if witness_keys:
        witness_key_set = _load_witness_keys(witness_keys)

    verifier = Verifier(
        key_set,
        key_metadata=key_metadata,
        tsa_cert_path=str(tsa_cert) if tsa_cert else None,
        witness_keys=witness_key_set,
    )

    if since or until:
        if since and until:
            since_dt = datetime.datetime.fromisoformat(since)
            until_dt = datetime.datetime.fromisoformat(until)
            if since_dt > until_dt:
                raise click.ClickException("--since must be <= --until")
        report = verifier.verify_bundle_filtered(
            bundle_path,
            since=since,
            until=until,
        )
    else:
        report = verifier.verify_bundle(bundle_path)

    if fmt == "json":
        result = json.dumps(Verifier.format_report_json(report), indent=2)
    elif fmt == "html":
        result = Verifier.format_report_html(report)
    else:
        result = Verifier.format_report(report)

    if output:
        output.write_text(result)
        click.echo(f"Report written to {output}")
    else:
        click.echo(result, nl=False)

    if not report.all_ok:
        sys.exit(1)


@main.command("verify-chain")
@click.option(
    "--bundles",
    required=True,
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Bundle paths in chronological order (oldest first)",
)
@click.option("--keys", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "html"]),
    default="text",
    help="Report format: text (human-readable), JSON, or self-contained HTML",
)
def verify_chain(
    bundles: tuple[Path, ...],
    keys: Path,
    output: Path | None,
    fmt: str,
) -> None:
    """Verify a chain of bundles linked by previous_bundle_hash."""
    for w in check_key_file_permissions(str(keys)):
        click.echo(f"WARNING: {w}", err=True)

    key_set = _load_key_set(keys)
    key_metadata = _load_key_metadata(keys)

    verifier = Verifier(key_set, key_metadata=key_metadata)
    report = verifier.verify_bundle_chain(list(bundles))

    if fmt == "json":
        result = json.dumps(Verifier.format_report_json(report), indent=2)
    elif fmt == "html":
        result = Verifier.format_report_html(report)
    else:
        result = Verifier.format_report(report)

    if output:
        output.write_text(result)
        click.echo(f"Report written to {output}")
    else:
        click.echo(result, nl=False)

    if not report.all_ok:
        sys.exit(1)


@main.command()
@click.option("--dsn", required=True, help="Postgres DSN")
@click.option("--project", required=True, help="Regista project name")
@click.option("--keys", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", required=True, type=click.Path(path_type=Path))
@click.option("--since", default=None, help="ISO timestamp for lower bound")
@click.option("--until", default=None, help="ISO timestamp for upper bound")
@click.option(
    "--previous-bundle-hash",
    default=None,
    help="sha256:... hash of the preceding bundle for chain integrity",
)
@click.option(
    "--previous-bundle",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help=(
        "Path to the previous bundle file; its manifest.bundle_hash is used as "
        "previous_bundle_hash."
    ),
)
def export(
    dsn: str,
    project: str,
    keys: Path,
    output: Path,
    since: str | None,
    until: str | None,
    previous_bundle_hash: str | None,
    previous_bundle: Path | None,
) -> None:
    """Export events from regista into a signed bundle for offline verification."""
    _check_key_permissions_strict(keys)

    from regista import Regista

    sub = Regista(dsn=dsn, project=project, hmac_key_path=str(keys))
    try:
        start = datetime.datetime.fromisoformat(since) if since else None
        end = datetime.datetime.fromisoformat(until) if until else None

        events = sub.read_events(
            start=start,
            end=end,
            limit=10_000,
        )

        readme_text = ""
        if README_PATH.exists():
            readme_text = README_PATH.read_text()
        control_description, trust_model_caveat = _extract_readme_sections(readme_text)

        source_host = getattr(getattr(sub, "connection_info", None), "host", None) or "unknown"

        manifest: dict[str, Any] = {
            "events_count": len(events),
            "exported_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "source_project": project,
            "source_dsn_host": source_host,
        }

        effective_prev_hash: str | None = None
        if previous_bundle is not None:
            effective_prev_hash = _read_previous_bundle_hash(previous_bundle)
        elif previous_bundle_hash:
            effective_prev_hash = previous_bundle_hash
        else:
            effective_prev_hash = _load_last_bundle_hash(output.parent)

        if effective_prev_hash:
            manifest["previous_bundle_hash"] = effective_prev_hash

        if control_description:
            manifest["control_description"] = control_description
            manifest["control_description_source_digest"] = (
                "sha256:" + hashlib.sha256(readme_text.encode("utf-8")).hexdigest()
            )
        manifest["trust_model_caveat"] = trust_model_caveat

        bundle: dict[str, Any] = {
            "manifest": manifest,
            "events": [ev.to_dict() for ev in events],
        }

        exported_event_ids = {str(ev.event_id) for ev in events}
        try:
            confirmed_batches = sub.timestamping.list_batches(status="confirmed")
            covering_batches = []
            for batch in confirmed_batches:
                batch_event_ids = {str(eid) for eid in batch.event_ids}
                if batch_event_ids & exported_event_ids:
                    covering_batches.append(batch.to_dict())
            if covering_batches:
                bundle["timestamp_batches"] = covering_batches
        except Exception as exc:
            click.echo(
                f"Warning: failed to load timestamp batches — "
                f"bundle will not contain timestamp data: {exc}",
                err=True,
            )

        # Include witness registrations and confirmed receipts
        try:
            witnesses = sub.witnesses.list(status="active")
            if witnesses:
                safe_witnesses = []
                for w in witnesses:
                    sw = {k: v for k, v in w.items() if k != "sign_secret"}
                    if sw.get("public_key") is not None:
                        pk = sw["public_key"]
                        if isinstance(pk, (bytes, bytearray, memoryview)):
                            sw["public_key"] = bytes(pk).hex()
                    safe_witnesses.append(sw)
                bundle["witness_registrations"] = safe_witnesses

                witness_receipts = []
                for ev_id in exported_event_ids:
                    receipts = sub.witnesses.receipts(event_id=ev_id, status="confirmed")
                    for r in receipts:
                        witness_receipts.append({
                            "event_id": str(r.get("event_id", "")),
                            "witness_id": str(r.get("witness_id", "")),
                            "status": r.get("status"),
                            "confirmed_at": r.get("confirmed_at").isoformat()
                            if r.get("confirmed_at")
                            else None,
                            "witness_signature": r.get("witness_signature").hex()
                            if r.get("witness_signature")
                            else None,
                        })
                if witness_receipts:
                    bundle["witness_receipts"] = witness_receipts
        except Exception as exc:
            click.echo(
                f"Warning: failed to load witness data — "
                f"bundle will not contain witness registrations or receipts: {exc}",
                err=True,
            )

        canonical = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")
        digest = "sha256:" + hashlib.sha256(canonical).hexdigest()

        bundle["manifest"]["bundle_hash"] = digest
        bundle["manifest"]["bundle_hash_covers"] = (
            "manifest (minus bundle_hash) + events + timestamp_batches (if present) "
            "+ witness_registrations + witness_receipts, canonical JSON"
        )

        ts_count = len(bundle.get("timestamp_batches", []))
        ts_note = f", {ts_count} TSA timestamp batches" if ts_count else ""
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(bundle, indent=2))
        click.echo(f"Exported {len(events)} events{ts_note} to {output}")
        _save_last_bundle_hash(output.parent, digest)
    finally:
        sub.close()


@main.command("extract-control")
@click.option(
    "--readme",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to README.md (auto-detected if omitted)",
)
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format: text (human-readable) or JSON",
)
def extract_control(readme: Path | None, output: Path | None, fmt: str) -> None:
    """Extract the control description and trust-model caveat from README §4.2.

    Outputs the control narrative that deploying organizations can copy
    into their SOX system description, SOC 2 system description, or
    internal control narrative.
    """
    if readme is None:
        readme = README_PATH
    if not readme.exists():
        click.echo(f"README not found: {readme}", err=True)
        sys.exit(1)

    readme_text = readme.read_text()
    control_description, trust_model_caveat = _extract_readme_sections(readme_text)
    source_digest = "sha256:" + hashlib.sha256(readme_text.encode("utf-8")).hexdigest()

    if fmt == "json":
        result = json.dumps(
            {
                "control_description": control_description,
                "trust_model_caveat": trust_model_caveat,
                "source_path": str(readme),
                "source_digest": source_digest,
                "source_section": "§4.2",
            },
            indent=2,
        )
    else:
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("CAIRN CONTROL DESCRIPTION")
        lines.append("=" * 60)
        lines.append("")
        if control_description:
            lines.append(control_description)
        else:
            lines.append("(No control description found in README §4.2)")
        lines.append("")
        lines.append("-" * 60)
        lines.append("TRUST MODEL CAVEAT")
        lines.append("-" * 60)
        lines.append(trust_model_caveat or "(no caveat)")
        lines.append("")
        lines.append(f"Source: {readme}")
        lines.append(f"Digest: {source_digest}")
        lines.append("=" * 60)
        result = "\n".join(lines) + "\n"

    if output:
        output.write_text(result)
        click.echo(f"Written to {output}")
    else:
        click.echo(result, nl=False)


@main.command()
@click.option(
    "--older",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Older bundle path (baseline)",
)
@click.option(
    "--newer",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Newer bundle path to compare against baseline",
)
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Report format: text (human-readable) or JSON",
)
def diff(older: Path, newer: Path, output: Path | None, fmt: str) -> None:
    """Compare two bundles and show what changed."""
    verifier = Verifier({})
    diff_result = verifier.diff_bundles(older, newer)

    if fmt == "json":
        result = json.dumps(Verifier.format_diff_json(diff_result), indent=2)
    else:
        result = Verifier.format_diff(diff_result)

    if output:
        output.write_text(result)
        click.echo(f"Diff written to {output}")
    else:
        click.echo(result, nl=False)


@main.command()
@click.option("--dsn", required=True, help="Postgres DSN")
@click.option("--project", required=True, help="Regista project name")
@click.option("--keys", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--tsa-url", required=True, help="RFC 3161 TSA endpoint URL")
@click.option("--batch-size", default=1000, help="Max events per batch")
@click.option("--hash-algo", default="sha256", help="Hash algorithm (sha256/sha384/sha512)")
def timestamp(
    dsn: str,
    project: str,
    keys: Path,
    tsa_url: str,
    batch_size: int,
    hash_algo: str,
) -> None:
    """Submit event batches to an RFC 3161 TSA for timestamping.

    Connects to regista, computes a Merkle root over unbaptized events,
    submits it to the configured TSA, and stores the resulting token.
    Requires asn1crypto: pip install regista[timestamping]
    """
    _check_key_permissions_strict(keys)

    from regista import Regista
    from regista._timestamping import TSAConfig

    sub = Regista(dsn=dsn, project=project, hmac_key_path=str(keys))

    tsa_config = TSAConfig(
        tsa_url=tsa_url,
        batch_size=batch_size,
        hash_algorithm=hash_algo,
    )
    sub.timestamping.set_config(tsa_config)

    try:
        batch = sub.timestamping.trigger()
        if batch is None:
            click.echo("No unbaptized events to timestamp.")
        else:
            click.echo(f"Timestamped batch {batch.batch_id}")
            click.echo(f"  Events      : {len(batch.event_ids)}")
            click.echo(f"  Merkle root : {batch.merkle_root.hex()[:32]}...")
            click.echo(f"  Status      : {batch.status}")
            if batch.tsa_timestamp:
                click.echo(f"  TSA time    : {batch.tsa_timestamp}")
    except Exception as exc:
        click.echo(f"Timestamping failed: {exc}", err=True)
        raise SystemExit(1) from exc
    finally:
        sub.close()


@main.command("install-harness")
@click.argument(
    "harness",
    type=click.Choice(["claude", "opencode", "all"]),
)
@click.option("--dry-run", is_flag=True, help="Print planned changes; act on nothing")
@click.option("--uninstall", is_flag=True, help="Reverse a prior install-harness")
@click.option("--user", default=None, help="Per-user principal_id overlay")
@click.option("--json", "json_output", is_flag=True, help="Emit contract-shaped JSON")
def install_harness(
    harness: str,
    dry_run: bool,
    uninstall: bool,
    user: str | None,
    json_output: bool,
) -> None:
    """Wire cairn's interception (hooks + default-on env) into a named harness."""
    from ._install import format_results_human, run_install_harness

    results = run_install_harness(harness, dry_run=dry_run, uninstall=uninstall, user=user)

    if json_output:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        click.echo(format_results_human(results, dry_run=dry_run, uninstall=uninstall))

    if dry_run:
        sys.exit(2)


@main.command("uninstall-harness")
@click.argument(
    "harness",
    type=click.Choice(["claude", "opencode", "all"]),
)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_output", is_flag=True)
def uninstall_harness(harness: str, dry_run: bool, json_output: bool) -> None:
    """Reverse a prior ``cairn install-harness`` — removes only cairn's wiring."""
    from ._install import format_results_human, run_install_harness

    results = run_install_harness(harness, dry_run=dry_run, uninstall=True)

    if json_output:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        click.echo(format_results_human(results, dry_run=dry_run, uninstall=True))

    if dry_run:
        sys.exit(2)


@main.command()
@click.option("--json", "json_output", is_flag=True, help="Emit suite-shape JSON")
def doctor(json_output: bool) -> None:
    """Health check — validates config, regista connectivity, harness wiring."""
    from ._doctor import run_doctor

    sys.exit(run_doctor(json_output=json_output))


if __name__ == "__main__":
    main()
