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
import sys
from pathlib import Path
from typing import Any

import click

from .schema import check_key_file_permissions
from .verifier import Verifier

TRUST_MODEL_CAVEAT = (
    "HMAC-SHA256 only; Ed25519 + RFC 3161 + witness federation are tracked as "
    "substrate Plan 011/012/013 dependencies. FIM-class positioning is a working "
    "hypothesis (README §4.1), not auditor-validated."
)

README_PATH = Path(__file__).resolve().parent.parent.parent / "README.md"


def _extract_readme_sections(readme_text: str) -> tuple[str | None, str | None]:
    """Return control description and caveat from README §4.2.

    Uses simple heading-match heuristics.
    """
    control_lines: list[str] = []
    in_control = False
    for raw in readme_text.splitlines():
        line = raw.rstrip()
        if line.lstrip("#").startswith(" 4.2"):
            in_control = True
            continue
        if line.lstrip("#").startswith(" 4.3"):
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
@click.version_option(version="0.1.0", prog_name="cairn")
def main() -> None:
    """Cairn — Cryptographic provenance for agentic workflows."""


@main.command()
@click.option("--bundle-path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--keys", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option("--format", "fmt", type=click.Choice(["text", "json", "html"]), default="text",
              help="Report format: text (human-readable), JSON, or self-contained HTML")
def verify(bundle_path: Path, keys: Path, output: Path | None, fmt: str) -> None:
    """Verify a signed Cairn bundle and emit an auditor-ready report."""
    for w in check_key_file_permissions(str(keys)):
        click.echo(f"WARNING: {w}", err=True)

    key_data = json.loads(keys.read_text())
    key_set: dict[str, bytes] = {}
    for entry in key_data["keys"]:
        key_id: str = entry["key_id"]
        secret_raw = entry["secret"]
        encoding = entry.get("encoding", "utf8")
        if encoding == "base64":
            secret: bytes = base64.b64decode(secret_raw)
        else:
            secret = secret_raw.encode("utf-8")
        key_set[key_id] = secret

    verifier = Verifier(key_set)
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
@click.option("--format", "fmt", type=click.Choice(["text", "json", "html"]), default="text",
              help="Report format: text (human-readable), JSON, or self-contained HTML")
def verify_chain(
    bundles: tuple[Path, ...],
    keys: Path,
    output: Path | None,
    fmt: str,
) -> None:
    """Verify a chain of bundles linked by previous_bundle_hash."""
    for w in check_key_file_permissions(str(keys)):
        click.echo(f"WARNING: {w}", err=True)

    key_data = json.loads(keys.read_text())
    key_set: dict[str, bytes] = {}
    for entry in key_data["keys"]:
        key_id: str = entry["key_id"]
        secret_raw = entry["secret"]
        encoding = entry.get("encoding", "utf8")
        if encoding == "base64":
            secret: bytes = base64.b64decode(secret_raw)
        else:
            secret = secret_raw.encode("utf-8")
        key_set[key_id] = secret

    verifier = Verifier(key_set)
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
@click.option("--project", required=True, help="Substrate project name")
@click.option("--keys", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", required=True, type=click.Path(path_type=Path))
@click.option("--since", default=None, help="ISO timestamp for lower bound")
@click.option("--until", default=None, help="ISO timestamp for upper bound")
@click.option(
    "--previous-bundle-hash",
    default=None,
    help="sha256:... hash of the preceding bundle for chain integrity",
)
def export(
    dsn: str,
    project: str,
    keys: Path,
    output: Path,
    since: str | None,
    until: str | None,
    previous_bundle_hash: str | None,
) -> None:
    """Export events from substrate into a signed bundle for offline verification."""
    for w in check_key_file_permissions(str(keys)):
        click.echo(f"WARNING: {w}", err=True)

    from substrate import Substrate

    sub = Substrate(dsn=dsn, project=project, hmac_key_path=str(keys))

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

    if previous_bundle_hash:
        manifest["previous_bundle_hash"] = previous_bundle_hash

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

    canonical = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()

    bundle["manifest"]["bundle_hash"] = digest
    bundle["manifest"]["bundle_hash_covers"] = (
        "manifest (minus bundle_hash) + events, canonical JSON"
    )

    output.write_text(json.dumps(bundle, indent=2))
    click.echo(f"Exported {len(events)} events to {output}")
    sub.close()


@main.command("extract-control")
@click.option("--readme", type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to README.md (auto-detected if omitted)")
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format: text (human-readable) or JSON")
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
        result = json.dumps({
            "control_description": control_description,
            "trust_model_caveat": trust_model_caveat,
            "source_path": str(readme),
            "source_digest": source_digest,
            "source_section": "§4.2",
        }, indent=2)
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
        lines.append(trust_model_caveat)
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
@click.option("--older", required=True, type=click.Path(exists=True, path_type=Path),
              help="Older bundle path (baseline)")
@click.option("--newer", required=True, type=click.Path(exists=True, path_type=Path),
              help="Newer bundle path to compare against baseline")
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Report format: text (human-readable) or JSON")
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


if __name__ == "__main__":
    main()
