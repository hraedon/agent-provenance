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
        if line.startswith("## 4.2"):
            in_control = True
            continue
        if line.startswith("## 4.3"):
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
def verify(bundle_path: Path, keys: Path, output: Path | None) -> None:
    """Verify a signed Cairn bundle and emit an auditor-ready report."""
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

    text = Verifier.format_report(report)
    if output:
        output.write_text(text)
        click.echo(f"Report written to {output}")
    else:
        click.echo(text, nl=False)

    if not report.all_ok:
        sys.exit(1)


@main.command()
@click.option("--dsn", required=True, help="Postgres DSN")
@click.option("--project", required=True, help="Substrate project name")
@click.option("--keys", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", required=True, type=click.Path(path_type=Path))
@click.option("--since", default=None, help="ISO timestamp for lower bound")
@click.option("--until", default=None, help="ISO timestamp for upper bound")
def export(
    dsn: str,
    project: str,
    keys: Path,
    output: Path,
    since: str | None,
    until: str | None,
) -> None:
    """Export events from substrate into a signed bundle for offline verification."""
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

    manifest: dict[str, Any] = {
        "events_count": len(events),
        "exported_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "source_project": project,
        "source_dsn_host": sub.connection_info.host,
    }

    if control_description:
        manifest["control_description"] = control_description
        manifest["control_description_source_digest"] = (
            "sha256:" + hashlib.sha256(readme_text.encode("utf-8")).hexdigest()
        )
    manifest["trust_model_caveat"] = trust_model_caveat

    bundle = {
        "manifest": manifest,
        "events": [ev.to_dict() for ev in events],
    }

    canonical = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")
    bundle["manifest"]["bundle_hash"] = "sha256:" + hashlib.sha256(canonical).hexdigest()

    output.write_text(json.dumps(bundle, indent=2))
    click.echo(f"Exported {len(events)} events to {output}")
    sub.close()


if __name__ == "__main__":
    main()
