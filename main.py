import os
from typing import Optional

import truststore
import typer

# Inject the OS/system trust store into Python's SSL handling early so
# downstream imports that make HTTPS requests (requests, ssl) will use it.
truststore.inject_into_ssl()
from checks import run_checks
from report import write_reports
from scanner import scan_target

app = typer.Typer(help="SurfaceSnap - baseline security analyzer")


def _scan_one_target(target: str, out_dir: str, timeout: int, max_hosts: int, ca_bundle: Optional[str]) -> None:
    # Ensure output directory exists
    os.makedirs(out_dir, exist_ok=True)

    # Run scan with provided timeout, optional host cap and optional custom CA bundle
    max_hosts_value = max_hosts if max_hosts and max_hosts > 0 else None
    result = scan_target(target, timeout=timeout, max_hosts=max_hosts_value, ca_bundle=ca_bundle)

    # Write reports (HTML + JSON)
    html_path, json_path = write_reports(result, out_dir)

    # Concise summary from result
    summary = result.get("summary", {})
    print(
        f"Scanned: {summary.get('total_hosts', 0)} host(s); Resolved: {summary.get('resolved_hosts', 0)}; Missing HSTS: {summary.get('missing_hsts_hosts', 0)}"
    )
    print(f"Reports: {html_path}, {json_path}")


def _load_targets(target: Optional[str], targets_file: Optional[str]) -> list[str]:
    targets: list[str] = []

    if target:
        targets.append(target)

    if targets_file:
        if not os.path.isfile(targets_file):
            typer.echo(f"Error: targets file not found: {targets_file}", err=True)
            raise typer.Exit(code=1)
        with open(targets_file, "r", encoding="utf-8") as file_handle:
            for line in file_handle:
                value = line.strip()
                if value and not value.startswith("#"):
                    targets.append(value)

    seen = set()
    deduped: list[str] = []
    for value in targets:
        if value not in seen:
            deduped.append(value)
            seen.add(value)
    return deduped


@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Single target domain or URL to scan"),
    targets_file: Optional[str] = typer.Option(
        None, "--targets-file", "-f", help="Path to a text file with one target per line"
    ),
    out: str = typer.Option("out", "--out", "-o", help="Output directory for reports"),
    timeout: int = typer.Option(5, "--timeout", help="Timeout (seconds) for network operations"),
    max_hosts: int = typer.Option(0, "--max-hosts", help="Maximum number of hosts to scan (0 = no limit)"),
    ca_bundle: Optional[str] = typer.Option(
        None, "--ca-bundle", help="Path to a PEM CA bundle to use for HTTPS verification"
    ),
) -> None:
    """Run a surface scan against one or more targets."""
    targets = _load_targets(target, targets_file)
    if not targets:
        typer.echo("Error: provide --target/-t and/or --targets-file/-f.", err=True)
        raise typer.Exit(code=1)

    for item in targets:
        _scan_one_target(item, out, timeout, max_hosts, ca_bundle)


@app.command()
def version() -> None:
    """Show CLI version."""
    typer.echo("SurfaceSnap CLI")


def main() -> None:
    app()


if __name__ == "__main__":
    app()
