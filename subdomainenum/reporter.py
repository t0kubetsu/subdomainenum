"""Rich terminal rendering and JSON serialization for subdomainenum reports."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from subdomainenum.models import EnumReport, EnumMode, Status
from subdomainenum.verdict import build_verdict

_console = Console()


# ---------------------------------------------------------------------------
# JSON / dict serialization
# ---------------------------------------------------------------------------


def to_dict(report: EnumReport) -> dict:
    """Serialize *report* to a plain dictionary suitable for JSON output.

    :param report: Completed enumeration report.
    :returns: JSON-serializable dict.
    :rtype: dict
    """
    return {
        "domain": report.domain,
        "mode": report.mode.value,
        "subdomains": [
            {
                "fqdn": s.fqdn,
                "status": s.status.value,
                "alive": s.alive,
                "ip_addresses": s.ip_addresses,
                "sources": s.sources,
            }
            for s in report.subdomains
        ],
        "vhosts": [
            {
                "vhost": v.vhost,
                "status_code": v.status_code,
                "ip": v.ip,
                "content_length": v.content_length,
            }
            for v in report.vhosts
        ],
        "sources": [
            {
                "name": s.name,
                "count": len(s.subdomains),
                "available": s.available,
                "error": s.error,
            }
            for s in report.sources
        ],
    }


# ---------------------------------------------------------------------------
# Rich rendering
# ---------------------------------------------------------------------------


def _status_style(status: Status) -> str:
    return {
        Status.ALIVE: "green",
        Status.DEAD: "red",
        Status.TIMEOUT: "yellow",
        Status.ERROR: "red bold",
        Status.FOUND: "cyan",
        Status.NOT_FOUND: "dim",
        Status.SKIPPED: "dim",
    }.get(status, "white")


def print_report(report: EnumReport, *, console: Console | None = None) -> None:
    """Render the full enumeration report to the terminal using Rich.

    :param report: Completed enumeration report.
    :param console: Optional Rich :class:`~rich.console.Console` instance
        (defaults to the module-level console).
    """
    con = console or _console
    verdict = build_verdict(report)

    # Header
    con.print(Panel(
        f"[bold cyan]Subdomain Enumeration[/bold cyan]  ·  [white]{report.domain}[/white]"
        f"  ·  mode: [yellow]{report.mode.value}[/yellow]",
        box=box.ROUNDED,
        expand=False,
    ))

    # Subdomains table
    if report.subdomains:
        sub_table = Table(
            "FQDN", "Status", "IP Addresses", "Sources",
            box=box.SIMPLE_HEAD,
            highlight=True,
        )
        for s in report.subdomains:
            sub_table.add_row(
                s.fqdn,
                Text(s.status.value, style=_status_style(s.status)),
                ", ".join(s.ip_addresses) or "—",
                ", ".join(s.sources),
            )
        con.print(sub_table)
    else:
        con.print("[dim]No subdomains found.[/dim]")

    # Vhosts table
    if report.vhosts:
        con.print("\n[bold]Virtual Hosts (wfuzz)[/bold]")
        vh_table = Table("Host", "Status Code", "Content-Length", "IP", box=box.SIMPLE_HEAD)
        for v in report.vhosts:
            vh_table.add_row(v.vhost, str(v.status_code), str(v.content_length), v.ip or "—")
        con.print(vh_table)

    # Sources summary table
    if report.sources:
        con.print("\n[bold]Sources[/bold]")
        src_table = Table("Source", "Found", "Available", "Error", box=box.SIMPLE_HEAD)
        for s in report.sources:
            avail = "[green]yes[/green]" if s.available else "[red]no[/red]"
            src_table.add_row(s.name, str(len(s.subdomains)), avail, s.error or "")
        con.print(src_table)

    # Verdict summary line
    con.print(Panel(verdict.summary_line, title="Summary", box=box.ROUNDED, expand=False))


def save_report(report: EnumReport, path: str | Path) -> None:
    """Save the report as JSON to *path*.

    :param report: Completed enumeration report.
    :param path: Destination file path.
    """
    data = to_dict(report)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
