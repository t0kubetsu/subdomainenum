"""Rich terminal rendering and JSON serialization for subdomainenum reports."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console, Group
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from subdomainenum.models import EnumMode, EnumReport, Status
from subdomainenum.verdict import build_verdict

_console = Console()


_SECTION_PANEL_KWARGS = dict(style="white", padding=(0, 1))
_TABLE_KWARGS = dict(
    box=box.ROUNDED,
    show_header=True,
    header_style="bold white",
    border_style="dim",
    expand=False,
    padding=(0, 1),
)


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
                "tools": s.tools,
            }
            for s in report.subdomains
        ],
        "vhosts": [
            {
                "vhost": v.vhost,
                "status_code": v.status_code,
                "content_length": v.content_length,
            }
            for v in report.vhosts
        ],
        "tools": [
            {
                "name": t.name,
                "count": len(t.subdomains),
                "available": t.available,
                "error": t.error,
                "timed_out": t.timed_out,
                "mode": t.mode.value if t.mode is not None else None,
            }
            for t in report.tools
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

    # Header rule
    con.rule(f"[bold cyan]Subdomain Enumeration Report — {report.domain}[/bold cyan]")
    con.print(f"  [dim]mode:[/dim] [yellow]{report.mode.value}[/yellow]", highlight=False)
    con.print()

    # Subdomains section
    if report.subdomains:
        sub_table = Table(**_TABLE_KWARGS)
        sub_table.add_column("FQDN", style="cyan", no_wrap=True)
        sub_table.add_column("Status", min_width=8, no_wrap=True)
        sub_table.add_column("IP Addresses")
        sub_table.add_column("Tools", style="dim")
        for s in report.subdomains:
            sub_table.add_row(
                s.fqdn,
                Text(s.status.value, style=_status_style(s.status)),
                ", ".join(s.ip_addresses) or "—",
                ", ".join(s.tools),
            )
        con.print(Panel(
            sub_table,
            title="[bold]Subdomains[/bold]",
            **_SECTION_PANEL_KWARGS,
        ))
    else:
        con.print(Panel(
            "[dim]No subdomains found.[/dim]",
            title="[bold]Subdomains[/bold]",
            **_SECTION_PANEL_KWARGS,
        ))

    # Vhosts section
    if report.vhosts:
        vh_table = Table(**_TABLE_KWARGS)
        vh_table.add_column("Host", style="cyan", no_wrap=True)
        vh_table.add_column("Status Code", justify="right", min_width=5)
        vh_table.add_column("Content-Length", justify="right", min_width=7)
        for v in report.vhosts:
            vh_table.add_row(v.vhost, str(v.status_code), str(v.content_length))
        con.print(Panel(
            vh_table,
            title="[bold]Virtual Hosts (ffuf)[/bold]",
            **_SECTION_PANEL_KWARGS,
        ))

    # Tools section
    if report.tools:
        show_mode = report.mode == EnumMode.ALL
        tool_table = Table(**_TABLE_KWARGS)
        tool_table.add_column("Tool", style="cyan", no_wrap=True)
        if show_mode:
            tool_table.add_column("Mode", style="dim", no_wrap=True)
        tool_table.add_column("Found", justify="right", min_width=5)
        tool_table.add_column("Available", justify="center", min_width=9)
        tool_table.add_column("Timed Out", justify="center", min_width=9)
        tool_table.add_column("Error", style="dim")
        for t in report.tools:
            avail = "[green]yes[/green]" if t.available else "[red]no[/red]"
            timeout_cell = "[yellow]yes[/yellow]" if t.timed_out else ""
            row = [t.name]
            if show_mode:
                row.append(t.mode.value if t.mode is not None else "—")
            row += [str(len(t.subdomains)), avail, timeout_cell, t.error or ""]
            tool_table.add_row(*row)
        con.print(Panel(
            tool_table,
            title="[bold]Tools[/bold]",
            **_SECTION_PANEL_KWARGS,
        ))

    # Summary panel (counts only — no grading)
    summary_text = Text.from_markup(f"[bold]{verdict.summary_line}[/bold]")
    breakdown = Table(box=box.SIMPLE, show_header=False, expand=False, padding=(0, 1))
    breakdown.add_column(style="dim", no_wrap=True)
    breakdown.add_column()
    breakdown.add_row(
        "Subdomains",
        f"{verdict.total_subdomains} total · "
        f"[green]{verdict.alive} alive[/green] · "
        f"[red]{verdict.dead} dead[/red] · "
        f"[yellow]{verdict.timeouts} timeout(s)[/yellow]",
    )
    if verdict.vhosts_found:
        breakdown.add_row("Vhosts", f"{verdict.vhosts_found} discovered")
    tools_total = verdict.tools_ran + verdict.tools_failed + verdict.tools_timed_out
    breakdown.add_row(
        "Tools",
        f"{tools_total} total · "
        f"[green]{verdict.tools_ran} ran[/green] · "
        f"[red]{verdict.tools_failed} failed[/red] · "
        f"[yellow]{verdict.tools_timed_out} timed out[/yellow]",
    )
    if verdict.tools_available:
        breakdown.add_row("Available", ", ".join(verdict.tools_available))
    if verdict.tools_missing:
        breakdown.add_row("Missing", ", ".join(verdict.tools_missing))

    con.print(Panel(
        Group(summary_text, breakdown),
        title="Summary",
        border_style="white",
        expand=False,
        padding=(0, 1),
    ))

    con.rule("[dim]End of Report[/dim]")


def save_report(report: EnumReport, path: str | Path) -> None:
    """Save the report as JSON to *path*.

    :param report: Completed enumeration report.
    :param path: Destination file path.
    """
    data = to_dict(report)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
