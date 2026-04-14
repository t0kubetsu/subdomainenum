"""subdomainenum CLI – passive and active subdomain enumeration.

Sub-commands
------------
check   Run enumeration for a domain and print the report.
info    Show available/missing tools and their install hints.

Usage example::

    subdomainenum check example.com
    subdomainenum check example.com --mode active --wordlist /opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    subdomainenum check example.com --mode all --url http://10.0.0.1 --json
    subdomainenum check example.com --debug-log
    subdomainenum info
"""

from __future__ import annotations

import datetime
import json
import re
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from subdomainenum import __version__
from subdomainenum.assessor import assess
from subdomainenum.constants import ACTIVE_TOOLS, detect_tools, get_install_hint
from subdomainenum.debug_logger import DebugLogger
from subdomainenum.models import EnumMode
from subdomainenum.reporter import print_report, to_dict

app = typer.Typer(
    name="subdomainenum",
    help="Passive and active subdomain enumeration for a target domain.",
    add_completion=False,
)

_console = Console(stderr=False)
_err = Console(stderr=True)


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}$"
)


def _auto_log_path(domain: str) -> Path:
    """Return an auto-generated log file path for *domain*.

    If ``/reports`` is a mounted directory (Docker volume), the file is placed
    there so it survives ``docker compose run --rm``.  Otherwise the file lands
    in the current working directory.

    :param domain: The enumeration target (used as a filename prefix).
    :returns: Absolute or relative :class:`~pathlib.Path` for the log file.
    """
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{ts}.log"
    reports_dir = Path("/reports")
    if reports_dir.is_dir():
        return reports_dir / filename
    return Path(filename)


def _validate_domain(value: str) -> str:
    if not _DOMAIN_RE.match(value):
        raise typer.BadParameter(f"Invalid domain: {value!r}")
    return value.lower()


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"subdomainenum {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool,
        typer.Option("--version", "-V", callback=version_callback, is_eager=True, help="Print version and exit."),
    ] = False,
) -> None:
    pass


# ---------------------------------------------------------------------------
# check command
# ---------------------------------------------------------------------------


@app.command()
def check(
    domain: Annotated[str, typer.Argument(help="Target domain (e.g. example.com).")],
    mode: Annotated[
        EnumMode,
        typer.Option("--mode", "-m", help="Enumeration mode: passive | active | all."),
    ] = EnumMode.ALL,
    wordlist: Annotated[
        Optional[str],
        typer.Option("--wordlist", "-w", help="Path to DNS wordlist (required for active/all modes)."),
    ] = None,
    url: Annotated[
        Optional[str],
        typer.Option("--url", "-u", help="Target URL for wfuzz vhost fuzzing (e.g. http://10.0.0.1). Auto-derived from the domain's resolved IP when omitted."),
    ] = None,
    output: Annotated[
        Optional[str],
        typer.Option(
            "--output",
            "-o",
            help=(
                "Save the report to a file. Format is inferred from the extension: "
                ".txt for plain text, .svg for SVG, .html for HTML."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print machine-readable JSON to stdout instead of Rich tables."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="DNS resolution timeout per query in seconds."),
    ] = 5.0,
    debug_log: Annotated[
        bool,
        typer.Option(
            "--debug-log",
            help=(
                "Save each tool's raw output to an auto-named log file. "
                "Written to /reports/<domain>_<timestamp>.log when that volume is mounted, "
                "otherwise to ./<domain>_<timestamp>.log."
            ),
        ),
    ] = False,
) -> None:
    """Run subdomain enumeration for DOMAIN and display the results."""
    domain = _validate_domain(domain)

    if mode in (EnumMode.ACTIVE, EnumMode.ALL) and not wordlist:
        _err.print("[red]Error:[/red] --wordlist is required for active and all modes.")
        raise typer.Exit(code=1)

    if wordlist and not Path(wordlist).is_file():
        _err.print(f"[red]Error:[/red] wordlist not found: {wordlist}")
        raise typer.Exit(code=1)

    logger: DebugLogger | None = DebugLogger() if debug_log else None

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=_err) as progress:
        task = progress.add_task(f"Enumerating {domain}…", total=None)

        def _progress_cb(msg: str) -> None:
            progress.update(task, description=msg)

        assess_kwargs: dict = dict(
            mode=mode,
            wordlist=wordlist,
            url=url,
            timeout=timeout,
            progress_cb=_progress_cb,
        )
        if logger is not None:
            assess_kwargs["debug_cb"] = logger.add_line
            assess_kwargs["cmd_cb"] = logger.set_command
            assess_kwargs["finish_cb"] = logger.finish

        try:
            report = assess(domain, **assess_kwargs)
        except Exception as exc:
            if json_output:
                _console.print(json.dumps({"error": str(exc)}, indent=2))
            else:
                _err.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1)

    if logger is not None:
        log_path = _auto_log_path(domain)
        logger.save_to_file(str(log_path), domain=domain)
        _err.print(f"[dim]Debug log →[/dim] {log_path}")

    if json_output:
        _print_json(report)
        return

    print_report(report, console=_console)

    if output:
        _save_report(report, output)


# ---------------------------------------------------------------------------
# info command
# ---------------------------------------------------------------------------


@app.command()
def info() -> None:
    """Show which external tools are available and how to install missing ones."""
    availability = detect_tools()

    table = Table("Tool", "Available", "Install hint", box=box.SIMPLE_HEAD)
    for name in sorted(ACTIVE_TOOLS):
        avail = availability.get(name, False)
        style = "green" if avail else "red"
        table.add_row(
            name,
            f"[{style}]{'yes' if avail else 'no'}[/{style}]",
            get_install_hint(name) if not avail else "",
        )
    _console.print(table)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _print_json(report) -> None:
    """Serialise *report* to JSON and print it to stdout via the console.

    :param report: :class:`~subdomainenum.models.EnumReport` to serialise.
    """
    _console.print(json.dumps(to_dict(report), indent=2))


def _save_report(report, path: str) -> None:
    """Render *report* to a file at *path*.

    The output format is inferred from the file extension:
    ``.txt`` → plain text (no ANSI codes), ``.svg`` → SVG image,
    ``.html`` → self-contained HTML page.  Any other extension is
    treated as plain text.

    :param report: :class:`~subdomainenum.models.EnumReport` to render.
    :param path: Destination file path.
    """
    from rich.console import Console as RichConsole

    ext = Path(path).suffix.lower()

    rec_console = RichConsole(record=True, highlight=False, width=120)
    print_report(report, console=rec_console)

    if ext == ".svg":
        content = rec_console.export_svg(title=f"subdomainenum — {report.domain}")
    elif ext == ".html":
        content = rec_console.export_html(inline_styles=True)
    else:
        content = rec_console.export_text()

    Path(path).write_text(content, encoding="utf-8")
    _console.print(f"[dim]Report saved to[/dim] {path}")


if __name__ == "__main__":  # pragma: no cover
    app()
