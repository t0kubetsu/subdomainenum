"""subdomainenum CLI – passive and active subdomain enumeration.

Sub-commands
------------
check   Run enumeration for a domain and print the report.
info    Show available/missing tools and their install hints.

Usage example::

    subdomainenum check example.com
    subdomainenum check example.com --mode active --wordlist /opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    subdomainenum check example.com --mode all --url http://10.0.0.1 --json
    subdomainenum info
"""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from typing import Annotated, Optional

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from subdomainenum import __version__
from subdomainenum.assessor import assess
from subdomainenum.constants import ACTIVE_TOOLS, detect_tools, get_install_hint
from subdomainenum.models import EnumMode
from subdomainenum.reporter import print_report, to_dict

app = typer.Typer(
    name="subdomainenum",
    help="Passive and active subdomain enumeration for a target domain.",
    add_completion=False,
)

_console = Console(stderr=False)
_err = Console(stderr=True)

_DEBUG_COLOURS: dict[str, str] = {
    "subfinder": "cyan",
    "amass": "yellow",
    "findomain": "blue",
    "assetfinder": "green",
    "dnsrecon": "magenta",
    "gobuster": "red",
    "wfuzz": "orange3",
    "crt.sh": "bright_cyan",
    "san": "bright_green",
}

_MAX_DEBUG_LINES = 20


class _DebugDisplay:
    """Thread-safe Live Rich display that renders each source's output in its own panel.

    Passive sources run concurrently, so ``add_line`` and ``set_command`` must be
    safe to call from multiple threads simultaneously.  A :class:`threading.Lock`
    protects the shared buffers; the :class:`~rich.live.Live` display is updated
    after each write.

    Usage::

        with _DebugDisplay(console, domain) as display:
            assess(..., debug_cb=display.add_line, cmd_cb=display.set_command)
    """

    def __init__(self, console: Console, domain: str) -> None:
        self._domain = domain
        self._lock = Lock()
        self._buffers: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=_MAX_DEBUG_LINES))
        self._commands: dict[str, str] = {}
        self._order: list[str] = []
        self._live = Live(
            self._render(),
            console=console,
            refresh_per_second=10,
        )

    def __enter__(self) -> _DebugDisplay:
        self._live.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        self._live.update(self._render())
        self._live.__exit__(*args)

    def add_line(self, source: str, line: str) -> None:
        """Append *line* from *source* and refresh the live display.

        :param source: Tool/source name (e.g. ``"subfinder"``).
        :param line: Raw output line emitted by the tool.
        """
        with self._lock:
            if source not in self._order:
                self._order.append(source)
            self._buffers[source].append(line)
        self._live.update(self._render())

    def set_command(self, source: str, cmd: str) -> None:
        """Record the command/label for *source* and refresh the live display.

        :param source: Tool/source name (e.g. ``"subfinder"``).
        :param cmd: Full command string or descriptive label for the operation.
        """
        with self._lock:
            if source not in self._order:
                self._order.append(source)
            self._commands[source] = cmd
        self._live.update(self._render())

    def _render(self) -> Group | Panel:
        """Build the current renderable from buffered lines."""
        with self._lock:
            order = list(self._order)
            snapshots = {s: list(self._buffers[s]) for s in order}
            commands = dict(self._commands)

        if not order:
            return Panel(
                "[dim]Waiting for sources…[/dim]",
                title=f"[bold]DEBUG[/bold] — {self._domain}",
                border_style="dim",
            )

        panels: list[Panel] = []
        for source in order:
            colour = _DEBUG_COLOURS.get(source, "white")
            lines = snapshots[source]
            cmd = commands.get(source)
            body_parts: list[str] = []
            if cmd:
                body_parts.append(f"[dim]$ {cmd}[/dim]")
            body_parts.append("\n".join(lines) if lines else "[dim]waiting…[/dim]")
            content = "\n".join(body_parts)
            panels.append(Panel(
                content,
                title=f"[bold {colour}]{source}[/bold {colour}]",
                border_style=colour,
                expand=True,
            ))
        return Group(*panels)


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}$"
)


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
    ] = EnumMode.PASSIVE,
    wordlist: Annotated[
        Optional[str],
        typer.Option("--wordlist", "-w", help="Path to DNS wordlist (required for active/all modes)."),
    ] = None,
    url: Annotated[
        Optional[str],
        typer.Option("--url", "-u", help="Target URL for wfuzz vhost fuzzing (e.g. http://10.0.0.1)."),
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
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Stream each tool's raw output to stderr in real time (coloured by source)."),
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

    if json_output:
        if debug:
            with _DebugDisplay(_err, domain) as display:
                try:
                    report = assess(
                        domain,
                        mode=mode,
                        wordlist=wordlist,
                        url=url,
                        timeout=timeout,
                        debug_cb=display.add_line,
                        cmd_cb=display.set_command,
                    )
                except Exception as exc:
                    _console.print(json.dumps({"error": str(exc)}, indent=2))
                    raise typer.Exit(code=1)
        else:
            try:
                report = assess(
                    domain,
                    mode=mode,
                    wordlist=wordlist,
                    url=url,
                    timeout=timeout,
                )
            except Exception as exc:
                _console.print(json.dumps({"error": str(exc)}, indent=2))
                raise typer.Exit(code=1)
        _print_json(report)
        return

    if debug:
        with _DebugDisplay(_err, domain) as display:
            try:
                report = assess(
                    domain,
                    mode=mode,
                    wordlist=wordlist,
                    url=url,
                    timeout=timeout,
                    debug_cb=display.add_line,
                    cmd_cb=display.set_command,
                )
            except ValueError as exc:
                _err.print(f"[red]Error:[/red] {exc}")
                raise typer.Exit(code=1)
    else:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=_err) as progress:
            task = progress.add_task(f"Enumerating {domain}…", total=None)

            def _progress_cb(msg: str) -> None:
                progress.update(task, description=msg)

            try:
                report = assess(
                    domain,
                    mode=mode,
                    wordlist=wordlist,
                    url=url,
                    timeout=timeout,
                    progress_cb=_progress_cb,
                )
            except ValueError as exc:
                _err.print(f"[red]Error:[/red] {exc}")
                raise typer.Exit(code=1)

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
