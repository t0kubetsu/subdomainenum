"""Thread-safe debug logger for subdomain enumeration tool output.

Collects per-source output lines, commands, and finish signals from
``assess()`` callbacks and writes a structured plain-text log file.
No Rich / terminal dependency — pure stdlib.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from threading import Lock


class DebugLogger:
    """Collect tool output from ``assess()`` callbacks and persist to a file.

    All public methods are safe to call from multiple threads concurrently
    (passive sources run in a :class:`~concurrent.futures.ThreadPoolExecutor`).

    Usage::

        logger = DebugLogger()
        assess(
            domain,
            ...,
            debug_cb=logger.add_line,
            cmd_cb=logger.set_command,
            finish_cb=logger.finish,
        )
        logger.save_to_file("/tmp/debug.log")
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._order: list[str] = []
        self._lines: dict[str, list[str]] = {}
        self._commands: dict[str, str] = {}
        self._errors: dict[str, str | None] = {}
        self._statuses: dict[str, str] = {}
        self._invocation: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Callbacks wired to assess()
    # ------------------------------------------------------------------

    def _register(self, source: str) -> None:
        """Ensure *source* is tracked (must be called with ``self._lock`` held)."""
        if source not in self._order:
            self._order.append(source)
            self._lines[source] = []
            self._statuses[source] = "PENDING"

    def add_line(self, source: str, line: str) -> None:
        """Append an output *line* from *source*.

        :param source: Tool/source name (e.g. ``"subfinder"``).
        :param line: Raw output line emitted by the tool.
        """
        with self._lock:
            self._register(source)
            if self._statuses[source] == "PENDING":
                self._statuses[source] = "RUNNING"
            self._lines[source].append(line)

    def set_command(self, source: str, cmd: str) -> None:
        """Record the full command string for *source*.

        :param source: Tool/source name.
        :param cmd: Full command string or descriptive label.
        """
        with self._lock:
            self._register(source)
            self._commands[source] = cmd
            self._statuses[source] = "RUNNING"

    def finish(self, source: str, error: str | None) -> None:
        """Mark *source* as DONE or FAILED.

        :param source: Tool/source name.
        :param error: Error message if the source failed; ``None`` on success.
        """
        with self._lock:
            self._register(source)
            self._errors[source] = error
            self._statuses[source] = "FAILED" if error else "DONE"

    def set_invocation(
        self,
        version: str,
        mode: str,
        wordlist: str | None,
        url: str | None,
        timeout: float,
    ) -> None:
        """Record the CLI invocation parameters for inclusion in the log header.

        :param version: subdomainenum version string (e.g. ``"0.7.1"``).
        :param mode: Enumeration mode string (e.g. ``"passive"``, ``"active"``, ``"all"``).
        :param wordlist: Path to the DNS wordlist file, or ``None`` if not used.
        :param url: Target URL for vhost fuzzing, or ``None`` if not used.
        :param timeout: DNS resolution timeout per query in seconds.
        """
        with self._lock:
            self._invocation = {
                "version": version,
                "mode": mode,
                "wordlist": wordlist or "none",
                "url": url or "none",
                "timeout": f"{timeout}s",
            }

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def format_log(self, domain: str = "") -> str:
        """Return the complete log as a plain-text string.

        :param domain: Target domain included in the header (optional).
        :returns: Formatted log string.
        :rtype: str
        """
        with self._lock:
            order = list(self._order)
            lines_snap = {s: list(self._lines[s]) for s in order}
            commands = dict(self._commands)
            statuses = dict(self._statuses)
            errors = dict(self._errors)
            invocation = dict(self._invocation)

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        parts: list[str] = []
        header = f"subdomainenum debug log — {domain or 'unknown'} — {now}"
        parts.append(header)
        parts.append("=" * len(header))
        parts.append("")

        if invocation:
            parts.append("Invocation")
            field_width = max(len(k) for k in invocation)
            for key, val in invocation.items():
                parts.append(f"  {key:<{field_width}} : {val}")
            parts.append("")

        for source in order:
            status = statuses.get(source, "PENDING")
            parts.append(f"[{source}]  status={status}")

            cmd = commands.get(source)
            if cmd:
                parts.append(f"  $ {cmd}")

            for line in lines_snap[source]:
                parts.append(f"  {line}")

            error = errors.get(source)
            if error:
                parts.append(f"  ERROR: {error}")

            if not lines_snap[source] and not cmd and not error:
                parts.append("  (no output)")

            parts.append("")

        return "\n".join(parts)

    def save_to_file(self, path: str, domain: str = "") -> None:
        """Write the complete log to *path*.

        :param path: Destination file path.
        :param domain: Target domain included in the log header.
        :raises OSError: If the file cannot be written.
        """
        content = self.format_log(domain=domain)
        Path(path).write_text(content, encoding="utf-8")
