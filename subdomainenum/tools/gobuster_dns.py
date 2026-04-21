"""Wrapper for gobuster in dns mode."""

from __future__ import annotations

from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import ToolResult


def run_gobuster_dns(
    domain: str,
    *,
    wordlist: str,
    threads: int = 50,
    timeout: int = 300,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
    fqdn_cb: Callable[[str], None] | None = None,
) -> ToolResult:
    """Run gobuster dns brute-force for *domain*.

    :param domain: Target base domain.
    :param wordlist: Absolute path to the wordlist file.
    :param threads: Number of concurrent threads (default 50).
    :param timeout: Maximum seconds to wait for gobuster.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :param fqdn_cb: Optional callback invoked with each in-scope FQDN as soon as
        gobuster emits it. Lines are tokenized and any token matching the
        target domain or its suffix is forwarded after lower-casing and
        trailing-dot trimming.
    :rtype: ToolResult
    """
    result = ToolResult(name="gobuster")
    cmd = [
        "gobuster", "dns",
        "--domain", domain,
        "-w", wordlist,
        "-t", str(threads),
        "-q",
        "--no-color",
    ]

    suffix = f".{domain}"
    streamed_seen: set[str] = set()
    streamed: list[str] = []

    def _on_line(line: str) -> None:
        if line_cb is not None:
            line_cb(line)
        if fqdn_cb is None:
            return
        for raw in line.split():
            part = raw.lower().rstrip(".")
            if part in streamed_seen:
                continue
            if part == domain or part.endswith(suffix):
                streamed_seen.add(part)
                streamed.append(part)
                fqdn_cb(part)

    try:
        lines, timed_out = run_tool(cmd, timeout=timeout, line_cb=_on_line, cmd_cb=cmd_cb)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    if fqdn_cb is not None:
        result.subdomains = streamed
    else:
        # gobuster dns outputs: "Found: sub.example.com"
        for line in lines:
            parts = line.split()
            for part in parts:
                part = part.lower().rstrip(".")
                if part == domain or part.endswith(suffix):
                    if part not in result.subdomains:
                        result.subdomains.append(part)

    result.timed_out = timed_out
    return result
