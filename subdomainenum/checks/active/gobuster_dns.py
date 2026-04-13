"""Wrapper for gobuster in dns mode."""

from __future__ import annotations

from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import SourceResult


def run_gobuster_dns(
    domain: str,
    *,
    wordlist: str,
    threads: int = 50,
    timeout: int = 300,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run gobuster dns brute-force for *domain*.

    :param domain: Target base domain.
    :param wordlist: Absolute path to the wordlist file.
    :param threads: Number of concurrent threads (default 50).
    :param timeout: Maximum seconds to wait for gobuster.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :rtype: SourceResult
    """
    result = SourceResult(name="gobuster")
    cmd = [
        "gobuster", "dns",
        "--domain", domain,
        "-w", wordlist,
        "-t", str(threads),
        "-q",
        "--no-color",
    ]
    try:
        lines = run_tool(cmd, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    # gobuster dns outputs: "Found: sub.example.com"
    suffix = f".{domain}"
    for line in lines:
        parts = line.split()
        for part in parts:
            part = part.lower().rstrip(".")
            if part == domain or part.endswith(suffix):
                if part not in result.subdomains:
                    result.subdomains.append(part)

    return result
