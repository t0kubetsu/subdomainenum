"""Wrapper for dnsrecon DNS brute-force tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import SourceResult


def run_dnsrecon(
    domain: str,
    *,
    wordlist: str,
    timeout: int = 300,
    line_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run dnsrecon brute-force mode for *domain* using *wordlist*.

    :param domain: Target base domain.
    :param wordlist: Absolute path to the wordlist file.
    :param timeout: Maximum seconds to wait for dnsrecon.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :rtype: SourceResult
    """
    result = SourceResult(name="dnsrecon")
    cmd = [
        "dnsrecon",
        "-d", domain,
        "-D", wordlist,
        "-t", "brt",
        "--lifetime", "3",
        "-q",
    ]
    try:
        lines = run_tool(cmd, timeout=timeout, line_cb=line_cb)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    # dnsrecon outputs lines like: "[*] A sub.example.com 1.2.3.4"
    # Extract the hostname (third token when line starts with [*] or similar).
    suffix = f".{domain}"
    for line in lines:
        parts = line.split()
        for part in parts:
            part = part.lower()
            if part == domain or part.endswith(suffix):
                if part not in result.subdomains:
                    result.subdomains.append(part)

    return result
