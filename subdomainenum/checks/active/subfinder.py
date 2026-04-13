"""Wrapper for subfinder subdomain enumeration tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import SourceResult


def run_subfinder(
    domain: str,
    *,
    timeout: int = 120,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run subfinder for *domain* and return a :class:`~subdomainenum.models.SourceResult`.

    :param domain: Target base domain.
    :param timeout: Maximum seconds to wait for subfinder.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :rtype: SourceResult
    """
    result = SourceResult(name="subfinder")
    cmd = ["subfinder", "-d", domain, "-silent"]
    try:
        lines = run_tool(cmd, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    result.subdomains = lines
    return result
