"""Wrapper for subfinder subdomain enumeration tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import SourceResult


def run_subfinder(
    domain: str,
    *,
    passive: bool = True,
    timeout: int = 120,
    line_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run subfinder for *domain* and return a :class:`~subdomainenum.models.SourceResult`.

    :param domain: Target base domain.
    :param passive: When ``True``, passes ``-passive`` to restrict to passive APIs.
    :param timeout: Maximum seconds to wait for subfinder.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :rtype: SourceResult
    """
    result = SourceResult(name="subfinder")
    cmd = ["subfinder", "-d", domain, "-silent"]
    if passive:
        cmd.append("-passive")
    try:
        lines = run_tool(cmd, timeout=timeout, line_cb=line_cb)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    result.subdomains = lines
    return result
