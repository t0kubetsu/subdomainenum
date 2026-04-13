"""Wrapper for amass subdomain enumeration tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import SourceResult


def run_amass(
    domain: str,
    *,
    passive: bool = True,
    timeout: int = 300,
    line_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run amass for *domain* and return a :class:`~subdomainenum.models.SourceResult`.

    :param domain: Target base domain.
    :param passive: When ``True``, passes ``-passive`` to use only passive APIs.
    :param timeout: Maximum seconds to wait for amass (it can be slow).
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :rtype: SourceResult
    """
    result = SourceResult(name="amass")
    cmd = ["amass", "enum", "-d", domain, "-silent"]
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
