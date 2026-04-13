"""Wrapper for findomain subdomain enumeration tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import SourceResult


def run_findomain(
    domain: str,
    *,
    timeout: int = 120,
    line_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run findomain for *domain* and return a :class:`~subdomainenum.models.SourceResult`.

    findomain is passive by nature (queries multiple APIs).

    :param domain: Target base domain.
    :param timeout: Maximum seconds to wait for findomain.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :rtype: SourceResult
    """
    result = SourceResult(name="findomain")
    cmd = ["findomain", "--target", domain, "--quiet"]
    try:
        lines = run_tool(cmd, timeout=timeout, line_cb=line_cb)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    result.subdomains = lines
    return result
