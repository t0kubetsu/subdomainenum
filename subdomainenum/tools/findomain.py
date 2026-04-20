"""Wrapper for findomain subdomain enumeration tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import ToolResult


def run_findomain(
    domain: str,
    *,
    timeout: int = 120,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> ToolResult:
    """Run findomain for *domain* and return a :class:`~subdomainenum.models.ToolResult`.

    findomain is passive by nature (queries multiple APIs).

    :param domain: Target base domain.
    :param timeout: Maximum seconds to wait for findomain.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :rtype: ToolResult
    """
    result = ToolResult(name="findomain")
    cmd = ["findomain", "--target", domain, "--quiet"]
    try:
        lines, timed_out = run_tool(cmd, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    result.subdomains = lines
    result.timed_out = timed_out
    return result
