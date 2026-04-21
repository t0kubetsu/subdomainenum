"""Wrapper for assetfinder subdomain enumeration tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import ToolResult


def run_assetfinder(
    domain: str,
    *,
    timeout: int = 120,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
    fqdn_cb: Callable[[str], None] | None = None,
) -> ToolResult:
    """Run assetfinder for *domain* and return a :class:`~subdomainenum.models.ToolResult`.

    :param domain: Target base domain.
    :param timeout: Maximum seconds to wait for assetfinder.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :param fqdn_cb: Optional callback invoked with each in-scope FQDN as soon as
        assetfinder emits it. With ``--subs-only`` assetfinder emits one FQDN
        per line, so every matching line is forwarded after lower-casing and
        stripping.
    :rtype: ToolResult
    """
    result = ToolResult(name="assetfinder")
    cmd = ["assetfinder", "--subs-only", domain]

    suffix = f".{domain}"

    def _on_line(line: str) -> None:
        if line_cb is not None:
            line_cb(line)
        if fqdn_cb is None:
            return
        fqdn = line.lower().strip()
        if fqdn and (fqdn == domain or fqdn.endswith(suffix)):
            fqdn_cb(fqdn)

    try:
        lines, timed_out = run_tool(cmd, timeout=timeout, line_cb=_on_line, cmd_cb=cmd_cb)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    result.subdomains = lines
    result.timed_out = timed_out
    return result
