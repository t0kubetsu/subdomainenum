"""Wrapper for amass subdomain enumeration tool."""

from __future__ import annotations

import re
from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import EnumMode, ToolResult

# amass v4 outputs relationship lines: "<entity> (<type>) --> <relation> --> <entity> (<type>)"
_AMASS_FQDN_RE = re.compile(r"^(\S+)\s+\(FQDN\)\s+-->")
# Strip ANSI terminal escape sequences that some amass builds emit in certain environments.
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def _parse_amass_output(lines: list[str], domain: str) -> list[str]:
    """Extract target-domain FQDNs from amass v4 graph-format output.

    amass v4 outputs relationship lines such as::

        sub.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)
        example.com (FQDN) --> ns_record --> ns1.eurodns.com (FQDN)

    Only left-hand FQDNs that equal *domain* or end with ``.<domain>`` are kept.
    External FQDNs (e.g. nameservers) appearing on the right-hand side are ignored.

    :param lines: Raw output lines from amass.
    :param domain: Base domain to filter by.
    :returns: Deduplicated list of matching FQDNs.
    :rtype: list[str]
    """
    suffix = f".{domain}"
    seen: set[str] = set()
    results: list[str] = []
    for line in lines:
        clean = _ANSI_ESCAPE_RE.sub("", line)
        match = _AMASS_FQDN_RE.match(clean)
        if not match:
            continue
        fqdn = match.group(1).lower()
        if fqdn == domain or fqdn.endswith(suffix):
            if fqdn not in seen:
                seen.add(fqdn)
                results.append(fqdn)
    return results


def run_amass(
    domain: str,
    *,
    mode: EnumMode = EnumMode.PASSIVE,
    wordlist: str | None = None,
    timeout: int = 600,
    idle_timeout: int = 120,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> ToolResult:
    """Run amass for *domain* and return a :class:`~subdomainenum.models.ToolResult`.

    :param domain: Target base domain.
    :param mode: Enumeration mode.  When ``active`` or ``all``, ``-active`` is
        appended to enable zone transfers and certificate name grabs.
    :param wordlist: Path to a wordlist file.  When provided and mode is ``active``
        or ``all``, ``-brute -w <wordlist>`` is appended to enable brute-force
        subdomain enumeration.
    :param timeout: Hard ceiling in seconds; amass is killed if it runs this long
        regardless of output activity.
    :param idle_timeout: Seconds of silence after which amass is killed even if the
        hard *timeout* has not elapsed.  Resets whenever amass emits a new line.
        Prevents the common case where amass stalls indefinitely without output.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :rtype: ToolResult
    """
    result = ToolResult(name="amass")
    cmd = ["amass", "enum", "-d", domain]
    if mode in (EnumMode.ACTIVE, EnumMode.ALL):
        cmd.append("-active")
        if wordlist:
            cmd += ["-brute", "-w", wordlist]
    try:
        lines, timed_out = run_tool(
            cmd,
            timeout=timeout,
            idle_timeout=idle_timeout,
            line_cb=line_cb,
            cmd_cb=cmd_cb,
            ignore_returncode=True,
        )
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    result.subdomains = _parse_amass_output(lines, domain)
    result.timed_out = timed_out
    return result
