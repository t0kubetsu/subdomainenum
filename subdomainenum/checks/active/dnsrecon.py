"""Wrapper for dnsrecon DNS enumeration tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import SourceResult

# All applicable types in one invocation.
# -D wordlist is always passed; types that don't need it simply ignore it.
# Excluded:
#   rvl      — requires -r IP range, not available here
#   tld      — tests TLD variations, not subdomain discovery
#   snoop    — requires -n NS_SERVER in addition to -D; not generally available
_ALL_TYPES = "std,srv,axfr,crt,zonewalk,bing,yand,brt"


def run_dnsrecon(
    domain: str,
    *,
    wordlist: str,
    timeout: int = 300,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run dnsrecon for *domain* covering all applicable enumeration types.

    A single subprocess invocation is used with ``-t std,srv,axfr,crt,
    zonewalk,bing,yand,brt`` and ``-D wordlist``.  Types that do not need a
    wordlist silently ignore the ``-D`` flag.

    Excluded types:
    - ``rvl`` — requires an IP range (``-r``), not applicable here.
    - ``tld`` — tests TLD variations, not subdomain discovery.
    - ``snoop`` — requires ``-n NS_SERVER`` in addition to ``-D``.

    :param domain: Target base domain.
    :param wordlist: Absolute path to the wordlist file.
    :param timeout: Maximum seconds to wait for dnsrecon.
    :param line_cb: Optional callback invoked with each output line (debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :rtype: SourceResult
    """
    result = SourceResult(name="dnsrecon")
    cmd = [
        "dnsrecon",
        "-d", domain,
        "-D", wordlist,
        "-t", _ALL_TYPES,
        "--lifetime", "3",
    ]
    try:
        lines = run_tool(cmd, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    # dnsrecon outputs lines like: "[*] A sub.example.com 1.2.3.4"
    suffix = f".{domain}"
    for line in lines:
        parts = line.split()
        for part in parts:
            part = part.lower()
            if part == domain or part.endswith(suffix):
                if part not in result.subdomains:
                    result.subdomains.append(part)

    return result
