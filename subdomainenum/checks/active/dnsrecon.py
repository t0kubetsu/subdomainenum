"""Wrapper for dnsrecon DNS enumeration tool."""

from __future__ import annotations

import os
from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import SourceResult

# Core enumeration types:
#   std  — SOA, NS, A, AAAA, MX, SRV (base standard)
#   brt  — brute-force subdomain/host names using -D wordlist
# The boolean flags below extend std with additional data sources.
_TYPES = "std,brt"


def run_dnsrecon(
    domain: str,
    *,
    wordlist: str,
    timeout: int = 300,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run dnsrecon for *domain* using all applicable enumeration capabilities.

    Runs a single invocation combining standard enumeration with all supported
    boolean extension flags and brute-force:

    - ``-t std,brt`` — standard records + wordlist brute-force
    - ``-a`` — AXFR zone transfer attempt against all NS servers
    - ``-s`` — reverse lookup of IPv4 ranges found in SPF records
    - ``-b`` — Bing search enumeration
    - ``-y`` — Yandex search enumeration
    - ``-k`` — crt.sh certificate transparency enumeration
    - ``-w`` — deep whois analysis with reverse lookup of found IP ranges
    - ``-z`` — DNSSEC zone walk via NSEC records
    - ``--shodan`` — Shodan lookup, added automatically when
      ``SHODAN_API_KEY`` is set in the environment

    Excluded:
    - ``rvl`` — requires ``-r`` IP range, not available here
    - ``tld`` — tests TLD variations, not subdomain discovery
    - ``snoop`` — requires ``-n NS_SERVER``; errors without it

    :param domain: Target base domain.
    :param wordlist: Absolute path to the wordlist file (used for brt).
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
        "-t", _TYPES,
        "-a",   # AXFR with standard enumeration
        "-s",   # SPF IPv4 reverse lookup
        "-b",   # Bing enumeration
        "-y",   # Yandex enumeration
        "-k",   # crt.sh enumeration
        "-w",   # deep whois + IP range reverse lookup
        "-z",   # DNSSEC zone walk
        "--lifetime", "3",
    ]
    if os.environ.get("SHODAN_API_KEY"):
        cmd.append("--shodan")

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
