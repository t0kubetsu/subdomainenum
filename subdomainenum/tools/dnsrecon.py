"""Wrapper for dnsrecon DNS enumeration tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import EnumMode, SourceResult

# Passive enumeration types (no wordlist required):
#   std — SOA, NS, A, AAAA, MX, SRV (standard DNS records)
#   srv — SRV record enumeration
# Extended with boolean flags: -b (Bing), -y (Yandex), -k (crt.sh)
_PASSIVE_TYPES = "std,srv"

# Active enumeration types (require -D wordlist):
#   brt — brute-force subdomain/host names using -D wordlist
# Extended with boolean flags: -a (AXFR), -z (DNSSEC zone walk)
_ACTIVE_TYPES = "brt"


def run_dnsrecon(
    domain: str,
    *,
    mode: EnumMode = EnumMode.ALL,
    wordlist: str | None = None,
    timeout: int = 300,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run dnsrecon for *domain* using the enumeration types appropriate for *mode*.

    Mode behaviour:

    - ``passive`` — ``-t std,srv`` with Bing (``-b``), Yandex (``-y``), and
      crt.sh (``-k``) flags; no wordlist required.
    - ``active`` — ``-t brt`` with AXFR (``-a``) and DNSSEC zone walk (``-z``)
      flags; requires a wordlist.
    - ``all`` — combines both type sets and all flags; requires a wordlist.

    Excluded:
    - ``snoop`` — requires ``-n NS_SERVER``; errors without it
    - ``rvl`` — requires ``-r`` IP range, not available here
    - ``tld`` — tests TLD variations, not subdomain discovery

    :param domain: Target base domain.
    :param mode: Enumeration mode controlling which types and flags are used.
    :param wordlist: Path to the wordlist file (required for active/all modes).
    :param timeout: Maximum seconds to wait for dnsrecon.
    :param line_cb: Optional callback invoked with each output line (debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :rtype: SourceResult
    """
    result = SourceResult(name="dnsrecon")

    if mode == EnumMode.PASSIVE:
        types = _PASSIVE_TYPES
        use_passive_flags = True
        use_active_flags = False
        use_wordlist = False
    elif mode == EnumMode.ACTIVE:
        types = _ACTIVE_TYPES
        use_passive_flags = False
        use_active_flags = True
        use_wordlist = True
    else:  # ALL
        types = f"{_PASSIVE_TYPES},{_ACTIVE_TYPES}"
        use_passive_flags = True
        use_active_flags = True
        use_wordlist = True

    cmd = ["dnsrecon", "-d", domain, "-t", types, "--lifetime", "3"]

    if use_wordlist and wordlist:
        cmd += ["-D", wordlist]

    if use_passive_flags:
        cmd += ["-b", "-y", "-k"]  # Bing, Yandex, crt.sh

    if use_active_flags:
        cmd += ["-a", "-z"]  # AXFR zone transfer, DNSSEC zone walk

    try:
        lines = run_tool(cmd, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb, capture_stderr=True, ignore_returncode=True)
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
