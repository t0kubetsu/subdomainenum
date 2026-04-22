"""Wrapper for dnsrecon DNS enumeration tool."""

from __future__ import annotations

import os
from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import EnumMode, ToolResult
from subdomainenum.dns_utils import resolve_ips, resolve_ns

# Passive enumeration types (no wordlist required):
#   std — SOA, NS, A, AAAA, MX, SRV (standard DNS records)
#   srv — SRV record enumeration
# Extended with boolean flags: -b (Bing), -y (Yandex), -k (crt.sh)
_PASSIVE_TYPES = "std,srv"

# Optional passive type (requires -D wordlist and -n nameserver):
#   snoop — cache-snoop the domain's authoritative NS for entries in the
#   wordlist. We resolve NS records first and pass them via -n so that
#   dnsrecon does not need to auto-derive them (which is unreliable).
_PASSIVE_SNOOP_TYPE = "snoop"

# Active-phase DNS brute-force is delegated to ``gobuster dns`` (higher
# concurrency, faster turnaround); dnsrecon's ``brt`` type is intentionally
# no longer emitted. AXFR (``-a``) and DNSSEC zone walk (``-z``) are cheap
# and remain in the active invocation alongside ``std,srv``.
_ACTIVE_TYPES = "std,srv"

# dnsrecon consults SHODAN_API_KEY as the fallback for --shodan-key. When the
# env var is present we enable --shodan and --shodan-active during passive
# enumeration to enrich netblocks discovered via -s (SPF reverse) and -w
# (whois). No CLI flag is exposed in subdomainenum — the enrichment is
# opt-in purely via the environment.
_SHODAN_ENV_VAR = "SHODAN_API_KEY"


def run_dnsrecon(
    domain: str,
    *,
    mode: EnumMode = EnumMode.ALL,
    wordlist: str | None = None,
    timeout: int = 300,
    threads: int | None = None,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
    fqdn_cb: Callable[[str], None] | None = None,
) -> ToolResult:
    """Run dnsrecon for *domain* using the enumeration types appropriate for *mode*.

    Mode behaviour:

    - ``passive`` — ``-t std,srv`` with Bing (``-b``), Yandex (``-y``), crt.sh
      (``-k``), and SPF reverse lookup (``-s``) flags; no wordlist required.
      When a wordlist *is* supplied, ``snoop`` is added to the types so the
      domain's authoritative NS is cache-snooped for each wordlist entry. When
      the ``SHODAN_API_KEY`` environment variable is set, ``--shodan`` and
      ``--shodan-active`` are added to enrich netblocks discovered via ``-s``.
    - ``active`` — ``-t std,srv`` with AXFR (``-a``) and DNSSEC zone walk
      (``-z``) flags. Brute-force (``brt``) is delegated to ``gobuster dns``
      and no longer emitted here, so a wordlist is *not* required in this
      mode — it is silently ignored if supplied.
    - ``all`` — ``-t std,srv,snoop`` with all passive flags plus ``-a``/``-z``;
      a wordlist is mandatory (for ``snoop``). Shodan enrichment is enabled
      when ``SHODAN_API_KEY`` is set.

    Excluded:
    - ``brt`` — superseded by ``gobuster dns`` in the active pool
    - ``rvl`` — requires ``-r`` IP range, not available here
    - ``tld`` — tests TLD variations, not subdomain discovery

    :param domain: Target base domain.
    :param mode: Enumeration mode controlling which types and flags are used.
    :param wordlist: Path to the wordlist file. Required in ALL mode for the
        ``snoop`` cache-snoop pass; optional in PASSIVE mode where it unlocks
        ``snoop``; ignored in ACTIVE mode (brute-force is handled by gobuster).
    :param timeout: Maximum seconds to wait for dnsrecon.
    :param threads: Number of threads for dnsrecon (``--threads``). ``None`` uses the dnsrecon default.
    :param line_cb: Optional callback invoked with each output line (debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :param fqdn_cb: Optional callback invoked with each in-scope FQDN as soon as
        it is parsed, allowing callers to start downstream work (e.g. DNS
        resolution) in parallel with enumeration.
    :rtype: ToolResult
    """
    result = ToolResult(name="dnsrecon")

    has_wordlist = bool(wordlist)

    if mode == EnumMode.PASSIVE:
        types = (
            f"{_PASSIVE_TYPES},{_PASSIVE_SNOOP_TYPE}"
            if has_wordlist
            else _PASSIVE_TYPES
        )
        use_passive_flags = True
        use_active_flags = False
        use_wordlist = has_wordlist
    elif mode == EnumMode.ACTIVE:
        types = _ACTIVE_TYPES
        use_passive_flags = False
        use_active_flags = True
        use_wordlist = False  # no brt → wordlist is unused
    else:  # ALL — wordlist is mandatory, so snoop is always on
        types = f"{_PASSIVE_TYPES},{_PASSIVE_SNOOP_TYPE}"
        use_passive_flags = True
        use_active_flags = True
        use_wordlist = True

    use_snoop = _PASSIVE_SNOOP_TYPE in types

    cmd = ["dnsrecon", "-d", domain, "-t", types]

    if use_wordlist and wordlist:
        cmd += ["-D", wordlist]

    if use_snoop:
        ns_hostnames = resolve_ns(domain)
        ns_ips: list[str] = []
        for host in ns_hostnames:
            for ip in resolve_ips(host):
                if ":" not in ip and ip not in ns_ips:  # IPv4 only
                    ns_ips.append(ip)
        if ns_ips:
            cmd += ["-n", ",".join(ns_ips)]

    if threads is not None:
        cmd += ["--threads", str(threads)]

    if use_passive_flags:
        cmd += ["-b", "-y", "-k", "-s"]  # Bing, Yandex, crt.sh, SPF reverse
        # Shodan enrichment is opt-in via env var; dnsrecon itself reads
        # SHODAN_API_KEY when --shodan-key is omitted, so we don't have to
        # forward the secret on the command line.
        if os.environ.get(_SHODAN_ENV_VAR, "").strip():
            cmd += ["--shodan", "--shodan-active"]

    if use_active_flags:
        cmd += ["-a", "-z"]  # AXFR zone transfer, DNSSEC zone walk

    suffix = f".{domain}"
    streamed_seen: set[str] = set()
    streamed: list[str] = []

    def _on_line(line: str) -> None:
        if line_cb is not None:
            line_cb(line)
        if fqdn_cb is None:
            return
        for raw in line.split():
            part = raw.lower()
            if part in streamed_seen:
                continue
            if part == domain or part.endswith(suffix):
                streamed_seen.add(part)
                streamed.append(part)
                fqdn_cb(part)

    try:
        lines, timed_out = run_tool(
            cmd,
            timeout=timeout,
            line_cb=_on_line,
            cmd_cb=cmd_cb,
            capture_stderr=True,
            ignore_returncode=True,
        )
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    if fqdn_cb is not None:
        result.subdomains = streamed
    else:
        # dnsrecon outputs lines like: "[*] A sub.example.com 1.2.3.4"
        for line in lines:
            for raw in line.split():
                part = raw.lower()
                if part == domain or part.endswith(suffix):
                    if part not in result.subdomains:
                        result.subdomains.append(part)

    result.timed_out = timed_out
    return result
