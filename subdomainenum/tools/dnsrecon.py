"""Wrapper for dnsrecon DNS enumeration tool."""

from __future__ import annotations

import os
from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import ToolResult

# Enumeration types used in all modes:
#   std — SOA, NS, A, AAAA, MX, SRV (standard DNS records)
#   srv — SRV record enumeration
_TYPES = "std,srv"

# Active-phase DNS brute-force is delegated to ``gobuster dns`` (higher
# concurrency, faster turnaround); dnsrecon's ``brt`` type is intentionally
# not used. AXFR (``-a``) and DNSSEC zone walk (``-z``) target the domain's
# authoritative nameservers — public DNS infrastructure, not the target
# application — so they are included in the passive invocation.

# dnsrecon consults SHODAN_API_KEY as the fallback for --shodan-key. When the
# env var is present we enable --shodan and --shodan-active during passive
# enumeration to enrich netblocks discovered via -s (SPF reverse). No CLI flag
# is exposed in subdomainenum — the enrichment is opt-in purely via the
# environment.
_SHODAN_ENV_VAR = "SHODAN_API_KEY"


def run_dnsrecon(
    domain: str,
    *,
    timeout: int = 300,
    threads: int | None = None,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
    fqdn_cb: Callable[[str], None] | None = None,
) -> ToolResult:
    """Run dnsrecon for *domain*.

    Always uses ``-t std,srv`` with Bing (``-b``), Yandex (``-y``), crt.sh
    (``-k``), SPF reverse lookup (``-s``), AXFR zone transfer (``-a``), and
    DNSSEC zone walk (``-z``). AXFR and zone walk target the domain's
    authoritative nameservers (public DNS infrastructure, not the target
    application), so they are treated as passive enumeration. When the
    ``SHODAN_API_KEY`` environment variable is set, ``--shodan`` and
    ``--shodan-active`` are added.

    :param domain: Target base domain.
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

    cmd = ["dnsrecon", "-d", domain, "-t", _TYPES]

    if threads is not None:
        cmd += ["--threads", str(threads)]

    cmd += ["-b", "-y", "-k", "-s", "-a", "-z"]  # Bing, Yandex, crt.sh, SPF, AXFR, DNSSEC zone walk
    # Shodan enrichment is opt-in via env var; dnsrecon itself reads
    # SHODAN_API_KEY when --shodan-key is omitted, so we don't have to
    # forward the secret on the command line.
    if os.environ.get(_SHODAN_ENV_VAR, "").strip():
        cmd += ["--shodan", "--shodan-active"]

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
