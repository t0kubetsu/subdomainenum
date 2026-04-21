"""Shared result dataclasses and enums for subdomainenum.

Every tool and check function returns one of the typed objects defined here.
:class:`EnumReport` is the top-level aggregate returned by
:func:`subdomainenum.assessor.assess`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """Resolution / liveness status for a discovered subdomain.

    - ``FOUND``     – discovered by at least one tool; DNS not yet resolved.
    - ``ALIVE``     – resolves to at least one IP address.
    - ``DEAD``      – DNS lookup returned NXDOMAIN or empty answer.
    - ``TIMEOUT``   – DNS resolution timed out.
    - ``ERROR``     – unexpected error during resolution.
    - ``NOT_FOUND`` – explicitly absent (used internally by tools).
    - ``SKIPPED``   – step was intentionally skipped.
    """

    FOUND = "FOUND"
    ALIVE = "ALIVE"
    DEAD = "DEAD"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    NOT_FOUND = "NOT_FOUND"
    SKIPPED = "SKIPPED"


class EnumMode(str, Enum):
    """Enumeration strategy mode.

    - ``passive`` – passive-only: subfinder, amass (passive graph), findomain,
      assetfinder, dnsrecon (``std,srv`` with Bing/Yandex/crt.sh/SPF/whois,
      plus ``snoop`` when a wordlist is supplied).
    - ``active``  – active-only: amass (active, no brute-force), gobuster dns
      (brute-force, requires a wordlist), dnsrecon (``std,srv`` with AXFR and
      DNSSEC zone walk), and ffuf for vhost fuzzing when URLs are provided.
    - ``all``     – run passive + active concurrently; dnsrecon is only run
      passively in this mode to avoid duplicating work.
    """

    PASSIVE = "passive"
    ACTIVE = "active"
    ALL = "all"


@dataclass
class SubdomainResult:
    """A single discovered subdomain with resolution metadata.

    :param fqdn: Fully-qualified domain name (e.g. ``"mail.example.com"``).
    :param status: Resolution / liveness status.
    :param ip_addresses: Resolved A/AAAA addresses, or empty list.
    :param tools: Names of the tools that found this subdomain.
    :param alive: ``True`` if at least one IP resolved; ``False`` if NXDOMAIN;
        ``None`` if resolution was not attempted yet.
    """

    fqdn: str
    status: Status = Status.FOUND
    ip_addresses: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    alive: bool | None = None


@dataclass
class VhostResult:
    """A virtual host discovered via HTTP fuzzing (ffuf).

    :param vhost: The Host header value used (e.g. ``"admin.example.com"``).
    :param status_code: HTTP response status code.
    :param content_length: Response body length in bytes.
    """

    vhost: str
    status_code: int
    content_length: int = 0


@dataclass
class ToolResult:
    """Result of a single enumeration tool run.

    :param name: Short identifier for the tool (e.g. ``"subfinder"``, ``"dnsrecon"``).
    :param subdomains: FQDNs discovered by this tool.
    :param error: Error message if the tool failed; ``None`` on success.
    :param available: ``False`` when the required binary or API was unavailable.
    :param mode: Enumeration mode this tool was run in (``passive`` or ``active``),
        or ``None`` when not categorised.
    """

    name: str
    subdomains: list[str] = field(default_factory=list)
    error: str | None = None
    available: bool = True
    timed_out: bool = False
    mode: EnumMode | None = None


@dataclass
class EnumReport:
    """Aggregated enumeration result returned by :func:`subdomainenum.assessor.assess`.

    :param domain: The target domain that was assessed.
    :param mode: Enumeration mode used (passive / active / all).
    :param subdomains: Deduplicated list of discovered subdomains with resolution data.
    :param vhosts: Virtual hosts discovered via HTTP fuzzing.
    :param tools: Per-tool result objects including raw counts.
    """

    domain: str
    mode: EnumMode = EnumMode.ALL
    subdomains: list[SubdomainResult] = field(default_factory=list)
    vhosts: list[VhostResult] = field(default_factory=list)
    tools: list[ToolResult] = field(default_factory=list)
