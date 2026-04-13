"""DNS resolution helpers for subdomainenum."""

from __future__ import annotations

import dns.exception
import dns.resolver


def resolve_ips(fqdn: str, timeout: float = 5.0) -> list[str]:
    """Resolve *fqdn* to a deduplicated list of A/AAAA IP addresses.

    Returns an empty list on NXDOMAIN, NoAnswer, or timeout — never raises.

    :param fqdn: Fully-qualified domain name to resolve.
    :param timeout: Per-query timeout in seconds.
    :returns: Sorted, deduplicated list of IP address strings.
    :rtype: list[str]
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    ips: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = dns.resolver.resolve(fqdn, rdtype, lifetime=timeout)
            for rdata in answer:
                addr = rdata.address
                if addr not in ips:
                    ips.append(addr)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            continue
    return ips


def is_alive(fqdn: str, timeout: float = 5.0) -> bool:
    """Return ``True`` if *fqdn* resolves to at least one IP address.

    :param fqdn: Fully-qualified domain name to probe.
    :param timeout: Per-query timeout in seconds.
    :rtype: bool
    """
    return len(resolve_ips(fqdn, timeout=timeout)) > 0
