"""DNS resolution helpers for subdomainenum."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

_IP_RDTYPES = ("A", "AAAA")

# Persistent background pool used to issue A and AAAA queries concurrently
# for the same FQDN. Sized large enough that even when resolve_ips is called
# from a 100-worker caller pool, both per-FQDN queries can proceed without
# queueing (100 × 2 = 200 in-flight tasks in the worst case).
_QUERY_EXECUTOR = ThreadPoolExecutor(max_workers=256, thread_name_prefix="dns-rdtype")


def _query_rdtype(fqdn: str, rdtype: str, timeout: float) -> list[str]:
    """Return the addresses answering *rdtype* for *fqdn*, or an empty list.

    Wraps :func:`dns.resolver.resolve` so any of the common DNS failure modes
    (NXDOMAIN, empty answer, timeout, no reachable nameservers, generic DNS
    exception) collapse to an empty list instead of propagating.

    :param fqdn: Fully-qualified domain name to query.
    :param rdtype: DNS record type (``"A"`` or ``"AAAA"``).
    :param timeout: Per-query timeout in seconds (``lifetime`` on dnspython).
    :returns: Deduplicated IP address strings as returned by dnspython.
    :rtype: list[str]
    """
    try:
        answer = dns.resolver.resolve(fqdn, rdtype, lifetime=timeout)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ):
        return []
    addrs: list[str] = []
    for rdata in answer:
        addr = rdata.address
        if addr not in addrs:
            addrs.append(addr)
    return addrs


def resolve_ips(fqdn: str, timeout: float = 5.0) -> list[str]:
    """Resolve *fqdn* to a deduplicated list of A/AAAA IP addresses.

    A and AAAA queries are issued in parallel on a shared background pool so
    per-FQDN latency is bounded by the slower of the two queries rather than
    their sum. Returns an empty list on NXDOMAIN / NoAnswer / timeout /
    NoNameservers — never raises.

    :param fqdn: Fully-qualified domain name to resolve.
    :param timeout: Per-query timeout in seconds.
    :returns: Deduplicated list of IP address strings (A first, then AAAA).
    :rtype: list[str]
    """
    futures = [
        _QUERY_EXECUTOR.submit(_query_rdtype, fqdn, rdtype, timeout)
        for rdtype in _IP_RDTYPES
    ]
    ips: list[str] = []
    for fut in futures:
        for addr in fut.result():
            if addr not in ips:
                ips.append(addr)
    return ips


def is_alive(fqdn: str, timeout: float = 5.0) -> bool:
    """Return ``True`` if *fqdn* resolves to at least one IP address.

    :param fqdn: Fully-qualified domain name to probe.
    :param timeout: Per-query timeout in seconds.
    :rtype: bool
    """
    return len(resolve_ips(fqdn, timeout=timeout)) > 0
