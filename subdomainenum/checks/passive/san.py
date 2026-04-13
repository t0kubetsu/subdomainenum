"""Extract Subject Alternative Names from the target domain's TLS certificate.

Connects to port 443, grabs the leaf certificate, and returns all DNS SANs
that fall within the target domain scope.
"""

from __future__ import annotations

import socket
import ssl

from subdomainenum.models import SourceResult

_TIMEOUT = 10


def _fetch_san(domain: str, port: int = 443, timeout: float = _TIMEOUT) -> list[str]:
    """Connect via TLS and return the leaf certificate's DNS SAN entries.

    :param domain: Hostname to connect to.
    :param port: TCP port (default 443).
    :param timeout: Socket timeout in seconds.
    :returns: List of DNS SAN strings from the peer certificate.
    :raises OSError: On connection failure or TLS error.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((domain, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=domain) as tls:
            cert = tls.getpeercert()
            if not cert:
                return []
            sans: list[str] = []
            for typ, value in cert.get("subjectAltName", []):
                if typ == "DNS":
                    sans.append(value.lower())
            return sans


def query_san(domain: str, port: int = 443) -> SourceResult:
    """Probe *domain*:*port* via TLS and extract DNS SANs from the certificate.

    :param domain: Target base domain.
    :param port: TCP port to connect to (default 443).
    :returns: :class:`~subdomainenum.models.SourceResult` with ``name="san"``.
    :rtype: SourceResult
    """
    result = SourceResult(name="san")
    suffix = f".{domain}"
    try:
        san_entries = _fetch_san(domain, port=port)
    except OSError as exc:
        result.error = str(exc)
        return result

    seen: set[str] = set()
    for entry in san_entries:
        if entry.startswith("*"):
            continue
        if entry == domain or entry.endswith(suffix):
            if entry not in seen:
                seen.add(entry)
                result.subdomains.append(entry)

    return result
