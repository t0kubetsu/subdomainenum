"""Query the crt.sh Certificate Transparency database for subdomains.

This source connects directly to the crt.sh PostgreSQL replica
(``crt.sh:5432``, database ``certwatch``, user ``guest``) instead of the
HTTP API, which is more reliable and avoids HTML rate-limiting.
"""

from __future__ import annotations

from typing import Callable

import psycopg2

from subdomainenum.models import SourceResult

_HOST = "crt.sh"
_PORT = 5432
_USER = "guest"
_DBNAME = "certwatch"
_CONNECT_TIMEOUT = 20  # seconds

# Simple ILIKE scan against the certificate identities table.
# Only fetches direct subdomain matches (ILIKE '%.domain') to avoid noise.
# %s placeholder is '%.domain' (e.g. '%%.example.com' → '%.example.com').
_QUERY = """
SELECT DISTINCT name_value
    FROM certificate_and_identities
    WHERE name_value ILIKE %s
    LIMIT 10000;
"""

_PSQL_CMD_TEMPLATE = (
    "psql -h {host} -p {port} -U {user} {dbname} "
    "-c \"SELECT NAME_VALUE FROM certificate_and_identities WHERE NAME_VALUE ILIKE '%.{domain}' LIMIT 10000\""
)


def query_crt_sh(
    domain: str,
    *,
    cmd_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Query the crt.sh PostgreSQL replica for certificates issued for *domain*.

    Wildcard entries (``*.example.com``) are skipped.  Multi-value
    ``NAME_VALUE`` fields (newline-separated) are split.  Only entries that
    end with ``.{domain}`` or equal ``domain`` are kept.

    :param domain: Base domain to query (e.g. ``"example.com"``).
    :param cmd_cb: Optional callback invoked once with a descriptive psql command label.
    :returns: :class:`~subdomainenum.models.SourceResult` with ``name="crt.sh"``.
    :rtype: SourceResult
    """
    result = SourceResult(name="crt.sh")

    if cmd_cb is not None:
        cmd_cb(
            _PSQL_CMD_TEMPLATE.format(
                host=_HOST,
                port=_PORT,
                user=_USER,
                dbname=_DBNAME,
                domain=domain,
            )
        )

    try:
        conn = psycopg2.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            dbname=_DBNAME,
            connect_timeout=_CONNECT_TIMEOUT,
            sslmode="disable",
        )
        try:
            with conn.cursor() as cur:
                cur.execute(_QUERY, (f"%.{domain}",))
                rows = cur.fetchall()
        finally:
            conn.close()
    except Exception as exc:
        result.error = str(exc)
        return result

    seen: set[str] = set()
    suffix = f".{domain}"
    for (name_value,) in rows:
        if not name_value:
            continue
        name = name_value.strip().lower()
        if not name or name.startswith("*"):
            continue
        if name == domain or name.endswith(suffix):
            if name not in seen:
                seen.add(name)
                result.subdomains.append(name)

    return result
