"""Query the crt.sh Certificate Transparency log for subdomains.

This is a zero-dependency native Python source — no external binary required.
"""

from __future__ import annotations

import requests

from subdomainenum.models import SourceResult

_CRT_URL = "https://crt.sh/?q=%.{domain}&output=json"
_TIMEOUT = 20


def query_crt_sh(domain: str) -> SourceResult:
    """Query crt.sh for certificates issued for *domain* and return discovered subdomains.

    Wildcard entries (``*.example.com``) are skipped.  Multi-value
    ``name_value`` fields (newline-separated) are split.  Only entries that
    end with ``.{domain}`` or equal ``domain`` are kept.

    :param domain: Base domain to query (e.g. ``"example.com"``).
    :returns: :class:`~subdomainenum.models.SourceResult` with ``name="crt.sh"``.
    :rtype: SourceResult
    """
    result = SourceResult(name="crt.sh")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=_TIMEOUT, headers={"Accept": "application/json"})
        if not resp.ok:
            result.error = f"crt.sh returned HTTP {resp.status_code}"
            return result
        data = resp.json()
    except requests.RequestException as exc:
        result.error = str(exc)
        return result
    except ValueError as exc:
        result.error = f"JSON parse error: {exc}"
        return result

    seen: set[str] = set()
    suffix = f".{domain}"
    for entry in data:
        raw = entry.get("name_value", "")
        for name in raw.split("\n"):
            name = name.strip().lower()
            if not name or name.startswith("*"):
                continue
            if name == domain or name.endswith(suffix):
                if name not in seen:
                    seen.add(name)
                    result.subdomains.append(name)

    return result
