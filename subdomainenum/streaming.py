"""Background DNS resolution pipeline for subdomainenum.

Overlaps DNS resolution of discovered FQDNs with still-running enumeration
tools. Each tool's wrapper calls :meth:`StreamingResolver.submit` via its
``fqdn_cb`` parameter as soon as a new FQDN is parsed, so by the time the
enumeration pools drain the resolver cache is already populated for most
FQDNs. The remaining FQDNs are resolved by the final :func:`_resolve_all`
call, but only for those the streaming resolver has not already finished.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable, Iterable

from subdomainenum.dns_utils import resolve_ips

ResolveFn = Callable[[str], list[str]]


class StreamingResolver:
    """Submits FQDNs for background DNS resolution and collects results on demand.

    Submission is idempotent per FQDN — duplicates are silently deduplicated
    so the same FQDN discovered by multiple tools is resolved exactly once.
    After :meth:`shutdown` further submissions are no-ops; in-flight futures
    still complete so :meth:`collect` remains usable.

    :param max_workers: Maximum number of concurrent DNS resolutions.
    :param resolver: Resolver function; defaults to
        :func:`~subdomainenum.dns_utils.resolve_ips`. The only contract is
        ``resolver(fqdn: str) -> list[str]`` and that it never raises.
    """

    def __init__(
        self,
        *,
        max_workers: int = 100,
        resolver: ResolveFn | None = None,
    ) -> None:
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="dns-stream"
        )
        self._resolver: ResolveFn = resolver or resolve_ips
        self._lock = threading.Lock()
        self._futures: dict[str, Future[list[str]]] = {}
        self._closed = False

    def submit(self, fqdn: str) -> None:
        """Queue *fqdn* for resolution if it has not been seen before.

        Safe to call from any thread. After :meth:`shutdown` this is a no-op.
        Blank or whitespace-only inputs are ignored.
        """
        if not fqdn:
            return
        key = fqdn.lower().strip()
        if not key:
            return
        with self._lock:
            if self._closed or key in self._futures:
                return
            self._futures[key] = self._pool.submit(self._resolver, key)

    def collect_subset(self, fqdns: Iterable[str]) -> dict[str, list[str]]:
        """Submit any unseen *fqdns*, then block only on those futures.

        Useful for callers that need a specific slice of the cache (e.g. the
        base domain + passive FQDNs for ffuf URL derivation) without waiting
        for every other streamed resolution to finish.

        :returns: Mapping of fqdn (normalized to lower-case) → resolved IPs.
        :rtype: dict[str, list[str]]
        """
        keys: list[str] = []
        for fqdn in fqdns:
            key = (fqdn or "").lower().strip()
            if not key:
                continue
            keys.append(key)
            self.submit(key)
        with self._lock:
            subset = {k: self._futures[k] for k in keys if k in self._futures}
        out: dict[str, list[str]] = {}
        for k, fut in subset.items():
            try:
                out[k] = fut.result()
            except Exception:
                out[k] = []
        return out

    def collect(self, fqdns: Iterable[str] | None = None) -> dict[str, list[str]]:
        """Submit any unseen *fqdns* and block on every in-flight future.

        :param fqdns: Optional iterable of additional FQDNs to guarantee are
            resolved; already-submitted FQDNs need not appear here.
        :returns: Full cache of fqdn → resolved IP list (possibly empty).
        :rtype: dict[str, list[str]]
        """
        if fqdns is not None:
            for fqdn in fqdns:
                self.submit(fqdn)
        with self._lock:
            pending = dict(self._futures)
        result: dict[str, list[str]] = {}
        for fqdn, fut in pending.items():
            try:
                result[fqdn] = fut.result()
            except Exception:
                result[fqdn] = []
        return result

    def shutdown(self) -> None:
        """Stop accepting new submissions and tear down the background pool."""
        with self._lock:
            self._closed = True
        self._pool.shutdown(wait=False)

    def __enter__(self) -> StreamingResolver:
        return self

    def __exit__(self, *exc: object) -> None:
        self.shutdown()
