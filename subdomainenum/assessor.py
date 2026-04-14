"""High-level enumeration API – orchestrates all passive and active sources.

Typical usage::

    from subdomainenum.assessor import assess
    from subdomainenum.models import EnumMode

    report = assess("example.com", mode=EnumMode.ALL, wordlist="/opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from subdomainenum.tools.amass import run_amass
from subdomainenum.tools.assetfinder import run_assetfinder
from subdomainenum.tools.dnsrecon import run_dnsrecon
from subdomainenum.tools.findomain import run_findomain
from subdomainenum.tools.gobuster_dns import run_gobuster_dns
from subdomainenum.tools.subfinder import run_subfinder
from subdomainenum.tools.ffuf import run_ffuf
from subdomainenum.dns_utils import resolve_ips
from subdomainenum.models import (
    EnumMode,
    EnumReport,
    SourceResult,
    Status,
    SubdomainResult,
    VhostResult,
)


def _run_passive(
    domain: str,
    progress_cb: Callable[[str], None] | None,
    debug_cb: Callable[[str, str], None] | None = None,
    cmd_cb: Callable[[str, str], None] | None = None,
    finish_cb: Callable[[str, str | None], None] | None = None,
) -> list[SourceResult]:
    """Run all passive enumeration sources concurrently.

    :param domain: Target base domain.
    :param progress_cb: Optional callback for progress messages.
    :param debug_cb: Optional callback for real-time tool output lines,
        called as ``debug_cb(source_name, line)``.
    :param cmd_cb: Optional callback for the command/label that runs each source,
        called as ``cmd_cb(source_name, cmd_string)``.
    :param finish_cb: Optional callback called when a source completes,
        called as ``finish_cb(source_name, error_or_none)``.
    :returns: List of :class:`~subdomainenum.models.SourceResult` objects.
    """

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    def _line_cb(source: str) -> Callable[[str], None] | None:
        if debug_cb is None:
            return None
        return lambda line: debug_cb(source, line)

    def _cmd_cb(source: str) -> Callable[[str], None] | None:
        if cmd_cb is None:
            return None
        return lambda cmd: cmd_cb(source, cmd)

    sources: list[SourceResult] = []

    def _run_subfinder() -> SourceResult:
        _cb("Running subfinder (passive)…")
        return run_subfinder(domain, line_cb=_line_cb("subfinder"), cmd_cb=_cmd_cb("subfinder"))

    def _run_amass() -> SourceResult:
        _cb("Running amass (passive)…")
        return run_amass(domain, line_cb=_line_cb("amass"), cmd_cb=_cmd_cb("amass"))

    def _run_findomain() -> SourceResult:
        _cb("Running findomain…")
        return run_findomain(domain, line_cb=_line_cb("findomain"), cmd_cb=_cmd_cb("findomain"))

    def _run_assetfinder() -> SourceResult:
        _cb("Running assetfinder…")
        return run_assetfinder(domain, line_cb=_line_cb("assetfinder"), cmd_cb=_cmd_cb("assetfinder"))

    def _run_dnsrecon_passive() -> SourceResult:
        _cb("Running dnsrecon (passive)…")
        return run_dnsrecon(domain, mode=EnumMode.PASSIVE, line_cb=_line_cb("dnsrecon"), cmd_cb=_cmd_cb("dnsrecon"))

    source_tasks: dict[str, Callable[[], SourceResult]] = {
        "subfinder": _run_subfinder,
        "amass": _run_amass,
        "findomain": _run_findomain,
        "assetfinder": _run_assetfinder,
        "dnsrecon": _run_dnsrecon_passive,
    }
    with ThreadPoolExecutor(max_workers=len(source_tasks)) as pool:
        futures = {pool.submit(fn): name for name, fn in source_tasks.items()}
        for fut in as_completed(futures):
            source_name = futures[fut]
            try:
                result = fut.result()
                sources.append(result)
                if finish_cb:
                    finish_cb(source_name, result.error)
            except Exception as exc:
                sources.append(SourceResult(name=source_name, error=str(exc), available=False))
                if finish_cb:
                    finish_cb(source_name, str(exc))

    return sources


def _run_active(
    domain: str,
    wordlist: str,
    url: str | None,
    progress_cb: Callable[[str], None] | None,
    debug_cb: Callable[[str, str], None] | None = None,
    cmd_cb: Callable[[str, str], None] | None = None,
    finish_cb: Callable[[str, str | None], None] | None = None,
) -> tuple[list[SourceResult], list[VhostResult]]:
    """Run all active enumeration sources.

    :param domain: Target base domain.
    :param wordlist: Path to the DNS wordlist.
    :param url: Target URL for vhost fuzzing (wfuzz); skipped if ``None``.
    :param progress_cb: Optional callback for progress messages.
    :param debug_cb: Optional callback for real-time tool output lines,
        called as ``debug_cb(source_name, line)``.
    :param cmd_cb: Optional callback for the command that runs each source,
        called as ``cmd_cb(source_name, cmd_string)``.
    :param finish_cb: Optional callback called when a source completes,
        called as ``finish_cb(source_name, error_or_none)``.
    :returns: Tuple of (sources, vhosts).
    """

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    def _line_cb(source: str) -> Callable[[str], None] | None:
        if debug_cb is None:
            return None
        return lambda line: debug_cb(source, line)

    def _cmd_cb(source: str) -> Callable[[str], None] | None:
        if cmd_cb is None:
            return None
        return lambda cmd: cmd_cb(source, cmd)

    sources: list[SourceResult] = []
    vhosts: list[VhostResult] = []

    _cb("Running amass (active)…")
    result = run_amass(domain, mode=EnumMode.ACTIVE, line_cb=_line_cb("amass"), cmd_cb=_cmd_cb("amass"))
    sources.append(result)
    if finish_cb:
        finish_cb("amass", result.error)

    _cb("Running dnsrecon (active)…")
    result = run_dnsrecon(domain, mode=EnumMode.ACTIVE, wordlist=wordlist, line_cb=_line_cb("dnsrecon"), cmd_cb=_cmd_cb("dnsrecon"))
    sources.append(result)
    if finish_cb:
        finish_cb("dnsrecon", result.error)

    _cb("Running gobuster dns…")
    result = run_gobuster_dns(domain, wordlist=wordlist, line_cb=_line_cb("gobuster"), cmd_cb=_cmd_cb("gobuster"))
    sources.append(result)
    if finish_cb:
        finish_cb("gobuster", result.error)

    if url:
        _cb("Running ffuf (vhost fuzzing)…")
        vhosts = run_ffuf(domain, url=url, wordlist=wordlist, line_cb=_line_cb("ffuf"), cmd_cb=_cmd_cb("ffuf"))
        sources.append(SourceResult(name="ffuf", subdomains=[v.vhost for v in vhosts]))
        if finish_cb:
            finish_cb("ffuf", None)
    else:
        sources.append(SourceResult(name="ffuf", available=False, error="no URL resolved"))
        if finish_cb:
            finish_cb("ffuf", "no URL resolved")

    return sources, vhosts


def _resolve_all(
    fqdns: list[str],
    source_map: dict[str, list[str]],
    timeout: float = 5.0,
) -> list[SubdomainResult]:
    """Resolve all *fqdns* in parallel and build :class:`SubdomainResult` objects.

    :param fqdns: Unique fully-qualified domain names to resolve.
    :param source_map: Mapping of fqdn → list of source names that found it.
    :param timeout: Per-query DNS timeout in seconds.
    :returns: List of :class:`~subdomainenum.models.SubdomainResult` objects.
    """

    def _resolve_one(fqdn: str) -> SubdomainResult:
        ips = resolve_ips(fqdn, timeout=timeout)
        if ips:
            status = Status.ALIVE
            alive = True
        else:
            status = Status.DEAD
            alive = False
        return SubdomainResult(
            fqdn=fqdn,
            status=status,
            ip_addresses=ips,
            sources=source_map.get(fqdn, []),
            alive=alive,
        )

    with ThreadPoolExecutor(max_workers=min(50, len(fqdns) or 1)) as pool:
        results = list(pool.map(_resolve_one, fqdns))

    return sorted(results, key=lambda r: r.fqdn)


def assess(
    domain: str,
    *,
    mode: EnumMode = EnumMode.ALL,
    wordlist: str | None = None,
    url: str | None = None,
    timeout: float = 5.0,
    progress_cb: Callable[[str], None] | None = None,
    debug_cb: Callable[[str, str], None] | None = None,
    cmd_cb: Callable[[str, str], None] | None = None,
    finish_cb: Callable[[str, str | None], None] | None = None,
) -> EnumReport:
    """Run subdomain enumeration for *domain* and return an :class:`~subdomainenum.models.EnumReport`.

    :param domain: Target base domain (e.g. ``"example.com"``).
    :param mode: Enumeration strategy – ``passive``, ``active``, or ``all``.
    :param wordlist: Path to wordlist required for active/all modes.
    :param url: Target URL for wfuzz vhost fuzzing (optional).
    :param timeout: DNS resolution timeout per query in seconds.
    :param progress_cb: Optional callback called with progress strings.
    :param debug_cb: Optional callback for real-time tool output lines,
        called as ``debug_cb(source_name, line)`` for each line a tool emits.
    :param cmd_cb: Optional callback for the command/label that launches each source,
        called as ``cmd_cb(source_name, cmd_string)`` once per source.
    :param finish_cb: Optional callback called when a source completes,
        called as ``finish_cb(source_name, error_or_none)``.
    :returns: Completed enumeration report.
    :rtype: EnumReport
    :raises ValueError: When *mode* requires a wordlist but none was provided.
    """
    if mode in (EnumMode.ACTIVE, EnumMode.ALL) and not wordlist:
        raise ValueError("A wordlist path is required for active and all modes.")

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    all_sources: list[SourceResult] = []
    all_vhosts: list[VhostResult] = []

    if mode in (EnumMode.PASSIVE, EnumMode.ALL):
        _cb("Starting passive enumeration…")
        all_sources.extend(_run_passive(domain, progress_cb, debug_cb=debug_cb, cmd_cb=cmd_cb, finish_cb=finish_cb))

    if mode in (EnumMode.ACTIVE, EnumMode.ALL):
        _cb("Starting active enumeration…")
        if url is None:
            ips = resolve_ips(domain)
            if ips:
                url = f"http://{ips[0]}"
        active_sources, vhosts = _run_active(domain, wordlist=wordlist, url=url, progress_cb=progress_cb, debug_cb=debug_cb, cmd_cb=cmd_cb, finish_cb=finish_cb)  # type: ignore[arg-type]
        all_sources.extend(active_sources)
        all_vhosts.extend(vhosts)

    # Deduplicate FQDNs across all sources, track which source found each.
    fqdn_sources: dict[str, list[str]] = {}
    for src in all_sources:
        for fqdn in src.subdomains:
            fqdn = fqdn.lower().strip()
            if fqdn:
                fqdn_sources.setdefault(fqdn, [])
                if src.name not in fqdn_sources[fqdn]:
                    fqdn_sources[fqdn].append(src.name)

    unique_fqdns = list(fqdn_sources.keys())
    _cb(f"Resolving {len(unique_fqdns)} unique subdomains…")
    subdomains = _resolve_all(unique_fqdns, fqdn_sources, timeout=timeout)

    return EnumReport(
        domain=domain,
        mode=mode,
        subdomains=subdomains,
        vhosts=all_vhosts,
        sources=all_sources,
    )
