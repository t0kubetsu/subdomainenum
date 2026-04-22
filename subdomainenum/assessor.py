"""High-level enumeration API – orchestrates all passive and active tools.

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
from subdomainenum.streaming import StreamingResolver
from subdomainenum.models import (
    EnumMode,
    EnumReport,
    ToolResult,
    Status,
    SubdomainResult,
    VhostResult,
)


# Cap ffuf per-URL fan-out; existing ffuf -t 40 already saturates I/O inside each worker.
_FFUF_MAX_WORKERS = 8


def _run_passive(
    domain: str,
    progress_cb: Callable[[str], None] | None,
    debug_cb: Callable[[str, str], None] | None = None,
    cmd_cb: Callable[[str, str], None] | None = None,
    finish_cb: Callable[[str, str | None, bool], None] | None = None,
    overall_mode: EnumMode | None = None,
    wordlist: str | None = None,
    fqdn_cb: Callable[[str], None] | None = None,
) -> list[ToolResult]:
    """Run all passive enumeration tools concurrently.

    :param domain: Target base domain.
    :param progress_cb: Optional callback for progress messages.
    :param debug_cb: Optional callback for real-time tool output lines,
        called as ``debug_cb(tool_name, line)``.
    :param cmd_cb: Optional callback for the command/label that runs each tool,
        called as ``cmd_cb(tool_name, cmd_string)``.
    :param finish_cb: Optional callback called when a tool completes,
        called as ``finish_cb(tool_name, error_or_none, timed_out)``.
    :param overall_mode: The mode passed to :func:`assess`; when ``EnumMode.ALL``
        tools that also run in the active phase use a ``"<name> passive"`` key so
        the debug log shows a distinct section for each phase.
    :param wordlist: Optional DNS wordlist. When provided, dnsrecon's passive
        invocation adds the ``snoop`` type to cache-snoop the domain's NS for
        each wordlist entry. Ignored by every other passive source.
    :returns: List of :class:`~subdomainenum.models.ToolResult` objects.
    """

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    def _key(name: str) -> str:
        """Return the callback key for *name*, appending a phase suffix in ALL mode."""
        if overall_mode == EnumMode.ALL:
            if name == "amass":
                return "amass passive"
            if name == "dnsrecon":
                return "dnsrecon passive+active"
        return name

    def _line_cb(tool: str) -> Callable[[str], None] | None:
        if debug_cb is None:
            return None
        key = _key(tool)
        return lambda line: debug_cb(key, line)

    def _cmd_cb(tool: str) -> Callable[[str], None] | None:
        if cmd_cb is None:
            return None
        key = _key(tool)
        return lambda cmd: cmd_cb(key, cmd)

    tools: list[ToolResult] = []

    def _run_subfinder() -> ToolResult:
        _cb("Running subfinder (passive)…")
        return run_subfinder(
            domain, line_cb=_line_cb("subfinder"), cmd_cb=_cmd_cb("subfinder"),
            fqdn_cb=fqdn_cb,
        )

    def _run_amass() -> ToolResult:
        _cb("Running amass (passive)…")
        return run_amass(
            domain, line_cb=_line_cb("amass"), cmd_cb=_cmd_cb("amass"),
            fqdn_cb=fqdn_cb,
        )

    def _run_findomain() -> ToolResult:
        _cb("Running findomain…")
        return run_findomain(
            domain, line_cb=_line_cb("findomain"), cmd_cb=_cmd_cb("findomain"),
            fqdn_cb=fqdn_cb,
        )

    def _run_assetfinder() -> ToolResult:
        _cb("Running assetfinder…")
        return run_assetfinder(
            domain, line_cb=_line_cb("assetfinder"), cmd_cb=_cmd_cb("assetfinder"),
            fqdn_cb=fqdn_cb,
        )

    def _run_dnsrecon_passive() -> ToolResult:
        _cb("Running dnsrecon (passive)…")
        return run_dnsrecon(
            domain, mode=EnumMode.PASSIVE, wordlist=wordlist,
            line_cb=_line_cb("dnsrecon"), cmd_cb=_cmd_cb("dnsrecon"),
            fqdn_cb=fqdn_cb,
        )

    tool_tasks: dict[str, Callable[[], ToolResult]] = {
        "subfinder": _run_subfinder,
        "amass": _run_amass,
        "findomain": _run_findomain,
        "assetfinder": _run_assetfinder,
        "dnsrecon": _run_dnsrecon_passive,
    }
    with ThreadPoolExecutor(max_workers=len(tool_tasks)) as pool:
        futures = {pool.submit(fn): name for name, fn in tool_tasks.items()}
        for fut in as_completed(futures):
            tool_name = futures[fut]
            try:
                result = fut.result()
                result.mode = EnumMode.PASSIVE
                tools.append(result)
                if finish_cb:
                    finish_cb(_key(tool_name), result.error, result.timed_out)
            except Exception as exc:
                tools.append(ToolResult(name=tool_name, error=str(exc), available=False, mode=EnumMode.PASSIVE))
                if finish_cb:
                    finish_cb(_key(tool_name), str(exc), False)

    return tools


def _run_active_enum(
    domain: str,
    *,
    wordlist: str,
    progress_cb: Callable[[str], None] | None = None,
    debug_cb: Callable[[str, str], None] | None = None,
    cmd_cb: Callable[[str, str], None] | None = None,
    finish_cb: Callable[[str, str | None, bool], None] | None = None,
    overall_mode: EnumMode | None = None,
    fqdn_cb: Callable[[str], None] | None = None,
) -> list[ToolResult]:
    """Run the non-ffuf active tools in parallel.

    Tool mix depends on *overall_mode*:

    - In ``ALL`` mode the pool is **amass + gobuster**. dnsrecon is omitted
      because it already runs in the passive phase with ``-t std,srv,snoop``;
      re-running it actively would duplicate work without producing new data
      (its ``brt`` type has been replaced by ``gobuster dns``).
    - In ``ACTIVE`` mode (or when *overall_mode* is ``None``) the pool is
      **amass + gobuster + dnsrecon**. dnsrecon runs with ``-t std,srv -a -z``
      so AXFR zone transfer and DNSSEC zone-walk enumeration are still
      exercised in the active-only path where the passive pool never runs.

    :param domain: Target base domain.
    :param wordlist: Path to the DNS wordlist (consumed by gobuster;
        dnsrecon silently ignores it in ACTIVE mode).
    :param progress_cb: Optional callback for progress messages.
    :param debug_cb: Optional callback for real-time tool output lines,
        called as ``debug_cb(tool_name, line)``.
    :param cmd_cb: Optional callback for the command that runs each tool,
        called as ``cmd_cb(tool_name, cmd_string)``.
    :param finish_cb: Optional callback called when a tool completes,
        called as ``finish_cb(tool_name, error_or_none, timed_out)``.
    :param overall_mode: The mode passed to :func:`assess`; when ``EnumMode.ALL``
        ``amass`` uses the ``"amass active"`` key so the debug log shows a
        distinct section for each phase.
    :returns: List of :class:`~subdomainenum.models.ToolResult`.
    """

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    def _key(name: str) -> str:
        if overall_mode == EnumMode.ALL and name == "amass":
            return f"{name} active"
        return name

    def _line_cb(tool: str) -> Callable[[str], None] | None:
        if debug_cb is None:
            return None
        key = _key(tool)
        return lambda line: debug_cb(key, line)

    def _cmd_cb(tool: str) -> Callable[[str], None] | None:
        if cmd_cb is None:
            return None
        key = _key(tool)
        return lambda cmd: cmd_cb(key, cmd)

    tools: list[ToolResult] = []

    def _run_amass_active() -> ToolResult:
        _cb("Running amass (active)…")
        return run_amass(
            domain, mode=EnumMode.ACTIVE,
            line_cb=_line_cb("amass"), cmd_cb=_cmd_cb("amass"),
            fqdn_cb=fqdn_cb,
        )

    def _run_gobuster() -> ToolResult:
        _cb("Running gobuster dns…")
        return run_gobuster_dns(
            domain, wordlist=wordlist,
            line_cb=_line_cb("gobuster"), cmd_cb=_cmd_cb("gobuster"),
            fqdn_cb=fqdn_cb,
        )

    def _run_dnsrecon_active() -> ToolResult:
        _cb("Running dnsrecon (active)…")
        return run_dnsrecon(
            domain, mode=EnumMode.ACTIVE,
            line_cb=_line_cb("dnsrecon"), cmd_cb=_cmd_cb("dnsrecon"),
            fqdn_cb=fqdn_cb,
        )

    tool_tasks: dict[str, Callable[[], ToolResult]] = {
        "amass": _run_amass_active,
        "gobuster": _run_gobuster,
    }
    # Only add dnsrecon to the active pool when ALL mode is NOT in effect.
    # In ALL mode dnsrecon already runs passively; in ACTIVE-only mode the
    # passive pool is skipped, so we need it here for -a (AXFR) and -z
    # (DNSSEC zone walk) coverage.
    if overall_mode != EnumMode.ALL:
        tool_tasks["dnsrecon"] = _run_dnsrecon_active
    with ThreadPoolExecutor(max_workers=len(tool_tasks)) as pool:
        futures = {pool.submit(fn): name for name, fn in tool_tasks.items()}
        for fut in as_completed(futures):
            tool_name = futures[fut]
            try:
                result = fut.result()
                result.mode = EnumMode.ACTIVE
                tools.append(result)
                if finish_cb:
                    finish_cb(_key(tool_name), result.error, result.timed_out)
            except Exception as exc:
                tools.append(ToolResult(name=tool_name, error=str(exc), available=False, mode=EnumMode.ACTIVE))
                if finish_cb:
                    finish_cb(_key(tool_name), str(exc), False)

    return tools


def _run_ffuf_fanout(
    domain: str,
    *,
    wordlist: str,
    urls: list[str],
    progress_cb: Callable[[str], None] | None = None,
    debug_cb: Callable[[str, str], None] | None = None,
    cmd_cb: Callable[[str, str], None] | None = None,
    finish_cb: Callable[[str, str | None, bool], None] | None = None,
) -> tuple[ToolResult, list[VhostResult]]:
    """Run ffuf in parallel across *urls*, deduplicating discovered vhosts.

    :param domain: Target base domain (Host header suffix).
    :param wordlist: Path to the vhost wordlist.
    :param urls: List of target URLs; ffuf is launched once per URL in a thread pool
        capped at :data:`_FFUF_MAX_WORKERS`. Empty list → ffuf is skipped and the
        returned :class:`ToolResult` is marked unavailable.
    :param progress_cb: Optional callback for progress messages.
    :param debug_cb: Optional callback ``debug_cb(ffuf_key, line)``.
    :param cmd_cb: Optional callback ``cmd_cb(ffuf_key, cmd_string)``.
    :param finish_cb: Optional callback ``finish_cb(ffuf_key, error_or_none, timed_out)``
        invoked once per URL.
    :returns: Tuple of (aggregated ffuf :class:`ToolResult`, deduplicated
        :class:`VhostResult` list).
    """

    if not urls:
        tool = ToolResult(name="ffuf", available=False, error="no URL resolved", mode=EnumMode.ACTIVE)
        if finish_cb:
            finish_cb("ffuf", "no URL resolved", False)
        return tool, []

    if progress_cb:
        progress_cb(f"Running ffuf (vhost fuzzing) against {len(urls)} IP(s) in parallel…")

    def _make_task(idx: int, target_url: str) -> tuple[str, Callable[[], list[VhostResult]]]:
        ffuf_key = f"ffuf {idx + 1}" if len(urls) > 1 else "ffuf"
        _line = (lambda line, k=ffuf_key: debug_cb(k, line)) if debug_cb is not None else None
        _cmd = (lambda c, k=ffuf_key: cmd_cb(k, c)) if cmd_cb is not None else None

        def _run() -> list[VhostResult]:
            return run_ffuf(
                domain, url=target_url, wordlist=wordlist,
                line_cb=_line, cmd_cb=_cmd,
            )

        return ffuf_key, _run

    tasks = [_make_task(i, u) for i, u in enumerate(urls)]

    seen_vhosts: set[str] = set()
    all_vhosts: list[VhostResult] = []

    max_workers = min(len(urls), _FFUF_MAX_WORKERS)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fn): key for key, fn in tasks}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                hits = fut.result()
            except Exception as exc:
                if finish_cb:
                    finish_cb(key, str(exc), False)
                continue
            if finish_cb:
                finish_cb(key, None, False)
            for v in hits:
                if v.vhost not in seen_vhosts:
                    seen_vhosts.add(v.vhost)
                    all_vhosts.append(v)

    tool = ToolResult(
        name="ffuf",
        subdomains=[v.vhost for v in all_vhosts],
        mode=EnumMode.ACTIVE,
    )
    return tool, all_vhosts


def _run_active(
    domain: str,
    wordlist: str,
    urls: list[str],
    progress_cb: Callable[[str], None] | None,
    debug_cb: Callable[[str, str], None] | None = None,
    cmd_cb: Callable[[str, str], None] | None = None,
    finish_cb: Callable[[str, str | None, bool], None] | None = None,
    overall_mode: EnumMode | None = None,
    fqdn_cb: Callable[[str], None] | None = None,
) -> tuple[list[ToolResult], list[VhostResult]]:
    """Run all active enumeration tools (enumeration + ffuf).

    Thin wrapper: dispatches to :func:`_run_active_enum` for amass/gobuster
    (parallel) and :func:`_run_ffuf_fanout` for ffuf (parallel per URL). Used by
    :func:`assess` in ``ACTIVE`` mode; in ``ALL`` mode the two helpers are invoked
    directly so the enumeration pool can run concurrently with passive.

    :returns: Tuple of (tools, vhosts).
    """
    tools = _run_active_enum(
        domain, wordlist=wordlist,
        progress_cb=progress_cb, debug_cb=debug_cb,
        cmd_cb=cmd_cb, finish_cb=finish_cb, overall_mode=overall_mode,
        fqdn_cb=fqdn_cb,
    )
    ffuf_tool, vhosts = _run_ffuf_fanout(
        domain, wordlist=wordlist, urls=urls,
        progress_cb=progress_cb, debug_cb=debug_cb,
        cmd_cb=cmd_cb, finish_cb=finish_cb,
    )
    tools.append(ffuf_tool)
    return tools, vhosts


def _resolve_all(
    fqdns: list[str],
    tool_map: dict[str, list[str]],
    timeout: float = 5.0,
    pre_resolved: dict[str, list[str]] | None = None,
) -> list[SubdomainResult]:
    """Resolve all *fqdns* in parallel and build :class:`SubdomainResult` objects.

    :param fqdns: Unique fully-qualified domain names to resolve.
    :param tool_map: Mapping of fqdn → list of tool names that found it.
    :param timeout: Per-query DNS timeout in seconds.
    :param pre_resolved: Optional mapping of fqdn → cached IP list. Membership is
        tested with ``in`` so an empty list means "cached as dead, skip live DNS",
        while absence means "not cached, resolve live". Used to avoid double
        resolution when FQDNs were already resolved for ffuf URL enrichment.
    :returns: List of :class:`~subdomainenum.models.SubdomainResult` objects.
    """
    cache = pre_resolved or {}

    def _resolve_one(fqdn: str) -> SubdomainResult:
        if fqdn in cache:
            ips = cache[fqdn]
        else:
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
            tools=tool_map.get(fqdn, []),
            alive=alive,
        )

    with ThreadPoolExecutor(max_workers=min(100, len(fqdns) or 1)) as pool:
        results = list(pool.map(_resolve_one, fqdns))

    return sorted(results, key=lambda r: r.fqdn)


def _compute_ffuf_urls(
    domain: str,
    url: str | None,
    passive_fqdns: list[str],
    resolver: StreamingResolver | None = None,
) -> tuple[list[str], dict[str, list[str]]]:
    """Build the list of ffuf target URLs and return the IP cache in one call.

    When *url* is given it is returned as-is and the cache is empty. Otherwise
    the base *domain* is resolved alongside every distinct FQDN in
    *passive_fqdns*. When a :class:`~subdomainenum.streaming.StreamingResolver`
    is supplied, its cache is used: FQDNs already submitted during enumeration
    don't pay the DNS cost twice; the resolver blocks only on the subset
    needed here. When *resolver* is ``None`` the function falls back to an
    ad-hoc local thread pool. IPv6 addresses are bracketed.

    :param domain: Target base domain.
    :param url: Caller-supplied URL (takes precedence over auto-derivation).
    :param passive_fqdns: FQDNs discovered in the passive phase (may be empty).
    :param resolver: Optional shared streaming resolver; when present its
        :meth:`collect_subset` is used instead of a local pool so IPs already
        resolved during enumeration are re-used.
    :returns: Tuple of (deduplicated ``http://<ip>`` URL list, fqdn→IPs cache
        suitable for :func:`_resolve_all`'s ``pre_resolved`` kwarg).
    """
    if url is not None:
        return [url], {}

    # Collect the base domain and every passive FQDN into one deduplicated list.
    normalized: list[str] = []
    seen: set[str] = set()
    base = (domain or "").lower().strip()
    if base:
        seen.add(base)
        normalized.append(base)
    for fqdn in passive_fqdns:
        f = fqdn.lower().strip()
        if f and f not in seen:
            seen.add(f)
            normalized.append(f)

    pre_resolved: dict[str, list[str]] = {}
    if normalized:
        if resolver is not None:
            pre_resolved = resolver.collect_subset(normalized)
        else:
            with ThreadPoolExecutor(max_workers=min(100, len(normalized))) as pool:
                ip_lists = list(pool.map(resolve_ips, normalized))
            for fqdn, ips in zip(normalized, ip_lists):
                pre_resolved[fqdn] = ips

    candidate_ips: list[str] = []
    for fqdn in normalized:
        candidate_ips.extend(pre_resolved.get(fqdn, []))

    seen_ips: set[str] = set()
    unique_urls: list[str] = []
    for ip in candidate_ips:
        if ip not in seen_ips:
            seen_ips.add(ip)
            formatted = f"[{ip}]" if ":" in ip else ip
            unique_urls.append(f"http://{formatted}")
    return unique_urls, pre_resolved


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
    finish_cb: Callable[[str, str | None, bool], None] | None = None,
) -> EnumReport:
    """Run subdomain enumeration for *domain* and return an :class:`~subdomainenum.models.EnumReport`.

    In ``ALL`` mode, the 5 passive tools and the 2 non-ffuf active tools
    (amass + gobuster) run concurrently in two pools submitted to an outer
    executor; ffuf runs after both pools drain so it can target IPs resolved
    from passive FQDNs. dnsrecon runs only in the passive phase in ALL mode;
    in ACTIVE-only mode it joins the active pool so AXFR and DNSSEC zone-walk
    enumeration are still executed when passive tools are skipped.

    :param domain: Target base domain (e.g. ``"example.com"``).
    :param mode: Enumeration strategy – ``passive``, ``active``, or ``all``.
    :param wordlist: Path to wordlist. Required for active/all modes; optional
        for passive mode, where it unlocks dnsrecon's ``snoop`` cache-snoop of
        the domain's authoritative NS.
    :param url: Target URL for ffuf vhost fuzzing (optional).
    :param timeout: DNS resolution timeout per query in seconds.
    :param progress_cb: Optional callback called with progress strings.
    :param debug_cb: Optional callback for real-time tool output lines,
        called as ``debug_cb(tool_name, line)`` for each line a tool emits.
    :param cmd_cb: Optional callback for the command/label that launches each tool,
        called as ``cmd_cb(tool_name, cmd_string)`` once per tool.
    :param finish_cb: Optional callback called when a tool completes,
        called as ``finish_cb(tool_name, error_or_none, timed_out)``.
    :returns: Completed enumeration report.
    :rtype: EnumReport
    :raises ValueError: When *mode* requires a wordlist but none was provided.
    """
    if mode in (EnumMode.ACTIVE, EnumMode.ALL) and not wordlist:
        raise ValueError("A wordlist path is required for active and all modes.")

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    all_tools: list[ToolResult] = []
    all_vhosts: list[VhostResult] = []
    pre_resolved: dict[str, list[str]] = {}

    # Streaming DNS resolver: tools call resolver.submit(fqdn) via fqdn_cb as
    # soon as a new FQDN is parsed, so resolution overlaps with enumeration.
    resolver = StreamingResolver(resolver=lambda f: resolve_ips(f, timeout=timeout))
    try:
        if mode == EnumMode.PASSIVE:
            _cb("Starting passive enumeration…")
            all_tools.extend(_run_passive(
                domain, progress_cb,
                debug_cb=debug_cb, cmd_cb=cmd_cb, finish_cb=finish_cb, overall_mode=mode,
                wordlist=wordlist, fqdn_cb=resolver.submit,
            ))

        elif mode == EnumMode.ACTIVE:
            _cb("Starting active enumeration…")
            urls, pre_resolved = _compute_ffuf_urls(
                domain, url, passive_fqdns=[], resolver=resolver,
            )
            active_tools, vhosts = _run_active(
                domain, wordlist=wordlist, urls=urls,
                progress_cb=progress_cb, debug_cb=debug_cb,
                cmd_cb=cmd_cb, finish_cb=finish_cb, overall_mode=mode,
                fqdn_cb=resolver.submit,
            )
            all_tools.extend(active_tools)
            all_vhosts.extend(vhosts)

        else:  # EnumMode.ALL — fuse passive + non-ffuf active phases
            _cb("Starting enumeration (passive + active concurrent)…")
            with ThreadPoolExecutor(max_workers=2) as outer:
                f_passive = outer.submit(
                    _run_passive, domain, progress_cb,
                    debug_cb=debug_cb, cmd_cb=cmd_cb, finish_cb=finish_cb, overall_mode=mode,
                    wordlist=wordlist, fqdn_cb=resolver.submit,
                )
                f_active_enum = outer.submit(
                    _run_active_enum, domain,
                    wordlist=wordlist, progress_cb=progress_cb,
                    debug_cb=debug_cb, cmd_cb=cmd_cb, finish_cb=finish_cb, overall_mode=mode,
                    fqdn_cb=resolver.submit,
                )
                passive_tools = f_passive.result()
                active_enum_tools = f_active_enum.result()

            all_tools.extend(passive_tools)
            all_tools.extend(active_enum_tools)

            # ffuf runs after both pools drain so it can target passive-enriched IPs.
            # _compute_ffuf_urls pulls from the shared resolver's cache, so the
            # base domain and passive FQDNs are not resolved twice.
            passive_fqdns = [sub for tool in passive_tools for sub in tool.subdomains]
            urls, pre_resolved = _compute_ffuf_urls(
                domain, url, passive_fqdns=passive_fqdns, resolver=resolver,
            )
            ffuf_tool, vhosts = _run_ffuf_fanout(
                domain, wordlist=wordlist, urls=urls,
                progress_cb=progress_cb, debug_cb=debug_cb,
                cmd_cb=cmd_cb, finish_cb=finish_cb,
            )
            all_tools.append(ffuf_tool)
            all_vhosts.extend(vhosts)

        # Deduplicate FQDNs across all tools, track which tool found each.
        fqdn_tools: dict[str, list[str]] = {}
        for tool in all_tools:
            for fqdn in tool.subdomains:
                fqdn = fqdn.lower().strip()
                if fqdn:
                    fqdn_tools.setdefault(fqdn, [])
                    if tool.name not in fqdn_tools[fqdn]:
                        fqdn_tools[fqdn].append(tool.name)

        unique_fqdns = list(fqdn_tools.keys())
        _cb(f"Resolving {len(unique_fqdns)} unique subdomains…")

        # Merge the streaming resolver's cache (mostly populated during
        # enumeration) with the ffuf-URL cache so _resolve_all hits DNS only
        # for FQDNs nothing has resolved yet.
        streamed_cache = resolver.collect(unique_fqdns)
        merged_cache: dict[str, list[str]] = dict(streamed_cache)
        merged_cache.update(pre_resolved)

        subdomains = _resolve_all(
            unique_fqdns, fqdn_tools, timeout=timeout, pre_resolved=merged_cache,
        )
    finally:
        resolver.shutdown()

    return EnumReport(
        domain=domain,
        mode=mode,
        subdomains=subdomains,
        vhosts=all_vhosts,
        tools=all_tools,
    )
