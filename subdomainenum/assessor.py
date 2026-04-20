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
from subdomainenum.models import (
    EnumMode,
    EnumReport,
    ToolResult,
    Status,
    SubdomainResult,
    VhostResult,
)


def _run_passive(
    domain: str,
    progress_cb: Callable[[str], None] | None,
    debug_cb: Callable[[str, str], None] | None = None,
    cmd_cb: Callable[[str, str], None] | None = None,
    finish_cb: Callable[[str, str | None, bool], None] | None = None,
    overall_mode: EnumMode | None = None,
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
    :returns: List of :class:`~subdomainenum.models.ToolResult` objects.
    """

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    def _key(name: str) -> str:
        """Return the callback key for *name*, appending a phase suffix in ALL mode."""
        if overall_mode == EnumMode.ALL and name in ("amass", "dnsrecon"):
            return f"{name} passive"
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
        return run_subfinder(domain, line_cb=_line_cb("subfinder"), cmd_cb=_cmd_cb("subfinder"))

    def _run_amass() -> ToolResult:
        _cb("Running amass (passive)…")
        return run_amass(domain, line_cb=_line_cb("amass"), cmd_cb=_cmd_cb("amass"))

    def _run_findomain() -> ToolResult:
        _cb("Running findomain…")
        return run_findomain(domain, line_cb=_line_cb("findomain"), cmd_cb=_cmd_cb("findomain"))

    def _run_assetfinder() -> ToolResult:
        _cb("Running assetfinder…")
        return run_assetfinder(domain, line_cb=_line_cb("assetfinder"), cmd_cb=_cmd_cb("assetfinder"))

    def _run_dnsrecon_passive() -> ToolResult:
        _cb("Running dnsrecon (passive)…")
        return run_dnsrecon(domain, mode=EnumMode.PASSIVE, line_cb=_line_cb("dnsrecon"), cmd_cb=_cmd_cb("dnsrecon"))

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


def _run_active(
    domain: str,
    wordlist: str,
    urls: list[str],
    progress_cb: Callable[[str], None] | None,
    debug_cb: Callable[[str, str], None] | None = None,
    cmd_cb: Callable[[str, str], None] | None = None,
    finish_cb: Callable[[str, str | None, bool], None] | None = None,
    overall_mode: EnumMode | None = None,
) -> tuple[list[ToolResult], list[VhostResult]]:
    """Run all active enumeration tools.

    :param domain: Target base domain.
    :param wordlist: Path to the DNS wordlist.
    :param urls: Target URLs for vhost fuzzing; one ``run_ffuf`` call is made per URL.
        Pass an empty list to skip ffuf entirely.
    :param progress_cb: Optional callback for progress messages.
    :param debug_cb: Optional callback for real-time tool output lines,
        called as ``debug_cb(tool_name, line)``.
    :param cmd_cb: Optional callback for the command that runs each tool,
        called as ``cmd_cb(tool_name, cmd_string)``.
    :param finish_cb: Optional callback called when a tool completes,
        called as ``finish_cb(tool_name, error_or_none, timed_out)``.
    :param overall_mode: The mode passed to :func:`assess`; when ``EnumMode.ALL``
        tools that also run in the passive phase use a ``"<name> active"`` key so
        the debug log shows a distinct section for each phase.
    :returns: Tuple of (tools, vhosts).
    """

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    def _key(name: str) -> str:
        """Return the callback key for *name*, appending a phase suffix in ALL mode."""
        if overall_mode == EnumMode.ALL and name in ("amass", "dnsrecon"):
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

    _cb("Running amass (active)…")
    result = run_amass(domain, mode=EnumMode.ACTIVE, wordlist=wordlist, line_cb=_line_cb("amass"), cmd_cb=_cmd_cb("amass"))
    result.mode = EnumMode.ACTIVE
    tools.append(result)
    if finish_cb:
        finish_cb(_key("amass"), result.error, result.timed_out)

    _cb("Running dnsrecon (active)…")
    result = run_dnsrecon(domain, mode=EnumMode.ACTIVE, wordlist=wordlist, line_cb=_line_cb("dnsrecon"), cmd_cb=_cmd_cb("dnsrecon"))
    result.mode = EnumMode.ACTIVE
    tools.append(result)
    if finish_cb:
        finish_cb(_key("dnsrecon"), result.error, result.timed_out)

    _cb("Running gobuster dns…")
    result = run_gobuster_dns(domain, wordlist=wordlist, line_cb=_line_cb("gobuster"), cmd_cb=_cmd_cb("gobuster"))
    result.mode = EnumMode.ACTIVE
    tools.append(result)
    if finish_cb:
        finish_cb(_key("gobuster"), result.error, result.timed_out)

    all_vhosts: list[VhostResult] = []
    if urls:
        _cb(f"Running ffuf (vhost fuzzing) against {len(urls)} IP(s)…")
        seen_vhosts: set[str] = set()
        for i, target_url in enumerate(urls):
            ffuf_key = f"ffuf {i + 1}" if len(urls) > 1 else "ffuf"
            _cb(f"  ffuf → {target_url}")
            hits = run_ffuf(
                domain, url=target_url, wordlist=wordlist,
                line_cb=(lambda line, k=ffuf_key: debug_cb(k, line)) if debug_cb is not None else None,
                cmd_cb=(lambda c, k=ffuf_key: cmd_cb(k, c)) if cmd_cb is not None else None,
            )
            if finish_cb:
                finish_cb(ffuf_key, None, False)
            for v in hits:
                if v.vhost not in seen_vhosts:
                    seen_vhosts.add(v.vhost)
                    all_vhosts.append(v)
        tools.append(ToolResult(name="ffuf", subdomains=[v.vhost for v in all_vhosts], mode=EnumMode.ACTIVE))
    else:
        tools.append(ToolResult(name="ffuf", available=False, error="no URL resolved", mode=EnumMode.ACTIVE))
        if finish_cb:
            finish_cb("ffuf", "no URL resolved", False)

    return tools, all_vhosts


def _resolve_all(
    fqdns: list[str],
    tool_map: dict[str, list[str]],
    timeout: float = 5.0,
) -> list[SubdomainResult]:
    """Resolve all *fqdns* in parallel and build :class:`SubdomainResult` objects.

    :param fqdns: Unique fully-qualified domain names to resolve.
    :param tool_map: Mapping of fqdn → list of tool names that found it.
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
            tools=tool_map.get(fqdn, []),
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
    finish_cb: Callable[[str, str | None, bool], None] | None = None,
) -> EnumReport:
    """Run subdomain enumeration for *domain* and return an :class:`~subdomainenum.models.EnumReport`.

    :param domain: Target base domain (e.g. ``"example.com"``).
    :param mode: Enumeration strategy – ``passive``, ``active``, or ``all``.
    :param wordlist: Path to wordlist required for active/all modes.
    :param url: Target URL for wfuzz vhost fuzzing (optional).
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

    if mode in (EnumMode.PASSIVE, EnumMode.ALL):
        _cb("Starting passive enumeration…")
        all_tools.extend(_run_passive(domain, progress_cb, debug_cb=debug_cb, cmd_cb=cmd_cb, finish_cb=finish_cb, overall_mode=mode))

    if mode in (EnumMode.ACTIVE, EnumMode.ALL):
        _cb("Starting active enumeration…")
        if url is not None:
            urls: list[str] = [url]
        else:
            candidate_ips: list[str] = resolve_ips(domain)
            if mode == EnumMode.ALL and all_tools:
                passive_fqdns: list[str] = list({
                    sub for tool in all_tools for sub in tool.subdomains
                })
                if passive_fqdns:
                    with ThreadPoolExecutor(max_workers=min(50, len(passive_fqdns))) as exc:
                        extra_ip_lists = list(exc.map(resolve_ips, passive_fqdns))
                    for ip_list in extra_ip_lists:
                        candidate_ips.extend(ip_list)
            seen_ips: set[str] = set()
            unique_ips: list[str] = []
            for ip in candidate_ips:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    formatted = f"[{ip}]" if ":" in ip else ip
                    unique_ips.append(f"http://{formatted}")
            urls = unique_ips
        active_tools, vhosts = _run_active(
            domain, wordlist=wordlist, urls=urls,
            progress_cb=progress_cb, debug_cb=debug_cb,
            cmd_cb=cmd_cb, finish_cb=finish_cb, overall_mode=mode,
        )
        all_tools.extend(active_tools)
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
    subdomains = _resolve_all(unique_fqdns, fqdn_tools, timeout=timeout)

    return EnumReport(
        domain=domain,
        mode=mode,
        subdomains=subdomains,
        vhosts=all_vhosts,
        tools=all_tools,
    )
