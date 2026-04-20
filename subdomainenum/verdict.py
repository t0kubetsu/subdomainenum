"""Factual summary of enumeration results.

No grading, no severity, no recommended actions.  Only counts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from subdomainenum.models import EnumReport, Status


@dataclass
class VerdictSummary:
    """Pure count summary of an :class:`~subdomainenum.models.EnumReport`.

    :param total_subdomains: Total number of unique subdomains discovered.
    :param alive: Subdomains that resolved to at least one IP.
    :param dead: Subdomains that returned NXDOMAIN or empty answer.
    :param timeouts: Subdomains for which DNS resolution timed out.
    :param vhosts_found: Virtual hosts discovered via HTTP fuzzing.
    :param tools_ran: Number of tools that ran to completion without error or timeout
        (``available=True``, ``error is None``, ``timed_out=False``).
    :param tools_failed: Number of tools that failed — unavailable binary or wrapper
        error. Takes precedence over ``tools_timed_out`` when both conditions hold.
    :param tools_timed_out: Number of tools that were killed due to timeout but
        otherwise ran (``available=True``, ``error is None``, ``timed_out=True``).
        Combined with ``tools_ran`` and ``tools_failed``, the three counts partition
        ``len(report.tools)``.
    :param tools_available: Unique tool names whose binary was found in at least one
        run (deduplicated across phases — a tool run in both passive and active
        in ``ALL`` mode appears once).
    :param tools_missing: Unique tool names whose every run reported the binary
        as unavailable. A name that is available in any run is excluded from
        this list even if another run reported it missing.
    :param summary_line: Single human-readable summary string.
    """

    total_subdomains: int = 0
    alive: int = 0
    dead: int = 0
    timeouts: int = 0
    vhosts_found: int = 0
    tools_ran: int = 0
    tools_failed: int = 0
    tools_timed_out: int = 0
    tools_available: list[str] = field(default_factory=list)
    tools_missing: list[str] = field(default_factory=list)
    summary_line: str = ""


def build_verdict(report: EnumReport) -> VerdictSummary:
    """Compute a :class:`VerdictSummary` from *report*.

    :param report: The completed enumeration report.
    :returns: A counts-only summary with no scoring or grading.
    :rtype: VerdictSummary
    """
    alive = sum(1 for s in report.subdomains if s.status == Status.ALIVE)
    dead = sum(1 for s in report.subdomains if s.status == Status.DEAD)
    timeouts = sum(1 for s in report.subdomains if s.status == Status.TIMEOUT)

    tools_failed = sum(1 for t in report.tools if not t.available or t.error is not None)
    tools_timed_out = sum(
        1 for t in report.tools
        if t.timed_out and t.available and t.error is None
    )
    tools_ran = sum(
        1 for t in report.tools
        if t.available and t.error is None and not t.timed_out
    )

    # Deduplicate by name while preserving first-seen order. In ALL mode amass
    # and dnsrecon each produce two ToolResults (one per phase); naive list
    # comprehensions would list them twice. A tool is "available" if at least
    # one run found the binary; it appears in "missing" only if no run did.
    tools_available = list(dict.fromkeys(
        t.name for t in report.tools if t.available
    ))
    available_set = set(tools_available)
    tools_missing = list(dict.fromkeys(
        t.name for t in report.tools
        if not t.available and t.name not in available_set
    ))

    total = len(report.subdomains)
    vhosts_found = len(report.vhosts)

    parts = [f"{total} subdomain{'s' if total != 1 else ''} found"]
    if total > 0:
        parts.append(f"({alive} alive, {dead} dead, {timeouts} timeout{'s' if timeouts != 1 else ''})")
    if vhosts_found:
        parts.append(f"· {vhosts_found} vhost{'s' if vhosts_found != 1 else ''}")

    return VerdictSummary(
        total_subdomains=total,
        alive=alive,
        dead=dead,
        timeouts=timeouts,
        vhosts_found=vhosts_found,
        tools_ran=tools_ran,
        tools_failed=tools_failed,
        tools_timed_out=tools_timed_out,
        tools_available=tools_available,
        tools_missing=tools_missing,
        summary_line=" ".join(parts),
    )
