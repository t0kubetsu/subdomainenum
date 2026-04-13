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
    :param sources_ran: Number of sources that ran successfully (available=True, no error).
    :param sources_failed: Number of sources that failed (unavailable binary or request error).
    :param tools_available: Names of available external tools.
    :param tools_missing: Names of requested tools that were not found on the system.
    :param summary_line: Single human-readable summary string.
    """

    total_subdomains: int = 0
    alive: int = 0
    dead: int = 0
    timeouts: int = 0
    vhosts_found: int = 0
    sources_ran: int = 0
    sources_failed: int = 0
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

    sources_ran = sum(1 for s in report.sources if s.available and s.error is None)
    sources_failed = sum(1 for s in report.sources if not s.available or s.error is not None)

    tools_available = [s.name for s in report.sources if s.available]
    tools_missing = [s.name for s in report.sources if not s.available]

    total = len(report.subdomains)
    vhosts_found = len(report.vhosts)

    parts = [f"{total} subdomain{'s' if total != 1 else ''} found"]
    if total > 0:
        parts.append(f"({alive} alive, {dead} dead, {timeouts} timeout{'s' if timeouts != 1 else ''})")
    if vhosts_found:
        parts.append(f"· {vhosts_found} vhost{'s' if vhosts_found != 1 else ''}")
    parts.append(f"via {sources_ran} source{'s' if sources_ran != 1 else ''}")

    return VerdictSummary(
        total_subdomains=total,
        alive=alive,
        dead=dead,
        timeouts=timeouts,
        vhosts_found=vhosts_found,
        sources_ran=sources_ran,
        sources_failed=sources_failed,
        tools_available=tools_available,
        tools_missing=tools_missing,
        summary_line=" ".join(parts),
    )
