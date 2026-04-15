"""Tests for subdomainenum.verdict – pure counts summary."""

from __future__ import annotations

from subdomainenum.models import EnumMode, EnumReport, SourceResult, Status, SubdomainResult, VhostResult
from subdomainenum.verdict import VerdictSummary, build_verdict


class TestVerdictSummary:
    def test_construction(self) -> None:
        v = VerdictSummary(
            total_subdomains=10,
            alive=6,
            dead=3,
            timeouts=1,
            vhosts_found=2,
            sources_ran=4,
            sources_failed=1,
            tools_available=["subfinder", "amass"],
            tools_missing=["findomain"],
            summary_line="10 subdomains found (6 alive, 3 dead, 1 timeout) via 4 sources",
        )
        assert v.total_subdomains == 10
        assert v.alive == 6
        assert v.dead == 3
        assert v.timeouts == 1
        assert v.vhosts_found == 2
        assert v.sources_ran == 4
        assert v.sources_failed == 1
        assert "subfinder" in v.tools_available
        assert "findomain" in v.tools_missing
        assert "10 subdomains" in v.summary_line


class TestBuildVerdict:
    def _make_report(
        self,
        subs: list[SubdomainResult] | None = None,
        vhosts: list[VhostResult] | None = None,
        sources: list[SourceResult] | None = None,
        mode: EnumMode = EnumMode.PASSIVE,
    ) -> EnumReport:
        return EnumReport(
            domain="example.com",
            mode=mode,
            subdomains=subs or [],
            vhosts=vhosts or [],
            sources=sources or [],
        )

    def test_empty_report(self) -> None:
        report = self._make_report()
        v = build_verdict(report)
        assert v.total_subdomains == 0
        assert v.alive == 0
        assert v.dead == 0
        assert v.timeouts == 0
        assert v.vhosts_found == 0
        assert v.sources_ran == 0
        assert v.sources_failed == 0
        assert v.tools_available == []
        assert v.tools_missing == []

    def test_counts_from_subdomains(self) -> None:
        subs = [
            SubdomainResult(fqdn="a.example.com", status=Status.ALIVE, alive=True),
            SubdomainResult(fqdn="b.example.com", status=Status.ALIVE, alive=True),
            SubdomainResult(fqdn="c.example.com", status=Status.DEAD, alive=False),
            SubdomainResult(fqdn="d.example.com", status=Status.TIMEOUT),
        ]
        report = self._make_report(subs=subs)
        v = build_verdict(report)
        assert v.total_subdomains == 4
        assert v.alive == 2
        assert v.dead == 1
        assert v.timeouts == 1

    def test_vhosts_count(self) -> None:
        vhosts = [
            VhostResult(vhost="admin.example.com", status_code=200),
            VhostResult(vhost="dev.example.com", status_code=302),
        ]
        report = self._make_report(vhosts=vhosts)
        v = build_verdict(report)
        assert v.vhosts_found == 2

    def test_sources_count(self) -> None:
        sources = [
            SourceResult(name="subfinder", subdomains=["a.example.com"], available=True),
            SourceResult(name="amass", subdomains=[], available=True),
            SourceResult(name="findomain", available=False, error="not found"),
        ]
        report = self._make_report(sources=sources)
        v = build_verdict(report)
        assert v.sources_ran == 2
        assert v.sources_failed == 1

    def test_tools_lists(self) -> None:
        sources = [
            SourceResult(name="subfinder", available=True),
            SourceResult(name="amass", available=True),
            SourceResult(name="findomain", available=False, error="not found"),
        ]
        report = self._make_report(sources=sources)
        v = build_verdict(report)
        assert "subfinder" in v.tools_available
        assert "amass" in v.tools_available
        assert "findomain" in v.tools_missing

    def test_summary_line_contains_key_counts(self) -> None:
        subs = [
            SubdomainResult(fqdn="a.example.com", status=Status.ALIVE, alive=True),
            SubdomainResult(fqdn="b.example.com", status=Status.DEAD, alive=False),
        ]
        sources = [SourceResult(name="subfinder", available=True)]
        report = self._make_report(subs=subs, sources=sources)
        v = build_verdict(report)
        assert "2" in v.summary_line  # total subdomains
        assert "1" in v.summary_line  # alive or sources

    def test_summary_line_not_empty(self) -> None:
        report = self._make_report()
        v = build_verdict(report)
        assert len(v.summary_line) > 0
