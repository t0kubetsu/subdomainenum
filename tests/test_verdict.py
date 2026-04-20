"""Tests for subdomainenum.verdict – pure counts summary."""

from __future__ import annotations

from subdomainenum.models import EnumMode, EnumReport, ToolResult, Status, SubdomainResult, VhostResult
from subdomainenum.verdict import VerdictSummary, build_verdict


class TestVerdictSummary:
    def test_construction(self) -> None:
        v = VerdictSummary(
            total_subdomains=10,
            alive=6,
            dead=3,
            timeouts=1,
            vhosts_found=2,
            tools_ran=4,
            tools_failed=1,
            tools_timed_out=2,
            tools_available=["subfinder", "amass"],
            tools_missing=["findomain"],
            summary_line="10 subdomains found (6 alive, 3 dead, 1 timeout)",
        )
        assert v.total_subdomains == 10
        assert v.alive == 6
        assert v.dead == 3
        assert v.timeouts == 1
        assert v.vhosts_found == 2
        assert v.tools_ran == 4
        assert v.tools_failed == 1
        assert v.tools_timed_out == 2
        assert "subfinder" in v.tools_available
        assert "findomain" in v.tools_missing
        assert "10 subdomains" in v.summary_line


class TestBuildVerdict:
    def _make_report(
        self,
        subs: list[SubdomainResult] | None = None,
        vhosts: list[VhostResult] | None = None,
        tools: list[ToolResult] | None = None,
        mode: EnumMode = EnumMode.PASSIVE,
    ) -> EnumReport:
        return EnumReport(
            domain="example.com",
            mode=mode,
            subdomains=subs or [],
            vhosts=vhosts or [],
            tools=tools or [],
        )

    def test_empty_report(self) -> None:
        report = self._make_report()
        v = build_verdict(report)
        assert v.total_subdomains == 0
        assert v.alive == 0
        assert v.dead == 0
        assert v.timeouts == 0
        assert v.vhosts_found == 0
        assert v.tools_ran == 0
        assert v.tools_failed == 0
        assert v.tools_timed_out == 0
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

    def test_tools_count(self) -> None:
        tools = [
            ToolResult(name="subfinder", subdomains=["a.example.com"], available=True),
            ToolResult(name="amass", subdomains=[], available=True),
            ToolResult(name="findomain", available=False, error="not found"),
        ]
        report = self._make_report(tools=tools)
        v = build_verdict(report)
        assert v.tools_ran == 2
        assert v.tools_failed == 1
        assert v.tools_timed_out == 0

    def test_tools_timed_out_count(self) -> None:
        tools = [
            ToolResult(name="subfinder", available=True, timed_out=True),
            ToolResult(name="amass", available=True, timed_out=False),
            ToolResult(name="dnsrecon", available=True, timed_out=True),
        ]
        report = self._make_report(tools=tools)
        v = build_verdict(report)
        assert v.tools_timed_out == 2

    def test_tools_counts_are_mutually_exclusive(self) -> None:
        """ran / failed / timed_out must partition len(report.tools)."""
        tools = [
            ToolResult(name="subfinder", available=True),
            ToolResult(name="amass", available=True, timed_out=True),
            ToolResult(name="findomain", available=False, error="not found"),
            ToolResult(name="dnsrecon", available=True, error="crash", timed_out=True),
        ]
        report = self._make_report(tools=tools)
        v = build_verdict(report)
        assert v.tools_ran == 1
        assert v.tools_timed_out == 1
        assert v.tools_failed == 2
        assert v.tools_ran + v.tools_failed + v.tools_timed_out == len(tools)

    def test_summary_line_has_no_via_tools_clause(self) -> None:
        tools = [ToolResult(name="subfinder", available=True)]
        report = self._make_report(tools=tools)
        v = build_verdict(report)
        assert "via" not in v.summary_line
        assert "tool" not in v.summary_line

    def test_tools_lists(self) -> None:
        tools = [
            ToolResult(name="subfinder", available=True),
            ToolResult(name="amass", available=True),
            ToolResult(name="findomain", available=False, error="not found"),
        ]
        report = self._make_report(tools=tools)
        v = build_verdict(report)
        assert "subfinder" in v.tools_available
        assert "amass" in v.tools_available
        assert "findomain" in v.tools_missing

    def test_tools_available_deduplicated_across_phases(self) -> None:
        """In ALL mode amass/dnsrecon each have two ToolResults; each name appears once."""
        tools = [
            ToolResult(name="subfinder", available=True, mode=EnumMode.PASSIVE),
            ToolResult(name="amass", available=True, mode=EnumMode.PASSIVE),
            ToolResult(name="dnsrecon", available=True, mode=EnumMode.PASSIVE),
            ToolResult(name="amass", available=True, mode=EnumMode.ACTIVE),
            ToolResult(name="dnsrecon", available=True, mode=EnumMode.ACTIVE),
            ToolResult(name="gobuster", available=True, mode=EnumMode.ACTIVE),
        ]
        report = self._make_report(tools=tools, mode=EnumMode.ALL)
        v = build_verdict(report)
        assert v.tools_available.count("amass") == 1
        assert v.tools_available.count("dnsrecon") == 1
        assert v.tools_available == ["subfinder", "amass", "dnsrecon", "gobuster"]

    def test_tools_missing_excludes_names_available_elsewhere(self) -> None:
        """If a name is available in one run and unavailable in another, it's NOT in missing."""
        tools = [
            ToolResult(name="amass", available=True, mode=EnumMode.PASSIVE),
            ToolResult(name="amass", available=False, error="not found", mode=EnumMode.ACTIVE),
            ToolResult(name="findomain", available=False, error="not found"),
        ]
        report = self._make_report(tools=tools)
        v = build_verdict(report)
        assert v.tools_available == ["amass"]
        assert v.tools_missing == ["findomain"]
        assert "amass" not in v.tools_missing

    def test_tools_missing_deduplicated(self) -> None:
        """A missing tool listed twice appears once in tools_missing."""
        tools = [
            ToolResult(name="findomain", available=False, error="not found"),
            ToolResult(name="findomain", available=False, error="not found"),
        ]
        report = self._make_report(tools=tools)
        v = build_verdict(report)
        assert v.tools_missing == ["findomain"]

    def test_summary_line_contains_key_counts(self) -> None:
        subs = [
            SubdomainResult(fqdn="a.example.com", status=Status.ALIVE, alive=True),
            SubdomainResult(fqdn="b.example.com", status=Status.DEAD, alive=False),
        ]
        tools = [ToolResult(name="subfinder", available=True)]
        report = self._make_report(subs=subs, tools=tools)
        v = build_verdict(report)
        assert "2" in v.summary_line
        assert "1" in v.summary_line

    def test_summary_line_not_empty(self) -> None:
        report = self._make_report()
        v = build_verdict(report)
        assert len(v.summary_line) > 0
