"""Tests for subdomainenum.reporter – Rich rendering and to_dict serialization."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

from subdomainenum.models import EnumMode, EnumReport, ToolResult, Status, SubdomainResult, VhostResult
from subdomainenum.reporter import print_report, save_report, to_dict


def _make_report() -> EnumReport:
    return EnumReport(
        domain="example.com",
        mode=EnumMode.ALL,
        subdomains=[
            SubdomainResult(fqdn="sub.example.com", status=Status.ALIVE, alive=True, ip_addresses=["1.2.3.4"], tools=["dnsrecon"]),
            SubdomainResult(fqdn="dead.example.com", status=Status.DEAD, alive=False),
        ],
        vhosts=[
            VhostResult(vhost="admin.example.com", status_code=200, content_length=512),
        ],
        tools=[
            ToolResult(name="dnsrecon", subdomains=["sub.example.com"], available=True, mode=EnumMode.PASSIVE),
            ToolResult(name="amass", available=False, error="not found", mode=EnumMode.ACTIVE),
        ],
    )


class TestToDict:
    def test_returns_dict(self) -> None:
        report = _make_report()
        result = to_dict(report)
        assert isinstance(result, dict)

    def test_domain_present(self) -> None:
        result = to_dict(_make_report())
        assert result["domain"] == "example.com"

    def test_mode_present(self) -> None:
        result = to_dict(_make_report())
        assert result["mode"] == "all"

    def test_subdomains_list(self) -> None:
        result = to_dict(_make_report())
        assert isinstance(result["subdomains"], list)
        assert len(result["subdomains"]) == 2

    def test_subdomain_has_fqdn_and_status(self) -> None:
        result = to_dict(_make_report())
        sub = next(s for s in result["subdomains"] if s["fqdn"] == "sub.example.com")
        assert sub["status"] == "ALIVE"
        assert sub["alive"] is True

    def test_vhosts_list(self) -> None:
        result = to_dict(_make_report())
        assert isinstance(result["vhosts"], list)
        assert len(result["vhosts"]) == 1

    def test_vhost_has_status_code(self) -> None:
        result = to_dict(_make_report())
        assert result["vhosts"][0]["status_code"] == 200

    def test_sources_list(self) -> None:
        result = to_dict(_make_report())
        assert isinstance(result["tools"], list)
        assert len(result["tools"]) == 2

    def test_sources_include_mode(self) -> None:
        result = to_dict(_make_report())
        passive_src = next(s for s in result["tools"] if s["name"] == "dnsrecon")
        active_src = next(s for s in result["tools"] if s["name"] == "amass")
        assert passive_src["mode"] == "passive"
        assert active_src["mode"] == "active"

    def test_sources_mode_none_when_untagged(self) -> None:
        report = EnumReport(
            domain="example.com",
            mode=EnumMode.PASSIVE,
            tools=[ToolResult(name="subfinder")],
        )
        result = to_dict(report)
        assert result["tools"][0]["mode"] is None

    def test_json_serializable(self) -> None:
        result = to_dict(_make_report())
        # Must not raise
        serialized = json.dumps(result)
        assert "example.com" in serialized


class TestPrintReport:
    def test_runs_without_error(self) -> None:
        console = Console(file=StringIO(), width=120)
        report = _make_report()
        # Should not raise
        print_report(report, console=console)

    def test_output_contains_domain(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=120, highlight=False)
        print_report(_make_report(), console=console)
        output = buf.getvalue()
        assert "example.com" in output

    def test_output_contains_subdomain(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=120, highlight=False)
        print_report(_make_report(), console=console)
        output = buf.getvalue()
        assert "sub.example.com" in output

    def test_prints_no_subdomains_message_when_empty(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=120, highlight=False)
        report = EnumReport(domain="example.com", mode=EnumMode.PASSIVE, subdomains=[], tools=[])
        print_report(report, console=console)
        assert "No subdomains found" in buf.getvalue()

    def test_mode_column_shown_in_all_mode(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=200, highlight=False)
        print_report(_make_report(), console=console)
        output = buf.getvalue()
        assert "Mode" in output
        assert "passive" in output
        assert "active" in output

    def test_mode_column_hidden_in_passive_mode(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=200, highlight=False)
        report = EnumReport(
            domain="example.com",
            mode=EnumMode.PASSIVE,
            tools=[ToolResult(name="subfinder", mode=EnumMode.PASSIVE)],
        )
        print_report(report, console=console)
        output = buf.getvalue()
        assert "Mode" not in output

    def test_mode_column_hidden_in_active_mode(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=200, highlight=False)
        report = EnumReport(
            domain="example.com",
            mode=EnumMode.ACTIVE,
            tools=[ToolResult(name="gobuster", mode=EnumMode.ACTIVE)],
        )
        print_report(report, console=console)
        output = buf.getvalue()
        assert "Mode" not in output

    def test_mode_column_shows_dash_for_untagged_source(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=200, highlight=False)
        report = EnumReport(
            domain="example.com",
            mode=EnumMode.ALL,
            tools=[ToolResult(name="unknown")],
        )
        print_report(report, console=console)
        output = buf.getvalue()
        assert "Mode" in output
        assert "—" in output

    def test_output_contains_header_rule(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=120, highlight=False)
        print_report(_make_report(), console=console)
        assert "Subdomain Enumeration Report" in buf.getvalue()

    def test_output_contains_end_of_report(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=120, highlight=False)
        print_report(_make_report(), console=console)
        assert "End of Report" in buf.getvalue()

    def test_output_contains_summary_panel(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=120, highlight=False)
        print_report(_make_report(), console=console)
        assert "Summary" in buf.getvalue()

    def test_output_contains_vhost_section_title_when_present(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=120, highlight=False)
        print_report(_make_report(), console=console)
        assert "Virtual Hosts (ffuf)" in buf.getvalue()

    def test_sources_table_has_timed_out_column(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=200, highlight=False)
        print_report(_make_report(), console=console)
        assert "Timed Out" in buf.getvalue()

    def test_sources_timed_out_flag_rendered(self) -> None:
        buf = StringIO()
        console = Console(file=buf, width=200, highlight=False)
        report = EnumReport(
            domain="example.com",
            mode=EnumMode.PASSIVE,
            tools=[
                ToolResult(name="subfinder", mode=EnumMode.PASSIVE, timed_out=True),
                ToolResult(name="findomain", mode=EnumMode.PASSIVE, timed_out=False),
            ],
        )
        print_report(report, console=console)
        output = buf.getvalue()
        assert "Timed Out" in output
        assert "yes" in output


class TestSaveReport:
    def test_save_report_writes_json(self, tmp_path) -> None:
        out = tmp_path / "report.json"
        save_report(_make_report(), out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["domain"] == "example.com"
