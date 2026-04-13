"""Tests for subdomainenum.reporter – Rich rendering and to_dict serialization."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

from subdomainenum.models import EnumMode, EnumReport, SourceResult, Status, SubdomainResult, VhostResult
from subdomainenum.reporter import print_report, save_report, to_dict


def _make_report() -> EnumReport:
    return EnumReport(
        domain="example.com",
        mode=EnumMode.ALL,
        subdomains=[
            SubdomainResult(fqdn="sub.example.com", status=Status.ALIVE, alive=True, ip_addresses=["1.2.3.4"], sources=["crt.sh"]),
            SubdomainResult(fqdn="dead.example.com", status=Status.DEAD, alive=False),
        ],
        vhosts=[
            VhostResult(vhost="admin.example.com", status_code=200, ip="1.2.3.4", content_length=512),
        ],
        sources=[
            SourceResult(name="crt.sh", subdomains=["sub.example.com"], available=True),
            SourceResult(name="amass", available=False, error="not found"),
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
        assert isinstance(result["sources"], list)
        assert len(result["sources"]) == 2

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
        report = EnumReport(domain="example.com", mode=EnumMode.PASSIVE, subdomains=[], sources=[])
        print_report(report, console=console)
        assert "No subdomains found" in buf.getvalue()


class TestSaveReport:
    def test_save_report_writes_json(self, tmp_path) -> None:
        out = tmp_path / "report.json"
        save_report(_make_report(), out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["domain"] == "example.com"
