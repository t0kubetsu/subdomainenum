"""Tests for subdomainenum.assessor – main orchestration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from subdomainenum.assessor import assess, _run_passive, _run_active, _resolve_all
from subdomainenum.models import EnumMode, EnumReport, SourceResult, Status, SubdomainResult


def _make_source(*fqdns: str, name: str = "crt.sh", available: bool = True) -> SourceResult:
    return SourceResult(name=name, subdomains=list(fqdns), available=available)


class TestAssess:
    def test_returns_enum_report(self) -> None:
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[_make_source("sub.example.com")]),
            patch("subdomainenum.assessor._resolve_all", return_value=[
                SubdomainResult(fqdn="sub.example.com", status=Status.ALIVE, alive=True),
            ]),
        ):
            report = assess("example.com", mode=EnumMode.PASSIVE)
        assert isinstance(report, EnumReport)
        assert report.domain == "example.com"

    def test_passive_mode_skips_active_tools(self) -> None:
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]) as mock_passive,
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.PASSIVE)
        mock_passive.assert_called_once()
        mock_active.assert_not_called()

    def test_active_mode_skips_passive_sources(self) -> None:
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]) as mock_passive,
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt")
        mock_passive.assert_not_called()
        mock_active.assert_called_once()

    def test_all_mode_runs_both(self) -> None:
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]) as mock_passive,
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        mock_passive.assert_called_once()
        mock_active.assert_called_once()

    def test_progress_cb_called(self) -> None:
        calls: list[str] = []
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]),
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.PASSIVE, progress_cb=calls.append)
        assert len(calls) > 0

    def test_deduplicates_subdomains_across_sources(self) -> None:
        sources = [
            _make_source("sub.example.com", name="crt.sh"),
            _make_source("sub.example.com", name="subfinder"),
        ]
        with (
            patch("subdomainenum.assessor._run_passive", return_value=sources),
            patch("subdomainenum.assessor._resolve_all") as mock_resolve,
        ):
            mock_resolve.return_value = [
                SubdomainResult(fqdn="sub.example.com", status=Status.ALIVE, alive=True)
            ]
            report = assess("example.com", mode=EnumMode.PASSIVE)
        assert len(report.subdomains) == 1

    def test_report_contains_sources(self) -> None:
        sources = [_make_source("sub.example.com", name="crt.sh")]
        with (
            patch("subdomainenum.assessor._run_passive", return_value=sources),
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
        ):
            report = assess("example.com", mode=EnumMode.PASSIVE)
        assert any(s.name == "crt.sh" for s in report.sources)

    def test_active_wordlist_required_raises(self) -> None:
        with pytest.raises(ValueError, match="wordlist"):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist=None)


# ---------------------------------------------------------------------------
# _run_passive
# ---------------------------------------------------------------------------


class TestRunPassive:
    def _patches(self, src: SourceResult):
        return (
            patch("subdomainenum.assessor.query_crt_sh", return_value=src),
            patch("subdomainenum.assessor.query_san", return_value=src),
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
        )

    def test_returns_all_source_results(self) -> None:
        src = _make_source("sub.example.com")
        with (
            patch("subdomainenum.assessor.query_crt_sh", return_value=src),
            patch("subdomainenum.assessor.query_san", return_value=src),
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
        ):
            results = _run_passive("example.com", progress_cb=None)
        assert len(results) == 6

    def test_progress_cb_called(self) -> None:
        calls: list[str] = []
        src = _make_source()
        with (
            patch("subdomainenum.assessor.query_crt_sh", return_value=src),
            patch("subdomainenum.assessor.query_san", return_value=src),
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
        ):
            _run_passive("example.com", progress_cb=calls.append)
        assert len(calls) > 0

    def test_debug_cb_lambda_invoked(self) -> None:
        """Cover the lambda body in _line_cb by having a mock call line_cb."""
        debug_calls: list[tuple] = []

        def fake_subfinder(domain, *, line_cb=None, **kwargs):
            if line_cb:
                line_cb("sub.example.com")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.query_crt_sh", return_value=src),
            patch("subdomainenum.assessor.query_san", return_value=src),
            patch("subdomainenum.assessor.run_subfinder", side_effect=fake_subfinder),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
        ):
            _run_passive(
                "example.com",
                progress_cb=None,
                debug_cb=lambda s, l: debug_calls.append((s, l)),
            )
        assert ("subfinder", "sub.example.com") in debug_calls

    def test_cmd_cb_lambda_invoked(self) -> None:
        """Cover the lambda body in _cmd_cb by having a mock call cmd_cb."""
        cmd_calls: list[tuple] = []

        def fake_crt_sh(domain, *, cmd_cb=None, **kwargs):
            if cmd_cb:
                cmd_cb("GET https://crt.sh/...")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.query_crt_sh", side_effect=fake_crt_sh),
            patch("subdomainenum.assessor.query_san", return_value=src),
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
        ):
            _run_passive(
                "example.com",
                progress_cb=None,
                cmd_cb=lambda s, c: cmd_calls.append((s, c)),
            )
        assert any(s == "crt.sh" for s, _ in cmd_calls)

    def test_source_exception_captured(self) -> None:
        """Cover lines 91-92: exception from a future is caught and stored."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.query_crt_sh", side_effect=RuntimeError("boom")),
            patch("subdomainenum.assessor.query_san", return_value=src),
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
        ):
            results = _run_passive("example.com", progress_cb=None)
        error_sources = [r for r in results if r.available is False]
        assert len(error_sources) == 1
        assert "boom" in error_sources[0].error


# ---------------------------------------------------------------------------
# _run_active
# ---------------------------------------------------------------------------


class TestRunActive:
    def test_returns_sources_without_url(self) -> None:
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
            patch("subdomainenum.assessor.run_wfuzz") as mock_wfuzz,
        ):
            sources, vhosts = _run_active("example.com", wordlist="/tmp/w.txt", url=None, progress_cb=None)
        mock_wfuzz.assert_not_called()
        assert len(sources) == 2

    def test_runs_wfuzz_when_url_provided(self) -> None:
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
            patch("subdomainenum.assessor.run_wfuzz", return_value=[]) as mock_wfuzz,
        ):
            sources, vhosts = _run_active(
                "example.com", wordlist="/tmp/w.txt", url="http://example.com", progress_cb=None
            )
        mock_wfuzz.assert_called_once()

    def test_progress_cb_called(self) -> None:
        calls: list[str] = []
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active("example.com", wordlist="/tmp/w.txt", url=None, progress_cb=calls.append)
        assert len(calls) > 0

    def test_debug_cb_lambda_invoked(self) -> None:
        """Cover the lambda body in _line_cb by having a mock call line_cb."""
        debug_calls: list[tuple] = []

        def fake_dnsrecon(domain, *, wordlist, timeout=300, line_cb=None, **kwargs):
            if line_cb:
                line_cb("output line")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_dnsrecon", side_effect=fake_dnsrecon),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                url=None,
                progress_cb=None,
                debug_cb=lambda s, l: debug_calls.append((s, l)),
            )
        assert ("dnsrecon", "output line") in debug_calls

    def test_cmd_cb_lambda_invoked(self) -> None:
        """Cover the lambda body in _cmd_cb for active sources."""
        cmd_calls: list[tuple] = []

        def fake_dnsrecon(domain, *, wordlist, timeout=300, cmd_cb=None, **kwargs):
            if cmd_cb:
                cmd_cb("dnsrecon -d example.com -w /tmp/w.txt")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_dnsrecon", side_effect=fake_dnsrecon),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                url=None,
                progress_cb=None,
                cmd_cb=lambda s, c: cmd_calls.append((s, c)),
            )
        assert any(s == "dnsrecon" for s, _ in cmd_calls)


# ---------------------------------------------------------------------------
# _resolve_all
# ---------------------------------------------------------------------------


class TestResolveAll:
    def test_alive_when_ips_present(self) -> None:
        with patch("subdomainenum.assessor.resolve_ips", return_value=["1.2.3.4"]):
            results = _resolve_all(["sub.example.com"], {"sub.example.com": ["crt.sh"]})
        assert results[0].alive is True
        assert results[0].status == Status.ALIVE

    def test_dead_when_no_ips(self) -> None:
        with patch("subdomainenum.assessor.resolve_ips", return_value=[]):
            results = _resolve_all(["dead.example.com"], {})
        assert results[0].alive is False
        assert results[0].status == Status.DEAD

    def test_empty_fqdns_returns_empty(self) -> None:
        results = _resolve_all([], {})
        assert results == []

    def test_results_sorted_by_fqdn(self) -> None:
        with patch("subdomainenum.assessor.resolve_ips", return_value=["1.2.3.4"]):
            results = _resolve_all(["z.example.com", "a.example.com"], {})
        assert results[0].fqdn == "a.example.com"
        assert results[1].fqdn == "z.example.com"
