"""Tests for subdomainenum.assessor – main orchestration."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from subdomainenum.assessor import (
    assess,
    _run_passive,
    _run_active,
    _run_active_enum,
    _run_ffuf_fanout,
    _resolve_all,
)
from subdomainenum.models import EnumMode, EnumReport, ToolResult, Status, SubdomainResult, VhostResult


def _make_source(*fqdns: str, name: str = "subfinder", available: bool = True) -> ToolResult:
    return ToolResult(name=name, subdomains=list(fqdns), available=available)


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
            patch("subdomainenum.assessor.resolve_ips", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt")
        mock_passive.assert_not_called()
        mock_active.assert_called_once()

    def test_all_mode_runs_both(self) -> None:
        """In ALL mode, passive and active-enum helpers are both invoked
        (directly from assess, fused in a single outer executor).
        """
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]) as mock_passive,
            patch("subdomainenum.assessor._run_active_enum", return_value=[]) as mock_active_enum,
            patch(
                "subdomainenum.assessor._run_ffuf_fanout",
                return_value=(ToolResult(name="ffuf", mode=EnumMode.ACTIVE), []),
            ),
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        mock_passive.assert_called_once()
        mock_active_enum.assert_called_once()

    def test_auto_derives_url_from_resolved_ip(self) -> None:
        """When url is None and domain resolves, ffuf URLs are derived from all IPs."""
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]),
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=["1.2.3.4"]),
        ):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt", url=None)
        _, kwargs = mock_active.call_args
        assert kwargs["urls"] == ["http://1.2.3.4"]

    def test_skips_ffuf_when_domain_does_not_resolve(self) -> None:
        """When url is None and domain resolves to no IPs, urls is empty."""
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]),
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt", url=None)
        _, kwargs = mock_active.call_args
        assert kwargs["urls"] == []

    def test_explicit_url_not_overridden(self) -> None:
        """When url is explicitly provided, resolve_ips is not called."""
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]),
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips") as mock_resolve,
        ):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt", url="http://10.0.0.1")
        mock_resolve.assert_not_called()
        _, kwargs = mock_active.call_args
        assert kwargs["urls"] == ["http://10.0.0.1"]

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
            _make_source("sub.example.com", name="amass"),
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
        sources = [_make_source("sub.example.com", name="subfinder")]
        with (
            patch("subdomainenum.assessor._run_passive", return_value=sources),
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
        ):
            report = assess("example.com", mode=EnumMode.PASSIVE)
        assert any(s.name == "subfinder" for s in report.tools)

    def test_active_wordlist_required_raises(self) -> None:
        with pytest.raises(ValueError, match="wordlist"):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist=None)

    def test_all_mode_includes_passive_subdomain_ips(self) -> None:
        """In ALL mode, IPs from passive subdomains are added to the ffuf URL list."""
        passive_src = _make_source("sub.example.com", name="subfinder")
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[passive_src]),
            patch("subdomainenum.assessor._run_active_enum", return_value=[]),
            patch(
                "subdomainenum.assessor._run_ffuf_fanout",
                return_value=(ToolResult(name="ffuf", mode=EnumMode.ACTIVE), []),
            ) as mock_ffuf,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch(
                "subdomainenum.assessor.resolve_ips",
                side_effect=lambda fqdn, **_kw: ["1.2.3.4"] if fqdn == "example.com" else ["5.6.7.8"],
            ),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        _, kwargs = mock_ffuf.call_args
        assert "http://1.2.3.4" in kwargs["urls"]
        assert "http://5.6.7.8" in kwargs["urls"]

    def test_active_mode_only_uses_domain_ips(self) -> None:
        """In ACTIVE-only mode, only the target domain IPs are used (no passive subdomains)."""
        with (
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=["9.9.9.9"]),
        ):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt")
        _, kwargs = mock_active.call_args
        assert kwargs["urls"] == ["http://9.9.9.9"]

    def test_ipv6_addresses_bracketed_in_urls(self) -> None:
        """IPv6 addresses in the URL list are wrapped in brackets."""
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]),
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=["2606:2800::1"]),
        ):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt")
        _, kwargs = mock_active.call_args
        assert "http://[2606:2800::1]" in kwargs["urls"]

    def test_duplicate_ips_deduplicated_in_urls(self) -> None:
        """The same IP from multiple passive subdomains appears only once in urls."""
        passive_src = _make_source("a.example.com", "b.example.com", name="subfinder")
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[passive_src]),
            patch("subdomainenum.assessor._run_active_enum", return_value=[]),
            patch(
                "subdomainenum.assessor._run_ffuf_fanout",
                return_value=(ToolResult(name="ffuf", mode=EnumMode.ACTIVE), []),
            ) as mock_ffuf,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=["1.2.3.4"]),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        _, kwargs = mock_ffuf.call_args
        assert kwargs["urls"].count("http://1.2.3.4") == 1

    def test_multi_url_ffuf_deduplicates_vhost_results(self) -> None:
        """run_ffuf results across multiple URLs are deduplicated by vhost name."""
        from subdomainenum.models import VhostResult
        hit = VhostResult(vhost="admin.example.com", status_code=200, content_length=100)
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
            patch("subdomainenum.assessor.run_ffuf", return_value=[hit]),
        ):
            _, vhosts = _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                urls=["http://1.2.3.4", "http://5.6.7.8"],
                progress_cb=None,
            )
        # admin.example.com found by both URLs — must appear only once
        assert len(vhosts) == 1
        assert vhosts[0].vhost == "admin.example.com"


# ---------------------------------------------------------------------------
# _run_passive
# ---------------------------------------------------------------------------


class TestRunPassive:
    def test_returns_all_source_results(self) -> None:
        src = _make_source("sub.example.com")
        with (
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            results = _run_passive("example.com", progress_cb=None)
        assert len(results) == 5

    def test_progress_cb_called(self) -> None:
        calls: list[str] = []
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
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
            patch("subdomainenum.assessor.run_subfinder", side_effect=fake_subfinder),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            _run_passive(
                "example.com",
                progress_cb=None,
                debug_cb=lambda s, line: debug_calls.append((s, line)),
            )
        assert ("subfinder", "sub.example.com") in debug_calls

    def test_cmd_cb_lambda_invoked(self) -> None:
        """Cover the lambda body in _cmd_cb by having a mock call cmd_cb."""
        cmd_calls: list[tuple] = []

        def fake_subfinder(domain, *, cmd_cb=None, **kwargs):
            if cmd_cb:
                cmd_cb("subfinder -d example.com -silent")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_subfinder", side_effect=fake_subfinder),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            _run_passive(
                "example.com",
                progress_cb=None,
                cmd_cb=lambda s, c: cmd_calls.append((s, c)),
            )
        assert any(s == "subfinder" for s, _ in cmd_calls)

    def test_source_exception_captured(self) -> None:
        """Cover the exception branch: exception from a future is caught and stored."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_subfinder", side_effect=RuntimeError("boom")),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            results = _run_passive("example.com", progress_cb=None)
        error_sources = [r for r in results if r.available is False]
        assert len(error_sources) == 1
        assert "boom" in error_sources[0].error

    def test_finish_cb_called_on_completion(self) -> None:
        """finish_cb is called once per source with (name, None, False) on success."""
        finish_calls: list[tuple] = []
        src = _make_source("sub.example.com")
        with (
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            _run_passive(
                "example.com",
                progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
            )
        assert len(finish_calls) == 5
        assert all(err is None for _, err, _ in finish_calls)

    def test_finish_cb_called_on_error(self) -> None:
        """finish_cb is called with (name, error_str, False) when a source raises."""
        finish_calls: list[tuple] = []
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_subfinder", side_effect=RuntimeError("network error")),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            _run_passive(
                "example.com",
                progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
            )
        error_calls = [(n, e) for n, e, _ in finish_calls if e is not None]
        assert len(error_calls) == 1
        assert "network error" in error_calls[0][1]

    def test_passive_sources_have_mode_passive(self) -> None:
        """All results from _run_passive have mode=EnumMode.PASSIVE stamped on them."""
        src = _make_source("sub.example.com")
        with (
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            results = _run_passive("example.com", progress_cb=None)
        assert all(r.mode == EnumMode.PASSIVE for r in results)

    def test_exception_source_has_mode_passive(self) -> None:
        """Sources that raise exceptions still get mode=EnumMode.PASSIVE in the error ToolResult."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_subfinder", side_effect=RuntimeError("boom")),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            results = _run_passive("example.com", progress_cb=None)
        error_results = [r for r in results if r.available is False]
        assert len(error_results) == 1
        assert error_results[0].mode == EnumMode.PASSIVE

    def test_wordlist_forwarded_to_dnsrecon(self) -> None:
        """When a wordlist is supplied, _run_passive threads it into run_dnsrecon."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src) as mock_dnsrecon,
        ):
            _run_passive("example.com", progress_cb=None, wordlist="/tmp/snoop.txt")
        assert mock_dnsrecon.call_args.kwargs.get("wordlist") == "/tmp/snoop.txt"

    def test_wordlist_defaults_to_none_for_dnsrecon(self) -> None:
        """Omitting wordlist means dnsrecon's passive call receives wordlist=None."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src) as mock_dnsrecon,
        ):
            _run_passive("example.com", progress_cb=None)
        assert mock_dnsrecon.call_args.kwargs.get("wordlist") is None


# ---------------------------------------------------------------------------
# _run_active
# ---------------------------------------------------------------------------


class TestRunActive:
    def test_returns_sources_without_urls(self) -> None:
        """With overall_mode unset (ACTIVE-only path), the active pool contains
        amass + gobuster + dnsrecon (for AXFR / DNSSEC zone walk) plus the ffuf
        sentinel marked unavailable when no URLs are provided → 4 sources."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_ffuf") as mock_ffuf,
        ):
            sources, vhosts = _run_active("example.com", wordlist="/tmp/w.txt", urls=[], progress_cb=None)
        mock_ffuf.assert_not_called()
        assert len(sources) == 4
        ffuf_src = next(s for s in sources if s.name == "ffuf")
        assert ffuf_src.available is False

    def test_runs_ffuf_when_urls_provided(self) -> None:
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
            patch("subdomainenum.assessor.run_ffuf", return_value=[]) as mock_ffuf,
        ):
            sources, vhosts = _run_active(
                "example.com", wordlist="/tmp/w.txt", urls=["http://example.com"], progress_cb=None
            )
        mock_ffuf.assert_called_once()

    def test_progress_cb_called(self) -> None:
        calls: list[str] = []
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active("example.com", wordlist="/tmp/w.txt", urls=[], progress_cb=calls.append)
        assert len(calls) > 0

    def test_debug_cb_lambda_invoked(self) -> None:
        """Cover the lambda body in _line_cb by having a mock call line_cb."""
        debug_calls: list[tuple] = []

        def fake_gobuster(domain, *, wordlist, timeout=300, line_cb=None, **kwargs):
            if line_cb:
                line_cb("output line")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", side_effect=fake_gobuster),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                urls=[],
                progress_cb=None,
                debug_cb=lambda s, line: debug_calls.append((s, line)),
            )
        assert ("gobuster", "output line") in debug_calls

    def test_cmd_cb_lambda_invoked(self) -> None:
        """Cover the lambda body in _cmd_cb for active sources."""
        cmd_calls: list[tuple] = []

        def fake_gobuster(domain, *, wordlist, timeout=300, cmd_cb=None, **kwargs):
            if cmd_cb:
                cmd_cb("gobuster dns -d example.com -w /tmp/w.txt")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", side_effect=fake_gobuster),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                urls=[],
                progress_cb=None,
                cmd_cb=lambda s, c: cmd_calls.append((s, c)),
            )
        assert any(s == "gobuster" for s, _ in cmd_calls)

    def test_finish_cb_called(self) -> None:
        """finish_cb is called for each active source (amass, gobuster, dnsrecon, ffuf)
        in ACTIVE-only mode (overall_mode unset)."""
        finish_calls: list[tuple] = []
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                urls=[],
                progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
            )
        names = [n for n, _, _ in finish_calls]
        assert "amass" in names
        assert "gobuster" in names
        assert "dnsrecon" in names
        assert "ffuf" in names
        ffuf_err = next(err for name, err, _ in finish_calls if name == "ffuf")
        assert ffuf_err is not None  # skipped without urls

    def test_finish_cb_called_for_ffuf(self) -> None:
        """finish_cb is called for ffuf when urls are provided."""
        finish_calls: list[tuple] = []
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
            patch("subdomainenum.assessor.run_ffuf", return_value=[]),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                urls=["http://example.com"],
                progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
            )
        names = [n for n, _, _ in finish_calls]
        assert "ffuf" in names

    def test_amass_called_with_active_mode(self) -> None:
        """run_amass must be invoked with mode=EnumMode.ACTIVE in _run_active."""
        from subdomainenum.models import EnumMode
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src) as mock_amass,
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active("example.com", wordlist="/tmp/w.txt", urls=[], progress_cb=None)
        assert mock_amass.call_args.kwargs.get("mode") == EnumMode.ACTIVE

    def test_active_sources_have_mode_active(self) -> None:
        """All ToolResults returned by _run_active have mode=EnumMode.ACTIVE stamped."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            sources, _ = _run_active("example.com", wordlist="/tmp/w.txt", urls=[], progress_cb=None)
        assert all(s.mode == EnumMode.ACTIVE for s in sources)

    def test_ffuf_source_with_urls_has_mode_active(self) -> None:
        """ffuf ToolResult created when urls are provided has mode=EnumMode.ACTIVE."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
            patch("subdomainenum.assessor.run_ffuf", return_value=[]),
        ):
            sources, _ = _run_active(
                "example.com", wordlist="/tmp/w.txt", urls=["http://example.com"], progress_cb=None
            )
        ffuf_src = next(s for s in sources if s.name == "ffuf")
        assert ffuf_src.mode == EnumMode.ACTIVE

    def test_ffuf_source_without_urls_has_mode_active(self) -> None:
        """ffuf ToolResult created when urls is empty (skipped branch) has mode=EnumMode.ACTIVE."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            sources, _ = _run_active("example.com", wordlist="/tmp/w.txt", urls=[], progress_cb=None)
        ffuf_src = next(s for s in sources if s.name == "ffuf")
        assert ffuf_src.mode == EnumMode.ACTIVE


# ---------------------------------------------------------------------------
# _resolve_all
# ---------------------------------------------------------------------------


class TestResolveAll:
    def test_alive_when_ips_present(self) -> None:
        with patch("subdomainenum.assessor.resolve_ips", return_value=["1.2.3.4"]):
            results = _resolve_all(["sub.example.com"], {"sub.example.com": ["subfinder"]})
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


# ---------------------------------------------------------------------------
# Phase-aware callback keys (ALL mode)
# ---------------------------------------------------------------------------


class TestPhaseAwareKeys:
    """Verify that in ALL mode, shared tools get '<name> passive'/'<name> active' keys."""

    def _passive_finish_names(self, overall_mode: EnumMode | None) -> list[str]:
        """Run _run_passive and collect the source-name arguments passed to finish_cb."""
        finish_names: list[str] = []
        src = _make_source("sub.example.com")
        with (
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            _run_passive(
                "example.com",
                progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_names.append(name),
                overall_mode=overall_mode,
            )
        return finish_names

    def _active_finish_names(self, overall_mode: EnumMode | None) -> list[str]:
        """Run _run_active and collect the source-name arguments passed to finish_cb."""
        finish_names: list[str] = []
        src = _make_source("sub.example.com")
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                urls=[],
                progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_names.append(name),
                overall_mode=overall_mode,
            )
        return finish_names

    # --- passive phase ---

    def test_passive_all_mode_amass_key_is_suffixed(self) -> None:
        names = self._passive_finish_names(EnumMode.ALL)
        assert "amass passive" in names
        assert "amass" not in names

    def test_passive_all_mode_dnsrecon_key_is_suffixed(self) -> None:
        names = self._passive_finish_names(EnumMode.ALL)
        assert "dnsrecon passive+active" in names
        assert "dnsrecon passive" not in names
        assert "dnsrecon" not in names

    def test_passive_all_mode_other_tools_keep_plain_keys(self) -> None:
        names = self._passive_finish_names(EnumMode.ALL)
        assert "subfinder" in names
        assert "findomain" in names
        assert "assetfinder" in names

    def test_passive_passive_mode_plain_keys(self) -> None:
        """In PASSIVE-only mode no suffix is added."""
        names = self._passive_finish_names(EnumMode.PASSIVE)
        assert "amass" in names
        assert "dnsrecon" in names
        assert "amass passive" not in names
        assert "dnsrecon passive" not in names

    def test_passive_no_overall_mode_plain_keys(self) -> None:
        """Without overall_mode (None) no suffix is added."""
        names = self._passive_finish_names(None)
        assert "amass" in names
        assert "dnsrecon" in names

    # --- active phase ---

    def test_active_all_mode_amass_key_is_suffixed(self) -> None:
        names = self._active_finish_names(EnumMode.ALL)
        assert "amass active" in names
        assert "amass" not in names

    def test_active_all_mode_dnsrecon_absent_from_active_pool(self) -> None:
        """dnsrecon is delegated to the passive phase; no active key (with or
        without suffix) should appear in ALL mode's active finish_cb names."""
        names = self._active_finish_names(EnumMode.ALL)
        assert "dnsrecon active" not in names
        assert "dnsrecon" not in names

    def test_active_all_mode_other_tools_keep_plain_keys(self) -> None:
        names = self._active_finish_names(EnumMode.ALL)
        assert "gobuster" in names
        assert "ffuf" in names

    def test_active_active_mode_plain_keys(self) -> None:
        """In ACTIVE-only mode no suffix is added, and dnsrecon is present
        (it joins the active pool so AXFR/DNSSEC checks still run)."""
        names = self._active_finish_names(EnumMode.ACTIVE)
        assert "amass" in names
        assert "dnsrecon" in names
        assert "amass active" not in names
        assert "dnsrecon active" not in names

    def test_active_no_overall_mode_plain_keys(self) -> None:
        """Without overall_mode (None) no suffix is added, and dnsrecon is
        present in the active pool (same as ACTIVE-only mode)."""
        names = self._active_finish_names(None)
        assert "amass" in names
        assert "dnsrecon" in names
        assert "amass active" not in names
        assert "dnsrecon active" not in names

    # --- debug_cb key routing in ALL mode ---

    def test_passive_all_mode_debug_cb_uses_suffixed_key_for_amass(self) -> None:
        debug_calls: list[tuple] = []

        def fake_amass(domain, *, line_cb=None, **kwargs):
            if line_cb:
                line_cb("output line")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_subfinder", return_value=src),
            patch("subdomainenum.assessor.run_amass", side_effect=fake_amass),
            patch("subdomainenum.assessor.run_findomain", return_value=src),
            patch("subdomainenum.assessor.run_assetfinder", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
        ):
            _run_passive(
                "example.com",
                progress_cb=None,
                debug_cb=lambda s, line: debug_calls.append((s, line)),
                overall_mode=EnumMode.ALL,
            )
        assert ("amass passive", "output line") in debug_calls

    def test_active_all_mode_debug_cb_uses_suffixed_key_for_amass(self) -> None:
        debug_calls: list[tuple] = []

        def fake_amass(domain, *, mode=None, wordlist=None, line_cb=None, **kwargs):
            if line_cb:
                line_cb("output line")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", side_effect=fake_amass),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                urls=[],
                progress_cb=None,
                debug_cb=lambda s, line: debug_calls.append((s, line)),
                overall_mode=EnumMode.ALL,
            )
        assert ("amass active", "output line") in debug_calls

    # --- assess() wires overall_mode correctly ---

    def test_assess_passes_overall_mode_to_passive(self) -> None:
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]) as mock_passive,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.PASSIVE)
        _, kwargs = mock_passive.call_args
        assert kwargs.get("overall_mode") == EnumMode.PASSIVE

    def test_assess_passes_overall_mode_all_to_passive(self) -> None:
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]) as mock_passive,
            patch("subdomainenum.assessor._run_active", return_value=([], [])),
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        _, kwargs = mock_passive.call_args
        assert kwargs.get("overall_mode") == EnumMode.ALL

    def test_assess_passes_overall_mode_all_to_active(self) -> None:
        """In ALL mode, overall_mode is forwarded to _run_active_enum so that
        amass/dnsrecon debug keys get the 'active' suffix for phase disambiguation.
        """
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]),
            patch("subdomainenum.assessor._run_active_enum", return_value=[]) as mock_active_enum,
            patch(
                "subdomainenum.assessor._run_ffuf_fanout",
                return_value=(ToolResult(name="ffuf", mode=EnumMode.ACTIVE), []),
            ),
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        _, kwargs = mock_active_enum.call_args
        assert kwargs.get("overall_mode") == EnumMode.ALL

    def test_assess_passes_overall_mode_active_to_active(self) -> None:
        with (
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt")
        _, kwargs = mock_active.call_args
        assert kwargs.get("overall_mode") == EnumMode.ACTIVE


# ---------------------------------------------------------------------------
# Parallelism (Barrier-based concurrency proofs)
# ---------------------------------------------------------------------------


class TestActiveParallelism:
    """The non-ffuf active tools must run concurrently in _run_active_enum."""

    def test_active_tools_run_in_parallel(self) -> None:
        """With overall_mode unset, the pool is amass + gobuster + dnsrecon.
        All three reach a Barrier(3) together → proves concurrency."""
        import threading
        barrier = threading.Barrier(3, timeout=2.0)

        def fake_amass(domain, **kwargs):
            barrier.wait()
            return _make_source(name="amass")

        def fake_gobuster(domain, **kwargs):
            barrier.wait()
            return _make_source(name="gobuster")

        def fake_dnsrecon(domain, **kwargs):
            barrier.wait()
            return _make_source(name="dnsrecon")

        with (
            patch("subdomainenum.assessor.run_amass", side_effect=fake_amass),
            patch("subdomainenum.assessor.run_gobuster_dns", side_effect=fake_gobuster),
            patch("subdomainenum.assessor.run_dnsrecon", side_effect=fake_dnsrecon),
        ):
            tools = _run_active_enum("example.com", wordlist="/tmp/w.txt", progress_cb=None)

        # Barrier did not raise BrokenBarrierError → all 3 reached the barrier together.
        assert len(tools) == 3
        names = {t.name for t in tools}
        assert names == {"amass", "gobuster", "dnsrecon"}

    def test_all_mode_omits_dnsrecon_from_active_pool(self) -> None:
        """In ALL mode dnsrecon already runs passively, so _run_active_enum must
        NOT start a second dnsrecon invocation."""
        with (
            patch("subdomainenum.assessor.run_amass", return_value=_make_source(name="amass")),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=_make_source(name="gobuster")),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=_make_source(name="dnsrecon")) as mock_dnsrecon,
        ):
            tools = _run_active_enum(
                "example.com", wordlist="/tmp/w.txt",
                progress_cb=None, overall_mode=EnumMode.ALL,
            )
        mock_dnsrecon.assert_not_called()
        names = {t.name for t in tools}
        assert names == {"amass", "gobuster"}

    def test_active_enum_captures_unexpected_exception(self) -> None:
        """If a tool runner raises, the pool captures it as ToolResult(available=False)."""
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", side_effect=RuntimeError("boom")),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            tools = _run_active_enum("example.com", wordlist="/tmp/w.txt", progress_cb=None)
        error_tools = [t for t in tools if t.available is False]
        assert len(error_tools) == 1
        assert "boom" in (error_tools[0].error or "")
        assert error_tools[0].mode == EnumMode.ACTIVE

    def test_active_enum_finish_cb_error_invoked_on_exception(self) -> None:
        """finish_cb receives (name, error_str, False) when a runner raises."""
        finish_calls: list[tuple] = []
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", side_effect=RuntimeError("boom")),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active_enum(
                "example.com", wordlist="/tmp/w.txt", progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
            )
        errored = [(n, e) for n, e, _ in finish_calls if e is not None]
        assert len(errored) == 1
        assert "boom" in errored[0][1]


class TestFfufParallelism:
    """ffuf must run in parallel across URLs."""

    def test_ffuf_runs_urls_in_parallel(self) -> None:
        """Three URLs reach a Barrier(3) → all three ffuf workers are concurrent."""
        import threading
        barrier = threading.Barrier(3, timeout=2.0)

        def fake_ffuf(domain, **kwargs):
            barrier.wait()
            return []

        urls = ["http://1.1.1.1", "http://2.2.2.2", "http://3.3.3.3"]
        with patch("subdomainenum.assessor.run_ffuf", side_effect=fake_ffuf):
            tool, vhosts = _run_ffuf_fanout(
                "example.com", wordlist="/tmp/w.txt", urls=urls, progress_cb=None,
            )
        assert tool.name == "ffuf"
        assert tool.available is True
        assert vhosts == []

    def test_ffuf_fanout_deduplicates_vhosts_across_urls(self) -> None:
        """The same vhost found by multiple URL workers appears once in the result."""
        hit = VhostResult(vhost="admin.example.com", status_code=200, content_length=100)
        with patch("subdomainenum.assessor.run_ffuf", return_value=[hit]):
            tool, vhosts = _run_ffuf_fanout(
                "example.com", wordlist="/tmp/w.txt",
                urls=["http://1.2.3.4", "http://5.6.7.8"], progress_cb=None,
            )
        assert len(vhosts) == 1
        assert tool.subdomains == ["admin.example.com"]

    def test_ffuf_single_url_keeps_plain_key(self) -> None:
        """Single-URL fan-out uses 'ffuf' as the debug/finish key, not 'ffuf 1'."""
        finish_calls: list[tuple] = []
        with patch("subdomainenum.assessor.run_ffuf", return_value=[]):
            _run_ffuf_fanout(
                "example.com", wordlist="/tmp/w.txt", urls=["http://1.2.3.4"],
                progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
            )
        names = [n for n, _, _ in finish_calls]
        assert names == ["ffuf"]

    def test_ffuf_multi_url_keys_are_numbered(self) -> None:
        """Multi-URL fan-out uses 'ffuf 1' and 'ffuf 2' keys."""
        finish_calls: list[tuple] = []
        with patch("subdomainenum.assessor.run_ffuf", return_value=[]):
            _run_ffuf_fanout(
                "example.com", wordlist="/tmp/w.txt",
                urls=["http://1.1.1.1", "http://2.2.2.2"], progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
            )
        names = {n for n, _, _ in finish_calls}
        assert names == {"ffuf 1", "ffuf 2"}

    def test_ffuf_empty_urls_returns_unavailable_tool(self) -> None:
        """With no URLs, the aggregated ffuf ToolResult is marked unavailable."""
        finish_calls: list[tuple] = []
        tool, vhosts = _run_ffuf_fanout(
            "example.com", wordlist="/tmp/w.txt", urls=[],
            progress_cb=None,
            finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
        )
        assert tool.available is False
        assert tool.error == "no URL resolved"
        assert vhosts == []
        assert finish_calls == [("ffuf", "no URL resolved", False)]

    def test_ffuf_worker_exception_captured(self) -> None:
        """If one ffuf worker raises, other URLs still complete and finish_cb records error."""
        call_count = {"n": 0}
        finish_calls: list[tuple] = []

        def flaky_ffuf(domain, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("ffuf crashed")
            return []

        with patch("subdomainenum.assessor.run_ffuf", side_effect=flaky_ffuf):
            tool, vhosts = _run_ffuf_fanout(
                "example.com", wordlist="/tmp/w.txt",
                urls=["http://1.1.1.1", "http://2.2.2.2"], progress_cb=None,
                finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
            )
        errored = [(n, e) for n, e, _ in finish_calls if e is not None]
        assert len(errored) == 1
        assert "ffuf crashed" in errored[0][1]
        assert tool.name == "ffuf"

    def test_ffuf_progress_cb_invoked(self) -> None:
        """Covers the _cb lambda body inside _run_ffuf_fanout."""
        calls: list[str] = []
        with patch("subdomainenum.assessor.run_ffuf", return_value=[]):
            _run_ffuf_fanout(
                "example.com", wordlist="/tmp/w.txt", urls=["http://1.1.1.1"],
                progress_cb=calls.append,
            )
        assert any("ffuf" in m for m in calls)


class TestAllModePhaseFusion:
    """In ALL mode, _run_passive and _run_active_enum run concurrently in an outer pool."""

    def test_all_mode_fuses_phases(self) -> None:
        """Passive helpers (5) and active-enum helpers (2) all hit a Barrier(7) → fused.
        run_amass is called in both phases (2 hits) and run_dnsrecon only in passive (1 hit)."""
        import threading
        barrier = threading.Barrier(7, timeout=2.0)

        def make_fake(name):
            def _fake(*args, **kwargs):
                barrier.wait()
                return _make_source(name=name)
            return _fake

        with (
            patch("subdomainenum.assessor.run_subfinder", side_effect=make_fake("subfinder")),
            patch("subdomainenum.assessor.run_amass", side_effect=make_fake("amass")),
            patch("subdomainenum.assessor.run_findomain", side_effect=make_fake("findomain")),
            patch("subdomainenum.assessor.run_assetfinder", side_effect=make_fake("assetfinder")),
            patch("subdomainenum.assessor.run_dnsrecon", side_effect=make_fake("dnsrecon")),
            patch("subdomainenum.assessor.run_gobuster_dns", side_effect=make_fake("gobuster")),
            patch("subdomainenum.assessor._run_ffuf_fanout",
                  return_value=(ToolResult(name="ffuf", mode=EnumMode.ACTIVE), [])),
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=[]),
        ):
            report = assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")

        # Reaching the barrier proves concurrency. amass runs in both phases (2×);
        # dnsrecon only passively (1×); gobuster only actively (1×).
        tool_names = [t.name for t in report.tools]
        assert tool_names.count("amass") == 2  # passive + active
        assert tool_names.count("dnsrecon") == 1  # passive only
        assert "subfinder" in tool_names
        assert "gobuster" in tool_names


class TestResolveAllCache:
    """_resolve_all reuses pre_resolved IPs instead of calling resolve_ips again."""

    def test_cached_fqdn_uses_cached_ips(self) -> None:
        """A cached fqdn produces an ALIVE SubdomainResult without calling resolve_ips."""
        with patch("subdomainenum.assessor.resolve_ips") as mock_resolve:
            results = _resolve_all(
                ["a.example.com"],
                {"a.example.com": ["subfinder"]},
                pre_resolved={"a.example.com": ["1.2.3.4"]},
            )
        mock_resolve.assert_not_called()
        assert results[0].ip_addresses == ["1.2.3.4"]
        assert results[0].status == Status.ALIVE
        assert results[0].alive is True

    def test_cached_empty_list_treated_as_dead(self) -> None:
        """A cached empty list means 'resolved, no IPs' — DEAD without a live DNS call."""
        with patch("subdomainenum.assessor.resolve_ips") as mock_resolve:
            results = _resolve_all(
                ["dead.example.com"],
                {},
                pre_resolved={"dead.example.com": []},
            )
        mock_resolve.assert_not_called()
        assert results[0].status == Status.DEAD
        assert results[0].alive is False

    def test_uncached_fqdn_falls_through_to_live_resolution(self) -> None:
        """An fqdn absent from the cache still triggers a live resolve_ips call."""
        with patch("subdomainenum.assessor.resolve_ips", return_value=["9.9.9.9"]) as mock_resolve:
            results = _resolve_all(
                ["a.example.com", "b.example.com"],
                {},
                pre_resolved={"a.example.com": ["1.2.3.4"]},
            )
        # resolve_ips called exactly once (for "b.example.com")
        assert mock_resolve.call_count == 1
        by_fqdn = {r.fqdn: r for r in results}
        assert by_fqdn["a.example.com"].ip_addresses == ["1.2.3.4"]
        assert by_fqdn["b.example.com"].ip_addresses == ["9.9.9.9"]

    def test_none_pre_resolved_behaves_as_before(self) -> None:
        """Omitting pre_resolved matches the pre-cache behaviour (backwards compatibility)."""
        with patch("subdomainenum.assessor.resolve_ips", return_value=["1.2.3.4"]):
            results = _resolve_all(["sub.example.com"], {})
        assert results[0].ip_addresses == ["1.2.3.4"]

    def test_empty_fqdns_with_nonempty_cache(self) -> None:
        """Empty fqdn list + populated cache still returns empty results without crashing."""
        results = _resolve_all([], {}, pre_resolved={"ignored.example.com": ["1.2.3.4"]})
        assert results == []


class TestComputeFfufUrlsFallback:
    """_compute_ffuf_urls without a StreamingResolver falls back to a local pool."""

    def test_fallback_resolves_via_local_pool(self) -> None:
        from subdomainenum.assessor import _compute_ffuf_urls
        with patch(
            "subdomainenum.assessor.resolve_ips",
            side_effect=lambda f: ["1.2.3.4"] if f == "example.com" else ["5.6.7.8"],
        ):
            urls, cache = _compute_ffuf_urls(
                "example.com", url=None,
                passive_fqdns=["sub.example.com"],
                resolver=None,
            )
        assert "http://1.2.3.4" in urls
        assert "http://5.6.7.8" in urls
        assert cache["example.com"] == ["1.2.3.4"]
        assert cache["sub.example.com"] == ["5.6.7.8"]

    def test_explicit_url_skips_dns_entirely(self) -> None:
        from subdomainenum.assessor import _compute_ffuf_urls
        with patch("subdomainenum.assessor.resolve_ips") as mock_resolve:
            urls, cache = _compute_ffuf_urls(
                "example.com", url="http://10.0.0.1",
                passive_fqdns=["sub.example.com"],
                resolver=None,
            )
        mock_resolve.assert_not_called()
        assert urls == ["http://10.0.0.1"]
        assert cache == {}
