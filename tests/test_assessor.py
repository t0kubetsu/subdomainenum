"""Tests for subdomainenum.assessor – main orchestration."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from subdomainenum.assessor import assess, _run_passive, _run_active, _resolve_all
from subdomainenum.models import EnumMode, EnumReport, ToolResult, Status, SubdomainResult


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
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]) as mock_passive,
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        mock_passive.assert_called_once()
        mock_active.assert_called_once()

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
        """In ALL mode, IPs from passive subdomains are added to the URL list."""
        passive_src = _make_source("sub.example.com", name="subfinder")
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[passive_src]),
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch(
                "subdomainenum.assessor.resolve_ips",
                side_effect=lambda fqdn, **_kw: ["1.2.3.4"] if fqdn == "example.com" else ["5.6.7.8"],
            ),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        _, kwargs = mock_active.call_args
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
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=["1.2.3.4"]),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        _, kwargs = mock_active.call_args
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


# ---------------------------------------------------------------------------
# _run_active
# ---------------------------------------------------------------------------


class TestRunActive:
    def test_returns_sources_without_urls(self) -> None:
        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", return_value=src),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
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

        def fake_dnsrecon(domain, *, wordlist, timeout=300, line_cb=None, **kwargs):
            if line_cb:
                line_cb("output line")
            return _make_source()

        src = _make_source()
        with (
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", side_effect=fake_dnsrecon),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                urls=[],
                progress_cb=None,
                debug_cb=lambda s, line: debug_calls.append((s, line)),
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
            patch("subdomainenum.assessor.run_amass", return_value=src),
            patch("subdomainenum.assessor.run_dnsrecon", side_effect=fake_dnsrecon),
            patch("subdomainenum.assessor.run_gobuster_dns", return_value=src),
        ):
            _run_active(
                "example.com",
                wordlist="/tmp/w.txt",
                urls=[],
                progress_cb=None,
                cmd_cb=lambda s, c: cmd_calls.append((s, c)),
            )
        assert any(s == "dnsrecon" for s, _ in cmd_calls)

    def test_finish_cb_called(self) -> None:
        """finish_cb is called for each active source with (name, error_or_none, timed_out)."""
        finish_calls: list[tuple] = []
        src = _make_source()
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
                finish_cb=lambda name, err, timed_out: finish_calls.append((name, err, timed_out)),
            )
        names = [n for n, _, _ in finish_calls]
        assert "amass" in names
        assert "dnsrecon" in names
        assert "gobuster" in names
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
        assert "dnsrecon passive" in names
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

    def test_active_all_mode_dnsrecon_key_is_suffixed(self) -> None:
        names = self._active_finish_names(EnumMode.ALL)
        assert "dnsrecon active" in names
        assert "dnsrecon" not in names

    def test_active_all_mode_other_tools_keep_plain_keys(self) -> None:
        names = self._active_finish_names(EnumMode.ALL)
        assert "gobuster" in names
        assert "ffuf" in names

    def test_active_active_mode_plain_keys(self) -> None:
        """In ACTIVE-only mode no suffix is added."""
        names = self._active_finish_names(EnumMode.ACTIVE)
        assert "amass" in names
        assert "dnsrecon" in names
        assert "amass active" not in names
        assert "dnsrecon active" not in names

    def test_active_no_overall_mode_plain_keys(self) -> None:
        """Without overall_mode (None) no suffix is added."""
        names = self._active_finish_names(None)
        assert "amass" in names
        assert "dnsrecon" in names

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
        with (
            patch("subdomainenum.assessor._run_passive", return_value=[]),
            patch("subdomainenum.assessor._run_active", return_value=([], [])) as mock_active,
            patch("subdomainenum.assessor._resolve_all", return_value=[]),
            patch("subdomainenum.assessor.resolve_ips", return_value=[]),
        ):
            assess("example.com", mode=EnumMode.ALL, wordlist="/tmp/w.txt")
        _, kwargs = mock_active.call_args
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
