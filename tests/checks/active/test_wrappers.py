"""Tests for active tool wrappers (subfinder, amass, findomain, assetfinder,
dnsrecon, gobuster_dns, wfuzz)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from subdomainenum.checks.active.amass import run_amass
from subdomainenum.checks.active.assetfinder import run_assetfinder
from subdomainenum.checks.active.dnsrecon import run_dnsrecon
from subdomainenum.checks.active.findomain import run_findomain
from subdomainenum.checks.active.gobuster_dns import run_gobuster_dns
from subdomainenum.checks.active.subfinder import run_subfinder
from subdomainenum.checks.active.wfuzz import run_wfuzz
from subdomainenum.models import SourceResult, VhostResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_run_tool(output: list[str]) -> patch:
    return patch("subdomainenum.checks.active.tool_runner.run_tool", return_value=output)


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------


class TestRunSubfinder:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.subfinder.run_tool", return_value=["sub.example.com"]):
            result = run_subfinder("example.com", passive=True)
        assert isinstance(result, SourceResult)
        assert result.name == "subfinder"

    def test_passive_flag_true(self) -> None:
        with patch("subdomainenum.checks.active.subfinder.run_tool", return_value=[]) as mock:
            run_subfinder("example.com", passive=True)
            cmd = mock.call_args[0][0]
        assert "-passive" in cmd or "--passive" in cmd

    def test_tool_missing_sets_available_false(self) -> None:
        with patch(
            "subdomainenum.checks.active.subfinder.run_tool",
            side_effect=RuntimeError("subfinder not found"),
        ):
            result = run_subfinder("example.com", passive=True)
        assert result.available is False
        assert result.error is not None

    def test_parses_subdomains(self) -> None:
        with patch(
            "subdomainenum.checks.active.subfinder.run_tool",
            return_value=["a.example.com", "b.example.com"],
        ):
            result = run_subfinder("example.com", passive=True)
        assert "a.example.com" in result.subdomains


# ---------------------------------------------------------------------------
# amass
# ---------------------------------------------------------------------------


class TestRunAmass:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.amass.run_tool", return_value=[]):
            result = run_amass("example.com", passive=True)
        assert isinstance(result, SourceResult)
        assert result.name == "amass"

    def test_passive_flag(self) -> None:
        with patch("subdomainenum.checks.active.amass.run_tool", return_value=[]) as mock:
            run_amass("example.com", passive=True)
            cmd = mock.call_args[0][0]
        assert "enum" in cmd
        assert "-passive" in cmd

    def test_active_flag_absent_in_passive_mode(self) -> None:
        with patch("subdomainenum.checks.active.amass.run_tool", return_value=[]) as mock:
            run_amass("example.com", passive=False)
            cmd = mock.call_args[0][0]
        assert "-passive" not in cmd

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.checks.active.amass.run_tool",
            side_effect=RuntimeError("amass not found"),
        ):
            result = run_amass("example.com", passive=True)
        assert result.available is False


# ---------------------------------------------------------------------------
# findomain
# ---------------------------------------------------------------------------


class TestRunFindomain:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.findomain.run_tool", return_value=[]):
            result = run_findomain("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "findomain"

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.checks.active.findomain.run_tool",
            side_effect=RuntimeError("findomain not found"),
        ):
            result = run_findomain("example.com")
        assert result.available is False


# ---------------------------------------------------------------------------
# assetfinder
# ---------------------------------------------------------------------------


class TestRunAssetfinder:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.assetfinder.run_tool", return_value=[]):
            result = run_assetfinder("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "assetfinder"

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.checks.active.assetfinder.run_tool",
            side_effect=RuntimeError("assetfinder not found"),
        ):
            result = run_assetfinder("example.com")
        assert result.available is False


# ---------------------------------------------------------------------------
# dnsrecon
# ---------------------------------------------------------------------------


class TestRunDnsrecon:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.dnsrecon.run_tool", return_value=[]):
            result = run_dnsrecon("example.com", wordlist="/tmp/words.txt")
        assert isinstance(result, SourceResult)
        assert result.name == "dnsrecon"

    def test_wordlist_in_command(self) -> None:
        with patch("subdomainenum.checks.active.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", wordlist="/tmp/subdomains.txt")
            cmd = mock.call_args[0][0]
        assert "/tmp/subdomains.txt" in cmd

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.checks.active.dnsrecon.run_tool",
            side_effect=RuntimeError("dnsrecon not found"),
        ):
            result = run_dnsrecon("example.com", wordlist="/tmp/w.txt")
        assert result.available is False

    def test_parses_output_lines(self) -> None:
        output = ["[*] A sub.example.com 1.2.3.4"]
        with patch("subdomainenum.checks.active.dnsrecon.run_tool", return_value=output):
            result = run_dnsrecon("example.com", wordlist="/tmp/w.txt")
        assert "sub.example.com" in result.subdomains


# ---------------------------------------------------------------------------
# gobuster_dns
# ---------------------------------------------------------------------------


class TestRunGobusterDns:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.gobuster_dns.run_tool", return_value=[]):
            result = run_gobuster_dns("example.com", wordlist="/tmp/words.txt")
        assert isinstance(result, SourceResult)
        assert result.name == "gobuster"

    def test_wordlist_in_command(self) -> None:
        with patch("subdomainenum.checks.active.gobuster_dns.run_tool", return_value=[]) as mock:
            run_gobuster_dns("example.com", wordlist="/tmp/dns.txt")
            cmd = mock.call_args[0][0]
        assert "/tmp/dns.txt" in cmd

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.checks.active.gobuster_dns.run_tool",
            side_effect=RuntimeError("gobuster not found"),
        ):
            result = run_gobuster_dns("example.com", wordlist="/tmp/w.txt")
        assert result.available is False

    def test_parses_found_lines(self) -> None:
        output = ["Found: sub.example.com"]
        with patch("subdomainenum.checks.active.gobuster_dns.run_tool", return_value=output):
            result = run_gobuster_dns("example.com", wordlist="/tmp/w.txt")
        assert "sub.example.com" in result.subdomains


# ---------------------------------------------------------------------------
# wfuzz (vhost fuzzing)
# ---------------------------------------------------------------------------


class TestRunWfuzz:
    def test_returns_list_of_vhost_results(self) -> None:
        raw_output = [
            '000000001:   200        42 L      102 W      1024 Ch     "admin"',
            '000000002:   404        5 L       12 W       200 Ch     "nope"',
        ]
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=raw_output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        assert isinstance(results, list)

    def test_filters_404_by_default(self) -> None:
        raw_output = [
            '000000001:   200        42 L      102 W      1024 Ch     "admin"',
            '000000002:   404        5 L       12 W       200 Ch     "nope"',
        ]
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=raw_output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        vhosts = [r.vhost for r in results]
        assert not any("nope" in v for v in vhosts)

    def test_returns_vhost_result_objects(self) -> None:
        raw_output = ['000000001:   200        42 L      102 W      1024 Ch     "admin"']
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=raw_output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        if results:
            assert isinstance(results[0], VhostResult)

    def test_tool_missing_returns_empty_list(self) -> None:
        with patch(
            "subdomainenum.checks.active.wfuzz.run_tool",
            side_effect=RuntimeError("wfuzz not found"),
        ):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        assert results == []

    def test_wordlist_in_command(self) -> None:
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=[]) as mock:
            run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/vhosts.txt")
            cmd = mock.call_args[0][0]
        assert "/tmp/vhosts.txt" in cmd

    def test_skips_non_matching_lines(self) -> None:
        """Cover line 67: `continue` when regex does not match."""
        output = [
            "This is a header line with no wfuzz pattern",
            '000000001:   200        42 L      102 W      1024 Ch     "admin"',
        ]
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        assert len(results) == 1
