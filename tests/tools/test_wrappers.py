"""Tests for active tool wrappers (subfinder, amass, findomain, assetfinder,
dnsrecon, gobuster_dns, wfuzz)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from subdomainenum.tools.amass import run_amass
from subdomainenum.tools.assetfinder import run_assetfinder
from subdomainenum.tools.dnsrecon import run_dnsrecon
from subdomainenum.tools.findomain import run_findomain
from subdomainenum.tools.gobuster_dns import run_gobuster_dns
from subdomainenum.tools.subfinder import run_subfinder
from subdomainenum.tools.wfuzz import run_wfuzz
from subdomainenum.models import EnumMode, SourceResult, VhostResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_run_tool(output: list[str]) -> patch:
    return patch("subdomainenum.tools.tool_runner.run_tool", return_value=output)


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------


class TestRunSubfinder:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.subfinder.run_tool", return_value=["sub.example.com"]):
            result = run_subfinder("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "subfinder"

    def test_command_contains_domain_and_silent(self) -> None:
        with patch("subdomainenum.tools.subfinder.run_tool", return_value=[]) as mock:
            run_subfinder("example.com")
            cmd = mock.call_args[0][0]
        assert "example.com" in cmd
        assert "-silent" in cmd
        assert "-passive" not in cmd

    def test_tool_missing_sets_available_false(self) -> None:
        with patch(
            "subdomainenum.tools.subfinder.run_tool",
            side_effect=RuntimeError("subfinder not found"),
        ):
            result = run_subfinder("example.com")
        assert result.available is False
        assert result.error is not None

    def test_parses_subdomains(self) -> None:
        with patch(
            "subdomainenum.tools.subfinder.run_tool",
            return_value=["a.example.com", "b.example.com"],
        ):
            result = run_subfinder("example.com")
        assert "a.example.com" in result.subdomains

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.tools.subfinder.run_tool", return_value=[]) as mock:
            run_subfinder("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# amass
# ---------------------------------------------------------------------------


class TestRunAmass:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.amass.run_tool", return_value=[]):
            result = run_amass("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "amass"

    def test_command_contains_enum_and_domain(self) -> None:
        with patch("subdomainenum.tools.amass.run_tool", return_value=[]) as mock:
            run_amass("example.com")
            cmd = mock.call_args[0][0]
        assert "enum" in cmd
        assert "example.com" in cmd
        # -passive is deprecated; amass passive is the default
        assert "-passive" not in cmd

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.tools.amass.run_tool",
            side_effect=RuntimeError("amass not found"),
        ):
            result = run_amass("example.com")
        assert result.available is False

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.tools.amass.run_tool", return_value=[]) as mock:
            run_amass("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# findomain
# ---------------------------------------------------------------------------


class TestRunFindomain:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.findomain.run_tool", return_value=[]):
            result = run_findomain("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "findomain"

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.tools.findomain.run_tool",
            side_effect=RuntimeError("findomain not found"),
        ):
            result = run_findomain("example.com")
        assert result.available is False

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.tools.findomain.run_tool", return_value=[]) as mock:
            run_findomain("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# assetfinder
# ---------------------------------------------------------------------------


class TestRunAssetfinder:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.assetfinder.run_tool", return_value=[]):
            result = run_assetfinder("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "assetfinder"

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.tools.assetfinder.run_tool",
            side_effect=RuntimeError("assetfinder not found"),
        ):
            result = run_assetfinder("example.com")
        assert result.available is False

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.tools.assetfinder.run_tool", return_value=[]) as mock:
            run_assetfinder("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# dnsrecon
# ---------------------------------------------------------------------------


class TestRunDnsrecon:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]):
            result = run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
        assert isinstance(result, SourceResult)
        assert result.name == "dnsrecon"

    def test_single_invocation(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
        assert mock.call_count == 1

    def test_all_mode_uses_std_srv_and_brt_types(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "std" in type_val
        assert "srv" in type_val
        assert "brt" in type_val

    def test_all_mode_includes_passive_and_active_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        for flag in ("-a", "-b", "-y", "-k", "-z"):
            assert flag in cmd, f"expected {flag} in command"

    def test_all_mode_wordlist_in_command(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/subdomains.txt")
            cmd = mock.call_args[0][0]
        assert "-D" in cmd
        assert "/tmp/subdomains.txt" in cmd

    def test_passive_mode_uses_std_and_srv_types(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "std" in type_val
        assert "srv" in type_val
        assert "brt" not in type_val

    def test_passive_mode_includes_passive_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        for flag in ("-b", "-y", "-k"):
            assert flag in cmd, f"expected {flag} in passive command"

    def test_passive_mode_excludes_active_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "-a" not in cmd
        assert "-z" not in cmd
        assert "-D" not in cmd

    def test_active_mode_uses_brt_type(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "brt" in type_val
        assert "std" not in type_val

    def test_active_mode_includes_active_flags_and_wordlist(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-a" in cmd
        assert "-z" in cmd
        assert "-D" in cmd
        assert "/tmp/words.txt" in cmd

    def test_active_mode_excludes_passive_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-b" not in cmd
        assert "-y" not in cmd
        assert "-k" not in cmd

    def test_tool_missing_sets_available_false(self) -> None:
        with patch(
            "subdomainenum.tools.dnsrecon.run_tool",
            side_effect=RuntimeError("dnsrecon not found"),
        ):
            result = run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert result.available is False

    def test_parses_logging_format_output(self) -> None:
        """dnsrecon writes via Python logging (to stderr); parse the timestamped format."""
        output = ["2026-04-13T11:10:38.863437-0400 INFO      A sub.example.com 1.2.3.4"]
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=output):
            result = run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt")
        assert "sub.example.com" in result.subdomains

    def test_parses_cname_logging_format(self) -> None:
        """CNAME lines in logging format are also parsed correctly."""
        output = ["2026-04-13T11:10:40.252299-0400 INFO      CNAME cr.example.com alias.example.com"]
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=output):
            result = run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt")
        assert "cr.example.com" in result.subdomains

    def test_parses_output_lines(self) -> None:
        output = ["[*] A sub.example.com 1.2.3.4"]
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=output):
            result = run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert "sub.example.com" in result.subdomains

    def test_deduplicates_subdomains(self) -> None:
        output = [
            "[*] A dup.example.com 1.1.1.1",
            "[*] AAAA dup.example.com ::1",
        ]
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=output):
            result = run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert result.subdomains.count("dup.example.com") == 1

    def test_uses_capture_stderr(self) -> None:
        """dnsrecon must capture stderr because it logs via Python logging module."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert mock.call_args.kwargs.get("capture_stderr") is True

    def test_uses_ignore_returncode(self) -> None:
        """dnsrecon must ignore non-zero exit codes (AXFR refusal etc.)."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert mock.call_args.kwargs.get("ignore_returncode") is True

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# gobuster_dns
# ---------------------------------------------------------------------------


class TestRunGobusterDns:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=[]):
            result = run_gobuster_dns("example.com", wordlist="/tmp/words.txt")
        assert isinstance(result, SourceResult)
        assert result.name == "gobuster"

    def test_wordlist_in_command(self) -> None:
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=[]) as mock:
            run_gobuster_dns("example.com", wordlist="/tmp/dns.txt")
            cmd = mock.call_args[0][0]
        assert "/tmp/dns.txt" in cmd

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.tools.gobuster_dns.run_tool",
            side_effect=RuntimeError("gobuster not found"),
        ):
            result = run_gobuster_dns("example.com", wordlist="/tmp/w.txt")
        assert result.available is False

    def test_parses_found_lines(self) -> None:
        output = ["Found: sub.example.com"]
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=output):
            result = run_gobuster_dns("example.com", wordlist="/tmp/w.txt")
        assert "sub.example.com" in result.subdomains

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=[]) as mock:
            run_gobuster_dns("example.com", wordlist="/tmp/w.txt", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# wfuzz (vhost fuzzing)
# ---------------------------------------------------------------------------


class TestRunWfuzz:
    def test_returns_list_of_vhost_results(self) -> None:
        raw_output = [
            '000000001:   200        42 L      102 W      1024 Ch     "admin"',
            '000000002:   404        5 L       12 W       200 Ch     "nope"',
        ]
        with patch("subdomainenum.tools.wfuzz.run_tool", return_value=raw_output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        assert isinstance(results, list)

    def test_filters_404_by_default(self) -> None:
        raw_output = [
            '000000001:   200        42 L      102 W      1024 Ch     "admin"',
            '000000002:   404        5 L       12 W       200 Ch     "nope"',
        ]
        with patch("subdomainenum.tools.wfuzz.run_tool", return_value=raw_output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        vhosts = [r.vhost for r in results]
        assert not any("nope" in v for v in vhosts)

    def test_returns_vhost_result_objects(self) -> None:
        raw_output = ['000000001:   200        42 L      102 W      1024 Ch     "admin"']
        with patch("subdomainenum.tools.wfuzz.run_tool", return_value=raw_output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        if results:
            assert isinstance(results[0], VhostResult)

    def test_tool_missing_returns_empty_list(self) -> None:
        with patch(
            "subdomainenum.tools.wfuzz.run_tool",
            side_effect=RuntimeError("wfuzz not found"),
        ):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        assert results == []

    def test_wordlist_in_command(self) -> None:
        with patch("subdomainenum.tools.wfuzz.run_tool", return_value=[]) as mock:
            run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/vhosts.txt")
            cmd = mock.call_args[0][0]
        assert "/tmp/vhosts.txt" in cmd

    def test_skips_non_matching_lines(self) -> None:
        """Cover line 67: `continue` when regex does not match."""
        output = [
            "This is a header line with no wfuzz pattern",
            '000000001:   200        42 L      102 W      1024 Ch     "admin"',
        ]
        with patch("subdomainenum.tools.wfuzz.run_tool", return_value=output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        assert len(results) == 1

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.tools.wfuzz.run_tool", return_value=[]) as mock:
            run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb
