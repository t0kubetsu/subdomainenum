"""Tests for active tool wrappers (subfinder, amass, findomain, assetfinder,
dnsrecon, gobuster_dns, ffuf)."""

from __future__ import annotations

from unittest.mock import patch

import pytest


from subdomainenum.models import EnumMode, ToolResult, VhostResult
from subdomainenum.tools.amass import _parse_amass_output, run_amass
from subdomainenum.tools.assetfinder import run_assetfinder
from subdomainenum.tools.dnsrecon import run_dnsrecon
from subdomainenum.tools.findomain import run_findomain
from subdomainenum.tools.gobuster_dns import run_gobuster_dns
from subdomainenum.tools.subfinder import run_subfinder
from subdomainenum.tools.ffuf import _parse_ffuf_line, run_ffuf


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_run_tool(output: list[str]) -> patch:
    return patch("subdomainenum.tools.tool_runner.run_tool", return_value=(output, False))


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------


class TestRunSubfinder:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.subfinder.run_tool", return_value=(["sub.example.com"], False)):
            result = run_subfinder("example.com")
        assert isinstance(result, ToolResult)
        assert result.name == "subfinder"

    def test_command_contains_domain_and_silent(self) -> None:
        with patch("subdomainenum.tools.subfinder.run_tool", return_value=([], False)) as mock:
            run_subfinder("example.com")
            cmd = mock.call_args[0][0]
        assert "example.com" in cmd
        assert "-silent" in cmd
        assert "-all" in cmd
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
            return_value=(["a.example.com", "b.example.com"], False),
        ):
            result = run_subfinder("example.com")
        assert "a.example.com" in result.subdomains

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        def cb(cmd: str) -> None:
            pass
        with patch("subdomainenum.tools.subfinder.run_tool", return_value=([], False)) as mock:
            run_subfinder("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb

    def test_timed_out_sets_timed_out_flag(self) -> None:
        with patch(
            "subdomainenum.tools.subfinder.run_tool",
            return_value=(["partial.example.com"], True),
        ):
            result = run_subfinder("example.com")
        assert result.timed_out is True

    def test_normal_completion_timed_out_false(self) -> None:
        with patch(
            "subdomainenum.tools.subfinder.run_tool",
            return_value=(["sub.example.com"], False),
        ):
            result = run_subfinder("example.com")
        assert result.timed_out is False


# ---------------------------------------------------------------------------
# amass
# ---------------------------------------------------------------------------


class TestParseAmassOutput:
    """Unit tests for _parse_amass_output — amass v4 graph format parser."""

    def test_extracts_subdomain_fqdn(self) -> None:
        lines = ["sub.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)"]
        assert _parse_amass_output(lines, "example.com") == ["sub.example.com"]

    def test_extracts_apex_domain(self) -> None:
        lines = ["example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)"]
        assert _parse_amass_output(lines, "example.com") == ["example.com"]

    def test_filters_out_external_fqdns(self) -> None:
        lines = [
            "example.com (FQDN) --> ns_record --> ns1.eurodns.com (FQDN)",
            "ns1.eurodns.com (FQDN) --> a_record --> 199.167.66.107 (IPAddress)",
        ]
        result = _parse_amass_output(lines, "example.com")
        assert result == ["example.com"]
        assert "ns1.eurodns.com" not in result

    def test_deduplicates_fqdns(self) -> None:
        lines = [
            "sub.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)",
            "sub.example.com (FQDN) --> aaaa_record --> ::1 (IPAddress)",
        ]
        result = _parse_amass_output(lines, "example.com")
        assert result.count("sub.example.com") == 1

    def test_skips_non_fqdn_lines(self) -> None:
        lines = [
            "31.22.120.0/21 (Netblock) --> contains --> 1.2.3.4 (IPAddress)",
            "12345 (ASN) --> managed_by --> ACME (RIROrganization)",
            "[*] Some dnsrecon-style line",
        ]
        assert _parse_amass_output(lines, "example.com") == []

    def test_empty_input(self) -> None:
        assert _parse_amass_output([], "example.com") == []

    def test_case_insensitive_normalisation(self) -> None:
        lines = ["Sub.Example.COM (FQDN) --> a_record --> 1.2.3.4 (IPAddress)"]
        result = _parse_amass_output(lines, "example.com")
        assert result == ["sub.example.com"]

    def test_multiple_subdomains_preserved_in_order(self) -> None:
        lines = [
            "a.example.com (FQDN) --> a_record --> 1.1.1.1 (IPAddress)",
            "b.example.com (FQDN) --> a_record --> 2.2.2.2 (IPAddress)",
        ]
        result = _parse_amass_output(lines, "example.com")
        assert result == ["a.example.com", "b.example.com"]

    def test_strips_ansi_codes(self) -> None:
        """ANSI escape sequences in amass output must not corrupt the FQDN capture."""
        lines = ["\x1b[32msub.example.com\x1b[0m (FQDN) --> a_record --> 1.2.3.4 (IPAddress)"]
        result = _parse_amass_output(lines, "example.com")
        assert result == ["sub.example.com"]


class TestRunAmass:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)):
            result = run_amass("example.com")
        assert isinstance(result, ToolResult)
        assert result.name == "amass"

    def test_command_contains_enum_and_domain(self) -> None:
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
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

    def test_parses_graph_format_output(self) -> None:
        """run_amass must parse amass v4 graph-format output, not store raw lines."""
        graph_lines = [
            "sub.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)",
            "example.com (FQDN) --> ns_record --> ns1.eurodns.com (FQDN)",
            "ns1.eurodns.com (FQDN) --> a_record --> 5.6.7.8 (IPAddress)",
        ]
        with patch("subdomainenum.tools.amass.run_tool", return_value=(graph_lines, False)):
            result = run_amass("example.com")
        assert "sub.example.com" in result.subdomains
        assert "example.com" in result.subdomains
        assert "ns1.eurodns.com" not in result.subdomains

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        def cb(cmd: str) -> None:
            pass
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb

    def test_ignore_returncode_is_true(self) -> None:
        """amass exits non-zero on partial failures; results must still be parsed."""
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com")
        assert mock.call_args.kwargs.get("ignore_returncode") is True

    def test_no_active_flag_in_passive_mode(self) -> None:
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "-active" not in cmd

    def test_active_flag_in_active_mode(self) -> None:
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com", mode=EnumMode.ACTIVE)
            cmd = mock.call_args[0][0]
        assert "-active" in cmd

    def test_active_flag_in_all_mode(self) -> None:
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com", mode=EnumMode.ALL)
            cmd = mock.call_args[0][0]
        assert "-active" in cmd

    def test_timed_out_sets_timed_out_flag(self) -> None:
        graph_lines = ["partial.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)"]
        with patch("subdomainenum.tools.amass.run_tool", return_value=(graph_lines, True)):
            result = run_amass("example.com")
        assert result.timed_out is True

    def test_normal_completion_timed_out_false(self) -> None:
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)):
            result = run_amass("example.com")
        assert result.timed_out is False

    def test_no_brute_flag_without_wordlist(self) -> None:
        """No wordlist → -brute and -w must not appear in the command."""
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com", mode=EnumMode.ACTIVE)
            cmd = mock.call_args[0][0]
        assert "-brute" not in cmd
        assert "-w" not in cmd

    def test_idle_timeout_forwarded_to_run_tool(self) -> None:
        """idle_timeout kwarg is forwarded to run_tool."""
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com", idle_timeout=90)
        assert mock.call_args.kwargs.get("idle_timeout") == 90


# ---------------------------------------------------------------------------
# findomain
# ---------------------------------------------------------------------------


class TestRunFindomain:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.findomain.run_tool", return_value=([], False)):
            result = run_findomain("example.com")
        assert isinstance(result, ToolResult)
        assert result.name == "findomain"

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.tools.findomain.run_tool",
            side_effect=RuntimeError("findomain not found"),
        ):
            result = run_findomain("example.com")
        assert result.available is False

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        def cb(cmd: str) -> None:
            pass
        with patch("subdomainenum.tools.findomain.run_tool", return_value=([], False)) as mock:
            run_findomain("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb

    def test_timed_out_sets_timed_out_flag(self) -> None:
        with patch(
            "subdomainenum.tools.findomain.run_tool",
            return_value=(["partial.example.com"], True),
        ):
            result = run_findomain("example.com")
        assert result.timed_out is True

    def test_normal_completion_timed_out_false(self) -> None:
        with patch(
            "subdomainenum.tools.findomain.run_tool",
            return_value=(["sub.example.com"], False),
        ):
            result = run_findomain("example.com")
        assert result.timed_out is False


# ---------------------------------------------------------------------------
# assetfinder
# ---------------------------------------------------------------------------


class TestRunAssetfinder:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.assetfinder.run_tool", return_value=([], False)):
            result = run_assetfinder("example.com")
        assert isinstance(result, ToolResult)
        assert result.name == "assetfinder"

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.tools.assetfinder.run_tool",
            side_effect=RuntimeError("assetfinder not found"),
        ):
            result = run_assetfinder("example.com")
        assert result.available is False

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        def cb(cmd: str) -> None:
            pass
        with patch("subdomainenum.tools.assetfinder.run_tool", return_value=([], False)) as mock:
            run_assetfinder("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb

    def test_timed_out_sets_timed_out_flag(self) -> None:
        with patch(
            "subdomainenum.tools.assetfinder.run_tool",
            return_value=(["partial.example.com"], True),
        ):
            result = run_assetfinder("example.com")
        assert result.timed_out is True

    def test_normal_completion_timed_out_false(self) -> None:
        with patch(
            "subdomainenum.tools.assetfinder.run_tool",
            return_value=(["sub.example.com"], False),
        ):
            result = run_assetfinder("example.com")
        assert result.timed_out is False


# ---------------------------------------------------------------------------
# dnsrecon
# ---------------------------------------------------------------------------


class TestRunDnsrecon:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)):
            result = run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
        assert isinstance(result, ToolResult)
        assert result.name == "dnsrecon"

    def test_single_invocation(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
        assert mock.call_count == 1

    def test_all_mode_uses_std_srv_snoop_and_excludes_brt(self) -> None:
        """ALL mode emits std,srv,snoop — brt is delegated to gobuster."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "std" in type_val
        assert "srv" in type_val
        assert "snoop" in type_val
        assert "brt" not in type_val

    def test_all_mode_includes_passive_and_active_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        for flag in ("-a", "-b", "-y", "-k", "-z", "-s"):
            assert flag in cmd, f"expected {flag} in command"

    def test_all_mode_wordlist_in_command(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/subdomains.txt")
            cmd = mock.call_args[0][0]
        assert "-D" in cmd
        assert "/tmp/subdomains.txt" in cmd

    def test_passive_mode_uses_std_and_srv_types(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "std" in type_val
        assert "srv" in type_val
        assert "brt" not in type_val

    def test_passive_mode_includes_passive_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        for flag in ("-b", "-y", "-k", "-s"):
            assert flag in cmd, f"expected {flag} in passive command"

    def test_passive_mode_excludes_active_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "-a" not in cmd
        assert "-z" not in cmd
        assert "-D" not in cmd

    def test_active_mode_uses_std_srv_and_excludes_brt(self) -> None:
        """Active mode emits std,srv only — brt has been delegated to gobuster."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "std" in type_val
        assert "srv" in type_val
        assert "brt" not in type_val

    def test_active_mode_includes_active_flags_and_ignores_wordlist(self) -> None:
        """Active mode keeps AXFR and DNSSEC zone walk but ignores the wordlist
        since brt has been removed."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-a" in cmd
        assert "-z" in cmd
        assert "-D" not in cmd
        assert "/tmp/words.txt" not in cmd

    def test_active_mode_excludes_passive_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
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
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=(output, False)):
            result = run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt")
        assert "sub.example.com" in result.subdomains

    def test_parses_cname_logging_format(self) -> None:
        """CNAME lines in logging format are also parsed correctly."""
        output = ["2026-04-13T11:10:40.252299-0400 INFO      CNAME cr.example.com alias.example.com"]
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=(output, False)):
            result = run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/w.txt")
        assert "cr.example.com" in result.subdomains

    def test_parses_output_lines(self) -> None:
        output = ["[*] A sub.example.com 1.2.3.4"]
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=(output, False)):
            result = run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert "sub.example.com" in result.subdomains

    def test_deduplicates_subdomains(self) -> None:
        output = [
            "[*] A dup.example.com 1.1.1.1",
            "[*] AAAA dup.example.com ::1",
        ]
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=(output, False)):
            result = run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert result.subdomains.count("dup.example.com") == 1

    def test_uses_capture_stderr(self) -> None:
        """dnsrecon must capture stderr because it logs via Python logging module."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert mock.call_args.kwargs.get("capture_stderr") is True

    def test_uses_ignore_returncode(self) -> None:
        """dnsrecon must ignore non-zero exit codes (AXFR refusal etc.)."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert mock.call_args.kwargs.get("ignore_returncode") is True

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        def cb(cmd: str) -> None:
            pass
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb

    def test_timed_out_sets_timed_out_flag(self) -> None:
        output = ["[*] A partial.example.com 1.2.3.4"]
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=(output, True)):
            result = run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert result.timed_out is True

    def test_normal_completion_timed_out_false(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)):
            result = run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
        assert result.timed_out is False

    def test_active_mode_never_adds_f_or_iw(self) -> None:
        """-f and --iw are brt-only; with brt removed, neither flag should appear."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-f" not in cmd
        assert "--iw" not in cmd

    def test_passive_mode_excludes_f_and_iw(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "-f" not in cmd
        assert "--iw" not in cmd

    def test_threads_appended_when_provided(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, threads=10)
            cmd = mock.call_args[0][0]
        assert "--threads" in cmd
        assert cmd[cmd.index("--threads") + 1] == "10"

    def test_threads_omitted_when_none(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "--threads" not in cmd


    def test_all_mode_never_adds_f_or_iw(self) -> None:
        """-f and --iw are brt-only; with brt removed from ALL mode, neither flag appears."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-f" not in cmd
        assert "--iw" not in cmd

    # --- Shodan enrichment (opt-in via SHODAN_API_KEY env var) ---

    def test_passive_mode_adds_shodan_flags_when_env_var_set(self, monkeypatch) -> None:
        monkeypatch.setenv("SHODAN_API_KEY", "fake-key")
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "--shodan" in cmd
        assert "--shodan-active" in cmd

    def test_passive_mode_omits_shodan_flags_when_env_var_unset(self, monkeypatch) -> None:
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "--shodan" not in cmd
        assert "--shodan-active" not in cmd

    @pytest.mark.parametrize("blank_value", ["", " ", "   ", "\t", "\n", " \t\n "])
    def test_passive_mode_omits_shodan_flags_when_env_var_blank(
        self, monkeypatch, blank_value: str
    ) -> None:
        """Empty/whitespace-only env var must be treated as unset."""
        monkeypatch.setenv("SHODAN_API_KEY", blank_value)
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "--shodan" not in cmd
        assert "--shodan-active" not in cmd

    def test_all_mode_adds_shodan_flags_when_env_var_set(self, monkeypatch) -> None:
        monkeypatch.setenv("SHODAN_API_KEY", "fake-key")
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "--shodan" in cmd
        assert "--shodan-active" in cmd

    def test_active_mode_never_adds_shodan_flags(self, monkeypatch) -> None:
        """Active-only mode skips the passive-flag block, so no Shodan enrichment."""
        monkeypatch.setenv("SHODAN_API_KEY", "fake-key")
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "--shodan" not in cmd
        assert "--shodan-active" not in cmd

    def test_shodan_key_is_never_forwarded_on_cli(self, monkeypatch) -> None:
        """dnsrecon reads SHODAN_API_KEY from env itself — we must not leak it into argv."""
        monkeypatch.setenv("SHODAN_API_KEY", "super-secret-key-42")
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "--shodan-key" not in cmd
        assert "super-secret-key-42" not in cmd

    # --- snoop cache-snooping in passive mode (requires a wordlist) ---

    def test_passive_mode_without_wordlist_excludes_snoop(self, monkeypatch) -> None:
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "snoop" not in type_val
        assert "-D" not in cmd

    def test_passive_mode_with_wordlist_includes_snoop(self, monkeypatch) -> None:
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, wordlist="/tmp/snoop.txt")
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "snoop" in type_val
        assert "std" in type_val
        assert "srv" in type_val
        # brt stays out of passive mode even with a wordlist
        assert "brt" not in type_val

    def test_passive_mode_with_wordlist_passes_D_flag(self, monkeypatch) -> None:
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, wordlist="/tmp/snoop.txt")
            cmd = mock.call_args[0][0]
        assert "-D" in cmd
        assert "/tmp/snoop.txt" in cmd

    def test_all_mode_includes_snoop_type(self) -> None:
        """ALL mode always has a wordlist, so snoop must be enabled (brt is delegated to gobuster)."""
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "snoop" in type_val
        assert "brt" not in type_val

    def test_active_mode_excludes_snoop(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "snoop" not in type_val

    def test_passive_snoop_passes_n_flag_with_resolved_ns(self, monkeypatch) -> None:
        """dnsrecon snoop requires -n with IPv4; NS hostnames are resolved to IPs."""
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        with (
            patch(
                "subdomainenum.tools.dnsrecon.resolve_ns",
                return_value=["ns1.example.com", "ns2.example.com"],
            ) as mock_ns,
            patch(
                "subdomainenum.tools.dnsrecon.resolve_ips",
                side_effect=lambda host: {"ns1.example.com": ["1.2.3.4"], "ns2.example.com": ["5.6.7.8"]}[host],
            ),
            patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock_tool,
        ):
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, wordlist="/tmp/snoop.txt")
            cmd = mock_tool.call_args[0][0]
        mock_ns.assert_called_once_with("example.com")
        assert "-n" in cmd
        n_idx = cmd.index("-n")
        assert "1.2.3.4" in cmd[n_idx + 1]
        assert "5.6.7.8" in cmd[n_idx + 1]

    def test_passive_snoop_skips_n_flag_when_ns_empty(self, monkeypatch) -> None:
        """If NS lookup returns nothing, -n is omitted."""
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        with (
            patch("subdomainenum.tools.dnsrecon.resolve_ns", return_value=[]),
            patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock_tool,
        ):
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, wordlist="/tmp/snoop.txt")
            cmd = mock_tool.call_args[0][0]
        assert "-n" not in cmd

    def test_passive_snoop_skips_n_flag_when_ns_has_no_ipv4(self, monkeypatch) -> None:
        """If NS hostnames resolve to no IPv4, -n is omitted."""
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        with (
            patch("subdomainenum.tools.dnsrecon.resolve_ns", return_value=["ns1.example.com"]),
            patch("subdomainenum.tools.dnsrecon.resolve_ips", return_value=[]),
            patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock_tool,
        ):
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, wordlist="/tmp/snoop.txt")
            cmd = mock_tool.call_args[0][0]
        assert "-n" not in cmd

    def test_all_mode_snoop_passes_n_flag(self) -> None:
        """ALL mode always enables snoop — NS IPv4 must be injected here too."""
        with (
            patch("subdomainenum.tools.dnsrecon.resolve_ns", return_value=["ns1.example.com"]),
            patch("subdomainenum.tools.dnsrecon.resolve_ips", return_value=["1.2.3.4"]),
            patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock_tool,
        ):
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock_tool.call_args[0][0]
        assert "-n" in cmd
        assert "1.2.3.4" in cmd[cmd.index("-n") + 1]

    def test_active_mode_no_snoop_no_n_flag(self) -> None:
        """ACTIVE mode does not use snoop, so resolve_ns must not be called."""
        with (
            patch(
                "subdomainenum.tools.dnsrecon.resolve_ns",
                return_value=["ns1.example.com"],
            ) as mock_ns,
            patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock_tool,
        ):
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock_tool.call_args[0][0]
        mock_ns.assert_not_called()
        assert "-n" not in cmd


# ---------------------------------------------------------------------------
# gobuster_dns
# ---------------------------------------------------------------------------


class TestRunGobusterDns:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=([], False)):
            result = run_gobuster_dns("example.com", wordlist="/tmp/words.txt")
        assert isinstance(result, ToolResult)
        assert result.name == "gobuster"

    def test_wordlist_in_command(self) -> None:
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=([], False)) as mock:
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
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=(output, False)):
            result = run_gobuster_dns("example.com", wordlist="/tmp/w.txt")
        assert "sub.example.com" in result.subdomains

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        def cb(cmd: str) -> None:
            pass
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=([], False)) as mock:
            run_gobuster_dns("example.com", wordlist="/tmp/w.txt", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb

    def test_timed_out_sets_timed_out_flag(self) -> None:
        output = ["Found: partial.example.com"]
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=(output, True)):
            result = run_gobuster_dns("example.com", wordlist="/tmp/w.txt")
        assert result.timed_out is True

    def test_normal_completion_timed_out_false(self) -> None:
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=([], False)):
            result = run_gobuster_dns("example.com", wordlist="/tmp/w.txt")
        assert result.timed_out is False


# ---------------------------------------------------------------------------
# ffuf (vhost fuzzing)
# ---------------------------------------------------------------------------


class TestParseFfufLine:
    """Unit tests for the pure _parse_ffuf_line helper."""

    def test_returns_vhost_result_for_match_line(self) -> None:
        line = "admin   [Status: 200, Size: 512, Words: 5, Lines: 10, Duration: 5ms]"
        result = _parse_ffuf_line(line, "example.com", {404, 400})
        assert isinstance(result, VhostResult)
        assert result.vhost == "admin.example.com"

    def test_constructs_vhost_fqdn(self) -> None:
        line = "mail   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 5ms]"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is not None
        assert result.vhost == "mail.example.com"

    def test_captures_status_code_and_content_length(self) -> None:
        line = "www   [Status: 301, Size: 8192, Words: 3, Lines: 5, Duration: 10ms]"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is not None
        assert result.status_code == 301
        assert result.content_length == 8192

    def test_filtered_status_excluded(self) -> None:
        line = "ghost   [Status: 404, Size: 100, Words: 1, Lines: 1, Duration: 5ms]"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is None

    def test_skips_non_match_lines(self) -> None:
        line = " :: Method           : GET"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is None

    def test_empty_fuzz_word_skipped(self) -> None:
        line = "   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 5ms]"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is None

    def test_progress_line_skipped(self) -> None:
        line = ":: Progress: [100/100] :: Job [1/1] :: 50 req/sec :: Duration: [0:00:02] :: Errors: 0 ::"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is None

    def test_ansi_erase_line_prefix_stripped(self) -> None:
        """ffuf emits \\x1b[2K before result lines; the ANSI code must not pollute the vhost name."""
        line = "\x1b[2Kwww   [Status: 200, Size: 512, Words: 5, Lines: 10, Duration: 5ms]"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is not None
        assert result.vhost == "www.example.com"

    def test_ansi_reset_code_stripped(self) -> None:
        line = "\x1b[0madmin   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 5ms]"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is not None
        assert result.vhost == "admin.example.com"

    def test_multiple_ansi_codes_stripped(self) -> None:
        line = "\x1b[2K\x1b[0mmail   [Status: 200, Size: 1024, Words: 3, Lines: 5, Duration: 5ms]"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is not None
        assert result.vhost == "mail.example.com"
        assert result.status_code == 200
        assert result.content_length == 1024

    def test_ansi_only_line_skipped(self) -> None:
        """A line that is only ANSI codes with no match content should return None."""
        line = "\x1b[2K\x1b[0m"
        result = _parse_ffuf_line(line, "example.com", {404})
        assert result is None


class TestRunFfuf:
    def test_tool_missing_returns_empty_list(self) -> None:
        with patch(
            "subdomainenum.tools.ffuf.run_tool",
            side_effect=RuntimeError("ffuf not found"),
        ):
            results = run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt")
        assert results == []

    def test_wordlist_in_command(self) -> None:
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=([], False)) as mock:
            run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/vhosts.txt")
            cmd = mock.call_args[0][0]
        assert "/tmp/vhosts.txt" in cmd

    def test_url_and_filter_codes_in_command(self) -> None:
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=([], False)) as mock:
            run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt")
            cmd = mock.call_args[0][0]
        assert "http://10.0.0.1" in cmd
        assert "-fc" in cmd
        assert "-noninteractive" in cmd

    def test_no_json_file_flags_in_command(self) -> None:
        """ffuf must NOT use -of, -s, or -o (stdout parsing replaces tempfile approach)."""
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=([], False)) as mock:
            run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt")
            cmd = mock.call_args[0][0]
        assert "-of" not in cmd
        assert "-s" not in cmd
        assert "-o" not in cmd
        assert "-ac" in cmd

    def test_returns_vhost_results_from_stdout(self) -> None:
        stdout_lines = ["admin   [Status: 200, Size: 1024, Words: 5, Lines: 10, Duration: 5ms]"]
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=(stdout_lines, False)):
            results = run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt")
        assert len(results) == 1
        assert isinstance(results[0], VhostResult)
        assert results[0].vhost == "admin.example.com"
        assert results[0].status_code == 200
        assert results[0].content_length == 1024

    def test_non_match_lines_are_skipped(self) -> None:
        stdout_lines = [
            ":: Method           : GET",
            "admin   [Status: 200, Size: 1024, Words: 5, Lines: 10, Duration: 5ms]",
        ]
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=(stdout_lines, False)):
            results = run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt")
        assert len(results) == 1

    def test_filtered_status_excluded_in_run(self) -> None:
        stdout_lines = ["ghost   [Status: 404, Size: 100, Words: 1, Lines: 1, Duration: 5ms]"]
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=(stdout_lines, False)):
            results = run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt",
                               filter_codes={404})
        assert results == []

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        def cb(cmd: str) -> None:
            pass
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=([], False)) as mock:
            run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb

    def test_ignore_returncode_passed_to_run_tool(self) -> None:
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=([], False)) as mock:
            run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt")
        assert mock.call_args.kwargs.get("ignore_returncode") is True

    def test_capture_stderr_passed_to_run_tool(self) -> None:
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=([], False)) as mock:
            run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt")
        assert mock.call_args.kwargs.get("capture_stderr") is True

    def test_ac_flag_in_command(self) -> None:
        with patch("subdomainenum.tools.ffuf.run_tool", return_value=([], False)) as mock:
            run_ffuf("example.com", url="http://10.0.0.1", wordlist="/tmp/w.txt")
            cmd = mock.call_args[0][0]
        assert "-ac" in cmd


# ---------------------------------------------------------------------------
# fqdn_cb streaming — exercises each wrapper's real-time FQDN emission path
# ---------------------------------------------------------------------------


def _fake_run_tool(output_lines: list[str]):
    """Build a fake run_tool that actually invokes the wrapper's line_cb."""

    def _impl(cmd, *, timeout=None, idle_timeout=None, line_cb=None, cmd_cb=None, **kwargs):
        if line_cb is not None:
            for line in output_lines:
                line_cb(line)
        return (output_lines, False)

    return _impl


class TestSubfinderFqdnCb:
    def test_emits_in_scope_fqdns_and_ignores_others(self) -> None:
        seen: list[str] = []
        with patch(
            "subdomainenum.tools.subfinder.run_tool",
            side_effect=_fake_run_tool([
                "a.example.com",
                "B.EXAMPLE.com",
                "   ",
                "other.domain.test",
            ]),
        ):
            run_subfinder("example.com", fqdn_cb=seen.append)
        assert "a.example.com" in seen
        assert "b.example.com" in seen
        assert "other.domain.test" not in seen

    def test_no_callback_skips_fqdn_emission(self) -> None:
        with patch(
            "subdomainenum.tools.subfinder.run_tool",
            side_effect=_fake_run_tool(["a.example.com"]),
        ):
            # Should not raise when fqdn_cb is None.
            result = run_subfinder("example.com")
        assert "a.example.com" in result.subdomains


class TestAssetfinderFqdnCb:
    def test_emits_in_scope_fqdns(self) -> None:
        seen: list[str] = []
        with patch(
            "subdomainenum.tools.assetfinder.run_tool",
            side_effect=_fake_run_tool(["asset1.example.com", "foreign.test"]),
        ):
            run_assetfinder("example.com", fqdn_cb=seen.append)
        assert seen == ["asset1.example.com"]


class TestFindomainFqdnCb:
    def test_emits_in_scope_fqdns(self) -> None:
        seen: list[str] = []
        with patch(
            "subdomainenum.tools.findomain.run_tool",
            side_effect=_fake_run_tool(["find.example.com", "other.test"]),
        ):
            run_findomain("example.com", fqdn_cb=seen.append)
        assert seen == ["find.example.com"]


class TestGobusterDnsFqdnCb:
    def test_emits_in_scope_fqdns_once_per_fqdn(self) -> None:
        seen: list[str] = []
        with patch(
            "subdomainenum.tools.gobuster_dns.run_tool",
            side_effect=_fake_run_tool([
                "Found: admin.example.com",
                "Found: admin.example.com",  # duplicate should not re-fire
                "Found: api.example.com.",  # trailing-dot must be trimmed
                "Found: evil.other.test",
            ]),
        ):
            run_gobuster_dns(
                "example.com", wordlist="/tmp/w.txt", fqdn_cb=seen.append,
            )
        assert seen == ["admin.example.com", "api.example.com"]


class TestAmassFqdnCb:
    def test_emits_in_scope_fqdn_from_graph_line(self) -> None:
        seen: list[str] = []
        with patch(
            "subdomainenum.tools.amass.run_tool",
            side_effect=_fake_run_tool([
                "svc.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)",
                "ns1.other.test (FQDN) --> a_record --> 5.6.7.8 (IPAddress)",
                "svc.example.com (FQDN) --> aaaa_record --> ::1 (IPAddress)",
            ]),
        ):
            result = run_amass("example.com", fqdn_cb=seen.append)
        assert seen == ["svc.example.com"]
        assert result.subdomains == ["svc.example.com"]


class TestDnsreconFqdnCb:
    def test_emits_in_scope_fqdns_from_tokens(self) -> None:
        seen: list[str] = []
        with patch(
            "subdomainenum.tools.dnsrecon.run_tool",
            side_effect=_fake_run_tool([
                "[*] A mail.example.com 1.2.3.4",
                "[*] CNAME cdn.example.com cdn.provider.net",
                "[*] A foreign.test 9.9.9.9",
            ]),
        ):
            result = run_dnsrecon(
                "example.com", mode=EnumMode.PASSIVE, fqdn_cb=seen.append,
            )
        assert "mail.example.com" in seen
        assert "cdn.example.com" in seen
        assert "foreign.test" not in seen
        # Streamed FQDNs must populate result.subdomains when fqdn_cb is set.
        assert "mail.example.com" in result.subdomains
