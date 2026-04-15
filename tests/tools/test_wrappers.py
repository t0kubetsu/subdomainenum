"""Tests for active tool wrappers (subfinder, amass, findomain, assetfinder,
dnsrecon, gobuster_dns, ffuf)."""

from __future__ import annotations

from unittest.mock import patch


from subdomainenum.models import EnumMode, SourceResult, VhostResult
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
        assert isinstance(result, SourceResult)
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
        assert isinstance(result, SourceResult)
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

    def test_brute_flag_with_wordlist_in_active_mode(self) -> None:
        """wordlist + ACTIVE mode → -brute -w <path> in command."""
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-brute" in cmd
        assert "-w" in cmd
        assert "/tmp/words.txt" in cmd

    def test_brute_flag_with_wordlist_in_all_mode(self) -> None:
        """wordlist + ALL mode → -brute -w <path> in command."""
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-brute" in cmd
        assert "-w" in cmd
        assert "/tmp/words.txt" in cmd

    def test_no_brute_flag_in_passive_mode_with_wordlist(self) -> None:
        """wordlist + PASSIVE mode → -brute must not appear (passive ignores wordlist)."""
        with patch("subdomainenum.tools.amass.run_tool", return_value=([], False)) as mock:
            run_amass("example.com", mode=EnumMode.PASSIVE, wordlist="/tmp/words.txt")
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
        assert isinstance(result, SourceResult)
        assert result.name == "dnsrecon"

    def test_single_invocation(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
        assert mock.call_count == 1

    def test_all_mode_uses_std_srv_and_brt_types(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "std" in type_val
        assert "srv" in type_val
        assert "brt" in type_val

    def test_all_mode_includes_passive_and_active_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        for flag in ("-a", "-b", "-y", "-k", "-z", "-s", "-w"):
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
        for flag in ("-b", "-y", "-k", "-s", "-w"):
            assert flag in cmd, f"expected {flag} in passive command"

    def test_passive_mode_excludes_active_flags(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "-a" not in cmd
        assert "-z" not in cmd
        assert "-D" not in cmd

    def test_active_mode_uses_brt_type(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        type_val = cmd[cmd.index("-t") + 1]
        assert "brt" in type_val
        assert "std" not in type_val

    def test_active_mode_includes_active_flags_and_wordlist(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-a" in cmd
        assert "-z" in cmd
        assert "-D" in cmd
        assert "/tmp/words.txt" in cmd

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

    def test_active_mode_filter_wildcard_default_adds_f(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-f" in cmd
        assert "--iw" not in cmd

    def test_active_mode_no_filter_wildcard_adds_iw(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon(
                "example.com", mode=EnumMode.ACTIVE, wordlist="/tmp/words.txt",
                filter_wildcard=False,
            )
            cmd = mock.call_args[0][0]
        assert "--iw" in cmd
        assert "-f" not in cmd

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

    def test_disable_check_nxdomain(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, disable_check_nxdomain=True)
            cmd = mock.call_args[0][0]
        assert "--disable_check_nxdomain" in cmd

    def test_disable_check_recursion(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, disable_check_recursion=True)
            cmd = mock.call_args[0][0]
        assert "--disable_check_recursion" in cmd

    def test_disable_check_bindversion(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE, disable_check_bindversion=True)
            cmd = mock.call_args[0][0]
        assert "--disable_check_bindversion" in cmd

    def test_disable_check_flags_absent_by_default(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.PASSIVE)
            cmd = mock.call_args[0][0]
        assert "--disable_check_nxdomain" not in cmd
        assert "--disable_check_recursion" not in cmd
        assert "--disable_check_bindversion" not in cmd

    def test_all_mode_filter_wildcard_default_adds_f(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon("example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt")
            cmd = mock.call_args[0][0]
        assert "-f" in cmd
        assert "--iw" not in cmd

    def test_all_mode_no_filter_wildcard_adds_iw(self) -> None:
        with patch("subdomainenum.tools.dnsrecon.run_tool", return_value=([], False)) as mock:
            run_dnsrecon(
                "example.com", mode=EnumMode.ALL, wordlist="/tmp/words.txt",
                filter_wildcard=False,
            )
            cmd = mock.call_args[0][0]
        assert "--iw" in cmd
        assert "-f" not in cmd


# ---------------------------------------------------------------------------
# gobuster_dns
# ---------------------------------------------------------------------------


class TestRunGobusterDns:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.tools.gobuster_dns.run_tool", return_value=([], False)):
            result = run_gobuster_dns("example.com", wordlist="/tmp/words.txt")
        assert isinstance(result, SourceResult)
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
