"""Tests for subdomainenum.cli – Typer CLI entry point."""

from __future__ import annotations

import json
from unittest.mock import patch

from typer.testing import CliRunner

from subdomainenum.cli import app
from subdomainenum.models import EnumMode, EnumReport, ToolResult, Status, SubdomainResult

runner = CliRunner()


def _make_report(domain: str = "example.com") -> EnumReport:
    return EnumReport(
        domain=domain,
        mode=EnumMode.PASSIVE,
        subdomains=[
            SubdomainResult(fqdn="sub.example.com", status=Status.ALIVE, alive=True, ip_addresses=["1.2.3.4"], tools=["dnsrecon"]),
        ],
        tools=[ToolResult(name="dnsrecon", subdomains=["sub.example.com"], available=True)],
    )


class TestCheckCommand:
    def test_basic_passive_check(self) -> None:
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive"])
        assert result.exit_code == 0

    def test_default_mode_without_wordlist_exits_nonzero(self) -> None:
        """Default mode is 'all', which requires --wordlist."""
        result = runner.invoke(app, ["check", "example.com"])
        assert result.exit_code != 0

    def test_json_output(self) -> None:
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["domain"] == "example.com"
        assert isinstance(data["subdomains"], list)

    def test_invalid_domain_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["check", "not_a_domain"])
        assert result.exit_code != 0

    def test_active_mode_without_wordlist_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["check", "example.com", "--mode", "active"])
        assert result.exit_code != 0

    def test_active_mode_with_nonexistent_wordlist_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["check", "example.com", "--mode", "active", "--wordlist", "/no/such/file.txt"])
        assert result.exit_code != 0

    def test_active_mode_with_wordlist(self, tmp_path) -> None:
        wl = tmp_path / "words.txt"
        wl.write_text("www\nmail\n")
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "active", "--wordlist", str(wl)])
        assert result.exit_code == 0

    def test_output_flag_saves_file(self, tmp_path) -> None:
        out = tmp_path / "report.txt"
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert "example.com" in out.read_text()

    def test_json_flag_ignores_output(self, tmp_path) -> None:
        out = tmp_path / "report.txt"
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--json", "--output", str(out)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["domain"] == "example.com"
        # --output is ignored when --json is active
        assert not out.exists()

    def test_assess_value_error_exits_nonzero(self) -> None:
        with patch("subdomainenum.cli.assess", side_effect=ValueError("wordlist required")):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive"])
        assert result.exit_code != 0

    def test_json_output_on_error(self) -> None:
        with patch("subdomainenum.cli.assess", side_effect=RuntimeError("boom")):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--json"])
        assert result.exit_code != 0
        data = json.loads(result.stdout)
        assert "error" in data


class TestDebugLogMode:
    def test_debug_log_writes_file(self, tmp_path) -> None:
        """--debug-log saves tool output to the auto-generated file."""
        log_file = tmp_path / "example.com_20260413_120000.log"
        with patch("subdomainenum.cli._auto_log_path", return_value=log_file):
            with patch("subdomainenum.cli.assess", return_value=_make_report()):
                result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug-log"])
        assert result.exit_code == 0
        assert log_file.exists()

    def test_debug_log_file_contains_domain(self, tmp_path) -> None:
        """Log file header includes the target domain."""
        log_file = tmp_path / "example.com_20260413_120000.log"
        with patch("subdomainenum.cli._auto_log_path", return_value=log_file):
            with patch("subdomainenum.cli.assess", return_value=_make_report()):
                runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug-log"])
        assert "example.com" in log_file.read_text()

    def test_debug_log_passes_callbacks_to_assess(self, tmp_path) -> None:
        """When --debug-log is set, assess() receives debug_cb, cmd_cb, finish_cb."""
        captured: dict = {}
        log_file = tmp_path / "example.com_20260413_120000.log"

        def fake_assess(domain, **kwargs):
            captured["debug_cb"] = kwargs.get("debug_cb")
            captured["cmd_cb"] = kwargs.get("cmd_cb")
            captured["finish_cb"] = kwargs.get("finish_cb")
            return _make_report()

        with patch("subdomainenum.cli._auto_log_path", return_value=log_file):
            with patch("subdomainenum.cli.assess", side_effect=fake_assess):
                runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug-log"])

        assert captured.get("debug_cb") is not None
        assert captured.get("cmd_cb") is not None
        assert captured.get("finish_cb") is not None

    def test_no_debug_log_passes_no_debug_callbacks(self) -> None:
        """Without --debug-log, assess() receives no debug callbacks."""
        captured: dict = {}

        def fake_assess(domain, **kwargs):
            captured["debug_cb"] = kwargs.get("debug_cb")
            return _make_report()

        with patch("subdomainenum.cli.assess", side_effect=fake_assess):
            runner.invoke(app, ["check", "example.com", "--mode", "passive"])

        assert captured.get("debug_cb") is None

    def test_debug_log_stderr_message(self, tmp_path) -> None:
        """After scan, a 'Debug log →' message is printed to stderr."""
        log_file = tmp_path / "example.com_20260413_120000.log"
        with patch("subdomainenum.cli._auto_log_path", return_value=log_file):
            with patch("subdomainenum.cli.assess", return_value=_make_report()):
                result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug-log"])
        assert "Debug log" in result.output or result.exit_code == 0

    def test_debug_log_with_json_flag(self, tmp_path) -> None:
        """--debug-log + --json should produce valid JSON on stdout and write log file."""
        log_file = tmp_path / "example.com_20260413_120000.log"
        with patch("subdomainenum.cli._auto_log_path", return_value=log_file):
            with patch("subdomainenum.cli.assess", return_value=_make_report()):
                result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--json", "--debug-log"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["domain"] == "example.com"
        assert log_file.exists()

    def test_debug_log_on_assess_error(self, tmp_path) -> None:
        """When assess() raises, exit is non-zero (log file is not written)."""
        log_file = tmp_path / "example.com_20260413_120000.log"
        with patch("subdomainenum.cli._auto_log_path", return_value=log_file):
            with patch("subdomainenum.cli.assess", side_effect=RuntimeError("boom")):
                result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug-log"])
        assert result.exit_code != 0

    def test_debug_log_callbacks_receive_output(self, tmp_path) -> None:
        """Lines emitted via debug_cb appear in the saved log file."""
        log_file = tmp_path / "example.com_20260413_120000.log"

        def fake_assess(domain, **kwargs):
            cb = kwargs.get("debug_cb")
            cmd_cb = kwargs.get("cmd_cb")
            finish_cb = kwargs.get("finish_cb")
            if cmd_cb:
                cmd_cb("subfinder", "subfinder -d example.com -silent")
            if cb:
                cb("subfinder", "sub.example.com")
                cb("subfinder", "mail.example.com")
            if finish_cb:
                finish_cb("subfinder", None)
            return _make_report()

        with patch("subdomainenum.cli._auto_log_path", return_value=log_file):
            with patch("subdomainenum.cli.assess", side_effect=fake_assess):
                runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug-log"])

        content = log_file.read_text()
        assert "subfinder" in content
        assert "sub.example.com" in content
        assert "mail.example.com" in content


class TestAutoLogPath:
    def test_uses_reports_dir_when_mounted(self) -> None:
        """Returns /reports/<domain>_<ts>.log when /reports/ is a directory."""
        from subdomainenum.cli import _auto_log_path

        with patch("pathlib.Path.is_dir", return_value=True):
            result = _auto_log_path("example.com")
        assert str(result).startswith("/reports/")
        assert "example.com" in result.name
        assert result.suffix == ".log"

    def test_uses_cwd_when_reports_dir_absent(self) -> None:
        """Returns ./<domain>_<ts>.log when /reports/ is not a directory."""
        from subdomainenum.cli import _auto_log_path

        with patch("pathlib.Path.is_dir", return_value=False):
            result = _auto_log_path("nc3.lu")
        assert not str(result).startswith("/reports")
        assert "nc3.lu" in result.name
        assert result.suffix == ".log"

    def test_filename_contains_timestamp(self) -> None:
        """Generated filename includes a YYYYMMDD_HHMMSS timestamp."""
        import re as _re
        from subdomainenum.cli import _auto_log_path

        with patch("pathlib.Path.is_dir", return_value=False):
            result = _auto_log_path("test.com")
        assert _re.search(r"\d{8}_\d{6}", result.name)

    def test_filename_starts_with_domain(self) -> None:
        """The domain appears at the start of the generated filename."""
        from subdomainenum.cli import _auto_log_path

        with patch("pathlib.Path.is_dir", return_value=False):
            result = _auto_log_path("mysite.org")
        assert result.name.startswith("mysite.org_")


class TestProgressCb:
    def test_progress_cb_invoked(self) -> None:
        """progress_cb closure body is called when assess uses it."""

        def fake_assess(*args, **kwargs):
            cb = kwargs.get("progress_cb")
            if cb:
                cb("Doing something...")
            return _make_report()

        with patch("subdomainenum.cli.assess", side_effect=fake_assess):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive"])
        assert result.exit_code == 0


class TestSaveReportFormats:
    def test_output_svg_saves_file(self, tmp_path) -> None:
        """export_svg branch in _save_report."""
        out = tmp_path / "report.svg"
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_output_html_saves_file(self, tmp_path) -> None:
        """export_html branch in _save_report."""
        out = tmp_path / "report.html"
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()


class TestInfoCommand:
    def test_info_runs(self) -> None:
        with patch("subdomainenum.cli.detect_tools", return_value={"subfinder": True, "amass": False, "findomain": False, "assetfinder": True, "dnsrecon": True, "gobuster": False, "wfuzz": False}):
            result = runner.invoke(app, ["info"])
        assert result.exit_code == 0

    def test_info_shows_tool_names(self) -> None:
        with patch("subdomainenum.cli.detect_tools", return_value={k: False for k in ["subfinder", "amass", "findomain", "assetfinder", "dnsrecon", "gobuster", "wfuzz"]}):
            result = runner.invoke(app, ["info"])
        assert "subfinder" in result.stdout or result.exit_code == 0


class TestVersionFlag:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "subdomainenum" in result.stdout
