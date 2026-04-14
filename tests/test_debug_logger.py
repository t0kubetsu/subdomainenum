"""Tests for subdomainenum.debug_logger — DebugLogger."""

from __future__ import annotations

import threading
from pathlib import Path


from subdomainenum.debug_logger import DebugLogger


class TestAddLine:
    def test_add_line_registers_source(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "sub.example.com")
        assert "subfinder" in logger._order

    def test_add_line_stores_content(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "sub.example.com")
        assert logger._lines["subfinder"] == ["sub.example.com"]

    def test_add_line_multiple_lines(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "a.example.com")
        logger.add_line("subfinder", "b.example.com")
        assert logger._lines["subfinder"] == ["a.example.com", "b.example.com"]

    def test_add_line_sets_status_running(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "sub.example.com")
        assert logger._statuses["subfinder"] == "RUNNING"

    def test_add_line_multiple_sources(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "a.example.com")
        logger.add_line("amass", "b.example.com")
        assert "subfinder" in logger._order
        assert "amass" in logger._order

    def test_add_line_preserves_registration_order(self) -> None:
        logger = DebugLogger()
        logger.add_line("amass", "x")
        logger.add_line("subfinder", "y")
        assert logger._order[0] == "amass"
        assert logger._order[1] == "subfinder"


class TestSetCommand:
    def test_set_command_stores_cmd(self) -> None:
        logger = DebugLogger()
        logger.set_command("dnsrecon", "dnsrecon -d example.com -t brt")
        assert logger._commands["dnsrecon"] == "dnsrecon -d example.com -t brt"

    def test_set_command_sets_status_running(self) -> None:
        logger = DebugLogger()
        logger.set_command("dnsrecon", "dnsrecon -d example.com")
        assert logger._statuses["dnsrecon"] == "RUNNING"

    def test_set_command_registers_source(self) -> None:
        logger = DebugLogger()
        logger.set_command("gobuster", "gobuster dns ...")
        assert "gobuster" in logger._order


class TestFinish:
    def test_finish_success_sets_done(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "sub.example.com")
        logger.finish("subfinder", None)
        assert logger._statuses["subfinder"] == "DONE"

    def test_finish_error_sets_failed(self) -> None:
        logger = DebugLogger()
        logger.add_line("amass", "x")
        logger.finish("amass", "timeout after 30s")
        assert logger._statuses["amass"] == "FAILED"

    def test_finish_stores_error_message(self) -> None:
        logger = DebugLogger()
        logger.finish("wfuzz", "connection refused")
        assert logger._errors["wfuzz"] == "connection refused"

    def test_finish_stores_none_on_success(self) -> None:
        logger = DebugLogger()
        logger.finish("subfinder", None)
        assert logger._errors["subfinder"] is None

    def test_finish_registers_source_if_not_seen(self) -> None:
        logger = DebugLogger()
        logger.finish("san", None)
        assert "san" in logger._order


class TestSetInvocation:
    def test_set_invocation_stores_version(self) -> None:
        logger = DebugLogger()
        logger.set_invocation("0.7.2", "passive", None, None, 5.0)
        assert logger._invocation["version"] == "0.7.2"

    def test_set_invocation_stores_mode(self) -> None:
        logger = DebugLogger()
        logger.set_invocation("0.7.2", "all", "/tmp/words.txt", "http://10.0.0.1", 3.0)
        assert logger._invocation["mode"] == "all"

    def test_set_invocation_wordlist_none_shown_as_none_string(self) -> None:
        logger = DebugLogger()
        logger.set_invocation("0.7.2", "passive", None, None, 5.0)
        assert logger._invocation["wordlist"] == "none"

    def test_set_invocation_url_none_shown_as_none_string(self) -> None:
        logger = DebugLogger()
        logger.set_invocation("0.7.2", "passive", None, None, 5.0)
        assert logger._invocation["url"] == "none"

    def test_set_invocation_timeout_formatted_with_unit(self) -> None:
        logger = DebugLogger()
        logger.set_invocation("0.7.2", "passive", None, None, 10.0)
        assert logger._invocation["timeout"] == "10.0s"

    def test_set_invocation_wordlist_stored_when_provided(self) -> None:
        logger = DebugLogger()
        logger.set_invocation("0.7.2", "active", "/opt/words.txt", None, 5.0)
        assert logger._invocation["wordlist"] == "/opt/words.txt"

    def test_set_invocation_url_stored_when_provided(self) -> None:
        logger = DebugLogger()
        logger.set_invocation("0.7.2", "all", "/tmp/w.txt", "http://10.0.0.1", 5.0)
        assert logger._invocation["url"] == "http://10.0.0.1"


class TestFormatLog:
    def test_format_log_includes_domain(self) -> None:
        logger = DebugLogger()
        result = logger.format_log(domain="example.com")
        assert "example.com" in result

    def test_format_log_includes_source_name(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "sub.example.com")
        result = logger.format_log()
        assert "subfinder" in result

    def test_format_log_includes_output_lines(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "sub.example.com")
        logger.add_line("subfinder", "mail.example.com")
        result = logger.format_log()
        assert "sub.example.com" in result
        assert "mail.example.com" in result

    def test_format_log_includes_command(self) -> None:
        logger = DebugLogger()
        logger.set_command("gobuster", "gobuster dns -d example.com -w /tmp/words.txt")
        result = logger.format_log()
        assert "gobuster dns -d example.com" in result

    def test_format_log_includes_error(self) -> None:
        logger = DebugLogger()
        logger.finish("amass", "binary not found")
        result = logger.format_log()
        assert "binary not found" in result

    def test_format_log_includes_status(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "x")
        logger.finish("subfinder", None)
        result = logger.format_log()
        assert "DONE" in result

    def test_format_log_includes_failed_status(self) -> None:
        logger = DebugLogger()
        logger.finish("dnsrecon", "timeout")
        result = logger.format_log()
        assert "FAILED" in result

    def test_format_log_empty_logger(self) -> None:
        logger = DebugLogger()
        result = logger.format_log(domain="example.com")
        assert "example.com" in result
        assert isinstance(result, str)

    def test_format_log_no_output_placeholder(self) -> None:
        """A source with no lines, no command, no error shows a placeholder."""
        logger = DebugLogger()
        logger.finish("san", None)
        result = logger.format_log()
        assert "(no output)" in result

    def test_format_log_includes_invocation_block(self) -> None:
        logger = DebugLogger()
        logger.set_invocation("0.7.2", "all", "/tmp/words.txt", "http://10.0.0.1", 5.0)
        result = logger.format_log(domain="example.com")
        assert "Invocation" in result
        assert "mode" in result
        assert "all" in result

    def test_format_log_invocation_shows_none_for_missing_optional_params(self) -> None:
        logger = DebugLogger()
        logger.set_invocation("0.7.2", "passive", None, None, 5.0)
        result = logger.format_log()
        assert "wordlist" in result
        assert "none" in result

    def test_format_log_no_invocation_block_when_not_set(self) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "x.example.com")
        result = logger.format_log()
        assert "Invocation" not in result


class TestSaveToFile:
    def test_save_to_file_creates_file(self, tmp_path) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "sub.example.com")
        path = str(tmp_path / "debug.log")
        logger.save_to_file(path)
        assert Path(path).exists()

    def test_save_to_file_content_matches_format_log(self, tmp_path) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "sub.example.com")
        path = str(tmp_path / "debug.log")
        logger.save_to_file(path, domain="example.com")
        content = Path(path).read_text(encoding="utf-8")
        assert content == logger.format_log(domain="example.com")

    def test_save_to_file_includes_all_lines(self, tmp_path) -> None:
        logger = DebugLogger()
        for i in range(50):
            logger.add_line("gobuster", f"host{i}.example.com")
        path = str(tmp_path / "debug.log")
        logger.save_to_file(path)
        content = Path(path).read_text()
        assert "host0.example.com" in content
        assert "host49.example.com" in content

    def test_save_to_file_encoding_utf8(self, tmp_path) -> None:
        logger = DebugLogger()
        logger.add_line("subfinder", "sub-αβγ.example.com")
        path = str(tmp_path / "debug.log")
        logger.save_to_file(path)
        content = Path(path).read_text(encoding="utf-8")
        assert "sub-αβγ.example.com" in content


class TestThreadSafety:
    def test_concurrent_add_line_does_not_lose_lines(self) -> None:
        """All lines from concurrent threads must be retained."""
        logger = DebugLogger()
        n_threads = 10
        lines_per_thread = 100

        def worker(source: str) -> None:
            for i in range(lines_per_thread):
                logger.add_line(source, f"line{i}")

        threads = [threading.Thread(target=worker, args=(f"src{t}",)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        total = sum(len(logger._lines[s]) for s in logger._order)
        assert total == n_threads * lines_per_thread

    def test_concurrent_mixed_ops(self) -> None:
        """add_line, set_command, finish from multiple threads must not raise."""
        logger = DebugLogger()
        errors: list[Exception] = []

        def worker(idx: int) -> None:
            try:
                source = f"tool{idx}"
                logger.set_command(source, f"cmd{idx}")
                for i in range(20):
                    logger.add_line(source, f"result{i}")
                logger.finish(source, None)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
