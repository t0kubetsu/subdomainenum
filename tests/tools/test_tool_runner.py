"""Tests for subdomainenum.tools.tool_runner – subprocess wrapper."""

from __future__ import annotations

import io
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from subdomainenum.tools.tool_runner import run_tool


def _make_popen(stdout_text: str, returncode: int = 0) -> MagicMock:
    """Build a mock Popen object whose stdout iterates over *stdout_text* lines."""
    mock_proc = MagicMock()
    mock_proc.stdout = io.StringIO(stdout_text)
    mock_proc.returncode = returncode
    mock_proc.wait.return_value = returncode
    mock_proc.kill.return_value = None
    return mock_proc


class TestRunTool:
    def test_returns_stdout_lines_on_success(self) -> None:
        with patch("subprocess.Popen", return_value=_make_popen("sub1.example.com\nsub2.example.com\n")) as mock_popen:
            lines = run_tool(["subfinder", "-d", "example.com"], timeout=30)
        mock_popen.assert_called_once()
        assert "sub1.example.com" in lines
        assert "sub2.example.com" in lines

    def test_returns_empty_list_on_nonzero_exit(self) -> None:
        with patch("subprocess.Popen", return_value=_make_popen("", returncode=1)):
            lines = run_tool(["gobuster", "dns"], timeout=30)
        assert lines == []

    def test_raises_file_not_found_as_runtime_error(self) -> None:
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError, match="not found"):
                run_tool(["nonexistent_binary"], timeout=5)

    def test_handles_timeout(self) -> None:
        """When the reader thread is still alive after *timeout*, kill the process."""
        import threading

        def _slow_popen(*args, **kwargs):
            mock_proc = MagicMock()
            # stdout blocks forever — simulate via an event
            event = threading.Event()

            class _BlockingStream:
                def __iter__(self):
                    event.wait()  # never returns in test
                    return iter([])

                def close(self):
                    event.set()

            mock_proc.stdout = _BlockingStream()
            mock_proc.returncode = -9
            mock_proc.wait.return_value = -9
            mock_proc.kill.side_effect = lambda: event.set()
            return mock_proc

        with patch("subprocess.Popen", side_effect=_slow_popen):
            lines = run_tool(["tool"], timeout=0)  # zero timeout → instant
        assert lines == []

    def test_strips_blank_lines(self) -> None:
        with patch("subprocess.Popen", return_value=_make_popen("sub.example.com\n\n  \nsub2.example.com\n")):
            lines = run_tool(["subfinder"], timeout=30)
        assert "" not in lines
        assert "  " not in lines
        assert len(lines) == 2

    def test_line_cb_called_for_each_line(self) -> None:
        collected: list[str] = []
        with patch("subprocess.Popen", return_value=_make_popen("a.example.com\nb.example.com\n")):
            run_tool(["subfinder"], timeout=30, line_cb=collected.append)
        assert collected == ["a.example.com", "b.example.com"]

    def test_line_cb_not_called_for_blank_lines(self) -> None:
        collected: list[str] = []
        with patch("subprocess.Popen", return_value=_make_popen("a.example.com\n\n  \nb.example.com\n")):
            run_tool(["subfinder"], timeout=30, line_cb=collected.append)
        assert "" not in collected
        assert "  " not in collected
        assert len(collected) == 2

    def test_no_line_cb_still_returns_lines(self) -> None:
        with patch("subprocess.Popen", return_value=_make_popen("x.example.com\n")):
            lines = run_tool(["tool"], timeout=30, line_cb=None)
        assert lines == ["x.example.com"]

    def test_cmd_cb_called_once_before_popen(self) -> None:
        """cmd_cb must be invoked exactly once with the joined command string."""
        calls: list[str] = []
        with patch("subprocess.Popen", return_value=_make_popen("sub.example.com\n")):
            run_tool(["subfinder", "-d", "example.com"], timeout=30, cmd_cb=calls.append)
        assert calls == ["subfinder -d example.com"]

    def test_cmd_cb_not_called_when_none(self) -> None:
        """run_tool must not raise when cmd_cb is None (default path)."""
        with patch("subprocess.Popen", return_value=_make_popen("sub.example.com\n")):
            lines = run_tool(["subfinder", "-d", "example.com"], timeout=30, cmd_cb=None)
        assert lines == ["sub.example.com"]

    def test_cmd_cb_receives_full_command_string(self) -> None:
        """Verify the exact joined string passed to cmd_cb."""
        received: list[str] = []
        cmd = ["gobuster", "dns", "-d", "example.com", "-w", "/tmp/w.txt"]
        with patch("subprocess.Popen", return_value=_make_popen("")):
            run_tool(cmd, timeout=30, cmd_cb=received.append)
        assert received == ["gobuster dns -d example.com -w /tmp/w.txt"]

    def test_cmd_cb_quotes_args_with_spaces(self) -> None:
        """Args containing spaces must be shell-quoted in the cmd_cb string."""
        received: list[str] = []
        cmd = ["ffuf", "-H", "Host: FUZZ.example.com", "-fc", "400,404"]
        with patch("subprocess.Popen", return_value=_make_popen("")):
            run_tool(cmd, timeout=30, cmd_cb=received.append)
        assert len(received) == 1
        # The Host header value must be quoted so the string is shell-safe.
        assert "Host: FUZZ.example.com" in received[0]
        assert received[0].count("Host: FUZZ.example.com") == 1
        # Unquoted form must NOT appear (would break shell copy-paste).
        import shlex
        reparsed = shlex.split(received[0])
        assert "Host: FUZZ.example.com" in reparsed

    def test_capture_stderr_merges_into_stdout(self) -> None:
        """capture_stderr=True passes subprocess.STDOUT as stderr dest."""
        with patch("subprocess.Popen", return_value=_make_popen("line1\n")) as mock_popen:
            run_tool(["tool"], timeout=30, capture_stderr=True)
        _, kwargs = mock_popen.call_args
        assert kwargs["stderr"] == subprocess.STDOUT

    def test_capture_stderr_false_uses_devnull(self) -> None:
        """capture_stderr=False (default) discards stderr."""
        with patch("subprocess.Popen", return_value=_make_popen("line1\n")) as mock_popen:
            run_tool(["tool"], timeout=30, capture_stderr=False)
        _, kwargs = mock_popen.call_args
        assert kwargs["stderr"] == subprocess.DEVNULL

    def test_ignore_returncode_returns_lines_on_nonzero_exit(self) -> None:
        """ignore_returncode=True keeps collected lines even when exit code != 0."""
        with patch("subprocess.Popen", return_value=_make_popen("sub.example.com\n", returncode=1)):
            lines = run_tool(["tool"], timeout=30, ignore_returncode=True)
        assert lines == ["sub.example.com"]

    def test_ignore_returncode_false_drops_lines_on_nonzero_exit(self) -> None:
        """Default behaviour: non-zero exit discards collected lines."""
        with patch("subprocess.Popen", return_value=_make_popen("sub.example.com\n", returncode=1)):
            lines = run_tool(["tool"], timeout=30, ignore_returncode=False)
        assert lines == []
