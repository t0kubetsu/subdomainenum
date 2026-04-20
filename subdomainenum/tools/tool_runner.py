"""Generic subprocess wrapper for external enumeration tools."""

from __future__ import annotations

import shlex
import subprocess
import threading
import time
from typing import Callable


def run_tool(
    cmd: list[str],
    timeout: int = 120,
    idle_timeout: int | None = None,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
    capture_stderr: bool = False,
    ignore_returncode: bool = False,
) -> tuple[list[str], bool]:
    """Run *cmd* as a subprocess and return its output lines and a timeout flag.

    :param cmd: Command and arguments to execute.
    :param timeout: Absolute maximum seconds to wait for the process.  On timeout,
        any lines already collected are returned (partial results) rather than raising.
        When *idle_timeout* is also set, this acts as a hard ceiling.
    :param idle_timeout: When set, the process is killed after this many seconds
        of silence (no output lines received), even if *timeout* has not elapsed.
        The idle window resets on every output line.  Useful for long-running tools
        like amass that produce bursts of output interspersed with quiet periods.
    :param line_cb: Optional callback invoked with each non-empty line as it
        arrives from the process's output (useful for real-time debug output).
    :param cmd_cb: Optional callback invoked once with the full command string
        immediately before the subprocess is launched (useful for showing the
        command in debug panels).
    :param capture_stderr: When ``True``, merge stderr into stdout so that tools
        writing output via the logging module (e.g. dnsrecon) are captured too.
    :param ignore_returncode: When ``True``, return collected lines even if the
        process exits with a non-zero code (useful for tools that report partial
        failures via exit code but still emit valid results, e.g. dnsrecon when
        AXFR is refused).
    :returns: Tuple of (non-empty stripped output lines, timed_out flag).
        ``timed_out`` is ``True`` only when the process was killed due to timeout.
    :rtype: tuple[list[str], bool]
    :raises RuntimeError: When the binary was not found (``FileNotFoundError``).
    """
    if cmd_cb is not None:
        cmd_cb(shlex.join(cmd))
    stderr_dest = subprocess.STDOUT if capture_stderr else subprocess.DEVNULL
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=stderr_dest,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(f"{cmd[0]!r} not found – is it installed and on your PATH?")

    lines: list[str] = []

    # When idle_timeout is active, wrap line_cb to track the last activity time.
    _effective_line_cb = line_cb
    _last_line_time: list[float] = []
    if idle_timeout is not None:
        _last_line_time.append(time.monotonic())
        _orig_cb = line_cb

        def _tracking_cb(line: str) -> None:
            _last_line_time[0] = time.monotonic()
            if _orig_cb is not None:
                _orig_cb(line)

        _effective_line_cb = _tracking_cb

    def _read() -> None:
        assert proc.stdout is not None  # noqa: S101 – guaranteed by PIPE
        for raw_line in proc.stdout:
            stripped = raw_line.strip()
            if stripped:
                if _effective_line_cb is not None:
                    _effective_line_cb(stripped)
                lines.append(stripped)

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()

    if idle_timeout is None:
        reader.join(timeout=timeout)
    else:
        # Poll at 0.5 s intervals; break when idle or hard timeout fires.
        _start = time.monotonic()
        while reader.is_alive():
            reader.join(timeout=0.5)
            if reader.is_alive():
                now = time.monotonic()
                if (now - _last_line_time[0] >= idle_timeout
                        or now - _start >= timeout):
                    break

    if reader.is_alive():
        proc.kill()
        # Do NOT close proc.stdout here: the reader thread is still iterating it
        # and an explicit close races with `for raw_line in proc.stdout`, raising
        # ValueError("I/O operation on closed file"). After SIGKILL the kernel
        # tears down the child's fds, closing the pipe's write end → the reader's
        # loop sees EOF and exits cleanly.
        reader.join(2)
        return list(lines), True  # partial results collected before the timeout

    proc.wait()

    if proc.returncode != 0 and not ignore_returncode:
        return [], False

    return lines, False
