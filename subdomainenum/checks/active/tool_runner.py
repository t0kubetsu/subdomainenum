"""Generic subprocess wrapper for external enumeration tools."""

from __future__ import annotations

import subprocess
import threading
from typing import Callable


def run_tool(
    cmd: list[str],
    timeout: int = 120,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> list[str]:
    """Run *cmd* as a subprocess and return its stdout as a list of non-empty lines.

    :param cmd: Command and arguments to execute.
    :param timeout: Maximum seconds to wait for the process.  On timeout,
        an empty list is returned rather than raising.
    :param line_cb: Optional callback invoked with each non-empty line as it
        arrives from the process's stdout (useful for real-time debug output).
    :param cmd_cb: Optional callback invoked once with the full command string
        immediately before the subprocess is launched (useful for showing the
        command in debug panels).
    :returns: Non-empty, stripped stdout lines.
    :rtype: list[str]
    :raises RuntimeError: When the binary was not found (``FileNotFoundError``).
    """
    if cmd_cb is not None:
        cmd_cb(" ".join(cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(f"{cmd[0]!r} not found – is it installed and on your PATH?")

    lines: list[str] = []

    def _read() -> None:
        assert proc.stdout is not None  # noqa: S101 – guaranteed by PIPE
        for raw_line in proc.stdout:
            stripped = raw_line.strip()
            if stripped:
                if line_cb is not None:
                    line_cb(stripped)
                lines.append(stripped)

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    reader.join(timeout=timeout)

    if reader.is_alive():
        proc.kill()
        if proc.stdout:
            proc.stdout.close()
        return []

    proc.wait()

    if proc.returncode != 0:
        return []

    return lines
