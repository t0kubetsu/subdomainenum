"""Wrapper for wfuzz HTTP virtual host fuzzing."""

from __future__ import annotations

import re
from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import VhostResult

# wfuzz output line pattern:
# "000000001:   200        42 L      102 W      1024 Ch     \"admin\""
_WFUZZ_RE = re.compile(
    r"(\d+):\s+(\d+)\s+\d+ L\s+\d+ W\s+(\d+) Ch\s+\"(.+?)\""
)
_DEFAULT_FILTER_CODES = {404, 400}


def run_wfuzz(
    domain: str,
    *,
    url: str,
    wordlist: str,
    threads: int = 40,
    timeout: int = 300,
    filter_codes: set[int] | None = None,
    line_cb: Callable[[str], None] | None = None,
) -> list[VhostResult]:
    """Run wfuzz to fuzz virtual hosts via the Host header.

    The ``FUZZ`` placeholder in *url* is replaced by ``FUZZ.{domain}`` used
    as the ``Host`` header value.

    :param domain: Target base domain (used to build Host header values).
    :param url: Target URL (e.g. ``"http://10.0.0.1"``).
    :param wordlist: Absolute path to a vhost wordlist.
    :param threads: Number of concurrent threads.
    :param timeout: Maximum seconds to wait for wfuzz.
    :param filter_codes: HTTP status codes to exclude from results.
        Defaults to ``{404, 400}``.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :returns: List of :class:`~subdomainenum.models.VhostResult` with
        non-filtered status codes.
    :rtype: list[VhostResult]
    """
    if filter_codes is None:
        filter_codes = _DEFAULT_FILTER_CODES

    cmd = [
        "wfuzz",
        "-c",
        "-w", wordlist,
        "-H", f"Host: FUZZ.{domain}",
        "-t", str(threads),
        "--hc", ",".join(str(c) for c in sorted(filter_codes)),
        url,
    ]
    try:
        lines = run_tool(cmd, timeout=timeout, line_cb=line_cb)
    except RuntimeError:
        return []

    results: list[VhostResult] = []
    for line in lines:
        m = _WFUZZ_RE.search(line)
        if not m:
            continue
        status_code = int(m.group(2))
        content_length = int(m.group(3))
        fuzz_word = m.group(4).strip()
        if status_code in filter_codes:
            continue
        vhost = f"{fuzz_word}.{domain}"
        results.append(VhostResult(vhost=vhost, status_code=status_code, content_length=content_length))

    return results
