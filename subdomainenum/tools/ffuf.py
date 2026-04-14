"""Wrapper for ffuf HTTP virtual host fuzzing."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import VhostResult

_DEFAULT_FILTER_CODES = {404, 400}


def _parse_ffuf_json(
    data: dict,
    domain: str,
    filter_codes: set[int],
) -> list[VhostResult]:
    """Parse a ffuf JSON output dict into :class:`~subdomainenum.models.VhostResult` objects.

    :param data: Parsed JSON dict from ffuf (``{"results": [...]}`` shape).
    :param domain: Base domain used to construct the vhost FQDN.
    :param filter_codes: HTTP status codes to exclude.
    :returns: List of matching :class:`~subdomainenum.models.VhostResult` objects.
    :rtype: list[VhostResult]
    """
    results: list[VhostResult] = []
    for hit in data.get("results", []):
        status_code = hit.get("status", 0)
        if status_code in filter_codes:
            continue
        fuzz_word = hit.get("input", {}).get("FUZZ", "")
        if not fuzz_word:
            continue
        content_length = hit.get("length", 0)
        vhost = f"{fuzz_word}.{domain}"
        results.append(VhostResult(vhost=vhost, status_code=status_code, content_length=content_length))
    return results


def run_ffuf(
    domain: str,
    *,
    url: str,
    wordlist: str,
    threads: int = 40,
    timeout: int = 300,
    filter_codes: set[int] | None = None,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> list[VhostResult]:
    """Run ffuf to fuzz virtual hosts via the Host header.

    Each word from *wordlist* is substituted as ``FUZZ`` in the Host header
    value ``FUZZ.<domain>``.  Results are written to a temporary JSON file
    via ``-of json -o <file>`` so that output is captured reliably even in
    non-TTY subprocess environments (e.g. Docker) where ffuf suppresses its
    human-readable stdout.

    :param domain: Target base domain (used to build Host header values).
    :param url: Target URL (e.g. ``"http://10.0.0.1"``).
    :param wordlist: Absolute path to a vhost wordlist.
    :param threads: Number of concurrent threads.
    :param timeout: Maximum seconds to wait for ffuf.
    :param filter_codes: HTTP status codes to exclude from results.
        Defaults to ``{404, 400}``.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :returns: List of :class:`~subdomainenum.models.VhostResult` with
        non-filtered status codes.
    :rtype: list[VhostResult]
    """
    if filter_codes is None:
        filter_codes = _DEFAULT_FILTER_CODES

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        output_file: str = tf.name
    cleanup = True

    try:
        cmd = [
            "ffuf",
            "-w", wordlist,
            "-u", url,
            "-H", f"Host: FUZZ.{domain}",
            "-t", str(threads),
            "-fc", ",".join(str(c) for c in sorted(filter_codes)),
            "-ac",
            "-noninteractive",
            "-s",
            "-of", "json",
            "-o", output_file,
        ]
        try:
            run_tool(cmd, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb,
                     ignore_returncode=True, capture_stderr=True)
        except RuntimeError:
            return []

        try:
            with open(output_file) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return []

        return _parse_ffuf_json(data, domain, filter_codes)

    finally:
        try:
            os.unlink(output_file)
        except OSError:
            pass
