"""Tests for subdomainenum.checks.passive.crt_sh – crt.sh CT log query via PostgreSQL."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import psycopg2
import pytest

from subdomainenum.checks.passive.crt_sh import query_crt_sh
from subdomainenum.models import SourceResult


def _make_conn(rows: list[tuple[str]]) -> MagicMock:
    """Return a mock psycopg2 connection whose cursor returns *rows*."""
    cur = MagicMock()
    cur.__enter__ = lambda s: s
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchall.return_value = rows

    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn


class TestQueryCrtSh:
    def test_returns_source_result(self) -> None:
        conn = _make_conn([("sub.example.com",), ("*.example.com",)])
        with patch("psycopg2.connect", return_value=conn):
            result = query_crt_sh("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "crt.sh"

    def test_parses_subdomains(self) -> None:
        conn = _make_conn([
            ("mail.example.com",),
            ("www.example.com",),
            ("mail.example.com",),  # duplicate row
        ])
        with patch("psycopg2.connect", return_value=conn):
            result = query_crt_sh("example.com")
        assert "mail.example.com" in result.subdomains
        assert "www.example.com" in result.subdomains
        assert result.subdomains.count("mail.example.com") == 1

    def test_strips_wildcard_prefix(self) -> None:
        conn = _make_conn([("*.example.com",)])
        with patch("psycopg2.connect", return_value=conn):
            result = query_crt_sh("example.com")
        assert "*.example.com" not in result.subdomains
        assert result.subdomains == []

    def test_handles_connection_error(self) -> None:
        with patch("psycopg2.connect", side_effect=psycopg2.OperationalError("timeout")):
            result = query_crt_sh("example.com")
        assert result.available is True  # passive/native source, always available
        assert result.error is not None
        assert result.subdomains == []

    def test_handles_db_error(self) -> None:
        conn = _make_conn([])
        cur = conn.cursor.return_value
        cur.execute.side_effect = psycopg2.DatabaseError("query failed")
        with patch("psycopg2.connect", return_value=conn):
            result = query_crt_sh("example.com")
        assert result.error is not None
        assert result.subdomains == []

    def test_multiline_name_value(self) -> None:
        """NAME_VALUE column can contain newline-separated DNS names."""
        conn = _make_conn([("a.example.com\nb.example.com",)])
        with patch("psycopg2.connect", return_value=conn):
            result = query_crt_sh("example.com")
        assert "a.example.com" in result.subdomains
        assert "b.example.com" in result.subdomains

    def test_filters_out_of_scope_domains(self) -> None:
        conn = _make_conn([
            ("sub.example.com",),
            ("unrelated.com",),
        ])
        with patch("psycopg2.connect", return_value=conn):
            result = query_crt_sh("example.com")
        assert "unrelated.com" not in result.subdomains
        assert "sub.example.com" in result.subdomains

    def test_handles_unexpected_exception(self) -> None:
        """Any exception from psycopg2 is caught and stored in result.error."""
        with patch("psycopg2.connect", side_effect=RuntimeError("unexpected")):
            result = query_crt_sh("example.com")
        assert result.error is not None
        assert "unexpected" in result.error
        assert result.subdomains == []

    def test_cmd_cb_called_with_psql_cmd(self) -> None:
        calls: list[str] = []
        conn = _make_conn([])
        with patch("psycopg2.connect", return_value=conn):
            query_crt_sh("example.com", cmd_cb=calls.append)
        assert len(calls) == 1
        assert "psql" in calls[0]
        assert "crt.sh" in calls[0]
        assert "example.com" in calls[0]

    def test_cmd_cb_not_called_when_none(self) -> None:
        conn = _make_conn([])
        with patch("psycopg2.connect", return_value=conn):
            result = query_crt_sh("example.com", cmd_cb=None)
        assert isinstance(result, SourceResult)

    def test_empty_name_value_row_skipped(self) -> None:
        """Rows with empty or None NAME_VALUE are skipped gracefully."""
        conn = _make_conn([("",), ("sub.example.com",)])
        with patch("psycopg2.connect", return_value=conn):
            result = query_crt_sh("example.com")
        assert result.subdomains == ["sub.example.com"]
