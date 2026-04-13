"""Tests for subdomainenum.checks.passive.crt_sh – crt.sh CT log query."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from subdomainenum.checks.passive.crt_sh import query_crt_sh
from subdomainenum.models import SourceResult


class TestQueryCrtSh:
    def test_returns_source_result(self) -> None:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = [
            {"name_value": "sub.example.com"},
            {"name_value": "*.example.com"},
        ]
        with patch("requests.get", return_value=mock_resp):
            result = query_crt_sh("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "crt.sh"

    def test_parses_subdomains(self) -> None:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = [
            {"name_value": "mail.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "mail.example.com"},  # duplicate
        ]
        with patch("requests.get", return_value=mock_resp):
            result = query_crt_sh("example.com")
        assert "mail.example.com" in result.subdomains
        assert "www.example.com" in result.subdomains
        # deduplication
        assert result.subdomains.count("mail.example.com") == 1

    def test_strips_wildcard_prefix(self) -> None:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = [{"name_value": "*.example.com"}]
        with patch("requests.get", return_value=mock_resp):
            result = query_crt_sh("example.com")
        # Wildcard entries are skipped or stripped – not included as-is
        assert "*.example.com" not in result.subdomains

    def test_handles_request_error(self) -> None:
        import requests

        with patch("requests.get", side_effect=requests.RequestException("timeout")):
            result = query_crt_sh("example.com")
        assert result.available is True  # source is passive/native, always available
        assert result.error is not None
        assert result.subdomains == []

    def test_handles_http_error(self) -> None:
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 503
        with patch("requests.get", return_value=mock_resp):
            result = query_crt_sh("example.com")
        assert result.error is not None

    def test_multiline_name_value(self) -> None:
        """crt.sh can return newline-separated entries in one name_value field."""
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = [{"name_value": "a.example.com\nb.example.com"}]
        with patch("requests.get", return_value=mock_resp):
            result = query_crt_sh("example.com")
        assert "a.example.com" in result.subdomains
        assert "b.example.com" in result.subdomains

    def test_filters_out_of_scope_domains(self) -> None:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = [
            {"name_value": "sub.example.com"},
            {"name_value": "unrelated.com"},
        ]
        with patch("requests.get", return_value=mock_resp):
            result = query_crt_sh("example.com")
        assert "unrelated.com" not in result.subdomains

    def test_json_parse_error_sets_error(self) -> None:
        """Cover lines 38-40: ValueError from resp.json() is captured."""
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.side_effect = ValueError("Unexpected token")
        with patch("requests.get", return_value=mock_resp):
            result = query_crt_sh("example.com")
        assert result.error is not None
        assert "JSON" in result.error
        assert result.subdomains == []

    def test_cmd_cb_called_with_url(self) -> None:
        calls: list[str] = []
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = []
        with patch("requests.get", return_value=mock_resp):
            query_crt_sh("example.com", cmd_cb=calls.append)
        assert len(calls) == 1
        assert "crt.sh" in calls[0]
        assert "example.com" in calls[0]

    def test_cmd_cb_not_called_when_none(self) -> None:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = []
        with patch("requests.get", return_value=mock_resp):
            result = query_crt_sh("example.com", cmd_cb=None)
        assert isinstance(result, SourceResult)
