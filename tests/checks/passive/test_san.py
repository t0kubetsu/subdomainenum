"""Tests for subdomainenum.checks.passive.san – TLS certificate SAN extraction."""

from __future__ import annotations

import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest

from subdomainenum.checks.passive.san import _fetch_san, query_san
from subdomainenum.models import SourceResult


class TestQuerySan:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.passive.san._fetch_san", return_value=["www.example.com"]):
            result = query_san("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "san"

    def test_parses_san_entries(self) -> None:
        with patch(
            "subdomainenum.checks.passive.san._fetch_san",
            return_value=["www.example.com", "mail.example.com"],
        ):
            result = query_san("example.com")
        assert "www.example.com" in result.subdomains
        assert "mail.example.com" in result.subdomains

    def test_handles_connection_error(self) -> None:
        with patch(
            "subdomainenum.checks.passive.san._fetch_san",
            side_effect=OSError("connection refused"),
        ):
            result = query_san("example.com")
        assert result.error is not None
        assert result.subdomains == []

    def test_filters_out_of_scope(self) -> None:
        with patch(
            "subdomainenum.checks.passive.san._fetch_san",
            return_value=["sub.example.com", "other.com"],
        ):
            result = query_san("example.com")
        assert "other.com" not in result.subdomains
        assert "sub.example.com" in result.subdomains

    def test_deduplicates(self) -> None:
        with patch(
            "subdomainenum.checks.passive.san._fetch_san",
            return_value=["sub.example.com", "sub.example.com"],
        ):
            result = query_san("example.com")
        assert result.subdomains.count("sub.example.com") == 1

    def test_filters_wildcard_entries(self) -> None:
        """Cover line 60: wildcard entries are skipped via `continue`."""
        with patch(
            "subdomainenum.checks.passive.san._fetch_san",
            return_value=["*.example.com", "www.example.com"],
        ):
            result = query_san("example.com")
        assert "*.example.com" not in result.subdomains
        assert "www.example.com" in result.subdomains


class TestFetchSan:
    def _make_ctx_and_raw(self, cert: dict):
        """Build ssl/socket mocks for _fetch_san."""
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = cert
        # wrap_socket returns mock_tls which is used as a context manager
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        mock_raw = MagicMock()
        mock_raw.__enter__ = MagicMock(return_value=mock_raw)
        mock_raw.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls
        return mock_ctx, mock_raw

    def test_returns_dns_sans(self) -> None:
        cert = {"subjectAltName": [("DNS", "www.example.com"), ("DNS", "mail.example.com"), ("IP", "1.2.3.4")]}
        mock_ctx, mock_raw = self._make_ctx_and_raw(cert)
        with (
            patch("ssl.create_default_context", return_value=mock_ctx),
            patch("socket.create_connection", return_value=mock_raw),
        ):
            sans = _fetch_san("example.com")
        assert "www.example.com" in sans
        assert "mail.example.com" in sans
        # IP entries are not included
        assert "1.2.3.4" not in sans

    def test_returns_empty_when_no_cert(self) -> None:
        mock_ctx, mock_raw = self._make_ctx_and_raw({})
        with (
            patch("ssl.create_default_context", return_value=mock_ctx),
            patch("socket.create_connection", return_value=mock_raw),
        ):
            sans = _fetch_san("example.com")
        assert sans == []
