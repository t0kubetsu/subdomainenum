"""Tests for subdomainenum.dns_utils – DNS resolution helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from subdomainenum.dns_utils import is_alive, resolve_ips


class TestResolveIps:
    def test_returns_list_of_strings(self) -> None:
        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([MagicMock(address="1.2.3.4")]))
        with patch("dns.resolver.resolve", return_value=mock_answer):
            result = resolve_ips("sub.example.com")
        assert isinstance(result, list)

    def test_returns_empty_on_nxdomain(self) -> None:
        import dns.resolver

        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
            result = resolve_ips("nonexistent.example.com")
        assert result == []

    def test_returns_empty_on_no_answer(self) -> None:
        import dns.resolver

        with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer):
            result = resolve_ips("sub.example.com")
        assert result == []

    def test_returns_empty_on_timeout(self) -> None:
        import dns.exception

        with patch("dns.resolver.resolve", side_effect=dns.exception.Timeout):
            result = resolve_ips("sub.example.com")
        assert result == []

    def test_deduplicates_results(self) -> None:
        rdata1 = MagicMock()
        rdata1.address = "1.2.3.4"
        rdata2 = MagicMock()
        rdata2.address = "1.2.3.4"
        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([rdata1, rdata2]))
        with patch("dns.resolver.resolve", return_value=mock_answer):
            result = resolve_ips("sub.example.com")
        assert result.count("1.2.3.4") == 1


class TestIsAlive:
    def test_alive_when_ips_returned(self) -> None:
        with patch("subdomainenum.dns_utils.resolve_ips", return_value=["1.2.3.4"]):
            assert is_alive("sub.example.com") is True

    def test_dead_when_no_ips(self) -> None:
        with patch("subdomainenum.dns_utils.resolve_ips", return_value=[]):
            assert is_alive("sub.example.com") is False
