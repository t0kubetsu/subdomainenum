"""Tests for subdomainenum.models – data structures and enums."""

from __future__ import annotations

import pytest

from subdomainenum.models import (
    EnumMode,
    EnumReport,
    SourceResult,
    Status,
    SubdomainResult,
    VhostResult,
)


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status_values_are_strings(self) -> None:
        assert Status.FOUND == "FOUND"
        assert Status.NOT_FOUND == "NOT_FOUND"
        assert Status.ALIVE == "ALIVE"
        assert Status.DEAD == "DEAD"
        assert Status.TIMEOUT == "TIMEOUT"
        assert Status.ERROR == "ERROR"
        assert Status.SKIPPED == "SKIPPED"

    def test_status_is_str_subclass(self) -> None:
        assert isinstance(Status.FOUND, str)


# ---------------------------------------------------------------------------
# EnumMode enum
# ---------------------------------------------------------------------------


class TestEnumMode:
    def test_mode_values(self) -> None:
        assert EnumMode.PASSIVE == "passive"
        assert EnumMode.ACTIVE == "active"
        assert EnumMode.ALL == "all"

    def test_mode_is_str_subclass(self) -> None:
        assert isinstance(EnumMode.PASSIVE, str)


# ---------------------------------------------------------------------------
# SubdomainResult
# ---------------------------------------------------------------------------


class TestSubdomainResult:
    def test_minimal_construction(self) -> None:
        r = SubdomainResult(fqdn="sub.example.com")
        assert r.fqdn == "sub.example.com"
        assert r.status == Status.FOUND
        assert r.ip_addresses == []
        assert r.sources == []
        assert r.alive is None

    def test_full_construction(self) -> None:
        r = SubdomainResult(
            fqdn="sub.example.com",
            status=Status.ALIVE,
            ip_addresses=["1.2.3.4"],
            sources=["crt.sh", "subfinder"],
            alive=True,
        )
        assert r.alive is True
        assert "1.2.3.4" in r.ip_addresses
        assert "subfinder" in r.sources


# ---------------------------------------------------------------------------
# VhostResult
# ---------------------------------------------------------------------------


class TestVhostResult:
    def test_minimal_construction(self) -> None:
        v = VhostResult(vhost="admin.example.com", status_code=200)
        assert v.vhost == "admin.example.com"
        assert v.status_code == 200
        assert v.ip == ""
        assert v.content_length == 0

    def test_full_construction(self) -> None:
        v = VhostResult(
            vhost="admin.example.com",
            status_code=301,
            ip="10.0.0.1",
            content_length=1024,
        )
        assert v.ip == "10.0.0.1"
        assert v.content_length == 1024


# ---------------------------------------------------------------------------
# SourceResult
# ---------------------------------------------------------------------------


class TestSourceResult:
    def test_minimal_construction(self) -> None:
        s = SourceResult(name="subfinder")
        assert s.name == "subfinder"
        assert s.subdomains == []
        assert s.error is None
        assert s.available is True

    def test_error_state(self) -> None:
        s = SourceResult(name="amass", error="binary not found", available=False)
        assert s.available is False
        assert s.error == "binary not found"

    def test_subdomains_list(self) -> None:
        s = SourceResult(name="crt.sh", subdomains=["a.example.com", "b.example.com"])
        assert len(s.subdomains) == 2


# ---------------------------------------------------------------------------
# EnumReport
# ---------------------------------------------------------------------------


class TestEnumReport:
    def test_minimal_construction(self) -> None:
        r = EnumReport(domain="example.com")
        assert r.domain == "example.com"
        assert r.mode == EnumMode.ALL
        assert r.subdomains == []
        assert r.vhosts == []
        assert r.sources == []

    def test_with_subdomains(self) -> None:
        subs = [
            SubdomainResult(fqdn="a.example.com", status=Status.ALIVE, alive=True),
            SubdomainResult(fqdn="b.example.com", status=Status.DEAD, alive=False),
            SubdomainResult(fqdn="c.example.com", status=Status.TIMEOUT),
        ]
        r = EnumReport(domain="example.com", mode=EnumMode.ALL, subdomains=subs)
        assert len(r.subdomains) == 3
        assert r.mode == EnumMode.ALL

    def test_with_vhosts(self) -> None:
        vhosts = [VhostResult(vhost="admin.example.com", status_code=200)]
        r = EnumReport(domain="example.com", vhosts=vhosts)
        assert len(r.vhosts) == 1
