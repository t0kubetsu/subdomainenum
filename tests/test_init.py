"""Tests for subdomainenum.__init__ – version fallback."""

from __future__ import annotations

import importlib
import sys
from unittest.mock import patch


def test_version_fallback_when_metadata_unavailable() -> None:
    """Cover the except branch when importlib.metadata.version raises PackageNotFoundError."""
    from importlib.metadata import PackageNotFoundError

    saved = sys.modules.pop("subdomainenum", None)
    try:
        with patch("importlib.metadata.version", side_effect=PackageNotFoundError("subdomainenum")):
            fresh = importlib.import_module("subdomainenum")
        assert fresh.__version__ == "0.14.2"
    finally:
        if saved is not None:
            sys.modules["subdomainenum"] = saved
        elif "subdomainenum" in sys.modules:
            del sys.modules["subdomainenum"]
