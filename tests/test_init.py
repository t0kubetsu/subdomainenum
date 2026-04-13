"""Tests for subdomainenum.__init__ – version fallback."""

from __future__ import annotations

import importlib
import sys
from unittest.mock import patch


def test_version_fallback_when_metadata_unavailable() -> None:
    """Cover lines 9-10: the except branch when importlib.metadata.version raises."""
    saved = sys.modules.pop("subdomainenum", None)
    try:
        with patch("importlib.metadata.version", side_effect=Exception("pkg not found")):
            fresh = importlib.import_module("subdomainenum")
        assert fresh.__version__ == "0.1.0"
    finally:
        if saved is not None:
            sys.modules["subdomainenum"] = saved
        elif "subdomainenum" in sys.modules:
            del sys.modules["subdomainenum"]
