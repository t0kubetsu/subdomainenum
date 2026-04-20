"""Subdomain enumeration – passive and active discovery for a target domain."""

from __future__ import annotations

try:
    from importlib.metadata import version

    __version__ = version("subdomainenum")
except Exception:
    __version__ = "0.11.0"

# NullHandler so library users who have not configured logging
# do not see "No handler found" warnings (PEP 3118 / logging HOWTO).
import logging as _logging

_logging.getLogger("subdomainenum").addHandler(_logging.NullHandler())
del _logging

__all__ = ["__version__"]
