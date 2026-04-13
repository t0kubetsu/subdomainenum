"""Tool registry and availability detection for subdomainenum.

:data:`ACTIVE_TOOLS` maps short tool names to metadata needed to locate the
binary and display installation hints.  :func:`detect_tools` checks which
tools are available on the current ``PATH``.
"""

from __future__ import annotations

import shutil

ACTIVE_TOOLS: dict[str, dict[str, str]] = {
    "subfinder": {
        "binary": "subfinder",
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "amass": {
        "binary": "amass",
        "install": "go install -v github.com/owasp-amass/amass/v4/...@master",
    },
    "findomain": {
        "binary": "findomain",
        "install": "cargo install findomain  # or download from github.com/Findomain/Findomain/releases",
    },
    "assetfinder": {
        "binary": "assetfinder",
        "install": "go install github.com/tomnomnom/assetfinder@latest",
    },
    "dnsrecon": {
        "binary": "dnsrecon",
        "install": "pip install dnsrecon  # or: apt install dnsrecon",
    },
    "gobuster": {
        "binary": "gobuster",
        "install": "go install github.com/OJ/gobuster/v3@latest",
    },
    "wfuzz": {
        "binary": "wfuzz",
        "install": "pip install wfuzz",
    },
}


def detect_tools() -> dict[str, bool]:
    """Return a mapping of tool name → availability on the current ``PATH``.

    :returns: Dict where keys are tool names from :data:`ACTIVE_TOOLS` and
        values are ``True`` if the binary was found, ``False`` otherwise.
    :rtype: dict[str, bool]
    """
    return {name: shutil.which(info["binary"]) is not None for name, info in ACTIVE_TOOLS.items()}


def get_install_hint(name: str) -> str:
    """Return the install hint string for a tool.

    :param name: Tool name (key in :data:`ACTIVE_TOOLS`).
    :returns: Install command string, or a generic hint for unknown tools.
    :rtype: str
    """
    info = ACTIVE_TOOLS.get(name)
    if info:
        return info["install"]
    return f"Install '{name}' manually and ensure it is on your PATH."
