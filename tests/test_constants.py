"""Tests for subdomainenum.constants – tool registry and detection."""

from __future__ import annotations

from unittest.mock import patch

from subdomainenum.constants import ACTIVE_TOOLS, detect_tools, get_install_hint


class TestActiveTools:
    def test_registry_not_empty(self) -> None:
        assert len(ACTIVE_TOOLS) > 0

    def test_required_tools_present(self) -> None:
        required = {"subfinder", "amass", "findomain", "assetfinder", "dnsrecon", "gobuster", "ffuf"}
        assert required.issubset(ACTIVE_TOOLS.keys())

    def test_each_tool_has_binary_key(self) -> None:
        for name, info in ACTIVE_TOOLS.items():
            assert "binary" in info, f"{name} missing 'binary' key"

    def test_each_tool_has_install_hint(self) -> None:
        for name, info in ACTIVE_TOOLS.items():
            assert "install" in info, f"{name} missing 'install' key"


class TestDetectTools:
    def test_returns_dict_with_all_tool_names(self) -> None:
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/tool"
            result = detect_tools()
        assert set(result.keys()) == set(ACTIVE_TOOLS.keys())

    def test_tool_found_when_which_returns_path(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/subfinder"):
            result = detect_tools()
        assert result["subfinder"] is True

    def test_tool_missing_when_which_returns_none(self) -> None:
        with patch("shutil.which", return_value=None):
            result = detect_tools()
        for name in ACTIVE_TOOLS:
            assert result[name] is False


class TestGetInstallHint:
    def test_returns_string_for_known_tool(self) -> None:
        hint = get_install_hint("subfinder")
        assert isinstance(hint, str)
        assert len(hint) > 0

    def test_returns_string_for_unknown_tool(self) -> None:
        hint = get_install_hint("nonexistent_tool_xyz")
        assert isinstance(hint, str)
