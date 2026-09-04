"""mcp-defender-xdr: An MCP server for Microsoft Defender XDR."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

_DISTRIBUTION_NAME = "mcp-defender-xdr"

#: Reported when the package metadata cannot be located — e.g. the source
#: tree is on ``PYTHONPATH`` without ever having been installed.
_UNKNOWN_VERSION = "0.0.0+unknown"


def _detect_version() -> str:
    """Read the installed distribution version, so it cannot drift from ``pyproject.toml``."""
    try:
        return version(_DISTRIBUTION_NAME)
    except PackageNotFoundError:
        return _UNKNOWN_VERSION


__version__ = _detect_version()

__all__ = ["__version__"]
