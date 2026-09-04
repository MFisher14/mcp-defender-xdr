"""The package version must track the installed distribution metadata."""

from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from typing import Any

import pytest

import mcp_defender_xdr
from mcp_defender_xdr import __version__, _detect_version
from mcp_defender_xdr.auth import TokenManager
from mcp_defender_xdr.server import build_server

from .conftest import FakeCredentialProvider, FakeMsalApp

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_version() -> str:
    with _PYPROJECT.open("rb") as handle:
        version: str = tomllib.load(handle)["project"]["version"]
    return version


def test_version_matches_pyproject() -> None:
    assert __version__ == _declared_version()


def test_detect_version_reads_distribution_metadata() -> None:
    assert _detect_version() == _declared_version()


def test_detect_version_falls_back_when_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(_name: str) -> str:
        raise PackageNotFoundError("mcp-defender-xdr")

    monkeypatch.setattr(mcp_defender_xdr, "version", _raise)
    assert _detect_version() == "0.0.0+unknown"


def test_server_advertises_package_version() -> None:
    def factory(**_: Any) -> Any:
        return FakeMsalApp()

    server = build_server(TokenManager(FakeCredentialProvider(), msal_factory=factory))
    assert server.version == __version__
    assert server.create_initialization_options().server_version == __version__
