"""Per-call context handed to tool runners."""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from types import TracebackType
from typing import Self

import httpx

from .auth import (
    ARM_RESOURCE,
    ARM_SCOPE,
    LOG_ANALYTICS_RESOURCE,
    LOG_ANALYTICS_SCOPE,
    SentinelWorkspace,
    TokenManager,
)
from .defender_client import DefenderApi, DefenderClient
from .fixtures import FixtureClient, FixtureStore

_USER_AGENT = "mcp-defender-xdr/0.1 (+https://github.com/MFisher14/mcp-defender-xdr)"


API_DEFENDER = "defender"
API_LOG_ANALYTICS = "log_analytics"
API_ARM = "arm"

# api -> (base URL or None for the DEFENDER_API_BASE default, token scope, name)
_APIS: dict[str, tuple[str | None, str | None, str]] = {
    API_DEFENDER: (None, None, "Defender API"),
    API_LOG_ANALYTICS: (LOG_ANALYTICS_RESOURCE, LOG_ANALYTICS_SCOPE, "Log Analytics API"),
    API_ARM: (ARM_RESOURCE, ARM_SCOPE, "Azure Resource Manager"),
}


class ToolContext(AbstractAsyncContextManager["ToolContext"]):
    """Shared execution context for a single MCP tool call.

    Backed either by a live :class:`TokenManager` (real Defender API calls) or by
    a :class:`FixtureStore` (offline synthetic responses). Exactly one of the two
    must be supplied; there is no mode where both or neither is available, so a
    context can never silently fall back from one to the other.
    """

    def __init__(
        self,
        token_manager: TokenManager | None = None,
        *,
        http_client: httpx.AsyncClient | None = None,
        max_fan_out: int = 5,
        fixtures: FixtureStore | None = None,
    ) -> None:
        if (token_manager is None) == (fixtures is None):
            raise ValueError(
                "ToolContext requires exactly one of token_manager or fixtures "
                "(live mode or fixture mode, never both and never neither)."
            )
        self._token_manager = token_manager
        self._fixtures = fixtures
        self._max_fan_out = max_fan_out
        # Fixture mode issues no requests, so it builds no HTTP stack at all.
        self._owns_http = fixtures is None and http_client is None
        self._http: httpx.AsyncClient | None = http_client
        if self._http is None and fixtures is None:
            self._http = httpx.AsyncClient(
                headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
            )

    @property
    def token_manager(self) -> TokenManager:
        if self._token_manager is None:
            raise RuntimeError("No token manager: this context is in fixture mode.")
        return self._token_manager

    @property
    def fixture_mode(self) -> bool:
        return self._fixtures is not None

    @property
    def default_tenant_key(self) -> str:
        if self._fixtures is not None:
            return self._fixtures.default_tenant_key
        return self.token_manager.default_tenant_key

    @property
    def max_fan_out(self) -> int:
        return self._max_fan_out

    def available_tenants(self) -> list[str]:
        if self._fixtures is not None:
            return self._fixtures.list_tenants()
        return self.token_manager.list_tenants()

    def sentinel_workspace(self, tenant_key: str) -> SentinelWorkspace | None:
        if self._fixtures is not None:
            return self._fixtures.sentinel_workspaces.get(tenant_key)
        return self.token_manager.sentinel_workspaces().get(tenant_key)

    def client_for(self, tenant_key: str, api: str = API_DEFENDER) -> DefenderApi:
        """A client for one tenant and one upstream API, with that API's pinned scope."""
        if api not in _APIS:
            raise ValueError(f"unknown upstream API: {api}")
        if self._fixtures is not None:
            return FixtureClient(self._fixtures, tenant_key)
        assert self._http is not None  # noqa: S101 - guaranteed by __init__
        base_url, scope, name = _APIS[api]
        return DefenderClient(
            self.token_manager,
            http_client=self._http,
            tenant_key=tenant_key,
            base_url=base_url,
            scope=scope,
            api_name=name,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        del exc_type, exc, tb
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
