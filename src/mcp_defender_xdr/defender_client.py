"""Async HTTP client for the Microsoft Defender XDR API."""

from __future__ import annotations

import asyncio
import os
import secrets
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from types import TracebackType
from typing import Any, Self

import httpx

from .auth import DEFAULT_DEFENDER_RESOURCE, TokenManager
from .errors import (
    AuthError,
    NotFoundError,
    RateLimitedError,
    UpstreamError,
)

_DEFAULT_TIMEOUT_SECONDS = 30.0
_MAX_RETRIES = 3
_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_USER_AGENT = "mcp-defender-xdr/0.1 (+https://github.com/MFisher14/mcp-defender-xdr)"


def _default_base_url() -> str:
    return os.environ.get("DEFENDER_API_BASE", DEFAULT_DEFENDER_RESOURCE).rstrip("/")


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    if seconds < 0:
        return None
    return min(seconds, 60.0)


class DefenderClient(AbstractAsyncContextManager["DefenderClient"]):
    """Thin async wrapper around the Defender API."""

    def __init__(
        self,
        token_manager: TokenManager,
        *,
        base_url: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.AsyncClient | None = None,
        max_retries: int = _MAX_RETRIES,
        tenant_key: str = "default",
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._token_manager = token_manager
        self._tenant_key = tenant_key
        self._base_url = (base_url or _default_base_url()).rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._sleep: Callable[[float], Awaitable[None]] = sleep or asyncio.sleep
        self._owns_client = http_client is None
        self._http: httpx.AsyncClient = http_client or httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
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
        if self._owns_client:
            await self._http.aclose()

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, *, json: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("POST", path, json=json)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = self._build_url(path)
        attempt = 0
        retried_after_401 = False

        while True:
            token = self._token_manager.get_token(self._tenant_key)
            headers = {"Authorization": f"Bearer {token}"}
            try:
                response = await self._http.request(
                    method,
                    url,
                    params=dict(params) if params else None,
                    json=dict(json) if json else None,
                    headers=headers,
                )
            except httpx.TimeoutException as exc:
                if attempt < self._max_retries:
                    await self._backoff(attempt, retry_after=None)
                    attempt += 1
                    continue
                raise UpstreamError("Defender API request timed out") from exc
            except httpx.HTTPError as exc:
                raise UpstreamError("Defender API network error") from exc

            if 200 <= response.status_code < 300:
                return self._parse_json(response)

            if response.status_code == 401 and not retried_after_401:
                retried_after_401 = True
                self._token_manager.invalidate(self._tenant_key)
                continue

            if response.status_code == 401:
                raise AuthError("Defender API rejected the access token")

            if response.status_code == 404:
                raise NotFoundError(
                    "Defender API returned 404 Not Found",
                    status_code=response.status_code,
                )

            if response.status_code in _RETRYABLE_STATUSES and attempt < self._max_retries:
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                await self._backoff(attempt, retry_after=retry_after)
                attempt += 1
                continue

            if response.status_code == 429:
                raise RateLimitedError(
                    "Defender API rate limit exceeded; retries exhausted",
                    status_code=response.status_code,
                )

            raise UpstreamError(
                f"Defender API returned HTTP {response.status_code}",
                status_code=response.status_code,
            )

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return f"{self._base_url}{path}"

    @staticmethod
    def _parse_json(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise UpstreamError("Defender API returned non-JSON response") from exc
        if not isinstance(payload, dict):
            raise UpstreamError("Defender API returned unexpected JSON shape")
        return payload

    async def _backoff(self, attempt: int, *, retry_after: float | None) -> None:
        if retry_after is not None:
            delay = retry_after
        else:
            cap_ms = min(2**attempt, 8) * 1000
            delay = secrets.randbelow(cap_ms + 1) / 1000.0
        await self._sleep(delay)
