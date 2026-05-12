"""Tests for the three tool implementations and the fan-out runtime."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from mcp_defender_xdr.errors import (
    AuthError,
    InvalidInputError,
    NotFoundError,
    RateLimitedError,
    UpstreamError,
)
from mcp_defender_xdr.tools import advanced_hunting, alerts, incidents

# ---------- query_advanced_hunting ----------


async def test_advanced_hunting_success(make_context) -> None:
    received: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        received["path"] = request.url.path
        received["method"] = request.method
        received["auth"] = request.headers.get("Authorization")
        return httpx.Response(
            200,
            json={
                "Schema": [{"Name": "Timestamp", "Type": "DateTime"}],
                "Results": [{"Timestamp": "2026-05-01T00:00:00Z"}],
            },
        )

    ctx, _ = make_context(handler)
    async with ctx:
        result = await advanced_hunting.run(
            ctx, {"query": "DeviceEvents | take 1", "timespan": "P1D"}
        )

    assert received["method"] == "POST"
    assert received["path"] == "/api/advancedqueries/run"
    assert received["auth"] is not None
    assert received["auth"].startswith("Bearer ")
    assert len(result["rows"]) == 1
    assert result["metadata"]["row_count"] == 1
    assert result["metadata"]["column_count"] == 1


async def test_advanced_hunting_rejects_destructive_query(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("upstream must not be called for invalid input")

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await advanced_hunting.run(ctx, {"query": ".drop table users"})


async def test_advanced_hunting_oversized_query_rejected(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("upstream must not be called")

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await advanced_hunting.run(ctx, {"query": "x" * 10_001})


# ---------- get_incident ----------


async def test_get_incident_success(make_context) -> None:
    payload = {
        "incidentId": "INC-1",
        "incidentName": "Suspicious PowerShell",
        "severity": "High",
        "status": "Active",
        "alerts": [
            {
                "id": "a1",
                "entities": [{"entityType": "User", "userPrincipalName": "alice@example.com"}],
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/incidents/INC-1"
        return httpx.Response(200, json=payload)

    ctx, _ = make_context(handler)
    async with ctx:
        result = await incidents.run(ctx, {"incident_id": "INC-1"})

    assert result["incident_id"] == "INC-1"
    assert result["title"] == "Suspicious PowerShell"
    assert len(result["alerts"]) == 1
    assert len(result["entities"]) == 1


async def test_get_incident_not_found(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"message": "not found"}})

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(NotFoundError):
            await incidents.run(ctx, {"incident_id": "missing"})


async def test_get_incident_rejects_path_traversal(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("upstream must not be called")

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await incidents.run(ctx, {"incident_id": "../../etc/passwd"})


# ---------- list_alerts ----------


async def test_list_alerts_no_filters(make_context) -> None:
    received: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        received["params"] = dict(request.url.params)
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "a1",
                        "title": "Suspicious",
                        "severity": "High",
                        "status": "New",
                        "category": "Execution",
                    }
                ]
            },
        )

    ctx, _ = make_context(handler)
    async with ctx:
        result = await alerts.run(ctx, {})

    assert received["params"] == {"$top": "25"}
    assert result["metadata"]["count"] == 1
    assert result["alerts"][0]["title"] == "Suspicious"


async def test_list_alerts_with_filters(make_context) -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"value": []})

    ctx, _ = make_context(handler)
    async with ctx:
        result = await alerts.run(ctx, {"severity": "Medium", "status": "InProgress", "limit": 10})

    assert captured["params"]["$top"] == "10"
    assert "severity eq 'Medium'" in captured["params"]["$filter"]
    assert "status eq 'InProgress'" in captured["params"]["$filter"]
    assert result["metadata"]["count"] == 0


async def test_list_alerts_rejects_bad_severity(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("upstream must not be called")

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await alerts.run(ctx, {"severity": "Critical"})


# ---------- defender_client error handling ----------


async def test_rate_limit_retries_then_succeeds(make_context) -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        if call_count["n"] <= 2:
            return httpx.Response(429, headers={"Retry-After": "1"}, json={})
        return httpx.Response(200, json={"value": []})

    ctx, sleeps = make_context(handler)
    async with ctx:
        result = await alerts.run(ctx, {})

    assert call_count["n"] == 3
    assert len(sleeps) == 2
    assert all(s == 1.0 for s in sleeps)
    assert result["alerts"] == []


async def test_rate_limit_exhausts_retries(make_context) -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(429, headers={"Retry-After": "0"}, json={})

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(RateLimitedError):
            await alerts.run(ctx, {})
    assert call_count["n"] == 4


async def test_server_error_retried_then_raised(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={})

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(UpstreamError):
            await alerts.run(ctx, {})


async def test_401_refreshes_token_once(make_context, fake_msal_app) -> None:
    fake_msal_app.results = [
        {"access_token": "stale", "expires_in": 3600},
        {"access_token": "fresh", "expires_in": 3600},
    ]
    tokens_seen: list[str] = []
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        tokens_seen.append(request.headers.get("Authorization", ""))
        call_count["n"] += 1
        if call_count["n"] == 1:
            return httpx.Response(401, json={"error": "expired"})
        return httpx.Response(200, json={"value": []})

    ctx, _ = make_context(handler)
    async with ctx:
        await alerts.run(ctx, {})

    assert tokens_seen[0] == "Bearer stale"
    assert tokens_seen[1] == "Bearer fresh"


async def test_persistent_401_becomes_auth_error(make_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "expired"})

    ctx, _ = make_context(handler)
    async with ctx:
        with pytest.raises(AuthError):
            await alerts.run(ctx, {})


# ---------- server-level error mapping ----------


async def test_server_dispatch_maps_known_error(make_context) -> None:
    from mcp_defender_xdr.errors import ErrorCode
    from mcp_defender_xdr.server import _dispatch

    async def failing_handler(ctx, params):
        raise InvalidInputError("bad input")

    ctx, _ = make_context(lambda r: httpx.Response(500))
    async with ctx:
        result = await _dispatch(failing_handler, ctx, {}, "x")

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == ErrorCode.INVALID_INPUT.value


async def test_server_dispatch_maps_unhandled_to_internal(make_context) -> None:
    from mcp_defender_xdr.errors import ErrorCode
    from mcp_defender_xdr.server import _dispatch

    async def boom(ctx, params):
        raise RuntimeError("internal detail with secret token-xyz")

    ctx, _ = make_context(lambda r: httpx.Response(500))
    async with ctx:
        result = await _dispatch(boom, ctx, {}, "x")

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == ErrorCode.INTERNAL_ERROR.value
    assert "token-xyz" not in result.structuredContent["error"]["message"]


# ---------- multi-tenant + fan-out ----------


async def test_explicit_tenant_routes_to_right_credentials(make_multi_tenant_context) -> None:
    """When `tenant=fabrikam`, the request carries fabrikam's bearer token."""
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(200, json={"value": []})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        await alerts.run(ctx, {"tenant": "fabrikam"})

    assert seen["auth"] == "Bearer token-fabrikam"


async def test_default_tenant_when_omitted(make_multi_tenant_context) -> None:
    """With multi-tenant config, omitting `tenant` uses the configured default."""
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(200, json={"value": []})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        await alerts.run(ctx, {})

    assert seen["auth"] == "Bearer token-contoso"


async def test_unknown_explicit_tenant_rejected(make_multi_tenant_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("upstream must not be called")

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        with pytest.raises(InvalidInputError) as exc_info:
            await alerts.run(ctx, {"tenant": "ghost-tenant"})
    assert "ghost-tenant" not in str(exc_info.value)


async def test_fan_out_aggregates_per_tenant(make_multi_tenant_context) -> None:
    """`tenant="*"` queries each tenant and aggregates labelled results."""
    seen_tokens: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_tokens.append(request.headers.get("Authorization", ""))
        return httpx.Response(
            200,
            json={"value": [{"id": "a1", "title": "alpha", "severity": "High", "status": "New"}]},
        )

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await alerts.run(ctx, {"tenant": "*"})

    assert result["fan_out"] is True
    assert sorted(result["tenants"]) == ["contoso", "fabrikam"]
    assert len(result["results"]) == 2
    by_tenant = {r["tenant"]: r for r in result["results"]}
    assert "result" in by_tenant["contoso"]
    assert "result" in by_tenant["fabrikam"]
    assert sorted(seen_tokens) == sorted(["Bearer token-contoso", "Bearer token-fabrikam"])


async def test_fan_out_partial_failure(make_multi_tenant_context) -> None:
    """One tenant returning 500 produces a per-tenant error; others still succeed."""

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "fabrikam" in auth:
            return httpx.Response(503, json={})
        return httpx.Response(200, json={"value": []})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await alerts.run(ctx, {"tenant": "*"})

    by_tenant = {r["tenant"]: r for r in result["results"]}
    assert "result" in by_tenant["contoso"]
    assert "error" in by_tenant["fabrikam"]
    assert by_tenant["fabrikam"]["error"]["code"] == "upstream_error"


async def test_fan_out_unhandled_exception_per_tenant(
    make_multi_tenant_context, monkeypatch
) -> None:
    """A non-DefenderError raised inside the per-tenant call is caught and surfaced."""
    call_count = {"n": 0}

    real_summarize = alerts._summarize

    def flaky_summarize(alert):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("kaboom")
        return real_summarize(alert)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": [{"id": "x"}]})

    monkeypatch.setattr(alerts, "_summarize", flaky_summarize)

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await alerts.run(ctx, {"tenant": "*"})

    by_tenant = {r["tenant"]: r for r in result["results"]}
    errors = [t for t, r in by_tenant.items() if "error" in r]
    oks = [t for t, r in by_tenant.items() if "result" in r]
    assert len(errors) == 1
    assert len(oks) == 1
    assert by_tenant[errors[0]]["error"]["code"] == "internal_error"


async def test_fan_out_respects_max_fan_out(make_multi_tenant_context) -> None:
    """Concurrency bound prevents more than `max_fan_out` simultaneous requests."""
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def gate_handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, max_in_flight
        async with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.01)
        async with lock:
            in_flight -= 1
        return httpx.Response(200, json={"value": []})

    ctx, _ = make_multi_tenant_context(gate_handler, max_fan_out=1)
    async with ctx:
        result = await alerts.run(ctx, {"tenant": "*"})

    assert len(result["results"]) == 2
    assert max_in_flight == 1


async def test_advanced_hunting_explicit_tenant(make_multi_tenant_context) -> None:
    """The fan-out runtime also wraps `query_advanced_hunting`."""
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(200, json={"Schema": [], "Results": []})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await advanced_hunting.run(
            ctx, {"query": "DeviceEvents | take 1", "tenant": "contoso"}
        )

    assert seen["auth"] == "Bearer token-contoso"
    assert result["metadata"]["row_count"] == 0
