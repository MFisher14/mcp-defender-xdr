"""Tests for per-tenant rolling-window quotas (issue #11)."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_defender_xdr.auth import JsonFileCredentialProvider, TokenManager
from mcp_defender_xdr.errors import AuthError, ErrorCode, QuotaExceededError
from mcp_defender_xdr.quota import QuotaTracker, TenantQuota, rows_in
from mcp_defender_xdr.server import build_server
from mcp_defender_xdr.tools import advanced_hunting, alerts


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


# ---------- tracker: request quota ----------


def test_under_quota_is_admitted(clock: FakeClock) -> None:
    tracker = QuotaTracker({"a": TenantQuota(requests_per_minute=3)}, clock=clock)
    tracker.admit("a", "t")
    tracker.admit("a", "t")


def test_at_quota_admits_the_last_request_then_refuses(clock: FakeClock) -> None:
    tracker = QuotaTracker({"a": TenantQuota(requests_per_minute=2)}, clock=clock)
    tracker.admit("a", "t")
    clock.now += 10
    tracker.admit("a", "t")  # second of two: still allowed
    with pytest.raises(QuotaExceededError) as excinfo:
        tracker.admit("a", "t")
    assert excinfo.value.code is ErrorCode.QUOTA_EXCEEDED
    # Oldest request expires 50s from now.
    assert excinfo.value.retry_after_seconds == 50
    assert "requests per minute" in str(excinfo.value)


def test_over_quota_keeps_refusing_without_consuming(clock: FakeClock) -> None:
    tracker = QuotaTracker({"a": TenantQuota(requests_per_minute=1)}, clock=clock)
    tracker.admit("a", "t")
    for _ in range(5):
        with pytest.raises(QuotaExceededError):
            tracker.admit("a", "t")
    # Refused calls are not counted, so the window resets on schedule.
    clock.now += 60.001
    tracker.admit("a", "t")


def test_quota_resets_after_window(clock: FakeClock) -> None:
    tracker = QuotaTracker({"a": TenantQuota(requests_per_minute=2)}, clock=clock)
    tracker.admit("a", "t")
    tracker.admit("a", "t")
    clock.now += 59.9
    with pytest.raises(QuotaExceededError):
        tracker.admit("a", "t")
    clock.now += 0.2
    tracker.admit("a", "t")
    tracker.admit("a", "t")


def test_rolling_window_frees_slots_one_at_a_time(clock: FakeClock) -> None:
    tracker = QuotaTracker({"a": TenantQuota(requests_per_minute=2)}, clock=clock)
    tracker.admit("a", "t")  # t=0
    clock.now += 30
    tracker.admit("a", "t")  # t=30
    clock.now += 31  # t=61: first expired, second still live
    tracker.admit("a", "t")
    with pytest.raises(QuotaExceededError):
        tracker.admit("a", "t")


def test_tenants_without_quota_are_unlimited(clock: FakeClock) -> None:
    tracker = QuotaTracker({"a": TenantQuota(requests_per_minute=1)}, clock=clock)
    for _ in range(100):
        tracker.admit("b", "t")
    tracker.admit("a", "t")


def test_unlimited_quotas_are_dropped() -> None:
    assert QuotaTracker({"a": TenantQuota()}).enabled is False
    assert QuotaTracker({"a": TenantQuota(rows_per_minute=5)}).enabled is True


# ---------- tracker: row quota ----------


def test_row_quota_refuses_once_rows_are_spent(clock: FakeClock) -> None:
    tracker = QuotaTracker({"a": TenantQuota(rows_per_minute=100)}, clock=clock)
    tracker.admit("a", "t")
    tracker.record_rows("a", 60)
    tracker.admit("a", "t")  # 60 < 100: still allowed
    tracker.record_rows("a", 40)
    with pytest.raises(QuotaExceededError) as excinfo:
        tracker.admit("a", "t")
    assert "rows per minute" in str(excinfo.value)
    clock.now += 61
    tracker.admit("a", "t")


def test_record_rows_ignores_untracked_and_zero(clock: FakeClock) -> None:
    tracker = QuotaTracker(
        {"a": TenantQuota(requests_per_minute=5), "b": TenantQuota(rows_per_minute=1)},
        clock=clock,
    )
    tracker.record_rows("a", 1000)  # no row limit on a
    tracker.record_rows("ghost", 1000)
    tracker.record_rows("b", 0)
    tracker.admit("a", "t")
    tracker.admit("b", "t")


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"metadata": {"row_count": 7}}, 7),
        ({"metadata": {"event_count": 3}}, 3),
        ({"metadata": {"alert_count": 2, "count": 9}}, 2),
        ({"metadata": {"count": 4}}, 4),
        ({"metadata": {"row_count": True}}, 1),
        ({"metadata": {"row_count": -1}}, 1),
        ({"incident_id": "x"}, 1),
    ],
)
def test_rows_in(payload: dict[str, Any], expected: int) -> None:
    assert rows_in(payload) == expected


# ---------- audit ----------


def test_quota_decisions_are_audited(clock: FakeClock, caplog: pytest.LogCaptureFixture) -> None:
    tracker = QuotaTracker({"a": TenantQuota(requests_per_minute=1)}, clock=clock)
    with caplog.at_level(logging.INFO, logger="mcp_defender_xdr.audit"):
        tracker.admit("a", "list_alerts")
        with pytest.raises(QuotaExceededError):
            tracker.admit("a", "list_alerts")
    decisions = [
        r.audit_fields  # type: ignore[attr-defined]
        for r in caplog.records
        if r.getMessage() == "quota-decision"
    ]
    assert [d["decision"] for d in decisions] == ["allowed", "denied"]
    assert decisions[1]["reason"] == "requests_per_minute"
    assert decisions[1]["tenant"] == "a"
    assert decisions[1]["tool"] == "list_alerts"


# ---------- config parsing ----------


def _write_tenants(tmp_path: Path, extra: dict[str, Any], **tenant_extra: Any) -> Path:
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"x")
    tenants: dict[str, Any] = {}
    for key in ("contoso", "fabrikam", "tailspin"):
        tenants[key] = {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "client_id": "22222222-2222-2222-2222-222222222222",
            "cert_path": str(pfx),
            **tenant_extra.get(key, {}),
        }
    path = tmp_path / "tenants.json"
    path.write_text(json.dumps({"default": "contoso", "tenants": tenants, **extra}))
    os.chmod(path, 0o600)
    return path


def test_tenants_file_quota_inheritance(tmp_path: Path) -> None:
    path = _write_tenants(
        tmp_path,
        {"default_quota": {"requests_per_minute": 30}},
        fabrikam={"quota": {"requests_per_minute": 5, "rows_per_minute": 5000}},
        tailspin={"quota": None},
    )
    quotas = JsonFileCredentialProvider(path).quotas()
    assert quotas == {
        "contoso": TenantQuota(requests_per_minute=30),
        "fabrikam": TenantQuota(requests_per_minute=5, rows_per_minute=5000),
    }


def test_tenants_file_without_quotas_has_none(tmp_path: Path) -> None:
    assert JsonFileCredentialProvider(_write_tenants(tmp_path, {})).quotas() == {}


@pytest.mark.parametrize(
    "bad",
    [
        {"default_quota": []},
        {"default_quota": {"requests_per_minute": 0}},
        {"default_quota": {"requests_per_minute": "10"}},
        {"default_quota": {"requests_per_minute": True}},
        {"default_quota": {"burst": 3}},
    ],
)
def test_tenants_file_rejects_bad_quota(tmp_path: Path, bad: dict[str, Any]) -> None:
    with pytest.raises(AuthError, match="Invalid quota"):
        JsonFileCredentialProvider(_write_tenants(tmp_path, bad))


# ---------- end to end through the tools ----------


def _rows_handler(n_rows: int):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/alerts":
            return httpx.Response(200, json={"value": [{"id": str(i)} for i in range(n_rows)]})
        return httpx.Response(
            200, json={"Schema": [], "Results": [{"n": i} for i in range(n_rows)]}
        )

    return handler


async def test_fan_out_quota_isolates_the_noisy_tenant(make_multi_tenant_context, clock) -> None:
    ctx, _ = make_multi_tenant_context(_rows_handler(1))
    ctx._quotas = QuotaTracker({"fabrikam": TenantQuota(requests_per_minute=1)}, clock=clock)
    async with ctx:
        first = await alerts.run(ctx, {"tenant": "*"})
        second = await alerts.run(ctx, {"tenant": "*"})

    assert all("result" in r for r in first["results"])
    by_tenant = {r["tenant"]: r for r in second["results"]}
    assert "result" in by_tenant["contoso"]
    assert by_tenant["fabrikam"]["error"]["code"] == "quota_exceeded"


async def test_row_quota_counts_rows_returned(make_multi_tenant_context, clock) -> None:
    ctx, _ = make_multi_tenant_context(_rows_handler(30))
    ctx._quotas = QuotaTracker({"contoso": TenantQuota(rows_per_minute=50)}, clock=clock)
    async with ctx:
        await advanced_hunting.run(ctx, {"query": "T", "tenant": "contoso"})
        await advanced_hunting.run(ctx, {"query": "T", "tenant": "contoso"})  # 30 < 50
        with pytest.raises(QuotaExceededError):
            await advanced_hunting.run(ctx, {"query": "T", "tenant": "contoso"})  # 60 >= 50
        clock.now += 61
        await advanced_hunting.run(ctx, {"query": "T", "tenant": "contoso"})


async def test_single_tenant_quota_error_maps_to_tool_error(make_context, clock) -> None:
    from mcp_defender_xdr.server import _dispatch

    ctx, _ = make_context(_rows_handler(1))
    ctx._quotas = QuotaTracker({"default": TenantQuota(requests_per_minute=1)}, clock=clock)
    async with ctx:
        ok = await _dispatch(alerts.run, ctx, {}, alerts.TOOL_NAME)
        refused = await _dispatch(alerts.run, ctx, {}, alerts.TOOL_NAME)
    assert ok.isError is False
    assert refused.isError is True
    assert refused.structuredContent is not None
    assert refused.structuredContent["error"]["code"] == "quota_exceeded"


def test_server_builds_with_and_without_quotas(token_manager: TokenManager) -> None:
    assert build_server(token_manager) is not None
