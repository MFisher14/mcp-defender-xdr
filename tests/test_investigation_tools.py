"""Tests for get_device_timeline, investigate_user, and query_threat_intelligence."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_defender_xdr import kql
from mcp_defender_xdr.errors import InvalidInputError
from mcp_defender_xdr.fixtures import FixtureStore
from mcp_defender_xdr.server import _HANDLERS, _tool_definitions
from mcp_defender_xdr.tool_context import ToolContext
from mcp_defender_xdr.tools import device_timeline, investigate_user, threat_intelligence

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "examples" / "fixtures"
DEVICE = "fixture0000000000000000000000000000a014"
UPN = "j.doe.fixture@example.com"
SID = "S-1-5-21-1000000000-2000000000-3000000000-1104"
SHA256 = "0" * 63 + "1"
WINDOW = {"start": "2026-08-31T00:00:00Z", "end": "2026-08-31T06:00:00Z"}


def _hunting_handler(
    rows: list[dict[str, Any]] | None = None, *, sink: list[dict[str, Any]] | None = None
):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/advancedqueries/run"
        body = json.loads(request.content)
        if sink is not None:
            sink.append(body)
        return httpx.Response(200, json={"Schema": [], "Results": list(rows or [])})

    return handler


def _no_upstream(request: httpx.Request) -> httpx.Response:
    raise AssertionError("upstream must not be called for invalid input")


# ---------- kql helpers ----------


def test_string_literal_escapes_quotes_and_backslashes() -> None:
    assert kql.string_literal('a"b\\c') == '"a\\"b\\\\c"'


def test_string_literal_rejects_control_characters() -> None:
    with pytest.raises(ValueError):
        kql.string_literal("line\nbreak")


def test_datetime_literal_normalises_to_utc() -> None:
    plus_two = datetime(2026, 8, 31, 2, 0, tzinfo=timezone(timedelta(hours=2)))
    assert kql.datetime_literal(plus_two) == "datetime(2026-08-31T00:00:00.000000Z)"
    with pytest.raises(ValueError):
        kql.datetime_literal(datetime(2026, 8, 31))


def test_query_tag_round_trips_and_rejects_whitespace() -> None:
    tag = kql.query_tag("get_device_timeline", "abc")
    match = kql.TAG_RE.match(tag)
    assert match is not None
    assert (match["view"], match["subject"]) == ("get_device_timeline", "abc")
    with pytest.raises(ValueError):
        kql.query_tag("get_device_timeline", "a b")


def test_lookback_timespan_covers_start_and_is_capped() -> None:
    now = datetime(2026, 9, 10, tzinfo=UTC)
    assert kql.lookback_timespan(now - timedelta(hours=3), now=now) == "P1D"
    assert kql.lookback_timespan(now - timedelta(days=4, hours=1), now=now) == "P5D"
    assert kql.lookback_timespan(now - timedelta(days=90), now=now) == "P30D"
    assert kql.lookback_timespan(now + timedelta(days=1), now=now) == "P1D"


# ---------- registration ----------


def test_new_tools_are_registered() -> None:
    names = {tool.name for tool in _tool_definitions()}
    for module in (device_timeline, investigate_user, threat_intelligence):
        assert module.TOOL_NAME in names
        assert module.TOOL_NAME in _HANDLERS


# ---------- get_device_timeline ----------


async def test_device_timeline_happy_path(make_context) -> None:
    sent: list[dict[str, Any]] = []
    rows = [
        {"Timestamp": "2026-08-31T02:00:00Z", "EventType": "process", "FileName": "a.exe"},
        {"Timestamp": "2026-08-31T01:00:00Z", "EventType": "network", "RemoteIP": ""},
    ]
    ctx, _ = make_context(_hunting_handler(rows, sink=sent))
    async with ctx:
        result = await device_timeline.run(ctx, {"device_id": DEVICE, **WINDOW})

    query = sent[0]["Query"]
    assert query.startswith(f"// mcp-defender-xdr:get_device_timeline subject={DEVICE}")
    for table in (
        "DeviceProcessEvents",
        "DeviceNetworkEvents",
        "DeviceFileEvents",
        "DeviceRegistryEvents",
        "DeviceEvents",
    ):
        assert f"({table} |" in query
    assert f'let _device = "{DEVICE}";' in query
    assert "take 201" in query
    assert result["metadata"] == {
        "event_count": 2,
        "truncated": False,
        "limit": 200,
        "counts_by_type": {"network": 1, "process": 1},
    }
    # Empty columns are stripped from each event.
    assert "RemoteIP" not in result["events"][1]


async def test_device_timeline_event_type_filter_and_truncation(make_context) -> None:
    sent: list[dict[str, Any]] = []
    rows = [{"Timestamp": f"2026-08-31T0{i}:00:00Z", "EventType": "network"} for i in range(4)]
    ctx, _ = make_context(_hunting_handler(rows, sink=sent))
    async with ctx:
        result = await device_timeline.run(
            ctx,
            {"device_id": DEVICE, **WINDOW, "event_types": ["network", "network"], "limit": 3},
        )
    query = sent[0]["Query"]
    assert "DeviceNetworkEvents" in query
    assert "DeviceProcessEvents" not in query
    assert query.count("(DeviceNetworkEvents") == 1
    assert result["metadata"]["truncated"] is True
    assert result["metadata"]["event_count"] == 3


async def test_device_timeline_empty_result(make_context) -> None:
    ctx, _ = make_context(_hunting_handler([]))
    async with ctx:
        result = await device_timeline.run(ctx, {"device_id": DEVICE, **WINDOW})
    assert result["events"] == []
    assert result["metadata"]["event_count"] == 0
    assert result["metadata"]["truncated"] is False


@pytest.mark.parametrize(
    "window",
    [
        {"start": "2026-08-31T06:00:00Z", "end": "2026-08-31T00:00:00Z"},
        {"start": "2026-08-31T00:00:00Z", "end": "2026-08-31T00:00:00Z"},
        {"start": "2026-07-01T00:00:00Z", "end": "2026-08-31T00:00:00Z"},
        {"start": "2026-08-31T00:00:00", "end": "2026-08-31T06:00:00"},
        {"start": "yesterday", "end": "today"},
    ],
)
async def test_device_timeline_invalid_time_window(make_context, window) -> None:
    ctx, _ = make_context(_no_upstream)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await device_timeline.run(ctx, {"device_id": DEVICE, **window})


@pytest.mark.parametrize("device_id", ['abc" | take 1 //', "abc\ndef", "../../etc", "x" * 65, ""])
async def test_device_timeline_rejects_unsafe_device_id(make_context, device_id) -> None:
    ctx, _ = make_context(_no_upstream)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await device_timeline.run(ctx, {"device_id": device_id, **WINDOW})


async def test_device_timeline_rejects_unknown_event_type(make_context) -> None:
    ctx, _ = make_context(_no_upstream)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await device_timeline.run(
                ctx, {"device_id": DEVICE, **WINDOW, "event_types": ["kernel"]}
            )


async def test_device_timeline_fan_out(make_multi_tenant_context) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Authorization"])
        return httpx.Response(200, json={"Schema": [], "Results": [{"EventType": "file"}]})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await device_timeline.run(ctx, {"device_id": DEVICE, **WINDOW, "tenant": "*"})
    assert result["fan_out"] is True
    assert {r["tenant"] for r in result["results"]} == {"contoso", "fabrikam"}
    assert all(r["result"]["metadata"]["event_count"] == 1 for r in result["results"])
    assert sorted(seen) == ["Bearer token-contoso", "Bearer token-fabrikam"]


# ---------- investigate_user ----------


async def test_investigate_user_happy_path_groups_by_signal(make_context) -> None:
    sent: list[dict[str, Any]] = []
    rows = [
        {"SignalType": "sign_in", "ActionType": "LogonSuccess", "AccountUpn": UPN},
        {"SignalType": "mailbox", "Subject": "hello", "ThreatTypes": ""},
        {"SignalType": "device", "DeviceName": "wkstn"},
        {"SignalType": "device", "DeviceName": "srv"},
    ]
    ctx, _ = make_context(_hunting_handler(rows, sink=sent))
    async with ctx:
        result = await investigate_user.run(ctx, {"account_upn": UPN.upper(), **WINDOW})

    query = sent[0]["Query"]
    assert query.startswith(f"// mcp-defender-xdr:investigate_user subject={UPN}")
    assert f'let _given_upn = "{UPN}";' in query
    assert 'let _given_sid = "";' in query
    for table in ("IdentityLogonEvents", "EmailEvents", "DeviceLogonEvents", "IdentityInfo"):
        assert table in query
    assert "union isfuzzy=true" in query
    assert result["found"] is True
    assert {k: v["count"] for k, v in result["signals"].items()} == {
        "sign_in": 1,
        "mailbox": 1,
        "device": 2,
    }
    assert result["subject"] == {"account_upn": UPN, "account_sid": None}
    assert "ThreatTypes" not in result["signals"]["mailbox"]["events"][0]


async def test_investigate_user_by_sid_and_signal_filter(make_context) -> None:
    sent: list[dict[str, Any]] = []
    ctx, _ = make_context(_hunting_handler([], sink=sent))
    async with ctx:
        result = await investigate_user.run(
            ctx, {"account_sid": SID.lower(), **WINDOW, "signal_types": ["device"]}
        )
    query = sent[0]["Query"]
    assert f'let _given_sid = "{SID}";' in query
    assert "DeviceLogonEvents | where" in query
    assert "EmailEvents | where" not in query
    assert list(result["signals"]) == ["device"]


async def test_investigate_user_unknown_user(make_context) -> None:
    ctx, _ = make_context(_hunting_handler([]))
    async with ctx:
        result = await investigate_user.run(ctx, {"account_upn": "ghost@example.com", **WINDOW})
    assert result["found"] is False
    assert result["metadata"]["event_count"] == 0
    assert all(v["count"] == 0 and v["truncated"] is False for v in result["signals"].values())


async def test_investigate_user_per_signal_truncation(make_context) -> None:
    rows = [{"SignalType": "mailbox", "Subject": str(i)} for i in range(3)]
    rows.append({"SignalType": "sign_in"})
    ctx, _ = make_context(_hunting_handler(rows))
    async with ctx:
        result = await investigate_user.run(ctx, {"account_upn": UPN, **WINDOW, "limit": 2})
    assert result["signals"]["mailbox"] == {
        "events": [
            {"SignalType": "mailbox", "Subject": "0"},
            {"SignalType": "mailbox", "Subject": "1"},
        ],
        "count": 2,
        "truncated": True,
    }
    assert result["signals"]["sign_in"]["truncated"] is False


@pytest.mark.parametrize(
    "identity",
    [
        {},
        {"account_upn": UPN, "account_sid": SID},
        {"account_upn": 'x"@example.com'},
        {"account_upn": "no-at-sign"},
        {"account_upn": "a b@example.com"},
        {"account_sid": "S-1-5-21-abc"},
        {"account_sid": "not-a-sid"},
    ],
)
async def test_investigate_user_rejects_bad_identity(make_context, identity) -> None:
    ctx, _ = make_context(_no_upstream)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await investigate_user.run(ctx, {**identity, **WINDOW})


async def test_investigate_user_allows_apostrophe_upn_safely(make_context) -> None:
    sent: list[dict[str, Any]] = []
    ctx, _ = make_context(_hunting_handler([], sink=sent))
    async with ctx:
        await investigate_user.run(ctx, {"account_upn": "o'brien@example.com", **WINDOW})
    assert 'let _given_upn = "o\'brien@example.com";' in sent[0]["Query"]


async def test_investigate_user_fan_out(make_multi_tenant_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "token-fabrikam" in request.headers["Authorization"]:
            return httpx.Response(200, json={"Schema": [], "Results": []})
        return httpx.Response(200, json={"Schema": [], "Results": [{"SignalType": "sign_in"}]})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await investigate_user.run(ctx, {"account_upn": UPN, **WINDOW, "tenant": "*"})
    found = {r["tenant"]: r["result"]["found"] for r in result["results"]}
    assert found == {"contoso": True, "fabrikam": False}


# ---------- query_threat_intelligence ----------


def _ti_handler(alerts: list[dict[str, Any]], sightings: list[dict[str, Any]], sink=None):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if sink is not None:
            sink.append(body)
        first = body["Query"].split("\n", 1)[0]
        rows = alerts if "/alerts " in first else sightings
        return httpx.Response(200, json={"Schema": [], "Results": rows})

    return handler


async def test_threat_intel_happy_path(make_context) -> None:
    sent: list[dict[str, Any]] = []
    alerts = [
        {"AlertId": "a1", "Severity": "Medium", "DetectionSource": "EDR"},
        {"AlertId": "a2", "Severity": "High", "DetectionSource": "Custom TI"},
    ]
    sightings = [{"Source": "DeviceNetworkEvents", "Hits": 3}]
    ctx, _ = make_context(_ti_handler(alerts, sightings, sink=sent))
    async with ctx:
        result = await threat_intelligence.run(
            ctx, {"ioc_type": "ip", "ioc_value": "192.0.2.44", "lookback_days": 7}
        )

    assert len(sent) == 2
    assert all(b["Timespan"] == "P7D" for b in sent)
    alerts_query, sightings_query = (b["Query"] for b in sent)
    assert "AlertEvidence" in alerts_query
    assert "RemoteIP == _ioc" in alerts_query
    assert 'let _ioc = "192.0.2.44";' in alerts_query
    assert "ago(7d)" in sightings_query
    assert "union isfuzzy=true" in sightings_query
    assert result["matched"] is True
    assert result["highest_severity"] == "High"
    assert result["detection_sources"] == ["Custom TI", "EDR"]
    assert result["metadata"]["sighting_sources"] == ["DeviceNetworkEvents"]
    assert result["coverage_note"] == threat_intelligence.COVERAGE_NOTE


async def test_threat_intel_no_match(make_context) -> None:
    ctx, _ = make_context(_ti_handler([], []))
    async with ctx:
        result = await threat_intelligence.run(
            ctx, {"ioc_type": "domain", "ioc_value": "Clean.Example.COM."}
        )
    assert result["matched"] is False
    assert result["ioc"]["value"] == "clean.example.com"
    assert result["highest_severity"] is None
    assert result["alerts"] == [] and result["sightings"] == []


@pytest.mark.parametrize(
    ("value", "kind", "column"),
    [
        ("A" * 40, "sha1", "SHA1 =~ _ioc"),
        ("b" * 64, "sha256", "SHA256 =~ _ioc"),
        ("c" * 32, "md5", "SHA1 in (_sha1s)"),
    ],
)
async def test_threat_intel_hash_kinds(make_context, value, kind, column) -> None:
    sent: list[dict[str, Any]] = []
    ctx, _ = make_context(_ti_handler([], [], sink=sent))
    async with ctx:
        result = await threat_intelligence.run(ctx, {"ioc_type": "hash", "ioc_value": value})
    assert result["ioc"]["hash_kind"] == kind
    assert result["ioc"]["value"] == value.lower()
    assert column in sent[0]["Query"]


async def test_threat_intel_alert_truncation(make_context) -> None:
    alerts = [{"AlertId": f"a{i}", "Severity": "Low"} for i in range(4)]
    ctx, _ = make_context(_ti_handler(alerts, []))
    async with ctx:
        result = await threat_intelligence.run(
            ctx, {"ioc_type": "url", "ioc_value": "https://bad.example.com/x?y=1", "limit": 3}
        )
    assert result["metadata"]["alert_count"] == 3
    assert result["metadata"]["alerts_truncated"] is True


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        ("ip", "999.1.1.1"),
        ("ip", "192.0.2.1; drop"),
        ("domain", "bad domain.com"),
        ("domain", 'evil.com" | take 1'),
        ("hash", "abc123"),
        ("hash", "z" * 64),
        ("url", "ftp://example.com/file"),
        ("url", 'https://example.com/"quoted"'),
        ("url", "https://example.com/a b"),
        ("registry", "HKLM"),
    ],
)
async def test_threat_intel_rejects_invalid_ioc(make_context, ioc_type, value) -> None:
    ctx, _ = make_context(_no_upstream)
    async with ctx:
        with pytest.raises(InvalidInputError):
            await threat_intelligence.run(ctx, {"ioc_type": ioc_type, "ioc_value": value})


async def test_threat_intel_ipv6_is_normalised(make_context) -> None:
    sent: list[dict[str, Any]] = []
    ctx, _ = make_context(_ti_handler([], [], sink=sent))
    async with ctx:
        result = await threat_intelligence.run(
            ctx, {"ioc_type": "ip", "ioc_value": "2001:DB8:0:0:0:0:0:1"}
        )
    assert result["ioc"]["value"] == "2001:db8::1"


async def test_threat_intel_fan_out(make_multi_tenant_context) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "token-fabrikam" in request.headers["Authorization"]:
            return httpx.Response(500)
        return httpx.Response(200, json={"Schema": [], "Results": []})

    ctx, _ = make_multi_tenant_context(handler)
    async with ctx:
        result = await threat_intelligence.run(
            ctx, {"ioc_type": "ip", "ioc_value": "198.51.100.7", "tenant": "*"}
        )
    by_tenant = {r["tenant"]: r for r in result["results"]}
    assert by_tenant["contoso"]["result"]["matched"] is False
    assert by_tenant["fabrikam"]["error"]["code"] == "upstream_error"


# ---------- offline fixture mode ----------


@pytest.fixture
def fixture_ctx() -> ToolContext:
    return ToolContext(fixtures=FixtureStore.load(FIXTURE_DIR))


async def test_fixture_device_timeline(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        result = await device_timeline.run(ctx, {"device_id": DEVICE.upper(), **WINDOW})
        unknown = await device_timeline.run(ctx, {"device_id": "deadbeef", **WINDOW})
    assert result["fixture_mode"] is True
    assert result["metadata"]["event_count"] >= 8
    assert set(result["metadata"]["counts_by_type"]) == {
        "file",
        "network",
        "other",
        "process",
        "registry",
    }
    timestamps = [e["Timestamp"] for e in result["events"]]
    assert timestamps == sorted(timestamps, reverse=True)
    assert unknown["events"] == []


async def test_fixture_investigate_user_by_upn_and_sid(fixture_ctx: ToolContext) -> None:
    window = {"start": "2026-08-30T00:00:00Z", "end": "2026-09-01T00:00:00Z"}
    async with fixture_ctx as ctx:
        by_upn = await investigate_user.run(ctx, {"account_upn": UPN, **window})
        by_sid = await investigate_user.run(ctx, {"account_sid": SID, **window})
        ghost = await investigate_user.run(ctx, {"account_upn": "ghost@example.com", **window})
    assert by_upn["found"] is True
    assert by_upn["signals"] == by_sid["signals"]
    assert all(by_upn["signals"][s]["count"] > 0 for s in ("sign_in", "mailbox", "device"))
    assert ghost["found"] is False


async def test_fixture_threat_intel(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        hit = await threat_intelligence.run(ctx, {"ioc_type": "hash", "ioc_value": SHA256})
        domain = await threat_intelligence.run(
            ctx, {"ioc_type": "domain", "ioc_value": "updates.fixture.example.com"}
        )
        miss = await threat_intelligence.run(ctx, {"ioc_type": "ip", "ioc_value": "203.0.113.250"})
    assert hit["matched"] is True and hit["highest_severity"] == "High"
    assert hit["alerts"][0]["AlertId"] == "da-fixture-0002"
    assert {s["Source"] for s in domain["sightings"]} == {"DeviceNetworkEvents", "EmailUrlInfo"}
    assert miss["matched"] is False
    assert miss["fixture_mode"] is True


async def test_fixture_unrecorded_view_is_an_upstream_error(tmp_path: Path) -> None:
    from mcp_defender_xdr.errors import UpstreamError
    from mcp_defender_xdr.fixtures import FixtureClient

    store = FixtureStore.load(FIXTURE_DIR)
    client = FixtureClient(store, "contoso-fixture")
    with pytest.raises(UpstreamError):
        await client.post(
            "/api/advancedqueries/run",
            json={"Query": "// mcp-defender-xdr:nonexistent_view subject=x\nT"},
        )


def test_fixture_store_without_investigations_file_still_loads(tmp_path: Path) -> None:
    for name in ("advanced_hunting.json", "incidents.json", "alerts.json"):
        (tmp_path / name).write_text((FIXTURE_DIR / name).read_text("utf-8"), "utf-8")
    assert FixtureStore.load(tmp_path).hunting_views == {}


def test_fixture_views_must_be_objects(tmp_path: Path) -> None:
    from mcp_defender_xdr.errors import ConfigError

    for name in ("advanced_hunting.json", "incidents.json", "alerts.json"):
        (tmp_path / name).write_text((FIXTURE_DIR / name).read_text("utf-8"), "utf-8")
    (tmp_path / "investigations.json").write_text('{"views": []}', "utf-8")
    with pytest.raises(ConfigError):
        FixtureStore.load(tmp_path)
    (tmp_path / "investigations.json").write_text('{"views": {"v": []}}', "utf-8")
    with pytest.raises(ConfigError):
        FixtureStore.load(tmp_path)
