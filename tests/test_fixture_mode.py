"""Tests for offline fixture mode."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from pathlib import Path
from typing import Any

import pytest

from mcp_defender_xdr.errors import ConfigError, NotFoundError, UpstreamError
from mcp_defender_xdr.fixtures import (
    FIXTURE_AUDIT_EVENT,
    FIXTURE_MODE_ENV,
    FIXTURE_MODE_TOKEN,
    FIXTURE_TENANTS,
    SYNTHETIC_NOTICE,
    FixtureClient,
    FixtureStore,
    fixture_mode_requested,
    fixture_search_paths,
    mark_result,
)
from mcp_defender_xdr.server import build_server
from mcp_defender_xdr.tool_context import ToolContext
from mcp_defender_xdr.tools import advanced_hunting, alerts, incidents

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "examples" / "fixtures"
KNOWN_INCIDENT_ID = "INC-4471"


@pytest.fixture
def store() -> FixtureStore:
    return FixtureStore.load(FIXTURE_DIR)


@pytest.fixture
def fixture_ctx(store: FixtureStore) -> ToolContext:
    return ToolContext(fixtures=store)


# ---------- the enable gate: it must be hard to trip by accident ----------


def test_fixture_mode_off_when_unset() -> None:
    assert fixture_mode_requested({}) is False


@pytest.mark.parametrize("value", ["", "   "])
def test_fixture_mode_off_when_blank(value: str) -> None:
    assert fixture_mode_requested({FIXTURE_MODE_ENV: value}) is False


def test_fixture_mode_on_with_exact_token() -> None:
    assert fixture_mode_requested({FIXTURE_MODE_ENV: FIXTURE_MODE_TOKEN}) is True
    assert fixture_mode_requested({FIXTURE_MODE_ENV: f"  {FIXTURE_MODE_TOKEN}  "}) is True


@pytest.mark.parametrize(
    "value",
    ["1", "true", "True", "yes", "on", "enabled", "fixture", FIXTURE_MODE_TOKEN.upper()],
)
def test_plausible_truthy_values_are_refused_not_guessed(value: str) -> None:
    """A half-remembered value must fail loudly rather than resolve to either mode."""
    with pytest.raises(ConfigError) as excinfo:
        fixture_mode_requested({FIXTURE_MODE_ENV: value})
    assert FIXTURE_MODE_TOKEN in str(excinfo.value)


def test_env_var_is_read_from_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FIXTURE_MODE_ENV, raising=False)
    assert fixture_mode_requested() is False
    monkeypatch.setenv(FIXTURE_MODE_ENV, FIXTURE_MODE_TOKEN)
    assert fixture_mode_requested() is True


# ---------- loading ----------


def test_store_loads_from_examples_directory(store: FixtureStore) -> None:
    assert store.source_dir == FIXTURE_DIR
    assert store.advanced_hunting["Schema"]
    assert KNOWN_INCIDENT_ID in store.incidents
    assert store.alerts["value"]
    assert store.list_tenants() == list(FIXTURE_TENANTS)
    assert store.default_tenant_key in store.tenants


def test_default_search_paths_find_the_shipped_fixtures() -> None:
    assert FIXTURE_DIR in fixture_search_paths()
    assert FixtureStore.load().source_dir.is_dir()


def test_packaged_fixture_dir_wins_over_the_source_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Installed wheels ship fixtures at mcp_defender_xdr/fixture_data; prefer them."""
    import mcp_defender_xdr.fixtures as fixtures_module

    packaged = tmp_path / "fixture_data"
    packaged.mkdir()
    for name in ("advanced_hunting.json", "incidents.json", "alerts.json"):
        (packaged / name).write_text(
            json.dumps({"_comment": "packaged", "INC-P": {"incidentId": "INC-P"}, "value": []}),
            encoding="utf-8",
        )
    monkeypatch.setattr(fixtures_module, "fixture_search_paths", lambda: [packaged, FIXTURE_DIR])
    assert FixtureStore.load().source_dir == packaged


def test_source_checkout_dir_is_used_when_no_packaged_copy_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcp_defender_xdr.fixtures as fixtures_module

    monkeypatch.setattr(
        fixtures_module, "fixture_search_paths", lambda: [tmp_path / "absent", FIXTURE_DIR]
    )
    assert FixtureStore.load().source_dir == FIXTURE_DIR


def test_missing_fixture_directory_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        FixtureStore.load(tmp_path)


def test_malformed_fixture_json_is_a_config_error(tmp_path: Path) -> None:
    (tmp_path / "advanced_hunting.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        FixtureStore.load(tmp_path)


def test_non_object_fixture_json_is_a_config_error(tmp_path: Path) -> None:
    for name in ("advanced_hunting.json", "incidents.json", "alerts.json"):
        (tmp_path / name).write_text("[]", encoding="utf-8")
    with pytest.raises(ConfigError):
        FixtureStore.load(tmp_path)


def test_empty_incident_fixtures_are_a_config_error(tmp_path: Path) -> None:
    (tmp_path / "advanced_hunting.json").write_text("{}", encoding="utf-8")
    (tmp_path / "incidents.json").write_text("{}", encoding="utf-8")
    (tmp_path / "alerts.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ConfigError):
        FixtureStore.load(tmp_path)


# ---------- the tools, offline ----------


async def test_advanced_hunting_returns_fixture_rows(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        result = await advanced_hunting.run(ctx, {"query": "DeviceProcessEvents | take 5"})
    assert result["metadata"]["row_count"] == len(result["rows"])
    assert result["metadata"]["row_count"] > 0
    assert result["metadata"]["column_count"] == len(result["schema"])
    assert result["fixture_mode"] is True


async def test_get_incident_returns_alerts_and_entities(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        result = await incidents.run(ctx, {"incident_id": KNOWN_INCIDENT_ID})
    assert result["incident_id"] == KNOWN_INCIDENT_ID
    assert len(result["alerts"]) >= 2
    assert len(result["entities"]) >= 2
    assert result["fixture_mode"] is True


async def test_unknown_incident_maps_to_not_found(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        with pytest.raises(NotFoundError):
            await incidents.run(ctx, {"incident_id": "INC-NOPE"})


async def test_list_alerts_returns_fixture_alerts(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        result = await alerts.run(ctx, {})
    assert result["metadata"]["count"] == len(result["alerts"])
    assert result["metadata"]["count"] > 0
    assert result["fixture_mode"] is True


async def test_list_alerts_applies_severity_and_status_filter(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        result = await alerts.run(ctx, {"severity": "High", "status": "New"})
    assert result["alerts"]
    for alert in result["alerts"]:
        assert alert["severity"] == "High"
        assert alert["status"] == "New"


async def test_list_alerts_honours_limit(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        unlimited = await alerts.run(ctx, {})
        limited = await alerts.run(ctx, {"limit": 2})
    assert unlimited["metadata"]["count"] > 2
    assert limited["metadata"]["count"] == 2


async def test_fan_out_across_fixture_tenants(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        result = await alerts.run(ctx, {"tenant": "*"})
    assert result["fan_out"] is True
    assert result["tenants"] == list(FIXTURE_TENANTS)
    assert [entry["tenant"] for entry in result["results"]] == list(FIXTURE_TENANTS)
    assert all("result" in entry for entry in result["results"])
    assert result["fixture_mode"] is True


async def test_validation_still_applies_offline(fixture_ctx: ToolContext) -> None:
    """Fixture mode replaces the transport, not the guardrails."""
    from mcp_defender_xdr.errors import InvalidInputError

    async with fixture_ctx as ctx:
        with pytest.raises(InvalidInputError):
            await advanced_hunting.run(ctx, {"query": ".drop table alerts"})


# ---------- unmistakability ----------


def _audit_fields(record: logging.LogRecord) -> dict[str, Any]:
    """`audit_fields` is attached via logging `extra`, so it is not on the stub."""
    fields = getattr(record, "audit_fields", None)
    assert isinstance(fields, dict)
    return fields


def test_mark_result_stamps_payload() -> None:
    marked = mark_result({"rows": []})
    assert marked["fixture_mode"] is True
    assert marked["notice"] == SYNTHETIC_NOTICE
    assert "SYNTHETIC" in marked["notice"]


@pytest.mark.parametrize(
    ("tool", "params"),
    [
        (advanced_hunting, {"query": "DeviceEvents | take 1"}),
        (incidents, {"incident_id": KNOWN_INCIDENT_ID}),
        (alerts, {}),
    ],
)
async def test_every_tool_call_logs_a_warning(
    fixture_ctx: ToolContext,
    caplog: pytest.LogCaptureFixture,
    tool: Any,
    params: dict[str, Any],
) -> None:
    with caplog.at_level(logging.WARNING, logger="mcp_defender_xdr.audit"):
        async with fixture_ctx as ctx:
            await tool.run(ctx, params)
    warnings = [r for r in caplog.records if r.getMessage() == FIXTURE_AUDIT_EVENT]
    assert len(warnings) == 1
    fields = _audit_fields(warnings[0])
    assert fields["fixture_mode"] is True
    assert fields["notice"] == SYNTHETIC_NOTICE
    assert fields["tool"] == tool.TOOL_NAME


async def test_fan_out_call_also_logs_the_warning(
    fixture_ctx: ToolContext, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="mcp_defender_xdr.audit"):
        async with fixture_ctx as ctx:
            await alerts.run(ctx, {"tenant": "*"})
    warnings = [r for r in caplog.records if r.getMessage() == FIXTURE_AUDIT_EVENT]
    assert len(warnings) == 1
    assert _audit_fields(warnings[0])["tenants"] == list(FIXTURE_TENANTS)


async def test_live_mode_emits_no_fixture_warning(
    make_context: Any, caplog: pytest.LogCaptureFixture
) -> None:
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Schema": [], "Results": []})

    ctx, _ = make_context(handler)
    with caplog.at_level(logging.WARNING, logger="mcp_defender_xdr.audit"):
        async with ctx:
            result = await advanced_hunting.run(ctx, {"query": "DeviceEvents | take 1"})
    assert not [r for r in caplog.records if r.getMessage() == FIXTURE_AUDIT_EVENT]
    assert "fixture_mode" not in result
    assert "notice" not in result


# ---------- the fixtures must be obviously synthetic ----------


def _walk_strings(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for v in node.values() for s in _walk_strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in _walk_strings(v)]
    return []


def _all_fixture_strings() -> list[str]:
    out: list[str] = []
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        out.extend(_walk_strings(json.loads(path.read_text(encoding="utf-8"))))
    return out


_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def test_every_ip_is_an_rfc5737_documentation_address() -> None:
    found = [ip for s in _all_fixture_strings() for ip in _IPV4_RE.findall(s)]
    assert found, "expected fixtures to contain IP addresses"
    for raw in found:
        address = ipaddress.ip_address(raw)
        assert any(address in net for net in _DOC_NETS), f"{raw} is not an RFC 5737 address"


def test_every_hostname_and_email_uses_example_com() -> None:
    pattern = re.compile(r"\b[\w.-]+\.(?:com|net|org|io|local)\b", re.IGNORECASE)
    for value in _all_fixture_strings():
        for host in pattern.findall(value):
            assert host.lower().endswith("example.com"), f"{host} is not under example.com"


def test_fixture_files_carry_a_synthetic_comment() -> None:
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert "SYNTHETIC" in payload["_comment"].upper(), path


# ---------- wiring ----------


def test_tool_context_rejects_both_backends(store: FixtureStore) -> None:
    from mcp_defender_xdr.auth import TokenManager

    from .conftest import FakeCredentialProvider, FakeMsalApp

    manager = TokenManager(FakeCredentialProvider(), msal_factory=lambda **_: FakeMsalApp())
    with pytest.raises(ValueError, match="exactly one"):
        ToolContext(manager, fixtures=store)


def test_tool_context_rejects_neither_backend() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        ToolContext()


def test_fixture_context_reports_fixture_mode(store: FixtureStore) -> None:
    ctx = ToolContext(fixtures=store)
    assert ctx.fixture_mode is True
    assert ctx.default_tenant_key == store.default_tenant_key
    assert ctx.available_tenants() == list(FIXTURE_TENANTS)
    with pytest.raises(RuntimeError):
        _ = ctx.token_manager


def test_server_builds_with_fixtures_and_no_credentials(store: FixtureStore) -> None:
    server = build_server(fixtures=store)
    assert server.name == "mcp-defender-xdr"


async def test_fixture_client_rejects_unrecorded_paths(store: FixtureStore) -> None:
    client = FixtureClient(store, "contoso-fixture")
    with pytest.raises(UpstreamError):
        await client.get("/api/machines")
    with pytest.raises(UpstreamError):
        await client.post("/api/machines/isolate")


async def test_fixture_client_rejects_unparseable_filter(store: FixtureStore) -> None:
    client = FixtureClient(store, "contoso-fixture")
    with pytest.raises(UpstreamError):
        await client.get("/api/alerts", params={"$filter": "severity gt 'High'"})
