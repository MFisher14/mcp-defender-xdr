"""Tests for the Microsoft Sentinel tools (#10)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_defender_xdr.auth import (
    ARM_SCOPE,
    DEFAULT_DEFENDER_SCOPE,
    LOG_ANALYTICS_SCOPE,
    AzureCredentials,
    EnvCredentialProvider,
    JsonFileCredentialProvider,
    SentinelWorkspace,
    TokenManager,
)
from mcp_defender_xdr.defender_client import DefenderClient
from mcp_defender_xdr.errors import AuthError, InvalidInputError, NotFoundError
from mcp_defender_xdr.fixtures import FixtureStore
from mcp_defender_xdr.server import _HANDLERS, _tool_definitions
from mcp_defender_xdr.tool_context import ToolContext
from mcp_defender_xdr.tools import sentinel

from .conftest import FakeCredentialProvider

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "examples" / "fixtures"
WS_ID = "11111111-2222-4333-8444-555555555555"
RID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-soc"
    "/providers/Microsoft.OperationalInsights/workspaces/law-soc"
)


class SentinelProvider(FakeCredentialProvider):
    def __init__(self, workspaces: dict[str, SentinelWorkspace], **kw: Any) -> None:
        super().__init__(**kw)
        self._workspaces = workspaces

    def sentinel_workspaces(self) -> dict[str, SentinelWorkspace]:
        return dict(self._workspaces)


class ScopeRecordingMsal:
    def __init__(self) -> None:
        self.scopes: list[str] = []

    def acquire_token_for_client(self, scopes: list[str]) -> dict[str, Any]:
        self.scopes.extend(scopes)
        return {"access_token": f"tok-{scopes[0].split('//')[1].split('/')[0]}", "expires_in": 3600}


def _creds(n: str) -> AzureCredentials:
    return AzureCredentials(
        tenant_id=n * 8 + "-1111-1111-1111-111111111111", client_id=n, cert_path="/dev/null"
    )


def _context(handler, workspaces: dict[str, SentinelWorkspace], *, tenants=("contoso",)):
    msal = ScopeRecordingMsal()
    provider = SentinelProvider(
        workspaces,
        credentials={t: _creds(str(i)) for i, t in enumerate(tenants)},
        default=tenants[0],
    )
    tm = TokenManager(provider, msal_factory=lambda **_: msal)
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = ToolContext(tm, http_client=http)
    return ctx, msal


def _la_response(n_rows: int = 2) -> dict[str, Any]:
    return {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "Ip", "type": "string"},
                ],
                "rows": [[f"2026-08-31T0{i}:00:00Z", f"192.0.2.{i}"] for i in range(n_rows)],
            }
        ]
    }


def _saved(
    name: str, category: str = "Hunting Queries", query: str = "SigninLogs | take 5", **tags: str
):
    return {
        "id": f"{RID}/savedSearches/{name}",
        "name": name,
        "properties": {
            "category": category,
            "displayName": f"Hunt {name}",
            "query": query,
            "tags": [{"name": k, "value": v} for k, v in tags.items()],
        },
    }


# ---------- registration and config ----------


def test_tools_registered() -> None:
    names = {t.name for t in _tool_definitions()}
    assert {sentinel.QUERY_TOOL_NAME, sentinel.LIST_TOOL_NAME} <= names
    assert sentinel.QUERY_TOOL_NAME in _HANDLERS and sentinel.LIST_TOOL_NAME in _HANDLERS


def test_workspace_config_validation() -> None:
    ws = SentinelWorkspace.from_config(WS_ID.upper(), RID, where="t")
    assert ws.workspace_id == WS_ID
    for bad_id, bad_rid in [("nope", None), (WS_ID, "/subscriptions/x"), (None, None), (WS_ID, 5)]:
        with pytest.raises(AuthError):
            SentinelWorkspace.from_config(bad_id, bad_rid, where="t")


def test_env_provider_reads_sentinel(tmp_path: Path) -> None:
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"x")
    base = {"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AZURE_CERT_PATH": str(pfx)}
    assert EnvCredentialProvider(base).sentinel_workspaces() == {}
    provider = EnvCredentialProvider(
        {
            **base,
            "MCP_DEFENDER_XDR_SENTINEL_WORKSPACE_ID": WS_ID,
            "MCP_DEFENDER_XDR_SENTINEL_WORKSPACE_RESOURCE_ID": RID,
        }
    )
    assert provider.sentinel_workspaces() == {"default": SentinelWorkspace(WS_ID, RID)}
    with pytest.raises(AuthError):
        EnvCredentialProvider({**base, "MCP_DEFENDER_XDR_SENTINEL_WORKSPACE_RESOURCE_ID": RID})


def test_tenants_file_reads_sentinel(tmp_path: Path) -> None:
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"x")
    entry = {"tenant_id": "t", "client_id": "c", "cert_path": str(pfx)}
    path = tmp_path / "tenants.json"
    path.write_text(
        json.dumps(
            {
                "default": "contoso",
                "tenants": {
                    "contoso": {**entry, "sentinel_workspace_id": WS_ID},
                    "fabrikam": entry,
                },
            }
        )
    )
    os.chmod(path, 0o600)
    assert JsonFileCredentialProvider(path).sentinel_workspaces() == {
        "contoso": SentinelWorkspace(WS_ID)
    }


# ---------- token scopes ----------


def test_token_manager_issues_per_scope_tokens() -> None:
    msal = ScopeRecordingMsal()
    tm = TokenManager(FakeCredentialProvider(), msal_factory=lambda **_: msal)
    assert tm.get_token() == "tok-api.securitycenter.microsoft.com"
    assert tm.get_token(scope=LOG_ANALYTICS_SCOPE) == "tok-api.loganalytics.io"
    assert tm.get_token(scope=ARM_SCOPE) == "tok-management.azure.com"
    tm.get_token(scope=LOG_ANALYTICS_SCOPE)  # cached per scope
    assert msal.scopes == [DEFAULT_DEFENDER_SCOPE, LOG_ANALYTICS_SCOPE, ARM_SCOPE]
    tm.invalidate(scope=LOG_ANALYTICS_SCOPE)
    tm.get_token(scope=LOG_ANALYTICS_SCOPE)
    assert msal.scopes[-1] == LOG_ANALYTICS_SCOPE


def test_token_manager_refuses_unlisted_scope() -> None:
    tm = TokenManager(FakeCredentialProvider(), msal_factory=lambda **_: ScopeRecordingMsal())
    with pytest.raises(AuthError):
        tm.get_token(scope="https://graph.microsoft.com/.default")


async def test_client_error_messages_name_the_api() -> None:
    tm = TokenManager(FakeCredentialProvider(), msal_factory=lambda **_: ScopeRecordingMsal())
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    client = DefenderClient(
        tm, http_client=http, base_url="https://api.loganalytics.io", api_name="Log Analytics API"
    )
    with pytest.raises(NotFoundError, match="Log Analytics API"):
        await client.get("/x")


# ---------- query_sentinel ----------


async def test_query_sentinel_happy_path() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_la_response(3))

    ctx, msal = _context(handler, {"contoso": SentinelWorkspace(WS_ID)})
    async with ctx:
        result = await sentinel.run_query(ctx, {"query": "SigninLogs | take 3", "timespan": "PT4H"})

    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == f"https://api.loganalytics.io/v1/workspaces/{WS_ID}/query"
    assert json.loads(request.content) == {"query": "SigninLogs | take 3", "timespan": "PT4H"}
    assert request.headers["Authorization"] == "Bearer tok-api.loganalytics.io"
    assert msal.scopes == [LOG_ANALYTICS_SCOPE]
    assert result["schema"] == [
        {"name": "TimeGenerated", "type": "datetime"},
        {"name": "Ip", "type": "string"},
    ]
    assert result["rows"][0] == {"TimeGenerated": "2026-08-31T00:00:00Z", "Ip": "192.0.2.0"}
    assert result["metadata"] == {"row_count": 3, "truncated": False, "timespan": "PT4H"}
    assert result["untrusted_content_notice"] == sentinel.UNTRUSTED_NOTICE


async def test_query_sentinel_truncates_and_handles_odd_shapes() -> None:
    responses = iter([_la_response(5), {"tables": []}, {"tables": [{"columns": "x", "rows": 1}]}])
    ctx, _ = _context(
        lambda r: httpx.Response(200, json=next(responses)), {"contoso": SentinelWorkspace(WS_ID)}
    )
    async with ctx:
        capped = await sentinel.run_query(ctx, {"query": "T", "limit": 2})
        empty = await sentinel.run_query(ctx, {"query": "T"})
        odd = await sentinel.run_query(ctx, {"query": "T"})
    assert capped["metadata"]["truncated"] is True and len(capped["rows"]) == 2
    assert empty["rows"] == [] and odd["rows"] == []


async def test_query_sentinel_runs_saved_query() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"value": [_saved("hunt-1", query="Syslog | take 9")]})
        return httpx.Response(200, json=_la_response(1))

    ctx, msal = _context(handler, {"contoso": SentinelWorkspace(WS_ID, RID)})
    async with ctx:
        result = await sentinel.run_query(ctx, {"saved_query_id": "HUNT-1"})
    arm, la = seen
    assert str(arm.url) == f"https://management.azure.com{RID}/savedSearches?api-version=2020-08-01"
    assert arm.headers["Authorization"] == "Bearer tok-management.azure.com"
    assert json.loads(la.content)["query"] == "Syslog | take 9"
    assert result["saved_query"]["id"] == "hunt-1"
    assert set(msal.scopes) == {ARM_SCOPE, LOG_ANALYTICS_SCOPE}


async def test_query_sentinel_saved_query_errors() -> None:
    saved = {"value": [_saved("evil", query=".drop table SigninLogs"), _saved("blank", query="")]}
    ctx, _ = _context(
        lambda r: httpx.Response(200, json=saved), {"contoso": SentinelWorkspace(WS_ID, RID)}
    )
    async with ctx:
        with pytest.raises(NotFoundError):
            await sentinel.run_query(ctx, {"saved_query_id": "missing"})
        with pytest.raises(InvalidInputError, match="Saved query rejected"):
            await sentinel.run_query(ctx, {"saved_query_id": "evil"})
        with pytest.raises(InvalidInputError):
            await sentinel.run_query(ctx, {"saved_query_id": "blank"})


async def test_query_sentinel_needs_resource_id_for_saved_queries() -> None:
    ctx, _ = _context(lambda r: httpx.Response(500), {"contoso": SentinelWorkspace(WS_ID)})
    async with ctx:
        with pytest.raises(InvalidInputError, match="resource_id"):
            await sentinel.run_query(ctx, {"saved_query_id": "hunt-1"})


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"query": "T", "saved_query_id": "x"},
        {"query": ".ingest into T <| X"},
        {"query": "x" * 10_001},
        {"saved_query_id": "../../x"},
        {"query": "T", "timespan": "yesterday"},
        {"query": "T", "limit": 5000},
    ],
)
async def test_query_sentinel_rejects_bad_input(params: dict[str, Any]) -> None:
    ctx, _ = _context(
        lambda r: pytest.fail("no upstream call"), {"contoso": SentinelWorkspace(WS_ID)}
    )
    async with ctx:
        with pytest.raises(InvalidInputError):
            await sentinel.run_query(ctx, params)


async def test_query_sentinel_unconfigured_tenant_and_fan_out() -> None:
    ctx, _ = _context(
        lambda r: httpx.Response(200, json=_la_response(1)),
        {"contoso": SentinelWorkspace(WS_ID)},
        tenants=("contoso", "fabrikam"),
    )
    async with ctx:
        with pytest.raises(InvalidInputError, match="not configured"):
            await sentinel.run_query(ctx, {"query": "T", "tenant": "fabrikam"})
        result = await sentinel.run_query(ctx, {"query": "T", "tenant": "*"})
    by_tenant = {r["tenant"]: r for r in result["results"]}
    assert by_tenant["contoso"]["result"]["metadata"]["row_count"] == 1
    assert by_tenant["fabrikam"]["error"]["code"] == "invalid_input"


# ---------- list_sentinel_hunting_queries ----------


async def test_list_hunting_queries_filters() -> None:
    items = {
        "value": [
            _saved("b", tactics="Persistence, Execution", description="run keys"),
            _saved("a", tactics="CredentialAccess", techniques="T1003", description="lsass"),
            _saved("r", category="Reports"),
            {"name": "junk"},
            "not-a-dict",
        ]
    }
    ctx, msal = _context(
        lambda r: httpx.Response(200, json=items), {"contoso": SentinelWorkspace(WS_ID, RID)}
    )
    async with ctx:
        everything = await sentinel.run_list(ctx, {})
        persistence = await sentinel.run_list(
            ctx, {"tactic": "persistence", "include_query": False}
        )
        search = await sentinel.run_list(ctx, {"search": "LSASS"})
        reports = await sentinel.run_list(ctx, {"category": "reports", "limit": 1})
    assert [q["id"] for q in everything["hunting_queries"]] == ["a", "b"]
    assert everything["hunting_queries"][0]["techniques"] == ["T1003"]
    assert persistence["hunting_queries"][0]["tactics"] == ["Persistence", "Execution"]
    assert "query" not in persistence["hunting_queries"][0]
    assert [q["id"] for q in search["hunting_queries"]] == ["a"]
    assert reports["metadata"]["count"] == 1
    assert set(msal.scopes) == {ARM_SCOPE}


async def test_list_hunting_queries_requires_resource_id() -> None:
    ctx, _ = _context(lambda r: httpx.Response(500), {"contoso": SentinelWorkspace(WS_ID)})
    async with ctx:
        with pytest.raises(InvalidInputError, match="resource_id"):
            await sentinel.run_list(ctx, {})


# ---------- fixture mode ----------


@pytest.fixture
def fixture_ctx() -> ToolContext:
    return ToolContext(fixtures=FixtureStore.load(FIXTURE_DIR))


async def test_fixture_sentinel_query_and_list(fixture_ctx: ToolContext) -> None:
    async with fixture_ctx as ctx:
        listed = await sentinel.run_list(ctx, {})
        ran = await sentinel.run_query(ctx, {"saved_query_id": "fixture-hunt-beaconing"})
        fan = await sentinel.run_query(ctx, {"query": "CommonSecurityLog | take 10", "tenant": "*"})
    assert listed["fixture_mode"] is True
    assert len(listed["hunting_queries"]) == 3  # the "Reports" item is filtered out
    assert ran["saved_query"]["display_name"].startswith("Periodic outbound beaconing")
    # The saved search gets its own recorded, aggregated result shape...
    assert [c["name"] for c in ran["schema"]][-2:] == ["Connections", "Bytes"]
    assert ran["metadata"]["row_count"] == 4
    # ...while ad-hoc KQL gets the default result set.
    adhoc = fan["results"][0]["result"]
    assert "DeviceAction" in [c["name"] for c in adhoc["schema"]]
    slots = {r["tenant"]: r for r in fan["results"]}
    assert "result" in slots["contoso-fixture"]
    assert slots["fabrikam-fixture"]["error"]["code"] == "invalid_input"


def test_fixture_store_without_sentinel_file(tmp_path: Path) -> None:
    for name in ("advanced_hunting.json", "incidents.json", "alerts.json"):
        (tmp_path / name).write_text((FIXTURE_DIR / name).read_text("utf-8"), "utf-8")
    store = FixtureStore.load(tmp_path)
    assert store.sentinel == {} and store.sentinel_workspaces == {}
