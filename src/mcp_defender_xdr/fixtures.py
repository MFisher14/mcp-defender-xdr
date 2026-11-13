"""Offline fixture mode: recorded synthetic responses in place of live Azure calls.

Fixture mode lets a reviewer exercise all three tools with **no Azure tenant, no
App Registration, and no certificate**. It replaces only the HTTP + OAuth layer:
the recorded payloads are shaped exactly like real upstream Defender responses,
so validation, the per-tool response transforms, fan-out, and the audit log all
run for real against them.

Two properties are load-bearing and deliberately awkward to defeat:

1. **It cannot be enabled by accident.** ``MCP_DEFENDER_XDR_FIXTURE_MODE`` must
   equal :data:`FIXTURE_MODE_TOKEN` exactly. Any other non-empty value is a hard
   startup failure rather than a silent fall-through to either mode, so a
   half-remembered ``=1`` never quietly serves fake data — nor quietly reaches a
   live tenant.
2. **Its output cannot be mistaken for live data.** Every tool result carries a
   ``fixture_mode`` flag and a ``notice``, and every tool call emits a
   WARNING-level audit record. See :func:`mark_result`.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .auth import SentinelWorkspace
from .errors import ConfigError, NotFoundError, UpstreamError
from .kql import TAG_RE

FIXTURE_MODE_ENV = "MCP_DEFENDER_XDR_FIXTURE_MODE"

#: The one value that turns fixture mode on. Deliberately long and descriptive:
#: nobody sets this by muscle memory or by copying a generic ``=true``.
FIXTURE_MODE_TOKEN = "synthetic-fixtures-no-live-data"  # noqa: S105 - mode sentinel

#: Attached to every fixture-mode tool result and audit record.
SYNTHETIC_NOTICE = (
    "SYNTHETIC FIXTURE DATA — generated for offline evaluation. "
    "This did NOT come from a live Microsoft Defender tenant. "
    "Hostnames, accounts, and IP addresses are invented; IPs are RFC 5737 "
    "documentation ranges. Do not treat any of it as a real detection."
)

#: Audit event name for the per-call warning. Shouty on purpose — it should be
#: impossible to skim a log and miss that the run was not live.
FIXTURE_AUDIT_EVENT = "FIXTURE-MODE-ACTIVE-SYNTHETIC-DATA"

#: Synthetic tenant keys, so ``tenant: "*"`` fan-out is demonstrable offline.
FIXTURE_TENANTS: tuple[str, ...] = ("contoso-fixture", "fabrikam-fixture")
FIXTURE_DEFAULT_TENANT = FIXTURE_TENANTS[0]

_ADVANCED_HUNTING_FILE = "advanced_hunting.json"
_INCIDENTS_FILE = "incidents.json"
_ALERTS_FILE = "alerts.json"
#: Optional: recorded results for the server-built investigation queries.
_INVESTIGATIONS_FILE = "investigations.json"
#: Optional: a Sentinel workspace per fixture tenant, a query result, saved searches.
_SENTINEL_FILE = "sentinel.json"
_LA_QUERY_RE = re.compile(r"^/v1/workspaces/(?P<ws>[0-9a-f-]{36})/query$")

_PACKAGED_FIXTURE_DIR = "fixture_data"

_ADVANCED_HUNTING_PATH = "/api/advancedqueries/run"
_ALERTS_PATH = "/api/alerts"
_INCIDENT_PATH_PREFIX = "/api/incidents/"

# The only OData filter shape `list_alerts` builds: `field eq 'value'`, joined
# by ` and `. Anything else is a bug in the caller, not something to guess at.
_FILTER_CLAUSE_RE = re.compile(r"^(?P<field>[A-Za-z][A-Za-z0-9_]*) eq '(?P<value>[^']*)'$")


def fixture_mode_requested(env: Mapping[str, str] | None = None) -> bool:
    """Return whether offline fixture mode is switched on.

    Raises:
        ConfigError: if the variable is set to anything other than the exact
            sentinel. Refusing is the point: an unrecognized value must never
            resolve to *either* mode by default.
    """
    source: Mapping[str, str] = os.environ if env is None else env
    raw = source.get(FIXTURE_MODE_ENV)
    if raw is None or not raw.strip():
        return False
    if raw.strip() == FIXTURE_MODE_TOKEN:
        return True
    raise ConfigError(
        f"{FIXTURE_MODE_ENV} is set to an unrecognized value. Offline fixture mode "
        f"must be enabled with the exact value '{FIXTURE_MODE_TOKEN}'; every other "
        "value is refused so that fixture mode cannot be switched on — or off — by "
        f"accident. Unset {FIXTURE_MODE_ENV} to run against live Defender APIs."
    )


def fixture_search_paths() -> list[Path]:
    """Directories searched for fixture JSON, in priority order."""
    here = Path(__file__).resolve().parent
    return [
        # Built wheels: examples/fixtures is force-included here (see pyproject).
        here / _PACKAGED_FIXTURE_DIR,
        # Source checkout / editable install: read examples/fixtures directly, so
        # the files a reviewer reads are byte-for-byte the ones the server serves.
        here.parent.parent / "examples" / "fixtures",
    ]


def _resolve_fixture_dir() -> Path:
    candidates = fixture_search_paths()
    for candidate in candidates:
        if (candidate / _ADVANCED_HUNTING_FILE).is_file():
            return candidate
    searched = ", ".join(str(c) for c in candidates)
    raise ConfigError(
        f"Fixture mode is enabled but no fixture data was found. Searched: {searched}."
    )


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Failed to read fixture file: {path}") from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Fixture file is not valid JSON: {path}") from exc
    if not isinstance(parsed, dict):
        raise ConfigError(f"Fixture file must contain a JSON object: {path}")
    return parsed


def _load_hunting_views(path: Path) -> dict[str, dict[str, Any]]:
    """Load the per-view, per-subject hunting results (optional file)."""
    if not path.is_file():
        return {}
    views = _load_json_object(path).get("views")
    if not isinstance(views, dict):
        raise ConfigError(f"Fixture file must contain a 'views' object: {path}")
    parsed: dict[str, dict[str, Any]] = {}
    for view, subjects in views.items():
        if not isinstance(subjects, dict):
            raise ConfigError(f"Fixture view '{view}' must be an object: {path}")
        parsed[str(view)] = {str(k).lower(): v for k, v in subjects.items()}
    return parsed


@dataclass(frozen=True)
class FixtureStore:
    """Recorded upstream payloads, keyed the way the live API returns them."""

    advanced_hunting: dict[str, Any]
    incidents: dict[str, Any]
    alerts: dict[str, Any]
    source_dir: Path
    #: ``{view: {subject: raw hunting response}}``; see ``investigations.json``.
    hunting_views: dict[str, dict[str, Any]] = field(default_factory=dict)
    tenants: tuple[str, ...] = FIXTURE_TENANTS
    default_tenant_key: str = FIXTURE_DEFAULT_TENANT
    #: Recorded Sentinel payloads; see ``sentinel.json``. Empty when absent.
    sentinel: dict[str, Any] = field(default_factory=dict)
    sentinel_workspaces: dict[str, SentinelWorkspace] = field(default_factory=dict)

    @classmethod
    def load(cls, directory: Path | None = None) -> FixtureStore:
        source = directory if directory is not None else _resolve_fixture_dir()
        incidents = _load_json_object(source / _INCIDENTS_FILE)
        if not incidents:
            raise ConfigError(f"Incident fixtures are empty: {source / _INCIDENTS_FILE}")
        sentinel_path = source / _SENTINEL_FILE
        sentinel = _load_json_object(sentinel_path) if sentinel_path.is_file() else {}
        workspaces_raw = sentinel.get("workspaces", {})
        if not isinstance(workspaces_raw, dict):
            raise ConfigError(f"'workspaces' must be an object: {sentinel_path}")
        workspaces: dict[str, SentinelWorkspace] = {}
        for tenant, ws in workspaces_raw.items():
            if not isinstance(ws, dict):
                raise ConfigError(f"Sentinel workspace for '{tenant}' must be an object")
            workspaces[str(tenant)] = SentinelWorkspace.from_config(
                ws.get("workspace_id"), ws.get("resource_id"), where=f"fixture '{tenant}'"
            )
        return cls(
            advanced_hunting=_load_json_object(source / _ADVANCED_HUNTING_FILE),
            incidents=incidents,
            alerts=_load_json_object(source / _ALERTS_FILE),
            source_dir=source,
            hunting_views=_load_hunting_views(source / _INVESTIGATIONS_FILE),
            sentinel=sentinel,
            sentinel_workspaces=workspaces,
        )

    def list_tenants(self) -> list[str]:
        return list(self.tenants)


def _clause_matches(alert: Mapping[str, Any], clause: str) -> bool:
    match = _FILTER_CLAUSE_RE.match(clause.strip())
    if match is None:
        raise UpstreamError(f"Fixture mode cannot evaluate OData filter clause: {clause!r}")
    return str(alert.get(match["field"], "")) == match["value"]


def _alert_matches(alert: Mapping[str, Any], odata_filter: str | None) -> bool:
    if not odata_filter:
        return True
    return all(_clause_matches(alert, clause) for clause in odata_filter.split(" and "))


class FixtureClient:
    """Serves :class:`FixtureStore` payloads over the ``DefenderApi`` surface.

    Returns *raw upstream shapes*, not finished tool output, so every tool's real
    parsing and summarizing code runs against fixtures exactly as it does against
    the live API.
    """

    def __init__(self, store: FixtureStore, tenant_key: str) -> None:
        self._store = store
        self._tenant_key = tenant_key

    @property
    def tenant_key(self) -> str:
        return self._tenant_key

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if path.startswith(_INCIDENT_PATH_PREFIX):
            return self._incident(path[len(_INCIDENT_PATH_PREFIX) :])
        if path == _ALERTS_PATH:
            return self._alerts(params)
        if path.endswith("/savedSearches") and isinstance(
            self._store.sentinel.get("saved_searches"), dict
        ):
            return dict(self._store.sentinel["saved_searches"])
        raise UpstreamError(f"No fixture recorded for GET {path}")

    async def post(self, path: str, *, json: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if _LA_QUERY_RE.match(path) and isinstance(self._store.sentinel.get("query_result"), dict):
            return self._sentinel_query(json)
        if path != _ADVANCED_HUNTING_PATH:
            raise UpstreamError(f"No fixture recorded for POST {path}")
        query = (json or {}).get("Query")
        first_line = query.split("\n", 1)[0] if isinstance(query, str) else ""
        tag = TAG_RE.match(first_line)
        if tag is None:
            # Free-form KQL: the recorded result set is returned regardless of the query.
            return dict(self._store.advanced_hunting)
        return self._hunting_view(tag["view"], tag["subject"])

    def _hunting_view(self, view: str, subject: str) -> dict[str, Any]:
        """Serve a server-built investigation query from ``investigations.json``."""
        subjects = self._store.hunting_views.get(view)
        if subjects is None:
            raise UpstreamError(f"No fixture recorded for hunting view {view!r}")
        recorded = subjects.get(subject.lower())
        if not isinstance(recorded, dict):
            # Nothing recorded for this subject: behave like a query with no matches.
            return {"Schema": [], "Results": []}
        return dict(recorded)

    def _sentinel_query(self, body: Mapping[str, Any] | None) -> dict[str, Any]:
        """Serve a saved search's own result when its exact KQL is posted, else the default."""
        query = (body or {}).get("query")
        saved = self._store.sentinel.get("saved_searches", {}).get("value", [])
        per_search = self._store.sentinel.get("saved_search_results", {})
        if isinstance(saved, list) and isinstance(per_search, dict):
            for item in saved:
                props = item.get("properties", {}) if isinstance(item, dict) else {}
                recorded = per_search.get(item.get("name")) if isinstance(item, dict) else None
                if isinstance(recorded, dict) and props.get("query") == query:
                    return dict(recorded)
        return dict(self._store.sentinel["query_result"])

    def _incident(self, incident_id: str) -> dict[str, Any]:
        incident = self._store.incidents.get(incident_id)
        if not isinstance(incident, dict):
            # Mirrors the live 404 so error mapping is demonstrable offline.
            raise NotFoundError("Defender API returned 404 Not Found", status_code=404)
        return dict(incident)

    def _alerts(self, params: Mapping[str, Any] | None) -> dict[str, Any]:
        raw = self._store.alerts.get("value", [])
        alerts: list[dict[str, Any]] = (
            [a for a in raw if isinstance(a, dict)] if isinstance(raw, list) else []
        )
        query = params or {}
        odata_filter = query.get("$filter")
        selected = [a for a in alerts if _alert_matches(a, odata_filter)]
        top = query.get("$top")
        if isinstance(top, int) and top >= 0:
            selected = selected[:top]
        return {"value": selected}


def mark_result(result: dict[str, Any]) -> dict[str, Any]:
    """Stamp a tool result as synthetic, in the payload the model actually reads."""
    marked = dict(result)
    marked["fixture_mode"] = True
    marked["notice"] = SYNTHETIC_NOTICE
    return marked
