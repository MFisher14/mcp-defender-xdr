"""Azure authentication and token management."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import msal

from .audit import audit
from .errors import AuthError

DEFAULT_DEFENDER_RESOURCE = "https://api.securitycenter.microsoft.com"
DEFAULT_DEFENDER_SCOPE = f"{DEFAULT_DEFENDER_RESOURCE}/.default"
#: Microsoft Sentinel queries go to the Log Analytics data plane...
LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io"
LOG_ANALYTICS_SCOPE = f"{LOG_ANALYTICS_RESOURCE}/.default"
#: ...and saved hunting queries are read from Azure Resource Manager.
ARM_RESOURCE = "https://management.azure.com"
ARM_SCOPE = f"{ARM_RESOURCE}/.default"
#: Every token audience this server may request. Pinned, so a code path cannot
#: quietly ask for a token to anything else (THREAT_MODEL.md, T3).
ALLOWED_SCOPES = frozenset({DEFAULT_DEFENDER_SCOPE, LOG_ANALYTICS_SCOPE, ARM_SCOPE})

DEFAULT_TENANT_KEY = "default"

_REFRESH_LEEWAY_SECONDS = 60

_TENANT_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_WORKSPACE_RESOURCE_ID_RE = re.compile(
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}"
    r"/providers/Microsoft\.OperationalInsights/workspaces/[A-Za-z0-9-]{4,63}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SentinelWorkspace:
    """A tenant's Microsoft Sentinel (Log Analytics) workspace."""

    #: Workspace (customer) ID, a GUID: used for KQL queries.
    workspace_id: str
    #: ARM resource ID: needed only to list saved hunting queries.
    resource_id: str | None = None

    @classmethod
    def from_config(cls, workspace_id: Any, resource_id: Any, *, where: str) -> SentinelWorkspace:
        if not isinstance(workspace_id, str) or not _GUID_RE.match(workspace_id.strip()):
            raise AuthError(f"{where}: sentinel_workspace_id must be a workspace GUID")
        if resource_id is not None and (
            not isinstance(resource_id, str)
            or not _WORKSPACE_RESOURCE_ID_RE.match(resource_id.strip())
        ):
            raise AuthError(
                f"{where}: sentinel_workspace_resource_id must look like /subscriptions/<id>"
                "/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>"
            )
        return cls(
            workspace_id=workspace_id.strip().lower(),
            resource_id=resource_id.strip() if isinstance(resource_id, str) else None,
        )


@dataclass(frozen=True)
class AzureCredentials:
    """Identity material for an Azure App Registration."""

    tenant_id: str
    client_id: str
    cert_path: str
    cert_passphrase: str | None = None

    def __repr__(self) -> str:
        passphrase_repr = "None" if self.cert_passphrase is None else "'***REDACTED***'"
        return (
            f"AzureCredentials(tenant_id={self.tenant_id!r}, "
            f"client_id={self.client_id!r}, cert_path={self.cert_path!r}, "
            f"cert_passphrase={passphrase_repr})"
        )

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"


class CredentialProvider(ABC):
    """Returns Azure credentials for a given logical tenant key."""

    @abstractmethod
    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials: ...

    def list_tenants(self) -> list[str]:
        return [DEFAULT_TENANT_KEY]

    @property
    def default_tenant_key(self) -> str:
        return DEFAULT_TENANT_KEY

    def sentinel_workspaces(self) -> dict[str, SentinelWorkspace]:
        """Sentinel workspaces keyed by tenant key; tenants without one are absent."""
        return {}


def _require_pfx_readable(path: str, *, source: str) -> None:
    pfx = Path(path)
    if not pfx.is_file():
        raise AuthError(f"Certificate file not found ({source}): {path}")
    if not os.access(pfx, os.R_OK):
        raise AuthError(f"Certificate file not readable ({source}): {path}")


class EnvCredentialProvider(CredentialProvider):
    """Loads a single tenant's credentials from process environment variables."""

    REQUIRED_VARS = ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CERT_PATH")
    PASSPHRASE_VAR = "AZURE_CERT_PASSPHRASE"  # noqa: S105

    def __init__(self, env: dict[str, str] | None = None) -> None:
        source: dict[str, str] = dict(env) if env is not None else dict(os.environ)
        missing = [name for name in self.REQUIRED_VARS if not source.get(name)]
        if missing:
            raise AuthError(
                "Missing required Azure credential environment variables: "
                + ", ".join(missing)
                + ". See .env.example for setup."
            )
        cert_path = source["AZURE_CERT_PATH"].strip()
        _require_pfx_readable(cert_path, source="AZURE_CERT_PATH")
        passphrase = source.get(self.PASSPHRASE_VAR) or None
        workspace_id = source.get("MCP_DEFENDER_XDR_SENTINEL_WORKSPACE_ID")
        resource_id = source.get("MCP_DEFENDER_XDR_SENTINEL_WORKSPACE_RESOURCE_ID") or None
        if resource_id and not workspace_id:
            raise AuthError(
                "MCP_DEFENDER_XDR_SENTINEL_WORKSPACE_RESOURCE_ID requires "
                "MCP_DEFENDER_XDR_SENTINEL_WORKSPACE_ID"
            )
        self._sentinel = (
            SentinelWorkspace.from_config(workspace_id, resource_id, where="environment")
            if workspace_id
            else None
        )
        self._credentials = AzureCredentials(
            tenant_id=source["AZURE_TENANT_ID"].strip(),
            client_id=source["AZURE_CLIENT_ID"].strip(),
            cert_path=cert_path,
            cert_passphrase=passphrase,
        )

    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        if tenant_key != DEFAULT_TENANT_KEY:
            raise AuthError("Unknown tenant")
        return self._credentials

    def sentinel_workspaces(self) -> dict[str, SentinelWorkspace]:
        return {DEFAULT_TENANT_KEY: self._sentinel} if self._sentinel else {}


class JsonFileCredentialProvider(CredentialProvider):
    """Loads N tenant credential bundles from a JSON config file."""

    def __init__(self, path: str | Path, *, env: dict[str, str] | None = None) -> None:
        self._path = Path(path)
        env_source: dict[str, str] = dict(env) if env is not None else dict(os.environ)
        if not self._path.is_file():
            raise AuthError(f"Tenants config file not found: {self._path}")
        self._check_permissions(self._path)
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AuthError(f"Failed to read tenants config: {self._path}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthError(f"Tenants config is not valid JSON: {self._path}") from exc

        self._default_tenant, self._tenants = self._parse(data, env_source)
        self._sentinel = {
            key: SentinelWorkspace.from_config(
                entry.get("sentinel_workspace_id"),
                entry.get("sentinel_workspace_resource_id"),
                where=f"Tenant '{key}'",
            )
            for key, entry in data["tenants"].items()
            if entry.get("sentinel_workspace_id") is not None
            or entry.get("sentinel_workspace_resource_id") is not None
        }

    @staticmethod
    def _check_permissions(path: Path) -> None:
        if sys.platform.startswith("win"):
            return
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            raise AuthError(f"Failed to stat tenants config: {path}") from exc
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise AuthError(
                f"Tenants config file permissions are too permissive (need 0600): {path}"
            )

    @staticmethod
    def _parse(data: Any, env_source: dict[str, str]) -> tuple[str, dict[str, AzureCredentials]]:
        if not isinstance(data, dict):
            raise AuthError("Tenants config root must be a JSON object")
        tenants_raw = data.get("tenants")
        if not isinstance(tenants_raw, dict) or not tenants_raw:
            raise AuthError("Tenants config must contain a non-empty 'tenants' object")

        parsed: dict[str, AzureCredentials] = {}
        for key, entry in tenants_raw.items():
            if not isinstance(key, str) or not _TENANT_KEY_RE.match(key):
                raise AuthError(
                    "Invalid tenant key in tenants config (must match [A-Za-z0-9_-]{1,64})"
                )
            if not isinstance(entry, dict):
                raise AuthError(f"Tenant entry must be an object: '{key}'")
            tenant_id = entry.get("tenant_id")
            client_id = entry.get("client_id")
            cert_path = entry.get("cert_path")
            if not (
                isinstance(tenant_id, str)
                and isinstance(client_id, str)
                and isinstance(cert_path, str)
            ):
                raise AuthError(
                    f"Tenant '{key}' missing required string fields "
                    "(tenant_id, client_id, cert_path)"
                )
            _require_pfx_readable(cert_path, source=f"tenant '{key}'")
            passphrase = JsonFileCredentialProvider._resolve_passphrase(key, entry, env_source)
            parsed[key] = AzureCredentials(
                tenant_id=tenant_id.strip(),
                client_id=client_id.strip(),
                cert_path=cert_path,
                cert_passphrase=passphrase,
            )

        default_key = data.get("default")
        if not isinstance(default_key, str) or default_key not in parsed:
            raise AuthError("Tenants config 'default' must name an existing tenant key")
        return default_key, parsed

    @staticmethod
    def _resolve_passphrase(
        tenant_key: str, entry: dict[str, Any], env_source: dict[str, str]
    ) -> str | None:
        env_name = entry.get("cert_passphrase_env")
        inline = entry.get("cert_passphrase")
        if env_name is not None and inline is not None:
            raise AuthError(
                f"Tenant '{tenant_key}' specifies both cert_passphrase_env and "
                "cert_passphrase; choose one."
            )
        if isinstance(env_name, str) and env_name:
            value = env_source.get(env_name)
            if not value:
                raise AuthError(
                    f"Tenant '{tenant_key}' cert_passphrase_env '{env_name}' "
                    "is not set in the environment"
                )
            return value
        if isinstance(inline, str) and inline:
            audit(
                "tenants-config-inline-passphrase",
                tenant=tenant_key,
                advice="prefer cert_passphrase_env to keep secrets out of config files",
            )
            return inline
        return None

    def get_credentials(self, tenant_key: str = DEFAULT_TENANT_KEY) -> AzureCredentials:
        resolved = self._default_tenant if tenant_key == DEFAULT_TENANT_KEY else tenant_key
        creds = self._tenants.get(resolved)
        if creds is None:
            raise AuthError("Unknown tenant")
        return creds

    def list_tenants(self) -> list[str]:
        return sorted(self._tenants.keys())

    @property
    def default_tenant_key(self) -> str:
        return self._default_tenant

    def sentinel_workspaces(self) -> dict[str, SentinelWorkspace]:
        return dict(self._sentinel)


class _MsalAppFactory(Protocol):
    def __call__(
        self,
        *,
        client_id: str,
        authority: str,
        client_credential: dict[str, Any],
    ) -> msal.ConfidentialClientApplication: ...


def _default_msal_factory(
    *,
    client_id: str,
    authority: str,
    client_credential: dict[str, Any],
) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=client_id,
        authority=authority,
        client_credential=client_credential,
    )


def _build_client_credential(creds: AzureCredentials) -> dict[str, Any]:
    payload: dict[str, Any] = {"private_key_pfx_path": creds.cert_path}
    if creds.cert_passphrase is not None:
        payload["passphrase"] = creds.cert_passphrase
    return payload


@dataclass
class _CachedToken:
    access_token: str
    expires_at_epoch: float

    def is_fresh(self, now: float, leeway: float = _REFRESH_LEEWAY_SECONDS) -> bool:
        return self.expires_at_epoch - leeway > now


class TokenManager:
    """Acquires and caches access tokens for the Defender API."""

    def __init__(
        self,
        credential_provider: CredentialProvider,
        *,
        scope: str = DEFAULT_DEFENDER_SCOPE,
        msal_factory: _MsalAppFactory | None = None,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        self._credential_provider = credential_provider
        self._scope = scope
        self._msal_factory = msal_factory or _default_msal_factory
        self._time_source: Callable[[], float] = time_source or time.time
        self._cache: dict[tuple[str, str], _CachedToken] = {}
        self._apps: dict[str, msal.ConfidentialClientApplication] = {}
        self._lock = threading.Lock()

    @property
    def scope(self) -> str:
        return self._scope

    @property
    def default_tenant_key(self) -> str:
        return self._credential_provider.default_tenant_key

    def list_tenants(self) -> list[str]:
        return self._credential_provider.list_tenants()

    def sentinel_workspaces(self) -> dict[str, SentinelWorkspace]:
        return self._credential_provider.sentinel_workspaces()

    def get_token(self, tenant_key: str = DEFAULT_TENANT_KEY, scope: str | None = None) -> str:
        """Return a cached or fresh token for ``tenant_key``.

        ``scope`` defaults to the Defender API. Other audiences (Log Analytics,
        ARM) must be in :data:`ALLOWED_SCOPES`.
        """
        resolved_scope = scope or self._scope
        if resolved_scope not in ALLOWED_SCOPES and resolved_scope != self._scope:
            raise AuthError("Requested token scope is not permitted")
        cache_key = (tenant_key, resolved_scope)
        now = self._time_source()
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None and cached.is_fresh(now):
                return cached.access_token
            new_token = self._acquire(tenant_key, resolved_scope)
            self._cache[cache_key] = new_token
            return new_token.access_token

    def invalidate(self, tenant_key: str = DEFAULT_TENANT_KEY, scope: str | None = None) -> None:
        with self._lock:
            self._cache.pop((tenant_key, scope or self._scope), None)

    def _acquire(self, tenant_key: str, scope: str) -> _CachedToken:
        credentials = self._credential_provider.get_credentials(tenant_key)
        app = self._apps.get(tenant_key)
        if app is None:
            app = self._msal_factory(
                client_id=credentials.client_id,
                authority=credentials.authority,
                client_credential=_build_client_credential(credentials),
            )
            self._apps[tenant_key] = app

        result = app.acquire_token_for_client(scopes=[scope])

        if not isinstance(result, dict) or "access_token" not in result:
            error_code = result.get("error") if isinstance(result, dict) else "unknown_error"
            raise AuthError(f"Failed to acquire Azure access token: {error_code}")

        access_token = str(result["access_token"])
        expires_in = float(result.get("expires_in", 3300))
        expires_at = self._time_source() + expires_in
        return _CachedToken(access_token=access_token, expires_at_epoch=expires_at)


def build_default_token_manager() -> TokenManager:
    """Build the token manager used by the production server."""
    tenants_file = os.environ.get("MCP_DEFENDER_XDR_TENANTS_FILE")
    provider: CredentialProvider
    if tenants_file:
        provider = JsonFileCredentialProvider(tenants_file)
    else:
        provider = EnvCredentialProvider()
    return TokenManager(provider)
