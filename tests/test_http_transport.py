"""Tests for the Streamable HTTP transport and its bearer-token authentication (#2, #5)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import secrets
import socket
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_defender_xdr import audit as audit_module
from mcp_defender_xdr.errors import ConfigError
from mcp_defender_xdr.fixtures import FixtureStore
from mcp_defender_xdr.http_transport import (
    ALLOW_PLAINTEXT_TOKEN,
    DEFAULT_MAX_TTL_SECONDS,
    HttpSettings,
    JwtSettings,
    Principal,
    ReplayGuard,
    TokenRejected,
    TokenValidator,
    build_http_app,
    http_settings_from_env,
    jwt_settings_from_env,
)
from mcp_defender_xdr.server import build_server, resolve_transport

SECRET = "s" * 48
AUD = "mcp-defender-xdr://test"
ISS = "https://tokens.example.com"
BASE_ENV = {
    "MCP_DEFENDER_XDR_JWT_SECRET": SECRET,
    "MCP_DEFENDER_XDR_JWT_AUDIENCE": AUD,
    "MCP_DEFENDER_XDR_JWT_ISSUER": ISS,
}


def mint(
    *,
    key: Any = SECRET,
    algorithm: str = "HS256",
    sub: str = "analyst@example.com",
    ttl: int = 600,
    iat_offset: int = 0,
    drop: tuple[str, ...] = (),
    **overrides: Any,
) -> str:
    now = int(time.time()) + iat_offset
    claims: dict[str, Any] = {
        "iss": ISS,
        "aud": AUD,
        "sub": sub,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_urlsafe(16),
        **overrides,
    }
    for name in drop:
        claims.pop(name, None)
    return jwt.encode(claims, key, algorithm=algorithm)


@pytest.fixture
def validator() -> TokenValidator:
    return TokenValidator(jwt_settings_from_env(BASE_ENV))


# ---------- transport selection ----------


def test_transport_defaults_to_stdio() -> None:
    assert resolve_transport(None, {}) == "stdio"


def test_cli_flag_beats_env() -> None:
    assert resolve_transport("stdio", {"MCP_DEFENDER_XDR_TRANSPORT": "http"}) == "stdio"
    assert resolve_transport(None, {"MCP_DEFENDER_XDR_TRANSPORT": " HTTP "}) == "http"


def test_unknown_transport_is_refused() -> None:
    with pytest.raises(ConfigError):
        resolve_transport(None, {"MCP_DEFENDER_XDR_TRANSPORT": "sse"})


def test_audit_records_carry_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit_module, "_transport", "stdio")
    record = logging.LogRecord("mcp_defender_xdr.audit", logging.INFO, "", 0, "probe", None, None)
    formatter = audit_module._JsonFormatter()
    assert json.loads(formatter.format(record))["transport"] == "stdio"
    audit_module.set_transport("http")
    assert json.loads(formatter.format(record))["transport"] == "http"


def test_main_exits_2_on_bad_http_config(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_defender_xdr import server

    monkeypatch.setattr(audit_module, "_transport", "stdio")
    monkeypatch.setenv("MCP_DEFENDER_XDR_TRANSPORT", "http")
    monkeypatch.delenv("MCP_DEFENDER_XDR_JWT_SECRET", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        server.main([])
    assert excinfo.value.code == 2


def test_main_rejects_host_without_http(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_defender_xdr import server

    monkeypatch.setattr(audit_module, "_transport", "stdio")
    monkeypatch.delenv("MCP_DEFENDER_XDR_TRANSPORT", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        server.main(["--port", "9000"])
    assert excinfo.value.code == 2


# ---------- settings ----------


def test_settings_defaults_bind_loopback() -> None:
    settings = http_settings_from_env(BASE_ENV)
    assert (settings.host, settings.port, settings.path) == ("127.0.0.1", 8765, "/mcp")
    assert settings.jwt.max_ttl_seconds == DEFAULT_MAX_TTL_SECONDS == 900
    assert "127.0.0.1:8765" in settings.allowed_hosts
    assert SECRET not in repr(settings.jwt)


@pytest.mark.parametrize(
    "env",
    [
        {k: v for k, v in BASE_ENV.items() if k != "MCP_DEFENDER_XDR_JWT_AUDIENCE"},
        {k: v for k, v in BASE_ENV.items() if k != "MCP_DEFENDER_XDR_JWT_ISSUER"},
        {k: v for k, v in BASE_ENV.items() if k != "MCP_DEFENDER_XDR_JWT_SECRET"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_JWT_SECRET": "short"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_JWT_ALGORITHM": "none"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_JWT_ALGORITHM": "RS256"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE": "/k.pem"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_JWT_MAX_TTL_SECONDS": "86400"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_JWT_MAX_TTL_SECONDS": "abc"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_HTTP_PORT": "0"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_HTTP_PATH": "mcp"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_HTTP_TLS_CERTFILE": "/c.pem"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_HTTP_HOST": "0.0.0.0"},
        {**BASE_ENV, "MCP_DEFENDER_XDR_HTTP_HOST": "10.0.0.5"},
        {
            **BASE_ENV,
            "MCP_DEFENDER_XDR_HTTP_HOST": "0.0.0.0",
            "MCP_DEFENDER_XDR_HTTP_ALLOW_PLAINTEXT": "true",
        },
    ],
)
def test_bad_settings_are_refused(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        http_settings_from_env(env)


def test_non_loopback_allowed_with_tls_or_explicit_proxy_opt_in() -> None:
    tls = http_settings_from_env(
        {
            **BASE_ENV,
            "MCP_DEFENDER_XDR_HTTP_HOST": "0.0.0.0",
            "MCP_DEFENDER_XDR_HTTP_TLS_CERTFILE": "/c.pem",
            "MCP_DEFENDER_XDR_HTTP_TLS_KEYFILE": "/k.pem",
            "MCP_DEFENDER_XDR_HTTP_ALLOWED_HOSTS": "mcp.example.com, mcp.example.com:443",
        }
    )
    assert tls.allowed_hosts == ("mcp.example.com", "mcp.example.com:443")
    proxied = http_settings_from_env(
        {
            **BASE_ENV,
            "MCP_DEFENDER_XDR_HTTP_HOST": "10.0.0.5",
            "MCP_DEFENDER_XDR_HTTP_ALLOW_PLAINTEXT": ALLOW_PLAINTEXT_TOKEN,
        },
        port=9443,
    )
    assert "10.0.0.5:9443" in proxied.allowed_hosts


def test_cli_host_and_port_override_env() -> None:
    settings = http_settings_from_env(
        {**BASE_ENV, "MCP_DEFENDER_XDR_HTTP_PORT": "9000"}, host="localhost", port=9100
    )
    assert (settings.host, settings.port) == ("localhost", 9100)


def _ec_keypair(tmp_path: Path) -> tuple[Any, Path]:
    private = ec.generate_private_key(ec.SECP256R1())
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path = tmp_path / "pub.pem"
    path.write_bytes(public_pem)
    return private, path


def test_asymmetric_settings(tmp_path: Path) -> None:
    private, pub = _ec_keypair(tmp_path)
    env = {
        "MCP_DEFENDER_XDR_JWT_ALGORITHM": "ES256",
        "MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE": str(pub),
        "MCP_DEFENDER_XDR_JWT_AUDIENCE": AUD,
        "MCP_DEFENDER_XDR_JWT_ISSUER": ISS,
    }
    validator = TokenValidator(jwt_settings_from_env(env))
    principal = validator.validate(mint(key=private, algorithm="ES256"))
    assert principal.subject == "analyst@example.com"

    with pytest.raises(ConfigError, match="private key"):
        priv_path = tmp_path / "priv.pem"
        priv_path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        jwt_settings_from_env({**env, "MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE": str(priv_path)})
    with pytest.raises(ConfigError, match="shared secret"):
        jwt_settings_from_env({**env, "MCP_DEFENDER_XDR_JWT_SECRET": SECRET})
    with pytest.raises(ConfigError, match="Cannot read"):
        jwt_settings_from_env({**env, "MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE": "/nope.pem"})


# ---------- token validation ----------


def test_valid_token(validator: TokenValidator) -> None:
    principal = validator.validate(mint(sub="alice"))
    assert principal.subject == "alice"
    assert principal.expires_at > time.time()


@pytest.mark.parametrize(
    ("token_kwargs", "reason"),
    [
        ({"ttl": -120}, "expired"),
        ({"aud": "someone-else"}, "wrong_audience"),
        ({"iss": "https://evil.example.com"}, "wrong_issuer"),
        ({"key": "x" * 48}, "invalid_signature"),
        ({"drop": ("jti",)}, "missing_claim"),
        ({"drop": ("sub",)}, "missing_claim"),
        ({"drop": ("exp",)}, "missing_claim"),
        ({"drop": ("iat",)}, "missing_claim"),
        ({"ttl": 3600}, "lifetime_too_long"),
        ({"iat_offset": 600}, "not_yet_valid"),
        ({"nbf": int(time.time()) + 600}, "not_yet_valid"),
        ({"jti": "short"}, "invalid_token"),
        ({"algorithm": "HS512"}, "algorithm_not_allowed"),
    ],
)
def test_rejected_tokens(
    validator: TokenValidator, token_kwargs: dict[str, Any], reason: str
) -> None:
    with pytest.raises(TokenRejected) as excinfo:
        validator.validate(mint(**token_kwargs))
    assert excinfo.value.reason == reason


def test_alg_none_and_garbage_are_rejected(validator: TokenValidator) -> None:
    unsigned = jwt.encode(
        {"iss": ISS, "aud": AUD, "sub": "x", "iat": 1, "exp": 2, "jti": "j" * 16},
        key=None,  # type: ignore[arg-type]
        algorithm="none",
    )
    for token in (unsigned, "not.a.jwt", "garbage"):
        with pytest.raises(TokenRejected):
            validator.validate(token)


def test_hs256_server_rejects_rs_confusion(tmp_path: Path, validator: TokenValidator) -> None:
    private, _ = _ec_keypair(tmp_path)
    with pytest.raises(TokenRejected) as excinfo:
        validator.validate(mint(key=private, algorithm="ES256"))
    assert excinfo.value.reason == "algorithm_not_allowed"


# ---------- replay guard ----------


def _principal(sub: str = "alice", jti: str | None = None) -> Principal:
    return Principal(
        subject=sub, token_id=jti or secrets.token_urlsafe(12), expires_at=time.time() + 600
    )


def test_token_opens_only_one_session() -> None:
    guard = ReplayGuard()
    p = _principal()
    guard.check(p, None)
    guard.bind_session(p, "s1")
    guard.check(p, "s1")  # continuing its own session is fine
    with pytest.raises(TokenRejected) as excinfo:
        guard.check(p, None)
    assert excinfo.value.reason == "token_replayed"


def test_token_cannot_move_to_another_session() -> None:
    guard = ReplayGuard()
    a, b = _principal(), _principal()
    guard.check(a, None)
    guard.bind_session(a, "s1")
    guard.check(b, None)
    guard.bind_session(b, "s2")
    with pytest.raises(TokenRejected) as excinfo:
        guard.check(a, "s2")
    assert excinfo.value.reason == "token_replayed"


def test_refreshed_token_for_same_subject_continues_session() -> None:
    guard = ReplayGuard()
    first = _principal("alice")
    guard.check(first, None)
    guard.bind_session(first, "s1")
    refreshed = _principal("alice")
    guard.check(refreshed, "s1")
    guard.check(refreshed, "s1")


def test_other_subject_cannot_use_session() -> None:
    guard = ReplayGuard()
    alice = _principal("alice")
    guard.check(alice, None)
    guard.bind_session(alice, "s1")
    with pytest.raises(TokenRejected) as excinfo:
        guard.check(_principal("mallory"), "s1")
    assert (excinfo.value.reason, excinfo.value.status) == ("session_subject_mismatch", 403)


def test_released_token_may_retry() -> None:
    guard = ReplayGuard()
    p = _principal()
    guard.check(p, None)
    guard.release(p)  # e.g. the probe was answered 400
    guard.check(p, None)
    guard.bind_session(p, "s1")
    guard.release(p)  # no-op once bound
    with pytest.raises(TokenRejected):
        guard.check(p, None)


def test_unknown_session_is_404() -> None:
    with pytest.raises(TokenRejected) as excinfo:
        ReplayGuard().check(_principal(), "never-opened")
    assert excinfo.value.status == 404


def test_expired_bindings_are_pruned() -> None:
    now = [1000.0]
    guard = ReplayGuard(clock=lambda: now[0])
    p = Principal(subject="a", token_id="t" * 12, expires_at=1100.0)
    guard.check(p, None)
    now[0] = 1200.0
    guard.check(Principal(subject="a", token_id="u" * 12, expires_at=1300.0), None)
    assert "t" * 12 not in guard._tokens


# ---------- middleware without a server ----------


async def _call(
    app: Any, path: str = "/mcp", headers: dict[str, str] | None = None
) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765") as client:
        return await client.post(path, headers=headers or {}, content=b"{}")


def _settings(**kw: Any) -> HttpSettings:
    return HttpSettings(jwt=jwt_settings_from_env(BASE_ENV), **kw)


async def _ok_app(scope: Any, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _middleware() -> Any:
    from mcp_defender_xdr.http_transport import BearerAuthMiddleware

    return BearerAuthMiddleware(
        _ok_app,
        path="/mcp",
        validator=TokenValidator(jwt_settings_from_env(BASE_ENV)),
        guard=ReplayGuard(),
    )


async def test_middleware_rejects_missing_and_malformed_auth(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _middleware()
    token = mint()
    with caplog.at_level(logging.INFO, logger="mcp_defender_xdr.audit"):
        missing = await _call(app)
        basic = await _call(app, headers={"Authorization": "Basic dXNlcjpwYXNz"})
        bad = await _call(app, headers={"Authorization": f"Bearer {token[:-4]}AAAA"})
    for response in (missing, basic, bad):
        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer ")
        assert response.json()["error"] == "invalid_token"
    reasons = [
        r.audit_fields["reason"]  # type: ignore[attr-defined]
        for r in caplog.records
        if r.getMessage() == "http-auth-rejected"
    ]
    assert reasons == ["missing_token", "malformed_authorization_header", "invalid_signature"]
    # The token never appears in the audit trail.
    assert all(token[:20] not in r.getMessage() + str(vars(r)) for r in caplog.records)


async def test_middleware_404s_other_paths_and_limits_body() -> None:
    app = _middleware()
    assert (await _call(app, path="/admin")).status_code == 404
    huge = await _call(
        app, headers={"Authorization": f"Bearer {mint()}", "Content-Length": str(10 * 1024 * 1024)}
    )
    assert huge.status_code == 413


async def test_middleware_passes_valid_token() -> None:
    response = await _call(_middleware(), headers={"Authorization": f"Bearer {mint()}"})
    assert response.status_code == 200
    assert response.text == "ok"


# ---------- end to end: real uvicorn + real MCP client ----------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextlib.asynccontextmanager
async def running_server() -> AsyncIterator[str]:
    import uvicorn

    port = _free_port()
    settings = http_settings_from_env(BASE_ENV, port=port)
    server = build_server(fixtures=FixtureStore.load())
    app, manager = build_http_app(server, settings)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, lifespan="off", log_level="error")
    uv = uvicorn.Server(config)
    async with manager.run():
        task = asyncio.create_task(uv.serve())
        for _ in range(200):
            if uv.started:
                break
            await asyncio.sleep(0.01)
        try:
            yield f"http://127.0.0.1:{port}/mcp"
        finally:
            uv.should_exit = True
            await task


_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "1"},
    },
}
_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


async def test_e2e_mcp_client_lists_and_calls_tools() -> None:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    from mcp.types import TextContent

    async with running_server() as url:
        headers = {"Authorization": f"Bearer {mint()}"}
        async with streamablehttp_client(url, headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert "list_alerts" in {t.name for t in tools.tools}
                result = await session.call_tool("list_alerts", {"severity": "High"})
                content = result.content[0]
                assert isinstance(content, TextContent)
                payload = json.loads(content.text)
                assert payload["fixture_mode"] is True
                assert payload["metadata"]["count"] >= 1


async def test_e2e_failed_probe_does_not_consume_token() -> None:
    """Clients may probe (e.g. `server/discover`) before initialize; a 400 must not burn the token."""
    async with running_server() as url, httpx.AsyncClient() as client:
        auth = {**_HEADERS, "Authorization": f"Bearer {mint()}"}
        probe = await client.post(
            url,
            json={"jsonrpc": "2.0", "id": "probe", "method": "server/discover", "params": {}},
            headers=auth,
        )
        assert probe.status_code == 400
        init = await client.post(url, json=_INIT, headers=auth)
        assert init.status_code == 200
        assert init.headers["mcp-session-id"]


async def test_e2e_unauthenticated_request_is_rejected() -> None:
    async with running_server() as url, httpx.AsyncClient() as client:
        response = await client.post(url, json=_INIT, headers=_HEADERS)
        assert response.status_code == 401


async def test_e2e_replayed_token_cannot_open_second_session() -> None:
    async with running_server() as url, httpx.AsyncClient() as client:
        token = mint(sub="alice")
        auth = {**_HEADERS, "Authorization": f"Bearer {token}"}
        first = await client.post(url, json=_INIT, headers=auth)
        assert first.status_code == 200
        session_id = first.headers["mcp-session-id"]

        replay = await client.post(url, json=_INIT, headers=auth)
        assert replay.status_code == 401

        # Same subject, fresh token: may continue the session.
        refreshed = {
            **_HEADERS,
            "Authorization": f"Bearer {mint(sub='alice')}",
            "mcp-session-id": session_id,
            "mcp-protocol-version": "2025-06-18",
        }
        ping = await client.post(
            url, json={"jsonrpc": "2.0", "id": 2, "method": "ping"}, headers=refreshed
        )
        assert ping.status_code == 200

        # A different subject's valid token may not ride on Alice's session.
        hijack = {**refreshed, "Authorization": f"Bearer {mint(sub='mallory')}"}
        stolen = await client.post(
            url, json={"jsonrpc": "2.0", "id": 3, "method": "ping"}, headers=hijack
        )
        assert stolen.status_code == 403


async def test_e2e_dns_rebinding_host_is_rejected() -> None:
    async with running_server() as url, httpx.AsyncClient() as client:
        response = await client.post(
            url,
            json=_INIT,
            headers={**_HEADERS, "Authorization": f"Bearer {mint()}", "Host": "evil.example.com"},
        )
        assert response.status_code in (400, 421)


def test_jwt_settings_repr_is_redacted() -> None:
    settings = JwtSettings(algorithm="HS256", key=SECRET, audience=AUD, issuer=ISS)
    assert SECRET not in repr(settings)
