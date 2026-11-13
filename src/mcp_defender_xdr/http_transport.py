"""Streamable HTTP transport with mandatory bearer-token authentication.

``stdio`` stays the default. ``MCP_DEFENDER_XDR_TRANSPORT=http`` (or
``--transport http``) serves the same MCP server over the MCP *Streamable
HTTP* transport (JSON-RPC over POST, server-to-client streaming over SSE) at
a single path, ``/mcp`` by default, for remote clients that cannot spawn the
process themselves.

An HTTP listener is a new trust boundary. Anyone who can reach the port and
present a usable request would get the full read capability of every
configured tenant, so HTTP mode will not start without token validation
configured (THREAT_MODEL.md, A4 and T8):

* Every request must carry ``Authorization: Bearer <JWT>``.
* The token is verified with exactly **one** configured algorithm (HS256 with
  a >=32-byte shared secret, or an asymmetric algorithm with a PEM public key),
  so the ``alg`` header can never choose the verification method.
* ``aud`` and ``iss`` must equal this server instance's configured values;
  ``exp``, ``iat``, ``sub`` and ``jti`` are required; and a token may not live
  longer than the configured maximum (15 minutes by default).
* **Replay binding.** A token opens at most one MCP session. Once used, its
  ``jti`` is bound to that session's ID, and a session is bound to the
  ``sub`` that opened it. Replaying a captured token to open a second
  session, carrying it into a different session, or presenting another
  subject's token on an existing session is rejected. A fresh token for the
  *same* subject may continue a session, so clients can refresh every few
  minutes without reconnecting.
* Rejections are audited with a reason code and the client address; the
  token itself is never logged or echoed.

The server only validates tokens. Minting is the operator's job; see
``examples/mint_token.py``.
"""

from __future__ import annotations

import ipaddress
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .audit import audit, audit_error
from .errors import ConfigError

TRANSPORT_ENV = "MCP_DEFENDER_XDR_TRANSPORT"
TRANSPORT_STDIO = "stdio"
TRANSPORT_HTTP = "http"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_PATH = "/mcp"
DEFAULT_MAX_TTL_SECONDS = 900
DEFAULT_LEEWAY_SECONDS = 30
MAX_BODY_BYTES = 1024 * 1024
#: Sessions the replay guard remembers; the oldest is forgotten first.
MAX_TRACKED_SESSIONS = 10_000
#: How long a session stays bound to its subject after its last token expires.
SESSION_RETENTION_SECONDS = 24 * 3600

#: The exact value that permits a non-loopback bind without TLS, for a
#: deployment behind a TLS-terminating reverse proxy. Long on purpose.
ALLOW_PLAINTEXT_TOKEN = "behind-tls-terminating-proxy"  # noqa: S105 - mode sentinel

_HMAC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
_ASYMMETRIC_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
_MIN_HMAC_SECRET_BYTES = 32
_SESSION_HEADER = b"mcp-session-id"


# ---------- configuration ----------


@dataclass(frozen=True)
class JwtSettings:
    algorithm: str
    key: str | bytes
    audience: str
    issuer: str
    max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS
    leeway_seconds: int = DEFAULT_LEEWAY_SECONDS

    def __repr__(self) -> str:
        return (
            f"JwtSettings(algorithm={self.algorithm!r}, key='***REDACTED***', "
            f"audience={self.audience!r}, issuer={self.issuer!r}, "
            f"max_ttl_seconds={self.max_ttl_seconds})"
        )


@dataclass(frozen=True)
class HttpSettings:
    jwt: JwtSettings
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    path: str = DEFAULT_PATH
    tls_certfile: str | None = None
    tls_keyfile: str | None = None
    allowed_hosts: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()


def _int_env(env: Mapping[str, str], name: str, default: int, *, lo: int, hi: int) -> int:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return value


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _csv(raw: str | None) -> tuple[str, ...]:
    return tuple(part.strip() for part in (raw or "").split(",") if part.strip())


def jwt_settings_from_env(env: Mapping[str, str]) -> JwtSettings:
    algorithm = (env.get("MCP_DEFENDER_XDR_JWT_ALGORITHM") or "HS256").strip()
    audience = (env.get("MCP_DEFENDER_XDR_JWT_AUDIENCE") or "").strip()
    issuer = (env.get("MCP_DEFENDER_XDR_JWT_ISSUER") or "").strip()
    if not audience or not issuer:
        raise ConfigError(
            "HTTP transport requires MCP_DEFENDER_XDR_JWT_AUDIENCE and "
            "MCP_DEFENDER_XDR_JWT_ISSUER, so that tokens are bound to this server instance."
        )
    key: str | bytes
    if algorithm in _HMAC_ALGORITHMS:
        secret = env.get("MCP_DEFENDER_XDR_JWT_SECRET") or ""
        if len(secret.encode("utf-8")) < _MIN_HMAC_SECRET_BYTES:
            raise ConfigError(
                f"MCP_DEFENDER_XDR_JWT_SECRET must be set and at least {_MIN_HMAC_SECRET_BYTES} "
                f"bytes for {algorithm} (e.g. `python -c 'import secrets; "
                "print(secrets.token_urlsafe(48))'`)."
            )
        if env.get("MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE"):
            raise ConfigError(
                "Set MCP_DEFENDER_XDR_JWT_SECRET for HMAC algorithms or "
                "MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE for asymmetric ones, not both."
            )
        key = secret
    elif algorithm in _ASYMMETRIC_ALGORITHMS:
        path = env.get("MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE")
        if not path:
            raise ConfigError(
                f"{algorithm} requires MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE (a PEM public key)."
            )
        if env.get("MCP_DEFENDER_XDR_JWT_SECRET"):
            raise ConfigError(
                "MCP_DEFENDER_XDR_JWT_SECRET is set but the algorithm is asymmetric; "
                "unset it so a shared secret can never verify tokens."
            )
        try:
            key = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"Cannot read MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE: {path}") from exc
        if "PRIVATE KEY" in key:
            raise ConfigError(
                "MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE contains a private key; "
                "give the server the public key only."
            )
    else:
        raise ConfigError(
            f"Unsupported MCP_DEFENDER_XDR_JWT_ALGORITHM {algorithm!r} "
            f"(supported: {', '.join(sorted(_HMAC_ALGORITHMS | _ASYMMETRIC_ALGORITHMS))})."
        )
    return JwtSettings(
        algorithm=algorithm,
        key=key,
        audience=audience,
        issuer=issuer,
        max_ttl_seconds=_int_env(
            env, "MCP_DEFENDER_XDR_JWT_MAX_TTL_SECONDS", DEFAULT_MAX_TTL_SECONDS, lo=60, hi=3600
        ),
        leeway_seconds=_int_env(
            env, "MCP_DEFENDER_XDR_JWT_LEEWAY_SECONDS", DEFAULT_LEEWAY_SECONDS, lo=0, hi=300
        ),
    )


def http_settings_from_env(
    env: Mapping[str, str], *, host: str | None = None, port: int | None = None
) -> HttpSettings:
    """Build and validate HTTP settings. CLI ``host``/``port`` override the environment."""
    jwt_settings = jwt_settings_from_env(env)
    bind_host = host or (env.get("MCP_DEFENDER_XDR_HTTP_HOST") or DEFAULT_HOST).strip()
    bind_port = (
        port
        if port is not None
        else _int_env(env, "MCP_DEFENDER_XDR_HTTP_PORT", DEFAULT_PORT, lo=1, hi=65535)
    )
    path = (env.get("MCP_DEFENDER_XDR_HTTP_PATH") or DEFAULT_PATH).strip()
    if not path.startswith("/") or any(c.isspace() for c in path):
        raise ConfigError("MCP_DEFENDER_XDR_HTTP_PATH must be an absolute path like /mcp")

    certfile = env.get("MCP_DEFENDER_XDR_HTTP_TLS_CERTFILE") or None
    keyfile = env.get("MCP_DEFENDER_XDR_HTTP_TLS_KEYFILE") or None
    if (certfile is None) != (keyfile is None):
        raise ConfigError(
            "Set both MCP_DEFENDER_XDR_HTTP_TLS_CERTFILE and MCP_DEFENDER_XDR_HTTP_TLS_KEYFILE, "
            "or neither."
        )
    plaintext = (env.get("MCP_DEFENDER_XDR_HTTP_ALLOW_PLAINTEXT") or "").strip()
    if plaintext and plaintext != ALLOW_PLAINTEXT_TOKEN:
        raise ConfigError(
            "MCP_DEFENDER_XDR_HTTP_ALLOW_PLAINTEXT has an unrecognized value; the only accepted "
            f"value is '{ALLOW_PLAINTEXT_TOKEN}'."
        )
    if certfile is None and not _is_loopback(bind_host) and not plaintext:
        raise ConfigError(
            f"Refusing to serve bearer tokens over plaintext HTTP on non-loopback host "
            f"{bind_host!r}. Configure MCP_DEFENDER_XDR_HTTP_TLS_CERTFILE/KEYFILE, bind to "
            "127.0.0.1, or (behind a TLS-terminating proxy only) set "
            f"MCP_DEFENDER_XDR_HTTP_ALLOW_PLAINTEXT={ALLOW_PLAINTEXT_TOKEN}."
        )

    allowed_hosts = _csv(env.get("MCP_DEFENDER_XDR_HTTP_ALLOWED_HOSTS")) or (
        f"127.0.0.1:{bind_port}",
        f"localhost:{bind_port}",
        *(() if bind_host in ("0.0.0.0", "::") else (f"{bind_host}:{bind_port}",)),  # noqa: S104
    )
    return HttpSettings(
        jwt=jwt_settings,
        host=bind_host,
        port=bind_port,
        path=path,
        tls_certfile=certfile,
        tls_keyfile=keyfile,
        allowed_hosts=tuple(dict.fromkeys(allowed_hosts)),
        allowed_origins=_csv(env.get("MCP_DEFENDER_XDR_HTTP_ALLOWED_ORIGINS")),
    )


# ---------- token validation ----------


class TokenRejected(Exception):
    """A request's bearer token is unusable. ``reason`` is a stable audit code."""

    def __init__(self, reason: str, *, status: int = 401) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class Principal:
    subject: str
    token_id: str
    expires_at: float


class TokenValidator:
    def __init__(self, settings: JwtSettings) -> None:
        self._settings = settings

    def validate(self, token: str) -> Principal:
        s = self._settings
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenRejected("malformed_token") from exc
        if header.get("alg") != s.algorithm:
            # Never let the token pick its own verification algorithm.
            raise TokenRejected("algorithm_not_allowed")
        now = time.time()
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                s.key,
                algorithms=[s.algorithm],
                audience=s.audience,
                issuer=s.issuer,
                leeway=s.leeway_seconds,
                options={"require": ["exp", "iat", "aud", "iss", "sub", "jti"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenRejected("expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenRejected("not_yet_valid") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenRejected("wrong_audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenRejected("wrong_issuer") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise TokenRejected("missing_claim") from exc
        except jwt.InvalidSignatureError as exc:
            raise TokenRejected("invalid_signature") from exc
        except jwt.PyJWTError as exc:
            raise TokenRejected("invalid_token") from exc

        exp, iat = claims["exp"], claims["iat"]
        sub, jti = claims["sub"], claims["jti"]
        if not (isinstance(exp, int | float) and isinstance(iat, int | float)):
            raise TokenRejected("invalid_token")
        if iat > now + s.leeway_seconds:
            raise TokenRejected("not_yet_valid")
        if exp - iat > s.max_ttl_seconds:
            raise TokenRejected("lifetime_too_long")
        if not (isinstance(sub, str) and sub and isinstance(jti, str) and 8 <= len(jti) <= 256):
            raise TokenRejected("invalid_token")
        return Principal(subject=sub, token_id=jti, expires_at=float(exp))


# ---------- replay / session binding ----------

_PENDING = ""  # jti used on an initialize request whose session ID we haven't seen yet


@dataclass
class _Session:
    subject: str
    retain_until: float


@dataclass
class ReplayGuard:
    """Binds each token to one MCP session and each session to one subject."""

    clock: Callable[[], float] = time.time
    _tokens: dict[str, tuple[str, float]] = field(default_factory=dict)
    _sessions: OrderedDict[str, _Session] = field(default_factory=OrderedDict)

    def _prune(self, now: float) -> None:
        for jti in [j for j, (_, exp) in self._tokens.items() if exp < now]:
            del self._tokens[jti]
        for sid in [s for s, sess in self._sessions.items() if sess.retain_until < now]:
            del self._sessions[sid]

    def check(self, principal: Principal, session_id: str | None) -> None:
        """Raise :class:`TokenRejected` if this token may not be used for this request."""
        now = self.clock()
        self._prune(now)
        bound = self._tokens.get(principal.token_id)
        if session_id is None:
            # Opening a session. A token opens at most one.
            if bound is not None:
                raise TokenRejected("token_replayed")
            self._tokens[principal.token_id] = (_PENDING, principal.expires_at)
            return
        session = self._sessions.get(session_id)
        if session is None:
            raise TokenRejected("unknown_session", status=404)
        if session.subject != principal.subject:
            raise TokenRejected("session_subject_mismatch", status=403)
        if bound is not None and bound[0] not in (_PENDING, session_id):
            raise TokenRejected("token_replayed")
        self._tokens[principal.token_id] = (session_id, principal.expires_at)
        session.retain_until = max(
            session.retain_until, principal.expires_at + SESSION_RETENTION_SECONDS
        )
        self._sessions.move_to_end(session_id)

    def release(self, principal: Principal) -> None:
        """Forget a token whose session-opening request failed, so it can retry.

        Clients may probe before initializing (e.g. a ``server/discover``
        request that the server answers 400). A failed request opens no
        session, so it must not use up the token's one session.
        """
        bound = self._tokens.get(principal.token_id)
        if bound is not None and bound[0] == _PENDING:
            del self._tokens[principal.token_id]

    def bind_session(self, principal: Principal, session_id: str) -> None:
        """Record the session an initialize request just opened."""
        self._tokens[principal.token_id] = (session_id, principal.expires_at)
        self._sessions[session_id] = _Session(
            subject=principal.subject,
            retain_until=principal.expires_at + SESSION_RETENTION_SECONDS,
        )
        self._sessions.move_to_end(session_id)
        while len(self._sessions) > MAX_TRACKED_SESSIONS:
            self._sessions.popitem(last=False)


# ---------- ASGI middleware ----------


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return str(value.decode("latin-1"))
    return None


def _client(scope: Scope) -> str | None:
    client = scope.get("client")
    return f"{client[0]}:{client[1]}" if client else None


async def _reject(send: Send, status: int) -> None:
    error = "invalid_token" if status == 401 else "invalid_request"
    body = (
        b'{"error":"'
        + error.encode()
        + b'","error_description":"'
        + {401: b"Unauthorized", 403: b"Forbidden", 404: b"Session not found"}.get(
            status, b"Bad request"
        )
        + b'"}'
    )
    headers = [(b"content-type", b"application/json"), (b"cache-control", b"no-store")]
    if status == 401:
        headers.append(
            (b"www-authenticate", f'Bearer realm="mcp-defender-xdr", error="{error}"'.encode())
        )
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class BearerAuthMiddleware:
    """Authenticates every HTTP request before it reaches the MCP session manager."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        path: str,
        validator: TokenValidator,
        guard: ReplayGuard,
    ) -> None:
        self._app = app
        self._path = path.rstrip("/") or "/"
        self._validator = validator
        self._guard = guard

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        if scope.get("path", "").rstrip("/") != self._path.rstrip("/"):
            await send(
                {
                    "type": "http.response.start",
                    "status": 404,
                    "headers": [(b"content-length", b"0")],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return

        length = _header(scope, b"content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
            audit_error("http-request-rejected", reason="body_too_large", client=_client(scope))
            await _reject(send, 413)
            return

        session_id = _header(scope, _SESSION_HEADER)
        try:
            principal = self._authenticate(scope)
            self._guard.check(principal, session_id)
        except TokenRejected as exc:
            audit_error(
                "http-auth-rejected",
                reason=exc.reason,
                status=exc.status,
                method=scope.get("method"),
                client=_client(scope),
                session=session_id,
            )
            await _reject(send, exc.status)
            return

        if session_id is not None:
            await self._app(scope, receive, send)
            return

        async def send_and_bind(message: Message) -> None:
            if message["type"] == "http.response.start":
                status = int(message.get("status", 500))
                new_sid = next(
                    (
                        value.decode("latin-1")
                        for key, value in message.get("headers", [])
                        if key.lower() == _SESSION_HEADER
                    ),
                    None,
                )
                # Only a successful response opens a session. The SDK can attach
                # a session ID even to a 400 (e.g. for an unknown probe method).
                if 200 <= status < 300 and new_sid:
                    self._guard.bind_session(principal, new_sid)
                    audit(
                        "http-session-opened",
                        subject=principal.subject,
                        token_id=principal.token_id,
                        session=new_sid,
                        client=_client(scope),
                    )
                elif not 200 <= status < 300:
                    self._guard.release(principal)
            await send(message)

        try:
            await self._app(scope, receive, send_and_bind)
        except BaseException:
            self._guard.release(principal)
            raise

    def _authenticate(self, scope: Scope) -> Principal:
        raw = _header(scope, b"authorization")
        if raw is None:
            raise TokenRejected("missing_token")
        scheme, _, token = raw.partition(" ")
        if scheme.lower() != "bearer" or not token.strip() or " " in token.strip():
            raise TokenRejected("malformed_authorization_header")
        return self._validator.validate(token.strip())


# ---------- wiring ----------


def build_http_app(server: Any, settings: HttpSettings) -> tuple[ASGIApp, Any]:
    """Return ``(asgi_app, session_manager)``; run the manager's ``run()`` around serving."""
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from mcp.server.transport_security import TransportSecuritySettings

    manager = StreamableHTTPSessionManager(
        app=server,
        json_response=False,
        stateless=False,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(settings.allowed_hosts),
            allowed_origins=list(settings.allowed_origins),
        ),
    )

    async def mcp_endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        await manager.handle_request(scope, receive, send)

    app = BearerAuthMiddleware(
        mcp_endpoint,
        path=settings.path,
        validator=TokenValidator(settings.jwt),
        guard=ReplayGuard(),
    )
    return app, manager


async def serve_http(server: Any, settings: HttpSettings) -> None:  # pragma: no cover - network
    import uvicorn

    app, manager = build_http_app(server, settings)
    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        ssl_certfile=settings.tls_certfile,
        ssl_keyfile=settings.tls_keyfile,
        lifespan="off",
        access_log=False,
        log_level="warning",
        server_header=False,
    )
    scheme = "https" if settings.tls_certfile else "http"
    audit(
        "http-transport-listening",
        url=f"{scheme}://{settings.host}:{settings.port}{settings.path}",
        jwt_algorithm=settings.jwt.algorithm,
        jwt_audience=settings.jwt.audience,
        jwt_issuer=settings.jwt.issuer,
        max_token_ttl_seconds=settings.jwt.max_ttl_seconds,
        allowed_hosts=list(settings.allowed_hosts),
    )
    async with manager.run():
        await uvicorn.Server(config).serve()


__all__ = [
    "ALLOW_PLAINTEXT_TOKEN",
    "TRANSPORT_ENV",
    "TRANSPORT_HTTP",
    "TRANSPORT_STDIO",
    "BearerAuthMiddleware",
    "HttpSettings",
    "JwtSettings",
    "Principal",
    "ReplayGuard",
    "TokenRejected",
    "TokenValidator",
    "build_http_app",
    "http_settings_from_env",
    "jwt_settings_from_env",
    "serve_http",
]
