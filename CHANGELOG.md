# Changelog

All notable changes to `mcp-defender-xdr` are recorded in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `get_device_timeline` (#7): one device's process, network, file,
  registry, and other events in a bounded window, merged newest-first.
- `investigate_user` (#8): one user's sign-ins, mail flow, and device
  logons by UPN or SID, grouped by signal type.
- `query_threat_intelligence` (#9): alerts and telemetry sightings for an
  IP, domain, URL, or MD5/SHA-1/SHA-256 hash. Built on Advanced Hunting so
  it stays read-only; custom indicators are not listed because that API
  requires `Ti.ReadWrite`.
- The three tools build their KQL server-side from validated inputs, with
  every value emitted as an escaped literal (`kql.py`). No new API
  permissions are required beyond `AdvancedQuery.Read.All`.
- Offline fixtures for all three (`examples/fixtures/investigations.json`),
  routed by a tag on the first line of each server-built query.
- Per-tenant rolling-window quotas (#11). The tenants file accepts
  `default_quota` and per-tenant `quota` objects with `requests_per_minute`
  and `rows_per_minute`. A tenant over quota gets a `quota_exceeded` error
  in its own fan-out slot while sibling tenants are unaffected. Each
  decision is audited as `quota-decision`. State is in-process only.
- `quota_exceeded` error code (`QuotaExceededError`).
- Azure Key Vault credential provider (#3): `"provider": "keyvault"` in a
  tenants-file entry reads the PFX, and optionally its passphrase, from Key
  Vault using `DefaultAzureCredential` (workload identity, managed identity,
  or an environment service principal). Extra: `[keyvault]`.
- AWS Secrets Manager credential provider (#4): `"provider":
  "aws-secretsmanager"` reads the same material using the standard AWS
  credential chain. Extra: `[aws-secretsmanager]`.
- Both parse the certificate in memory and pass MSAL a PEM key plus
  certificate, so the PFX never touches the host filesystem. They accept raw
  PKCS#12, base64 PKCS#12, or a PEM key+certificate bundle.

- Streamable HTTP transport (#2): `--transport http` or
  `MCP_DEFENDER_XDR_TRANSPORT=http` serves MCP at `/mcp` (default
  `127.0.0.1:8765`). stdio remains the default. It can serve TLS directly,
  refuses a plaintext non-loopback bind unless explicitly opted in, and
  has DNS-rebinding protection on.
- Bearer-token authentication for the HTTP transport (#5): signed JWTs
  verified with one pinned algorithm (HS* with a ≥32-byte secret, or an
  asymmetric public key), `aud`/`iss` bound to the instance, required
  `exp`/`iat`/`sub`/`jti`, a 15-minute maximum lifetime, and replay
  binding (a token opens one session; a session belongs to one `sub`).
  Rejections are audited without the token. `examples/mint_token.py`
  mints development tokens.
- Every audit record now includes `transport`.
- THREAT_MODEL.md: adversary A4 (network attacker) and T8 (token
  validation).
- README screenshots of real Claude Code sessions against fixture mode, with
  the recording and rendering scripts in `docs/screenshots/`.
- Deployment guide (#6): a decision table for choosing a transport and
  credential provider, client configs for each transport,
  `tenants.cloud.example.json`, and `.env.example` stanzas for every new
  variable.
- Microsoft Sentinel integration (#10): `query_sentinel` runs read-only KQL
  against a tenant's Log Analytics workspace, by inline query or by
  `saved_query_id`, and `list_sentinel_hunting_queries` surfaces the
  workspace's saved hunting queries with their tactics and techniques.
  Configured per tenant with `sentinel_workspace_id` and optional
  `sentinel_workspace_resource_id`, or with the matching
  `MCP_DEFENDER_XDR_SENTINEL_*` variables. Needs the Log Analytics Reader
  and Reader roles on the workspace.
- `TokenManager.get_token(scope=...)`: tokens for the Log Analytics and ARM
  audiences, pinned in `auth.ALLOWED_SCOPES`; any other scope is refused.
- Offline fixtures for Sentinel (`examples/fixtures/sentinel.json`).

### Changed

- `msal` floor raised to 1.35.0, the first release that derives a SHA-256
  thumbprint (PS256) from an in-memory `public_certificate`.
- `cryptography` is now a declared dependency (it was already installed
  transitively through `msal`).
- `AzureCredentials.cert_path` is optional; exactly one of `cert_path` or
  the new `certificate` must be set.
- Upstream error messages name the API that failed (Defender API, Log
  Analytics API, Azure Resource Manager).
- KQL validation is factored into `validation.validate_kql` and shared by
  every tool that runs KQL.

## [0.2.0] - 2026-09-04

Supersedes the 0.1.1 version bump, which was developed but never tagged or
published, so its changes are folded in here rather than kept as a separate
release that never shipped.

### Added

- Offline fixture mode. `MCP_DEFENDER_XDR_FIXTURE_MODE=synthetic-fixtures-no-live-data`
  serves recorded synthetic responses for all three tools and skips credential
  validation entirely, so the server boots with no environment variables set —
  no Azure tenant, App Registration, or certificate needed to evaluate it.
  Enabling requires that exact value; any other non-empty value fails startup
  with exit code 2 rather than resolving to either mode.
- `examples/` with fixture JSON for each tool (raw upstream response shapes, so
  the real per-tool transforms run against them), demo prompts, and a
  no-credentials MCP client config. Fixtures are force-included in built wheels
  at `mcp_defender_xdr/fixture_data`.
- Fixture output is marked as synthetic in three independent places: a
  `fixture_mode` flag and `notice` in every tool result, a WARNING-level
  `FIXTURE-MODE-ACTIVE-SYNTHETIC-DATA` audit record on every tool call, and
  invented `example.com` hostnames with RFC 5737 documentation IPs throughout —
  the last enforced by tests.
- "Quickstart (offline)" section at the top of the README.
- A section distinguishing this project from the unrelated `mcp-defender`
  package on PyPI.
- `DefenderApi` protocol, implemented by both the live HTTP client and the
  fixture client, so tool code is identical in both modes.
- `ConfigError` for startup misconfiguration and `audit_warning` for
  WARNING-level audit records.
- `THREAT_MODEL.md` T9 covering offline fixture mode: synthetic data mistaken
  for live, and the inverse — a config intended for fixtures reaching a live
  tenant. Mitigations were verified against the implementation; two gaps are
  recorded as residual risk rather than claimed as controls (error results
  carry no fixture marking, and calls rejected at input validation emit no
  fixture audit warning). Referenced from `OWASP_MCP_TOP10.md` MCP08 and
  MCP10.
- `SECURITY.md`, `CONTRIBUTING.md`, and `CODEOWNERS`.
- `OWASP_MCP_TOP10.md` mapping the server's controls to the OWASP MCP Top 10.

### Changed

- `__version__` is now read from the installed distribution metadata via
  `importlib.metadata.version`, so it can no longer drift from the version
  declared in `pyproject.toml`. It had drifted: the package reported `0.1.0`
  to MCP clients during the `initialize` handshake while `pyproject.toml`
  declared `0.1.1`.
- Installation instructions now lead with the from-source path. The README
  opened with `pip install mcp-defender-xdr` and
  `uvx --from mcp-defender-xdr mcp-defender-xdr`; the package has never been
  published to PyPI, so both commands failed for anyone who followed them.
  They are retained below, marked as planned for a future release.
- Threat model T1 reframed as OWASP LLM01 indirect prompt injection.
- The `mcp-defender` comparison section moved from directly under the intro
  into Scope & Design Philosophy, so it follows rather than precedes what the
  server does. Content unchanged.

### Fixed

- Corrected the `mcp` dependency range to `>=1.13.0,<2`. The previous
  `>=1.0.0` was wrong at both ends: `Server(version=...)` does not exist in
  1.0.0, so the declared floor was never installable, and the missing upper
  bound let `mcp` 2.x resolve by default. 2.x replaced the decorator
  registration model with constructor callbacks and renamed model attributes
  to snake_case, which broke the build on a clean install.
- README named the wrong API. The server targets the Defender for Endpoint
  REST API at `api.securitycenter.microsoft.com`, not the Microsoft Graph
  Security API, and `DEFENDER_API_BASE` overrides the host only — it does not
  change the pinned OAuth scope.
- **Action required — re-grant your Azure API permissions.** The required
  application permissions are corrected throughout to the WindowsDefenderATP
  resource that the server's token scope actually resolves to:
  `AdvancedQuery.Read.All`, `Alert.Read.All`, `Incident.Read.All`.

  Anyone who configured an App Registration by following the previous README
  granted the Microsoft Graph equivalents — `ThreatHunting.Read.All`,
  `SecurityEvents.Read.All`, `SecurityIncident.Read.All` — which authorize
  nothing against `api.securitycenter.microsoft.com`. Such a deployment was
  never functional: every tool call returns `auth_failure`. This release does
  not break it, it explains it. To fix: grant and admin-consent the three
  permissions above on the **WindowsDefenderATP** resource (app ID
  `fc780465-2017-40d4-a0c5-307022471b92`, listed under "APIs my organization
  uses", *not* Microsoft Graph), then remove the three Graph permissions. See
  the README's Prerequisites section.

  The old names had also spread to the `query_advanced_hunting` tool
  description, `THREAT_MODEL.md`, `OWASP_MCP_TOP10.md`, `CONTRIBUTING.md`,
  and `SECURITY.md`.
- Claude Desktop / Claude Code config examples launched the server via `uvx`
  from PyPI, which does not resolve. They now point at the console script in a
  source virtualenv.
- `SECURITY.md` directed upstream vulnerability reports for "the Microsoft
  Graph Security API", which this server does not call. It now names the
  Defender for Endpoint REST API.

## [0.1.0] - 2026-05-12

### Added

- `query_advanced_hunting` — run an Advanced Hunting KQL query against one or all configured tenants.
- `get_incident` — fetch a single Defender XDR incident with its alerts and impacted entities.
- `list_alerts` — list Defender XDR alerts filtered by severity, status, and result count.
- Certificate-based OAuth 2.0 client-credentials authentication via MSAL (PFX X.509, no client secret).
- Multi-tenant support via JSON config with per-tenant MSAL `ConfidentialClientApplication` instances and per-`(tenant_key, scope)` token cache isolation.
- Fan-out KQL hunting across all configured tenants via `tenant: "*"` with bounded `asyncio.Semaphore` concurrency and per-tenant labelled results.
- JSON-lines audit log on stderr with an explicit per-call field allowlist (no request-context dump path).
- Input validation: 10,000-character KQL length cap, forbidden KQL control-verb substrings, Unicode control-character stripping, tenant-key regex `^([A-Za-z0-9_-]{1,64}|\*)$`.
- Retry logic with full-jitter exponential backoff, bounded retry count, and `Retry-After` honoring (capped at 60 s).
- `THREAT_MODEL.md` covering seven enumerated threats (T1–T7).
- GitHub Actions CI on Python 3.11 and 3.12 with `ruff`, `mypy --strict`, and `pytest` gated at 80 % coverage.
- MIT license.

[0.2.0]: https://github.com/MFisher14/mcp-defender-xdr/releases/tag/v0.2.0
[0.1.0]: https://github.com/MFisher14/mcp-defender-xdr/releases/tag/v0.1.0
