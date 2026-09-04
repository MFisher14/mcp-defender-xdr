# Changelog

All notable changes to `mcp-defender-xdr` are recorded in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-04

### Added

- `SECURITY.md`, `CONTRIBUTING.md`, and `CODEOWNERS`.
- `OWASP_MCP_TOP10.md` mapping the server's controls to the OWASP MCP Top 10.

### Changed

- `__version__` is now read from the installed distribution metadata via
  `importlib.metadata.version`, so it can no longer drift from the version
  declared in `pyproject.toml`. It had drifted: the package reported `0.1.0`
  to MCP clients during the `initialize` handshake while `pyproject.toml`
  declared `0.1.1`.
- Threat model T1 reframed as OWASP LLM01 indirect prompt injection.

### Fixed

- README named the wrong API. The server targets the Defender for Endpoint
  REST API at `api.securitycenter.microsoft.com`, not the Microsoft Graph
  Security API, and `DEFENDER_API_BASE` overrides the host only — it does not
  change the pinned OAuth scope.
- README permissions table hedged between the WindowsDefenderATP and Microsoft
  Graph resources. The scope resolves to WindowsDefenderATP, so the required
  permissions are `AdvancedQuery.Read.All`, `Alert.Read.All`, and
  `Incident.Read.All`.

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

[0.1.1]: https://github.com/MFisher14/mcp-defender-xdr/releases/tag/v0.1.1
[0.1.0]: https://github.com/MFisher14/mcp-defender-xdr/releases/tag/v0.1.0
