# Changelog

All notable changes to `mcp-defender-xdr` are recorded in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-04

First tagged release. Supersedes the 0.1.1 version bump, which was developed
but never tagged or published, so its changes are folded in here.

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
- Permission names corrected throughout to the WindowsDefenderATP resource the
  token scope actually resolves to: `AdvancedQuery.Read.All`,
  `Alert.Read.All`, `Incident.Read.All`. The README table had hedged between
  WindowsDefenderATP and Microsoft Graph, and the Graph names had spread to the
  `query_advanced_hunting` tool description, `THREAT_MODEL.md`,
  `OWASP_MCP_TOP10.md`, and `CONTRIBUTING.md`.
- Claude Desktop / Claude Code config examples launched the server via `uvx`
  from PyPI, which does not resolve. They now point at the console script in a
  source virtualenv.

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
