# OWASP MCP Top 10 mapping — mcp-defender-xdr

This document maps the [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/)
to the mitigations actually implemented in this server. It is the
companion to [`THREAT_MODEL.md`](./THREAT_MODEL.md), which enumerates the
seven bespoke threats (T1–T7) specific to this server's surface area;
where a category below cites a threat ID, the deep analysis lives in
that file. Read the two together: the threat model explains *why* a
control exists, this document explains *which industry category it
discharges*. Status is one of **✅ Mitigated** (the threat is addressed
by code shipped in v0.1.0), **⚠️ Partial** (some controls in place, with
named residual risk), or **🗓 Roadmap** (acknowledged gap not yet
implemented).

---

## MCP01:2025 — Token Mismanagement & Secret Exposure

**Status: ✅ Mitigated** *(see T2, T4)*

Authentication is X.509 certificate-based via MSAL client-credentials —
no client secret is ever quoted in a config file or `.env`, only a path
to a PFX bundle. Access tokens are held only in `TokenManager._cache`
keyed by `(tenant_key, scope)`, never written to disk and never logged;
`AzureCredentials.__repr__` redacts the cert passphrase and is covered
by `test_credentials_repr_redacts_passphrase`. The audit module
(`audit.py`) uses an explicit-fields pattern — `audit(event, **fields)`
only logs what the caller passes by keyword, so there is no
"log-the-whole-request-context" path that could accidentally include
`Authorization` headers or PFX bytes. `EnvCredentialProvider` raises
`AuthError` naming the *missing* variable, never the value of a present
one.

## MCP02:2025 — Privilege Escalation via Scope Creep

**Status: ✅ Mitigated** *(see T3)*

Every HTTP call routes through `DefenderClient.get`/`post` against one
of three documented paths — `/api/advancedqueries/run`,
`/api/incidents/{id}`, `/api/alerts` — so a reviewer can audit the
entire blast radius in a single `grep`. The OAuth scope is the static
`https://api.securitycenter.microsoft.com/.default`; no `*.ReadWrite.*`
or other broader scopes are requested, and the README publishes the
exact three application permissions so a tenant admin reviewing consent
can decline anything larger. The residual risk is purely
Azure-administrative: a misconfigured App Registration with extra
permissions would still authorize anything the server's code happens to
call, so the server's read-only behavior must be enforced by code
review (T3 in the threat model).

## MCP03:2025 — Tool Poisoning

**Status: ⚠️ Partial** *(see T1, T5)*

Tool inputs are constrained at the boundary by `validation.py`:
`MAX_KQL_LENGTH = 10_000` caps query size, `_KQL_FORBIDDEN_SUBSTRINGS`
rejects destructive control verbs (`.drop`, `.alter`, `.ingest`,
`.external_table(`, …) before any HTTP call, and `_strip_control_chars`
removes zero-width and bidi-override characters so a payload cannot
visually disguise itself. These behaviors are covered by
`test_rejects_destructive_kql_verbs` and `test_strips_control_chars`.
Tool *outputs* — alert titles, file names, command lines flowing from
Defender — remain attacker-influenced data; each tool's
`TOOL_DESCRIPTION` explicitly instructs the model to treat returned
strings as data rather than instructions, and results are returned via
`structuredContent` so clients can render them as data. The residual
risk is the unsolved general problem that an LLM may still follow a
sufficiently clever payload (T5).

## MCP04:2025 — Software Supply Chain Attacks & Dependency Tampering

**Status: 🗓 Roadmap**

This is an honest gap. v0.1.0 does **not** ship Dependabot, does **not**
run CodeQL or any other SAST/SCA scanner in CI, does **not** produce an
SBOM (CycloneDX or SPDX), and does **not** sign release artifacts
(Sigstore/`gh attest`) or PyPI uploads. The CI workflow runs `ruff`,
`mypy --strict`, and `pytest --cov-fail-under=80` on Python 3.11 and
3.12 — those are correctness gates, not supply-chain integrity
controls, and should not be mistaken for them. All four items
(Dependabot, CodeQL, SBOM generation, signed releases) are tracked on
the v0.2/v0.3 roadmap; until they ship, downstream consumers should
pin the package by hash and review `msal`, `httpx`, `pydantic`, and
`mcp` dependency upgrades themselves.

## MCP05:2025 — Command Injection & Execution

**Status: ✅ Mitigated** *(see T1, T3)*

The server has no shell-out, no `subprocess`, no `eval`, and no
dynamic-import path. KQL is the only caller-supplied language; it is
executed remotely by Defender against a read-only scope
(`ThreatHunting.Read.All`), and the pre-filter in `validation.py`
rejects destructive verbs at the boundary as defense in depth. The
HTTP surface is constrained to the three named Defender endpoints
listed under MCP02, so a successful injection would have no local
execution sink to land in.

## MCP06:2025 — Intent Flow Subversion (Prompt Injection via Contextual Payloads)

**Status: ⚠️ Partial** *(see T1, T5)*

User-driven prompt injection on the input side is bounded by the same
KQL-input controls cited under MCP03 — length cap, forbidden-verb
substrings, control-character stripping. Indirect prompt injection on
the output side — attacker content embedded in alert titles or process
command lines (T5) — is mitigated by tool-description warnings to the
model and by structured-content outputs that allow MCP clients to
avoid inlining attacker strings into the conversation. The server
never chains tool calls on its own (every tool call originates from
the client), so a single hijacked output cannot cascade into further
calls. The residual risk is inherent to current LLM behavior: a
sufficiently crafted payload may still steer the model.

## MCP07:2025 — Insufficient Authentication & Authorization

**Status: ✅ Mitigated** *(see T2, T3, T7)*

Upstream authentication is MSAL client-credentials with X.509
certificates — stronger than shared-secret auth and resistant to
log-scrape exfiltration. Each tenant has its own
`ConfidentialClientApplication` instance and its own
`(tenant_key, scope)` cache entry; per-tenant isolation is verified by
`test_token_manager_per_tenant_cache_isolation`. Caller-supplied
`tenant` values are validated against
`^([A-Za-z0-9_-]{1,64}|\*)$` *and* against the configured tenant set,
with unknown keys rejected before any network call and without echoing
the bad key (`test_json_provider_unknown_tenant_does_not_echo_key`,
`test_unknown_explicit_tenant_rejected`). Per the documented non-goals
in `THREAT_MODEL.md`, end-user authorization within a service
principal is out of scope — operators who need per-user RBAC must
layer it in front of the MCP client, not inside the server.

## MCP08:2025 — Lack of Audit and Telemetry

**Status: ✅ Mitigated** *(see T2, T6, T7)*

`audit.py` emits one JSON-lines record per tool invocation to stderr,
leaving stdout reserved for the MCP stdio protocol. The
`audit(event, **fields)` signature is itself the allowlist — only the
keyword fields a caller explicitly passes are emitted, so there is no
convenience path that could accidentally serialize an `Authorization`
header or PFX byte. Logged fields cover tool name, target tenant,
validated parameters, duration, success/failure, error code, result
counts, and KQL query text; tokens, passphrases, PFX contents, raw
upstream bodies, and HTTP correlation IDs are not. Retry paths and
per-tenant fan-out outcomes both produce audit records, giving an
operator the signal needed to spot the rate-limit abuse pattern
described in T6.

## MCP09:2025 — Shadow MCP Servers

**Status: ⚠️ Partial** *(see T3)*

This package ships exactly one console-script entrypoint
(`mcp-defender-xdr` in `pyproject.toml`), one documented stdio
transport, and one published config schema for `mcpServers`. An
operator can therefore unambiguously identify a legitimate instance.
What this server cannot do is detect *other* MCP servers running on
the same host — discovery and inventory of MCP processes is a host- or
endpoint-management problem, addressed by the operator's EDR (which,
in this deployment, is Defender itself). State that boundary plainly:
trust in the running binary depends on the integrity of the install
path, which falls under MCP04.

## MCP10:2025 — Context Injection & Over-Sharing

**Status: ⚠️ Partial** *(see T5, T7)*

Per-tenant results from fan-out are labelled with the *server-side*
`tenant` key — never parsed out of the upstream JSON body — so an
attacker who can influence alert content cannot influence which tenant
label that content is filed under. Per-tenant fan-out workers catch
their own exceptions and surface them as
`{"tenant": k, "error": {...}}` entries, so one tenant's failure cannot
silently inherit another's data; this is covered by
`test_fan_out_partial_failure` and
`test_fan_out_unhandled_exception_per_tenant`. The residual gap is
deliberate: the server returns whatever Defender returns, and PII
scrubbing is a documented non-goal in `THREAT_MODEL.md`. Operators
who need DLP must run it downstream of the MCP client.

---

## Summary

| Category | Title                                                       | Status         | Threat refs    |
| -------- | ----------------------------------------------------------- | -------------- | -------------- |
| MCP01    | Token Mismanagement & Secret Exposure                       | ✅ Mitigated   | T2, T4         |
| MCP02    | Privilege Escalation via Scope Creep                        | ✅ Mitigated   | T3             |
| MCP03    | Tool Poisoning                                              | ⚠️ Partial      | T1, T5         |
| MCP04    | Software Supply Chain Attacks & Dependency Tampering        | 🗓 Roadmap      | —              |
| MCP05    | Command Injection & Execution                               | ✅ Mitigated   | T1, T3         |
| MCP06    | Intent Flow Subversion (Prompt Injection)                   | ⚠️ Partial      | T1, T5         |
| MCP07    | Insufficient Authentication & Authorization                 | ✅ Mitigated   | T2, T3, T7     |
| MCP08    | Lack of Audit and Telemetry                                 | ✅ Mitigated   | T2, T6, T7     |
| MCP09    | Shadow MCP Servers                                          | ⚠️ Partial      | T3             |
| MCP10    | Context Injection & Over-Sharing                            | ⚠️ Partial      | T5, T7         |
