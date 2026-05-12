# mcp-defender-xdr

[![CI](https://github.com/MFisher14/mcp-defender-xdr/actions/workflows/ci.yml/badge.svg)](https://github.com/MFisher14/mcp-defender-xdr/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![GitHub Issues](https://img.shields.io/github/issues/MFisher14/mcp-defender-xdr.svg)](https://github.com/MFisher14/mcp-defender-xdr/issues)

An [MCP](https://modelcontextprotocol.io/) server that exposes Microsoft
Defender XDR — Advanced Hunting (KQL), incidents, and alerts — as tools
Claude and other MCP clients can call. It lets a security analyst (or an
agent on their behalf) drive hunts, pivot through incidents, and triage
alerts in natural language without leaving Claude. The server runs locally
over stdio, authenticates as one or more Azure App Registrations via OAuth 2.0
**certificate** client credentials, supports a single tenant or many,
and treats every input and every upstream response as untrusted.

> **v0.1 status:** Certificate-based auth (PFX), multi-tenant via JSON
> config, fan-out KQL hunts via `tenant: "*"`.

---

## Prerequisites

1. An Azure tenant with Microsoft Defender for Endpoint / Defender XDR.
2. An [Azure App Registration](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
   per tenant, with the following **application** API permissions
   (admin consent required):

   | API                              | Permission                  | Why                          |
   | -------------------------------- | --------------------------- | ---------------------------- |
   | WindowsDefenderATP / Graph       | `ThreatHunting.Read.All`    | Run Advanced Hunting KQL     |
   | WindowsDefenderATP / Graph       | `SecurityEvents.Read.All`   | Read alerts                  |
   | WindowsDefenderATP / Graph       | `SecurityIncident.Read.All` | Read incidents               |

   All three permissions are **read-only**.

3. A certificate per App Registration. Generate one with OpenSSL:

   ```bash
   # 1. Generate cert + key.
   openssl req -x509 -newkey rsa:2048 \
     -keyout key.pem -out cert.pem \
     -days 365 -nodes \
     -subj "/CN=mcp-defender-xdr"

   # 2. Bundle into a PFX (use a strong passphrase in production).
   openssl pkcs12 -export \
     -out app-cert.pfx \
     -inkey key.pem -in cert.pem \
     -password pass:""

   # 3. Upload cert.pem (the public half) to the App Registration:
   #    Azure portal → App Registration → "Certificates & secrets"
   #      → "Certificates" → "Upload certificate".
   ```

4. Python 3.11+. We recommend [`uv`](https://docs.astral.sh/uv/).

---

## Installation

### With `uvx`

```bash
uvx --from mcp-defender-xdr mcp-defender-xdr
```

### With `pip`

```bash
pip install mcp-defender-xdr
mcp-defender-xdr
```

### From source (development)

```bash
git clone https://github.com/MFisher14/mcp-defender-xdr.git
cd mcp-defender-xdr
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

---

## Configuration

### Single tenant (development / small deployments)

Set these environment variables (or a `.env` file based on
[`.env.example`](./.env.example)):

| Variable                          | Required | Description                                                |
| --------------------------------- | -------- | ---------------------------------------------------------- |
| `AZURE_TENANT_ID`                 | yes      | Azure AD directory (tenant) ID.                            |
| `AZURE_CLIENT_ID`                 | yes      | App Registration client ID.                                |
| `AZURE_CERT_PATH`                 | yes      | Absolute path to the PFX (PKCS#12) bundle.                 |
| `AZURE_CERT_PASSPHRASE`           | no       | Passphrase for the PFX. Omit if unencrypted.               |
| `DEFENDER_API_BASE`               | no       | Override the API base URL.                                 |
| `MCP_DEFENDER_XDR_LOG_LEVEL`      | no       | Audit log level. Default `INFO`.                           |

The server validates that the PFX file exists at startup and fails fast
with exit code 2 if any required variable is missing or the file is not
readable.

By default, the server targets the Microsoft Graph Security API at
`securitycenter.microsoft.com`. If your organization's Defender
deployment uses the legacy Defender for Endpoint REST API, override
with:

```bash
export DEFENDER_API_BASE=https://api.securitycenter.microsoft.com
```

### Multi tenant (production)

Set `MCP_DEFENDER_XDR_TENANTS_FILE` to the absolute path of a JSON
config file. When that variable is set, the single-tenant `AZURE_*`
variables above are ignored. See
[`tenants.example.json`](./tenants.example.json) for the schema. The
file **must** be `chmod 0600` (owner read/write only) on POSIX; the
server refuses to load any looser permissions.

```json
{
  "default": "contoso",
  "tenants": {
    "contoso": {
      "tenant_id": "11111111-1111-1111-1111-111111111111",
      "client_id": "22222222-2222-2222-2222-222222222222",
      "cert_path": "/secrets/contoso.pfx",
      "cert_passphrase_env": "CONTOSO_CERT_PASS"
    },
    "fabrikam": {
      "tenant_id": "33333333-3333-3333-3333-333333333333",
      "client_id": "44444444-4444-4444-4444-444444444444",
      "cert_path": "/secrets/fabrikam.pfx"
    }
  }
}
```

Two passphrase patterns are supported per tenant; pick **one**:

- **`cert_passphrase_env`** *(recommended)* — names an environment
  variable that holds the passphrase. The on-disk file never contains the
  secret.
- **`cert_passphrase`** — inline literal. Convenient with `sops`/`age`
  but emits a warning to the audit log. Don't commit it.

---

## Claude Desktop / Claude Code integration

Add to your MCP client's config (Claude Desktop:
`claude_desktop_config.json`; Claude Code: `~/.claude.json`).

### Single tenant

```json
{
  "mcpServers": {
    "defender-xdr": {
      "command": "uvx",
      "args": ["--from", "mcp-defender-xdr", "mcp-defender-xdr"],
      "env": {
        "AZURE_TENANT_ID": "00000000-0000-0000-0000-000000000000",
        "AZURE_CLIENT_ID": "00000000-0000-0000-0000-000000000000",
        "AZURE_CERT_PATH": "/Users/me/.config/mcp-defender-xdr/app-cert.pfx"
      }
    }
  }
}
```

### Multi tenant

```json
{
  "mcpServers": {
    "defender-xdr": {
      "command": "uvx",
      "args": ["--from", "mcp-defender-xdr", "mcp-defender-xdr"],
      "env": {
        "MCP_DEFENDER_XDR_TENANTS_FILE": "/etc/mcp-defender-xdr/tenants.json",
        "CONTOSO_CERT_PASS": "..."
      }
    }
  }
}
```

---

## Tools

All three tools accept an optional `tenant` parameter:

- **omitted** → the configured `default` tenant.
- **`"contoso"`** (or any configured key) → that specific tenant.
- **`"*"`** → fan out across every configured tenant. Bounded concurrency
  (5 by default). Returns labelled per-tenant results; one failing
  tenant does not poison the rest.

### `query_advanced_hunting`

**Input**

```json
{
  "query": "DeviceProcessEvents | where FileName == 'powershell.exe' | take 5",
  "timespan": "P1D",
  "tenant": "contoso"
}
```

**Output** (single-tenant — truncated)

```json
{
  "schema": [{"Name": "Timestamp", "Type": "DateTime"}],
  "rows": [{"Timestamp": "2026-05-11T09:14:22Z", "DeviceName": "WS-37"}],
  "metadata": {"row_count": 1, "column_count": 1, "timespan": "P1D"}
}
```

**Output** (`tenant: "*"` — truncated)

```json
{
  "fan_out": true,
  "tenants": ["contoso", "fabrikam"],
  "results": [
    {"tenant": "contoso", "result": {"rows": [...], "metadata": {...}}},
    {"tenant": "fabrikam", "error": {"code": "rate_limited", "message": "..."}}
  ]
}
```

Queries longer than 10,000 chars or containing destructive KQL control
verbs (`.drop`, `.alter`, `.ingest`, `.external_table`, …) are rejected
before any HTTP call.

### `get_incident`

```json
{"incident_id": "12345", "tenant": "contoso"}
```

Returns severity, status, classification, alerts, and impacted entities.

### `list_alerts`

```json
{"severity": "High", "status": "New", "limit": 25, "tenant": "*"}
```

`severity` ∈ {`High`, `Medium`, `Low`, `Informational`}; `status` ∈
{`New`, `InProgress`, `Resolved`}; `limit` ∈ [1, 100], default 25.

---

## Security design

**OAuth scopes.** Only three application permissions are requested, all
read-only: `ThreatHunting.Read.All`, `SecurityEvents.Read.All`,
`SecurityIncident.Read.All`. No write or admin scopes. Even if KQL input
validation is bypassed, the underlying Defender API rejects
state-mutating queries.

**Certificate-based auth.** Authentication uses an X.509 certificate
rather than a client secret. The PFX private key never leaves the host;
only the public certificate is uploaded to Azure. Tokens are acquired
via MSAL's certificate-based client-credentials flow, cached in memory
per `(tenant_key, scope)`, and refreshed 60 s before expiry. Nothing is
written to disk.

**Multi-tenant isolation.** Each tenant has its own MSAL app instance
and its own cache entry. A fan-out across N tenants is N parallel calls
with N distinct bearer tokens; per-tenant results are labelled with the
*server-provided* `tenant` key (never derived from upstream JSON).

**Tenants config (when used).** Must be `chmod 0600`. Passphrases are
referenced from environment variables, not stored inline by default.
Unknown tenant lookups never echo the caller-provided key in the error
message — preventing the validator from being used as a tenant-existence
oracle.

**Audit log (stderr, JSON lines).**

| Logged                                                | Not logged                  |
| ----------------------------------------------------- | --------------------------- |
| Tool name, timestamp, target tenant(s)                | OAuth access token          |
| Validated/sanitized parameters                        | Certificate passphrase      |
| Duration, success/failure, error code on failure      | PFX file contents           |
| Result *counts* (rows, alerts)                        | Raw upstream response body  |
| KQL query text (so hunts are reviewable)              | HTTP headers, correlation IDs |
| Per-tenant outcomes during fan-out                    |                             |

stdout is reserved for the MCP stdio protocol.

For the full analysis, see [`THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## Scope & Design Philosophy

`mcp-defender-xdr` is purpose-built for **detection** and
**investigation**, not response. The v0.1.x surface intentionally
includes:

- Querying incidents and alerts
- Running Advanced Hunting (KQL) queries
- Fetching threat intelligence (planned for v0.3 — see
  [Issues](https://github.com/MFisher14/mcp-defender-xdr/issues))

**Out of scope** for v0.1.x and the foreseeable roadmap:

- Device isolation
- File or process remediation
- Response playbooks or automation

These belong in a separate `mcp-defender-actions` server with
`ThreatHunting.ReadWrite.All` scope and a stricter authorization model.
Keeping the read-only and write-capable surfaces in separate processes
means a compromise of the LLM-facing server cannot cause state changes.

---

## Development

```bash
uv pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
pytest --cov --cov-fail-under=80
```

CI runs on every push and PR to `main` against Python 3.11 and 3.12.

---

## Roadmap

See [GitHub Milestones](https://github.com/MFisher14/mcp-defender-xdr/milestones)
for the current scope of v0.2, v0.3, and future releases.
