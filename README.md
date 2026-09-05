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

## Quickstart (offline)

**Evaluate this server with no Azure tenant, no App Registration, and no
certificate.** Fixture mode swaps the HTTP and OAuth layer for recorded
synthetic responses; validation, the per-tool transforms, multi-tenant
fan-out, and the audit log all run for real on top of them.

```bash
git clone https://github.com/MFisher14/mcp-defender-xdr.git
cd mcp-defender-xdr
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Boots with no other environment variables set.
MCP_DEFENDER_XDR_FIXTURE_MODE=synthetic-fixtures-no-live-data mcp-defender-xdr
```

Then point your MCP client at it — no credentials in the config:

```json
{
  "mcpServers": {
    "defender-xdr-fixtures": {
      "command": "/absolute/path/to/mcp-defender-xdr/.venv/bin/mcp-defender-xdr",
      "args": [],
      "env": {
        "MCP_DEFENDER_XDR_FIXTURE_MODE": "synthetic-fixtures-no-live-data"
      }
    }
  }
}
```

Demo prompts covering all three tools, fan-out, and the error paths are in
[`examples/prompts.md`](./examples/prompts.md); setup detail is in
[`examples/README.md`](./examples/README.md).

**Fixture output cannot be confused with live data.** Every result carries
`"fixture_mode": true` and a synthetic-data `notice` in the payload the model
reads; every tool call emits a WARNING-level
`FIXTURE-MODE-ACTIVE-SYNTHETIC-DATA` audit record on stderr; and every
hostname is invented under `example.com` with every IP drawn from the RFC 5737
documentation ranges.

**It also cannot be switched on by accident.**
`MCP_DEFENDER_XDR_FIXTURE_MODE` must equal `synthetic-fixtures-no-live-data`
exactly. Any other non-empty value — `1`, `true`, `yes` — exits 2 at startup
rather than resolving to either mode, so a typo can neither serve fake data
nor quietly reach a live tenant. Unset it to run live, and continue with
Prerequisites below.

---

## Prerequisites

1. An Azure tenant with Microsoft Defender for Endpoint / Defender XDR.
2. An [Azure App Registration](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
   per tenant, with the following **application** API permissions
   (admin consent required).

   All three are granted on the **WindowsDefenderATP** resource (app ID
   `fc780465-2017-40d4-a0c5-307022471b92`). In the Azure portal that is
   "API permissions" → "Add a permission" → **APIs my organization uses**
   → **WindowsDefenderATP** → **Application permissions** — *not*
   Microsoft Graph. The server requests the token scope
   `https://api.securitycenter.microsoft.com/.default`, which resolves to
   exactly that resource and no other.

   | Permission               | Why                      |
   | ------------------------ | ------------------------ |
   | `AdvancedQuery.Read.All` | Run Advanced Hunting KQL |
   | `Alert.Read.All`         | Read alerts              |
   | `Incident.Read.All`      | Read incidents           |

   All three permissions are **read-only**.

   Microsoft Graph exposes similarly-named permissions
   (`ThreatHunting.Read.All`, `SecurityEvents.Read.All`,
   `SecurityIncident.Read.All`). Those belong to the Graph Security API and
   grant **nothing** against the host this server calls; granting them
   instead of the three above will leave every tool returning
   `auth_failure`.

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

> **This package is not published to PyPI yet.** Install from source — it
> is the only path that works today.

### From source

```bash
# 1. Clone.
git clone https://github.com/MFisher14/mcp-defender-xdr.git
cd mcp-defender-xdr

# 2. Create and activate a virtualenv.
#    `uv venv` is recommended; `python -m venv .venv` works just as well.
uv venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install the package (editable) plus the dev/test tooling.
uv pip install -e ".[dev]"

# 4. Confirm the install.
python -c "import mcp_defender_xdr; print(mcp_defender_xdr.__version__)"
command -v mcp-defender-xdr
```

Step 4 should print the current version and the path to the console
script. That script speaks MCP over stdio and is meant to be launched by an
MCP client rather than run by hand. Running it directly with no
credentials configured exits with status `2` and names the missing
environment variables — that is expected, not a failed install:

```console
$ mcp-defender-xdr
mcp-defender-xdr: Missing required Azure credential environment variables:
AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CERT_PATH. See .env.example for setup.
```

Continue with [Configuration](#configuration) to supply those, then wire the
absolute path to the console script into your MCP client — see
[Claude Desktop / Claude Code integration](#claude-desktop--claude-code-integration).

To run the test suite and the linters, see [Development](#development).

### From PyPI — not yet available (planned for v0.2)

The commands below are the intended v0.2 install path. **They do not work
today** and will fail with "No solution found" / "No matching distribution
found" until the first PyPI release. They are recorded here so the
published interface is settled ahead of time; track the release in
[Milestones](https://github.com/MFisher14/mcp-defender-xdr/milestones).

```bash
# Planned — does not work yet.
uvx --from mcp-defender-xdr mcp-defender-xdr
```

```bash
# Planned — does not work yet.
pip install mcp-defender-xdr
mcp-defender-xdr
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
| `DEFENDER_API_BASE`               | no       | Override the API base URL (host only — see below).         |
| `MCP_DEFENDER_XDR_LOG_LEVEL`      | no       | Audit log level. Default `INFO`.                           |
| `MCP_DEFENDER_XDR_FIXTURE_MODE`   | no       | Offline fixture mode. See [Quickstart (offline)](#quickstart-offline). |

The server validates that the PFX file exists at startup and fails fast
with exit code 2 if any required variable is missing or the file is not
readable.

### Which API this server talks to

The server targets the **Microsoft Defender for Endpoint REST API** at
`https://api.securitycenter.microsoft.com` (`DEFAULT_DEFENDER_RESOURCE` in
[`src/mcp_defender_xdr/auth.py`](./src/mcp_defender_xdr/auth.py)). All
three tools call paths on that host:

| Tool                     | Request                            |
| ------------------------ | ---------------------------------- |
| `query_advanced_hunting` | `POST /api/advancedqueries/run`    |
| `get_incident`           | `GET /api/incidents/{incident_id}` |
| `list_alerts`            | `GET /api/alerts`                  |

This is **not** the Microsoft Graph Security API, which lives at
`https://graph.microsoft.com/v1.0/security` and uses different paths,
different response shapes, and different permission names. The server does
not speak Graph today; pointing it at `graph.microsoft.com` will not work.

`DEFENDER_API_BASE` overrides **only** the host portion of those requests.
Use it to route through a recording proxy, an egress gateway, or a test
double. It does *not* change the OAuth scope, which stays pinned to
`https://api.securitycenter.microsoft.com/.default` and is not currently
configurable — so sovereign clouds (GCC High, DoD, 21Vianet), which need a
different host **and** a different token audience, are not reachable via
this variable alone.

```bash
# Example: route Defender API traffic through a local recording proxy.
export DEFENDER_API_BASE=https://defender-proxy.internal.example.com
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

Until the package is on PyPI, point `command` at the absolute path of the
`mcp-defender-xdr` console script inside the virtualenv you created in
[Installation](#installation) — `command -v mcp-defender-xdr` prints it
while that virtualenv is active. MCP clients launch the server without your
shell's `PATH`, so a bare `"mcp-defender-xdr"` will not resolve.

### Single tenant

```json
{
  "mcpServers": {
    "defender-xdr": {
      "command": "/absolute/path/to/mcp-defender-xdr/.venv/bin/mcp-defender-xdr",
      "args": [],
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
      "command": "/absolute/path/to/mcp-defender-xdr/.venv/bin/mcp-defender-xdr",
      "args": [],
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

**OAuth scopes.** The server requests a single token scope,
`https://api.securitycenter.microsoft.com/.default`, which resolves to the
WindowsDefenderATP resource. Only three application permissions need to be
consented on it, all read-only: `AdvancedQuery.Read.All`,
`Alert.Read.All`, `Incident.Read.All`. No write or admin scopes. Even if
KQL input validation is bypassed, the underlying Defender API rejects
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

These belong in a separate `mcp-defender-actions` server holding the
WindowsDefenderATP response permissions they require (`Machine.Isolate`,
`Machine.StopAndQuarantine`, and similar) under a stricter authorization
model.
Keeping the read-only and write-capable surfaces in separate processes
means a compromise of the LLM-facing server cannot cause state changes.

### Not the same project as `mcp-defender`

A separate MCP server named [`mcp-defender`](https://pypi.org/project/mcp-defender/),
by a different author, has been published on PyPI since January 2026 and
also exposes Defender Advanced Hunting. This is an unrelated codebase —
not a fork, no shared lineage — with different design choices: it
authenticates with X.509 certificates instead of client secrets, it is
multi-tenant from the ground up with per-tenant token isolation and
bounded fan-out across tenants, and it ships a published threat model in
[`THREAT_MODEL.md`](./THREAT_MODEL.md). If you are choosing between them,
compare on those axes and pick whichever suits your environment.

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
