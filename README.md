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

Demo prompts covering every tool, fan-out, and the error paths are in
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

### Choosing a deployment

Two independent choices: **how clients reach the server** (transport) and
**where the certificate lives** (credential provider).

| Scenario | Transport | Credential provider | Start here |
| -------- | --------- | ------------------- | ---------- |
| Trying it out, no Azure at all | stdio | none ([fixture mode](#quickstart-offline)) | [Quickstart (offline)](#quickstart-offline) |
| Laptop / analyst workstation, one tenant | stdio | env vars + PFX on disk | [Single tenant](#single-tenant-development--small-deployments) |
| Single-tenant production host | stdio | tenants file with one `keyvault` or `aws-secretsmanager` tenant | [Secret manager](#keeping-the-certificate-in-a-secret-manager-optional) |
| Multi-tenant production (MSSP, many customers) | stdio | tenants file, a secret-manager provider per tenant, plus [quotas](#per-tenant-quotas-optional) | [Multi tenant](#multi-tenant-production) |
| Shared remote server for a SOC team | HTTP + bearer tokens, behind TLS | tenants file with secret-manager providers | [HTTP transport](#http-transport-remote-clients) |

#### Transports

| | stdio (default) | HTTP (`--transport http`) |
| - | --------------- | ------------------------- |
| Who starts the process | The MCP client, on the same machine | You, as a long-running service |
| Who can call it | Only the client that spawned it | Anyone with network access **and** a valid token |
| Authentication | Implicit: process ownership | Short-lived signed JWT on every request ([T8](./THREAT_MODEL.md)) |
| Where the certificate must be | Same host as the client | The server host only; clients hold no Defender credentials |
| Claude Code | `command` config | `"type": "http"` + `headersHelper` |
| Claude Desktop | `command` config | Via a stdio bridge (see below); prefer stdio |

#### Credential providers

| Provider | Configured by | Certificate lives | Best for |
| -------- | ------------- | ----------------- | -------- |
| Env vars | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CERT_PATH` | PFX on the host | Development, one tenant |
| Tenants file, `file` | `MCP_DEFENDER_XDR_TENANTS_FILE` → `cert_path` per tenant | PFX on the host | Multiple tenants on a hardened host |
| Tenants file, `keyvault` | `provider`, `vault_url`, `cert_secret_name` | Azure Key Vault (in memory at runtime) | Hosts with an Azure managed or workload identity |
| Tenants file, `aws-secretsmanager` | `provider`, `region`, `secret_id` | AWS Secrets Manager (in memory at runtime) | Hosts with an AWS role (IRSA, ECS, EC2) |

Providers can be mixed per tenant in one tenants file. The secret-manager
providers are tenants-file only (see the `AZURE_CLIENT_ID` note under
[Keeping the certificate in a secret manager](#keeping-the-certificate-in-a-secret-manager-optional)).
[`tenants.cloud.example.json`](./tenants.cloud.example.json) shows all
three side by side, and [`.env.example`](./.env.example) has a commented
stanza for every variable.

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
[`src/mcp_defender_xdr/auth.py`](./src/mcp_defender_xdr/auth.py)). Every
tool calls paths on that host:

| Tool                        | Request                                         |
| --------------------------- | ----------------------------------------------- |
| `query_advanced_hunting`    | `POST /api/advancedqueries/run`                 |
| `get_incident`              | `GET /api/incidents/{incident_id}`              |
| `list_alerts`               | `GET /api/alerts`                               |
| `get_device_timeline`       | `POST /api/advancedqueries/run` (server-built KQL) |
| `investigate_user`          | `POST /api/advancedqueries/run` (server-built KQL) |
| `query_threat_intelligence` | `POST /api/advancedqueries/run` ×2 (server-built KQL) |

The three investigation tools are built on Advanced Hunting, so they need
no permission beyond `AdvancedQuery.Read.All`.

The two Sentinel tools are the exception. They call the Log Analytics
query API and Azure Resource Manager, with tokens for those audiences; see
[Microsoft Sentinel](#microsoft-sentinel-query_sentinel-and-list_sentinel_hunting_queries).

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

#### Per-tenant quotas (optional)

By default the server relies on Defender's own rate limits, so during a
`tenant: "*"` fan-out one expensive tenant can eat the latency budget for
the rest. A quota caps each tenant over a rolling 60-second window:

```json
{
  "default": "contoso",
  "default_quota": {"requests_per_minute": 30, "rows_per_minute": 50000},
  "tenants": {
    "contoso": {"...": "...", "quota": {"requests_per_minute": 60}},
    "fabrikam": {"...": "..."},
    "lab": {"...": "...", "quota": null}
  }
}
```

- `default_quota` applies to every tenant without its own `quota` key
  (`fabrikam` above). A tenant's `quota` replaces the default outright
  rather than merging with it (`contoso` above has no row limit), and
  `"quota": null` opts a tenant out (`lab`).
- `requests_per_minute` counts tool calls admitted for that tenant: a
  fan-out charges each tenant once, and retries of a 429 or 5xx inside one
  call are not counted again. `rows_per_minute`
  counts rows returned, which only approximates cost: a call is admitted
  while the tenant is under its row budget, and its rows are charged after
  it returns.
- A tenant over quota gets a `quota_exceeded` error in its own slot of a
  fan-out result, with an estimated retry time; sibling tenants are
  unaffected. On a single-tenant call it is the tool's error.
- Every admit or deny writes a `quota-decision` audit record with the
  tenant, the tool, and the usage in the current window.
- State is held in process memory. It resets on restart and is not shared
  between server processes.

#### Keeping the certificate in a secret manager (optional)

Instead of `cert_path`, a tenant can name a secret in **Azure Key Vault**
or **AWS Secrets Manager**. The server fetches it once at startup with the
host's cloud identity, parses it in memory, and never writes the PFX to
disk. Install the matching extra:

```bash
uv pip install -e ".[keyvault]"            # azure-identity + azure-keyvault-secrets
uv pip install -e ".[aws-secretsmanager]"  # boto3
```

```json
{
  "default": "contoso",
  "tenants": {
    "contoso": {
      "provider": "keyvault",
      "tenant_id": "11111111-1111-1111-1111-111111111111",
      "client_id": "22222222-2222-2222-2222-222222222222",
      "vault_url": "https://contoso-secops.vault.azure.net/",
      "cert_secret_name": "defender-xdr-mcp"
    },
    "fabrikam": {
      "provider": "aws-secretsmanager",
      "tenant_id": "33333333-3333-3333-3333-333333333333",
      "client_id": "44444444-4444-4444-4444-444444444444",
      "region": "us-east-1",
      "secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:defender/fabrikam-AbCdEf"
    }
  }
}
```

| Field | Provider | Notes |
| ----- | -------- | ----- |
| `provider` | both | `file` (the default when omitted), `keyvault`, or `aws-secretsmanager`. Providers can be mixed per tenant. |
| `vault_url`, `cert_secret_name` | keyvault | For a Key Vault **certificate**, use the certificate's name: its backing secret holds the PFX. |
| `cert_secret_version` | keyvault | Optional 32-hex version ID. Default is the current version. |
| `passphrase_secret_name` | keyvault | Optional secret holding the PFX passphrase. |
| `keyvault_identity_client_id` | keyvault | Optional client ID of the user-assigned managed or workload identity to use. |
| `region`, `secret_id` | aws-secretsmanager | `secret_id` is a name or full ARN. Uses the `AWSCURRENT` version. |
| `passphrase_secret_id` | aws-secretsmanager | Optional secret holding the PFX passphrase. |
| `cert_passphrase_env` | both | Alternative to a passphrase secret: an environment variable name. |

**Secret contents.** A secret may hold raw PKCS#12 bytes (AWS
`SecretBinary`), base64-encoded PKCS#12 (a Key Vault certificate's backing
secret, or `base64 -i app-cert.pfx` stored as a string), or PEM text
containing both the private key and the certificate.

**Cloud identity.** Key Vault uses `DefaultAzureCredential`: an
environment service principal, workload identity, managed identity, or a
developer sign-in such as `az login`. The identity needs the *Key Vault
Secrets User* role, or `get` permission on secrets. AWS uses the standard
boto3 chain (environment, profile/SSO, IRSA, ECS task role, instance
profile) and needs `secretsmanager:GetSecretValue`, plus `kms:Decrypt` if
the secret uses a customer-managed key.

> **`AZURE_CLIENT_ID` gotcha.** `DefaultAzureCredential` reads
> `AZURE_CLIENT_ID` as the managed or workload identity to use. If that
> variable holds the *Defender* App Registration's ID, Key Vault sign-in
> fails. Leave it unset in tenants-file mode, or set
> `keyvault_identity_client_id`. For the same reason, secret-store
> providers are available only through the tenants file, not the
> single-tenant `AZURE_*` variables; a one-tenant tenants file works fine.

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

### Claude Desktop over HTTP

Claude Desktop's `claude_desktop_config.json` launches local commands,
so reaching a remote HTTP server needs a stdio-to-HTTP bridge such as
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote). A bridge sends
whatever header it was started with. Mint the token in a wrapper script,
so every launch gets a fresh one:

```json
{
  "mcpServers": {
    "defender-xdr-remote": {
      "command": "/absolute/path/to/defender-xdr-remote.sh"
    }
  }
}
```

```sh
#!/bin/sh
# defender-xdr-remote.sh
TOKEN="$(your-token-command --audience mcp-defender-xdr://soc-prod)"
exec npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer ${TOKEN}"
```

The bridge can't refresh the token, so the session stops working when the
token expires (15 minutes by default) and Claude Desktop must be
restarted. That makes stdio the better fit for Claude Desktop. Claude Code
doesn't have this problem: it re-runs `headersHelper` on reconnect (see
below).

---

## HTTP transport (remote clients)

stdio is the default and needs nothing here. To serve MCP to clients on
another host, run the **Streamable HTTP** transport (JSON-RPC over POST,
with streaming over SSE) at `/mcp`. It requires short-lived signed bearer
tokens and will not start without them. See
[`THREAT_MODEL.md`](./THREAT_MODEL.md) T8.

```bash
export MCP_DEFENDER_XDR_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export MCP_DEFENDER_XDR_JWT_AUDIENCE="mcp-defender-xdr://soc-prod"
export MCP_DEFENDER_XDR_JWT_ISSUER="https://tokens.example.com"
mcp-defender-xdr --transport http            # → http://127.0.0.1:8765/mcp
```

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MCP_DEFENDER_XDR_TRANSPORT` | `stdio` | `stdio` or `http`. `--transport` overrides it. |
| `MCP_DEFENDER_XDR_HTTP_HOST` / `_PORT` / `_PATH` | `127.0.0.1` / `8765` / `/mcp` | Bind address and endpoint. `--host` and `--port` override. |
| `MCP_DEFENDER_XDR_HTTP_TLS_CERTFILE` / `_KEYFILE` | — | Serve HTTPS directly. **Required for a non-loopback bind**, unless the next variable is set. |
| `MCP_DEFENDER_XDR_HTTP_ALLOW_PLAINTEXT` | — | `behind-tls-terminating-proxy`, the only accepted value, permits a plaintext non-loopback bind behind a TLS proxy. |
| `MCP_DEFENDER_XDR_HTTP_ALLOWED_HOSTS` | loopback + bind host | Comma-separated `Host` header allowlist (DNS-rebinding protection). Set it to your public hostname behind a proxy. |
| `MCP_DEFENDER_XDR_HTTP_ALLOWED_ORIGINS` | none | Comma-separated `Origin` allowlist for browser clients. |
| `MCP_DEFENDER_XDR_JWT_AUDIENCE` / `_ISSUER` | — | **Required.** Tokens' `aud` and `iss` must equal these exactly. |
| `MCP_DEFENDER_XDR_JWT_ALGORITHM` | `HS256` | One pinned algorithm. `HS256/384/512`, or `RS*`, `PS*`, `ES*`, `EdDSA`. |
| `MCP_DEFENDER_XDR_JWT_SECRET` | — | HMAC shared secret, at least 32 bytes (HS* only). |
| `MCP_DEFENDER_XDR_JWT_PUBLIC_KEY_FILE` | — | PEM **public** key (asymmetric only). The server never needs a private key. |
| `MCP_DEFENDER_XDR_JWT_MAX_TTL_SECONDS` | `900` | Longest permitted `exp − iat` (60–3600). |

**Tokens.** Required claims are `iss`, `aud`, `sub`, `iat`, `exp`, and a
unique `jti`. The server only *validates* tokens. Issue them from your
identity provider or token service. For development,
[`examples/mint_token.py`](./examples/mint_token.py) mints one:

```bash
python examples/mint_token.py --audience mcp-defender-xdr://soc-prod \
  --issuer https://tokens.example.com --subject analyst@example.com
```

**One token, one session.** A token can open a single MCP session and is
then bound to it. A session is bound to the token's `sub`. A fresh token
for the same `sub` may continue the session, but a replayed token cannot
open a second one. Clients should therefore mint a token per connection,
not reuse one from a static config.

**Claude Code** does this with `headersHelper`, a command that prints the
headers as JSON. Claude Code runs it whenever it connects. When a token
expires mid-session, the server answers `401`, Claude Code reconnects, the
helper mints a new token, and the next tool call succeeds without user
action. This was verified against Claude Code with a 60-second TTL:

```json
{
  "mcpServers": {
    "defender-xdr": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headersHelper": "/path/to/print-defender-token-header.sh"
    }
  }
}
```

```sh
#!/bin/sh
# print-defender-token-header.sh
printf '{"Authorization": "Bearer %s"}' "$(your-token-command --audience mcp-defender-xdr://soc-prod)"
```

Every audit record carries `"transport": "stdio" | "http"`. HTTP mode also
logs `http-session-opened` (`sub`, `jti`, session ID) and
`http-auth-rejected` (reason code, client address). It never logs the token.

---

## Tools

Every tool accepts an optional `tenant` parameter:

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

### Investigation tools

These three answer the usual next question after an alert names a device,
a user, or an indicator. The caller never writes KQL: each tool validates
its inputs against strict patterns, then builds a read-only Advanced
Hunting query server-side (every value is emitted as an escaped KQL
literal, so validation and escaping both have to fail before injection is
possible). The full query text is written to the audit log.

Time windows take ISO 8601 timestamps **with a timezone**, `end` must be
after `start`, and the window is capped at 30 days (Advanced Hunting
retention). Results are capped at `limit` rows and flagged `truncated` when
more exist; empty columns are dropped from each row to keep the payload
small.

#### `get_device_timeline`

```json
{
  "device_id": "fixture0000000000000000000000000000a014",
  "start": "2026-08-31T00:00:00Z",
  "end": "2026-08-31T06:00:00Z",
  "event_types": ["process", "network"],
  "limit": 200
}
```

Merges `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`,
`DeviceRegistryEvents`, and `DeviceEvents` (`event_types` ∈ {`process`,
`network`, `file`, `registry`, `other`}; omit for all) into one timeline,
newest first, with per-type counts.

#### `investigate_user`

```json
{
  "account_upn": "j.doe@contoso.com",
  "start": "2026-08-30T00:00:00Z",
  "end": "2026-09-01T00:00:00Z",
  "signal_types": ["sign_in", "mailbox", "device"]
}
```

Give exactly one of `account_upn` or `account_sid`; the other is resolved
through `IdentityInfo`. Returns sign-ins (`IdentityLogonEvents`), mail sent
or received (`EmailEvents`, matched on the UPN), and device logons
(`DeviceLogonEvents`), grouped by signal and capped per signal so a busy
mailbox cannot crowd out sign-ins. `found: false` means nothing matched.
Tables a tenant is not licensed for are skipped (`union isfuzzy=true`)
rather than failing the call.

#### `query_threat_intelligence`

```json
{"ioc_type": "hash", "ioc_value": "<sha256>", "lookback_days": 30}
```

`ioc_type` ∈ {`ip`, `domain`, `url`, `hash`}; hashes may be MD5, SHA-1, or
SHA-256 (inferred from length). Returns the alerts whose evidence contains
the indicator (`AlertEvidence`: title, severity, detection source, MITRE
techniques, devices), the highest severity among them, and telemetry
sightings by table (hit count, first/last seen, devices or mailboxes).

**What it does not consult.** Custom indicators (Settings → Indicators)
are listed only by `GET /api/indicators`, which requires the
`Ti.ReadWrite` application permission, and the file and domain
related-alert endpoints require `Alert.ReadWrite.All`. Both are write
scopes, so this read-only server does not use them; every result carries a
`coverage_note` saying so, so a `matched: false` is never over-read.

### Microsoft Sentinel: `query_sentinel` and `list_sentinel_hunting_queries`

For SOCs that route Defender data into Microsoft Sentinel alongside their
own sources (firewalls, `SigninLogs`, custom `*_CL` tables), two tools query
the tenant's Log Analytics workspace:

```json
{"query": "CommonSecurityLog | where DestinationIP == '198.51.100.7' | take 50", "timespan": "P7D"}
```

```json
{"saved_query_id": "fixture-hunt-beaconing", "timespan": "P1D"}
```

- `query_sentinel` takes either `query` (KQL, with the same guardrails as
  Advanced Hunting) or `saved_query_id`. It returns the schema and up to
  `limit` rows (default 200, max 1,000), flagged `truncated` when the cap
  cuts rows off.
- `list_sentinel_hunting_queries` lists the workspace's saved searches in
  category `Hunting Queries` (configurable), with tactics, techniques,
  description, and KQL. Filter with `search` or `tactic`. The `id` it
  returns is what `saved_query_id` takes. A saved query's KQL passes the
  same validation before it runs.
- Every result carries an `untrusted_content_notice`: custom tables can
  hold anything anyone on the network chose to send.

**Configuration.** Per tenant, in the tenants file:

```json
"contoso": {
  "...": "...",
  "sentinel_workspace_id": "0f1c5000-0000-4000-8000-00000000f1c5",
  "sentinel_workspace_resource_id": "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>"
}
```

Or, in single-tenant mode, `MCP_DEFENDER_XDR_SENTINEL_WORKSPACE_ID` and
`MCP_DEFENDER_XDR_SENTINEL_WORKSPACE_RESOURCE_ID`. The workspace ID (a
GUID, under the workspace's *Overview* page) is enough for queries. The
resource ID is needed only to list or run saved hunting queries. Tenants
without a workspace return `invalid_input` in their fan-out slot.

**Permissions.** These are Azure RBAC role assignments on the workspace,
not API permissions, for the same App Registration and certificate:

| Role (scope: the workspace) | Why |
| --------------------------- | --- |
| **Log Analytics Reader** | Run KQL via `POST https://api.loganalytics.io/v1/workspaces/{id}/query` (token audience `https://api.loganalytics.io`) |
| **Reader** | Read saved searches via `GET https://management.azure.com{resource-id}/savedSearches` (token audience ARM) |

Both roles are read-only. Role assignments can take up to an hour to take
effect.

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
- Pivoting from a device, a user, or an indicator of compromise to the
  related telemetry and alerts (`get_device_timeline`, `investigate_user`,
  `query_threat_intelligence`)

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
