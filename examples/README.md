# Offline fixture mode

Run `mcp-defender-xdr` and exercise all three tools with **no Azure tenant, no
App Registration, and no certificate**. Fixture mode replaces the HTTP and
OAuth layer with recorded synthetic responses; everything above it —
validation, the per-tool response transforms, multi-tenant fan-out, the audit
log — runs exactly as it does against the live API.

This is for evaluating the server. It is not a test double you should ship
against, and it is not a way to preview a real tenant.

---

## Quickstart

```bash
git clone https://github.com/MFisher14/mcp-defender-xdr.git
cd mcp-defender-xdr
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

MCP_DEFENDER_XDR_FIXTURE_MODE=synthetic-fixtures-no-live-data mcp-defender-xdr
```

The server starts with no other environment variables set and prints a
fixture-mode banner to stderr. It then waits on stdin for MCP traffic — that
is correct; an MCP client drives it. Wire up the client config below.

## Claude Desktop / Claude Code config (no credentials)

Claude Desktop: `claude_desktop_config.json`. Claude Code: `~/.claude.json`.
Replace the path with your clone's virtualenv — `command -v mcp-defender-xdr`
prints it while the virtualenv is active.

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

No `AZURE_*` variables, no PFX, no tenants file. Restart the client, then work
through [`prompts.md`](./prompts.md).

Naming the server `defender-xdr-fixtures` rather than `defender-xdr` is worth
doing: if you later add a live entry, the tool names in the transcript tell you
which one answered.

## Enabling it

`MCP_DEFENDER_XDR_FIXTURE_MODE` must equal
`synthetic-fixtures-no-live-data` **exactly**.

Any other non-empty value — `1`, `true`, `yes`, `SYNTHETIC-FIXTURES-NO-LIVE-DATA` —
is a startup failure with exit code 2, not a silent fall-through:

```console
$ MCP_DEFENDER_XDR_FIXTURE_MODE=1 mcp-defender-xdr
mcp-defender-xdr: MCP_DEFENDER_XDR_FIXTURE_MODE is set to an unrecognized value.
Offline fixture mode must be enabled with the exact value
'synthetic-fixtures-no-live-data'; every other value is refused so that fixture
mode cannot be switched on — or off — by accident. Unset
MCP_DEFENDER_XDR_FIXTURE_MODE to run against live Defender APIs.
```

Refusing outright is the design: an unrecognized value must never resolve to
either mode. A typo can't quietly serve fake data, and it can't quietly reach a
live tenant either. Unset the variable to run live.

## You cannot mistake fixture output for live data

Three independent signals, on every call:

1. **In the payload the model reads.** Every result carries
   `"fixture_mode": true` and a `notice` naming the data as synthetic. Claude
   sees this on every response, so its own summaries say so too.
2. **In the audit log, per call.** A WARNING-level
   `FIXTURE-MODE-ACTIVE-SYNTHETIC-DATA` record on stderr for every tool
   invocation — not a startup banner that scrolls out of view:

   ```json
   {"ts":"...","level":"WARNING","logger":"mcp_defender_xdr.audit",
    "event":"FIXTURE-MODE-ACTIVE-SYNTHETIC-DATA","tool":"list_alerts",
    "fixture_mode":true,"tenants":["contoso-fixture"],"notice":"SYNTHETIC FIXTURE DATA — ..."}
   ```

3. **In the data itself.** Every hostname is invented and under
   `example.com`; every IP is an RFC 5737 documentation address
   (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); every tenant key ends
   in `-fixture`. Enforced by tests, not just convention — see
   `tests/test_fixture_mode.py`.

## What's here

| Path                             | Contents                                                      |
| -------------------------------- | ------------------------------------------------------------- |
| `fixtures/advanced_hunting.json` | `POST /api/advancedqueries/run` — 5 rows, 8-column schema      |
| `fixtures/incidents.json`        | `GET /api/incidents/{id}` — `INC-4471`, `INC-8892`             |
| `fixtures/alerts.json`           | `GET /api/alerts` — 6 alerts across all four severities        |
| `prompts.md`                     | Demo prompts covering all three tools, fan-out, and errors     |

The files hold **raw upstream response shapes**, not finished tool output. Each
tool's real parsing code runs against them, so what you see is what the live
transform produces.

Fixture mode also honours the request parameters the tools build: the OData
`$filter` from `severity`/`status` and the `$top` from `limit` are applied to
the recorded alert set, and an incident ID with no fixture raises the same
`not_found` error the live 404 maps to.

Two synthetic tenants (`contoso-fixture`, `fabrikam-fixture`) are configured so
`tenant: "*"` fan-out is demonstrable. Both return the same recorded payload;
what fan-out demonstrates is the labelled per-tenant envelope and bounded
concurrency, not differing data.

## Editing the fixtures

Edit the JSON in `fixtures/` and restart the server. Keep new data obviously
synthetic — the test suite fails on any IP outside RFC 5737, any hostname not
under `example.com`, and any fixture file missing its `_comment` banner.
