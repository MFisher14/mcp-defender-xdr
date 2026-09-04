# Demo prompts (offline fixture mode)

Paste these into Claude once the server is configured per
[`README.md`](./README.md) in this directory. They exercise all three tools
plus fan-out and error handling — with **no Azure tenant, no App
Registration, and no certificate**.

Every response is synthetic. Each result carries `"fixture_mode": true` and a
`notice` field, and the server logs a `FIXTURE-MODE-ACTIVE-SYNTHETIC-DATA`
warning on stderr for every single tool call.

---

## 1. `query_advanced_hunting` — run a KQL hunt

> Run an Advanced Hunting query for process creation events over the last day
> and summarize what you see. Tell me explicitly whether this is live tenant
> data or fixture data.

Expect five rows across four invented hosts: an encoded PowerShell command
spawned by Word, a `rundll32` load, SMB share enumeration by a service
account, a `curl` download, and shadow-copy deletion on a domain controller.

Claude should state up front that the data is synthetic — the `notice` field
and `fixture_mode` flag are in the payload it reads.

> That result set — walk me through it as an attack chain. Which host looks
> worst, and what would you pivot on next?

## 2. `get_incident` — pull one incident with alerts and entities

> Get incident INC-4471 and summarize the alerts and impacted entities.

Two alerts (`Execution`, `CredentialAccess`), seven entities across machine,
user, process, file, and IP types, on `wkstn-fixture-014.corp.example.com`.

> Now get incident INC-8892 and tell me why it was closed.

Resolved / FalsePositive / SecurityTesting.

> Get incident INC-0000.

Exercises the error path: an ID with no fixture returns the same `not_found`
error code the live API's 404 maps to.

## 3. `list_alerts` — filter and limit

> List all the alerts.

Six alerts spanning High, Medium, Low, and Informational.

> Now just the High severity alerts that are still New.

Filtering runs for real: fixture mode evaluates the same OData `$filter` the
tool builds, so exactly one alert comes back.

> List the two most relevant alerts only.

`limit` is applied to the fixture set the same way `$top` is applied upstream.

## 4. Fan-out across tenants

> List alerts across every configured tenant at once.

Two synthetic tenants, `contoso-fixture` and `fabrikam-fixture`, are
configured in fixture mode so the fan-out envelope is demonstrable. Both
return the same recorded payload — the point is the labelled per-tenant
structure and the bounded concurrency, not differing data.

> Run the same Advanced Hunting query across all tenants and compare.

## 5. Confirm the guardrails still apply

Fixture mode replaces the transport, not the validation. These are rejected
before anything is served:

> Run this Advanced Hunting query: `.drop table DeviceProcessEvents`

Rejected as a destructive KQL control verb.

> Run an Advanced Hunting query that's 20,000 characters long.

Rejected by the 10,000-character cap.
