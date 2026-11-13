# Demo prompts (offline fixture mode)

Paste these into Claude once the server is configured per
[`README.md`](./README.md) in this directory. They exercise every tool
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

## 5. Investigation pivots

> Incident INC-4471 names device fixture0000000000000000000000000000a014.
> Pull its timeline for 2026-08-31 between 00:00 and 06:00 UTC and walk me
> through the attack chain.

`get_device_timeline` returns ten events across all five event families:
a macro document lands, Word spawns encoded PowerShell, a DLL is dropped and
loaded by `rundll32`, a Run-key persistence value is set, LSASS is opened,
and the host beacons to `198.51.100.7`.

> Now investigate the user j.doe.fixture@example.com from 2026-08-30 to
> 2026-09-01. Anything that looks like the initial access?

`investigate_user` returns sign-ins (including a failed then successful
cloud sign-in from an unfamiliar location), the inbound invoice email, and
device logons — including one onto `srv-fixture-db02`.

> Is the SHA-256 0000000000000000000000000000000000000000000000000000000000000001
> known to Defender? What about the domain updates.fixture.example.com, and
> the IP 203.0.113.250?

`query_threat_intelligence` finds an alert and file/image-load sightings for
the hash, an alert plus network and email-URL sightings for the domain, and
`matched: false` for the IP.

## 6. Confirm the guardrails still apply

Fixture mode replaces the transport, not the validation. These are rejected
before anything is served:

> Run this Advanced Hunting query: `.drop table DeviceProcessEvents`

Rejected as a destructive KQL control verb.

> Run an Advanced Hunting query that's 20,000 characters long.

Rejected by the 10,000-character cap.

> Get the device timeline for device `abc" | take 1 //` over the last day.

Rejected: device IDs are alphanumerics and dashes only, so no value can
escape the server-built query.

> Pull a 60-day timeline for that device.

Rejected: the window is capped at 30 days.
