# Contributing to `mcp-defender-xdr`

Thanks for your interest. This is a small, focused project; contributions
that align with the project's scope (detection and investigation, not
response — see the README's *Scope & Design Philosophy*) are welcome.

## Prerequisites

- Python 3.11 or later.
- [`uv`](https://docs.astral.sh/uv/) (recommended) or `pip`.
- A GitHub account.

## Setup

```bash
git clone https://github.com/MFisher14/mcp-defender-xdr.git
cd mcp-defender-xdr
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

You do **not** need an Azure tenant or live Defender credentials to
develop or run the test suite — the tests stub the upstream API.

## Workflow

1. Open or comment on an issue first for anything non-trivial. This
   avoids wasted work on changes that fall outside scope.
2. Branch off `main`. Use a short, descriptive branch name
   (e.g. `feat/sentinel-tool`, `fix/kql-length-edge-case`).
3. Keep one logical change per pull request. Smaller PRs are reviewed
   faster.
4. Follow [Conventional Commits](https://www.conventionalcommits.org/)
   for commit messages. Existing repository conventions use prefixes
   like `feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`.

## Local checks

Run these before opening a pull request. CI will run them too.

```bash
ruff check . && ruff format --check .
mypy
pytest --cov --cov-fail-under=80
```

## Pull request checklist

- [ ] Tests added or updated for any behavior change.
- [ ] `ruff`, `mypy`, and `pytest` all pass locally.
- [ ] [`THREAT_MODEL.md`](./THREAT_MODEL.md) updated if the change
      affects the attack surface (new input source, new credential
      handling, new output path).
- [ ] New runtime dependencies justified in the PR description.
- [ ] Audit log entries reviewed for credential or PII leakage (see
      `THREAT_MODEL.md` T2).
- [ ] README updated if user-visible behavior or configuration changes.

## What we don't accept

This server is intentionally read-only. We will **not** merge:

- Tools that request write-scope permissions
  (e.g. `ThreatHunting.ReadWrite.All`).
- Device isolation, file remediation, or other response actions. These
  belong in a separate companion server with a stricter authorization
  model — see the README's *Scope & Design Philosophy*.
- Code that disables, weakens, or bypasses input validation (KQL length
  cap, forbidden-substring filter, Unicode stripping) without an
  equivalent replacement defense documented in `THREAT_MODEL.md`.

## Reporting security issues

Please do **not** open a public GitHub issue for security reports. See
[`SECURITY.md`](./SECURITY.md) for the disclosure process.
