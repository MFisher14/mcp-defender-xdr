# README screenshots

Each image is a **real Claude Code session** run against `mcp-defender-xdr` in
[offline fixture mode](../../examples/README.md), then re-rendered from its
transcript as a terminal-style page. Every prompt, tool call, argument, tool
result, and answer shown comes from the recorded session. Nothing was edited.
Two things are left out: Claude Code's internal `ToolSearch` step, which loads
the deferred MCP tool schemas, and the full tool results, which are shown
truncated the way the terminal shows them. All data is synthetic.

## Regenerating

```bash
# 1. MCP config pointing at this checkout, in fixture mode.
cat > /tmp/mcp.json <<JSON
{"mcpServers":{"defender-xdr":{"command":"$PWD/.venv/bin/mcp-defender-xdr",
  "env":{"MCP_DEFENDER_XDR_FIXTURE_MODE":"synthetic-fixtures-no-live-data"}}}}
JSON

# 2. Record a session (repeat per prompt below).
claude -p "<prompt> Keep the final answer concise." \
  --mcp-config /tmp/mcp.json --strict-mcp-config --allowedTools "mcp__defender-xdr" \
  --output-format stream-json --verbose < /dev/null > session.jsonl

# 3. Render, screenshot at 2x with headless Chrome, and trim.
pip install markdown pillow
python docs/screenshots/render_transcript.py session.jsonl "<prompt> Keep the final answer concise." "<title>" session.html
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --hide-scrollbars \
  --force-device-scale-factor=2 --window-size=1140,2600 --screenshot=raw.png "file://$PWD/session.html"
python docs/screenshots/trim.py raw.png out.png
```

| Image | Prompt |
| ----- | ------ |
| `triage-incident.png` | Triage time. List the High severity alerts that are still New, then pull the incident they belong to (INC-4471) and give me a short summary of what happened and which entities are involved. |
| `device-timeline.png` | Incident INC-4471 names device fixture0000000000000000000000000000a014. Pull its timeline for 2026-08-31 between 00:00 and 06:00 UTC and walk me through the attack chain step by step. |
| `threat-intelligence.png` | Check these indicators against Defender: the SHA-256 0000000000000000000000000000000000000000000000000000000000000001, the domain updates.fixture.example.com, and the IP 203.0.113.250. Which are known, and how bad is each? |
| `sentinel-hunting.png` | What hunting queries do we have saved in Sentinel? Run the beaconing one and tell me what it found. |

Model output varies between runs, so a regenerated image won't match exactly.
