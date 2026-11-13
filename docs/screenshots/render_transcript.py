"""Render a recorded `claude -p --output-format stream-json` transcript as a terminal-style HTML page.

Everything shown comes from the transcript: the prompt, each MCP tool call and
its arguments, the head of each tool result, and Claude's final answer.
Claude Code's internal ToolSearch (deferred tool loading) calls are omitted.
"""

from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

import markdown

SERVER = "mcp__defender-xdr__"
RESULT_LINES = 4

CSS = """
:root { --bg:#141413; --panel:#1f1e1d; --fg:#e8e6dc; --dim:#8a877d; --accent:#d97757;
        --green:#7fb069; --border:#3a3936; --code:#2a2927; }
* { box-sizing:border-box; }
body { margin:0; background:#0d0d0c; padding:28px; font-family:"SF Mono",Menlo,Monaco,Consolas,monospace; }
.win { width:1080px; background:var(--bg); border:1px solid var(--border); border-radius:12px;
       overflow:hidden; box-shadow:0 20px 60px rgba(0,0,0,.5); color:var(--fg); font-size:14px; line-height:1.55; }
.bar { background:var(--panel); padding:10px 14px; display:flex; align-items:center; gap:8px;
       border-bottom:1px solid var(--border); color:var(--dim); font-size:12.5px; }
.dot { width:12px; height:12px; border-radius:50%; display:inline-block; }
.title { flex:1; text-align:center; margin-right:52px; }
.body { padding:18px 22px 20px; }
.prompt { border:1px solid var(--border); border-radius:8px; padding:10px 14px; margin-bottom:16px; color:var(--fg); }
.prompt .gt { color:var(--dim); margin-right:8px; }
.step { margin:0 0 12px; }
.bullet { color:var(--green); margin-right:8px; }
.bullet.text { color:var(--fg); }
.tool { font-weight:600; }
.tool .srv { color:var(--accent); }
.args { color:var(--dim); font-weight:400; }
.result { color:var(--dim); margin:2px 0 0 22px; white-space:pre-wrap; word-break:break-all; font-size:12.5px; }
.result .corner { color:var(--dim); margin-right:6px; }
.answer { margin-left:22px; }
.answer p { margin:0 0 9px; }
.answer h2, .answer h3 { font-size:14px; margin:12px 0 6px; color:var(--accent); }
.answer strong { color:#fff; }
.answer code { background:var(--code); padding:1px 5px; border-radius:4px; font-size:12.5px; }
.answer ul, .answer ol { margin:0 0 9px; padding-left:22px; }
.answer li { margin:2px 0; }
.answer table { border-collapse:collapse; margin:4px 0 12px; font-size:12.5px; }
.answer th, .answer td { border:1px solid var(--border); padding:4px 9px; text-align:left; vertical-align:top; }
.answer th { color:var(--accent); background:var(--panel); }
.foot { border-top:1px solid var(--border); padding:8px 22px; color:var(--dim); font-size:11.5px;
        display:flex; justify-content:space-between; }
.badge { color:#e0b85a; }
"""


def _fmt_args(args: dict) -> str:
    parts = []
    for k, v in args.items():
        shown = json.dumps(v)
        if len(shown) > 70:
            shown = shown[:34] + "…" + shown[-30:]
        parts.append(f"{k}: {shown}")
    return ", ".join(parts)


def _result_head(content) -> str:
    text = (
        content
        if isinstance(content, str)
        else "".join(c.get("text", "") for c in content if isinstance(c, dict))
    )
    try:
        pretty = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except ValueError:
        pretty = text
    lines = pretty.splitlines()
    head = [ln if len(ln) <= 120 else ln[:117] + "…" for ln in lines[:RESULT_LINES]]
    more = len(lines) - RESULT_LINES
    if more > 0:
        head.append(f"… +{more} lines (ctrl+r to expand)")
    return "\n".join(head)


_LIST_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s")


def _list_spacing(text: str) -> str:
    """Python-Markdown needs a blank line before a list; terminals and CommonMark don't."""
    out: list[str] = []
    for line in text.splitlines():
        if _LIST_RE.match(line) and out and out[-1].strip() and not _LIST_RE.match(out[-1]):
            out.append("")
        out.append(line)
    return "\n".join(out)


def render(transcript: Path, prompt: str, title: str) -> str:
    steps: list[str] = []
    pending: dict[str, str] = {}
    for line in transcript.read_text().splitlines():
        event = json.loads(line)
        if event.get("type") == "assistant":
            for c in event["message"]["content"]:
                if c["type"] == "tool_use" and c["name"].startswith(SERVER):
                    tool = c["name"][len(SERVER) :]
                    pending[c["id"]] = (
                        '<div class="step"><span class="bullet">⏺</span>'
                        f'<span class="tool"><span class="srv">defender-xdr</span> - {tool} (MCP)'
                        f'<span class="args">({html.escape(_fmt_args(c["input"]))})</span></span>'
                    )
                elif c["type"] == "text" and c["text"].strip():
                    body = markdown.markdown(_list_spacing(c["text"]), extensions=["tables"])
                    steps.append(
                        '<div class="step" style="display:flex"><span class="bullet text">⏺</span>'
                        f'<div class="answer">{body}</div></div>'
                    )
        elif event.get("type") == "user":
            for c in event["message"]["content"]:
                if (
                    isinstance(c, dict)
                    and c.get("type") == "tool_result"
                    and c["tool_use_id"] in pending
                ):
                    head = html.escape(_result_head(c["content"]))
                    steps.append(
                        pending.pop(c["tool_use_id"])
                        + f'<div class="result"><span class="corner">⎿</span>{head}</div></div>'
                    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>{CSS}</style></head><body>
<div class="win">
  <div class="bar"><span class="dot" style="background:#ff5f57"></span><span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span>
    <span class="title">claude — {html.escape(title)}</span></div>
  <div class="body">
    <div class="prompt"><span class="gt">&gt;</span>{html.escape(prompt)}</div>
    {"".join(steps)}
  </div>
  <div class="foot"><span>Claude Code · MCP server <b>defender-xdr</b> (stdio)</span>
    <span class="badge">● offline fixture mode — synthetic data, not a live tenant</span></div>
</div></body></html>"""


if __name__ == "__main__":
    transcript, prompt, title, out = sys.argv[1:5]
    Path(out).write_text(render(Path(transcript), prompt, title), encoding="utf-8")
