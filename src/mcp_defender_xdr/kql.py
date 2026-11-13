"""Helpers for building server-side KQL from validated tool inputs.

The purpose-built investigation tools (``get_device_timeline``,
``investigate_user``, ``query_threat_intelligence``) never splice caller input
into KQL as raw text. Every value is validated against a strict pattern in
:mod:`.validation` first, and is then emitted through :func:`string_literal` /
:func:`datetime_literal` here — belt and braces, so a future loosening of a
validator cannot by itself turn into KQL injection.
"""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime, timedelta

#: First line of every server-built query. Identifies which tool built the
#: query (useful when reading the audit log) and lets offline fixture mode
#: route the request to the right recorded result set. ``subject`` is always a
#: validated value with no whitespace or control characters.
_TAG_PREFIX = "// mcp-defender-xdr:"
TAG_RE = re.compile(
    r"^// mcp-defender-xdr:(?P<view>[a-z_]+(?:/[a-z_]+)?) subject=(?P<subject>\S{1,2048})$"
)

#: Advanced Hunting retains 30 days of data; asking for more is never useful.
MAX_LOOKBACK_DAYS = 30


def string_literal(value: str) -> str:
    """Render ``value`` as a double-quoted KQL string literal.

    KQL string literals use backslash escapes, so backslash and double quote
    are escaped; newlines and other control characters are rejected because
    no validated input should ever contain them.
    """
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError("KQL string literal must not contain control characters")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def datetime_literal(value: datetime) -> str:
    """Render a timezone-aware datetime as a KQL ``datetime(...)`` literal in UTC."""
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    utc = value.astimezone(UTC)
    return f"datetime({utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"


def query_tag(view: str, subject: str) -> str:
    """Build the identifying first line for a server-built query."""
    line = f"{_TAG_PREFIX}{view} subject={subject}"
    if not TAG_RE.match(line):
        raise ValueError("query tag is malformed")
    return line


def lookback_timespan(start: datetime, *, now: datetime | None = None) -> str:
    """ISO 8601 duration reaching back from ``now`` to cover ``start``.

    The Advanced Hunting API scopes a query by a duration relative to now, so
    a window that starts N days ago needs a timespan of at least N days, even
    though the query also filters on the explicit window.
    """
    current = now or datetime.now(UTC)
    days = math.ceil((current - start) / timedelta(days=1))
    return f"P{min(max(days, 1), MAX_LOOKBACK_DAYS)}D"
