"""Schema fragments and result shaping shared by the investigation tools."""

from __future__ import annotations

from typing import Any

from ..validation import DEFAULT_INVESTIGATION_ROWS, MAX_INVESTIGATION_ROWS

TENANT_SCHEMA: dict[str, Any] = {
    "tenant": {
        "type": "string",
        "description": (
            "Tenant key to query. Omit for the configured default tenant. "
            "Use '*' to fan out across every configured tenant."
        ),
        "pattern": r"^([A-Za-z0-9_-]{1,64}|\*)$",
    },
}

TIME_WINDOW_SCHEMA: dict[str, Any] = {
    "start": {
        "type": "string",
        "format": "date-time",
        "description": "Window start, ISO 8601 with timezone (e.g. '2026-08-31T00:00:00Z').",
    },
    "end": {
        "type": "string",
        "format": "date-time",
        "description": "Window end, ISO 8601 with timezone. At most 30 days after `start`.",
    },
    "limit": {
        "type": "integer",
        "minimum": 1,
        "maximum": MAX_INVESTIGATION_ROWS,
        "default": DEFAULT_INVESTIGATION_ROWS,
        "description": f"Maximum rows to return (1-{MAX_INVESTIGATION_ROWS}).",
    },
}


def compact_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop empty columns from each row.

    The timeline queries normalise several tables to one wide schema, so most
    rows are mostly empty strings. Stripping them keeps the payload the model
    reads small without losing any information.
    """
    return [{k: v for k, v in row.items() if v not in ("", None, [], {})} for row in rows]
