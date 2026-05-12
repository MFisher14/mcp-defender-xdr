"""MCP server entry point."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from collections.abc import Awaitable, Callable
from typing import Any

import mcp.types as mcp_types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import __version__
from .audit import audit, audit_error
from .auth import TokenManager, build_default_token_manager
from .errors import DefenderError, ErrorCode
from .tool_context import ToolContext
from .tools import advanced_hunting, alerts, incidents

ServerName = "mcp-defender-xdr"

_log = logging.getLogger("mcp_defender_xdr.server")

ToolHandler = Callable[[ToolContext, dict[str, Any]], Awaitable[dict[str, Any]]]


def _tool_definitions() -> list[mcp_types.Tool]:
    return [
        mcp_types.Tool(
            name=advanced_hunting.TOOL_NAME,
            description=advanced_hunting.TOOL_DESCRIPTION,
            inputSchema=advanced_hunting.INPUT_SCHEMA,
        ),
        mcp_types.Tool(
            name=incidents.TOOL_NAME,
            description=incidents.TOOL_DESCRIPTION,
            inputSchema=incidents.INPUT_SCHEMA,
        ),
        mcp_types.Tool(
            name=alerts.TOOL_NAME,
            description=alerts.TOOL_DESCRIPTION,
            inputSchema=alerts.INPUT_SCHEMA,
        ),
    ]


_HANDLERS: dict[str, ToolHandler] = {
    advanced_hunting.TOOL_NAME: advanced_hunting.run,
    incidents.TOOL_NAME: incidents.run,
    alerts.TOOL_NAME: alerts.run,
}


def _error_result(code: ErrorCode, message: str) -> mcp_types.CallToolResult:
    payload: dict[str, Any] = {"error": {"code": code.value, "message": message}}
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=json.dumps(payload))],
        structuredContent=payload,
        isError=True,
    )


def _success_result(data: dict[str, Any]) -> mcp_types.CallToolResult:
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=json.dumps(data, default=str))],
        structuredContent=data,
        isError=False,
    )


async def _dispatch(
    handler: ToolHandler,
    ctx: ToolContext,
    arguments: dict[str, Any],
    tool_name: str,
) -> mcp_types.CallToolResult:
    try:
        data = await handler(ctx, arguments)
    except DefenderError as exc:
        audit_error(
            "tool-error-mapped",
            tool=tool_name,
            error_code=exc.code.value,
            error_class=exc.__class__.__name__,
        )
        return _error_result(exc.code, exc.public_message)
    except Exception as exc:
        audit_error(
            "tool-error-unhandled",
            tool=tool_name,
            error_class=exc.__class__.__name__,
        )
        return _error_result(
            ErrorCode.INTERNAL_ERROR,
            "An internal error occurred; check server logs for details.",
        )
    return _success_result(data)


def build_server(token_manager: TokenManager) -> Server:
    server: Server = Server(ServerName, version=__version__)

    @server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
    async def _list_tools() -> list[mcp_types.Tool]:
        return _tool_definitions()

    @server.call_tool()  # type: ignore[untyped-decorator]
    async def _call_tool(name: str, arguments: dict[str, Any]) -> mcp_types.CallToolResult:
        handler = _HANDLERS.get(name)
        if handler is None:
            audit_error("tool-unknown", tool=name)
            return _error_result(ErrorCode.INVALID_INPUT, f"Unknown tool: {name}")
        async with ToolContext(token_manager) as ctx:
            return await _dispatch(handler, ctx, arguments, name)

    return server


async def _async_main() -> None:
    audit("server-starting", version=__version__)
    try:
        token_manager = build_default_token_manager()
    except DefenderError as exc:
        audit_error("server-startup-failed", error_class=exc.__class__.__name__)
        print(f"mcp-defender-xdr: {exc}", file=sys.stderr)
        sys.exit(2)

    server = build_server(token_manager)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        audit("server-interrupted")
    except SystemExit:
        raise
    except Exception as exc:
        audit_error("server-crashed", error_class=exc.__class__.__name__)
        raise


if __name__ == "__main__":
    main()
