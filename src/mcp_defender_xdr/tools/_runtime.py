"""Shared runtime helpers for tool implementations."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from ..audit import audit, audit_error, audit_warning
from ..defender_client import DefenderApi
from ..errors import DefenderError, ErrorCode, InvalidInputError
from ..fixtures import FIXTURE_AUDIT_EVENT, SYNTHETIC_NOTICE, mark_result
from ..quota import rows_in
from ..tool_context import API_DEFENDER, ToolContext
from ..validation import FAN_OUT_TENANT

TenantCall = Callable[[DefenderApi], Awaitable[dict[str, Any]]]


def resolve_targets(ctx: ToolContext, tenant: str | None) -> list[str]:
    if tenant is None:
        return [ctx.default_tenant_key]
    if tenant == FAN_OUT_TENANT:
        tenants = ctx.available_tenants()
        if not tenants:
            raise InvalidInputError("Fan-out requested but no tenants are configured")
        return tenants
    available = set(ctx.available_tenants())
    if tenant not in available:
        raise InvalidInputError("Unknown tenant")
    return [tenant]


async def dispatch(
    ctx: ToolContext,
    tool_name: str,
    targets: list[str],
    call: TenantCall,
    *,
    api: str = API_DEFENDER,
) -> dict[str, Any]:
    if ctx.fixture_mode:
        # Loud, WARNING-level, on every single tool call — never a startup-only
        # banner that scrolls away before the calls a reviewer actually reads.
        audit_warning(
            FIXTURE_AUDIT_EVENT,
            tool=tool_name,
            fixture_mode=True,
            tenants=targets,
            notice=SYNTHETIC_NOTICE,
        )

    async def _metered(tenant_key: str) -> dict[str, Any]:
        """Run one tenant's call inside its quota (when quotas are configured)."""
        quotas = ctx.quotas
        if quotas is not None:
            quotas.admit(tenant_key, tool_name)
        payload = await call(ctx.client_for(tenant_key, api))
        if quotas is not None:
            quotas.record_rows(tenant_key, rows_in(payload))
        return payload

    if len(targets) == 1:
        single = await _metered(targets[0])
        return mark_result(single) if ctx.fixture_mode else single

    semaphore = asyncio.Semaphore(ctx.max_fan_out)

    async def _one(tenant_key: str) -> dict[str, Any]:
        async with semaphore:
            try:
                payload = await _metered(tenant_key)
            except DefenderError as exc:
                audit_error(
                    "fan-out-tenant-failed",
                    tool=tool_name,
                    tenant=tenant_key,
                    error_code=exc.code.value,
                    error_class=exc.__class__.__name__,
                )
                return {
                    "tenant": tenant_key,
                    "error": {"code": exc.code.value, "message": exc.public_message},
                }
            except Exception as exc:
                audit_error(
                    "fan-out-tenant-unhandled",
                    tool=tool_name,
                    tenant=tenant_key,
                    error_class=exc.__class__.__name__,
                )
                return {
                    "tenant": tenant_key,
                    "error": {
                        "code": ErrorCode.INTERNAL_ERROR.value,
                        "message": "An internal error occurred for this tenant.",
                    },
                }
            audit(
                "fan-out-tenant-succeeded",
                tool=tool_name,
                tenant=tenant_key,
            )
            return {"tenant": tenant_key, "result": payload}

    results = await asyncio.gather(*(_one(t) for t in targets))
    envelope: dict[str, Any] = {
        "fan_out": True,
        "tenants": targets,
        "results": results,
    }
    return mark_result(envelope) if ctx.fixture_mode else envelope
