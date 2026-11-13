"""Per-tenant rolling-window quotas, enforced in-process before each upstream call.

Without these, a ``tenant: "*"`` fan-out trusts each tenant's upstream rate
limit to throttle naturally, so one noisy tenant (large data set, expensive
hunts) can dominate the latency budget for everyone else. A quota is a
server-side bound that fails *that tenant's* slot with ``quota_exceeded``
while its siblings carry on. See THREAT_MODEL.md, T6.

State is deliberately in-process (no external store): quotas reset on
restart, and two server processes do not share a budget.
"""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .audit import audit
from .errors import QuotaExceededError

DEFAULT_WINDOW_SECONDS = 60.0

#: Metadata keys tools use for "how many rows did this call return", in the
#: order they are consulted. A call with none of them counts as one row.
_ROW_COUNT_KEYS = ("row_count", "event_count", "alert_count", "count")


@dataclass(frozen=True)
class TenantQuota:
    """Limits for one tenant over a rolling window. ``None`` means unlimited."""

    requests_per_minute: int | None = None
    rows_per_minute: int | None = None
    window_seconds: float = DEFAULT_WINDOW_SECONDS

    @classmethod
    def from_config(cls, raw: Any, *, where: str) -> TenantQuota:
        """Parse a ``quota`` object from the tenants file.

        Raises ``ValueError`` with a message naming ``where`` on bad input; the
        caller wraps it in the config error type it uses.
        """
        if not isinstance(raw, dict):
            raise ValueError(f"{where}: quota must be an object")
        unknown = set(raw) - {"requests_per_minute", "rows_per_minute"}
        if unknown:
            raise ValueError(f"{where}: unknown quota field(s): {', '.join(sorted(unknown))}")
        values: dict[str, int | None] = {}
        for name in ("requests_per_minute", "rows_per_minute"):
            value = raw.get(name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 1
            ):
                raise ValueError(f"{where}: quota.{name} must be a positive integer")
            values[name] = value
        return cls(
            requests_per_minute=values["requests_per_minute"],
            rows_per_minute=values["rows_per_minute"],
        )

    @property
    def unlimited(self) -> bool:
        return self.requests_per_minute is None and self.rows_per_minute is None


@dataclass
class _Usage:
    requests: deque[float] = field(default_factory=deque)
    rows: deque[tuple[float, int]] = field(default_factory=deque)

    def prune(self, cutoff: float) -> None:
        while self.requests and self.requests[0] <= cutoff:
            self.requests.popleft()
        while self.rows and self.rows[0][0] <= cutoff:
            self.rows.popleft()

    @property
    def row_total(self) -> int:
        return sum(n for _, n in self.rows)


def rows_in(payload: Mapping[str, Any]) -> int:
    """Best-effort row count for a single-tenant tool payload."""
    metadata = payload.get("metadata")
    if isinstance(metadata, Mapping):
        for key in _ROW_COUNT_KEYS:
            value = metadata.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
    return 1


class QuotaTracker:
    """Admits or refuses calls per tenant and records what admitted calls returned.

    The tracker is shared by every tool call for the life of the server
    process. All access happens on the event loop between ``await`` points, so
    check-then-record needs no lock.
    """

    def __init__(
        self,
        quotas: Mapping[str, TenantQuota],
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._quotas = {k: q for k, q in quotas.items() if not q.unlimited}
        self._clock: Callable[[], float] = clock or time.monotonic
        self._usage: dict[str, _Usage] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._quotas)

    def admit(self, tenant_key: str, tool: str) -> None:
        """Reserve one request for ``tenant_key`` or raise :class:`QuotaExceededError`."""
        quota = self._quotas.get(tenant_key)
        if quota is None:
            return
        now = self._clock()
        usage = self._usage.setdefault(tenant_key, _Usage())
        usage.prune(now - quota.window_seconds)

        reason: str | None = None
        oldest: float | None = None
        if quota.requests_per_minute is not None and (
            len(usage.requests) >= quota.requests_per_minute
        ):
            reason = "requests_per_minute"
            oldest = usage.requests[0]
        elif quota.rows_per_minute is not None and usage.row_total >= quota.rows_per_minute:
            reason = "rows_per_minute"
            oldest = usage.rows[0][0]

        fields = {
            "tool": tool,
            "tenant": tenant_key,
            "requests_in_window": len(usage.requests),
            "rows_in_window": usage.row_total,
            "requests_per_minute": quota.requests_per_minute,
            "rows_per_minute": quota.rows_per_minute,
        }
        if reason is not None and oldest is not None:
            retry_after = max(1, math.ceil(oldest + quota.window_seconds - now))
            audit("quota-decision", decision="denied", reason=reason, **fields)
            raise QuotaExceededError(
                f"Tenant quota exceeded ({reason.replace('_', ' ')}); "
                f"retry in about {retry_after}s.",
                retry_after_seconds=retry_after,
            )
        usage.requests.append(now)
        audit("quota-decision", decision="allowed", **fields)

    def record_rows(self, tenant_key: str, rows: int) -> None:
        """Charge ``rows`` returned by an admitted call against the tenant's budget."""
        quota = self._quotas.get(tenant_key)
        if quota is None or quota.rows_per_minute is None or rows <= 0:
            return
        self._usage.setdefault(tenant_key, _Usage()).rows.append((self._clock(), rows))
