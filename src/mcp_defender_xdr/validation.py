"""Input validation and sanitization for tool parameters."""

from __future__ import annotations

import re
import unicodedata
from enum import StrEnum
from typing import Annotated, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import InvalidInputError

T = TypeVar("T", bound=BaseModel)

MAX_KQL_LENGTH = 10_000
DEFAULT_TIMESPAN = "P1D"
INCIDENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TENANT_KEY_PATTERN = re.compile(r"^([A-Za-z0-9_-]{1,64}|\*)$")
FAN_OUT_TENANT = "*"
ISO8601_DURATION_PATTERN = re.compile(
    r"^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$"
)

_KQL_FORBIDDEN_SUBSTRINGS = (
    ".external_table(",
    ".create-or-alter",
    ".alter",
    ".drop",
    ".set-or-append",
    ".ingest",
)


class Severity(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class AlertStatus(StrEnum):
    NEW = "New"
    IN_PROGRESS = "InProgress"
    RESOLVED = "Resolved"


def _strip_control_chars(value: str) -> str:
    return "".join(
        ch for ch in value if ch == "\n" or ch == "\t" or unicodedata.category(ch)[0] != "C"
    )


def _validate_tenant_value(value: str | None) -> str | None:
    if value is None:
        return None
    if not TENANT_KEY_PATTERN.match(value):
        raise ValueError("tenant must match [A-Za-z0-9_-]{1,64} or be '*' for fan-out")
    return value


class _TenantField(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    tenant: str | None = None

    @field_validator("tenant")
    @classmethod
    def _check_tenant(cls, value: str | None) -> str | None:
        return _validate_tenant_value(value)


class AdvancedHuntingInput(_TenantField):
    query: Annotated[str, Field(min_length=1, max_length=MAX_KQL_LENGTH)]
    timespan: Annotated[str, Field(min_length=2, max_length=32)] = DEFAULT_TIMESPAN

    @field_validator("query")
    @classmethod
    def _validate_query(cls, value: str) -> str:
        cleaned = _strip_control_chars(value)
        if not cleaned.strip():
            raise ValueError("KQL query must contain non-whitespace characters")
        lowered = cleaned.lower()
        for forbidden in _KQL_FORBIDDEN_SUBSTRINGS:
            if forbidden in lowered:
                raise ValueError(
                    f"KQL query contains a disallowed control verb ({forbidden!r}); "
                    "only read-only Advanced Hunting queries are supported."
                )
        return cleaned

    @field_validator("timespan")
    @classmethod
    def _validate_timespan(cls, value: str) -> str:
        if not ISO8601_DURATION_PATTERN.match(value):
            raise ValueError("timespan must be an ISO 8601 duration (e.g., 'P1D', 'PT4H', 'P7D')")
        return value


class IncidentInput(_TenantField):
    incident_id: Annotated[str, Field(min_length=1, max_length=64)]

    @field_validator("incident_id")
    @classmethod
    def _validate_incident_id(cls, value: str) -> str:
        if not INCIDENT_ID_PATTERN.match(value):
            raise ValueError("incident_id must contain only alphanumerics, dashes, and underscores")
        return value


class AlertsInput(_TenantField):
    severity: Severity | None = None
    status: AlertStatus | None = None
    limit: Annotated[int, Field(ge=1, le=100)] = 25


def parse_input(model: type[T], raw: dict[str, object]) -> T:
    try:
        return model.model_validate(raw)
    except Exception as exc:
        raise InvalidInputError(_format_validation_error(exc)) from exc


def _format_validation_error(exc: BaseException) -> str:
    errors_method = getattr(exc, "errors", None)
    if callable(errors_method):
        try:
            error_list = errors_method()
        except Exception:
            return "Invalid input"
        parts: list[str] = []
        for err in error_list:
            loc = ".".join(str(p) for p in err.get("loc", ())) or "<root>"
            msg = err.get("msg", "invalid value")
            parts.append(f"{loc}: {msg}")
        return "; ".join(parts) or "Invalid input"
    return "Invalid input"
