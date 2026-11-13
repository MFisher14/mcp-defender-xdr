"""Input validation and sanitization for tool parameters."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from datetime import timedelta
from enum import StrEnum
from typing import Annotated, Self, TypeVar

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

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


# ---------- investigation tools (device / user / IOC pivots) ----------

#: Advanced Hunting retains 30 days; a wider window can only return less than asked.
MAX_INVESTIGATION_WINDOW = timedelta(days=30)
MAX_INVESTIGATION_ROWS = 1000
DEFAULT_INVESTIGATION_ROWS = 200

# Defender device IDs are 40-char hex SHA-1s; allow a little slack for other
# tenants' formats but never anything that could escape a KQL string literal.
DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")
# A deliberately conservative UPN shape. Apostrophes are allowed (o'brien@...);
# double quotes, backslashes, whitespace, and control characters are not.
UPN_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
SID_PATTERN = re.compile(r"^S-1-\d{1,14}(?:-\d{1,10}){1,15}$", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
URL_PATTERN = re.compile(r"^https?://[^\s\"\\<>]{1,2040}$", re.IGNORECASE)
HASH_PATTERNS: dict[str, re.Pattern[str]] = {
    "md5": re.compile(r"^[0-9a-fA-F]{32}$"),
    "sha1": re.compile(r"^[0-9a-fA-F]{40}$"),
    "sha256": re.compile(r"^[0-9a-fA-F]{64}$"),
}


class DeviceEventType(StrEnum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    REGISTRY = "registry"
    OTHER = "other"


class UserSignalType(StrEnum):
    SIGN_IN = "sign_in"
    MAILBOX = "mailbox"
    DEVICE = "device"


class IocType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"


class _TimeWindow(_TenantField):
    start: AwareDatetime
    end: AwareDatetime
    limit: Annotated[int, Field(ge=1, le=MAX_INVESTIGATION_ROWS)] = DEFAULT_INVESTIGATION_ROWS

    @model_validator(mode="after")
    def _check_window(self) -> Self:
        if self.end <= self.start:
            raise ValueError("end must be later than start")
        if self.end - self.start > MAX_INVESTIGATION_WINDOW:
            raise ValueError("time window must not exceed 30 days (Advanced Hunting retention)")
        return self


class DeviceTimelineInput(_TimeWindow):
    device_id: Annotated[str, Field(min_length=1, max_length=64)]
    event_types: Annotated[list[DeviceEventType], Field(min_length=1, max_length=5)] | None = None

    @field_validator("device_id")
    @classmethod
    def _validate_device_id(cls, value: str) -> str:
        if not DEVICE_ID_PATTERN.match(value):
            raise ValueError("device_id must contain only alphanumerics and dashes")
        return value.lower()


class InvestigateUserInput(_TimeWindow):
    account_upn: Annotated[str, Field(min_length=3, max_length=320)] | None = None
    account_sid: Annotated[str, Field(min_length=5, max_length=184)] | None = None
    signal_types: Annotated[list[UserSignalType], Field(min_length=1, max_length=3)] | None = None

    @field_validator("account_upn")
    @classmethod
    def _validate_upn(cls, value: str | None) -> str | None:
        if value is not None and not UPN_PATTERN.match(value):
            raise ValueError("account_upn must be a user principal name like user@example.com")
        return value.lower() if value is not None else None

    @field_validator("account_sid")
    @classmethod
    def _validate_sid(cls, value: str | None) -> str | None:
        if value is not None and not SID_PATTERN.match(value):
            raise ValueError("account_sid must be a Windows SID like S-1-5-21-...")
        return value.upper() if value is not None else None

    @model_validator(mode="after")
    def _exactly_one_identity(self) -> Self:
        if (self.account_upn is None) == (self.account_sid is None):
            raise ValueError("provide exactly one of account_upn or account_sid")
        return self

    @property
    def subject(self) -> str:
        value = self.account_upn or self.account_sid
        assert value is not None  # noqa: S101 - guaranteed by _exactly_one_identity
        return value


class ThreatIntelInput(_TenantField):
    ioc_type: IocType
    ioc_value: Annotated[str, Field(min_length=1, max_length=2048)]
    lookback_days: Annotated[int, Field(ge=1, le=30)] = 30
    limit: Annotated[int, Field(ge=1, le=MAX_INVESTIGATION_ROWS)] = 50

    @model_validator(mode="after")
    def _validate_ioc(self) -> Self:
        value = self.ioc_value
        if self.ioc_type is IocType.IP:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("ioc_value is not a valid IPv4 or IPv6 address") from exc
            self.ioc_value = address.compressed
        elif self.ioc_type is IocType.DOMAIN:
            domain = value.rstrip(".")
            if not DOMAIN_PATTERN.match(domain):
                raise ValueError("ioc_value is not a valid domain name")
            self.ioc_value = domain.lower()
        elif self.ioc_type is IocType.HASH:
            if self.hash_kind is None:
                raise ValueError("ioc_value must be an MD5, SHA-1, or SHA-256 hex digest")
            self.ioc_value = value.lower()
        elif not URL_PATTERN.match(value):
            raise ValueError("ioc_value must be an http(s) URL without spaces or quotes")
        return self

    @property
    def hash_kind(self) -> str | None:
        if self.ioc_type is not IocType.HASH:
            return None
        for kind, pattern in HASH_PATTERNS.items():
            if pattern.match(self.ioc_value):
                return kind
        return None


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
