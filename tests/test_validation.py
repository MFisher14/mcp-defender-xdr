"""Tests for input validation."""

from __future__ import annotations

import pytest

from mcp_defender_xdr.errors import InvalidInputError
from mcp_defender_xdr.validation import (
    AdvancedHuntingInput,
    AlertsInput,
    AlertStatus,
    IncidentInput,
    Severity,
    parse_input,
)


class TestAdvancedHuntingInput:
    def test_accepts_simple_query(self) -> None:
        model = parse_input(AdvancedHuntingInput, {"query": "DeviceProcessEvents | take 10"})
        assert isinstance(model, AdvancedHuntingInput)
        assert model.query == "DeviceProcessEvents | take 10"
        assert model.timespan == "P1D"

    def test_rejects_empty_query(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(AdvancedHuntingInput, {"query": "   "})

    def test_rejects_oversized_query(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(AdvancedHuntingInput, {"query": "x" * 10_001})

    @pytest.mark.parametrize(
        "forbidden",
        [
            "let x = 1; .drop table foo",
            "DeviceEvents | .ingest into bar",
            "print .external_table(blah)",
            ".alter table widgets",
        ],
    )
    def test_rejects_destructive_kql_verbs(self, forbidden: str) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(AdvancedHuntingInput, {"query": forbidden})

    def test_rejects_bad_timespan(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(
                AdvancedHuntingInput,
                {"query": "DeviceEvents | take 1", "timespan": "yesterday"},
            )

    @pytest.mark.parametrize("ts", ["P1D", "PT4H", "P7D", "PT30M", "P1DT4H"])
    def test_accepts_valid_iso8601_durations(self, ts: str) -> None:
        model = parse_input(
            AdvancedHuntingInput, {"query": "DeviceEvents | take 1", "timespan": ts}
        )
        assert isinstance(model, AdvancedHuntingInput)
        assert model.timespan == ts

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(
                AdvancedHuntingInput,
                {"query": "DeviceEvents | take 1", "drop_table": "users"},
            )

    def test_strips_control_chars(self) -> None:
        raw = "DeviceEvents \x07 | take 1"
        model = parse_input(AdvancedHuntingInput, {"query": raw})
        assert isinstance(model, AdvancedHuntingInput)
        assert "\x07" not in model.query
        assert "DeviceEvents" in model.query


class TestIncidentInput:
    def test_accepts_alphanumeric_id(self) -> None:
        model = parse_input(IncidentInput, {"incident_id": "abc_123-XYZ"})
        assert isinstance(model, IncidentInput)
        assert model.incident_id == "abc_123-XYZ"

    @pytest.mark.parametrize(
        "bad_id",
        [
            "",
            "id with spaces",
            "id/with/slashes",
            "../../etc/passwd",
            "x" * 65,
            "id'; DROP TABLE",
        ],
    )
    def test_rejects_malformed_ids(self, bad_id: str) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(IncidentInput, {"incident_id": bad_id})


class TestAlertsInput:
    def test_defaults(self) -> None:
        model = parse_input(AlertsInput, {})
        assert isinstance(model, AlertsInput)
        assert model.severity is None
        assert model.status is None
        assert model.limit == 25

    def test_accepts_enum_values(self) -> None:
        model = parse_input(AlertsInput, {"severity": "High", "status": "New", "limit": 50})
        assert isinstance(model, AlertsInput)
        assert model.severity is Severity.HIGH
        assert model.status is AlertStatus.NEW
        assert model.limit == 50

    @pytest.mark.parametrize("limit", [0, -1, 101, 1000])
    def test_rejects_out_of_range_limit(self, limit: int) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(AlertsInput, {"limit": limit})

    def test_rejects_unknown_severity(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(AlertsInput, {"severity": "Critical"})

    def test_rejects_unknown_status(self) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(AlertsInput, {"status": "Closed"})


class TestTenantField:
    """The shared optional ``tenant`` parameter on every input model."""

    @pytest.mark.parametrize(
        "model, base",
        [
            (AdvancedHuntingInput, {"query": "DeviceEvents | take 1"}),
            (IncidentInput, {"incident_id": "INC-1"}),
            (AlertsInput, {}),
        ],
    )
    def test_tenant_omitted_defaults_to_none(self, model, base) -> None:
        parsed = parse_input(model, dict(base))
        assert parsed.tenant is None

    @pytest.mark.parametrize(
        "model, base",
        [
            (AdvancedHuntingInput, {"query": "DeviceEvents | take 1"}),
            (IncidentInput, {"incident_id": "INC-1"}),
            (AlertsInput, {}),
        ],
    )
    def test_tenant_accepts_valid_keys(self, model, base) -> None:
        for key in ("contoso", "tenant-1", "TENANT_2", "*"):
            parsed = parse_input(model, {**base, "tenant": key})
            assert parsed.tenant == key

    @pytest.mark.parametrize(
        "bad",
        [
            "tenant with spaces",
            "tenant/with/slashes",
            "tenant!exclaim",
            "x" * 65,
            "**",
            "",
        ],
    )
    def test_tenant_rejects_malformed(self, bad: str) -> None:
        with pytest.raises(InvalidInputError):
            parse_input(
                AdvancedHuntingInput,
                {"query": "DeviceEvents | take 1", "tenant": bad},
            )
