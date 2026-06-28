# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.policy.prosumer_ledger import (
    PROSUMER_METER_OF_RECORD_BOUNDARY,
    ProsumerLedgerError,
    bounded_fast_loop_interval,
    kwh_from_watts,
    load_settlement_statement_data,
)


def _statement(overrides=None):
    data = {
        "statement_id": "ikeja-2026-06",
        "disco": "Ikeja Electric",
        "period_start": "2026-06-01",
        "period_end": "2026-06-30",
        "import_kwh": 120.5,
        "export_kwh": 18.25,
        "import_value": 27112.5,
        "export_credit_value": 730.0,
        "net_value": 26382.5,
        "currency": "NGN",
        "source": {
            "type": "disco_statement",
            "reference": "statement PDF sha256:abc123",
            "retrieved_at": "2026-07-01",
        },
        "notes": "Monthly statement uploaded by operator.",
    }
    if overrides:
        data.update(overrides)
    return data


def test_bounded_fast_loop_interval_first_sample_is_not_usable():
    interval = bounded_fast_loop_interval(None, 1_000_000, max_interval_seconds=900.0)

    assert interval.hours == 0.0
    assert interval.interval_ms == 0
    assert interval.usable is False
    assert interval.reason == "first_sample"


def test_bounded_fast_loop_interval_caps_long_gaps():
    interval = bounded_fast_loop_interval(
        1_000_000, 4_900_000, max_interval_seconds=900.0
    )

    assert interval.interval_ms == 900_000
    assert interval.hours == 0.25
    assert interval.capped is True
    assert interval.usable is True
    assert interval.reason == "capped"


def test_bounded_fast_loop_interval_rejects_backward_clock():
    interval = bounded_fast_loop_interval(
        1_000_000, 999_999, max_interval_seconds=900.0
    )

    assert interval.hours == 0.0
    assert interval.usable is False
    assert interval.reason == "non_monotonic_timestamp"


def test_kwh_from_watts_clamps_negative_inputs():
    assert kwh_from_watts(1000.0, 0.5) == 0.5
    assert kwh_from_watts(-1000.0, 0.5) == 0.0
    assert kwh_from_watts(1000.0, -0.5) == 0.0


def test_loads_settlement_statement():
    statement = load_settlement_statement_data(_statement())

    assert statement.statement_id == "ikeja-2026-06"
    assert statement.disco == "Ikeja Electric"
    assert statement.import_kwh == 120.5
    assert statement.export_kwh == 18.25
    assert statement.net_value == 26382.5
    assert statement.source.source_type == "disco_statement"
    assert statement.meter_of_record_boundary == PROSUMER_METER_OF_RECORD_BOUNDARY


def test_rejects_invalid_settlement_source():
    with pytest.raises(ProsumerLedgerError, match="source.type"):
        load_settlement_statement_data(
            _statement({"source": {"type": "whatsapp_guess", "reference": "x"}})
        )


def test_rejects_settlement_period_end_before_start():
    with pytest.raises(ProsumerLedgerError, match="period_end"):
        load_settlement_statement_data(
            _statement({"period_start": "2026-06-30", "period_end": "2026-06-01"})
        )


def test_rejects_negative_settlement_import_kwh():
    with pytest.raises(ProsumerLedgerError, match="import_kwh"):
        load_settlement_statement_data(_statement({"import_kwh": -1.0}))
