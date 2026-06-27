# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.policy.tariff_profiles import (
    METER_OF_RECORD_BOUNDARY,
    TariffProfileError,
    TariffStatus,
    load_tariff_profile_data,
)


def _profile(overrides=None):
    data = {
        "profile": "ng-ikeja-operator-2026-06",
        "version": "2026-06-01",
        "status": TariffStatus.OPERATOR_PROVIDED,
        "country": "NG",
        "currency": "NGN",
        "disco": "Ikeja Electric",
        "effective_from": "2026-06-01",
        "effective_until": "",
        "import_tariff_per_kwh": 225.0,
        "export_credit_per_kwh": 40.0,
        "export_credit_formula": "operator_supplied_fixed_credit",
        "fixed_charges_per_month": 0.0,
        "interconnection_charges_per_kwh": 0.0,
        "source": {
            "type": "operator_estimate",
            "reference": "customer bill 2026-06",
            "retrieved_at": "2026-06-26",
        },
        "notes": "Operational estimate only.",
    }
    if overrides:
        data.update(overrides)
    return data


def test_loads_versioned_tariff_profile():
    profile = load_tariff_profile_data(_profile())

    assert profile.profile == "ng-ikeja-operator-2026-06"
    assert profile.version == "2026-06-01"
    assert profile.status == "operator_provided"
    assert profile.advisory_qualified is True
    assert profile.import_tariff_per_kwh == 225.0
    assert profile.export_credit_per_kwh == 40.0
    assert profile.export_credit_formula == "operator_supplied_fixed_credit"
    assert profile.source.reference == "customer bill 2026-06"
    assert profile.meter_of_record_boundary == METER_OF_RECORD_BOUNDARY


def test_draft_profile_is_not_advisory_qualified():
    profile = load_tariff_profile_data(_profile({"status": TariffStatus.DRAFT}))

    assert profile.advisory_qualified is False


def test_rejects_missing_source_reference():
    data = _profile({"source": {"type": "operator_estimate", "reference": ""}})

    with pytest.raises(TariffProfileError, match="reference"):
        load_tariff_profile_data(data)


def test_rejects_unknown_status():
    with pytest.raises(TariffProfileError, match="status"):
        load_tariff_profile_data(_profile({"status": "trusted_by_ai"}))


def test_rejects_negative_export_credit():
    with pytest.raises(TariffProfileError, match="export_credit_per_kwh"):
        load_tariff_profile_data(_profile({"export_credit_per_kwh": -1.0}))


def test_rejects_missing_import_tariff():
    data = _profile()
    data.pop("import_tariff_per_kwh")

    with pytest.raises(TariffProfileError, match="import_tariff_per_kwh"):
        load_tariff_profile_data(data)


def test_rejects_invalid_effective_date():
    with pytest.raises(TariffProfileError, match="YYYY-MM-DD"):
        load_tariff_profile_data(_profile({"effective_from": "June 2026"}))


def test_rejects_effective_until_before_effective_from():
    with pytest.raises(TariffProfileError, match="effective_until"):
        load_tariff_profile_data(
            _profile({"effective_from": "2026-06-01", "effective_until": "2026-05-31"})
        )
