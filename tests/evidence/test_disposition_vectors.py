# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime held to the disposition corpus, `evidence-disposition-v2.json`.

Two parts of the corpus are the runtime's to reproduce. `reoffer_schedule`
fixes when an unconfirmed registration is re-offered and when it is overdue,
and is driven here through the real ledger, restarts included. `wire_cases`
fix a disposition's canonical bytes, which the runtime's canonical form must
reproduce before any verifier can check a signature over them. The
`mapping_cases` and `rollback_sequences` are the authority's emission rules
and are not driven here; `runtime_sequences` are covered case by case in
`test_registration_disposition.py`.
"""

from __future__ import annotations

import base64
import json
import pathlib
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ori.security.evidence import first_party
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.registration import reoffer_due

from .test_registration_obligation import (
    REFERENCE,
    Clock,
    Device,
    _health,
    _retire_copy,
)

VECTOR = json.loads(
    (
        pathlib.Path(__file__).resolve().parent.parent
        / "vectors"
        / "evidence_exchange"
        / "evidence-disposition-v2.json"
    ).read_text()
)
SCHEDULE = VECTOR["reoffer_schedule"]
T0 = 1_787_000_000_000


def _ms(seconds: int) -> int:
    return int(seconds) * 1000


def _ids(cases: list[dict[str, Any]]) -> list[str]:
    return [c["name"] for c in cases]


# --------------------------------------------------------------------------
# The schedule as a pure function
# --------------------------------------------------------------------------


@pytest.mark.parametrize("attempt, delay_s", list(enumerate(SCHEDULE["delays_s"], 1)))
def test_the_delay_before_each_reoffer_is_the_contracts(attempt, delay_s) -> None:
    """Re-offer N is due exactly `delays_s[N-1]` seconds after the previous offer."""
    assert reoffer_due(attempt - 1, 0, at_ms=_ms(delay_s) - 1) is False
    assert reoffer_due(attempt - 1, 0, at_ms=_ms(delay_s)) is True


@pytest.mark.parametrize("case", SCHEDULE["due_cases"], ids=_ids(SCHEDULE["due_cases"]))
def test_due_cases(case) -> None:
    due = reoffer_due(case["attempt"] - 1, 0, at_ms=_ms(case["since_previous_offer_s"]))
    assert due is case["expected_due"]


# --------------------------------------------------------------------------
# The schedule through the ledger: attempted offers, restarts, the bound
# --------------------------------------------------------------------------


@pytest.fixture
async def device(tmp_path):
    d = Device(tmp_path)
    await d.start()
    try:
        yield d
    finally:
        if d.attestor is not None:
            d.attestor.close()


async def _seal_at(device: Device, at_ms: int) -> Any:
    assert device.attestor is not None
    with patch.object(first_party, "now_ms", return_value=at_ms):
        await device.attestor.reconcile_registration(REFERENCE)
    [row] = device.obligations()
    assert int(row["sealed_at_ms"]) == at_ms
    return row


async def _attempted_offer(
    device: Device, at_ms: int, digest: str, first: bool
) -> None:
    """One attempted offer of the sealed bytes, as the drain records it.

    The first is the courier copy's handoff, acknowledged `queued`; each later
    one is a re-offer from the obligation.
    """
    attestor = device.attestor
    assert attestor is not None and attestor.outbound is not None
    if first:
        await _retire_copy(attestor, Clock(at_ms), digest)
    else:
        await attestor.outbound.note_registration_offer(digest, at_ms=at_ms)


async def _restart(device: Device) -> None:
    device.restart_close()
    await device.start()


def _reoffer_due_at(device: Device, at_ms: int) -> bool:
    attestor = device.attestor
    assert attestor is not None and attestor._ledger is not None
    ledger = attestor._ledger
    rows = attestor._executor.run(
        lambda: ledger.registration_reoffers_due(at_ms=at_ms, limit=1)
    )
    return bool(rows)


@pytest.mark.parametrize(
    "case", SCHEDULE["anchor_cases"], ids=_ids(SCHEDULE["anchor_cases"])
)
async def test_anchor_cases(device, case) -> None:
    """The delay runs from the previous attempted offer, never from sealing."""
    row = await _seal_at(device, T0 + _ms(case["sealed_s"]))
    for index, offered_s in enumerate(case["attempted_offers_s"]):
        await _attempted_offer(
            device, T0 + _ms(offered_s), row["artifact_digest"], first=index == 0
        )
    if "restart_s" in case:
        await _restart(device)
    assert _reoffer_due_at(device, T0 + _ms(case["now_s"])) is case["expected_due"]


@pytest.mark.parametrize(
    "case", SCHEDULE["restart_cases"], ids=_ids(SCHEDULE["restart_cases"])
)
async def test_restart_cases(device, case) -> None:
    """A restart measures from the persisted offer and never extends the ceiling."""
    row = await _seal_at(device, T0 - 1)
    previous = T0 + _ms(case["previous_offer_s"])
    for index in range(case["attempt"] - 1):
        await _attempted_offer(
            device, previous, row["artifact_digest"], first=index == 0
        )
    assert int(device.obligations()[0]["offers"]) == case["attempt"] - 2
    await _restart(device)
    assert _reoffer_due_at(device, T0 + _ms(case["now_s"])) is case["expected_due"]


async def test_a_restart_does_not_bring_a_reoffer_forward(device) -> None:
    """The corpus restart cases all expect `due`, so a reset schedule passes them.

    A runtime that forgot its offers on restart would re-offer at once; this
    holds the persisted count and time from the other side of the bound.
    """
    row = await _seal_at(device, T0 - 1)
    for index in range(8):
        await _attempted_offer(device, T0, row["artifact_digest"], first=index == 0)
    await _restart(device)
    assert _reoffer_due_at(device, T0 + _ms(3599)) is False
    assert _reoffer_due_at(device, T0 + _ms(3600)) is True
    assert int(device.obligations()[0]["offers"]) == 7


@pytest.mark.parametrize(
    "case", SCHEDULE["overdue_cases"], ids=_ids(SCHEDULE["overdue_cases"])
)
async def test_overdue_cases(device, case) -> None:
    """Overdue once the bound has elapsed since sealing, across restarts."""
    await _seal_at(device, T0 + _ms(case["pending_since_s"]))
    # The corpus gives restart times; only their number matters to a wall-clock
    # measure, and each restart reopens the same persisted obligation.
    for _ in range(len(case["restarts_at_s"])):
        await _restart(device)
    assert device.attestor is not None
    fields = await _health(device.attestor, T0 + _ms(case["now_s"]))
    assert fields["registration_status"] == "pending_confirmation"
    assert fields["registration_pending_since_ms"] == T0 + _ms(case["pending_since_s"])
    assert fields["registration_confirmation_overdue"] is case["expected_overdue"]


# --------------------------------------------------------------------------
# A disposition's bytes
# --------------------------------------------------------------------------


@pytest.mark.parametrize("case", VECTOR["wire_cases"], ids=_ids(VECTOR["wire_cases"]))
def test_the_runtime_canonical_form_reproduces_each_dispositions_bytes(case) -> None:
    unsigned = {k: v for k, v in case["artifact"].items() if k != "signature"}
    assert canonical_json(unsigned).hex() == case["canonical_hex"]


@pytest.mark.parametrize(
    "case",
    [c for c in VECTOR["wire_cases"] if c["expected"] == "accept"],
    ids=_ids([c for c in VECTOR["wire_cases"] if c["expected"] == "accept"]),
)
def test_each_accepted_dispositions_signature_covers_those_bytes(case) -> None:
    """The published key signs the runtime's bytes under the published domain."""
    entry = VECTOR["registry"][case["artifact"]["key_id"]]
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key_hex"]))
    scheme, encoded = case["artifact"]["signature"].split(":", 1)
    assert scheme == "ed25519"
    unsigned = {k: v for k, v in case["artifact"].items() if k != "signature"}
    public.verify(
        base64.b64decode(encoded, validate=True),
        VECTOR["domain_ascii"].encode("ascii") + b"\x00" + canonical_json(unsigned),
    )
