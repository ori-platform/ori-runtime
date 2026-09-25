# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Evidence dispositions at the runtime, per `evidence-exchange/v1`.

The wire verifier is not yet shipped, so these drive the seam it drops into:
`accept_disposition`, fed a `VerifiedDisposition` that steps 1 to 3 would
produce. Steps 4 to 6 and every effect are the runtime's own and are what is
tested. Dispositions are bound as the contract emits them: identity scope from
a checkpoint or an envelope, artifact scope from any sealed artifact, and
`retained_pending` only from an anchor registration.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from dataclasses import replace
from typing import Any
from unittest.mock import patch

import pytest

from ori.security.evidence.disposition import (
    DispositionScope,
    DispositionValue,
    VerifiedDisposition,
)
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.evidence.ledger import DispositionRefusedError
from ori.security.evidence.registration import (
    CONFIRMATION_OVERDUE_MS,
    REOFFER_BASE_S,
    REOFFER_MAX_S,
    RegistrationStatus,
)

from .test_registration_obligation import (
    DEVICE,
    OTHER_REFERENCE,
    REFERENCE,
    SECRET,
    Clock,
    Device,
    _Client,
    _confirmation,
    _registry,
    _retire_copy,
    _serve,
    _stop,
    _tier_d_row,
)

SCOPE = {
    DispositionValue.RETAINED_PENDING: DispositionScope.ARTIFACT,
    DispositionValue.ARTIFACT_TERMINAL: DispositionScope.ARTIFACT,
    DispositionValue.EPOCH_REPROVISIONING_REQUIRED: DispositionScope.EPOCH,
    DispositionValue.IDENTITY_REPLACEMENT_REQUIRED: DispositionScope.IDENTITY,
}


class _Verifier:
    """Stands in for the wire verifier: returns what steps 1 to 3 would."""

    def __init__(self) -> None:
        self.next: VerifiedDisposition | None = None
        self.raises = False

    def verify_disposition(self, artifact: object) -> VerifiedDisposition | None:
        if self.raises:
            raise RuntimeError("verifier failed")
        return self.next


class _Site(Device):
    def __init__(self, root, verifier: _Verifier | None) -> None:
        super().__init__(root)
        self.verifier = verifier

    async def start(self) -> FirstPartyEvidenceAttestor:
        self.attestor = FirstPartyEvidenceAttestor(
            db_path=str(self.root / "evidence.db"),
            key_path=str(self.root / "evidence.key"),
            device_secret=SECRET,
            device_id=DEVICE,
            authority_keys=_registry(),
            disposition_verifier=self.verifier,
        )
        assert await self.attestor.start() is True
        return self.attestor


@pytest.fixture
async def site(tmp_path):
    s = _Site(tmp_path, _Verifier())
    await s.start()
    try:
        yield s
    finally:
        if s.attestor is not None:
            s.attestor.close()


def _disposition(
    digest: str, epoch: str, value: DispositionValue, *, salt: str = ""
) -> VerifiedDisposition:
    own = (
        "sha256:" + hashlib.sha256(f"{digest}{value.value}{salt}".encode()).hexdigest()
    )
    return VerifiedDisposition(
        digest=own,
        triggering_digest=digest,
        device_id=DEVICE,
        anchor_epoch_id=epoch,
        scope=SCOPE[value],
        value=value,
        decided_at_ms=1787000009000,
        key_id="authority-disposition-1",
    )


async def _apply(site: _Site, disposition: VerifiedDisposition | None) -> Any:
    assert site.verifier is not None and site.attestor is not None
    site.verifier.next = disposition
    assert site.attestor.ingest is not None
    return site.attestor.ingest.accept_disposition({"opaque": True})


async def _sealed(site: _Site) -> Any:
    assert site.attestor is not None
    await site.attestor.reconcile_registration(REFERENCE)
    [row] = site.obligations()
    return row


async def _checkpoint(site: _Site) -> dict[str, Any]:
    assert site.attestor is not None
    row = await site.attestor.issue_checkpoint()
    assert row is not None
    return row


async def _envelope(site: _Site) -> tuple[str, str]:
    assert site.attestor is not None
    assert await site.attestor.attest_action(_tier_d_row(7)) is not None
    [row] = site.rows(
        "SELECT envelope_digest, anchor_epoch_id FROM evidence_delivery_ledger"
    )
    return str(row["envelope_digest"]), str(row["anchor_epoch_id"])


async def _reoffered(site: _Site, row: Any) -> list[bytes]:
    """What a publisher far past every delay carries, after the copy is retired."""
    assert site.attestor is not None
    clock = Clock(int(row["sealed_at_ms"]) + 100 * int(REOFFER_MAX_S * 1000))
    await _retire_copy(site.attestor, clock, row["artifact_digest"])
    # The first re-offer runs from that handoff attempt, not from sealing.
    clock.now += int(REOFFER_BASE_S * 1000)
    _publisher, client, shutdown, task = await _serve(site.attestor, clock)
    try:
        return client.registrations()
    finally:
        await _stop(shutdown, task)


async def _health(site: _Site, at_ms: int = 10**13) -> dict[str, Any]:
    assert site.attestor is not None
    fields = await site.attestor.registration_health(at_ms)
    assert fields is not None
    return fields


def _epoch(site: _Site) -> str:
    assert site.attestor is not None and site.attestor.anchor is not None
    return site.attestor.anchor.anchor_epoch_id


# --------------------------------------------------------------------------
# The seam as the runtime ships it
# --------------------------------------------------------------------------


async def test_the_shipped_verifier_verifies_nothing_and_nothing_changes(tmp_path):
    shipped = _Site(tmp_path, None)
    await shipped.start()
    try:
        row = await _sealed(shipped)
        assert shipped.attestor is not None and shipped.attestor.ingest is not None
        outcome = shipped.attestor.ingest.accept_disposition(
            {"triggering_digest": row["artifact_digest"], "disposition": "x"}
        )
        assert not outcome.accepted
        assert [dict(r) for r in shipped.obligations()] == [dict(row)]
        assert shipped.rows("SELECT * FROM evidence_disposition") == []
        assert await _reoffered(shipped, row) == [row["artifact_json"].encode()]
    finally:
        assert shipped.attestor is not None
        shipped.attestor.close()


# --------------------------------------------------------------------------
# retained_pending
# --------------------------------------------------------------------------


async def test_retained_pending_suspends_reoffers_and_keeps_the_obligation_open(site):
    row = await _sealed(site)
    outcome = await _apply(
        site,
        _disposition(
            row["artifact_digest"], _epoch(site), DispositionValue.RETAINED_PENDING
        ),
    )
    assert outcome.accepted and outcome.detail == "applied"

    [after] = site.obligations()
    assert after["state"] == "open" and after["suspended_at_ms"] is not None
    assert await _reoffered(site, row) == [], "a suspended registration was re-offered"

    sealed = int(row["sealed_at_ms"])
    health = await _health(site, sealed + CONFIRMATION_OVERDUE_MS + 1)
    assert health["registration_status"] == "pending_confirmation"
    assert health["registration_pending_since_ms"] == sealed
    assert health["registration_confirmation_overdue"] is True
    assert health["registration_offer"] == "suspended"
    assert health["delivery_stop_status"] == "not_stopped"
    last = health["last_disposition"]
    assert last["disposition"] == "retained_pending" and last["scope"] == "artifact"
    assert set(last) == {"disposition", "scope", "observed_at_ms"}

    # Suspension keeps checkpoints: they carry the answer back.
    await _checkpoint(site)

    site.restart_close()
    await site.start()
    assert site.obligations()[0]["suspended_at_ms"] == after["suspended_at_ms"]
    assert await _reoffered(site, row) == []

    assert site.attestor.ingest.accept_epoch_confirmation(
        _confirmation(site.attestor)
    ).accepted
    assert site.obligations()[0]["state"] == "confirmed"


async def test_retained_pending_on_anything_but_a_registration_is_refused(site):
    checkpoint = await _checkpoint(site)
    outcome = await _apply(
        site,
        _disposition(
            checkpoint["artifact_digest"],
            _epoch(site),
            DispositionValue.RETAINED_PENDING,
        ),
    )
    assert not outcome.accepted and outcome.reason == "binding_mismatch"
    assert site.rows("SELECT * FROM evidence_disposition") == []


async def test_a_fresh_reference_resumes_offers_after_suspension(site):
    row = await _sealed(site)
    await _apply(
        site,
        _disposition(
            row["artifact_digest"], _epoch(site), DispositionValue.RETAINED_PENDING
        ),
    )
    await site.attestor.reconcile_registration(OTHER_REFERENCE)
    first, second = site.obligations()
    assert first["state"] == "superseded"
    assert second["suspended_at_ms"] is None
    carried = await _reoffered(site, second)
    assert carried == [second["artifact_json"].encode()]


# --------------------------------------------------------------------------
# artifact_terminal
# --------------------------------------------------------------------------


async def test_artifact_terminal_on_a_registration_closes_the_attempt(site):
    row = await _sealed(site)
    outcome = await _apply(
        site,
        _disposition(
            row["artifact_digest"], _epoch(site), DispositionValue.ARTIFACT_TERMINAL
        ),
    )
    assert outcome.accepted
    [closed] = site.obligations()
    assert closed["state"] == "closed"
    assert closed["closed_reason"] == "artifact_terminal"
    assert site.handoff(row["artifact_digest"])["withdrawn_at_ms"] is not None
    assert await _reoffered(site, row) == []

    status = await site.attestor.reconcile_registration(REFERENCE)
    assert status is RegistrationStatus.PENDING_CONFIRMATION
    assert len(site.obligations()) == 1, "a closed attempt was resealed unrepaired"
    # The reference is still held and no confirmation arrived, so the status
    # stays pending; the closure shows as the offer, and the overdue
    # diagnostic keeps running from the sealing time.
    health = await _health(site, int(row["sealed_at_ms"]) + CONFIRMATION_OVERDUE_MS)
    assert health["registration_status"] == "pending_confirmation"
    assert health["registration_offer"] == "closed"
    assert health["registration_pending_since_ms"] == int(row["sealed_at_ms"])
    assert health["registration_confirmation_overdue"] is True
    assert health["delivery_stop_status"] == "not_stopped"

    await _checkpoint(site)

    await site.attestor.reconcile_registration(OTHER_REFERENCE)
    assert [r["state"] for r in site.obligations()] == ["closed", "open"]
    assert (await _health(site))["registration_status"] == "pending_confirmation"


@pytest.mark.parametrize("anchor_epoch_id", ["current", ""], ids=["epoch", "no-epoch"])
async def test_artifact_terminal_on_a_checkpoint_is_recorded_and_delivery_continues(
    site, anchor_epoch_id
):
    row = await _sealed(site)
    checkpoint = await _checkpoint(site)
    epoch = _epoch(site) if anchor_epoch_id == "current" else ""
    outcome = await _apply(
        site,
        _disposition(
            checkpoint["artifact_digest"], epoch, DispositionValue.ARTIFACT_TERMINAL
        ),
    )
    assert outcome.accepted
    assert site.obligations()[0]["state"] == "open"
    assert await _reoffered(site, row) == [row["artifact_json"].encode()]
    await _checkpoint(site)
    health = await _health(site)
    assert health["registration_offer"] == "offering"
    assert health["delivery_stop_status"] == "not_stopped"
    assert health["last_disposition"]["disposition"] == "artifact_terminal"


# --------------------------------------------------------------------------
# Epoch and identity scope, from the triggers that emit them
# --------------------------------------------------------------------------


async def test_an_epoch_disposition_stops_that_epochs_offers_and_checkpoints(site):
    row = await _sealed(site)
    checkpoint = await _checkpoint(site)
    outcome = await _apply(
        site,
        _disposition(
            checkpoint["artifact_digest"],
            _epoch(site),
            DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
        ),
    )
    assert outcome.accepted
    assert await site.attestor.issue_checkpoint() is None
    assert await _reoffered(site, row) == []
    await site.attestor.reconcile_registration(OTHER_REFERENCE)
    assert len(site.obligations()) == 1, "a reference lifted an epoch disposition"
    health = await _health(site)
    assert health["registration_offer"] == "closed"
    assert health["delivery_stop_status"] == "epoch_stopped"


async def test_an_identity_disposition_from_an_envelope_stops_everything_but_evidence(
    site,
):
    row = await _sealed(site)
    envelope_digest, envelope_epoch = await _envelope(site)
    outcome = await _apply(
        site,
        _disposition(
            envelope_digest,
            envelope_epoch,
            DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
        ),
    )
    assert outcome.accepted
    assert await site.attestor.issue_checkpoint() is None
    assert (await _health(site))["delivery_stop_status"] == "identity_stopped"

    site.restart_close()
    await site.start()
    assert await site.attestor.issue_checkpoint() is None
    await site.attestor.reconcile_registration(OTHER_REFERENCE)
    assert len(site.obligations()) == 1
    assert await _reoffered(site, row) == []
    health = await _health(site)
    assert health["registration_offer"] == "closed"
    assert health["delivery_stop_status"] == "identity_stopped"
    assert health["last_disposition"]["scope"] == "identity"

    assert await site.attestor.attest_action(_tier_d_row(8)) is not None, (
        "local Tier D evidence stopped with the offers"
    )

    conn = sqlite3.connect(str(site.root / "evidence.db"))
    try:
        for statement in (
            "DELETE FROM evidence_offer_stop",
            "UPDATE evidence_offer_stop SET scope = 'epoch'",
            "DELETE FROM evidence_disposition",
            "UPDATE evidence_disposition SET scope = 'artifact'",
        ):
            with pytest.raises(sqlite3.DatabaseError):
                conn.execute(statement)
    finally:
        conn.close()


@pytest.mark.parametrize(
    "value,current_carried",
    [
        (DispositionValue.EPOCH_REPROVISIONING_REQUIRED, True),
        (DispositionValue.IDENTITY_REPLACEMENT_REQUIRED, False),
    ],
    ids=["epoch-scope", "identity-scope"],
)
async def test_a_disposition_on_an_earlier_epoch_reaches_as_far_as_its_scope(
    site, value, current_carried
):
    """An epoch stop ends that epoch only; an identity stop ends the current one too."""
    row = await _sealed(site)
    ledger = site.attestor._ledger
    assert ledger is not None
    earlier = dict(json.loads(row["artifact_json"]))
    earlier["anchor_epoch_id"] = "sha256:" + "7" * 64
    earlier_row = site.attestor._executor.run(
        lambda: dict(ledger.seal_registration(earlier, sealed_at_ms=1))
    )
    await _retire_copy(site.attestor, Clock(1), earlier_row["artifact_digest"])
    outcome = await _apply(
        site,
        _disposition(earlier_row["artifact_digest"], earlier["anchor_epoch_id"], value),
    )
    assert outcome.accepted
    expected = [row["artifact_json"].encode()] if current_carried else []
    assert await _reoffered(site, row) == expected
    assert (await site.attestor.issue_checkpoint() is not None) is current_carried
    health = await _health(site)
    assert (health["delivery_stop_status"] == "not_stopped") is current_carried


# --------------------------------------------------------------------------
# Verification steps 4 to 6: dispositions that change nothing
# --------------------------------------------------------------------------


async def test_a_disposition_not_bound_to_a_sealed_artifact_changes_nothing(site):
    row = await _sealed(site)
    checkpoint = await _checkpoint(site)
    before = [dict(r) for r in site.obligations()]
    base = _disposition(
        row["artifact_digest"], _epoch(site), DispositionValue.ARTIFACT_TERMINAL
    )
    cases = [
        (
            "unsealed digest",
            replace(base, triggering_digest="sha256:" + "0" * 64),
            "binding_mismatch",
        ),
        (
            "another device",
            replace(base, device_id="another-device"),
            "binding_mismatch",
        ),
        (
            "another epoch",
            replace(base, anchor_epoch_id="sha256:" + "1" * 64),
            "binding_mismatch",
        ),
        (
            "epoch named on the checkpoint differs",
            replace(
                base,
                triggering_digest=checkpoint["artifact_digest"],
                anchor_epoch_id="sha256:" + "1" * 64,
            ),
            "binding_mismatch",
        ),
        (
            "value/scope pairing",
            replace(base, scope=DispositionScope.IDENTITY),
            "malformed",
        ),
        (
            "epoch scope naming no epoch",
            replace(
                base,
                value=DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
                scope=DispositionScope.EPOCH,
                anchor_epoch_id="",
            ),
            "malformed",
        ),
    ]
    for name, disposition, reason in cases:
        outcome = await _apply(site, disposition)
        assert not outcome.accepted, name
        assert outcome.reason == reason, (name, outcome.reason)
        assert [dict(r) for r in site.obligations()] == before, name
    site.verifier.raises = True
    assert not (await _apply(site, None)).accepted
    assert [dict(r) for r in site.obligations()] == before
    assert site.rows("SELECT * FROM evidence_offer_stop") == []
    assert site.rows("SELECT * FROM evidence_disposition") == []
    assert (await _health(site))["last_disposition"] is None
    assert await _reoffered(site, row) == [row["artifact_json"].encode()]


async def test_the_ledger_refuses_an_unbound_disposition_on_its_own(site):
    """The ingest checks do not hold this one up: the ledger is called directly."""
    row = await _sealed(site)
    before = [dict(r) for r in site.obligations()]
    ledger = site.attestor._ledger
    assert ledger is not None
    base = _disposition(
        row["artifact_digest"], _epoch(site), DispositionValue.ARTIFACT_TERMINAL
    )
    for disposition in (
        replace(base, triggering_digest="sha256:" + "0" * 64),
        replace(base, device_id="another-device"),
        replace(base, anchor_epoch_id="sha256:" + "1" * 64),
    ):
        with pytest.raises(DispositionRefusedError):
            site.attestor._executor.run(
                ledger._apply_verified_disposition, disposition, at_ms=1
            )
        assert [dict(r) for r in site.obligations()] == before


async def test_ingest_refuses_another_devices_disposition_before_the_ledger(
    site, monkeypatch
):
    row = await _sealed(site)
    ledger = site.attestor._ledger
    assert ledger is not None
    reached: list[object] = []
    monkeypatch.setattr(
        ledger,
        "_apply_verified_disposition",
        lambda disposition, **_k: reached.append(disposition) or "applied",
    )
    base = _disposition(
        row["artifact_digest"], _epoch(site), DispositionValue.ARTIFACT_TERMINAL
    )
    outcome = await _apply(site, replace(base, device_id="another-device"))
    assert not outcome.accepted and outcome.reason == "binding_mismatch"
    assert reached == []


async def test_a_disposition_for_a_confirmed_registration_is_superseded(site):
    row = await _sealed(site)
    assert site.attestor.ingest.accept_epoch_confirmation(
        _confirmation(site.attestor)
    ).accepted
    for value in (
        DispositionValue.RETAINED_PENDING,
        DispositionValue.ARTIFACT_TERMINAL,
    ):
        outcome = await _apply(
            site, _disposition(row["artifact_digest"], _epoch(site), value)
        )
        assert not outcome.accepted and outcome.reason == "superseded", value
    assert site.obligations()[0]["state"] == "confirmed"
    assert site.rows("SELECT * FROM evidence_disposition") == []


async def test_a_disposition_for_a_closed_registration_is_superseded(site):
    row = await _sealed(site)
    first = _disposition(
        row["artifact_digest"], _epoch(site), DispositionValue.ARTIFACT_TERMINAL
    )
    assert (await _apply(site, first)).accepted
    again = _disposition(
        row["artifact_digest"],
        _epoch(site),
        DispositionValue.ARTIFACT_TERMINAL,
        salt="2",
    )
    outcome = await _apply(site, again)
    assert not outcome.accepted and outcome.reason == "superseded"


async def test_a_stop_already_in_force_is_superseded(site):
    checkpoint = await _checkpoint(site)
    identity = _disposition(
        checkpoint["artifact_digest"],
        _epoch(site),
        DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
    )
    assert (await _apply(site, identity)).accepted
    for value in (
        DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
        DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
    ):
        outcome = await _apply(
            site,
            _disposition(checkpoint["artifact_digest"], _epoch(site), value, salt="2"),
        )
        assert not outcome.accepted and outcome.reason == "superseded", value
    assert len(site.rows("SELECT * FROM evidence_offer_stop")) == 1


async def _carried_types(site: _Site, *, drains: int = 5) -> list[str]:
    """Artifact types published across several drains, nothing acknowledged first."""
    assert site.attestor is not None
    [row] = [r for r in site.obligations() if r["state"] != "superseded"][:1] or [None]
    start = int(row["sealed_at_ms"]) if row is not None else 1787000000000
    clock = Clock(start + 1)
    publisher, client, shutdown, task = await _serve(site.attestor, clock)
    try:
        for _ in range(drains):
            clock.now += 100 * int(REOFFER_MAX_S * 1000)
            await publisher.drain()
    finally:
        await _stop(shutdown, task)
    return [json.loads(p)["artifact_type"] for p in client.published]


@pytest.mark.parametrize(
    "value",
    [
        DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
        DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
    ],
    ids=["epoch", "identity"],
)
async def test_a_stop_holds_every_artifact_in_its_scope(site, value):
    """Registrations, checkpoints and envelopes in the stopped scope stay local."""
    await _sealed(site)
    envelope_digest, _envelope_epoch = await _envelope(site)
    checkpoint = await _checkpoint(site)
    outcome = await _apply(
        site, _disposition(checkpoint["artifact_digest"], _epoch(site), value)
    )
    assert outcome.accepted

    # A Tier C/D action after the stop still executes its evidence path: it is
    # signed and sealed locally, and not handed off.
    assert await site.attestor.attest_action(_tier_d_row(8)) is not None
    sealed = site.rows(
        "SELECT envelope_digest, envelope_json, custody_state"
        " FROM evidence_delivery_ledger ORDER BY local_seq"
    )
    assert len(sealed) == 2
    assert await _carried_types(site) == []

    # The stopped bytes survive a restart, unchanged and still local.
    site.restart_close()
    await site.start()
    assert [
        dict(r)
        for r in site.rows(
            "SELECT envelope_digest, envelope_json, custody_state"
            " FROM evidence_delivery_ledger ORDER BY local_seq"
        )
    ] == [dict(r) for r in sealed]
    assert all(r["custody_state"] == "none" for r in sealed)
    assert await _carried_types(site) == []
    assert envelope_digest in {r["envelope_digest"] for r in sealed}


async def test_an_epoch_stop_leaves_other_epochs_envelopes_flowing(site):
    """A stop on an earlier epoch holds nothing sealed under the current one."""
    row = await _sealed(site)
    ledger = site.attestor._ledger
    assert ledger is not None
    earlier = dict(json.loads(row["artifact_json"]))
    earlier["anchor_epoch_id"] = "sha256:" + "7" * 64
    earlier_row = site.attestor._executor.run(
        lambda: dict(ledger.seal_registration(earlier, sealed_at_ms=1))
    )
    outcome = await _apply(
        site,
        _disposition(
            earlier_row["artifact_digest"],
            earlier["anchor_epoch_id"],
            DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
        ),
    )
    assert outcome.accepted
    await _envelope(site)
    types = await _carried_types(site)
    assert "delivery_envelope" in types
    assert "anchor_registration" in types


async def test_an_artifact_scoped_disposition_stops_no_later_envelope(site):
    row = await _sealed(site)
    assert (
        await _apply(
            site,
            _disposition(
                row["artifact_digest"], _epoch(site), DispositionValue.ARTIFACT_TERMINAL
            ),
        )
    ).accepted
    await _envelope(site)
    assert "delivery_envelope" in await _carried_types(site)


async def test_retained_pending_holds_a_pending_registration_copy(site):
    row = await _sealed(site)
    await _checkpoint(site)
    assert (
        await _apply(
            site,
            _disposition(
                row["artifact_digest"], _epoch(site), DispositionValue.RETAINED_PENDING
            ),
        )
    ).accepted
    types = await _carried_types(site)
    assert "anchor_registration" not in types
    assert "checkpoint" in types, "suspension must not stop checkpoints"


async def test_every_outbound_copy_is_republished_after_the_clock_steps_back(site):
    """Envelope, checkpoint and registration copy all publish again at once."""
    row = await _sealed(site)
    await _envelope(site)
    await _checkpoint(site)
    sealed = int(row["sealed_at_ms"])
    clock = Clock(sealed + 1)
    publisher, client, shutdown, task = await _serve(site.attestor, clock)
    try:
        await publisher.drain()
        first = sorted(json.loads(p)["artifact_type"] for p in client.published)
        assert first == ["anchor_registration", "checkpoint", "delivery_envelope"]
        client.published.clear()
        clock.now = sealed - 10 * 24 * 3600 * 1000
        await publisher.drain()
        again = sorted(json.loads(p)["artifact_type"] for p in client.published)
    finally:
        await _stop(shutdown, task)
    assert again == ["anchor_registration", "checkpoint", "delivery_envelope"]


async def test_an_artifact_another_device_identity_sealed_binds_nothing(tmp_path):
    """The same files reopened as another device: its old artifacts are not its own."""
    old = _Site(tmp_path, _Verifier())
    await old.start()
    assert old.attestor is not None
    await old.attestor.reconcile_registration(REFERENCE)
    [old_row] = old.obligations()
    await _retire_copy(old.attestor, Clock(1), old_row["artifact_digest"])
    old_checkpoint = await _checkpoint(old)
    old_epoch = _epoch(old)
    old.attestor.close()

    new = _Site(tmp_path, _Verifier())
    new.attestor = FirstPartyEvidenceAttestor(
        db_path=str(tmp_path / "evidence.db"),
        key_path=str(tmp_path / "evidence.key"),
        device_secret=SECRET,
        device_id="replacement-device",
        authority_keys=_registry(),
        disposition_verifier=new.verifier,
    )
    assert await new.attestor.start()
    try:
        disposition = replace(
            _disposition(
                old_checkpoint["artifact_digest"],
                old_epoch,
                DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
            ),
            device_id="replacement-device",
        )
        outcome = await _apply(new, disposition)
        assert not outcome.accepted and outcome.reason == "binding_mismatch"
        assert new.rows("SELECT * FROM evidence_offer_stop") == []
        ledger = new.attestor._ledger
        assert ledger is not None
        due = new.attestor._executor.run(
            lambda: ledger.registration_reoffers_due(at_ms=10**15)
        )
        assert due == [], "another identity's obligation was re-offered"

        # The old identity's unretired checkpoint copy is never carried as this
        # one's, and health counts it.
        own = await _checkpoint(new)
        assert new.attestor.outbound is not None
        carried = await new.attestor.outbound.pending_artifacts()
        assert [r["artifact_digest"] for r in carried] == [own["artifact_digest"]]
        health = await _health(new)
        assert health["foreign_identity_pending_count"] == 1
    finally:
        new.attestor.close()
        new.attestor = None


#: Copies that name no identity a runtime could read: carried, never counted.
_UNREADABLE_BODIES = (
    "{not json",
    "[]",
    "{}",
    '"x"',
    '{"device_id": null}',
    '{"device_id": 5}',
    '{"device_id": {"id": "x"}}',
)


def _poison(site: _Site, body: str) -> str:
    digest = "sha256:" + hashlib.sha256(body.encode()).hexdigest()
    conn = sqlite3.connect(str(site.root / "evidence.db"))
    try:
        conn.execute(
            "INSERT INTO evidence_outbox (artifact_type, artifact_json,"
            " artifact_digest, created_at_ms) VALUES (?, ?, ?, ?)",
            ("checkpoint", body, digest, 1),
        )
        conn.commit()
    finally:
        conn.close()
    return digest


@pytest.mark.parametrize("body", _UNREADABLE_BODIES)
@pytest.mark.parametrize("stopped", [False, True], ids=["no-stop", "epoch-stop"])
async def test_a_row_that_is_not_json_poisons_nothing(site, stopped, body):
    """The route stays up and every other copy is carried as the stop allows."""
    row = await _sealed(site)
    checkpoint = await _checkpoint(site)
    await _envelope(site)
    if stopped:
        outcome = await _apply(
            site,
            _disposition(
                checkpoint["artifact_digest"],
                _epoch(site),
                DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
            ),
        )
        assert outcome.accepted
    poison = _poison(site, body)
    clock = Clock(int(row["sealed_at_ms"]) + 1)
    publisher, client, shutdown, task = await _serve(site.attestor, clock)
    try:
        await publisher.drain()
        assert publisher.connected
    finally:
        await _stop(shutdown, task)
    carried = [json.loads(p) for p in client.published]
    types = sorted(c["artifact_type"] for c in carried)
    # Under the stop only the unreadable copy is carried, as the checkpoint
    # head; without it the sealed checkpoint is the head and the unreadable
    # copy waits behind it.
    expected = ["checkpoint"]
    if not stopped:
        expected = ["anchor_registration", "checkpoint", "delivery_envelope"]
    assert types == expected
    assert (await _health(site))["foreign_identity_pending_count"] == 0
    assert site.handoff(poison)["retired_at_ms"] is None


async def test_a_byte_identical_repetition_is_applied_again_with_no_new_state(site):
    row = await _sealed(site)
    disposition = _disposition(
        row["artifact_digest"], _epoch(site), DispositionValue.ARTIFACT_TERMINAL
    )
    assert (await _apply(site, disposition)).detail == "applied"
    before = [dict(r) for r in site.rows("SELECT * FROM evidence_disposition")]
    repeated = await _apply(site, disposition)
    assert repeated.accepted and repeated.detail == "repeated"
    assert [dict(r) for r in site.rows("SELECT * FROM evidence_disposition")] == before


# --------------------------------------------------------------------------
# Stops across a drain, a re-provisioning and an identity replacement
# --------------------------------------------------------------------------


async def _reprovision(site: _Site) -> str:
    """A new device key, and so a new epoch, over the same evidence files."""
    before = _epoch(site)
    site.restart_close()
    os.remove(site.root / "evidence.key")
    await site.start()
    assert _epoch(site) != before
    return before


def _carried(client: Any) -> list[tuple[str, str]]:
    out = []
    for payload in client.published:
        carriage = json.loads(payload)
        wire = base64.b64decode(carriage["artifact_b64"])
        out.append(
            (
                carriage["artifact_type"],
                "sha256:" + hashlib.sha256(wire).hexdigest(),
            )
        )
    return out


async def _serve_stopping_after_first(
    site: _Site, clock: Clock, disposition: VerifiedDisposition
) -> Any:
    """Serve once; the first handoff is followed at once by *disposition*."""
    attestor, verifier = site.attestor, site.verifier
    assert attestor is not None and attestor.ingest is not None
    assert verifier is not None
    ingest = attestor.ingest
    original = _Client.publish
    fired: list[Any] = []

    def publish(self: Any, topic: str, payload: bytes, qos: int = 0) -> None:
        original(self, topic, payload, qos)
        if topic.endswith("/outbound") and not fired:
            verifier.next = disposition
            fired.append(ingest.accept_disposition({"opaque": 1}))

    with patch.object(_Client, "publish", publish):
        _publisher, client, shutdown, task = await _serve(attestor, clock)
        await _stop(shutdown, task)
    assert fired and fired[0].accepted
    return client


@pytest.mark.parametrize(
    "value",
    [
        DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
        DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
    ],
    ids=["epoch", "identity"],
)
async def test_a_stop_during_a_drain_holds_what_it_has_not_yet_carried(site, value):
    """The stop is read again before each handoff, not once per batch."""
    for i in range(4):
        assert await site.attestor.attest_action(_tier_d_row(20 + i)) is not None
    checkpoint = await _checkpoint(site)
    await _sealed(site)
    client = await _serve_stopping_after_first(
        site,
        Clock(10**12),
        _disposition(checkpoint["artifact_digest"], _epoch(site), value),
    )
    assert len(client.published) == 1


@pytest.mark.parametrize("carried_as", ["copies", "reoffers"])
async def test_a_stop_during_a_drain_holds_the_remaining_registrations(
    site, carried_as
):
    """Both registrations are read before either is carried; the stop holds one."""
    row = await _sealed(site)
    ledger = site.attestor._ledger
    assert ledger is not None
    earlier = dict(json.loads(row["artifact_json"]))
    earlier["anchor_epoch_id"] = "sha256:" + "7" * 64
    earlier_row = site.attestor._executor.run(
        lambda: dict(ledger.seal_registration(earlier, sealed_at_ms=1))
    )
    clock = Clock(int(row["sealed_at_ms"]) + 100 * int(REOFFER_MAX_S * 1000))
    if carried_as == "reoffers":
        for sealed in (earlier_row, row):
            await _retire_copy(site.attestor, clock, sealed["artifact_digest"])
        clock.now += int(REOFFER_BASE_S * 1000)
    client = await _serve_stopping_after_first(
        site,
        clock,
        _disposition(
            earlier_row["artifact_digest"],
            earlier["anchor_epoch_id"],
            DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
        ),
    )
    carried = client.registrations()
    assert len(carried) == 1
    assert carried[0] in (
        earlier_row["artifact_json"].encode(),
        row["artifact_json"].encode(),
    )


async def test_the_per_handoff_recheck_answers_for_that_row_alone(site):
    """A stopped row is not carriable though other rows are."""
    row = await _sealed(site)
    ledger = site.attestor._ledger
    assert ledger is not None
    earlier = dict(json.loads(row["artifact_json"]))
    earlier["anchor_epoch_id"] = "sha256:" + "7" * 64
    earlier_row = site.attestor._executor.run(
        lambda: dict(ledger.seal_registration(earlier, sealed_at_ms=1))
    )
    assert (
        await _apply(
            site,
            _disposition(
                earlier_row["artifact_digest"],
                earlier["anchor_epoch_id"],
                DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
            ),
        )
    ).accepted
    run = site.attestor._executor.run

    def copy_id(digest: str) -> int:
        found = ledger.find_artifact(digest)
        assert found is not None
        return int(found["id"])

    stopped_copy = run(lambda: copy_id(earlier_row["artifact_digest"]))
    live_copy = run(lambda: copy_id(row["artifact_digest"]))
    assert run(lambda: ledger.pending_artifacts(1, only_id=stopped_copy)) == []
    assert len(run(lambda: ledger.pending_artifacts(1, only_id=live_copy))) == 1

    clock = Clock(10**15)
    for digest in (earlier_row["artifact_digest"], row["artifact_digest"]):
        await _retire_copy(site.attestor, clock, digest)
    clock.now += int(REOFFER_BASE_S * 1000)
    stopped_obligation, live_obligation = (
        int(r["id"])
        for r in sorted(
            site.obligations(),
            key=lambda r: r["artifact_digest"] != earlier_row["artifact_digest"],
        )
    )

    def due(only: int) -> list[Any]:
        return ledger.registration_reoffers_due(at_ms=clock.now, limit=1, only_id=only)

    assert run(lambda: due(stopped_obligation)) == []
    assert len(run(lambda: due(live_obligation))) == 1


async def test_the_envelope_recheck_answers_for_that_envelope_alone(site):
    old_digest, old_epoch = await _envelope(site)
    await _reprovision(site)
    assert await site.attestor.attest_action(_tier_d_row(8)) is not None
    assert (
        await _apply(
            site,
            _disposition(
                old_digest, old_epoch, DispositionValue.EPOCH_REPROVISIONING_REQUIRED
            ),
        )
    ).accepted
    outbound = site.attestor.outbound
    assert outbound is not None
    assert await outbound.awaiting_custody(1, only_seq=1) == []
    assert len(await outbound.awaiting_custody(1, only_seq=2)) == 1


async def test_an_earlier_epochs_registration_copy_stays_held(site):
    row = await _sealed(site)
    ledger = site.attestor._ledger
    assert ledger is not None
    earlier = dict(json.loads(row["artifact_json"]))
    earlier["anchor_epoch_id"] = "sha256:" + "7" * 64
    earlier_row = site.attestor._executor.run(
        lambda: dict(ledger.seal_registration(earlier, sealed_at_ms=1))
    )
    outcome = await _apply(
        site,
        _disposition(
            earlier_row["artifact_digest"],
            earlier["anchor_epoch_id"],
            DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
        ),
    )
    assert outcome.accepted
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(site.attestor, clock)
    try:
        for _ in range(3):
            clock.now += 10**10
            await publisher.drain()
    finally:
        await _stop(shutdown, task)
    registrations = {d for t, d in _carried(client) if t == "anchor_registration"}
    assert earlier_row["artifact_digest"] not in registrations
    assert row["artifact_digest"] in registrations


async def test_an_earlier_epochs_envelopes_stay_held_after_reprovisioning(site):
    old_digest, old_epoch = await _envelope(site)
    await _reprovision(site)
    assert await site.attestor.attest_action(_tier_d_row(8)) is not None
    [new_row] = site.rows(
        "SELECT envelope_digest FROM evidence_delivery_ledger WHERE local_seq = 2"
    )
    outcome = await _apply(
        site,
        _disposition(
            old_digest, old_epoch, DispositionValue.EPOCH_REPROVISIONING_REQUIRED
        ),
    )
    assert outcome.accepted
    clock = Clock(10**12)
    publisher, client, shutdown, task = await _serve(site.attestor, clock)
    try:
        for _ in range(3):
            clock.now += 10**10
            await publisher.drain()
    finally:
        await _stop(shutdown, task)
    envelopes = {d for t, d in _carried(client) if t == "delivery_envelope"}
    assert envelopes == {new_row["envelope_digest"]}


# --------------------------------------------------------------------------
# Stopped local custody: counted, sized and dated, never lost from the totals
# --------------------------------------------------------------------------


def _sizes(site: _Site) -> dict[str, int]:
    """Every retained artifact awaiting a courier, by digest, with its size."""
    rows = site.rows(
        "SELECT envelope_digest AS d, length(CAST(envelope_json AS BLOB)) AS n"
        " FROM evidence_delivery_ledger WHERE custody_state = 'none'"
        " UNION ALL SELECT artifact_digest, length(CAST(artifact_json AS BLOB))"
        " FROM evidence_outbox WHERE retired_at_ms IS NULL AND withdrawn_at_ms IS NULL"
    )
    return {str(r["d"]): int(r["n"]) for r in rows}


async def _stopped(site: _Site) -> tuple[int, int, int | None]:
    health = await _health(site)
    return (
        health["stopped_local_artifact_count"],
        health["stopped_local_bytes"],
        health["oldest_stopped_local_since_ms"],
    )


async def _assert_partition(site: _Site, stopped: set[str]) -> None:
    """Active plus stopped is everything retained: nothing counted twice or lost."""
    assert site.attestor is not None and site.attestor.outbound is not None
    sizes = _sizes(site)
    active_envelopes = await site.attestor.outbound.awaiting_custody()
    active_copies = await site.attestor.outbound.pending_artifacts()
    active = {str(r["envelope_digest"]) for r in active_envelopes} | {
        str(r["artifact_digest"]) for r in active_copies
    }
    assert not active & stopped
    assert active | stopped == set(sizes)
    # Every sealed envelope no courier holds, stopped or not: the field keeps
    # its contract meaning, and the stopped-local rows say how many a stop keeps.
    stopped_envelopes = {
        str(r["envelope_digest"])
        for r in site.rows("SELECT envelope_digest FROM evidence_delivery_ledger")
    } & stopped
    assert await site.attestor.pending_export_count() == len(active_envelopes) + len(
        stopped_envelopes
    )
    count, size, _since = await _stopped(site)
    assert count == len(stopped)
    assert size == sum(sizes[d] for d in stopped)


async def test_nothing_is_stopped_and_the_diagnostics_say_so(site):
    await _sealed(site)
    await _envelope(site)
    assert await _stopped(site) == (0, 0, None)
    await _assert_partition(site, set())


async def test_a_current_epoch_stop_is_counted_sized_and_survives_restart(site):
    row = await _sealed(site)
    envelope_digest, _ = await _envelope(site)
    checkpoint = await _checkpoint(site)
    assert (
        await _apply(
            site,
            _disposition(
                checkpoint["artifact_digest"],
                _epoch(site),
                DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
            ),
        )
    ).accepted
    [stop] = site.rows("SELECT stopped_at_ms FROM evidence_offer_stop")
    stopped = {row["artifact_digest"], envelope_digest, checkpoint["artifact_digest"]}
    await _assert_partition(site, stopped)
    assert (await _stopped(site))[2] == int(stop["stopped_at_ms"])

    # Evidence sealed after the stop is stopped from the moment it is sealed.
    assert await site.attestor.attest_action(_tier_d_row(8)) is not None
    [late] = site.rows(
        "SELECT envelope_digest, sealed_at_ms FROM evidence_delivery_ledger"
        " WHERE local_seq = 2"
    )
    stopped.add(str(late["envelope_digest"]))
    await _assert_partition(site, stopped)

    before = await _stopped(site)
    site.restart_close()
    await site.start()
    assert await _stopped(site) == before
    await _assert_partition(site, stopped)


async def test_an_earlier_epochs_stop_is_still_counted_after_reprovisioning(site):
    old_digest, old_epoch = await _envelope(site)
    await _reprovision(site)
    assert (
        await _apply(
            site,
            _disposition(
                old_digest, old_epoch, DispositionValue.EPOCH_REPROVISIONING_REQUIRED
            ),
        )
    ).accepted
    assert await site.attestor.attest_action(_tier_d_row(8)) is not None
    health = await _health(site)
    assert health["delivery_stop_status"] == "not_stopped"
    assert health["stopped_local_artifact_count"] == 1
    await _assert_partition(site, {old_digest})


async def test_an_identity_stop_counts_every_epoch(site):
    old_digest, _ = await _envelope(site)
    await _reprovision(site)
    checkpoint = await _checkpoint(site)
    assert await site.attestor.attest_action(_tier_d_row(8)) is not None
    [new_row] = site.rows(
        "SELECT envelope_digest FROM evidence_delivery_ledger WHERE local_seq = 2"
    )
    assert (
        await _apply(
            site,
            _disposition(
                checkpoint["artifact_digest"],
                _epoch(site),
                DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
            ),
        )
    ).accepted
    await _assert_partition(
        site,
        {old_digest, str(new_row["envelope_digest"]), checkpoint["artifact_digest"]},
    )


async def test_custody_taken_before_the_stop_leaves_stopped_local_custody(site):
    """Bytes the courier already holds are the courier's, not stopped locally."""
    envelope_digest, _ = await _envelope(site)
    checkpoint = await _checkpoint(site)
    assert (
        await _apply(
            site,
            _disposition(
                checkpoint["artifact_digest"],
                _epoch(site),
                DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
            ),
        )
    ).accepted
    assert (await _stopped(site))[0] == 2
    ledger = site.attestor._ledger
    assert ledger is not None
    site.attestor._executor.run(
        lambda: ledger._apply_verified_custody(
            1, custody_at_ms=5, key_id="hkdf-sha256:" + "a" * 64
        )
    )
    await _assert_partition(site, {checkpoint["artifact_digest"]})
    assert envelope_digest not in _sizes(site)


async def test_a_stop_that_fails_to_commit_leaves_everything_active(site):
    """The stop record is the move: all of it lands, or none of it does."""
    await _envelope(site)
    checkpoint = await _checkpoint(site)
    conn = sqlite3.connect(str(site.root / "evidence.db"))
    try:
        conn.execute(
            "CREATE TRIGGER crash_mid_disposition BEFORE INSERT ON"
            " evidence_disposition BEGIN SELECT RAISE(ABORT, 'crash'); END"
        )
        conn.commit()
    finally:
        conn.close()
    disposition = _disposition(
        checkpoint["artifact_digest"],
        _epoch(site),
        DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
    )
    with pytest.raises(sqlite3.DatabaseError):
        await _apply(site, disposition)
    assert site.rows("SELECT * FROM evidence_offer_stop") == []
    await _assert_partition(site, set())


# --------------------------------------------------------------------------
# A stop is permanent
# --------------------------------------------------------------------------


async def test_nothing_lifts_a_stop(tmp_path):
    """Not a restart, a new reference, a later disposition, a new epoch or identity."""
    site = _Site(tmp_path, _Verifier())
    await site.start()
    try:
        row = await _sealed(site)
        checkpoint = await _checkpoint(site)
        epoch = _epoch(site)
        assert (
            await _apply(
                site,
                _disposition(
                    checkpoint["artifact_digest"],
                    epoch,
                    DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
                ),
            )
        ).accepted
        stops = [dict(r) for r in site.rows("SELECT * FROM evidence_offer_stop")]

        def unchanged() -> None:
            assert [
                dict(r) for r in site.rows("SELECT * FROM evidence_offer_stop")
            ] == stops

        for value in DispositionValue:
            if value is DispositionValue.IDENTITY_REPLACEMENT_REQUIRED:
                continue
            for digest in (row["artifact_digest"], checkpoint["artifact_digest"]):
                await _apply(site, _disposition(digest, epoch, value, salt="again"))
                unchanged()
        assert site.attestor is not None
        await site.attestor.reconcile_registration(OTHER_REFERENCE)
        unchanged()
        site.restart_close()
        await site.start()
        unchanged()
        assert (await _health(site))["delivery_stop_status"] == "epoch_stopped"
        await _reprovision(site)
        unchanged()
        assert (await _health(site))["delivery_stop_status"] == "not_stopped"
        conn = sqlite3.connect(str(site.root / "evidence.db"))
        try:
            for sql in (
                "DELETE FROM evidence_offer_stop",
                "UPDATE evidence_offer_stop SET scope = 'epoch'",
            ):
                with pytest.raises(sqlite3.DatabaseError):
                    conn.execute(sql)
        finally:
            conn.close()
        unchanged()
    finally:
        if site.attestor is not None:
            site.attestor.close()

    replacement = FirstPartyEvidenceAttestor(
        db_path=str(tmp_path / "evidence.db"),
        key_path=str(tmp_path / "evidence.key"),
        device_secret=SECRET,
        device_id="replacement-device",
        authority_keys=_registry(),
    )
    assert await replacement.start()
    replacement.close()
    unchanged()
