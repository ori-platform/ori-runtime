# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Mandatory notices cross the real typed sender and durable outbox boundary."""

from pathlib import Path

import pytest

from ori.actions.alert_delivery import AlertIntent, AlertSendReceipt, OutboundAlert
from ori.actions.alert_failover import AlertFailoverSender
from ori.runtime import OriRuntime
from ori.state.store import StateStore


class RecordingTransport:
    def __init__(self, *, accepted: bool) -> None:
        self.accepted = accepted
        self.sent: list[tuple[OutboundAlert, str]] = []

    async def submit(self, *, alert: OutboundAlert, to_number: str) -> AlertSendReceipt:
        self.sent.append((alert, to_number))
        if not self.accepted:
            return AlertSendReceipt.refused(channel="whatsapp")
        return AlertSendReceipt(
            accepted=True,
            channel="whatsapp",
            provider_message_id="SM" + "a" * 32,
            provider_status="queued",
            accepted_at_ms=1_800_000_000_000,
        )


def _runtime(monkeypatch: pytest.MonkeyPatch) -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._operator_contact = "+2340000000000"
    runtime._primary_alert_channel = "whatsapp"
    runtime._device_location = "Test site"
    runtime._device_timezone = "UTC"

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("mandatory notice reached a policy gate or counter")

    for name in (
        "_policy_permits_alert_class",
        "_policy_permits_external_alert",
        "_record_policy_counted_alert",
    ):
        monkeypatch.setattr(runtime, name, forbidden)
    return runtime


@pytest.mark.parametrize("accepted", [True, False])
async def test_safety_notice_retains_typed_delivery_state_after_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, accepted: bool
) -> None:
    runtime = _runtime(monkeypatch)
    transport = RecordingTransport(accepted=accepted)
    sender = AlertFailoverSender(
        primary_channel="whatsapp", sms_sender=None, whatsapp_sender=transport
    )
    database = str(tmp_path / "safety-alert.db")
    store = StateStore(database)
    await store.open()
    runtime._state_store = store
    try:
        assert (
            await runtime._send_or_queue_safety_alert(
                message="SAFETY measurement_loss: input unavailable",
                trigger_name="safety_measurement_loss",
                alert_sender=sender,
                recipient="+2340000000001",
            )
            is True
        )
    finally:
        await store.close()

    assert len(transport.sent) == 1
    alert, destination = transport.sent[0]
    assert destination == "whatsapp:+2340000000001"
    assert alert.intent is AlertIntent.TIER_A_ALERT
    assert alert.template_variables[:2] == ("safety_measurement_loss", "Test site")
    assert alert.sms_body == "SAFETY measurement_loss: input unavailable"

    reopened = StateStore(database)
    await reopened.open()
    try:
        assert reopened._conn is not None
        row = reopened._conn.execute("SELECT * FROM alert_outbox").fetchone()
        assert row is not None
        assert row["delivered_at_ms"] is None
        assert row["intent"] == "tier_a_alert"
        if accepted:
            assert row["status"] == "accepted"
            assert row["provider_message_id"] == "SM" + "a" * 32
            assert row["provider_status"] == "queued"
            assert row["accepted_at_ms"] == 1_800_000_000_000
            assert await reopened.get_retryable_alerts() == []
        else:
            assert row["status"] == "pending"
            queued = await reopened.get_retryable_alerts()
            assert len(queued) == 1
            assert queued[0]["template_variables"] == alert.template_variables
    finally:
        await reopened.close()


@pytest.mark.parametrize("accepted", [True, False])
async def test_safety_notice_without_store_reports_acceptance_not_receipt_truthiness(
    monkeypatch: pytest.MonkeyPatch, accepted: bool
) -> None:
    runtime = _runtime(monkeypatch)
    transport = RecordingTransport(accepted=accepted)
    sender = AlertFailoverSender(
        primary_channel="whatsapp", sms_sender=None, whatsapp_sender=transport
    )
    assert (
        await runtime._send_or_queue_safety_alert(
            message="SAFETY input unavailable",
            trigger_name="safety_measurement_loss",
            alert_sender=sender,
        )
        is accepted
    )
    assert len(transport.sent) == 1
