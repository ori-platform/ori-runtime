# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A refusal a sender can repeat writes a bounded number of log lines.

Each receiver that refuses an unverified gateway message reports through a
`CoalescedWarning`, so a flood at the topic's ingress rate writes one line per
reason per minute rather than one per message.
"""

from __future__ import annotations

import json
import logging
import threading
from types import SimpleNamespace

import pytest

from ori.utils.coalesced_log import CoalescedWarning
from tests.gateway_auth_helpers import cache_for

LOGGER = "tests.coalesced"


def _lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == LOGGER]


def test_one_line_per_reason_per_interval_with_the_count(caplog):
    clock = [0.0]
    warning = CoalescedWarning(
        logging.getLogger(LOGGER), interval_s=60.0, clock=lambda: clock[0]
    )
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        for _ in range(100):
            warning.warn("a", "refused %s", "a")
        warning.warn("b", "refused %s", "b")
        clock[0] = 60.0
        warning.warn("a", "refused %s", "a")
    assert _lines(caplog) == [
        "refused a (1 since the last report)",
        "refused b (1 since the last report)",
        "refused a (100 since the last report)",
    ]


def test_counts_hold_across_threads(caplog):
    warning = CoalescedWarning(logging.getLogger(LOGGER), clock=lambda: 0.0)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        threads = [
            threading.Thread(
                target=lambda: [warning.warn("a", "x") for _ in range(500)]
            )
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        warning._clock = lambda: 60.0  # type: ignore[method-assign]
        warning.warn("a", "x")
    assert _lines(caplog)[-1] == f"x ({8 * 500} since the last report)"


def _flood(caplog, logger: str, send, count: int = 50) -> list[str]:
    with caplog.at_level(logging.WARNING, logger=logger):
        for _ in range(count):
            send()
    return [r.getMessage() for r in caplog.records if r.name == logger]


def test_a_flood_of_rejected_heartbeats_writes_one_line(caplog):
    from ori.gateway.heartbeat import MqttGatewayHeartbeatSubscriber
    from ori.security.gateway_messages import (
        GatewayMessageAuthConfig,
        GatewayMessageAuthenticator,
    )

    sub = MqttGatewayHeartbeatSubscriber(
        broker_url="mqtt://localhost",
        posture_tracker=SimpleNamespace(),  # type: ignore[arg-type]
        device_id="dev-01",
        authenticator=GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(shared_secret="gateway-secret"),
            replay_cache=cache_for(
                GatewayMessageAuthConfig(shared_secret="gateway-secret")
            ),
        ),
        client_factory=lambda **_: None,
    )
    sub._loop = SimpleNamespace()  # type: ignore[assignment]
    message = SimpleNamespace(payload=json.dumps({"status": "ok"}).encode())
    lines = _flood(
        caplog,
        "ori.gateway.heartbeat",
        lambda: sub._on_message(None, None, message),
        count=5,  # within the heartbeat burst
    )
    assert [line for line in lines if "rejected heartbeat" in line] == [
        "[gateway-heartbeat] rejected heartbeat: missing_auth (1 since the last report)"
    ]


@pytest.mark.asyncio
async def test_a_flood_of_unauthenticated_export_requests_writes_one_line(
    caplog, tmp_path
):
    from ori.gateway.export import GatewayExportResponder
    from ori.security.gateway_messages import (
        GatewayMessageAuthConfig,
        GatewayMessageAuthenticator,
    )
    from ori.state.store import StateStore

    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        responder = GatewayExportResponder(
            state_store=store,
            device_id="dev-01",
            health_snapshot_provider=dict,
            message_auth=GatewayMessageAuthenticator(
                GatewayMessageAuthConfig(shared_secret="gateway-secret"),
                replay_cache=cache_for(
                    GatewayMessageAuthConfig(shared_secret="gateway-secret")
                ),
            ),
        )
        request = json.dumps(
            {"request_id": "req-1", "export_type": "health", "device_id": "dev-01"}
        ).encode()
        with caplog.at_level(logging.WARNING, logger="ori.gateway.export"):
            for _ in range(50):
                assert await responder.handle_payload(request) is None
        lines = [r.getMessage() for r in caplog.records if "dropped" in r.getMessage()]
        assert lines == [
            "[gateway-export] unauthenticated request dropped: missing_auth "
            "(1 since the last report)"
        ]
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_a_flood_of_refused_acknowledgements_writes_one_line(caplog):
    from ori.gateway.evidence_outbound import (
        ROUTED_REFUSED,
        MqttEvidenceOutboundPublisher,
    )

    class _Refusing:
        async def handle_ack(self, payload: bytes) -> SimpleNamespace:
            return SimpleNamespace(
                outcome=ROUTED_REFUSED,
                reason="envelope unauthenticated: missing_auth",
                artifact_type="",
            )

    publisher = MqttEvidenceOutboundPublisher(
        broker_url="mqtt://localhost",
        router=_Refusing(),  # type: ignore[arg-type]
        device_id="dev-01",
        outbox=None,  # type: ignore[arg-type]
        client_factory=lambda **_: None,
    )
    with caplog.at_level(logging.WARNING, logger="ori.gateway.evidence_outbound"):
        for _ in range(50):
            await publisher._apply_ack(b"{}")
    assert [r.getMessage() for r in caplog.records if "refused" in r.getMessage()] == [
        "[evidence-outbound] acknowledgement refused: envelope unauthenticated: "
        "missing_auth (1 since the last report)"
    ]


@pytest.mark.asyncio
async def test_a_flood_of_inbound_transport_refusals_writes_one_line(caplog):
    from ori.gateway.evidence_inbound import (
        InboundRefusal,
        MqttEvidenceInboundSubscriber,
        Routed,
    )

    class _Refusing:
        topic = "ori/dev-01/evidence/inbound"
        envelope_authenticated = True

        async def route(self, payload: bytes) -> Routed:
            return Routed(InboundRefusal("envelope_unauthenticated", "missing_auth"))

    subscriber = MqttEvidenceInboundSubscriber(
        broker_url="mqtt://localhost",
        router=_Refusing(),  # type: ignore[arg-type]
        device_id="dev-01",
        client_factory=lambda **_: None,
    )
    with caplog.at_level(logging.WARNING, logger="ori.gateway.evidence_inbound"):
        for _ in range(50):
            await subscriber._route_admitted(b"{}")
    assert [r.getMessage() for r in caplog.records if "refused" in r.getMessage()] == [
        "[evidence-inbound] message refused before ingest: envelope_unauthenticated "
        "(missing_auth) (1 since the last report)"
    ]
