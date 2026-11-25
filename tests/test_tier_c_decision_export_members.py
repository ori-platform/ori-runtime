# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""gateway-api/v2 export items carry their table's members only.

The store keeps the reply's sender number, its provider message id and the
row id; the export carries none of them, nor any provider message id nested in
`final_action_result`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from ori.actions.alert_delivery import AlertSendReceipt, InboundApprovalResponse
from ori.gateway.export import GatewayExportResponder
from ori.network.events import ActionTier, OriEvent, ReasoningResult, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import SkillContext
from ori.state._tier_c import (
    _EXPORTED_RECEIPT_MEMBERS,
    _EXPORTED_RESULT_MEMBERS,
    _exported_final_action_result,
)
from ori.state.store import StateStore
from tests.waiting import drained

DEVICE = "dev-01"
FROM_NUMBER = "whatsapp:+2348011112222"
REPLY_PROVIDER_ID = "SM" + "c" * 32
APPROVAL_PROVIDER_ID = "SM" + "a" * 32

#: gateway-api/v2's export item member tables, as the vendored corpus carries them.
EXPORT_ITEM_MEMBERS: dict[str, list[str]] = json.loads(
    (
        Path(__file__).parent / "vectors" / "gateway_api" / "payload-members-v2.json"
    ).read_text()
)["export_item_members"]
CONTRACT_MEMBERS = frozenset(EXPORT_ITEM_MEMBERS["tier_c_decision_log"])


class _Skill:
    name = "test-skill"
    config: dict[str, Any] = {}
    triggers: list[Any] = []
    actions: dict[str, Any] = {}
    first_party = True


def _context() -> SkillContext:
    reading = SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=5.0,
        unit="ampere",
        timestamp=int(time.time() * 1000),
        quality=1.0,
    )
    return SkillContext(
        skill=_Skill(), event=OriEvent.from_reading(reading, DEVICE), state_store=None
    )


async def _approved_decision(store: StateStore) -> None:
    sender = AsyncMock()
    sender.send = AsyncMock(
        return_value=AlertSendReceipt(
            accepted=True, channel="sms", provider_message_id=APPROVAL_PROVIDER_ID
        )
    )
    dispatcher = ActionDispatcher(
        state_store=store,
        alert_sender=sender,
        config={"operator_contact": "+2348000000000"},
    )
    dispatcher.register_executor("terminate_process", AsyncMock(return_value=True))
    reply = InboundApprovalResponse(
        body="YES-AB12CD34",
        channel="whatsapp",
        from_number=FROM_NUMBER,
        received_at_ms=12_345,
        provider_message_id=REPLY_PROVIDER_ID,
    )
    with (
        patch(
            "ori.reasoning.action_dispatcher._generate_proposal_id",
            return_value="AB12CD34",
        ),
        patch.object(
            dispatcher, "_listen_for_response", new=AsyncMock(return_value=reply)
        ),
    ):
        result = await dispatcher.dispatch(
            "terminate_process",
            ActionTier.HARD_PHYSICAL,
            _context(),
            ReasoningResult(
                text="Load is high.",
                tier="local_slm",
                model="qwen.gguf",
                tokens_used=20,
                latency_ms=500,
                confidence=0.85,
                action_tier="C",
            ),
            approval_timeout_seconds=10,
        )
    assert result.approved is True
    await drained(dispatcher)


async def test_an_exported_decision_carries_its_table_and_no_identifier(
    tmp_path: Path,
) -> None:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        await _approved_decision(store)
        stored = await store.get_tier_c_decision_log()
        assert stored[0]["operator_response_from_number"] == FROM_NUMBER
        assert stored[0]["operator_response_provider_message_id"] == REPLY_PROVIDER_ID
        assert (
            stored[0]["final_action_result"]["approval_delivery"]["provider_message_id"]
            == APPROVAL_PROVIDER_ID
        )

        responder = GatewayExportResponder(
            device_id=DEVICE, state_store=store, health_snapshot_provider=dict
        )
        response = await responder.handle_request(
            {
                "request_id": "req-001",
                "export_type": "tier_c_decision_log",
                "device_id": DEVICE,
                "limit": 10,
                "page_token": "",
                "params": {},
            }
        )
        assert response is not None and response.error is None
        (item,) = response.items
        assert set(item) == CONTRACT_MEMBERS
        assert item["operator_response_channel"] == "whatsapp"
        assert item["operator_response_received_at_ms"] == 12_345
        text = json.dumps(item)
        for identifier in (FROM_NUMBER, "2348011112222", REPLY_PROVIDER_ID):
            assert identifier not in text
        assert APPROVAL_PROVIDER_ID not in text
        result = item["final_action_result"]
        assert "operator_response_provider_message_id" not in result
        assert result["approval_delivery"]["accepted"] is True
        # Every member the dispatcher writes has the type the export expects.
        assert set(result) == set(_EXPORTED_RESULT_MEMBERS) | {
            "approval_delivery",
            "escalation_delivery",
        }
        for receipt in ("approval_delivery", "escalation_delivery"):
            assert set(result[receipt]) == set(_EXPORTED_RECEIPT_MEMBERS)
        assert "provider_message_id" not in result["approval_delivery"]
    finally:
        await store.close()


async def test_pages_keep_their_order_without_the_row_id(tmp_path: Path) -> None:
    """Rows sharing `created_at` page latest first, each once, with no `id`."""
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        for index in range(5):
            await store.log_tier_c_decision(
                device_id=DEVICE, proposal_id=f"p{index}", created_at=1_000
            )
        responder = GatewayExportResponder(
            device_id=DEVICE, state_store=store, health_snapshot_provider=dict
        )
        seen: list[str] = []
        token = ""
        for _ in range(10):
            response = await responder.handle_request(
                {
                    "request_id": "req-001",
                    "export_type": "tier_c_decision_log",
                    "device_id": DEVICE,
                    "limit": 2,
                    "page_token": token,
                    "params": {},
                }
            )
            assert response is not None and response.error is None
            assert all(set(item) == CONTRACT_MEMBERS for item in response.items)
            seen.extend(item["proposal_id"] for item in response.items)
            if response.complete:
                break
            token = response.next_page_token
        assert seen == ["p4", "p3", "p2", "p1", "p0"]
    finally:
        await store.close()


_HIDDEN = {
    "provider_message_id": APPROVAL_PROVIDER_ID,
    "operator_response_from_number": FROM_NUMBER,
}


#: Every member the dispatcher writes in `final_action_result`, and in each
#: delivery receipt, listed here independently of the export's own tables.
_WRITTEN_RESULT_MEMBERS = (
    "action_name",
    "tier",
    "executed",
    "approved",
    "action_taken",
    "operator_response",
    "operator_response_channel",
    "operator_response_provider_message_id",
    "operator_response_received_at_ms",
    "proposal_id",
    "timestamp",
)
_WRITTEN_RECEIPT_MEMBERS = (
    "accepted",
    "channel",
    "provider_message_id",
    "provider_status",
    "accepted_at_ms",
    "delivered_at_ms",
    "error",
)
_CARRIER = f"provider {APPROVAL_PROVIDER_ID} for {FROM_NUMBER}"


def _planted_results() -> list[dict[str, Any]]:
    """One stored result per written member, holding identifiers in its value."""
    planted: list[dict[str, Any]] = []
    for value in (_HIDDEN, [_HIDDEN], _CARRIER):
        for name in _WRITTEN_RESULT_MEMBERS:
            planted.append({name: value})
        for receipt in ("approval_delivery", "escalation_delivery"):
            for name in _WRITTEN_RECEIPT_MEMBERS:
                planted.append({receipt: {name: value}})
    return planted


async def test_no_identifier_survives_beneath_an_exported_member(
    tmp_path: Path,
) -> None:
    planted = _planted_results()
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        for index, result in enumerate(planted):
            await store.log_tier_c_decision(
                device_id=DEVICE,
                proposal_id=f"p{index}",
                final_action_result=result,
                created_at=1_000 + index,
            )
        responder = GatewayExportResponder(
            device_id=DEVICE, state_store=store, health_snapshot_provider=dict
        )
        response = await responder.handle_request(
            {
                "request_id": "req-001",
                "export_type": "tier_c_decision_log",
                "device_id": DEVICE,
                "limit": 1000,
                "page_token": "",
                "params": {},
            }
        )
        assert response is not None and response.error is None
        assert len(response.items) == len(planted)
        text = json.dumps(response.items)
        for identifier in (FROM_NUMBER, "2348011112222", APPROVAL_PROVIDER_ID):
            assert identifier not in text
    finally:
        await store.close()


def test_the_result_keeps_only_its_exported_members() -> None:
    stored = {
        "tier": "C",
        "approved": True,
        "executed": 1,
        "timestamp": True,
        "action_name": "terminate_process",
        "operator_response": "YES-AB12CD34",
        "operator_response_provider_message_id": REPLY_PROVIDER_ID,
        "added_later": "x",
        "approval_delivery": {
            "accepted": True,
            "channel": "sms",
            "accepted_at_ms": 5,
            "provider_status": "queued",
            "error": "",
        },
        "escalation_delivery": {"channel": "pager", "accepted": False},
    }
    assert _exported_final_action_result(stored) == {
        "tier": "C",
        "approved": True,
        "approval_delivery": {"accepted": True, "channel": "sms", "accepted_at_ms": 5},
        "escalation_delivery": {"accepted": False},
    }
    assert _exported_final_action_result({"tier": "E"}) == {}
    assert _exported_final_action_result(None) == {}
    assert _exported_final_action_result(["SM1"]) == {}


@pytest.mark.parametrize("export_type", ["action_log", "reasoning_log"])
async def test_the_other_paged_exports_carry_their_tables(
    tmp_path: Path, export_type: str
) -> None:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        assert store._conn is not None
        store._conn.execute(
            "INSERT INTO action_log (action_name, tier, executed, action_taken, "
            "trigger_name, timestamp, device_id, correlation_id, record_kind, "
            "record_key) VALUES ('alert_sms', 'A', 1, 'alert_sms', 't', 1000, ?, "
            "'c', 'dispatch', 'k')",
            (DEVICE,),
        )
        store._conn.execute(
            "INSERT INTO reasoning_log (trigger_name, tier_used, response, "
            "confidence, action_tier, timestamp, device_id, correlation_id) "
            "VALUES ('t', 'rule', 'r', 1.0, 'A', 1000, ?, 'c')",
            (DEVICE,),
        )
        store._conn.commit()
        responder = GatewayExportResponder(
            device_id=DEVICE, state_store=store, health_snapshot_provider=dict
        )
        response = await responder.handle_request(
            {
                "request_id": "req-001",
                "export_type": export_type,
                "device_id": DEVICE,
                "limit": 10,
                "page_token": "",
                "params": {},
            }
        )
    finally:
        await store.close()
    assert response is not None and response.error is None
    (item,) = response.items
    assert set(item) == set(EXPORT_ITEM_MEMBERS[export_type])
