# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import AsyncMock

import pytest

from ori.actions.alert_delivery import (
    AlertIntent,
    AlertSendReceipt,
    build_outbound_alert,
)
from ori.actions.alert_failover import AlertFailoverSender
from ori.reasoning.capability_posture import CapabilityPosture


class TestAlertFailoverSender:
    @staticmethod
    def _alert():
        return build_outbound_alert(
            intent=AlertIntent.TIER_A_ALERT,
            sms_body="hello",
            template_variables=("risk", "Abuja", "Wednesday 23:00"),
        )

    @pytest.mark.asyncio
    async def test_send_uses_primary_first(self):
        sms = AsyncMock()
        sms.submit = AsyncMock(
            return_value=AlertSendReceipt.accepted_without_provider_receipt(
                channel="sms"
            )
        )
        whatsapp = AsyncMock()
        whatsapp.submit = AsyncMock(
            return_value=AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )
        )

        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        receipt = await sender.send(self._alert(), "+2340000000")
        assert receipt.accepted is True
        sms.submit.assert_awaited_once()
        whatsapp.submit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_falls_back_to_secondary(self):
        sms = AsyncMock()
        sms.submit = AsyncMock(return_value=AlertSendReceipt.refused(channel="sms"))
        whatsapp = AsyncMock()
        whatsapp.submit = AsyncMock(
            return_value=AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )
        )

        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        receipt = await sender.send(self._alert(), "+2340000000")
        assert receipt.accepted is True
        sms.submit.assert_awaited_once()
        whatsapp.submit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_respects_preferred_channel_override(self):
        sms = AsyncMock()
        sms.submit = AsyncMock(
            return_value=AlertSendReceipt.accepted_without_provider_receipt(
                channel="sms"
            )
        )
        whatsapp = AsyncMock()
        whatsapp.submit = AsyncMock(
            return_value=AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )
        )

        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        receipt = await sender.send(
            self._alert(), "+2340000000", preferred_channel="whatsapp"
        )
        assert receipt.accepted is True
        whatsapp.submit.assert_awaited_once()
        sms.submit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_exact_does_not_fall_back(self):
        sms = AsyncMock()
        sms.submit = AsyncMock(
            return_value=AlertSendReceipt.accepted_without_provider_receipt(
                channel="sms"
            )
        )
        whatsapp = AsyncMock()
        whatsapp.submit = AsyncMock(
            return_value=AlertSendReceipt.refused(channel="whatsapp")
        )

        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )

        alert = self._alert()
        receipt = await sender.send_exact(
            alert,
            "+2340000000",
            channel="whatsapp",
        )

        assert receipt.accepted is False
        whatsapp.submit.assert_awaited_once_with(
            alert=alert,
            to_number="whatsapp:+2340000000",
        )
        sms.submit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_exact_skips_unavailable_channel(self):
        sms = AsyncMock()
        sms.submit = AsyncMock()
        whatsapp = AsyncMock()
        whatsapp.submit = AsyncMock()
        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        sender.update_capability_posture(
            CapabilityPosture(
                sms_available=True,
                whatsapp_available=True,
                gateway_reachable=False,
                local_slm_loaded=False,
                relay_connected=False,
                internet_available=False,
                checked_at_ms=1,
                expires_at_ms=2,
            )
        )

        receipt = await sender.send_exact(
            self._alert(), "+2340000000", channel="whatsapp"
        )

        assert receipt.accepted is False
        whatsapp.submit.assert_not_awaited()
        sms.submit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_normalizes_contact_per_channel(self):
        sms = AsyncMock()
        sms.submit = AsyncMock(return_value=AlertSendReceipt.refused(channel="sms"))
        whatsapp = AsyncMock()
        whatsapp.submit = AsyncMock(
            return_value=AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )
        )

        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        alert = self._alert()
        receipt = await sender.send(alert, "+2340000000")
        assert receipt.accepted is True
        whatsapp.submit.assert_awaited_once_with(
            alert=alert,
            to_number="whatsapp:+2340000000",
        )

    @pytest.mark.asyncio
    async def test_send_skips_whatsapp_when_internet_unavailable(self):
        sms = AsyncMock()
        sms.submit = AsyncMock(
            return_value=AlertSendReceipt.accepted_without_provider_receipt(
                channel="sms"
            )
        )
        whatsapp = AsyncMock()
        whatsapp.submit = AsyncMock(
            return_value=AlertSendReceipt.accepted_without_provider_receipt(
                channel="whatsapp"
            )
        )
        sender = AlertFailoverSender(
            primary_channel="whatsapp",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        sender.update_capability_posture(
            CapabilityPosture(
                sms_available=True,
                whatsapp_available=True,
                gateway_reachable=False,
                local_slm_loaded=False,
                relay_connected=False,
                internet_available=False,
                checked_at_ms=1,
                expires_at_ms=2,
            )
        )

        receipt = await sender.send(self._alert(), "+2340000000")
        assert receipt.accepted is True
        whatsapp.submit.assert_not_awaited()
        sms.submit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_listen_returns_first_non_none_response(self):
        sms = AsyncMock()
        sms.listen_for_response = AsyncMock(return_value=None)
        whatsapp = AsyncMock()
        whatsapp.listen_for_response = AsyncMock(return_value="YES")

        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        response = await sender.listen_for_response(
            from_number="+2340000000",
            timeout_seconds=3,
        )
        assert response == "YES"
        sms.listen_for_response.assert_awaited_once()
        whatsapp.listen_for_response.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_listen_without_compatible_senders_returns_none(self):
        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=object(),
            whatsapp_sender=object(),
        )
        response = await sender.listen_for_response(
            from_number="+2340000000",
            timeout_seconds=1,
        )
        assert response is None

    @pytest.mark.asyncio
    async def test_delivery_receipt_is_fetched_from_the_accepted_channel(self):
        sms = AsyncMock()
        whatsapp = AsyncMock()
        whatsapp.get_delivery_receipt = AsyncMock(return_value=None)
        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )

        receipt = await sender.get_delivery_receipt(
            channel="whatsapp",
            provider_message_id="SM" + "a" * 32,
        )

        assert receipt is None
        whatsapp.get_delivery_receipt.assert_awaited_once_with("SM" + "a" * 32)
        sms.get_delivery_receipt.assert_not_awaited()
