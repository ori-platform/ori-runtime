# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import AsyncMock

import pytest

from ori.actions.alert_failover import AlertFailoverSender
from ori.reasoning.capability_posture import CapabilityPosture


class TestAlertFailoverSender:
    @pytest.mark.asyncio
    async def test_send_uses_primary_first(self):
        sms = AsyncMock()
        sms.send = AsyncMock(return_value=True)
        whatsapp = AsyncMock()
        whatsapp.send = AsyncMock(return_value=True)

        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        ok = await sender.send("hello", "+2340000000")
        assert ok is True
        sms.send.assert_awaited_once()
        whatsapp.send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_falls_back_to_secondary(self):
        sms = AsyncMock()
        sms.send = AsyncMock(return_value=False)
        whatsapp = AsyncMock()
        whatsapp.send = AsyncMock(return_value=True)

        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        ok = await sender.send("hello", "+2340000000")
        assert ok is True
        sms.send.assert_awaited_once()
        whatsapp.send.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_respects_preferred_channel_override(self):
        sms = AsyncMock()
        sms.send = AsyncMock(return_value=True)
        whatsapp = AsyncMock()
        whatsapp.send = AsyncMock(return_value=True)

        sender = AlertFailoverSender(
            primary_channel="sms",
            sms_sender=sms,
            whatsapp_sender=whatsapp,
        )
        ok = await sender.send("hello", "+2340000000", preferred_channel="whatsapp")
        assert ok is True
        whatsapp.send.assert_awaited_once()
        sms.send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_skips_whatsapp_when_internet_unavailable(self):
        sms = AsyncMock()
        sms.send = AsyncMock(return_value=True)
        whatsapp = AsyncMock()
        whatsapp.send = AsyncMock(return_value=True)
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

        ok = await sender.send("hello", "+2340000000")
        assert ok is True
        whatsapp.send.assert_not_awaited()
        sms.send.assert_awaited_once()

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
