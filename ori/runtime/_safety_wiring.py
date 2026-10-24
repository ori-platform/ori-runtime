# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The safety registry's alert sink, and the refusal of an unbound active zone."""

import logging
from typing import TYPE_CHECKING

from ori.actions.alert_failover import AlertFailoverSender
from ori.config import ConfigValidationError

if TYPE_CHECKING:
    from ori.runtime._alerts import AlertDelivery


logger = logging.getLogger("ori.runtime")


class SafetyAlertAdapter:
    """The registry's alert sink: straight to the runtime's deliver-or-queue
    path, never the dispatcher, never anything DevicePolicy can gate. The
    sender arrives late in startup; a notice raised before then is refused
    and the registry logs it."""

    def __init__(self, runtime: "AlertDelivery") -> None:
        self._runtime = runtime
        self.sender: AlertFailoverSender | None = None

    async def send(
        self, *, kind: str, zone_id: str, profile_id: str, message: str
    ) -> bool:
        if self.sender is None:
            return False
        return await self._runtime._send_or_queue_safety_alert(
            message=f"SAFETY {kind}: {message}",
            trigger_name=f"safety_{kind}",
            alert_sender=self.sender,
        )


def refuse_unbound_active_zones(unbound: list[str], *, hardened: bool) -> None:
    """Active protection needs a physical executor. A zone with an active
    profile and no bound actuator refuses a hardened start; a development
    start degrades it explicitly rather than reporting protection."""
    if not unbound:
        return
    if hardened:
        raise ConfigValidationError(
            "hardened posture refuses to start: zones with active safety "
            f"profiles have no bound executor: {', '.join(unbound)}"
        )
    logger.warning(
        "[safety] starting degraded: zones %s have active profiles and no "
        "bound executor; their profiles cannot actuate",
        unbound,
    )
