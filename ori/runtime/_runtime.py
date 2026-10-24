# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""``OriRuntime``: wires every component into a running system and runs it."""

from ori.runtime._alerts import AlertDelivery
from ori.runtime._commissioning import Commissioning
from ori.runtime._device_policy import DevicePolicyRefresh
from ori.runtime._evidence import EvidenceLoops
from ori.runtime._firmware import FirmwareCommands
from ori.runtime._health import HealthSnapshot
from ori.runtime._loops import BackgroundLoops
from ori.runtime._measurement import MeasurementSupervision
from ori.runtime._remote_commands import RemoteCommands
from ori.runtime._sensors import SensorPolling
from ori.runtime._services import OperatorServices
from ori.runtime._shutdown import Shutdown
from ori.runtime._skills import SkillReload
from ori.runtime._startup import StartupStages
from ori.runtime._startup_foundation import StartupFoundation


class OriRuntime(
    StartupStages,
    Shutdown,
    OperatorServices,
    HealthSnapshot,
    StartupFoundation,
    Commissioning,
    RemoteCommands,
    DevicePolicyRefresh,
    SensorPolling,
    MeasurementSupervision,
    AlertDelivery,
    EvidenceLoops,
    FirmwareCommands,
    SkillReload,
    BackgroundLoops,
):
    """Main runtime class. Wires all Ori components and manages the event loop.

    Args:
        config_path: Path to ``ori.yaml``. Defaults to ``"ori.yaml"`` in the
            current working directory.
    """
