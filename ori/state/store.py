# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The state store: one SQLite database, composed from one class per domain."""

from ori.state._action_records import _check_action_record_shape
from ori.state._actions import ActionLogStore
from ori.state._alerts import AlertOutboxStore
from ori.state._approvers import ApproverStore
from ori.state._commissioning import CommissioningStore
from ori.state._core import (
    _READ_WORKERS,
    HOOK_BUSY_TIMEOUT_S,
    MINIMUM_SQLITE_VERSION,
    UnsupportedSQLiteError,
    require_supported_sqlite,
)
from ori.state._device_policy import DevicePolicyCacheStore
from ori.state._firmware import (
    FIRMWARE_ANCHOR_COLUMNS,
    FirmwareStore,
)
from ori.state._history import (
    RAW_HISTORY_RETENTION_MS,
    RECEIPT_READ_TOLERANCE_MS,
    HistoryStore,
)
from ori.state._measurement import MeasurementStore
from ori.state._migrations import (
    EVIDENCE_REFERENCE_DDL,
    HistoryReceiptMigrationRequiredError,
    _table_columns,
)
from ori.state._reasoning import ReasoningStore
from ori.state._remote_commands import RemoteCommandStore
from ori.state._skill_state import SkillStateStore
from ori.state._tier_c import (
    _TIER_C_DECISION_STATES,
    TierCStore,
)
from ori.state._trip_journal import TripJournal

__all__ = [
    "EVIDENCE_REFERENCE_DDL",
    "FIRMWARE_ANCHOR_COLUMNS",
    "HOOK_BUSY_TIMEOUT_S",
    "HistoryReceiptMigrationRequiredError",
    "MINIMUM_SQLITE_VERSION",
    "RAW_HISTORY_RETENTION_MS",
    "RECEIPT_READ_TOLERANCE_MS",
    "StateStore",
    "TripJournal",
    "UnsupportedSQLiteError",
    "_READ_WORKERS",
    "_TIER_C_DECISION_STATES",
    "_check_action_record_shape",
    "_table_columns",
    "require_supported_sqlite",
]


class StateStore(
    HistoryStore,
    ActionLogStore,
    TierCStore,
    RemoteCommandStore,
    AlertOutboxStore,
    FirmwareStore,
    CommissioningStore,
    DevicePolicyCacheStore,
    ReasoningStore,
    MeasurementStore,
    SkillStateStore,
    ApproverStore,
):
    """Async-safe SQLite state store.

    All blocking SQLite calls are dispatched to a thread-pool executor so the
    asyncio event loop is never blocked.
    """
