# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Which firmware identities must have no retained provisioning approval."""

from __future__ import annotations

import sqlite3

from ori.state._core import StoreCore


class FirmwareProvisioningStore(StoreCore):
    """The read behind clearing the retained approvals of withdrawn identities."""

    async def list_firmware_devices_revoked_or_unpromoted(self) -> list[str]:
        """Every registered identity revoked, or not promoted since it was
        registered or reinstated: none may have an approval retained
        (firmware-commands/v2, Provisioning Approval). Revocation and
        reinstatement both clear `approved`; only a promotion sets it."""
        return await self._run_read(self._revoked_or_unpromoted_sync)

    def _revoked_or_unpromoted_sync(self, conn: sqlite3.Connection) -> list[str]:
        # `revoked = 1` adds nothing while revocation also clears `approved`;
        # it keeps a revoked identity listed if that ever changes.
        rows = conn.execute(
            "SELECT device_id FROM firmware_device_registry "
            "WHERE revoked = 1 OR approved = 0 ORDER BY device_id"
        ).fetchall()
        return [str(row[0]) for row in rows]
