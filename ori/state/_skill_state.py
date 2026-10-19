# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Per-skill persistent state."""

import sqlite3
from typing import Optional

from ori.state._core import StoreCore
from ori.utils.time_utils import now_ms


class SkillStateStore(StoreCore):
    """Per-skill persistent state."""

    async def get_skill_state(self, skill_name: str, key: str) -> Optional[str]:
        return await self._run_read(self._get_skill_state_sync, skill_name, key)

    def hooks_get_skill_state(self, skill_name: str, key: str) -> Optional[str]:
        """Stable sync facade for hook skill-state reads."""
        return self._run_hook(self._get_skill_state_sync, skill_name, key)

    def _get_skill_state_sync(
        self, conn: sqlite3.Connection, skill_name: str, key: str
    ) -> Optional[str]:
        row = conn.execute(
            """
            SELECT value FROM skill_state
            WHERE skill_name = ? AND key = ?
            """,
            (skill_name, key),
        ).fetchone()
        return row["value"] if row else None

    async def set_skill_state(self, skill_name: str, key: str, value: str) -> None:
        await self._run_write(self._set_skill_state_sync, skill_name, key, value)

    def hooks_set_skill_state(self, skill_name: str, key: str, value: str) -> None:
        """Stable sync facade for hook skill-state writes, on the hooks' connection."""
        self._run_hook(self._set_skill_state_on, skill_name, key, value)

    def _set_skill_state_sync(self, skill_name: str, key: str, value: str) -> None:
        assert self._conn is not None
        self._set_skill_state_on(self._conn, skill_name, key, value)

    @staticmethod
    def _set_skill_state_on(
        conn: sqlite3.Connection, skill_name: str, key: str, value: str
    ) -> None:
        conn.execute(
            """
            INSERT INTO skill_state (skill_name, key, value, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(skill_name, key) DO UPDATE SET
                value      = excluded.value,
                updated_at = excluded.updated_at
            """,
            (skill_name, key, value, now_ms()),
        )
        conn.commit()
