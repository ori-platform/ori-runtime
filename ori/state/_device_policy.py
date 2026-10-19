# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The signed device policy cache."""

import sqlite3

from ori.state._core import StoreCore
from ori.utils.time_utils import now_ms


class DevicePolicyCacheStore(StoreCore):
    """The signed device policy cache."""

    async def upsert_device_policy_cache(
        self,
        *,
        policy_version: int,
        tier: str,
        relay_b_enabled: bool,
        relay_c_enabled: bool,
        cloud_llm_enabled: bool,
        valid_until: int,
        issued_at: int,
        signature: str,
        raw_payload: str,
        cached_at_ms: int | None = None,
    ) -> None:
        await self._run_write(
            self._upsert_device_policy_cache_sync,
            policy_version,
            tier,
            relay_b_enabled,
            relay_c_enabled,
            cloud_llm_enabled,
            valid_until,
            issued_at,
            signature,
            raw_payload,
            cached_at_ms if cached_at_ms is not None else now_ms(),
        )

    def _upsert_device_policy_cache_sync(
        self,
        policy_version: int,
        tier: str,
        relay_b_enabled: bool,
        relay_c_enabled: bool,
        cloud_llm_enabled: bool,
        valid_until: int,
        issued_at: int,
        signature: str,
        raw_payload: str,
        cached_at_ms: int,
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO device_policy_cache
                (policy_version, tier, relay_b_enabled, relay_c_enabled, cloud_llm_enabled,
                 valid_until, issued_at, signature, raw_payload, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(policy_version) DO UPDATE SET
                tier = excluded.tier,
                relay_b_enabled = excluded.relay_b_enabled,
                relay_c_enabled = excluded.relay_c_enabled,
                cloud_llm_enabled = excluded.cloud_llm_enabled,
                valid_until = excluded.valid_until,
                issued_at = excluded.issued_at,
                signature = excluded.signature,
                raw_payload = excluded.raw_payload,
                cached_at = excluded.cached_at
            """,
            (
                int(policy_version),
                tier,
                1 if relay_b_enabled else 0,
                1 if relay_c_enabled else 0,
                1 if cloud_llm_enabled else 0,
                int(valid_until),
                int(issued_at),
                signature,
                raw_payload,
                int(cached_at_ms),
            ),
        )
        self._conn.commit()

    async def get_latest_device_policy_cache(self) -> dict | None:
        return await self._run_read(self._get_latest_device_policy_cache_sync)

    def _get_latest_device_policy_cache_sync(
        self,
        conn: sqlite3.Connection,
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT policy_version, tier, relay_b_enabled, relay_c_enabled,
                   cloud_llm_enabled, valid_until, issued_at, signature,
                   raw_payload, cached_at
            FROM device_policy_cache
            ORDER BY policy_version DESC, cached_at DESC, id DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        return {
            "policy_version": int(row["policy_version"]),
            "tier": str(row["tier"]),
            "relay_b_enabled": bool(row["relay_b_enabled"]),
            "relay_c_enabled": bool(row["relay_c_enabled"]),
            "cloud_llm_enabled": bool(row["cloud_llm_enabled"]),
            "valid_until": int(row["valid_until"]),
            "issued_at": int(row["issued_at"]),
            "signature": str(row["signature"]),
            "raw_payload": str(row["raw_payload"]),
            "cached_at": int(row["cached_at"]),
        }
