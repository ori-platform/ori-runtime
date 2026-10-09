# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A firmware anchor decision holds the database's write lock from its first read.

Each writer reads the registry and the anchors, decides, then writes. Another
connection to the same file must not be able to change what was read before
the write lands, or a promotion could activate a candidate that was replaced or
a device that was revoked in between.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from ori.state.store import StateStore
from tests.firmware.test_manifest_device_mode import (
    ACTION,
    DEVICE,
    _legacy_register,
)

REPLACE_PENDING = (
    "UPDATE firmware_device_anchors SET state = 'discarded' "
    "WHERE device_id = ? AND state = 'pending'"
)
REVOKE = "UPDATE firmware_device_registry SET revoked = 1 WHERE device_id = ?"


def _other_connection_write(db_path: str, statement: str) -> str:
    """Try one write from a separate connection, without waiting for the lock."""
    conn = sqlite3.connect(db_path, timeout=0)
    try:
        conn.execute(statement, (DEVICE,))
        conn.commit()
        return "written"
    except sqlite3.OperationalError as exc:
        return "locked" if "locked" in str(exc) else f"error: {exc}"
    finally:
        conn.close()


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


@pytest.mark.parametrize(
    "statement", [REPLACE_PENDING, REVOKE], ids=["replace", "revoke"]
)
async def test_another_connection_cannot_write_while_a_promotion_decides(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, statement: str
) -> None:
    await _legacy_register(store, approve=False, mode="mixed", actions=[ACTION])
    pending = await store.get_pending_firmware_anchor(DEVICE)
    assert pending is not None
    decide = store._approve_firmware_device_sync
    attempts: list[str] = []

    def raced(*args: Any, **kwargs: Any) -> bool:
        attempts.append(_other_connection_write(store._db_path, statement))
        return decide(*args, **kwargs)

    monkeypatch.setattr(store, "_approve_firmware_device_sync", raced)
    assert await store.approve_firmware_device(
        DEVICE,
        actor="t",
        reason="t",
        expected_anchor_epoch_id=pending["anchor_epoch_id"],
    )
    assert attempts == ["locked"]
    row = await store.get_firmware_device(DEVICE)
    assert row is not None
    assert row["approved"] and not row["revoked"]
    assert row["anchor_epoch_id"] == pending["anchor_epoch_id"]


async def test_a_revocation_after_the_promotion_commits_still_takes_effect(
    store: StateStore,
) -> None:
    await _legacy_register(store, approve=False, mode="mixed", actions=[ACTION])
    assert await store.approve_firmware_device(DEVICE, actor="t", reason="t")
    assert _other_connection_write(store._db_path, REVOKE) == "written"
    row = await store.get_firmware_device(DEVICE)
    assert row is not None
    assert row["revoked"]


@pytest.mark.parametrize(
    "writer",
    [
        "_upsert_firmware_device_anchor_sync",
        "_revoke_firmware_device_sync",
        "_reinstate_firmware_device_sync",
        "_reprovision_firmware_device_sync",
    ],
)
async def test_every_anchor_writer_decides_under_the_write_lock(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, writer: str
) -> None:
    await _legacy_register(store, approve=True, mode="mixed", actions=[ACTION])
    decide = getattr(store, writer)
    attempts: list[str] = []

    def raced(*args: Any, **kwargs: Any) -> Any:
        attempts.append(_other_connection_write(store._db_path, REVOKE))
        return decide(*args, **kwargs)

    monkeypatch.setattr(store, writer, raced)
    public = (await store.get_firmware_device(DEVICE) or {})["public_key_b64"]
    calls = {
        "_upsert_firmware_device_anchor_sync": lambda: (
            store.upsert_firmware_device_anchor(
                device_id=DEVICE,
                public_key_b64=public,
                posture="development",
                capability_hash="sha256:" + "1" * 64,
                manifest_json="{}",
                channel_map_json="{}",
            )
        ),
        "_revoke_firmware_device_sync": lambda: store.revoke_firmware_device(
            DEVICE, actor="t", reason="t"
        ),
        "_reinstate_firmware_device_sync": lambda: store.reinstate_firmware_device(
            DEVICE, actor="t", reason="t"
        ),
        "_reprovision_firmware_device_sync": lambda: store.reprovision_firmware_device(
            device_id=DEVICE,
            public_key_b64="A" * 43 + "=",
            posture="development",
            capability_hash="sha256:" + "2" * 64,
            manifest_json="{}",
            channel_map_json="{}",
            board_profile="",
            actor="t",
            reason="t",
        ),
    }
    await calls[writer]()
    assert attempts == ["locked"]
