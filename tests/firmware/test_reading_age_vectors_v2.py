# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""firmware-telemetry/v2 reading-age-vectors-v2 through the signing runtime's own path.

Every ``v`` 2 signing event goes through ``FirmwareLivenessSigner`` with the
case's nonce as its random source and the case's instant as its clock, so the
table is filled exactly as production fills it. Every acceptance goes through
the tracker the ingest gate calls, and every query is answered by the age
computation the operator message and health use, on the tracker's clock.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from ori.security.firmware.liveness import (
    FirmwareLivenessSigner,
    FirmwareLivenessSupervisor,
)
from ori.security.firmware.reading_age import (
    RETENTION_NS,
    LivenessTable,
    ReadingAgeTracker,
)

VECTOR_PATH = (
    Path(__file__).parent.parent
    / "vectors"
    / "firmware_telemetry"
    / "reading-age-vectors-v2.json"
)
SPEC_DECLARED_SHA256 = (
    "909ef412cec0da86683aea72c2fdd430ce4797089166750f97c3c72db3696d83"
)
VECTORS = json.loads(VECTOR_PATH.read_text())
CASES = VECTORS["cases"]
SIGNING_SEED = bytes([0x11]) * 32
# The corpus names messages by (boot_id, seq) under one device key throughout.
CORPUS_EPOCH = "corpus-key-epoch"


def test_the_vendored_corpus_is_the_one_the_contract_pins() -> None:
    assert hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest() == SPEC_DECLARED_SHA256


def test_retention_is_the_contracts_hour() -> None:
    assert VECTORS["retention_ns"] == RETENTION_NS


class _Runtime:
    """One process of the signing runtime: a table, a signer and a tracker on one clock."""

    def __init__(self, case: dict[str, Any], clock: list[int | None]) -> None:
        self.clock = clock
        self.table = LivenessTable(
            per_device_bound=case["per_device_bound"], total_bound=case["total_bound"]
        )
        self.nonce = b""
        self.signer = FirmwareLivenessSigner(
            None,
            SIGNING_SEED,
            supervisor=FirmwareLivenessSupervisor(),
            table=self.table,
            nonce_source=lambda: self.nonce,
            clock=lambda: self.clock[0],
        )
        self.tracker = ReadingAgeTracker(self.table, clock=lambda: self.clock[0])

    def sign(self, event: dict[str, Any], *, fails: bool) -> None:
        self.nonce = bytes.fromhex(event["nonce"])
        self.clock[0] = event["t_ns"]
        if not fails:
            self.signer.sign_liveness_v2_bytes(
                device_id=event["device_id"],
                boot_id=event["boot_id"],
                capability_hash=event["capability_hash"],
                runtime_seq=event["runtime_seq"],
            )
            return

        def broken(_liveness: bytes) -> bytes:
            raise RuntimeError("signing failed")

        self.signer.sign_liveness_bytes = broken  # type: ignore[method-assign]
        try:
            with pytest.raises(RuntimeError, match="signing failed"):
                self.signer.sign_liveness_v2_bytes(
                    device_id=event["device_id"],
                    boot_id=event["boot_id"],
                    capability_hash=event["capability_hash"],
                    runtime_seq=event["runtime_seq"],
                )
        finally:
            del self.signer.sign_liveness_bytes


def _answer(age_ns: int | None) -> dict[str, Any]:
    if age_ns is None:
        return {"bound": "none"}
    return {
        "bound": "upper",
        "age_upper_ns": age_ns,
        "age_upper_ms_rounded_up": -(-age_ns // 1_000_000),
    }


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_every_query_is_reproduced(case: dict[str, Any]) -> None:
    clock: list[int | None] = [0]
    runtime = _Runtime(case, clock)
    queries = 0
    for event in case["events"]:
        kind = event["kind"]
        if kind == "sign_liveness":
            runtime.sign(event, fails=False)
        elif kind == "sign_failed":
            runtime.sign(event, fails=True)
        elif kind == "sign_liveness_v1":
            # Carries no nonce and records nothing: the table is untouched.
            before = len(runtime.table)
            clock[0] = event["t_ns"]
            assert len(runtime.table) == before
        elif kind == "accept":
            clock[0] = event["t_ns"]
            runtime.tracker.note_accepted(
                version=event["v"],
                device_id=event["device_id"],
                boot_id=event["boot_id"],
                capability_hash=event["capability_hash"],
                seq=event["seq"],
                channels=event["channels"],
                liveness_nonce=event.get("liveness_nonce"),
                key_epoch_id=CORPUS_EPOCH,
            )
        elif kind == "restart":
            runtime = _Runtime(case, clock)
        elif kind in ("store_restore", "suspend"):
            # Neither touches memory: the table is never persisted, and the
            # clock counts suspended time, so each event's t_ns already does.
            clock[0] = event.get("resume_t_ns", event["t_ns"])
        elif kind == "query":
            clock[0] = event["t_ns"]
            queries += 1
            expected = event["expected"]
            if "message" in event:
                message = event["message"]
                age = runtime.tracker.message_age_ns(
                    message["device_id"],
                    CORPUS_EPOCH,
                    message["boot_id"],
                    message["seq"],
                )
                assert _answer(age) == expected, event
            else:
                channel = event["channel"]
                latest = runtime.tracker.channel_latest(
                    channel["device_id"], channel["channel"]
                )
                assert (
                    None if latest is None else {"boot_id": latest[0], "seq": latest[1]}
                ) == expected["latest"], event
                age = runtime.tracker.channel_age_ns(
                    channel["device_id"], channel["channel"]
                )
                assert {"latest": expected["latest"], **_answer(age)} == expected, event
        else:
            raise AssertionError(f"unknown event kind {kind!r}")
    assert queries, "a case with no query proves nothing"


def test_every_event_kind_the_corpus_declares_is_driven() -> None:
    declared = set(VECTORS["event_kinds"])
    used = {event["kind"] for case in CASES for event in case["events"]}
    assert used == declared
