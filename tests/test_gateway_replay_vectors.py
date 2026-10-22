# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""gateway-api/v2 replay-v2 vectors, through the real authenticator.

Each case key is a request id on a genuinely signed envelope, so a case drives
the signature, freshness, floor and held-key checks in the runtime's order.
A restart builds a new cache and authenticator on the same state file, or on
none for a receiver that stores nothing.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from ori.security import gateway_messages
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
    GatewayReplayCache,
)

#: Cases whose declared outcome is one the contract permits and this runtime
#: declines, each with what the runtime does instead, event by event. Each
#: must differ from the corpus, or it declines nothing.
DECLINED: dict[str, list[dict[str, Any]]] = {}
VECTORS = Path(__file__).parent / "vectors" / "gateway_api" / "replay-v2.json"
CORPUS = json.loads(VECTORS.read_text(encoding="utf-8"))
MESSAGE_TYPE = "export_request"
DEVICE_ID = "dev-1"
SECRETS = ("replay-vector-secret-one", "replay-vector-secret-two")


class Receiver:
    def __init__(self, context: dict[str, Any], db_path: Path) -> None:
        self.stores = bool(context["stores"])
        self.skew_ms = int(context["skew_ms"])
        ttl = context["replay_ttl_ms"]
        # No setting: retention ends once the envelope is stale, which a
        # one-millisecond window from receipt never outlasts.
        self.ttl_ms = 1 if ttl is None else int(ttl)
        self.db_path = db_path
        self.secret_index = 0
        self.previous: str = ""
        self.blocker: sqlite3.Connection | None = None
        if self.stores or context["stored_floor_ms"] is not None:
            self._seed(context)
        self._start(int(context["start_clock_ms"]))

    def _seed(self, context: dict[str, Any]) -> None:
        seeding = GatewayMessageAuthenticator(
            self._config(), replay_cache=self._cache(start_ms=0, stores=True)
        )
        rows = []
        for held in context["held"]:
            envelope = self.envelope(seeding, held["key"], held["signed_at_ms"])
            signature = envelope["auth"]["signature"]
            key = "\n".join(
                [
                    MESSAGE_TYPE,
                    DEVICE_ID,
                    held["key"],
                    str(held["signed_at_ms"]),
                    signature,
                ]
            )
            # As a release that kept no floor wrote them: key and expiry only.
            rows.append((key, int(held["received_at_ms"]) + self.ttl_ms))
        conn = sqlite3.connect(self.db_path)
        with conn:
            conn.executemany(
                "INSERT INTO gateway_replay_cache (key, seen_until_ms) VALUES (?, ?)",
                rows,
            )
            conn.execute(
                "INSERT OR REPLACE INTO gateway_replay_floor (id, floor_ms) "
                "VALUES (1, ?)",
                (context["stored_floor_ms"],),
            )
        conn.close()
        self._close(seeding)

    def _config(self) -> GatewayMessageAuthConfig:
        return GatewayMessageAuthConfig(
            shared_secret=SECRETS[self.secret_index],
            previous_shared_secret=self.previous,
            max_skew_ms=self.skew_ms,
            replay_ttl_ms=self.ttl_ms,
        )

    def _cache(
        self, *, start_ms: int, stores: bool | None = None
    ) -> GatewayReplayCache:
        return GatewayReplayCache(
            ttl_ms=self.ttl_ms,
            max_skew_ms=self.skew_ms,
            db_path=str(self.db_path),
            stores=self.stores if stores is None else stores,
            start_ms=start_ms,
        )

    def floor_unreadable(self) -> None:
        """A real fault: another connection holds the store's exclusive lock,
        and the receiver's next look at its store finds it so."""
        self.blocker = sqlite3.connect(self.db_path, isolation_level=None)
        self.blocker.execute("BEGIN EXCLUSIVE")
        assert not self.cache.refresh()

    def floor_read(self) -> None:
        assert self.blocker is not None
        self.blocker.execute("ROLLBACK")
        self.blocker.close()
        self.blocker = None
        assert self.cache.refresh()

    def _start(self, start_ms: int) -> None:
        self.cache = self._cache(start_ms=start_ms)
        self.auth = GatewayMessageAuthenticator(self._config(), replay_cache=self.cache)

    @staticmethod
    def _close(auth: GatewayMessageAuthenticator) -> None:
        # A restart: the store has one owner, so the last run lets it go.
        auth._replay_cache.close()

    def restart(self, t: int, skew_ms: int | None) -> None:
        self._close(self.auth)
        if skew_ms is not None:
            self.skew_ms = int(skew_ms)
        self._start(t)

    def rotate(self, t: int, keeps_previous: bool) -> None:
        self._close(self.auth)
        self.previous = SECRETS[self.secret_index] if keeps_previous else ""
        self.secret_index = 1 - self.secret_index
        self._start(t)

    @staticmethod
    def envelope(
        auth: GatewayMessageAuthenticator, name: str, signed_at_ms: int
    ) -> dict[str, Any]:
        return auth.sign(
            {"device_id": DEVICE_ID, "request_id": name},
            message_type=MESSAGE_TYPE,
            signed_at_ms=signed_at_ms,
        )

    def held(self) -> list[str]:
        return sorted(key.split("\n")[2] for key in self.cache._held)


def _reason(action: Any) -> str | None:
    try:
        action()
    except GatewayMessageAuthError as exc:
        return str(exc)
    return None


@pytest.fixture(autouse=True)
def _bounded_store_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    # A locked store answers within the bound; a short one keeps cases fast.
    monkeypatch.setattr(gateway_messages, "_STORE_BUSY_TIMEOUT_MS", 20)


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda case: case["name"])
def test_every_replay_case(case: dict[str, Any], tmp_path: Path) -> None:
    receiver = Receiver(case["context"], tmp_path / "state.db")
    declined = DECLINED.get(case["name"])
    handles: dict[str, Any] = {}
    for index, event in enumerate(case["events"]):
        kind = event["event"]
        t = int(event["t"])
        expected = event["expected"] if declined is None else declined[index]
        reason: str | None = None
        if kind == "receive":
            payload = receiver.envelope(
                receiver.auth, event["key"], event["signed_at_ms"]
            )
            reason = _reason(
                lambda: receiver.auth.verify(
                    payload,
                    message_type=MESSAGE_TYPE,
                    expected_device_id=DEVICE_ID,
                    now_ms_value=t,
                )
            )
        elif kind == "authenticate":
            payload = receiver.envelope(
                receiver.auth, event["key"], event["signed_at_ms"]
            )

            def authenticate() -> None:
                handles[event["handle"]] = receiver.auth.authenticate(
                    payload,
                    message_type=MESSAGE_TYPE,
                    expected_device_id=DEVICE_ID,
                    now_ms_value=t,
                )

            reason = _reason(authenticate)
        elif kind == "commit":
            message = handles[event["handle"]]
            reason = _reason(lambda: receiver.auth.commit(message, now_ms_value=t))
        elif kind == "prune":
            receiver.cache.prune(t)
        elif kind == "evict":
            receiver.cache.evict_one()
        elif kind == "restart":
            receiver.restart(t, event.get("skew_ms"))
        elif kind == "rotate":
            receiver.rotate(t, bool(event["keeps_previous"]))
        elif kind == "floor_unreadable":
            receiver.floor_unreadable()
        elif kind == "floor_read":
            receiver.floor_read()
        else:
            raise AssertionError(f"unknown event {kind!r}")
        where = f"{case['name']} event {index} ({kind} at {t})"
        if "reason" in expected:
            assert reason == expected["reason"], where
        assert receiver.cache.floor_ms() == expected["floor_ms"], where
        assert receiver.held() == sorted(expected["held"]), where
    if receiver.blocker is not None:
        receiver.blocker.close()
    receiver.cache.close()


def test_the_corpus_names_every_event_kind_this_replays() -> None:
    kinds = {event["event"] for case in CORPUS["cases"] for event in case["events"]}
    assert kinds == {
        "receive",
        "authenticate",
        "commit",
        "prune",
        "evict",
        "restart",
        "rotate",
        "floor_unreadable",
        "floor_read",
    }
    assert set(CORPUS["reasons"]) == {
        "stale_timestamp",
        "future_timestamp",
        "before_replay_floor",
        "replay_detected",
    }


def test_every_declined_case_is_in_the_corpus_and_covers_its_events() -> None:
    cases = {case["name"]: case for case in CORPUS["cases"]}
    for name, outcomes in DECLINED.items():
        assert len(outcomes) == len(cases[name]["events"]), name
        declared = [event["expected"] for event in cases[name]["events"]]
        assert outcomes != declared, f"{name} declines nothing the corpus declares"
