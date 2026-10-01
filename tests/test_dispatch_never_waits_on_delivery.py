# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""No delivery state can hold a Tier D act or an approved Tier C act.

Each case runs the real dispatch path -- the coordinator, the elevator, the
dispatcher and, for Tier C, the governed approval workflow with a scoped reply
and a durable decision -- against the real state store, evidence attestor,
delivery ledger, outbound courier route and inbound authority route, with
fakes only at the MQTT client and the operator's phone. The courier and the
authority then refuse, stall, overflow or go away, and every case must
dispatch as the healthy baseline does, within the same bound, with the
evidence consequence recorded beside the act rather than ahead of it.

The latency bounds are an order of magnitude under what an obstruction costs:
a held evidence or state store answers after SQLite's five-second busy
timeout, per message queued ahead, and the healthy path takes milliseconds.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.gateway import evidence_inbound, evidence_outbound
from ori.gateway.evidence_inbound import (
    ARTIFACT_RECEIPT,
    INBOUND_IN_FLIGHT_BOUND,
    EvidenceInboundRouter,
    MqttEvidenceInboundSubscriber,
)
from ori.gateway.evidence_outbound import (
    EvidenceOutboundAckRouter,
    MqttEvidenceOutboundPublisher,
    artifact_digest,
)
from ori.network.events import OriEvent, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.dispatch_coordinator import DispatchCoordinator
from ori.reasoning.dispatch_plan import (
    CLOSE_PROTECTED_CIRCUIT,
    OPEN_PROTECTED_CIRCUIT,
    BindingView,
)
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.resource_gate import ResourceGate
from ori.reasoning.tier_c_admission import TierCAuthorityFacts
from ori.security.evidence import first_party
from ori.security.evidence.authority_keys import (
    PURPOSE_RECEIPT,
    STATUS_ACTIVE,
    AuthorityKey,
    derive_key_id,
)
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.evidence.ingest import RECEIPT_DOMAIN
from ori.security.evidence.registration import CONFIRMATION_OVERDUE_MS
from ori.skills.loader import Trigger
from ori.state.store import StateStore

DEVICE = "dev-01"
REFERENCE = "sha256:" + "ab" * 32
RECEIPT_SEED = bytes(range(32))
STRANGER_SEED = bytes(range(64, 96))
ZONE = ("local_gpio", "pin:26")
BOUND = BindingView(
    zone_identity_key=ZONE,
    binding_revision="7",
    consequence_by_outcome={
        OPEN_PROTECTED_CIRCUIT: "hard",
        CLOSE_PROTECTED_CIRCUIT: "hard",
    },
)
#: Reading to executor for a trip: discovery, gate admission, the act.
_TRIP_BOUND_S = 0.25
#: The operator's scoped reply to the executor: the approval commit, admission,
#: the act. The window an already-approved act must not lose.
_APPROVED_BOUND_S = 0.25
#: Reading to executor for the whole approval round, the reply instant.
_APPROVAL_ROUND_BOUND_S = 1.0
#: How long a test waits for something that should already have happened.
_PROMPT_S = 5.0
#: A Raspberry Pi 4's default executor: min(32, cpus + 4) threads.
_PI_DEFAULT_WORKERS = 8
_DECIDED = ["proposed", "approved_pending_dispatch", "dispatch_started", "executed"]


def _pub(seed: bytes) -> str:
    return (
        Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()
    )


RECEIPT_KEY_ID = derive_key_id(bytes.fromhex(_pub(RECEIPT_SEED)))


def _signed_receipt(body: dict[str, Any], seed: bytes) -> dict[str, Any]:
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(
        RECEIPT_DOMAIN + canonical_json(body)
    )
    return {**body, "signature": "ed25519:" + base64.b64encode(signature).decode()}


class _Courier:
    """The MQTT client at the transport edge, answering as the courier is told to.

    ``answer`` is ``queued``, a refusal reason, or ``silent``. ``connect_fails``
    stands for a broker that is down, ``publish_hangs`` for one that takes a
    publish and never returns.
    """

    def __init__(self, answer: str = "queued") -> None:
        self.answer = answer
        self.connect_fails = False
        self.publish_hangs = False
        self.release = threading.Event()
        self.published_types: set[str] = set()
        self.on_connect: Any = None
        self.on_subscribe: Any = None
        self.on_disconnect: Any = None
        self.on_message: Any = None

    def username_pw_set(self, *_a: Any, **_k: Any) -> None:
        pass

    def connect(self, *_a: Any, **_k: Any) -> None:
        if self.connect_fails:
            raise ConnectionRefusedError("broker down")

    def loop_start(self) -> None:
        self.on_connect(self, None, None, 0)

    def subscribe(self, _topic: str, qos: int = 0) -> tuple[int, int]:
        self.on_subscribe(self, None, 1, [1], None)
        return (0, 1)

    def publish(self, topic: str, payload: bytes, qos: int = 0) -> None:
        if self.publish_hangs:
            self.release.wait()
            return
        if topic.endswith("/ack"):
            return
        carriage = json.loads(payload)
        self.published_types.add(carriage["artifact_type"])
        if self.answer == "silent":
            return
        ack: dict[str, Any] = {
            "device_id": DEVICE,
            "artifact_type": carriage["artifact_type"],
            "artifact_digest": artifact_digest(
                base64.b64decode(carriage["artifact_b64"])
            ),
            "outcome": "queued" if self.answer == "queued" else "refused",
            "reason": "" if self.answer == "queued" else self.answer,
        }
        self.on_message(self, None, SimpleNamespace(payload=json.dumps(ack).encode()))

    def loop_stop(self) -> None:
        pass

    def disconnect(self) -> None:
        pass


class _Phone:
    """The operator: sends on a worker thread, as SMS delivery does, and says YES."""

    def __init__(self) -> None:
        self.proposals: list[str] = []
        self.replied_at: list[float] = []

    async def send(self, *, alert: Any, to_number: str) -> bool:
        await asyncio.to_thread(self.record, alert)
        return True

    def record(self, alert: Any) -> None:
        if alert.intent.value == "tier_c_approval":
            self.proposals.append(str(alert.template_variables[3]))

    async def listen_for_response(
        self, *, from_number: str, timeout_seconds: int
    ) -> str | None:
        while not self.proposals:
            await asyncio.sleep(0.002)
        self.replied_at.append(time.monotonic())
        return f"YES-{self.proposals[-1]}"


class _Skill:
    def __init__(
        self, name: str, sensor_type: str, triggers: list[Any], actions: dict
    ) -> None:
        self.name = name
        self.version = "1.0.0"
        self.config: dict[str, Any] = {}
        self.hooks: Any = None
        self.first_party = True
        self.sensors_required = [{"type": sensor_type}]
        self.triggers = triggers
        self.actions = actions

    def get_default_actions(self, _sensor_type: str) -> list[str]:
        return []


def _protector() -> _Skill:
    """A trip, and a notice that reads history, in one skill, as shipped."""
    return _Skill(
        "protector",
        "current_clamp",
        [
            Trigger(
                name="trip",
                condition="value > 3.0",
                action_tier="D",
                bypass_llm=True,
                cooldown_seconds=0,
            ),
            Trigger(
                name="drift",
                condition="value > history.avg_24h('load-current') * 1.4",
                action_tier="A",
                cooldown_seconds=0,
            ),
        ],
        {
            "available": [{"name": "trip_relay", "tier": "D"}],
            "defaults": {"trip": ["trip_relay"], "drift": []},
        },
    )


def _isolator() -> _Skill:
    """An isolation the operator approves: governed Tier C on the zone."""
    return _Skill(
        "isolator",
        "current",
        [
            Trigger(
                name="isolate",
                condition="value > 3.0",
                action_tier="C",
                escalate_to="rule",
                cooldown_seconds=0,
                approval_timeout_seconds=30,
                safe_default_action="log_to_dashboard",
            )
        ],
        {
            "available": [
                {"name": "trip_relay", "tier": "C"},
                {"name": "log_to_dashboard", "tier": "A"},
            ],
            "defaults": {"isolate": ["trip_relay"]},
        },
    )


def _event(sensor_type: str) -> OriEvent:
    reading = SensorReading(
        sensor_id="load-current",
        sensor_type=sensor_type,
        value=5.0,
        unit="ampere",
        timestamp=int(time.time() * 1000),
        quality=1.0,
    )
    return OriEvent.from_reading(reading, DEVICE)


class _Acts:
    """Executors that note when they ran."""

    def __init__(self) -> None:
        self.ran: dict[str, list[float]] = {}
        self.by_trigger: dict[str, list[tuple[str, float]]] = {}

    def executor(self, name: str) -> Any:
        self.ran[name] = []

        async def run(_action: str, context: Any, *_a: Any, **_k: Any) -> bool:
            at = time.monotonic()
            self.ran[name].append(at)
            trigger = str(getattr(context, "trigger_name", "") or "")
            self.by_trigger.setdefault(trigger, []).append((name, at))
            return True

        return run


async def _until(predicate: Any, timeout_s: float = _PROMPT_S) -> None:
    deadline = time.monotonic() + timeout_s
    while not predicate() and time.monotonic() < deadline:
        await asyncio.sleep(0.002)


def _pi_sized_default_executor() -> None:
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=_PI_DEFAULT_WORKERS)
    )


class _Site:
    """One device: store, attestor, both evidence routes, one dispatch path."""

    def __init__(self, root: Path, *, courier: _Courier) -> None:
        self.root = root
        self.courier = courier
        self.inbound_client = _Courier("silent")
        self.store = StateStore(db_path=str(root / "state.db"))
        self.attestor = FirstPartyEvidenceAttestor(
            db_path=str(root / "evidence.db"),
            key_path=str(root / "evidence.key"),
            device_secret="install-secret-for-delivery-tests",
            device_id=DEVICE,
            authority_keys={
                (PURPOSE_RECEIPT, RECEIPT_KEY_ID): AuthorityKey(
                    RECEIPT_KEY_ID, _pub(RECEIPT_SEED), PURPOSE_RECEIPT, STATUS_ACTIVE
                )
            },
        )
        self.acts = _Acts()
        self.phone = _Phone()
        self.history_reads: list[float] = []
        self._shutdown = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self.lockers: list[sqlite3.Connection] = []
        self.subscriber: MqttEvidenceInboundSubscriber | None = None
        self._flooding = threading.Event()
        self._flood: threading.Thread | None = None
        self.dispatching: asyncio.Task[Any] | None = None
        self._dispatches: list[asyncio.Task[Any]] = []

    async def open(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        await self.store.open()
        assert await self.attestor.start()
        original = self.store.avg_last_hours

        async def spied(*args: Any, **kwargs: Any) -> Any:
            self.history_reads.append(time.monotonic())
            return await original(*args, **kwargs)

        self.store.avg_last_hours = spied  # type: ignore[method-assign]
        self.dispatcher = ActionDispatcher(
            state_store=self.store,
            alert_sender=self.phone,
            evidence_attestor=self.attestor,
            config={"operator_contact": "+234800000000", "relay_enabled": True},
            authority_facts=lambda zone_id=None: TierCAuthorityFacts(
                zone_id="zone-a",
                zone_document={"zone_id": "zone-a", "identity": {"gpio_pin": 26}},
                binding_digest="sha256:" + "b" * 64,
                safety_profile_digest="",
                resource_for={
                    OPEN_PROTECTED_CIRCUIT: "relay-gpio-26",
                    CLOSE_PROTECTED_CIRCUIT: "relay-gpio-26",
                },
                deployment_inputs={},
            ),
        )
        gate = ResourceGate()
        self.dispatcher.bind_resource_gate(gate, BOUND)
        for action in ("trip_relay", "log_to_dashboard"):
            self.dispatcher.register_executor(action, self.acts.executor(action))
        self.coordinator = DispatchCoordinator(
            elevator=IntelligenceElevator(),
            dispatcher=self.dispatcher,
            state_store=self.store,
            gate=gate,
        )
        self.coordinator.set_binding(BOUND)
        self.coordinator.add_skill(_protector())
        self.coordinator.add_skill(_isolator())

    async def start_routes(self) -> None:
        outbox = self.attestor.outbound
        ingest = self.attestor.ingest
        assert outbox is not None and ingest is not None
        self.publisher = MqttEvidenceOutboundPublisher(
            broker_url="mqtt://127.0.0.1:1883",
            router=EvidenceOutboundAckRouter(device_id=DEVICE, outbox=outbox),
            device_id=DEVICE,
            outbox=outbox,
            client_factory=lambda **_k: self.courier,
            retry_interval_s=1.0,
        )
        self.subscriber = MqttEvidenceInboundSubscriber(
            broker_url="mqtt://127.0.0.1:1883",
            router=EvidenceInboundRouter(device_id=DEVICE, ingest=ingest),
            device_id=DEVICE,
            client_factory=lambda **_k: self.inbound_client,
        )
        self.attestor.set_sealed_listener(self.publisher.nudge)
        self._tasks = [
            asyncio.create_task(self.publisher.serve_until(self._shutdown)),
            asyncio.create_task(self.subscriber.serve_until(self._shutdown)),
        ]
        await asyncio.sleep(0.05)

    def deliver_inbound(self, payloads: list[bytes]) -> threading.Thread:
        """Hand messages to the inbound route from a thread, as paho does."""

        def deliver() -> None:
            for payload in payloads:
                self.inbound_client.on_message(
                    self.inbound_client, None, SimpleNamespace(payload=payload)
                )

        thread = threading.Thread(target=deliver)
        thread.start()
        return thread

    def flood_inbound(self, payload: bytes) -> None:
        """Deliver *payload* without pause until the site is released."""

        def deliver() -> None:
            while not self._flooding.is_set():
                self.inbound_client.on_message(
                    self.inbound_client, None, SimpleNamespace(payload=payload)
                )
                time.sleep(0.001)

        self._flood = threading.Thread(target=deliver)
        self._flood.start()

    def lock(self, name: str) -> None:
        """Take the named store's write lock from another connection."""
        locker = sqlite3.connect(str(self.root / name), isolation_level=None)
        locker.execute("BEGIN EXCLUSIVE")
        self.lockers.append(locker)

    def release(self) -> None:
        self._flooding.set()
        if self._flood is not None:
            self._flood.join(_PROMPT_S)
            self._flood = None
        for locker in self.lockers:
            locker.execute("COMMIT")
            locker.close()
        self.lockers = []
        self.courier.release.set()

    def _dispatch(self, sensor_type: str) -> None:
        # Never cancelled: an act under test is shielded, and cancelling the
        # event would wait on whatever holds it. Released and awaited at close.
        self.dispatching = asyncio.create_task(
            self.coordinator.dispatch_event(_event(sensor_type))
        )
        self._dispatches.append(self.dispatching)

    async def trip(self) -> dict[str, Any]:
        """Dispatch a trip and return once the act has run, or failed to in time."""
        ran = self.acts.ran["trip_relay"]
        before = len(ran)
        started = time.monotonic()
        self._dispatch("current_clamp")
        await _until(lambda: len(ran) > before)
        return {
            "ran": len(ran) - before,
            "after_s": ran[before] - started if len(ran) > before else None,
        }

    async def approve(self) -> dict[str, Any]:
        """Raise an approval, answer YES, and return once the act has run."""
        ran = self.acts.ran["trip_relay"]
        before = len(ran)
        started = time.monotonic()
        self._dispatch("current")
        await _until(lambda: len(ran) > before)
        executed = ran[before] if len(ran) > before else None
        return {
            "ran": len(ran) - before,
            "after_s": executed - started if executed is not None else None,
            "after_reply_s": executed - self.phone.replied_at[-1]
            if executed is not None and self.phone.replied_at
            else None,
            "safe_default_ran": len(self.acts.ran["log_to_dashboard"]),
        }

    async def decided(self) -> list[str]:
        """The latest proposal's durable decision records.

        The outcome is appended after the act, so this waits for it; read once
        nothing under test holds the store.
        """
        proposal = self.phone.proposals[-1] if self.phone.proposals else ""
        records: list[str] = []
        deadline = time.monotonic() + _PROMPT_S
        while time.monotonic() < deadline:
            records = await self.store.get_tier_c_proposal_records(proposal)
            if records == _DECIDED:
                break
            await asyncio.sleep(0.01)
        return records

    async def _finish_dispatches(self) -> None:
        if self._dispatches:
            await asyncio.wait(self._dispatches, timeout=_PROMPT_S * 3)

    async def settle(self) -> dict[str, Any]:
        """Release what was held and read the evidence consequence."""
        self.release()
        await self._finish_dispatches()
        await self.coordinator.drain(timeout=_PROMPT_S * 3)
        await self.dispatcher.drain_records(timeout=_PROMPT_S * 3)
        await asyncio.sleep(0.2)
        with sqlite3.connect(str(self.root / "evidence.db")) as ledger:
            failures = sorted(
                {
                    str(row[0])
                    for row in ledger.execute(
                        "SELECT last_failure FROM evidence_delivery_ledger"
                    )
                }
            )
        rows = await self.store.get_action_log(limit=20)
        return {
            "rows": sorted(
                (str(r["action_name"]), str(r["tier"]), int(r["executed"]))
                for r in rows
            ),
            "attestation": sorted(str(r.get("attestation_status", "")) for r in rows),
            "pending_export": await self.attestor.pending_export_count(),
            "refusals": await self.attestor.ingest_refusal_summary(),
            "delivery_failures": failures,
            "carried": sorted(self.courier.published_types),
        }

    async def close(self) -> None:
        self.release()
        await self._finish_dispatches()
        self._shutdown.set()
        for task in self._tasks:
            try:
                await asyncio.wait_for(task, _PROMPT_S)
            except (asyncio.TimeoutError, Exception):
                task.cancel()
        await self.coordinator.drain(timeout=_PROMPT_S)
        await self.dispatcher.drain_records(timeout=_PROMPT_S)
        await self.store.close()
        self.attestor.close()


@asynccontextmanager
async def _site(root: Path, *, courier: _Courier | None = None) -> AsyncIterator[_Site]:
    site = _Site(root, courier=courier or _Courier())
    await site.open()
    try:
        yield site
    finally:
        await site.close()


async def _commission(site: _Site, *, overdue: bool) -> None:
    anchor = site.attestor.anchor
    assert anchor is not None
    await site.store.record_evidence_commissioning_reference(
        device_id=DEVICE,
        anchor_epoch_id=anchor.anchor_epoch_id,
        commissioning_reference=REFERENCE,
        force=False,
        recorded_at_ms=first_party.now_ms(),
    )
    if overdue:
        sealed_at = first_party.now_ms() - CONFIRMATION_OVERDUE_MS - 60_000
        with patch.object(first_party, "now_ms", return_value=sealed_at):
            await site.attestor.reconcile_registration(REFERENCE)
    else:
        await site.attestor.reconcile_registration(REFERENCE)
    fields = await site.attestor.registration_health(first_party.now_ms())
    assert fields is not None
    assert fields["registration_status"] == "pending_confirmation"
    assert fields["registration_confirmation_overdue"] is overdue


async def _seal(site: _Site, count: int) -> None:
    """Seal *count* earlier trips straight into the chain and ledger."""
    authority = json.dumps(
        {
            "kind": "tier_d_legacy_skill",
            "skill_name": "protector",
            "skill_version": "1.0.0",
            "trigger_name": "trip",
        }
    )
    for n in range(count):
        assert await site.attestor.attest_action(
            {
                "id": 10_000 + n,
                "action_name": "trip_relay",
                "tier": "D",
                "executed": True,
                "action_taken": "trip_relay",
                "trigger_name": "trip",
                "timestamp": first_party.now_ms(),
                "authority_json": authority,
            }
        )


def _inbound(artifact_type: str, artifact: Any) -> bytes:
    return json.dumps(
        {"device_id": DEVICE, "artifact_type": artifact_type, "artifact": artifact}
    ).encode()


def _receipt(*, digest: str, seed: bytes, key_id: str) -> bytes:
    body = {
        "v": 1,
        "device_id": DEVICE,
        "from_seq": 1,
        "to_seq": 1,
        "range_digest": digest,
        "accepted_at_ms": 1787000001000,
        "key_id": key_id,
    }
    return _inbound(ARTIFACT_RECEIPT, _signed_receipt(body, seed))


#: Messages in a burst: several times the in-flight bound, and a literal, so a
#: bound raised past it fails here rather than flooding the run.
_FLOOD = 48
_MALFORMED_RECEIPT = _inbound(ARTIFACT_RECEIPT, {"v": 1})
_INBOUND_CASES: dict[str, tuple[bytes, str | None]] = {
    "receipt-binding-mismatch": (
        _receipt(
            digest="sha256:" + hashlib.sha256(b"not the sealed row").hexdigest(),
            seed=RECEIPT_SEED,
            key_id=RECEIPT_KEY_ID,
        ),
        "binding_mismatch",
    ),
    "receipt-unknown-key": (
        _receipt(
            digest="sha256:" + "0" * 64,
            seed=STRANGER_SEED,
            key_id=derive_key_id(bytes.fromhex(_pub(STRANGER_SEED))),
        ),
        "unknown_key",
    ),
    "receipt-malformed": (_MALFORMED_RECEIPT, "malformed"),
    "artifact-malformed": (_inbound(ARTIFACT_RECEIPT, ["not", "an", "object"]), None),
    "payload-unparseable": (b"\xff{not json", None),
}

#: Every delivery condition the device can be in when a trip or an approval
#: arrives.
CASES = [
    "baseline",
    "ack-refused-malformed",
    "ack-refused-binding-mismatch",
    "ack-queue-full",
    "courier-silent",
    "broker-down",
    "publish-hangs",
    "backlog",
    *(f"inbound-{name}" for name in _INBOUND_CASES),
    "registration-pending",
    "registration-overdue",
    "evidence-store-locked",
    "evidence-store-failing",
    "sustained-flood-evidence-store-locked",
]


def _courier_for(case: str) -> _Courier:
    courier = _Courier(
        {
            "ack-refused-malformed": "malformed",
            "ack-refused-binding-mismatch": "binding_mismatch",
            "ack-queue-full": "queue_full",
            "courier-silent": "silent",
            "backlog": "queue_full",
            "registration-pending": "silent",
            "registration-overdue": "silent",
        }.get(case, "queued")
    )
    courier.connect_fails = case == "broker-down"
    courier.publish_hangs = case == "publish-hangs"
    return courier


async def _prepare(site: _Site, case: str) -> threading.Thread | None:
    """Bring the site into *case*; return the inbound delivery thread if any."""
    if case == "backlog":
        # Hundreds of sealed envelopes the courier keeps refusing as full.
        await _seal(site, 300)
    if case.startswith("inbound-receipt"):
        # A sealed envelope for the receipt to name.
        await _seal(site, 1)
    if case in ("registration-pending", "registration-overdue"):
        await _commission(site, overdue=case == "registration-overdue")
    await site.start_routes()
    if case == "evidence-store-failing":
        site.attestor.close()
    if case in ("evidence-store-locked", "sustained-flood-evidence-store-locked"):
        site.lock("evidence.db")
    if case.startswith("inbound-"):
        payload, _reason = _INBOUND_CASES[case.removeprefix("inbound-")]
        return site.deliver_inbound([payload] * _FLOOD)
    if case == "sustained-flood-evidence-store-locked":
        site.flood_inbound(_MALFORMED_RECEIPT)
        await asyncio.sleep(0.2)
    return None


async def _run(case: str, root: Path) -> dict[str, Any]:
    _pi_sized_default_executor()
    async with _site(root, courier=_courier_for(case)) as site:
        delivering = await _prepare(site, case)
        tripped = await site.trip()
        approved = await site.approve()
        held_records = site.dispatcher.pending_record_count()
        approved["decided"] = await site.decided()
        if delivering is not None:
            delivering.join(_PROMPT_S)
        assert site.subscriber is not None
        shed = site.subscriber.shed_count
        consequence = await site.settle()
        return {
            "trip": tripped,
            "approved": approved,
            "evidence": consequence,
            "records_held_at_act": held_records,
            "inbound_shed": shed,
        }


@pytest.fixture(scope="module")
def baseline(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return asyncio.run(_run("baseline", tmp_path_factory.mktemp("baseline")))


def _assert_unobstructed(case: str, trip: dict, approved: dict) -> None:
    assert trip["ran"] == 1, f"{case}: the trip did not run"
    assert trip["after_s"] < _TRIP_BOUND_S, (
        f"{case}: the trip waited {trip['after_s']:.3f}s"
    )
    assert approved["ran"] == 1, f"{case}: the approved act did not run: {approved}"
    assert approved["safe_default_ran"] == 0, f"{case}: the safe default ran instead"
    assert approved["decided"] == _DECIDED, f"{case}: {approved['decided']}"
    assert approved["after_reply_s"] < _APPROVED_BOUND_S, (
        f"{case}: the approved act waited {approved['after_reply_s']:.3f}s after YES"
    )
    assert approved["after_s"] < _APPROVAL_ROUND_BOUND_S, (
        f"{case}: the approval round took {approved['after_s']:.3f}s"
    )


@pytest.mark.parametrize("case", CASES)
def test_delivery_state_never_changes_a_trip_or_an_approved_act(
    case: str, baseline: dict[str, Any], tmp_path: Path
) -> None:
    outcome = asyncio.run(_run(case, tmp_path))
    _assert_unobstructed(case, outcome["trip"], outcome["approved"])
    unchanged = ("ran", "decided", "safe_default_ran")
    assert {k: outcome["approved"][k] for k in unchanged} == {
        k: baseline["approved"][k] for k in unchanged
    }, f"{case}: the approved act dispatched differently from the baseline"
    # Both acts are recorded whatever delivery did; the record is the same.
    assert outcome["evidence"]["rows"] == baseline["evidence"]["rows"]


def test_the_baseline_seals_both_acts(baseline: dict[str, Any]) -> None:
    evidence = baseline["evidence"]
    assert evidence["rows"] == [("trip_relay", "C", 1), ("trip_relay", "D", 1)]
    assert evidence["attestation"] == ["signed", "signed"]


#: What the courier was handed, and what the ledger holds against the envelopes.
_UNDELIVERED = {
    "baseline": (["delivery_envelope"], ["None"]),
    "ack-refused-malformed": (["delivery_envelope"], ["refused"]),
    "ack-refused-binding-mismatch": (["delivery_envelope"], ["refused"]),
    "ack-queue-full": (["delivery_envelope"], ["queue_full"]),
    "courier-silent": (["delivery_envelope"], ["None"]),
    "broker-down": ([], ["None"]),
    "publish-hangs": ([], ["None"]),
    "registration-pending": (["anchor_registration", "delivery_envelope"], ["None"]),
    "registration-overdue": (["anchor_registration", "delivery_envelope"], ["None"]),
}


@pytest.mark.parametrize("case", sorted(_UNDELIVERED))
def test_an_undelivered_act_is_signed_and_left_for_export(
    case: str, tmp_path: Path
) -> None:
    """The courier's answer lands on the ledger, beside acts already signed."""
    evidence = asyncio.run(_run(case, tmp_path))["evidence"]
    carried, failures = _UNDELIVERED[case]
    assert evidence["attestation"] == ["signed", "signed"]
    assert evidence["pending_export"] >= 2
    assert evidence["carried"] == carried
    assert evidence["delivery_failures"] == failures


def test_a_backlog_the_courier_will_not_take_is_still_retained(tmp_path: Path) -> None:
    evidence = asyncio.run(_run("backlog", tmp_path))["evidence"]
    assert evidence["pending_export"] >= 302
    assert evidence["attestation"] == ["signed", "signed"]


@pytest.mark.parametrize(
    "case", ["evidence-store-locked", "sustained-flood-evidence-store-locked"]
)
def test_a_locked_evidence_store_holds_the_record_and_not_the_act(
    case: str, tmp_path: Path
) -> None:
    outcome = asyncio.run(_run(case, tmp_path))
    assert outcome["records_held_at_act"] > 0, "the store was never actually held"
    if case.startswith("sustained-flood"):
        assert outcome["inbound_shed"] > 0, "the flood never reached the bound"
    assert outcome["evidence"]["attestation"] == ["signed", "signed"]


@pytest.mark.parametrize(
    "name", [n for n, (_p, reason) in _INBOUND_CASES.items() if reason is not None]
)
def test_an_inbound_refusal_is_recorded_for_its_declared_reason(
    name: str, tmp_path: Path
) -> None:
    evidence = asyncio.run(_run(f"inbound-{name}", tmp_path))["evidence"]
    refusals = evidence["refusals"]
    assert refusals is not None and refusals["count"] >= 1
    assert refusals["last"]["reason"] == _INBOUND_CASES[name][1]


def test_a_failing_evidence_store_leaves_an_attestation_gap(tmp_path: Path) -> None:
    evidence = asyncio.run(_run("evidence-store-failing", tmp_path))["evidence"]
    assert "signed" not in evidence["attestation"]
    assert len(evidence["attestation"]) == 2


@contextmanager
def _held(executors: list[Any], count: int) -> Iterator[None]:
    """Occupy every thread of *executors* until the block ends."""
    hold = threading.Event()
    for executor in executors:
        for _ in range(count):
            executor.submit(hold.wait)
    try:
        yield
    finally:
        hold.set()


class TestATripHasNoExecutorToWaitFor:
    async def test_the_trip_runs_with_every_store_and_shared_thread_held(
        self, tmp_path: Path
    ) -> None:
        """Both stores locked, the inbound flood sustained, and every thread
        the default executor, the state store and the evidence store own taken.
        Discovery evaluates the trip on the reading in hand and the act needs
        no thread, so nothing held reaches it.
        """
        _pi_sized_default_executor()
        async with _site(tmp_path) as site:
            await site.start_routes()
            await site.store.get_action_log(limit=1)
            site.lock("evidence.db")
            site.lock("state.db")
            site.flood_inbound(_MALFORMED_RECEIPT)
            await asyncio.sleep(0.2)
            loop = asyncio.get_running_loop()
            default = loop._default_executor  # type: ignore[attr-defined]
            stores = [site.store._write_executor, site.store._read_executor]
            evidence = site.attestor._executor._executor
            with _held([default, *stores, evidence], _PI_DEFAULT_WORKERS):
                await asyncio.sleep(0.05)
                tripped = await site.trip()
                trip_at = site.acts.ran["trip_relay"][0]
                assert all(at >= trip_at for at in site.history_reads), (
                    "history was read before the trip"
                )
            site.release()
            await site._finish_dispatches()
            assert tripped["ran"] == 1
            assert tripped["after_s"] < _TRIP_BOUND_S, tripped
            assert site.subscriber is not None and site.subscriber.shed_count > 0


class TestAFailedTripStillRaisesTheAlarm:
    async def test_the_emergency_notice_goes_with_the_state_store_locked(
        self, tmp_path: Path
    ) -> None:
        """The trip's executor fails; the independent emergency SMS is not held.

        Both stores locked and the inbound flood running: neither the attempt
        nor the notice of its failure waits on either store.
        """
        _pi_sized_default_executor()
        async with _site(tmp_path) as site:
            sent: list[float] = []

            class _Sms:
                async def send(self, message: str, *, to_number: str) -> bool:
                    sent.append(time.monotonic())
                    return True

            site.dispatcher._emergency_sms_sender = _Sms()
            attempted: list[float] = []

            async def fails(*_a: Any, **_k: Any) -> bool:
                attempted.append(time.monotonic())
                return False

            site.dispatcher.register_executor("trip_relay", fails)
            await site.start_routes()
            site.lock("state.db")
            site.lock("evidence.db")
            site.flood_inbound(_MALFORMED_RECEIPT)
            await asyncio.sleep(0.2)
            started = time.monotonic()
            site._dispatch("current_clamp")
            await _until(lambda: bool(sent))
            assert attempted and attempted[0] - started < _TRIP_BOUND_S
            assert sent, "no emergency notice"
            assert sent[0] - started < _TRIP_BOUND_S, sent[0] - started
            site.release()


class TestTheDefaultExecutorIsNotTheEvidenceRoutes:
    async def test_a_flood_held_by_a_locked_store_occupies_no_shared_thread(
        self, tmp_path: Path
    ) -> None:
        """The default executor answers while every inbound message waits.

        The operator's SMS channel sends on that executor, so a flood that held
        its threads would hold the approval request too.
        """
        _pi_sized_default_executor()
        async with _site(tmp_path) as site:
            await site.start_routes()
            site.lock("evidence.db")
            site.flood_inbound(_MALFORMED_RECEIPT)
            await asyncio.sleep(0.3)
            started = time.monotonic()
            await asyncio.wait_for(asyncio.to_thread(lambda: None), _TRIP_BOUND_S)
            assert time.monotonic() - started < _TRIP_BOUND_S
            assert site.subscriber is not None and site.subscriber.shed_count > 0
            site.release()


class TestTheStoreHasItsOwnThreads:
    async def test_an_approved_act_runs_while_the_default_executor_is_full(
        self, tmp_path: Path
    ) -> None:
        """Every default-executor thread held by something else entirely."""
        _pi_sized_default_executor()
        async with _site(tmp_path) as site:
            # The phone here sends on the loop, so only the store's own path is
            # under test.
            async def send(*, alert: Any, to_number: str) -> bool:
                site.phone.record(alert)
                return True

            site.phone.send = send  # type: ignore[method-assign]
            default = asyncio.get_running_loop()._default_executor  # type: ignore[attr-defined]
            with _held([default], _PI_DEFAULT_WORKERS):
                await asyncio.sleep(0.05)
                approved = await site.approve()
            assert approved["ran"] == 1, approved
            assert await site.decided() == _DECIDED
            assert approved["after_reply_s"] < _APPROVED_BOUND_S, approved


class TestATripDoesNotWaitOnAnotherTriggersHistory:
    async def test_the_trip_runs_while_the_history_read_is_held(
        self, tmp_path: Path
    ) -> None:
        async with _site(tmp_path) as site:
            held = asyncio.Event()
            reading = site.store.avg_last_hours

            async def slow(*args: Any, **kwargs: Any) -> Any:
                await held.wait()
                return await reading(*args, **kwargs)

            site.store.avg_last_hours = slow  # type: ignore[method-assign]
            task = asyncio.create_task(site.trip())
            try:
                await _until(lambda: bool(site.acts.ran["trip_relay"]))
                assert site.acts.ran["trip_relay"], "the trip waited on history"
                assert len(site.history_reads) <= 1
            finally:
                held.set()
                tripped = await asyncio.wait_for(task, _PROMPT_S)
                await site._finish_dispatches()
            assert tripped["after_s"] < _TRIP_BOUND_S
            # The history-reading trigger was still evaluated, after the trip.
            assert len(site.history_reads) == 1
            assert site.history_reads[0] >= site.acts.ran["trip_relay"][0]


class TestAShippedTierDTriggerWithHistoryHooks:
    async def test_the_overcurrent_trigger_fires_with_both_stores_locked(
        self, tmp_path: Path
    ) -> None:
        """The packaged energy-anomaly-detector, its hook included.

        The Tier D condition is decided before the hook runs. The hook then
        reads history synchronously, and with the state store's write lock
        held by another connection those reads go through only because the
        store runs in WAL mode, where a writer does not block a reader. The trigger's bundled
        actions are notifications, no protective outcome is bound to it, and
        what is timed is the first of them.
        """
        from ori.skills.loader import SkillLoader

        skill = next(
            s
            for s in SkillLoader().load_all("skills")
            if s.name == "energy-anomaly-detector"
        )
        assert skill.first_party and skill.hooks is not None
        _pi_sized_default_executor()
        async with _site(tmp_path) as site:
            for n in range(6):
                await site.store.append_history(_event("current_clamp"))
            site.coordinator._skills = []
            site.coordinator.add_skill(skill)
            site.dispatcher.register_executor(
                "alert_whatsapp", site.acts.executor("alert_whatsapp")
            )
            hook_reads: list[float] = []
            original = site.store.hooks_avg_last_hours

            def spied(*args: Any, **kwargs: Any) -> Any:
                hook_reads.append(time.monotonic())
                return original(*args, **kwargs)

            site.store.hooks_avg_last_hours = spied  # type: ignore[method-assign]
            await site.start_routes()
            site.lock("state.db")
            site.lock("evidence.db")
            site.flood_inbound(_MALFORMED_RECEIPT)
            await asyncio.sleep(0.2)

            reading = SensorReading(
                sensor_id="load-current",
                sensor_type="current_clamp",
                value=30.0,
                unit="ampere",
                timestamp=int(time.time() * 1000),
                quality=1.0,
            )
            started = time.monotonic()
            site.dispatching = asyncio.create_task(
                site.coordinator.dispatch_event(OriEvent.from_reading(reading, DEVICE))
            )
            site._dispatches.append(site.dispatching)
            fired = site.acts.by_trigger.setdefault("dangerous_overcurrent", [])
            await _until(lambda: bool(fired))
            assert fired, "the overcurrent trigger did not fire"
            name, at = fired[0]
            assert name == "alert_whatsapp", site.acts.by_trigger
            assert at - started < _TRIP_BOUND_S, at - started
            # The hook runs after the trip, and its history reads still go
            # through the held write lock: the notices that need its baseline
            # follow promptly rather than after the store's busy timeout.
            spike = site.acts.by_trigger.setdefault("sudden_load_spike", [])
            await _until(lambda: bool(spike))
            assert hook_reads, "the hook never read history"
            assert spike, f"the hook never completed: {site.acts.by_trigger}"
            assert spike[0][1] - started < 1.0, spike[0][1] - started
            site.release()


# ── The broker keeps what the route has no room for ─────────────────────────


class _ManualAckClient(_Courier):
    """Records the MQTT acknowledgements the route sends."""

    def __init__(self) -> None:
        super().__init__("silent")
        self.manual = False
        self.acked: list[int] = []
        self.sessions = 0
        self.session_at: list[float] = []
        self.ack_code = 0

    def loop_start(self) -> None:
        self.sessions += 1
        self.session_at.append(time.monotonic())
        super().loop_start()

    def manual_ack_set(self, on: bool) -> None:
        self.manual = on

    def ack(self, mid: int, qos: int) -> int:
        self.acked.append(mid)
        return self.ack_code


async def test_a_message_past_the_bound_is_left_unacknowledged(tmp_path: Path) -> None:
    async with _site(tmp_path) as site:
        client = _ManualAckClient()
        site.inbound_client = client
        await site.start_routes()
        assert client.manual
        site.lock("evidence.db")
        total = min(INBOUND_IN_FLIGHT_BOUND, _FLOOD) + 4
        for mid in range(1, total + 1):
            client.on_message(
                client,
                None,
                SimpleNamespace(payload=_MALFORMED_RECEIPT, mid=mid, qos=1),
            )
        await asyncio.sleep(0.2)
        assert site.subscriber is not None
        assert site.subscriber.shed_count == 4
        assert client.acked == []
        site.release()
        await _until(lambda: len(client.acked) == INBOUND_IN_FLIGHT_BOUND)
        # Only what was routed is released at the broker; the rest stays there.
        assert sorted(client.acked) == list(range(1, INBOUND_IN_FLIGHT_BOUND + 1))


def _mosquitto() -> str | None:
    found = shutil.which("mosquitto")
    if found:
        return found
    for candidate in ("/opt/homebrew/sbin/mosquitto", "/usr/sbin/mosquitto"):
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@contextmanager
def _broker(root: Path) -> Iterator[int]:
    binary = _mosquitto()
    if binary is None:
        if os.environ.get("ORI_REQUIRE_MQTT_BROKER") == "1":
            pytest.fail("ORI_REQUIRE_MQTT_BROKER=1 and mosquitto is not installed")
        pytest.skip("mosquitto is not installed")
    port = _free_port()
    config = root / "mosquitto.conf"
    config.write_text(
        f"listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\n"
    )
    process = subprocess.Popen(
        [binary, "-c", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    try:
        deadline = time.monotonic() + _PROMPT_S
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.05)
        yield port
    finally:
        process.terminate()
        process.wait(_PROMPT_S)


async def test_the_broker_redelivers_what_the_route_had_no_room_for(
    tmp_path: Path,
) -> None:
    """A real broker, a real paho client, and a store held past the bound.

    Every message published reaches ingest once it can: the ones the route
    left unacknowledged are redelivered after it reconnects.
    """
    import paho.mqtt.client as mqtt

    with _broker(tmp_path) as port:
        async with _site(tmp_path / "site") as site:
            ingest = site.attestor.ingest
            assert ingest is not None
            router = EvidenceInboundRouter(device_id=DEVICE, ingest=ingest)
            routed: list[int] = []
            route = router.route

            async def counted(payload: Any) -> Any:
                outcome = await route(payload)
                routed.append(int(json.loads(payload)["artifact"]["n"]))
                return outcome

            router.route = counted  # type: ignore[method-assign]
            subscriber = MqttEvidenceInboundSubscriber(
                broker_url=f"mqtt://127.0.0.1:{port}",
                router=router,
                device_id=DEVICE,
            )
            # Every arrival as the real client hands it over: which message,
            # and whether the broker marked it a redelivery.
            arrivals: list[tuple[int, bool]] = []
            sessions: list[Any] = []
            on_message = subscriber._on_message
            factory = evidence_inbound._default_client_factory

            def observed(client: Any, userdata: Any, message: Any) -> None:
                body = json.loads(message.payload)
                arrivals.append((int(body["artifact"]["n"]), bool(message.dup)))
                on_message(client, userdata, message)

            def client_factory(**kwargs: Any) -> Any:
                client = factory(**kwargs)
                sessions.append(client)
                return client

            subscriber._on_message = observed  # type: ignore[method-assign]
            subscriber._client_factory = client_factory
            shutdown = asyncio.Event()
            serving = asyncio.create_task(subscriber.serve_until(shutdown))
            await _until(lambda: subscriber.connected)
            assert subscriber.connected
            site.lock("evidence.db")

            sender = mqtt.Client(
                callback_api_version=getattr(mqtt, "CallbackAPIVersion").VERSION2,
                client_id="courier",
            )
            sender.connect("127.0.0.1", port)
            sender.loop_start()
            published = _FLOOD
            for n in range(published):
                body = json.loads(_MALFORMED_RECEIPT)
                body["artifact"]["n"] = n
                sender.publish(
                    subscriber.topic, json.dumps(body), qos=1
                ).wait_for_publish(_PROMPT_S)
            await _until(lambda: subscriber.shed_count > 0)
            assert subscriber.shed_count > 0, "the route was never saturated"
            site.release()

            await _until(lambda: len(set(routed)) == published, _PROMPT_S * 4)
            # At least once, as QoS 1 promises: a message routed just before
            # the reconnect can come round again, and ingest is idempotent.
            assert set(routed) == set(range(published))
            # The session is persistent and the route acknowledges by hand, so
            # what it left unacknowledged came back from the broker as a
            # redelivery, on a second session of the same client.
            assert len(sessions) >= 2
            assert all(getattr(c, "_clean_session", False) is False for c in sessions)
            first_seen: set[int] = set()
            redelivered: set[int] = set()
            for n, dup in arrivals:
                if n in first_seen:
                    assert dup, f"message {n} came again without the dup flag"
                    redelivered.add(n)
                first_seen.add(n)
            assert redelivered, "nothing was redelivered by the broker"
            sender.loop_stop()
            sender.disconnect()
            shutdown.set()
            await asyncio.wait_for(serving, _PROMPT_S)


def test_the_bound_is_below_the_broker_window_and_the_flood() -> None:
    """Under mosquitto's default in-flight window of 20, and under every flood here."""
    assert evidence_inbound.INBOUND_IN_FLIGHT_BOUND < 20
    assert evidence_inbound.INBOUND_IN_FLIGHT_BOUND * 3 <= _FLOOD


def test_the_broker_proof_fails_rather_than_skips_when_required(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys.modules[__name__], "_mosquitto", lambda: None)
    monkeypatch.setenv("ORI_REQUIRE_MQTT_BROKER", "1")
    # A skip is an outcome here, not a pass: catch it and fail on it.
    try:
        with _broker(tmp_path):
            pass
    except pytest.fail.Exception as exc:
        assert "ORI_REQUIRE_MQTT_BROKER" in str(exc)
    except pytest.skip.Exception:
        pytest.fail("the broker proof skipped where it is required")
    else:
        pytest.fail("the broker proof ran without a broker")


def test_ci_installs_the_broker_and_requires_the_proof() -> None:
    workflow = (
        Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
    ).read_text()
    assert "apt-get install -y --no-install-recommends mosquitto" in workflow
    assert 'ORI_REQUIRE_MQTT_BROKER: "1"' in workflow


# ── The in-flight slots ──────────────────────────────────────────────────────


async def _serving(site: _Site) -> tuple[MqttEvidenceInboundSubscriber, Any]:
    client = _ManualAckClient()
    site.inbound_client = client
    await site.start_routes()
    assert site.subscriber is not None
    return site.subscriber, client


def _deliver(client: Any, mids: range, payload: bytes = _MALFORMED_RECEIPT) -> None:
    for mid in mids:
        client.on_message(
            client, None, SimpleNamespace(payload=payload, mid=mid, qos=1)
        )


@asynccontextmanager
async def _fast_reconnect(seconds: float = 0.05) -> AsyncIterator[None]:
    with patch.object(evidence_inbound, "_RECONNECT_MIN_S", seconds):
        yield


class TestRedeliveryTiming:
    async def test_past_the_bound_reconnects_at_once(self, tmp_path: Path) -> None:
        async with _site(tmp_path) as site, _fast_reconnect(1.0):
            subscriber, client = await _serving(site)
            site.lock("evidence.db")
            _deliver(client, range(1, INBOUND_IN_FLIGHT_BOUND + 5))
            await _until(lambda: subscriber.shed_count == 4)
            site.release()
            await _until(lambda: subscriber._in_flight == 0)
            drained = time.monotonic()
            await _until(lambda: client.sessions >= 2)
            assert client.sessions >= 2
            assert client.session_at[1] - drained < 0.5

    async def test_a_failed_route_reconnects_only_after_a_growing_backoff(
        self, tmp_path: Path
    ) -> None:
        async with _site(tmp_path) as site, _fast_reconnect(0.3):
            subscriber, client = await _serving(site)

            async def broken(_payload: Any) -> Any:
                raise RuntimeError("ingest failed")

            subscriber._router.route = broken  # type: ignore[method-assign]
            _deliver(client, range(1, 2))
            await _until(lambda: client.sessions >= 2, 5.0)
            _deliver(client, range(2, 3))
            await _until(lambda: client.sessions >= 3, 5.0)
            first, second, third = client.session_at[:3]
            assert second - first >= 0.3, second - first
            assert third - second >= 0.6, third - second


class TestTheInFlightSlots:
    async def test_a_slot_is_released_when_routing_succeeds(
        self, tmp_path: Path
    ) -> None:
        async with _site(tmp_path) as site:
            subscriber, client = await _serving(site)
            _deliver(client, range(1, 6))
            await _until(lambda: len(client.acked) == 5)
            assert subscriber._in_flight == 0
            assert sorted(client.acked) == [1, 2, 3, 4, 5]

    async def test_a_slot_is_released_when_routing_raises(self, tmp_path: Path) -> None:
        async with _site(tmp_path) as site, _fast_reconnect():
            subscriber, client = await _serving(site)

            async def broken(_payload: Any) -> Any:
                raise RuntimeError("ingest failed")

            subscriber._router.route = broken  # type: ignore[method-assign]
            _deliver(client, range(7, 8))
            # The message is still the broker's: the route reconnects for it.
            await _until(lambda: client.sessions >= 2)
            assert subscriber._in_flight == 0
            assert client.acked == []
            assert client.sessions >= 2

    async def test_a_slot_is_released_when_routing_is_cancelled(
        self, tmp_path: Path
    ) -> None:
        async with _site(tmp_path) as site, _fast_reconnect():
            subscriber, client = await _serving(site)
            site.lock("evidence.db")
            _deliver(client, range(9, 10))
            await _until(lambda: subscriber._in_flight == 1)
            await asyncio.sleep(0.05)
            (task,) = [
                t
                for t in asyncio.all_tasks()
                if getattr(t.get_coro(), "__qualname__", "").endswith("._routed")
            ]
            task.cancel()
            await _until(lambda: subscriber._in_flight == 0)
            assert subscriber._in_flight == 0
            assert client.acked == []
            await _until(lambda: client.sessions >= 2)
            assert client.sessions >= 2
            site.release()

    async def test_a_slot_is_released_when_routing_is_cancelled_before_it_starts(
        self, tmp_path: Path
    ) -> None:
        async with _site(tmp_path) as site:
            subscriber, client = await _serving(site)
            scheduled: list[Any] = []
            real = asyncio.run_coroutine_threadsafe

            def capture(coro: Any, loop: Any) -> Any:
                future = real(coro, loop)
                scheduled.append(future)
                return future

            with patch.object(asyncio, "run_coroutine_threadsafe", capture):
                _deliver(client, range(11, 12))
            # Still on the loop thread: the route has not started yet.
            assert subscriber._in_flight == 1
            (future,) = scheduled
            future.cancel()
            await _until(lambda: subscriber._in_flight == 0)
            assert subscriber._in_flight == 0
            assert client.acked == []

    async def test_a_burst_schedules_nothing_past_the_bound(
        self, tmp_path: Path
    ) -> None:
        """Admission is decided in the client's thread, before the loop sees it.

        A trip already queued on the loop when a sustained burst arrives, while
        the loop is briefly blocked, still runs within the bound once the loop
        is free; and at no instant does the loop hold more routing work than
        the bound.
        """
        async with _site(tmp_path) as site:
            subscriber, client = await _serving(site)
            site.lock("evidence.db")
            outstanding = 0
            peak = 0
            count_lock = threading.Lock()
            real = asyncio.run_coroutine_threadsafe

            def counted(coro: Any, loop: Any) -> Any:
                nonlocal outstanding, peak
                with count_lock:
                    outstanding += 1
                    peak = max(peak, outstanding)
                future = real(coro, loop)

                def done(_f: Any) -> None:
                    nonlocal outstanding
                    with count_lock:
                        outstanding -= 1

                future.add_done_callback(done)
                return future

            stop = threading.Event()

            def burst() -> None:
                mid = 0
                while not stop.is_set():
                    mid += 1
                    client.on_message(
                        client,
                        None,
                        SimpleNamespace(payload=_MALFORMED_RECEIPT, mid=mid, qos=1),
                    )

            with patch.object(asyncio, "run_coroutine_threadsafe", counted):
                ran = site.acts.ran["trip_relay"]
                site._dispatch("current_clamp")
                sender = threading.Thread(target=burst)
                sender.start()
                time.sleep(0.3)  # the loop is blocked; the burst keeps arriving
                unblocked = time.monotonic()
                await _until(lambda: bool(ran))
                stop.set()
                sender.join(_PROMPT_S)
            assert ran, "the queued trip never ran"
            assert ran[0] - unblocked < _TRIP_BOUND_S, ran[0] - unblocked
            assert subscriber.shed_count > 1000, subscriber.shed_count
            assert peak <= INBOUND_IN_FLIGHT_BOUND, peak
            site.release()
            await _until(lambda: subscriber._in_flight == 0)

    async def test_a_burst_of_courier_answers_schedules_nothing_past_the_bound(
        self, tmp_path: Path
    ) -> None:
        async with _site(tmp_path, courier=_Courier("silent")) as site:
            await site.start_routes()
            site.lock("evidence.db")
            outstanding = 0
            peak = 0
            count_lock = threading.Lock()
            real = asyncio.run_coroutine_threadsafe

            def counted(coro: Any, loop: Any) -> Any:
                nonlocal outstanding, peak
                with count_lock:
                    outstanding += 1
                    peak = max(peak, outstanding)
                future = real(coro, loop)

                def done(_f: Any) -> None:
                    nonlocal outstanding
                    with count_lock:
                        outstanding -= 1

                future.add_done_callback(done)
                return future

            answer = json.dumps(
                {
                    "device_id": DEVICE,
                    "artifact_type": "delivery_envelope",
                    "artifact_digest": "sha256:" + "a" * 64,
                    "outcome": "queued",
                    "reason": "",
                }
            ).encode()

            def burst() -> None:
                for _ in range(20000):
                    site.courier.on_message(
                        site.courier, None, SimpleNamespace(payload=answer)
                    )

            with patch.object(asyncio, "run_coroutine_threadsafe", counted):
                sender = threading.Thread(target=burst)
                sender.start()
                time.sleep(0.3)
                sender.join(_PROMPT_S)
                await asyncio.sleep(0.1)
            assert site.publisher.acks_shed > 1000, site.publisher.acks_shed
            assert peak <= evidence_outbound.ACK_IN_FLIGHT_BOUND, peak
            site.release()
            await _until(lambda: site.publisher._acks_in_flight == 0)

    async def test_the_route_stops_cleanly_with_work_in_flight(
        self, tmp_path: Path
    ) -> None:
        async with _site(tmp_path) as site:
            subscriber, client = await _serving(site)
            site.lock("evidence.db")
            _deliver(client, range(1, INBOUND_IN_FLIGHT_BOUND + 1))
            await _until(lambda: subscriber._in_flight == INBOUND_IN_FLIGHT_BOUND)
            site._shutdown.set()
            started = time.monotonic()
            inbound = site._tasks[1]
            await asyncio.wait_for(inbound, _PROMPT_S)
            assert time.monotonic() - started < 1.0
            assert subscriber._io._executor is None
            threads = {t.name for t in threading.enumerate()}
            site.release()
            await _until(lambda: subscriber._in_flight == 0)
            assert subscriber._in_flight == 0
            # The routes still in flight finished without a new route thread,
            # and nothing was acknowledged on the stopped client.
            assert subscriber._io._executor is None
            new = {t.name for t in threading.enumerate()} - threads
            assert not [n for n in new if n.startswith("ori-evidence-in")], new
            assert client.acked == []

    async def test_an_ack_the_client_refuses_leaves_the_message_owed(
        self, tmp_path: Path
    ) -> None:
        async with _site(tmp_path) as site, _fast_reconnect():
            subscriber, client = await _serving(site)
            client.ack_code = 4  # paho's MQTT_ERR_NO_CONN
            _deliver(client, range(1, 2))
            await _until(lambda: client.sessions >= 2)
            assert client.sessions >= 2

    async def test_a_reconnect_keeps_the_slots_it_holds(self, tmp_path: Path) -> None:
        async with _site(tmp_path) as site:
            subscriber, client = await _serving(site)
            site.lock("evidence.db")
            _deliver(client, range(1, INBOUND_IN_FLIGHT_BOUND + 1))
            await _until(lambda: subscriber._in_flight == INBOUND_IN_FLIGHT_BOUND)
            with patch.object(evidence_inbound, "_RECONNECT_MIN_S", 0.01):
                subscriber._signal_lost()
                await _until(lambda: subscriber.connected is False)
                await _until(lambda: subscriber.connected)
            assert subscriber._in_flight == INBOUND_IN_FLIGHT_BOUND
            _deliver(client, range(100, 101))
            await _until(lambda: subscriber.shed_count == 1)
            assert subscriber.shed_count == 1
            site.release()

    async def test_an_inbound_flood_takes_no_slot_from_courier_acknowledgements(
        self, tmp_path: Path
    ) -> None:
        """One device per runtime: the two evidence routes are bounded apart."""
        async with _site(tmp_path, courier=_Courier("queue_full")) as site:
            subscriber, client = await _serving(site)
            site.lock("evidence.db")
            _deliver(client, range(1, INBOUND_IN_FLIGHT_BOUND + 10))
            await _until(lambda: subscriber.shed_count > 0)
            for n in range(4):
                site.courier.on_message(
                    site.courier,
                    None,
                    SimpleNamespace(
                        payload=json.dumps(
                            {
                                "device_id": DEVICE,
                                "artifact_type": "delivery_envelope",
                                "artifact_digest": "sha256:" + f"{n:x}" * 64,
                                "outcome": "queued",
                                "reason": "",
                            }
                        ).encode()
                    ),
                )
            await asyncio.sleep(0.1)
            assert site.publisher.acks_shed == 0
            assert site.publisher._acks_in_flight == 4
            site.release()
            await _until(lambda: site.publisher._acks_in_flight == 0)


# ── A redelivered refusal is the same refusal ───────────────────────────────


class TestARedeliveredRefusalIsRecordedOnce:
    async def test_the_same_artifact_refused_again_adds_no_row(
        self, tmp_path: Path
    ) -> None:
        async with _site(tmp_path) as site:
            subscriber, client = await _serving(site)
            _deliver(client, range(1, 4))
            await _until(lambda: len(client.acked) == 3)
            refusals = await site.attestor.ingest_refusal_summary()
            assert refusals is not None and refusals["count"] == 1
            other = json.loads(_MALFORMED_RECEIPT)
            other["artifact"]["n"] = 1
            _deliver(client, range(4, 6), json.dumps(other).encode())
            await _until(lambda: len(client.acked) == 5)
            refusals = await site.attestor.ingest_refusal_summary()
            assert refusals is not None and refusals["count"] == 2
            # Every delivery is still answered: the courier retires on that.
            assert sorted(client.acked) == [1, 2, 3, 4, 5]


# ── Every executor admits a bounded amount of work ──────────────────────────


class TestTheExecutorsAreBounded:
    async def test_the_evidence_worker_refuses_past_its_ceiling(self) -> None:
        from ori.security.evidence.executor import (
            EvidenceExecutor,
            EvidenceExecutorSaturatedError,
        )

        executor = EvidenceExecutor()
        executor._pending_ceiling = 4
        hold = threading.Event()
        try:
            held = [
                asyncio.create_task(executor.run_async(hold.wait)) for _ in range(4)
            ]
            await asyncio.sleep(0.05)
            assert executor.pending == 4
            # Bounded waits: past the ceiling a call is refused at once, and
            # one queued behind the held calls would otherwise never return.
            with pytest.raises(EvidenceExecutorSaturatedError):
                await asyncio.wait_for(executor.run_async(lambda: None), 1.0)
            with pytest.raises(EvidenceExecutorSaturatedError):
                await asyncio.wait_for(
                    asyncio.to_thread(executor.run, lambda: None), 1.0
                )
            assert executor.pending == 4
            hold.set()
            await asyncio.gather(*held)
            assert executor.pending == 0
        finally:
            hold.set()
            executor.close()

    async def test_a_route_thread_refuses_past_its_ceiling(self) -> None:
        from ori.gateway.route_io import RouteIO, RouteIOSaturatedError

        io = RouteIO("test-route", ceiling=2)
        hold = threading.Event()
        try:
            held = [asyncio.create_task(io.run(hold.wait)) for _ in range(2)]
            await asyncio.sleep(0.05)
            assert io.pending == 2
            with pytest.raises(RouteIOSaturatedError):
                await asyncio.wait_for(io.run(lambda: None), 1.0)
            hold.set()
            await asyncio.gather(*held)
            assert io.pending == 0
        finally:
            hold.set()
            io.shutdown()

    async def test_store_reads_are_admitted_no_faster_than_the_pool_runs_them(
        self, tmp_path: Path
    ) -> None:
        from ori.state import store as store_module

        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        hold = threading.Event()
        running: list[int] = []
        peak = 0
        lock = threading.Lock()
        original = store._run_read_with_conn

        def held(fn: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal peak
            with lock:
                running.append(1)
                peak = max(peak, len(running))
            hold.wait()
            with lock:
                running.pop()
            return original(fn, *args, **kwargs)

        store._run_read_with_conn = held  # type: ignore[method-assign]
        try:
            reads = [
                asyncio.create_task(store.get_action_log(limit=1)) for _ in range(20)
            ]
            await asyncio.sleep(0.1)
            assert store._read_executor is not None
            assert store._read_executor._work_queue.qsize() == 0
            assert peak == store_module._READ_WORKERS
            hold.set()
            await asyncio.gather(*reads)
        finally:
            hold.set()
            await store.close()


async def test_the_confirmation_read_back_holds_no_default_executor_thread(
    tmp_path: Path,
) -> None:
    """The firmware confirmation read-back awaits the evidence worker directly."""
    from ori.security.firmware.confirmation import FirmwareConfirmationCoordinator

    async with _site(tmp_path) as site:
        backend = site.attestor.confirmation_backend()
        assert backend is not None
        coordinator = FirmwareConfirmationCoordinator(store=site.store, chain=backend)

        async def no_default_executor(*_a: Any, **_k: Any) -> Any:
            raise AssertionError("the read-back used the loop's default executor")

        with patch.object(asyncio, "to_thread", no_default_executor):
            assert await coordinator._readback("fw-1") is None
