# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""evidence-exchange/v3 at the inbound route, against a started attestor.

A restated record is decided against what the ledger holds; a store fault
leaves the artifact undecided, unacknowledged and released at the broker; and
nothing raised inside ingest escapes the route.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import sqlite3
from types import SimpleNamespace
from typing import Any

import pytest

from ori.gateway.evidence_inbound import (
    ARTIFACT_CUSTODY,
    ARTIFACT_RECEIPT,
    REFUSE_ENVELOPE_UNAUTHENTICATED,
    REFUSE_UNADMISSIBLE,
    REFUSE_UNKNOWN_ARTIFACT_TYPE,
    EvidenceInboundRouter,
    InboundRefusal,
    Routed,
)
from ori.security.evidence.custody_keys import (
    CustodyKeyRegistry,
    derive_custody_key_id,
)
from ori.security.evidence.executor import EvidenceExecutorSaturatedError
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.evidence.ingest import (
    REJECT_REASONS,
    REJECT_RESTATEMENT_CONFLICT,
    IngestRejectedError,
)
from ori.security.evidence.ingest_service import (
    ACCEPTED,
    REJECTED,
    UNDECIDED,
    IngestOutcome,
)
from ori.utils.time_utils import now_ms
from tests.waiting import wait_until

from .test_inbound_route import (
    CUSTODY_SECRET,
    DEVICE,
    PREVIOUS_CUSTODY_SECRET,
    _authenticator,
    _envelope,
    _FakeClient,
    _mac,
    _RecordingIngest,
    _seal_one,
    _signed,
    _subscriber,
)

RETIREMENT = json.loads(
    (
        pathlib.Path(__file__).resolve().parent.parent
        / "vectors"
        / "gateway_evidence_carriage"
        / "inbound-retirement-v1.json"
    ).read_text()
)


def _custody(base: dict, secret: str, custody_at_ms: int) -> bytes:
    artifact: dict[str, Any] = dict(base, custody_at_ms=custody_at_ms)
    artifact["key_id"] = derive_custody_key_id(secret)
    return json.dumps(_envelope(ARTIFACT_CUSTODY, _mac(artifact, secret))).encode()


def _row(attestor: FirstPartyEvidenceAttestor) -> dict[str, Any]:
    ledger = attestor._ledger
    assert ledger is not None
    row = attestor._executor.run(ledger.find_by_local_seq, 1)
    assert row is not None
    return {key: row[key] for key in row.keys()}


class _Answer:
    """One routed artifact: the ingest outcome and the acknowledgement."""

    def __init__(self, routed: Routed) -> None:
        assert isinstance(routed.outcome, IngestOutcome), routed.outcome
        self.outcome: IngestOutcome = routed.outcome
        self.acknowledgement: dict[str, Any] | None = routed.acknowledgement

    @property
    def ack(self) -> dict[str, Any]:
        assert self.acknowledgement is not None
        return self.acknowledgement


def _route(router: EvidenceInboundRouter, payload: bytes) -> _Answer:
    return _Answer(asyncio.run(asyncio.to_thread(router.handle_payload, payload)))


@pytest.fixture
def sealed(tmp_path):
    """A started attestor holding both custody generations, one envelope sealed."""
    attestor = FirstPartyEvidenceAttestor(
        db_path=str(tmp_path / "evidence.db"),
        key_path=str(tmp_path / "evidence.key"),
        device_secret="a-random-install-secret",
        device_id=DEVICE,
        custody_keys=CustodyKeyRegistry(
            active_secret=CUSTODY_SECRET, previous_secret=PREVIOUS_CUSTODY_SECRET
        ),
    )
    base = asyncio.run(_seal_one(attestor))
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=attestor.ingest)
    yield attestor, router, base
    attestor.close()


def test_a_conflicting_custody_restatement_is_refused_and_writes_nothing(sealed):
    attestor, router, base = sealed
    first = _route(router, _custody(base, CUSTODY_SECRET, 1787000000900))
    assert first.outcome.accepted
    held = _row(attestor)

    routed = _route(router, _custody(base, CUSTODY_SECRET, 1787000000901))

    assert (routed.outcome.state, routed.outcome.reason) == (
        REJECTED,
        REJECT_RESTATEMENT_CONFLICT,
    )
    assert routed.ack["outcome"] == "refused"
    assert routed.ack["reason"] == REJECT_RESTATEMENT_CONFLICT
    assert _row(attestor) == held
    summary = asyncio.run(attestor.ingest_refusal_summary())
    assert summary is not None and summary["count"] == 1
    assert summary["last"]["reason"] == REJECT_RESTATEMENT_CONFLICT
    assert attestor.application_storage_fault is False


def test_an_agreeing_restatement_under_the_other_generation_keeps_the_first_key(
    sealed,
):
    attestor, router, base = sealed
    assert _route(
        router, _custody(base, CUSTODY_SECRET, 1787000000900)
    ).outcome.accepted
    held = _row(attestor)

    routed = _route(router, _custody(base, PREVIOUS_CUSTODY_SECRET, 1787000000900))

    assert routed.outcome.accepted
    assert routed.ack["outcome"] == "applied"
    assert _row(attestor) == held
    assert held["custody_key_id"] == derive_custody_key_id(CUSTODY_SECRET)


def test_a_conflicting_restatement_under_the_other_generation_is_refused(sealed):
    attestor, router, base = sealed
    assert _route(
        router, _custody(base, CUSTODY_SECRET, 1787000000900)
    ).outcome.accepted
    held = _row(attestor)

    routed = _route(router, _custody(base, PREVIOUS_CUSTODY_SECRET, 1787000000800))

    assert routed.outcome.reason == REJECT_RESTATEMENT_CONFLICT
    assert _row(attestor) == held


def test_a_restatement_one_byte_away_is_still_decided_on_custody_time(sealed):
    """A different MAC over an identical body is a forgery, not a restatement."""
    attestor, router, base = sealed
    payload = _custody(base, CUSTODY_SECRET, 1787000000900)
    assert _route(router, payload).outcome.accepted
    held = _row(attestor)
    message = json.loads(payload)
    mac = message["artifact"]["mac"]
    message["artifact"]["mac"] = mac[:-1] + ("0" if mac[-1] != "0" else "1")

    routed = _route(router, json.dumps(message).encode())

    assert routed.outcome.reason == "bad_authenticator"
    assert _row(attestor) == held


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("an unanticipated defect"),
        sqlite3.IntegrityError("a constraint refused a verified artifact"),
    ],
    ids=["defect", "constraint"],
)
def test_nothing_raised_inside_ingest_escapes_the_route(sealed, monkeypatch, error):
    """A failure no rule anticipated is undecided, unacknowledged, and not a
    store fault: a constraint refusing a verified artifact is a receiver
    defect."""
    attestor, router, base = sealed
    ledger = attestor._ledger

    def broken(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(ledger, "_apply_verified_custody", broken)
    held = _row(attestor)

    routed = _route(router, _custody(base, CUSTODY_SECRET, 1787000000900))

    assert routed.outcome.state == UNDECIDED
    assert routed.acknowledgement is None
    assert _row(attestor) == held
    assert attestor.application_storage_fault is False


def test_a_store_fault_is_undecided_and_raises_the_signal(sealed, monkeypatch):
    attestor, router, base = sealed
    ledger = attestor._ledger

    def locked(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(ledger, "_apply_verified_custody", locked)
    routed = _route(router, _custody(base, CUSTODY_SECRET, 1787000000900))
    assert routed.outcome.state == UNDECIDED and routed.acknowledgement is None
    assert attestor.application_storage_fault is True
    summary = asyncio.run(attestor.ingest_refusal_summary())
    assert summary is not None and summary["count"] == 0

    monkeypatch.undo()
    again = _route(router, _custody(base, CUSTODY_SECRET, 1787000000900))
    assert again.outcome.accepted
    assert attestor.application_storage_fault is False


def test_an_unreadable_sealed_envelope_digest_is_a_store_fault(sealed):
    """Matching custody against a damaged digest would refuse, and retire, a valid one."""
    attestor, router, base = sealed
    ledger = attestor._ledger

    def damage() -> None:
        ledger._connection.execute("DROP TRIGGER evidence_ledger_no_sealed_update")
        ledger._connection.execute(
            "UPDATE evidence_delivery_ledger SET envelope_digest = 'sha256:zz'"
        )

    attestor._executor.run(damage)
    routed = _route(router, _custody(base, CUSTODY_SECRET, 1787000000900))
    assert routed.outcome.state == UNDECIDED
    assert routed.acknowledgement is None
    assert _row(attestor)["custody_state"] == "none"


def test_a_sealed_digest_rewritten_to_another_digest_is_a_store_fault(sealed):
    """On a production seal: the stored envelope bytes are the oracle."""
    attestor, router, base = sealed
    ledger = attestor._ledger

    def damage() -> None:
        connection = ledger._connection
        guard = connection.execute(
            "SELECT sql FROM sqlite_master"
            " WHERE name = 'evidence_ledger_no_sealed_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER evidence_ledger_no_sealed_update")
        connection.execute(
            "UPDATE evidence_delivery_ledger SET envelope_digest = ?",
            ("sha256:" + "0" * 64,),
        )
        connection.execute(guard)

    attestor._executor.run(damage)
    routed = _route(router, _custody(base, CUSTODY_SECRET, 1787000000900))

    assert routed.outcome.state == UNDECIDED and routed.acknowledgement is None
    assert attestor.application_storage_fault is True


def test_an_artifact_with_no_canonical_form_is_refused_without_escaping(sealed):
    """The contract does not yet define how such an artifact is named in an
    acknowledgement, so sending none is this release's provisional answer."""
    attestor, router, _base = sealed
    payload = json.dumps(
        _envelope(ARTIFACT_RECEIPT, {"v": 1, "from_seq": 1, "to_seq": 1e-9})
    ).encode()

    routed = _route(router, payload)

    assert routed.outcome.state == REJECTED and routed.outcome.reason == "malformed"
    assert routed.acknowledgement is None


@pytest.mark.parametrize(
    "artifact_type, field, value",
    [
        (ARTIFACT_CUSTODY, "local_seq", 2**63),
        (ARTIFACT_RECEIPT, "to_seq", 2**63),
        (ARTIFACT_CUSTODY, "device_id", "\ud800"),
    ],
    ids=[
        "custody-seq-past-sqlite",
        "receipt-seq-past-sqlite",
        "custody-surrogate",
    ],
)
def test_a_value_no_store_or_canonical_form_holds_is_malformed(
    sealed, artifact_type, field, value
):
    """Decided from the bytes before any store lookup, never left undecided."""
    attestor, router, base = sealed
    # A well-formed MAC under a held generation, so the surrogate reaches the
    # signing bytes rather than an earlier shape check.
    artifact = dict(
        base,
        key_id=derive_custody_key_id(CUSTODY_SECRET),
        mac="hmac-sha256:" + "0" * 64,
    )
    if artifact_type == ARTIFACT_RECEIPT:
        artifact = {"v": 1, "device_id": DEVICE, "from_seq": 1, "to_seq": 1}
    artifact[field] = value
    held = _row(attestor)

    routed = _route(router, json.dumps(_envelope(artifact_type, artifact)).encode())

    assert routed.outcome.state == REJECTED and routed.outcome.reason == "malformed"
    assert _row(attestor) == held
    assert attestor.application_storage_fault is False


class _AckingClient(_FakeClient):
    """Records the MQTT acknowledgements the route sends the broker."""

    def __init__(self) -> None:
        super().__init__()
        self.acked: list[Any] = []

    def manual_ack_set(self, _on: bool) -> None:
        pass

    def ack(self, mid: Any, _qos: Any) -> int:
        self.acked.append(mid)
        return 0


class _RaisingIngest(_RecordingIngest):
    """Answers the subscriber's awaited call by raising *error*."""

    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self._error = error

    async def accept_async(self, artifact_type: str, artifact: object) -> IngestOutcome:
        self.calls.append((artifact_type, artifact))
        raise self._error


def _deliver_on_the_wire(ingest: _RecordingIngest) -> tuple[_AckingClient, Any]:
    """One message through the MQTT subscriber, until its route has finished."""
    client = _AckingClient()
    subscriber = _subscriber(client, ingest=ingest)

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        await wait_until(lambda: subscriber.connected, what="the route to come up")
        message = SimpleNamespace(
            payload=_signed(_envelope(ARTIFACT_CUSTODY, {"v": 1})), mid=7, qos=1
        )
        assert client.on_message is not None
        await asyncio.to_thread(client.on_message, client, None, message)
        await wait_until(
            lambda: ingest.calls and subscriber._in_flight == 0,
            what="the message to finish routing",
        )
        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())
    return client, subscriber


def test_an_undecided_artifact_is_released_at_the_broker_and_never_acknowledged():
    """The courier keeps it and redelivers it in a fresh envelope."""
    undecided = IngestOutcome(artifact=ARTIFACT_CUSTODY, state=UNDECIDED)
    client, _ = _deliver_on_the_wire(_RecordingIngest(undecided))
    assert client.acked == [7]
    assert client.published == []


def test_a_failure_inside_ingest_is_released_rather_than_held_for_a_replay():
    """Held, the broker would bring back the identical envelope, which replay
    protection refuses with no acknowledgement; released, the courier sends a
    fresh one."""
    client, _ = _deliver_on_the_wire(_RaisingIngest(RuntimeError("a defect")))
    assert client.acked == [7]
    assert client.published == []


def test_a_saturated_evidence_worker_leaves_the_message_with_the_broker():
    """Nothing was attempted, so the broker keeps it for the reconnect."""
    client, subscriber = _deliver_on_the_wire(
        _RaisingIngest(EvidenceExecutorSaturatedError("the worker is full"))
    )
    assert client.acked == []
    assert client.published == []


# --------------------------------------------------------------------------
# gateway-evidence-carriage/v1 inbound-retirement-v1.json: the runtime's half
# --------------------------------------------------------------------------


def test_the_runtime_refuses_with_exactly_the_carriage_vocabulary():
    assert set(RETIREMENT["vocabulary"]) == REJECT_REASONS


@pytest.mark.parametrize(
    "case", RETIREMENT["cases"], ids=[c["name"] for c in RETIREMENT["cases"]]
)
def test_each_answer_the_runtime_gives_is_the_one_the_courier_reads(case):
    """The courier's retirement is the gateway's; the acknowledgement is ours."""
    ack = case["acknowledgement"]
    if ack is None:
        outcome = IngestOutcome(artifact=ARTIFACT_CUSTODY, state=UNDECIDED)
    elif ack["outcome"] == "applied":
        outcome = IngestOutcome(artifact=ARTIFACT_CUSTODY, state=ACCEPTED)
    elif ack["reason"] not in RETIREMENT["vocabulary"]:
        # A reason outside the vocabulary is one this runtime cannot send.
        with pytest.raises(ValueError):
            raise IngestRejectedError(ack["reason"], "outside the vocabulary")
        return
    else:
        outcome = IngestOutcome(
            artifact=ARTIFACT_CUSTODY, state=REJECTED, reason=ack["reason"]
        )
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=_RecordingIngest(outcome))

    routed = router.handle_payload(
        json.dumps(_envelope(ARTIFACT_CUSTODY, {"v": 1})).encode()
    )

    if ack is None:
        assert routed.acknowledgement is None
    else:
        assert routed.acknowledgement is not None
        assert {
            "outcome": routed.acknowledgement["outcome"],
            "reason": routed.acknowledgement["reason"],
        } == ack


@pytest.mark.parametrize(
    "state, reason",
    [
        (REJECTED, None),
        (REJECTED, ""),
        (REJECTED, "not_a_contract_reason"),
        (REJECTED, "envelope_unauthenticated"),
        (ACCEPTED, ""),
        (ACCEPTED, REJECT_RESTATEMENT_CONFLICT),
        (UNDECIDED, REJECT_RESTATEMENT_CONFLICT),
        ("refused", REJECT_RESTATEMENT_CONFLICT),
    ],
)
def test_an_outcome_the_courier_could_misread_cannot_be_built(state, reason):
    """`refused` always names a vocabulary reason, and nothing else names one."""
    with pytest.raises(ValueError):
        IngestOutcome(artifact=ARTIFACT_CUSTODY, state=state, reason=reason)


@pytest.mark.parametrize("reason", sorted(REJECT_REASONS))
def test_every_vocabulary_reason_builds_a_refusal(reason):
    assert IngestOutcome(artifact=ARTIFACT_CUSTODY, state=REJECTED, reason=reason)


@pytest.mark.parametrize("reason", [None, "", "not_a_contract_reason"])
def test_a_refusal_without_a_vocabulary_reason_is_never_published(reason):
    """Checked again where the acknowledgement is built, past the dataclass."""
    outcome = IngestOutcome(
        artifact=ARTIFACT_CUSTODY, state=REJECTED, reason=REJECT_RESTATEMENT_CONFLICT
    )
    object.__setattr__(outcome, "reason", reason)
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=_RecordingIngest(outcome))

    routed = router.handle_payload(
        json.dumps(_envelope(ARTIFACT_CUSTODY, {"v": 1})).encode()
    )

    assert routed.acknowledgement is None


def _hostile_envelope(base: dict[str, Any], shape: str) -> bytes:
    """A message as a sender controls it: well shaped, not authenticated."""
    artifact: dict[str, Any] = dict(base, key_id=derive_custody_key_id(CUSTODY_SECRET))
    message: dict[str, Any] = {
        **_envelope(ARTIFACT_CUSTODY, _mac(artifact, CUSTODY_SECRET)),
        "auth": {
            "scheme": "hmac-sha256",
            "signed_at_ms": now_ms(),
            "signature": "hmac-sha256:" + "0" * 64,
        },
    }
    if shape == "non_ascii_signature":
        message["auth"]["signature"] = "hmac-sha256:é"
    elif shape == "surrogate":
        message["artifact"]["device_id"] = "\ud800"
    elif shape == "non_finite":
        message["artifact"]["custody_at_ms"] = float("inf")
    return json.dumps(message).encode()


HOSTILE = ["non_ascii_signature", "surrogate", "non_finite"]


@pytest.mark.parametrize("shape", HOSTILE)
@pytest.mark.parametrize("entry", ["handle_payload", "route"])
def test_a_hostile_envelope_is_refused_by_the_transport_and_changes_nothing(
    sealed, shape, entry
):
    attestor, _, base = sealed
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=attestor.ingest, message_auth=_authenticator()
    )
    held = _row(attestor)
    payload = _hostile_envelope(base, shape)

    if entry == "route":
        routed = asyncio.run(router.route(payload))
    else:
        routed = asyncio.run(asyncio.to_thread(router.handle_payload, payload))

    assert isinstance(routed.outcome, InboundRefusal)
    assert routed.outcome.reason == REFUSE_ENVELOPE_UNAUTHENTICATED
    assert routed.acknowledgement is None
    assert _row(attestor) == held
    assert attestor.application_storage_fault is False


@pytest.mark.parametrize("shape", HOSTILE)
def test_a_hostile_envelope_on_the_wire_is_released_once_and_unacknowledged(
    sealed, shape
):
    """Held, it would come back identical and be refused as a replay forever."""
    attestor, _, base = sealed
    client = _AckingClient()
    subscriber = _subscriber(client, ingest=attestor.ingest)

    async def scenario() -> None:
        shutdown = asyncio.Event()
        task = asyncio.create_task(subscriber.serve_until(shutdown))
        await wait_until(lambda: subscriber.connected, what="the route to come up")
        message = SimpleNamespace(payload=_hostile_envelope(base, shape), mid=9, qos=1)
        assert client.on_message is not None
        await asyncio.to_thread(client.on_message, client, None, message)
        await wait_until(lambda: client.acked, what="the message to be released")
        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())
    assert client.acked == [9]
    assert client.published == []
    assert subscriber._redelivery_owed is False


def test_an_admission_failure_no_rule_anticipated_is_a_transport_refusal(
    sealed, monkeypatch
):
    attestor, _, base = sealed
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=attestor.ingest, message_auth=_authenticator()
    )

    def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("a verifier defect")

    monkeypatch.setattr(router._message_auth, "verify", broken)
    routed = asyncio.run(router.route(_hostile_envelope(base, "valid_shape")))

    assert isinstance(routed.outcome, InboundRefusal)
    assert routed.outcome.reason == REFUSE_UNADMISSIBLE
    assert routed.acknowledgement is None


def test_a_decision_whose_acknowledgement_cannot_be_signed_stands_unanswered(
    sealed, monkeypatch
):
    attestor, _, base = sealed
    auth = _authenticator()
    router = EvidenceInboundRouter(
        device_id=DEVICE, ingest=attestor.ingest, message_auth=auth
    )
    artifact = dict(base, key_id=derive_custody_key_id(CUSTODY_SECRET))
    payload = _signed(_envelope(ARTIFACT_CUSTODY, _mac(artifact, CUSTODY_SECRET)))

    def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise ValueError("cannot sign")

    monkeypatch.setattr(auth, "sign", broken)
    routed = asyncio.run(router.route(payload))

    assert isinstance(routed.outcome, IngestOutcome) and routed.outcome.accepted
    assert routed.acknowledgement is None
    assert _row(attestor)["custody_state"] == "held"


def _deep(depth: int = 200_000) -> object:
    nested: object = "x"
    for _ in range(depth):
        nested = [nested]
    return nested


def test_a_member_nested_past_the_recursion_limit_is_refused_inbound(sealed):
    """str() of it raises; a member is read only as text."""
    attestor, router, _base = sealed
    routed = router.handle_payload(
        {"device_id": DEVICE, "artifact_type": _deep(), "artifact": {}}
    )
    assert isinstance(routed.outcome, InboundRefusal)
    assert routed.outcome.reason == REFUSE_UNKNOWN_ARTIFACT_TYPE
    assert routed.acknowledgement is None
