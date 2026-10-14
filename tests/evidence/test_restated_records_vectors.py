# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime held to `restated-records-v3.json`, evidence-exchange/v3's receiver state.

Each case states every held record before, one verified artifact, an injected
store fault or none, the answer, and every held record after. The receiver is
the production ledger and ingest service on their own evidence thread. Custody
acknowledgements, receipts and epoch confirmations arrive through
`EvidenceInboundRouter.handle_payload`; dispositions have no inbound route and
no shipped verifier on this release, so they enter through the bound ingest
service with a verifier built from the corpus's own registry. Every held
record is read back from the store after each case.

A store fault is injected by failing one statement on the ledger's own
connection: the first read of the attempt (`at_read`), the second write
(`after_first_write`), the commit (`at_commit`), or the refusal record's
insert (`at_refusal_record`).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import pathlib
import sqlite3
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ori.gateway.evidence_inbound import (
    ARTIFACT_CUSTODY,
    ARTIFACT_EPOCH,
    ARTIFACT_RECEIPT,
    EvidenceInboundRouter,
)
from ori.security.evidence.authority_keys import (
    PURPOSE_DISPOSITION,
    AuthorityKey,
    parse_authority_key_registry,
    select_verifying_key,
)
from ori.security.evidence.bound import BoundIngestService
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.custody_keys import (
    CustodyKeyRegistry,
    derive_custody_key_id,
)
from ori.security.evidence.device_key import EvidenceDeviceKey
from ori.security.evidence.disposition import (
    DispositionScope,
    DispositionValue,
    VerifiedDisposition,
)
from ori.security.evidence.executor import EvidenceExecutor
from ori.security.evidence.ingest import REJECT_REASONS
from ori.security.evidence.ingest_service import (
    ACCEPTED,
    REJECTED,
    UNDECIDED,
    EvidenceIngestService,
    IngestOutcome,
)
from ori.security.evidence.ledger import EvidenceDeliveryLedger
from ori.security.evidence.store import NestedEvidenceTransactionError

CORPUS = json.loads(
    (
        pathlib.Path(__file__).resolve().parent.parent
        / "vectors"
        / "evidence_exchange_receiver_state"
        / "restated-records-v3.json"
    ).read_text()
)
CASES = CORPUS["cases"]
DEVICE = CORPUS["device"]["device_id"]
SEALING_EPOCH = CORPUS["device"]["sealing_epoch"]
DISPOSITION_DOMAIN = CORPUS["domains"]["evidence_disposition"].encode() + b"\x00"
ROUTED = {
    "custody_acknowledgement": ARTIFACT_CUSTODY,
    "delivery_receipt": ARTIFACT_RECEIPT,
    "epoch_confirmation": ARTIFACT_EPOCH,
}
ENVELOPE_LABEL = "ori-specs evidence-exchange/v3 restated records envelope {}"
FAULT = "disk I/O error"
ROLLBACK_FAULT = "disk I/O error during rollback"


def _secret(generation: str) -> str:
    return bytes.fromhex(CORPUS["custody_registry"][generation]["secret_hex"]).decode()


def _custody_keys() -> CustodyKeyRegistry:
    return CustodyKeyRegistry(
        active_secret=_secret("active"), previous_secret=_secret("verify_only")
    )


def _registry() -> dict[tuple[str, str], AuthorityKey]:
    return parse_authority_key_registry(CORPUS["authority_key_registry"])


class CorpusDispositionVerifier:
    """Shape, `(evidence_authority_disposition, key_id)` selection and signature.

    `digest` is over the wire bytes, the complete signed artifact, so a body
    re-signed is a different disposition.
    """

    def __init__(self, registry: dict[tuple[str, str], AuthorityKey]) -> None:
        self._registry = registry

    def verify_disposition(self, artifact: object) -> VerifiedDisposition | None:
        assert isinstance(artifact, dict)
        key = select_verifying_key(
            self._registry, PURPOSE_DISPOSITION, artifact["key_id"]
        )
        body = {k: v for k, v in artifact.items() if k != "signature"}
        signature = base64.b64decode(
            artifact["signature"].removeprefix("ed25519:"), validate=True
        )
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex)).verify(
            signature, DISPOSITION_DOMAIN + canonical_json(body)
        )
        return VerifiedDisposition(
            digest="sha256:" + hashlib.sha256(canonical_json(artifact)).hexdigest(),
            triggering_digest=artifact["triggering_digest"],
            device_id=artifact["device_id"],
            anchor_epoch_id=artifact["anchor_epoch_id"],
            scope=DispositionScope(artifact["scope"]),
            value=DispositionValue(artifact["disposition"]),
            decided_at_ms=artifact["decided_at_ms"],
            key_id=artifact["key_id"],
        )


class FaultingConnection:
    """The ledger's connection, failing one statement of one attempt."""

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real
        self.point: str | None = None
        self.fired = False
        self._writes = 0

    def arm(self, point: str | None) -> None:
        self.point, self.fired, self._writes = point, False, 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def execute(self, sql: str, params: Any = ()) -> sqlite3.Cursor:
        statement = " ".join(sql.split()).upper()
        if self.point == "commit_and_rollback":
            # The commit fails, and so does the rollback that follows it.
            if statement == "COMMIT" and not self.fired:
                self.fired = True
                raise sqlite3.OperationalError(FAULT)
            if statement == "ROLLBACK" and self.fired:
                self.point = None
                raise sqlite3.OperationalError(ROLLBACK_FAULT)
            return self._real.execute(sql, params)
        if self.point is not None and not self.fired:
            if statement.startswith(("UPDATE", "INSERT")):
                self._writes += 1
            fire = (
                (self.point == "at_read" and statement.startswith("SELECT"))
                or (self.point == "after_first_write" and self._writes == 2)
                or (self.point == "at_commit" and statement == "COMMIT")
                or (
                    self.point == "at_refusal_record"
                    and statement.startswith("INSERT INTO EVIDENCE_INGEST_REFUSALS")
                )
            )
            if fire:
                self.fired = True
                raise sqlite3.OperationalError(FAULT)
        return self._real.execute(sql, params)


class Receiver:
    """A ledger, ingest service and route holding one case's `held_before`."""

    def __init__(self, tmp_path: pathlib.Path, held: dict[str, Any]) -> None:
        self.executor = EvidenceExecutor()
        key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "install")
        registry = _registry()

        def open_ledger() -> EvidenceDeliveryLedger:
            return EvidenceDeliveryLedger(
                tmp_path / "ledger.db",
                key,
                DEVICE,
                anchor_epoch_id=SEALING_EPOCH,
                key_id="corpus-sealing-key",
            )

        self.ledger = self.executor.run(open_ledger)
        self.service = EvidenceIngestService(
            ledger=self.ledger,
            registry=registry,
            device_id=DEVICE,
            device_pubkey_hex=CORPUS["device"]["pubkey_hex"],
            custody_keys=_custody_keys(),
            disposition_verifier=CorpusDispositionVerifier(registry),
        )
        self.ingest = BoundIngestService(self.executor, self.service)
        self.router = EvidenceInboundRouter(device_id=DEVICE, ingest=self.ingest)
        self.executor.run(self._hold, held)
        self.service._application_storage_fault = bool(
            held["application_storage_fault"]
        )
        self.connection = FaultingConnection(self.ledger._connection)
        self.ledger._connection = self.connection  # type: ignore[assignment]

    def close(self) -> None:
        self.executor.close(teardown=self.ledger.close)

    def _hold(self, held: dict[str, Any]) -> None:
        db = self.ledger._connection
        for n, env in enumerate(CORPUS["sealed_envelopes"], 1):
            db.execute(
                """
                INSERT INTO evidence_delivery_ledger (
                    local_seq, event_id, chain_seq, device_id, anchor_epoch_id,
                    key_id, envelope_json, envelope_digest, chain_row_digest,
                    sealed_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    env["local_seq"],
                    f"corpus-event-{n}",
                    n,
                    DEVICE,
                    env["anchor_epoch_id"],
                    "corpus-sealing-key",
                    # The bytes the corpus's envelope digest is taken over
                    # (its sealed_note), so the stored digest holds to them.
                    ENVELOPE_LABEL.format(env["local_seq"]),
                    env["envelope_digest"],
                    env["chain_row_digest"],
                    1787000000000 + n,
                ),
            )
        states = {
            (o["anchor_epoch_id"], o["pubkey_hex"]): o
            for o in held["registration_obligations"]
        }
        for n, reg in enumerate(CORPUS["sealed_registrations"], 1):
            state = states[(reg["anchor_epoch_id"], reg["pubkey_hex"])]
            db.execute(
                """
                INSERT INTO evidence_registration_obligation (
                    device_id, anchor_epoch_id, pubkey_hex, commissioning_reference,
                    artifact_json, artifact_digest, sealed_at_ms, state, closed_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    DEVICE,
                    reg["anchor_epoch_id"],
                    reg["pubkey_hex"],
                    "sha256:" + "a" * 64,
                    "{}",
                    f"sha256:{n:064x}",
                    1787000000000,
                    state["state"],
                    state["closed_at_ms"],
                ),
            )
        for sealed in CORPUS["sealed_artifacts"]:
            db.execute(
                """
                INSERT INTO evidence_outbox (
                    artifact_type, artifact_json, artifact_digest, created_at_ms
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    sealed["artifact_type"],
                    json.dumps(
                        {
                            "device_id": DEVICE,
                            "anchor_epoch_id": sealed["anchor_epoch_id"],
                        }
                    ),
                    sealed["digest"],
                    1787000000000,
                ),
            )
        for c in held["custody"]:
            db.execute(
                """
                UPDATE evidence_delivery_ledger
                   SET custody_state = 'held', custody_at_ms = ?, custody_key_id = ?,
                       custody_recorded_at_ms = ?
                 WHERE local_seq = ?
                """,
                (c["custody_at_ms"], c["key_id"], c["recorded_at_ms"], c["local_seq"]),
            )
        for r in held["receipts"]:
            db.execute(
                """
                UPDATE evidence_delivery_ledger
                   SET receipt_state = 'accepted', receipt_at_ms = ?, receipt_key_id = ?
                 WHERE local_seq = ?
                """,
                (r["accepted_at_ms"], r["key_id"], r["local_seq"]),
            )
        for e in held["epoch_confirmations"]:
            db.execute(
                """
                INSERT INTO evidence_registration_confirmation (
                    anchor_epoch_id, device_id, pubkey_hex, actor, confirmed_at_ms,
                    key_id, applied_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    e["anchor_epoch_id"],
                    e["device_id"],
                    e["pubkey_hex"],
                    e["actor"],
                    e["confirmed_at_ms"],
                    e["key_id"],
                    e["applied_at_ms"],
                ),
            )
        active = held["active_epoch"]
        if active is not None:
            db.execute(
                """
                INSERT INTO evidence_device_epochs (
                    device_id, anchor_epoch_id, pubkey_hex, actor, confirmed_at_ms,
                    key_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    active["device_id"],
                    active["anchor_epoch_id"],
                    active["pubkey_hex"],
                    active["actor"],
                    active["confirmed_at_ms"],
                    active["key_id"],
                ),
            )
        types = {a["digest"]: a["artifact_type"] for a in CORPUS["sealed_artifacts"]}
        for d in held["dispositions"]:
            db.execute(
                """
                INSERT INTO evidence_disposition (
                    digest, triggering_digest, artifact_type, device_id,
                    anchor_epoch_id, scope, disposition, decided_at_ms, key_id,
                    observed_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    d["artifact_digest"],
                    d["triggering_digest"],
                    types[d["triggering_digest"]],
                    DEVICE,
                    d["anchor_epoch_id"],
                    d["scope"],
                    d["disposition"],
                    d["decided_at_ms"],
                    d["key_id"],
                    1787000000000,
                ),
            )
        for s in held["stops"]:
            identity = s["scope"] == "identity"
            db.execute(
                """
                INSERT INTO evidence_offer_stop (
                    scope, device_id, anchor_epoch_id, disposition, artifact_digest,
                    stopped_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    s["scope"],
                    DEVICE,
                    None if identity else s["anchor_epoch_id"],
                    "identity_replacement_required"
                    if identity
                    else "epoch_reprovisioning_required",
                    "sha256:" + "f" * 64,
                    1787000000000,
                ),
            )

    def held(self) -> dict[str, Any]:
        """Every held record, read from the store in the corpus's shape."""
        return {
            **self.executor.run(self._read, self.connection._real),
            "application_storage_fault": self.service.application_storage_fault,
        }

    @staticmethod
    def _read(db: sqlite3.Connection) -> dict[str, Any]:
        rows = db.execute(
            "SELECT * FROM evidence_delivery_ledger ORDER BY local_seq"
        ).fetchall()
        confirmations = db.execute(
            "SELECT * FROM evidence_registration_confirmation ORDER BY rowid"
        ).fetchall()
        active = db.execute(
            "SELECT * FROM evidence_device_epochs WHERE device_id = ?", (DEVICE,)
        ).fetchone()
        obligations = db.execute(
            "SELECT * FROM evidence_registration_obligation ORDER BY id"
        ).fetchall()
        dispositions = db.execute(
            "SELECT * FROM evidence_disposition ORDER BY rowid"
        ).fetchall()
        stops = db.execute("SELECT * FROM evidence_offer_stop ORDER BY id").fetchall()
        projection = (
            "device_id",
            "anchor_epoch_id",
            "pubkey_hex",
            "actor",
            "confirmed_at_ms",
            "key_id",
        )
        return {
            "custody": [
                {
                    "local_seq": r["local_seq"],
                    "custody_at_ms": r["custody_at_ms"],
                    "key_id": r["custody_key_id"],
                    "recorded_at_ms": r["custody_recorded_at_ms"],
                }
                for r in rows
                if r["custody_state"] == "held"
            ],
            "receipts": [
                {
                    "local_seq": r["local_seq"],
                    "accepted_at_ms": r["receipt_at_ms"],
                    "key_id": r["receipt_key_id"],
                }
                for r in rows
                if r["receipt_state"] == "accepted"
            ],
            "epoch_confirmations": [
                {k: c[k] for k in (*projection, "applied_at_ms")} for c in confirmations
            ],
            "active_epoch": (
                None if active is None else {k: active[k] for k in projection}
            ),
            "registration_obligations": [
                {
                    "anchor_epoch_id": o["anchor_epoch_id"],
                    "pubkey_hex": o["pubkey_hex"],
                    "state": o["state"],
                    "closed_at_ms": o["closed_at_ms"],
                }
                for o in obligations
            ],
            "dispositions": [
                {
                    "triggering_digest": d["triggering_digest"],
                    "anchor_epoch_id": d["anchor_epoch_id"],
                    "scope": d["scope"],
                    "disposition": d["disposition"],
                    "decided_at_ms": d["decided_at_ms"],
                    "key_id": d["key_id"],
                    "artifact_digest": d["digest"],
                }
                for d in dispositions
            ],
            "stops": [
                {"scope": s["scope"], "anchor_epoch_id": s["anchor_epoch_id"] or ""}
                for s in stops
            ],
        }

    def refusals(self) -> int:
        real = self.connection._real
        return self.executor.run(
            lambda: len(
                real.execute("SELECT id FROM evidence_ingest_refusals").fetchall()
            )
        )

    def deliver(self, case: dict[str, Any]) -> tuple[IngestOutcome, Any]:
        """The case's artifact through its real entry point: outcome and answer."""
        self.connection.arm(case["store_fault"])
        try:
            with patch(
                "ori.security.evidence.ingest_service.now_ms",
                lambda: case["receiver_now_ms"],
            ):
                if case["artifact_type"] == "evidence_disposition":
                    outcome = self.ingest.accept_disposition(dict(case["artifact"]))
                    return outcome, None
                payload = json.dumps(
                    {
                        "device_id": DEVICE,
                        "artifact_type": ROUTED[case["artifact_type"]],
                        "artifact": case["artifact"],
                    }
                ).encode()
                routed = self.router.handle_payload(payload)
                assert isinstance(routed.outcome, IngestOutcome)
                return routed.outcome, routed.acknowledgement
        finally:
            fired = self.connection.fired
            self.connection.arm(None)
            assert fired is (case["store_fault"] is not None), (
                f"the {case['store_fault']} fault was never reached"
            )


@pytest.fixture
def receiver(tmp_path, request):
    made: list[Receiver] = []

    def build(held: dict[str, Any]) -> Receiver:
        made.append(Receiver(tmp_path, held))
        return made[-1]

    yield build
    for r in made:
        r.close()


def test_the_corpus_material_is_what_the_runtime_derives() -> None:
    """The custody key ids derive from the published secrets, and the vocabulary is closed."""
    for generation in ("active", "verify_only"):
        assert (
            derive_custody_key_id(_secret(generation))
            == CORPUS["custody_registry"][generation]["key_id"]
        )
    reasons = {c["reject_reason"] for c in CASES if c["reject_reason"]}
    assert reasons <= REJECT_REASONS


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_every_restated_record_case(receiver, case) -> None:
    held = receiver(case["held_before"])
    assert held.held() == case["held_before"], "the fixture did not hold the state"
    refusals_before = held.refusals()

    outcome, acknowledgement = held.deliver(case)

    expected = case["expected"]
    if expected == "accept":
        assert outcome.state == ACCEPTED, outcome
        if case["artifact_type"] in ROUTED:
            assert acknowledgement is not None
            assert acknowledgement["outcome"] == "applied"
            assert acknowledgement["reason"] == ""
    elif expected == "reject":
        assert (outcome.state, outcome.reason) == (REJECTED, case["reject_reason"])
        if case["artifact_type"] in ROUTED:
            assert acknowledgement is not None
            assert acknowledgement["outcome"] == "refused"
            assert acknowledgement["reason"] == case["reject_reason"]
    else:
        assert expected == "undecided"
        assert (outcome.state, outcome.reason, outcome.decided) == (
            UNDECIDED,
            None,
            False,
        )
        assert acknowledgement is None
    if case["applied_sequences"] is not None:
        assert list(outcome.applied_sequences) == case["applied_sequences"]

    recorded = held.refusals() - refusals_before
    if expected == "reject" and case["store_fault"] is None:
        assert recorded == 1
    else:
        assert recorded == 0, "only a refusal whose record could be written is kept"

    assert held.held() == case["held_after"]


def test_a_faulted_attempt_then_a_redelivery_decides_afresh(receiver) -> None:
    """The store recovers and the same bytes arrive again: applied as if new."""
    faulted = next(c for c in CASES if c["name"] == "receipt_store_fault_at_commit")
    held = receiver(faulted["held_before"])
    held.deliver(faulted)
    assert held.held()["application_storage_fault"] is True

    again = dict(faulted, store_fault=None)
    outcome, acknowledgement = held.deliver(again)
    assert outcome.accepted and acknowledgement["outcome"] == "applied"
    after = held.held()
    assert after["application_storage_fault"] is False
    assert [r["local_seq"] for r in after["receipts"]] == list(
        range(faulted["artifact"]["from_seq"], faulted["artifact"]["to_seq"] + 1)
    )


def test_a_repeat_is_its_wire_bytes_whatever_order_its_members_arrive_in(
    receiver,
) -> None:
    """Members reordered in transit are the same canonical wire bytes: a repeat.

    A re-signed body is not, which the corpus's re-signed cases fix.
    """
    case = next(c for c in CASES if c["name"] == "disposition_byte_identical_repeat")
    held = receiver(case["held_before"])
    reordered = dict(reversed(list(case["artifact"].items())))

    outcome, _ = held.deliver(dict(case, artifact=reordered))

    assert outcome.state == ACCEPTED
    assert held.held() == case["held_after"]


def _route(held: Receiver, case: dict[str, Any], *, fault: str | None) -> Any:
    """The case's artifact through `route`, the path the MQTT subscriber awaits."""
    held.connection.arm(fault)
    payload = json.dumps(
        {
            "device_id": DEVICE,
            "artifact_type": ROUTED[case["artifact_type"]],
            "artifact": case["artifact"],
        }
    ).encode()
    with patch(
        "ori.security.evidence.ingest_service.now_ms", lambda: case["receiver_now_ms"]
    ):
        return asyncio.run(held.router.route(payload))


def test_a_refusal_whose_record_failed_is_recorded_on_redelivery(receiver) -> None:
    """The failed write is not remembered as written, so the next one is tried."""
    case = next(
        c for c in CASES if c["name"] == "custody_conflict_refusal_record_unwritable"
    )
    held = receiver(case["held_before"])

    first = _route(held, case, fault="at_refusal_record")
    assert held.connection.fired
    assert first.outcome.reason == case["reject_reason"]
    assert held.refusals() == 0

    again = _route(held, case, fault=None)
    assert again.outcome.reason == case["reject_reason"]
    assert held.refusals() == 1


def test_a_failed_rollback_does_not_strand_later_applications(receiver) -> None:
    """COMMIT and then ROLLBACK fail; the next artifact still applies."""
    case = next(c for c in CASES if c["name"] == "receipt_store_fault_at_commit")
    held = receiver(case["held_before"])

    first = _route(held, case, fault="commit_and_rollback")
    assert held.connection.fired
    assert first.outcome.state == UNDECIDED and first.acknowledgement is None
    assert held.service.application_storage_fault is True
    assert not held.ledger._connection.in_transaction
    assert held.executor.run(_pragmas, held.ledger._connection) == LEDGER_PRAGMAS

    again = _route(held, case, fault=None)
    assert again.outcome.state == ACCEPTED
    assert held.service.application_storage_fault is False
    receipted = {
        r["local_seq"]
        for r in held.executor.run(
            lambda: Receiver._read(held.ledger._connection)["receipts"]
        )
    }
    assert set(range(case["artifact"]["from_seq"], case["artifact"]["to_seq"] + 1)) <= (
        receipted
    )


def test_a_ledger_that_cannot_reopen_at_once_reopens_before_the_next_write(
    receiver, monkeypatch
) -> None:
    case = next(c for c in CASES if c["name"] == "receipt_store_fault_at_commit")
    held = receiver(case["held_before"])
    reopen = held.ledger._store._reopen
    attempts: list[int] = []

    def flaky() -> None:
        attempts.append(1)
        if len(attempts) == 1:
            raise sqlite3.OperationalError("unable to open database file")
        reopen()

    monkeypatch.setattr(held.ledger._store, "_reopen", flaky)

    first = _route(held, case, fault="commit_and_rollback")
    assert first.outcome.state == UNDECIDED

    again = _route(held, case, fault=None)
    assert again.outcome.state == ACCEPTED
    assert len(attempts) == 2


LEDGER_PRAGMAS = {
    "busy_timeout": 5000,
    "journal_mode": "wal",
    "foreign_keys": 1,
    "synchronous": 2,
}


def _pragmas(connection: sqlite3.Connection) -> dict[str, Any]:
    return {
        name: connection.execute(f"PRAGMA {name}").fetchone()[0]
        for name in LEDGER_PRAGMAS
    }


def test_an_outbound_transaction_whose_rollback_fails_heals_for_inbound(
    receiver,
) -> None:
    """The boot counter's COMMIT and ROLLBACK both fail: the commit's error is
    the one raised, and the next inbound artifact still applies."""
    case = next(c for c in CASES if c["name"] == "receipt_store_fault_at_commit")
    held = receiver(case["held_before"])
    held.connection.arm("commit_and_rollback")

    with pytest.raises(sqlite3.OperationalError) as raised:
        held.executor.run(held.ledger._allocate_boot_id)
    assert str(raised.value) == FAULT
    assert held.connection.fired

    applied = _route(held, case, fault=None)
    assert applied.outcome.state == ACCEPTED
    assert held.executor.run(_pragmas, held.ledger._connection) == LEDGER_PRAGMAS


def test_a_transaction_left_open_anywhere_is_healed_by_the_next_one(receiver) -> None:
    """A leak is a transaction open while no transaction frame is live; one
    opened inside a live frame is nesting, refused rather than healed (see
    tests/evidence/test_store.py)."""
    case = next(c for c in CASES if c["name"] == "receipt_store_fault_at_commit")
    held = receiver(case["held_before"])
    held.executor.run(held.connection._real.execute, "BEGIN IMMEDIATE")
    assert held.executor.run(lambda: held.ledger._connection.in_transaction)
    assert held.ledger._store._depth == 0

    applied = _route(held, case, fault=None)

    assert applied.outcome.state == ACCEPTED
    receipted = {
        r["local_seq"]
        for r in held.executor.run(
            lambda: Receiver._read(held.ledger._connection)["receipts"]
        )
    }
    assert set(range(case["artifact"]["from_seq"], case["artifact"]["to_seq"] + 1)) <= (
        receipted
    )


def test_a_nested_application_is_refused_and_the_outer_rolls_back_whole(
    receiver,
) -> None:
    """Not healed as a leak: the outer's own write is rolled back with it."""
    case = next(c for c in CASES if c["name"] == "receipt_store_fault_at_commit")
    held = receiver(case["held_before"])
    before = held.held()

    def nested() -> None:
        with held.ledger._application():
            held.ledger._connection.execute(
                "UPDATE evidence_delivery_ledger SET attempts = attempts + 1"
            )
            with held.ledger._application():
                pass  # pragma: no cover - refused on entry

    with pytest.raises(NestedEvidenceTransactionError):
        held.executor.run(nested)

    assert held.held() == before
    attempts = held.executor.run(
        lambda: held.ledger._connection.execute(
            "SELECT SUM(attempts) FROM evidence_delivery_ledger"
        ).fetchone()[0]
    )
    assert attempts == 0


def _corrupt(held: Receiver, sql: str, params: tuple[Any, ...] = ()) -> None:
    """Damage one stored value past the schema's own guards, then restore them."""

    def damage() -> None:
        db = held.connection._real
        triggers = db.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
        for row in triggers:
            db.execute(f'DROP TRIGGER "{row[0]}"')
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.execute(sql, params)
        db.execute("PRAGMA ignore_check_constraints=OFF")
        for row in triggers:
            db.execute(row[1])

    held.executor.run(damage)


TOO_LARGE = 2**53
BAD_KEY = "not-a-key"

DAMAGED_RECORDS = [
    (
        "custody_identical_repeat",
        "UPDATE evidence_delivery_ledger SET custody_at_ms = ? WHERE local_seq = 1",
        (TOO_LARGE,),
    ),
    (
        "custody_identical_repeat",
        "UPDATE evidence_delivery_ledger SET custody_key_id = ? WHERE local_seq = 1",
        (BAD_KEY,),
    ),
    (
        "custody_identical_repeat",
        "UPDATE evidence_delivery_ledger SET custody_recorded_at_ms = ?"
        " WHERE local_seq = 1",
        (TOO_LARGE,),
    ),
    (
        "custody_identical_repeat",
        "UPDATE evidence_delivery_ledger SET custody_state = 'broken'"
        " WHERE local_seq = 1",
        (),
    ),
    (
        "custody_first_acceptance",
        "UPDATE evidence_delivery_ledger SET envelope_digest = ? WHERE local_seq = 1",
        ("sha256:" + "0" * 64,),
    ),
    (
        "receipt_union_over_held_prefix",
        "UPDATE evidence_delivery_ledger SET receipt_state = 'broken'"
        " WHERE local_seq = 1",
        (),
    ),
    (
        "receipt_union_over_held_prefix",
        "UPDATE evidence_delivery_ledger SET receipt_at_ms = ? WHERE local_seq = 1",
        (TOO_LARGE,),
    ),
    (
        "receipt_union_over_held_prefix",
        "UPDATE evidence_delivery_ledger SET receipt_key_id = ? WHERE local_seq = 1",
        (BAD_KEY,),
    ),
    (
        "receipt_identical_repeat",
        "UPDATE evidence_delivery_ledger SET envelope_digest = ? WHERE local_seq = 2",
        ("sha256:" + "0" * 64,),
    ),
    (
        "confirmation_identical",
        "UPDATE evidence_registration_confirmation SET confirmed_at_ms = ?",
        (TOO_LARGE,),
    ),
    (
        "confirmation_identical",
        "UPDATE evidence_registration_confirmation SET key_id = ?",
        (BAD_KEY,),
    ),
    (
        "confirmation_identical",
        "UPDATE evidence_registration_confirmation SET applied_at_ms = ?",
        (TOO_LARGE,),
    ),
    (
        "confirmation_identical",
        "UPDATE evidence_registration_confirmation SET device_id = 'another-device'",
        (),
    ),
    (
        "confirmation_identical",
        "UPDATE evidence_registration_confirmation SET pubkey_hex = 'bad-key'",
        (),
    ),
    (
        "disposition_first_application",
        "UPDATE evidence_outbox SET artifact_json = ?",
        (json.dumps({"device_id": DEVICE, "anchor_epoch_id": ""}),),
    ),
]


@pytest.mark.parametrize(
    "name, sql, params",
    DAMAGED_RECORDS,
    ids=[f"{name}-{i}" for i, (name, _, _) in enumerate(DAMAGED_RECORDS)],
)
def test_a_damaged_held_record_is_a_store_fault_never_a_decision(
    receiver, name, sql, params
) -> None:
    """Neither a retiring refusal blaming the artifact, nor a rewrite of the
    first record: the store failed, so the artifact is left undecided."""
    case = next(c for c in CASES if c["name"] == name)
    held = receiver(case["held_before"])
    _corrupt(held, sql, params)
    damaged = held.executor.run(Receiver._read, held.connection._real)

    outcome, acknowledgement = held.deliver(dict(case, store_fault=None))

    assert (outcome.state, outcome.reason) == (UNDECIDED, None), outcome
    assert acknowledgement is None
    assert held.service.application_storage_fault is True
    assert held.executor.run(Receiver._read, held.connection._real) == damaged
