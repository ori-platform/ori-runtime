# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Registration state never gates, delays or suppresses an approved Tier C or any Tier D.

Each case drives the real dispatcher, with a real state store and a real
evidence attestor brought into one registration state, and compares the
outcome with the same dispatch in every other state. The attestor's
registration surface is armed to fail the test if the dispatch path reads it.
"""

from __future__ import annotations

import ast
import base64
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.network.events import ActionTier, OriEvent, ReasoningResult, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import SkillContext
from ori.security.evidence import first_party, ledger
from ori.security.evidence.authority_keys import (
    PURPOSE_EPOCH,
    STATUS_ACTIVE,
    AuthorityKey,
)
from ori.security.evidence.canonical import canonical_json
from ori.security.evidence.disposition import (
    DispositionScope,
    DispositionValue,
    VerifiedDisposition,
)
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.evidence.ingest import EPOCH_DOMAIN
from ori.security.evidence.registration import (
    CONFIRMATION_OVERDUE_MS,
    DELIVERY_STATUS_FIELD,
)
from ori.state import store as state_store_module
from ori.state.store import StateStore, record_evidence_commissioning_reference

DEVICE = "dev-01"
REFERENCE = "sha256:" + "ab" * 32
EPOCH_SEED = bytes(range(32, 64))
EPOCH_KEY_ID = "authority-epoch-1"
STATES = (
    "pending_authorisation",
    "pending_confirmation",
    "overdue",
    "confirmed",
    "suspended",
    "closed",
    "epoch_stopped",
    "identity_stopped",
)


@dataclass
class _Skill:
    name: str = "energy-anomaly-detector"
    version: str = "0.2.1"
    config: dict = field(default_factory=dict)
    triggers: list = field(default_factory=list)
    actions: dict = field(default_factory=dict)
    first_party: bool = True


def _event() -> OriEvent:
    reading = SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=60.0,
        unit="ampere",
        timestamp=int(time.time() * 1000),
        quality=1.0,
    )
    return OriEvent.from_reading(reading, DEVICE)


def _result(tier: str) -> ReasoningResult:
    return ReasoningResult(
        text="Overcurrent.",
        tier="rule",
        model="",
        tokens_used=0,
        latency_ms=0,
        action_tier=tier,
    )


def _pub(seed: bytes) -> str:
    return (
        Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()
    )


def _confirmation(attestor: FirstPartyEvidenceAttestor) -> dict[str, Any]:
    assert attestor.anchor is not None
    body: dict[str, Any] = {
        "v": 1,
        "device_id": DEVICE,
        "anchor_epoch_id": attestor.anchor.anchor_epoch_id,
        "pubkey_hex": attestor.public_key_hex,
        "actor": "commissioner@site",
        "confirmed_at_ms": 1787000009000,
        "key_id": EPOCH_KEY_ID,
    }
    signature = Ed25519PrivateKey.from_private_bytes(EPOCH_SEED).sign(
        EPOCH_DOMAIN + canonical_json(body)
    )
    body["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return body


class _Verifier:
    """The disposition seam, returning whatever the state under test needs."""

    def __init__(self) -> None:
        self.next: VerifiedDisposition | None = None

    def verify_disposition(self, artifact: object) -> VerifiedDisposition | None:
        return self.next


_DISPOSED = {
    "suspended": (DispositionValue.RETAINED_PENDING, DispositionScope.ARTIFACT),
    "closed": (DispositionValue.ARTIFACT_TERMINAL, DispositionScope.ARTIFACT),
    "epoch_stopped": (
        DispositionValue.EPOCH_REPROVISIONING_REQUIRED,
        DispositionScope.EPOCH,
    ),
    "identity_stopped": (
        DispositionValue.IDENTITY_REPLACEMENT_REQUIRED,
        DispositionScope.IDENTITY,
    ),
}


async def _commission(
    attestor: FirstPartyEvidenceAttestor, store: StateStore, db_path: Path
) -> None:
    """Record the reference the way the command does, and reconcile from the store."""
    assert attestor.anchor is not None
    record_evidence_commissioning_reference(
        db_path,
        device_id=DEVICE,
        anchor_epoch_id=attestor.anchor.anchor_epoch_id,
        commissioning_reference=REFERENCE,
        force=False,
        recorded_at_ms=first_party.now_ms(),
    )
    reference = await store.get_evidence_commissioning_reference(
        device_id=DEVICE, anchor_epoch_id=attestor.anchor.anchor_epoch_id
    )
    assert reference == REFERENCE
    await attestor.reconcile_registration(reference)


async def _attestor_in(
    state: str, tmp_path: Path, store: StateStore, db_path: Path
) -> FirstPartyEvidenceAttestor:
    verifier = _Verifier()
    attestor = FirstPartyEvidenceAttestor(
        db_path=str(tmp_path / "evidence.db"),
        key_path=str(tmp_path / "evidence.key"),
        device_secret="install-secret-for-gating-tests",
        device_id=DEVICE,
        authority_keys={
            (PURPOSE_EPOCH, EPOCH_KEY_ID): AuthorityKey(
                EPOCH_KEY_ID, _pub(EPOCH_SEED), PURPOSE_EPOCH, STATUS_ACTIVE
            )
        },
        disposition_verifier=verifier,
    )
    assert await attestor.start()
    if state == "overdue":
        sealed_at = first_party.now_ms() - CONFIRMATION_OVERDUE_MS - 60_000
        with patch.object(first_party, "now_ms", return_value=sealed_at):
            await _commission(attestor, store, db_path)
    elif state != "pending_authorisation":
        await _commission(attestor, store, db_path)
    assert attestor.ingest is not None
    if state == "confirmed":
        assert attestor.ingest.accept_epoch_confirmation(
            _confirmation(attestor)
        ).accepted
    if state in _DISPOSED:
        assert attestor.anchor is not None and attestor.outbound is not None
        value, scope = _DISPOSED[state]
        if scope is DispositionScope.ARTIFACT:
            [held] = await attestor.outbound.pending_artifacts()
        else:
            # Epoch and identity dispositions are emitted from checkpoints.
            held = await attestor.issue_checkpoint()
            assert held is not None
        verifier.next = VerifiedDisposition(
            digest="sha256:" + "d" * 64,
            triggering_digest=str(held["artifact_digest"]),
            device_id=DEVICE,
            anchor_epoch_id=attestor.anchor.anchor_epoch_id,
            scope=scope,
            value=value,
            decided_at_ms=1787000009000,
            key_id="authority-disposition-1",
        )
        assert attestor.ingest.accept_disposition({}).accepted

    fields = await attestor.registration_health(first_party.now_ms())
    assert fields is not None
    expected_status = {
        "pending_authorisation": "pending_authorisation",
        "confirmed": "confirmed",
    }.get(state, "pending_confirmation")
    assert fields["registration_status"] == expected_status
    if state == "closed":
        assert fields["registration_offer"] == "closed"
    assert fields["registration_confirmation_overdue"] is (state == "overdue")
    return attestor


def _arm(attestor: FirstPartyEvidenceAttestor) -> None:
    """Fail loudly if dispatch consults registration state at all."""

    async def consulted(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("the dispatch path consulted registration state")

    attestor.registration_health = consulted  # type: ignore[method-assign]
    attestor.reconcile_registration = consulted  # type: ignore[method-assign]


async def _dispatch(state: str, tier: str, tmp_path: Path) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "state.db"
    # One store: the one the reference is recorded in is the one the
    # dispatcher writes to, so a gate reading it would be seen here.
    store = StateStore(db_path=str(db_path))
    await store.open()
    attestor = await _attestor_in(state, tmp_path, store, db_path)
    _arm(attestor)
    try:
        references = await store.get_evidence_commissioning_reference(
            device_id=DEVICE,
            anchor_epoch_id=attestor.anchor.anchor_epoch_id if attestor.anchor else "",
        )
        assert (references is None) is (state == "pending_authorisation")
        order: list[str] = []
        executor = AsyncMock(side_effect=lambda *_a, **_k: order.append("executed"))
        dispatcher = ActionDispatcher(
            state_store=store,
            alert_sender=AsyncMock(),
            evidence_attestor=attestor,
            config={"operator_contact": "+234800000000"},
        )
        action = "close_gas_valve" if tier == "C" else "trip_relay"
        dispatcher.register_executor(action, executor)
        dispatcher.register_executor("log_to_dashboard", AsyncMock(return_value=True))
        context = SkillContext(
            skill=_Skill(),
            event=_event(),
            state_store=store,
            trigger_name="dangerous_overcurrent",
        )
        with (
            patch(
                "ori.reasoning.action_dispatcher._generate_proposal_id",
                return_value="AB12CD34",
            ),
            patch.object(
                dispatcher,
                "_listen_for_response",
                new=AsyncMock(return_value="YES-AB12CD34"),
            ),
        ):
            started = time.monotonic()
            result = await dispatcher.dispatch(
                action,
                ActionTier.HARD_PHYSICAL if tier == "C" else ActionTier.SAFETY_CRITICAL,
                context,
                _result(tier),
                approval_timeout_seconds=10,
            )
            elapsed = time.monotonic() - started
        rows = await store.get_action_log()
        return {
            "executor_awaits": executor.await_count,
            "executed": result.executed,
            "approved": result.approved,
            "action_taken": result.action_taken,
            "tier": result.tier,
            "logged": sorted(
                (str(r["action_name"]), int(r["executed"]), str(r["tier"]))
                for r in rows
            ),
            "attestation": sorted(str(r.get("attestation_status", "")) for r in rows),
            "elapsed": elapsed,
            "order": order,
        }
    finally:
        await store.close()
        attestor.close()


_TABLE = re.compile(r"CREATE TABLE IF NOT EXISTS (\w+) \((.*?)\n\);", re.S)
_COLUMN = re.compile(r"^\s+([a-z_][a-z0-9_]*)\s+(?:TEXT|INTEGER|REAL|BLOB)\b", re.M)
_SQL = re.compile(
    r"\bSELECT\b[\s\S]*\bFROM\b|\bUPDATE\s+\w+\s+SET\b|\bINSERT\b[\s\S]*\bINTO\b"
    r"|\bDELETE\s+FROM\b|\bWHERE\b"
)
_REGISTRATION_DDL = (
    ledger._REGISTRATION_SCHEMA + state_store_module.EVIDENCE_REFERENCE_DDL
)


def _ddl_tables(text: str) -> dict[str, set[str]]:
    return {name: set(_COLUMN.findall(body)) for name, body in _TABLE.findall(text)}


def _derive_registration_members() -> tuple[set[str], set[str]]:
    """Every table the registration DDL creates, and its columns no other table has.

    A column shared with any other table in the package (`device_id`,
    `sealed_at_ms`) cannot say whose state a query reads, so only the rest
    classify. Derived rather than listed, so a new table or column is
    classified the moment the DDL declares it.
    """
    tables = _ddl_tables(_REGISTRATION_DDL)
    elsewhere: set[str] = set()
    for path in (Path(__file__).resolve().parent.parent / "ori").rglob("*.py"):
        for name, columns in _ddl_tables(path.read_text(encoding="utf-8")).items():
            if name not in tables:
                elsewhere |= columns
    columns = set().union(*tables.values()) - elsewhere
    columns.add(ledger.OUTBOX_WITHDRAWAL_COLUMN)
    return set(tables), columns


_REGISTRATION_TABLES, _REGISTRATION_COLUMNS = _derive_registration_members()

_PACKAGE = Path(__file__).resolve().parent.parent / "ori"
#: Modules that define nothing but registration.
_REGISTRATION_MODULES = (
    "security/evidence/registration.py",
    "security/evidence/disposition.py",
)
#: Modules that define registration state beside other evidence state.
_MIXED_MODULES = (
    "security/evidence/ledger.py",
    "security/evidence/first_party.py",
    "security/evidence/ingest_service.py",
    "security/evidence/bound.py",
)
#: The anchor registration's courier copy, read out of the shared outbox.
_OUTBOX_REGISTRATION = re.compile(
    r"\bevidence_outbox\b[\s\S]*\banchor_registration\b"
    r"|\banchor_registration\b[\s\S]*\bevidence_outbox\b"
)
_OUTBOX_REGISTRATION_MEMBER = "evidence_outbox[anchor_registration]"


def _function_tokens(node: ast.AST) -> tuple[set[str], set[str]]:
    """Identifiers a function uses, and the words its SQL text names."""
    identifiers: set[str] = set()
    sql: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            identifiers.add(child.id)
        elif isinstance(child, ast.Attribute):
            identifiers.add(child.attr)
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", child.value))
            sql |= words & _REGISTRATION_TABLES
            if _SQL.search(child.value):
                sql |= words & _REGISTRATION_COLUMNS
                if _OUTBOX_REGISTRATION.search(child.value):
                    sql.add(_OUTBOX_REGISTRATION_MEMBER)
    return identifiers, sql


def _derive_registration_names() -> set[str]:
    """Every name the registration code defines, derived from the definitions.

    Everything a registration module defines at top level; every function in a
    mixed module whose SQL names registration state, or which uses a name
    already classified, to a fixed point. A name also defined anywhere else in
    the package (`start`) cannot say whose state a call reaches, so it is not
    classified and a call to it is not caught by name.
    """
    names: set[str] = set(_REGISTRATION_TABLES)
    for module in _REGISTRATION_MODULES:
        for node in ast.parse((_PACKAGE / module).read_text(encoding="utf-8")).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    functions: dict[str, tuple[set[str], set[str]]] = {}
    for module in _MIXED_MODULES:
        tree = ast.parse((_PACKAGE / module).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not (
                node.name.startswith("__")
            ):
                identifiers, sql = _function_tokens(node)
                previous = functions.get(node.name, (set(), set()))
                functions[node.name] = (previous[0] | identifiers, previous[1] | sql)
    changed = True
    while changed:
        changed = False
        for name, (identifiers, sql) in functions.items():
            if name not in names and (sql or identifiers & names):
                names.add(name)
                changed = True
    defined_elsewhere: set[str] = set()
    for path in _PACKAGE.rglob("*.py"):
        if str(path.relative_to(_PACKAGE)) in _REGISTRATION_MODULES + _MIXED_MODULES:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defined_elsewhere.add(node.name)
    _COLLISIONS.update((names & defined_elsewhere) - _REGISTRATION_TABLES)
    names -= defined_elsewhere - _REGISTRATION_TABLES
    # The health vocabulary is data, not a definition; it is named once here.
    names |= {
        "registration_status",
        "registration_offer",
        "registration_pending_since_ms",
        "registration_confirmation_overdue",
        DELIVERY_STATUS_FIELD,
        "stopped_local_artifact_count",
        "stopped_local_bytes",
        "oldest_stopped_local_since_ms",
        "get_evidence_commissioning_reference",
        "record_evidence_commissioning_reference",
    }
    return names


#: Registration functions whose name the package also defines elsewhere, so
#: a call to them cannot be classified by name. Filled by the derivation.
_COLLISIONS: set[str] = set()
_REGISTRATION_NAMES = _derive_registration_names()
#: Reviewed: `start` and `_open_sync` open the evidence store, which records
#: the current anchor, and share their names with unrelated lifecycle methods.
_REVIEWED_COLLISIONS = {"start", "_open_sync"}

#: Modules that exist to hold or carry registration state, named whole.
_READERS = {
    "cli_bridge.py",
    "gateway/evidence_inbound.py",
    "gateway/evidence_outbound.py",
    *_REGISTRATION_MODULES,
    *_MIXED_MODULES,
}
#: Modules that also hold the action path, narrowed to the scopes that may
#: name registration state: named functions, module-level assignments to the
#: DDL, and imports.
_SCOPED_READERS: dict[str, set[str]] = {
    "runtime.py": {
        "_evidence_health",
        "_evidence_registration_loop",
        "_reconcile_evidence_registration",
        "_evidence_checkpoint_loop",
        "_issue_shutdown_checkpoint",
        "<import>",
    },
    "state/store.py": {
        "get_evidence_commissioning_reference",
        "_get_evidence_commissioning_reference_sync",
        "record_evidence_commissioning_reference",
        "<assign:EVIDENCE_REFERENCE_DDL>",
    },
}


def _named(text: str, *, string: bool = False) -> list[str]:
    """Registration members *text* names, as whole tokens.

    Columns count only inside SQL text: a Python variable called `digest` is
    not a read of a registration column, and a query naming it is.
    """
    tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text))
    hits = sorted(tokens & _REGISTRATION_NAMES)
    if string and _SQL.search(text):
        hits += sorted(tokens & _REGISTRATION_COLUMNS)
        if _OUTBOX_REGISTRATION.search(text):
            hits.append(_OUTBOX_REGISTRATION_MEMBER)
    return hits


def _scoped_hits(tree: ast.AST) -> list[tuple[str, str]]:
    """(scope, name) for every registration name, by innermost enclosing scope."""
    hits: list[tuple[str, str]] = []

    def visit(node: ast.AST, scope: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = node.name
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            scope = "<import>"
        elif isinstance(node, ast.Assign) and scope == "<module>":
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            scope = f"<assign:{','.join(targets)}>"
        texts: list[str] = []
        if isinstance(node, ast.Name):
            texts.append(node.id)
        elif isinstance(node, ast.Attribute):
            texts.append(node.attr)
        elif isinstance(node, ast.alias):
            texts.append(node.name)
        elif isinstance(node, ast.keyword) and node.arg:
            texts.append(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            texts.append(node.name)
        for text in texts:
            hits.extend((scope, name) for name in _named(text))
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            hits.extend((scope, name) for name in _named(node.value, string=True))
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(tree, "<module>")
    return hits


def test_only_health_and_the_producer_read_registration_state():
    """No actuation, approval, commissioning or safety code names it."""
    root = Path(__file__).resolve().parent.parent / "ori"
    offenders = []
    for path in root.rglob("*.py"):
        name = str(path.relative_to(root))
        if name in _READERS:
            continue
        allowed = _SCOPED_READERS.get(name, set())
        offenders += [
            f"{name}:{scope}: {hit}"
            for scope, hit in _scoped_hits(ast.parse(path.read_text(encoding="utf-8")))
            if scope not in allowed
        ]
    assert not offenders, (
        "registration state is named outside health, the producer, the courier "
        "routes and the commission command. This guard matches names only, and "
        "has three limits: a value passed through a permitted scope to a gate is "
        "not caught; a registration function whose name is also defined elsewhere "
        "in the package is not classified, so a call to it is not caught; and SQL "
        "built at run time from fragments is not read. "
        "test_every_registration_state_dispatches_identically covers the "
        f"behaviour those limits leave open: {offenders}"
    )


def test_the_scoped_guard_sees_a_name_in_a_function_it_does_not_permit():
    """The AST walk itself: a registration read in an unlisted function is found."""
    tree = ast.parse(
        "def _approval_workflow(store):\n"
        "    return store.get_evidence_commissioning_reference()\n"
    )
    assert ("_approval_workflow", "get_evidence_commissioning_reference") in (
        _scoped_hits(tree)
    )


def test_the_derived_members_cover_every_registration_table_and_its_own_columns():
    """Derivation is checked against the DDL, so an empty set cannot pass silently."""
    assert _REGISTRATION_TABLES == {
        "evidence_commissioning_reference",
        "evidence_current_anchor",
        "evidence_disposition",
        "evidence_offer_stop",
        "evidence_registration_confirmation",
        "evidence_registration_obligation",
    }
    assert {"offers", "suspended_at_ms", "triggering_digest", "withdrawn_at_ms"} <= (
        _REGISTRATION_COLUMNS
    )
    assert "device_id" not in _REGISTRATION_COLUMNS
    tree = ast.parse(
        "def _log(conn):\n"
        "    conn.execute('SELECT 1 FROM evidence_registration_confirmation')\n"
        "    conn.execute('SELECT offers FROM some_view')\n"
        "    digest = 1\n"
    )
    hits = {name for _scope, name in _scoped_hits(tree)}
    assert hits == {"evidence_registration_confirmation", "offers"}


def test_no_new_registration_function_hides_behind_a_shared_name():
    """A registration function named like one elsewhere escapes the guard; pin the set."""
    assert _COLLISIONS == _REVIEWED_COLLISIONS, (
        "a registration function shares its name with a definition elsewhere in "
        "the package, so the name guard cannot classify calls to it. Rename it, "
        f"or review it and add it here: {sorted(_COLLISIONS ^ _REVIEWED_COLLISIONS)}"
    )


def test_the_derived_names_are_the_registration_definitions():
    """Derived from what the modules define, including private helpers."""
    assert {
        "registration_reoffers_due",
        "_identity_stopped",
        "seal_registration",
        "pending_artifacts",
        "reoffer_due",
        "RegistrationStatus",
    } <= _REGISTRATION_NAMES
    # Evidence the dispatcher legitimately reaches is not registration state.
    assert "attest_action" not in _REGISTRATION_NAMES
    assert "start" not in _REGISTRATION_NAMES
    tree = ast.parse(
        "def _gate(ledger, conn):\n"
        "    ledger.registration_reoffers_due(at_ms=0)\n"
        '    conn.execute("SELECT 1 FROM evidence_outbox'
        " WHERE artifact_type = 'anchor_registration'\")\n"
    )
    hits = {name for _scope, name in _scoped_hits(tree)}
    assert {"registration_reoffers_due", "evidence_outbox[anchor_registration]"} <= hits


@pytest.mark.parametrize("tier", ["C", "D"])
async def test_every_registration_state_dispatches_identically(tmp_path, tier):
    outcomes = {}
    for state in STATES:
        outcomes[state] = await _dispatch(state, tier, tmp_path / state)

    for state, outcome in outcomes.items():
        assert outcome["executor_awaits"] == 1, f"{state}: the executor did not run"
        assert outcome["executed"] is True, f"{state}: {outcome}"
        assert outcome["elapsed"] < 5.0, f"{state}: dispatch was delayed"
        if tier == "C":
            assert outcome["approved"] is True, f"{state}: approval was reopened"
            assert outcome["action_taken"] == "close_gas_valve"
        else:
            assert outcome["action_taken"] == "trip_relay"

    baseline = {
        k: v
        for k, v in outcomes["pending_authorisation"].items()
        if k not in {"elapsed"}
    }
    for state in STATES[1:]:
        compared = {k: v for k, v in outcomes[state].items() if k not in {"elapsed"}}
        assert compared == baseline, (
            f"{state} dispatched differently from no registration"
        )
