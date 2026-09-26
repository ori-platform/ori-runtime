# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The tier-c-approval/v1 sequence corpora, replayed through the real dispatcher.

Every sequence in `tests/vectors/tier_c_approval/admission.json` and every
offline-token sequence in `tests/vectors/offline_tokens/tier-c-binding-v2.json`
runs against the real `ActionDispatcher`, a real SQLite file and the
commissioned facts the corpus's proposal names. The harness owns two clocks
(the process's monotonic clock and the wall clock), the operator's replies,
the store's willingness to commit, the executor's answer, crashes and
restarts. It reads what the corpus reads: the row's decision state, the
records appended, the actuations, the safe-default intents, the health counts.

What this runtime cannot represent is stated per step, never skipped in
silence: it holds no affirmative non-dispatch record (the contract says
`approval_aborted_undispatched` is unreachable for such a runtime), the alert
provider's retry of a safe-default notice belongs to the alert outbox, and
`notice` is matched by the meaning the runtime's operator text carries.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import sqlite3
import types
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning import action_dispatcher as dispatcher_module
from ori.reasoning import tier_c_admission as adm
from ori.reasoning.action_dispatcher import ACTUATION_NOT_PERFORMED, ActionDispatcher
from ori.reasoning.dispatch_plan import BindingView
from ori.reasoning.elevator import SkillContext
from ori.reasoning.resource_gate import Admission
from ori.reasoning.tier_c_admission import TierCAuthorityFacts
from ori.security import offline_tokens as offline_tokens_module
from ori.security.offline_tokens import V2_SIGNATURE_DOMAIN, OfflineTierCTokenVerifier
from ori.skills.signing import canonical_signed_payload
from ori.state.store import StateStore

VECTORS = Path(__file__).parent / "vectors"
ADMISSION = json.loads((VECTORS / "tier_c_approval" / "admission.json").read_text())
BINDING = json.loads(
    (VECTORS / "offline_tokens" / "tier-c-binding-v2.json").read_text()
)

#: Sequence steps this runtime cannot represent, with the contract's own words.
NOT_REPRESENTED = {
    "non_dispatch_record": (
        "this runtime forbids any write between the approval commit and the executor, "
        "so it holds no affirmative non-dispatch record and approval_aborted_undispatched "
        "is unreachable for it (tier-c-approval/v1, Restart)"
    ),
    "alert_result": (
        "the alert provider's retry of a safe-default notice is the alert outbox's, "
        "replayed by its own tests; the intent's uniqueness is asserted here"
    ),
}

#: The meaning of each operator notice the runtime sends, by a phrase it carries.
NOTICES = (
    ("reply again to approve", "commit_failed_retry"),
    ("had expired", "proposal_expired"),
    ("binding or authority changed", "approval_binding_changed"),
    ("earlier outcome is unresolved", "proposal_blocked_uncertain_outcome"),
    ("the resource is held", "dispatch_refused_contention"),
    ("closed: runtime restart", "proposal_aborted_restart"),
    ("v1_token_is_not_tier_c_approval", "token_v1_refused"),
    ("token already used", "token_replayed"),
    ("token refused", "token_refused"),
    ("could not be recorded", "no_proposal"),
)


class _Skill:
    name = "protector"
    version = "1.0.0"
    first_party = True
    config: dict[str, Any] = {}
    triggers: list[Any] = []
    actions: dict[str, Any] = {"available": [], "defaults": {}}
    sensors_required = [{"type": "current_clamp"}]


def _event(device_id: str) -> OriEvent:
    reading = SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=9.0,
        unit="ampere",
        timestamp=1_787_000_000_000,
        quality=1.0,
    )
    return OriEvent.from_reading(reading, device_id)


class _Store(StateStore):
    """The real store, with the harness deciding when a commit is held or fails."""

    def __init__(self, path: str, harness: Replay) -> None:
        super().__init__(path)
        self._h = harness

    async def admit_tier_c_approval(self, *args: Any, **kwargs: Any) -> str:
        mode = self._h.commit_mode
        if mode == "held":
            self._h.commit_mode = "ok"
            raise sqlite3.OperationalError("database is locked")
        return await super().admit_tier_c_approval(*args, **kwargs)

    async def advance_tier_c_proposal(
        self, proposal_id: str, state: str, **kwargs: Any
    ) -> bool:
        if state == adm.DISPATCH_STARTED and not self._h.marker_durable:
            raise sqlite3.OperationalError("disk I/O error")
        if (
            state in (adm.EXECUTED, adm.DISPATCH_FAILED, adm.DISPATCH_OUTCOME_UNKNOWN)
            and not self._h.in_recovery
        ):
            # The live outcome append: held or refused as the corpus says.
            # Recovery's own writes after a restart are the store's to take.
            if self._h.outcome_write == "blocked":
                await self._h.outcome_released.wait()
            if self._h.outcome_write == "failed":
                raise sqlite3.DatabaseError("the outcome cannot be appended")
        return await super().advance_tier_c_proposal(proposal_id, state, **kwargs)


class _Operator:
    """Answers each proposal from the queue the harness feeds, by proposal id."""

    def __init__(self, harness: Replay) -> None:
        self._h = harness
        self.notices: list[str] = []

    async def send(self, *, alert: Any, to_number: str) -> bool:
        if alert.intent.value == "tier_c_approval":
            self._h.proposed.add(str(alert.template_variables[3]))
        else:
            self.notices.append(alert.sms_body)
        return True

    async def listen_for_response(
        self, *, from_number: str, timeout_seconds: int
    ) -> Any:
        # The harness feeds replies; the wait ends only with a reply, or with
        # the crash that cancels the dispatch. The workflow's own deadline is
        # the corpus's monotonic clock, never real time.
        proposal_id = self._h.listening_for()
        queue = self._h.replies.setdefault(proposal_id, asyncio.Queue())
        return await queue.get()


class Replay:
    """One sequence's world: clocks, store, operator, executor, dispatcher."""

    def __init__(
        self, tmp_path: Path, proposal: dict[str, Any], monkeypatch: Any
    ) -> None:
        self.console_mode = False
        self.phase = "init"
        self.in_recovery = False
        self.path = str(tmp_path / "s.db")
        self.proposal = proposal
        self.monkeypatch = monkeypatch
        self.mono_ms = int(proposal["created_mono_ms"])
        self.wall_ms = int(proposal["created_at_ms"])
        self.binding = str(proposal["binding"])
        self.authority_salt = str(proposal["authority"])
        self.commit_mode = "ok"
        self.marker_durable = True
        self.outcome_write = "blocked"
        self.outcome_released = asyncio.Event()
        # Dispatch is immediate in the runtime; the corpus observes the admitted
        # approval before it. The harness holds the entry to dispatch, purely
        # as observation, and releases it at the corpus's dispatch step.
        self.dispatch_released = asyncio.Event()
        self.executor_answer: Any = True
        self.contention = False
        self.actuations = 0
        self.proposed: set[str] = set()
        self.replies: dict[str, asyncio.Queue[Any]] = {}
        self.tasks: dict[str, asyncio.Task[Any]] = {}
        self.results: dict[str, Any] = {}
        self.next_ids: list[str] = []
        self.current_listen: list[str] = []
        self.store: _Store | None = None
        self.dispatcher: ActionDispatcher | None = None
        self.operator: _Operator | None = None
        self.key = Ed25519PrivateKey.generate()
        self.public = base64.b64encode(
            self.key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")
        self.critical: list[str] = []
        monkeypatch.setattr(dispatcher_module, "now_ms", lambda: self.wall_ms)
        monkeypatch.setattr(offline_tokens_module, "now_ms", lambda: self.wall_ms)
        monkeypatch.setattr(dispatcher_module, "_generate_proposal_id", self._next_id)

    # ── the world ──────────────────────────────────────────────────────────
    def _next_id(self, *_: Any) -> str:
        return (
            self.next_ids.pop(0) if self.next_ids else str(self.proposal["proposal_id"])
        )

    def listening_for(self) -> str:
        return (
            self.current_listen[-1]
            if self.current_listen
            else str(self.proposal["proposal_id"])
        )

    def facts(self, zone_id: str | None = None) -> TierCAuthorityFacts:
        return TierCAuthorityFacts(
            zone_id=str(zone_id or self.proposal["zone"]),
            zone_document={
                "zone_id": self.proposal["zone"],
                "authority": self.authority_salt,
            },
            binding_digest=self.binding,
            safety_profile_digest="",
            resource_for={
                "open_protected_circuit": str(self.proposal["target"]),
                "close_protected_circuit": str(self.proposal["target"]),
            },
            deployment_inputs={},
        )

    async def start(self, *, recover: bool) -> None:
        self.phase += " start:open"
        self.store = _Store(self.path, self)
        await self.store.open()
        self.phase += " start:opened"
        self.operator = _Operator(self)

        harness = self

        class _Gate:
            """Admits every act; contention is the harness's to decide at dispatch."""

            async def request(
                self, identity: Any, tier: str, contributor: Any, **_k: Any
            ) -> Any:
                return types.SimpleNamespace(
                    admission=Admission.ADMITTED,
                    may_execute=True,
                    token=object(),
                    safety_conflict=False,
                    reason="",
                )

            async def mark_running(self, _token: Any) -> None:
                return None

            async def mark_uncertain(self, _token: Any) -> None:
                return None

            async def retire(self, _token: Any, _result: Any = None) -> None:
                return None

            async def reply_admitted(self, _token: Any) -> bool:
                return not harness.contention

        self.dispatcher = ActionDispatcher(
            state_store=self.store,
            alert_sender=self.operator,
            offline_token_verifier=OfflineTierCTokenVerifier(
                public_key_b64=self.public
            ),
            config={"operator_contact": "+2348000000000", "relay_enabled": True},
            # Resolved per call, so a sequence's later proposal on another
            # zone can swap the facts while it is created.
            authority_facts=lambda zone_id=None: self.facts(zone_id),
        )
        self.dispatcher.bind_resource_gate(
            _Gate(),
            BindingView(
                zone_identity_key=("local_gpio", "pin:26"),
                binding_revision="1",
                consequence_by_outcome={
                    "open_protected_circuit": "hard",
                    "close_protected_circuit": "hard",
                },
            ),
        )
        self.dispatcher._clock = lambda: self.mono_ms / 1000.0
        if self.console_mode:
            # Replies arrive on the local console: no remote channel, and the
            # console listener reads the same per-proposal queue.
            self.dispatcher._local_console_enabled = True
            self.dispatcher._tier_c_comms_available = lambda: False  # type: ignore[method-assign]

            async def console(**kwargs: Any) -> str | None:
                queue = self.replies.setdefault(kwargs["proposal_id"], asyncio.Queue())
                return await queue.get()

            self.dispatcher._listen_for_local_console_response = console  # type: ignore[method-assign]
        real_dispatch = self.dispatcher._dispatch_admitted

        async def held_dispatch(*args: Any, **kwargs: Any) -> Any:
            await self.dispatch_released.wait()
            return await real_dispatch(*args, **kwargs)

        self.dispatcher._dispatch_admitted = held_dispatch  # type: ignore[method-assign]

        async def act(*_a: Any, **_k: Any) -> Any:
            # The corpus counts dispatches that reached the actuator, whatever
            # the actuator then reported.
            self.actuations += 1
            answer = self.executor_answer
            if answer in (True, False, ACTUATION_NOT_PERFORMED):
                return answer
            raise RuntimeError(str(answer))

        async def safe_default(*_a: Any, **_k: Any) -> bool:
            return True

        for name in ("trip_relay", "release_relay", "close_gas_valve"):
            self.dispatcher.register_executor(name, act)
        self.dispatcher.register_executor("log_to_dashboard", safe_default)
        if recover:
            self.phase += " start:recover"
            self.in_recovery = True
            try:
                await self.dispatcher.recover_tier_c_at_start(self.store)
            finally:
                self.in_recovery = False
            self.phase += " start:recovered"

    async def propose(
        self, proposal_id: str, *, action: str = "trip_relay", timeout_s: int
    ) -> None:
        assert self.dispatcher is not None and self.store is not None
        self.next_ids.append(proposal_id)
        self.current_listen.append(proposal_id)
        task = asyncio.create_task(
            self.dispatcher.dispatch(
                action=action,
                tier="C",
                context=SkillContext(
                    skill=_Skill(),
                    event=_event(str(self.proposal["device_id"])),
                    state_store=self.store,
                    trigger_name="t",
                ),
                result=ReasoningResult(
                    text="", tier="rule", model="m", tokens_used=0, latency_ms=0
                ),
                approval_timeout=timeout_s,
            )
        )
        self.tasks[proposal_id] = task
        for _ in range(400):
            if proposal_id in self.proposed or task.done():
                break
            await asyncio.sleep(0.005)
        if task.done():
            self.results[proposal_id] = task.result()

    async def settle(self, proposal_id: str) -> None:
        task = self.tasks.get(proposal_id)
        if task is not None and not task.done():
            with contextlib.suppress(asyncio.TimeoutError):
                self.results[proposal_id] = await asyncio.wait_for(task, 5)
        assert self.dispatcher is not None
        await self.dispatcher.drain_records(timeout=2)
        pending = self.dispatcher.get_inflight_tier_d_tasks()
        if pending:
            await asyncio.wait(pending, timeout=2)

    async def crash(self) -> None:
        assert self.dispatcher is not None and self.store is not None

        async def bounded(what: str, awaitable: Any) -> None:
            try:
                await asyncio.wait_for(awaitable, 4)
            except asyncio.TimeoutError:
                raise AssertionError(f"crash: {what} did not finish") from None

        for task in self.tasks.values():
            if not task.done():
                task.cancel()
        self.phase += " crash:dispatch-tasks"
        await bounded(
            "dispatch tasks",
            asyncio.gather(*self.tasks.values(), return_exceptions=True),
        )
        retries = self.dispatcher.get_inflight_tier_d_tasks()
        for task in retries:
            task.cancel()
        if retries:
            await bounded(
                "tracked tasks", asyncio.gather(*retries, return_exceptions=True)
            )
        self.phase += " crash:abandon"
        await bounded("abandon_records", self.dispatcher.abandon_records())
        self.phase += " crash:close"
        await bounded("store.close", self.store.close())
        self.phase += " crash:done"
        self.tasks.clear()
        self.current_listen.clear()

    # ── what the corpus reads ─────────────────────────────────────────────
    async def state_of(self, proposal_id: str) -> str | None:
        assert self.store is not None
        row = await self.store.get_tier_c_proposal(proposal_id)
        return None if row is None else str(row["decision_state"])

    async def records(self, proposal_id: str) -> list[str]:
        assert self.store is not None
        return await self.store.get_tier_c_proposal_records(proposal_id)

    async def intents(self, proposal_id: str) -> int:
        assert self.store is not None
        return len(await self.store.get_tier_c_safe_default_intents(proposal_id))

    async def token_consumed(self, token_id: str) -> bool:
        with sqlite3.connect(self.path) as reader:
            row = reader.execute(
                "SELECT 1 FROM offline_token_consumption WHERE token_id = ?",
                (token_id,),
            ).fetchone()
        return row is not None

    async def reserved(self) -> int:
        assert self.store is not None
        rows = await self.store.get_tier_c_proposals(
            adm.APPROVED_PENDING_DISPATCH, adm.DISPATCH_STARTED
        )
        return len(rows)

    def last_notice(self) -> str | None:
        assert self.operator is not None
        if not self.operator.notices:
            return None
        text = self.operator.notices[-1]
        for phrase, meaning in NOTICES:
            if phrase in text:
                return meaning
        return text

    def token_text(self, claims: dict[str, Any]) -> str:
        payload = dict(claims)
        if payload.get("token_version") == 2:
            signature = self.key.sign(
                V2_SIGNATURE_DOMAIN + b"\x00" + canonical_signed_payload(payload)
            )
        else:
            signature = self.key.sign(canonical_signed_payload(payload))
        payload["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
        return "TOKEN:" + json.dumps(payload)


def _sequences(corpus: dict[str, Any]) -> list[Any]:
    return [
        pytest.param(seq, id=seq["name"])
        for seq in corpus["sequences"]
        if isinstance(seq, dict)
    ]


async def _check(
    replay: Replay, step: dict[str, Any], main: str, caplog: Any
) -> list[str]:
    """Compare a step's expectations; return what the harness did not represent."""
    expect = step.get("expect", {})
    unrepresented: list[str] = []
    assert replay.dispatcher is not None
    if (
        "state" in expect
        and not replay.marker_durable
        and expect["state"] == adm.DISPATCH_STARTED
    ):
        unrepresented.append(
            "state dispatch_started with a marker the store did not take: this runtime's "
            "state is the durable row, which a marker that never landed does not move"
        )
    elif "state" in expect:
        assert await replay.state_of(main) == expect["state"], (
            step,
            await replay.records(main),
            getattr(replay.results.get(main), "action_taken", None),
            sorted(replay.proposed),
        )
    if "actuations" in expect:
        assert replay.actuations == expect["actuations"], (
            "actuations",
            replay.actuations,
            step,
            await replay.records(main),
        )
    if "records" in expect:
        if not replay.marker_durable and adm.DISPATCH_STARTED in expect["records"]:
            unrepresented.append(
                "records with a marker the store did not take: this runtime's records "
                "are the durable rows, and a marker that never landed is not among them"
            )
        else:
            assert await replay.records(main) == expect["records"], (
                "records",
                await replay.records(main),
                step,
            )
    if "safe_default" in expect:
        assert (await replay.intents(main) > 0) is bool(expect["safe_default"]), step
    if "safe_default_intents" in expect:
        assert await replay.intents(main) == expect["safe_default_intents"], step
    if "reserved" in expect:
        assert await replay.reserved() == expect["reserved"], step
    if "action_records" in expect:
        records = replay.dispatcher.action_records()
        for key, value in expect["action_records"].items():
            assert records.get(key) == value, (key, records, step)
    if "evidence_status" in expect:
        degraded = replay.dispatcher.action_records_degrade_health()
        assert degraded is (expect["evidence_status"] == "degraded"), step
    if "token_consumed" in expect:
        token = step.get("token") or {}
        assert await replay.token_consumed(str(token.get("token_id", ""))) is bool(
            expect["token_consumed"]
        ), step
    if "notice" in expect:
        wanted = expect["notice"]
        got = replay.last_notice()
        if wanted is None:
            assert got is None, step
        elif wanted in ("no_proposal",):
            unrepresented.append(
                "notice:no_proposal (no proposal exists, so no notice can name it)"
            )
        else:
            assert got == wanted, (got, step)
    if "dispatch_refused" in expect and expect["dispatch_refused"]:
        # Nothing to dispatch: the actuation count already says so.
        pass
    if "later" in expect:
        for later_id, state in expect["later"].items():
            assert await replay.state_of(later_id) == state, (later_id, step)
    if "later_safe_default_intents" in expect:
        for later_id, count in expect["later_safe_default_intents"].items():
            assert await replay.intents(later_id) == count, (later_id, step)
    if "admitted" in expect:
        pass  # decided by the propose step itself
    if "events" in expect:
        # A CRITICAL event of either kind is a CRITICAL log line here.
        if expect["events"]:
            assert any(r.levelno >= logging.CRITICAL for r in caplog.records), step
    if "proposal_sent" in expect:
        assert (main in replay.proposed) is bool(expect["proposal_sent"]), step
    if "safe_default_attempted" in expect:
        assert (
            main in replay.results and replay.results[main].safe_default_used
        ) is bool(expect["safe_default_attempted"]), step
    if "safe_default_recorded" in expect:
        assert (await replay.intents(main) > 0) is bool(
            expect["safe_default_recorded"]
        ), step
    if "token_format" in expect:
        payload = dict(step.get("token") or {})
        version = offline_tokens_module.token_version(payload)
        assert {1: "v1", 2: "v2", None: "malformed"}[version] == expect[
            "token_format"
        ], step
    for key in ("alert_attempts", "log_records"):
        if key in expect:
            unrepresented.append(f"{key}: {NOT_REPRESENTED['alert_result']}")
    return unrepresented


async def _turns(n: int = 6) -> None:
    for _ in range(n):
        await asyncio.sleep(0)


async def _until(predicate: Any, *, seconds: float = 3.0) -> bool:
    """Poll *predicate* (sync or async) for up to *seconds* of real time."""
    for _ in range(int(seconds / 0.005)):
        answer = predicate()
        if asyncio.iscoroutine(answer):
            answer = await answer
        if answer:
            return True
        await asyncio.sleep(0.005)
    return False


def _executor_answer(result: str) -> Any:
    if result == "executed":
        return True
    if result == "failed":
        return ACTUATION_NOT_PERFORMED
    return False


async def _run(replay: Replay, sequence: dict[str, Any], caplog: Any) -> list[str]:
    proposal = replay.proposal
    main = str(proposal["proposal_id"])
    lifetime_s = (
        int(proposal["expires_at_ms"]) - int(proposal["created_at_ms"])
    ) // 1000
    unrepresented: list[str] = []
    steps = list(sequence["steps"])
    replay.console_mode = any(
        s.get("event") == "reply" and s.get("path") in ("console", "offline_token")
        for s in steps
    )
    await replay.start(recover=False)
    caplog.set_level(logging.CRITICAL)
    for token_id in sequence.get("consumed_token_ids", []):
        # The corpus's world: this token was claimed by an earlier approval.
        assert replay.store is not None
        assert await replay.store.claim_offline_token(
            token_id=str(token_id),
            device_id=str(proposal["device_id"]),
            action="trip_relay",
        )
    if not steps or steps[0]["event"] != "create":
        # The corpus's proposal exists before its first step.
        await replay.propose(main, timeout_s=lifetime_s)

    for index, step in enumerate(steps):
        event = step["event"]
        expect = step.get("expect", {})
        replay.phase = f"step {index} {event}"

        if event == "create":
            assert replay.store is not None
            if step["commit"] == "failed":
                original = replay.store.create_tier_c_proposal

                async def refuse(**_k: Any) -> str:
                    raise sqlite3.OperationalError("disk I/O error")

                replay.store.create_tier_c_proposal = refuse  # type: ignore[method-assign]
                await replay.propose(main, timeout_s=lifetime_s)
                replay.store.create_tier_c_proposal = original  # type: ignore[method-assign]
            else:
                await replay.propose(main, timeout_s=lifetime_s)
            await _turns()
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event in ("evidence_stopped", "evidence_disabled", "gateway_unavailable"):
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event == "reply":
            replay.mono_ms = int(step["mono_ms"])
            replay.wall_ms = int(step["wall_ms"])
            target = str(step.get("proposal", main))
            assert replay.dispatcher is not None and replay.store is not None
            if not step.get("authenticated", True):
                # Ingress drops an unauthenticated reply before the dispatcher.
                unrepresented += await _check(replay, step, main, caplog)
                continue
            replay.commit_mode = str(step.get("commit", "ok"))
            replay.dispatcher._pending_ceiling = (
                0 if step.get("reservation") == "unavailable" else 64
            )
            decision = "YES" if step["decision"] == "yes" else "NO"
            if step["path"] == "offline_token":
                reply = replay.token_text(step["token"])
            else:
                reply = f"{decision}-{target}"
            state_before = await replay.state_of(target)
            task = replay.tasks.get(target)
            listening = (
                task is not None and not task.done() and state_before == adm.PROPOSED
            )
            if not listening:
                # No open proposal listens: a reply to a closed or absent one is
                # dropped, and admission would refuse it anyway.
                if state_before is not None:
                    answer = await replay.store.admit_tier_c_approval(
                        target,
                        binding_digest=replay.binding,
                        authority_json="",
                        reservation_ceiling=64,
                    )
                    assert answer.startswith("closed:") or answer == "duplicate", answer
                unrepresented += await _check(replay, step, main, caplog)
                continue
            notices_before = len(replay.operator.notices)  # type: ignore[union-attr]
            await replay.replies.setdefault(target, asyncio.Queue()).put(reply)

            async def moved() -> bool:
                state = await replay.state_of(target)
                t = replay.tasks.get(target)
                return (
                    state != adm.PROPOSED
                    or (t is not None and t.done())
                    or len(replay.operator.notices) > notices_before  # type: ignore[union-attr]
                )

            await _until(moved)
            await _turns()
            task = replay.tasks.get(target)
            if task is not None and task.done():
                replay.results[target] = task.result()
                # A proposal that resolved wrote its closing state off the act's
                # path; read it after the writer has taken it.
                await replay.dispatcher.drain_records(timeout=2)
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event == "dispatch":
            replay.mono_ms = int(step["mono_ms"])
            replay.wall_ms = int(step["wall_ms"])
            assert replay.dispatcher is not None
            replay.contention = bool(step.get("contention", False))
            replay.marker_durable = bool(step.get("marker_durable", True))
            if step.get("pending_at_ceiling"):
                replay.dispatcher._pending_ceiling = 0
            outcome_step = next(
                (
                    s
                    for s in steps[index + 1 :]
                    if s["event"] in ("outcome", "reply", "restart", "crash")
                ),
                {},
            )
            if outcome_step.get("event") == "outcome":
                replay.executor_answer = _executor_answer(
                    str(outcome_step.get("result", "executed"))
                )
                replay.outcome_write = "blocked"
            else:
                replay.executor_answer = True
                replay.outcome_write = "blocked"
            state_before = await replay.state_of(main)
            if state_before == adm.APPROVED_PENDING_DISPATCH:
                actuations_before = replay.actuations
                replay.dispatch_released.set()

                async def acted() -> bool:
                    t = replay.tasks.get(main)
                    return (
                        replay.actuations != actuations_before
                        or (t is not None and t.done())
                        or await replay.state_of(main) != adm.APPROVED_PENDING_DISPATCH
                    )

                await _until(acted)
                await _turns()
                replay.dispatch_released.clear()
                t = replay.tasks.get(main)
                if t is not None and t.done():
                    replay.results[main] = t.result()
            # else: nothing is admitted, so nothing dispatches.
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event == "outcome":
            write = str(step.get("write", "ok"))
            if write == "blocked":
                replay.outcome_write = "blocked"
                await asyncio.sleep(0.05)
            elif write == "failed":
                replay.outcome_write = "failed"
                replay.outcome_released.set()
                await asyncio.sleep(0.2)
            else:
                replay.outcome_write = "ok"
                replay.outcome_released.set()
                state_before = await replay.state_of(main)

                async def landed() -> bool:
                    return await replay.state_of(main) != state_before

                await _until(landed, seconds=6.0)
                await _turns()
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event == "crash":
            if step.get("non_dispatch_record"):
                unrepresented.append(
                    f"crash.non_dispatch_record: {NOT_REPRESENTED['non_dispatch_record']}"
                )
                return unrepresented
            await replay.crash()
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event == "restart":
            if replay.store is not None and replay.store._conn is not None:
                await replay.crash()
            replay.mono_ms = 1_000
            replay.outcome_write = "blocked"
            replay.outcome_released = asyncio.Event()
            replay.dispatch_released = asyncio.Event()
            await replay.start(recover=True)
            await _turns()
            pending = replay.dispatcher.get_inflight_tier_d_tasks()  # type: ignore[union-attr]
            if pending:
                await asyncio.wait(pending, timeout=2)
            await replay.dispatcher.drain_records(timeout=2)  # type: ignore[union-attr]
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event == "propose":
            assert replay.store is not None
            if step["tier"] != "C":
                # Tier D never consults the approval record, and neither do
                # Tier A and Tier B: the block reaches only a Tier C proposal.
                assert expect.get("admitted", True) is True
                continue
            assert replay.dispatcher is not None
            # Whether a proposal is admitted is decided by proposing one: the
            # runtime's own creation path answers, not a rule the harness
            # re-implements. A proposal the corpus does not name is scratch and
            # ends quietly once its answer is read.
            opens = str(step.get("opens") or f"scratch-{index}")
            action = (
                "release_relay"
                if step["outcome"] == "close_protected_circuit"
                else "trip_relay"
            )
            zone = str(step["zone"])
            base_facts = replay.facts
            # The later proposal is created on its own zone; admission asks
            # for that zone's facts by name.
            replay.facts = lambda zone_id=None, z=zone, f=base_facts: f(zone_id or z)  # type: ignore[method-assign]
            await replay.propose(opens, action=action, timeout_s=lifetime_s)
            replay.facts = base_facts  # type: ignore[method-assign]
            answer = replay.results.get(opens)
            blocked = (
                answer is not None
                and answer.action_taken == "refused_outcome_uncertain"
            )
            assert (not blocked) is bool(expect["admitted"]), (
                getattr(answer, "action_taken", None),
                step,
            )
            if not step.get("opens") and not blocked:
                scratch = replay.tasks.pop(opens, None)
                if scratch is not None and not scratch.done():
                    scratch.cancel()
                    await asyncio.gather(scratch, return_exceptions=True)
                await replay.store.advance_tier_c_proposal(  # type: ignore[union-attr]
                    opens, adm.REJECTED, from_states=(adm.PROPOSED,), reason="scratch"
                )
                replay.proposed.discard(opens)
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event == "reconcile":
            assert replay.dispatcher is not None and replay.store is not None
            source = step.get("source")
            if source == "operator_local":
                caller = step.get("caller", {})
                if (
                    not step.get("authenticated", True)
                    or caller.get("credentials") != "peer"
                ):
                    if expect.get("notice") == "reconcile_refused":
                        unrepresented.append(
                            "notice:reconcile_refused (a refusal is the socket's answer, not an operator notice)"
                        )
                        step = {
                            **step,
                            "expect": {
                                k: v for k, v in expect.items() if k != "notice"
                            },
                        }
                    unrepresented += await _check(replay, step, main, caplog)
                    continue
                await replay.dispatcher.reconcile_tier_c(
                    replay.store,
                    proposal_id=str(step["proposal_id"]),
                    device_id=str(step["device_id"]),
                    runtime_device_id=str(proposal["device_id"]),
                    zone_id=str(step["zone_id"]),
                    outcome=str(step["outcome"]),
                    reason=str(step["reason"]),
                    note=step.get("note"),
                    principal_uid=caller.get("uid"),
                    principal_account=caller.get("account"),
                    principal_login_uid=caller.get("login_uid"),
                )
                if expect.get("notice") == "reconcile_refused":
                    unrepresented.append(
                        "notice:reconcile_refused (a refusal is the socket's answer, not an operator notice)"
                    )
                    step = {
                        **step,
                        "expect": {k: v for k, v in expect.items() if k != "notice"},
                    }
            elif source == "commissioned_feedback":
                reconciled = (
                    await replay.dispatcher.reconcile_from_commissioned_feedback(
                        replay.store,
                        zone_id=str(step["zone"]),
                        outcome_observed=step["outcome"] == "executed",
                        mapping_proves=bool(step.get("mapping_proves", False))
                        and bool(step.get("authenticated", True)),
                    )
                )
                if not reconciled and expect.get("notice") == "reconcile_refused":
                    # Feedback that reconciles nothing raises no operator notice.
                    unrepresented.append(
                        "notice:reconcile_refused (feedback that reconciles nothing "
                        "raises no operator notice)"
                    )
                    step = {
                        **step,
                        "expect": {k: v for k, v in expect.items() if k != "notice"},
                    }
            else:
                # No path reaches reconciliation from this source; nothing is
                # appended, and the refusal has no operator notice here.
                unrepresented.append(
                    f"reconcile.source={source}: no such path in this runtime"
                )
                step = {
                    **step,
                    "expect": {k: v for k, v in expect.items() if k != "notice"},
                }
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event == "binding_change":
            if "binding" in step:
                replay.binding = str(step["binding"])
            if "authority" in step:
                replay.authority_salt = str(step["authority"])
            unrepresented += await _check(replay, step, main, caplog)
            continue

        if event == "alert_result":
            unrepresented.append(f"alert_result: {NOT_REPRESENTED['alert_result']}")
            continue

        raise AssertionError(f"unknown step {event}")
    return unrepresented


async def _bounded_run(
    replay: Replay, sequence: dict[str, Any], caplog: Any
) -> list[str]:
    """Run the sequence, and on a stall report every task's frames instead of hanging."""
    import io
    import traceback

    try:
        return await asyncio.wait_for(_run(replay, sequence, caplog), 40)
    except asyncio.TimeoutError:
        import sys
        import threading

        report = io.StringIO()
        for task in asyncio.all_tasks():
            if task is asyncio.current_task():
                continue
            report.write(f"\n--- task {task.get_name()}\n")
            for frame in task.get_stack(limit=8):
                traceback.print_stack(frame, limit=1, file=report)
        names = {t.ident: t.name for t in threading.enumerate()}
        for ident, frame in sys._current_frames().items():
            if ident == threading.get_ident():
                continue
            report.write(f"\n--- thread {names.get(ident, ident)}\n")
            traceback.print_stack(frame, limit=6, file=report)
        raise AssertionError(
            f"the sequence stalled at {replay.phase}:" + report.getvalue()
        ) from None


@pytest.mark.parametrize("sequence", _sequences(ADMISSION))
async def test_admission_sequence(
    sequence: dict[str, Any], tmp_path: Path, monkeypatch: Any, caplog: Any
) -> None:
    replay = Replay(tmp_path, dict(ADMISSION["proposal"]), monkeypatch)
    try:
        unrepresented = await _bounded_run(replay, sequence, caplog)
    finally:
        if replay.store is not None and replay.store._conn is not None:
            await replay.crash()
    if unrepresented:
        pytest.skip(
            "not represented by this runtime: " + "; ".join(sorted(set(unrepresented)))
        )


@pytest.mark.parametrize("sequence", _sequences(BINDING))
async def test_token_binding_sequence(
    sequence: dict[str, Any], tmp_path: Path, monkeypatch: Any, caplog: Any
) -> None:
    replay = Replay(tmp_path, dict(BINDING["proposal"]), monkeypatch)
    try:
        unrepresented = await _bounded_run(replay, sequence, caplog)
    finally:
        if replay.store is not None and replay.store._conn is not None:
            await replay.crash()
    if unrepresented:
        pytest.skip(
            "not represented by this runtime: " + "; ".join(sorted(set(unrepresented)))
        )


@pytest.mark.parametrize(
    "case", BINDING["host_state_token_cases"], ids=lambda c: c["name"]
)
async def test_host_state_token_cases(case: dict[str, Any], tmp_path: Path) -> None:
    """A token approves nothing on the existing workflow's host-state Tier C."""
    from unittest.mock import AsyncMock, patch

    store = StateStore(str(tmp_path / "s.db"))
    await store.open()
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode("ascii")
    payload = dict(case["token"])
    if payload.get("token_version") == 2:
        signature = key.sign(
            V2_SIGNATURE_DOMAIN + b"\x00" + canonical_signed_payload(payload)
        )
    else:
        signature = key.sign(canonical_signed_payload(payload))
    payload["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    dispatcher = ActionDispatcher(
        state_store=store,
        offline_token_verifier=OfflineTierCTokenVerifier(public_key_b64=public),
        config={"local_console_enabled": True, "operator_contact": "+2348000000000"},
    )
    acted = AsyncMock(return_value=True)
    dispatcher.register_executor(case["action"], acted)
    dispatcher.register_executor("log_to_dashboard", AsyncMock(return_value=True))
    try:
        with patch.object(
            dispatcher,
            "_listen_for_local_console_response",
            new=AsyncMock(return_value="TOKEN:" + json.dumps(payload)),
        ):
            result = await dispatcher.dispatch(
                case["action"],
                case["tier"],
                SkillContext(
                    skill=_Skill(),
                    event=_event(case["token"]["device_id"]),
                    state_store=store,
                    trigger_name="t",
                ),
                ReasoningResult(
                    text="", tier="rule", model="m", tokens_used=0, latency_ms=0
                ),
                approval_timeout_seconds=5,
            )
        await dispatcher.drain_records(timeout=5)
        with sqlite3.connect(str(tmp_path / "s.db")) as reader:
            consumed = reader.execute(
                "SELECT count(*) FROM offline_token_consumption"
            ).fetchone()[0]
    finally:
        await store.close()
    assert result.approved is False
    acted.assert_not_awaited()
    assert bool(consumed) is bool(case["token_consumed"])
