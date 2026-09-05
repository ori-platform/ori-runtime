# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Customer alert preferences, and the notices they may never reach.

A toggle a customer sets is allowed to silence an informational notice. It is
not allowed to silence a notice that a protection is absent or has failed, and
that separation is structural here rather than a lookup: mandatory notices
travel `_send_or_queue_safety_alert`, which never consults a preference.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from ori.policy import alert_classes
from ori.policy.alert_classes import (
    ALERT_CLASSES,
    UNBOUND_ALERT_CLASSES,
    alert_class_for_trigger,
)
from ori.policy.device_policy import DevicePolicy
from ori.policy.remote_fetch import _alert_preferences
from ori.reasoning.action_dispatcher import ALERT_SUPPRESSED
from ori.runtime import OriRuntime


def _policy(**overrides) -> DevicePolicy:
    return dataclasses.replace(DevicePolicy.unrestricted(), **overrides)


# --------------------------------------------------------------------------
# The map
# --------------------------------------------------------------------------


def test_every_mapped_class_is_a_declared_class() -> None:
    """A trigger cannot be bound to a class the policy has no toggle for."""
    assert set(alert_classes.TRIGGER_ALERT_CLASS.values()) <= ALERT_CLASSES


def test_the_unbound_classes_are_exactly_those_no_trigger_resolves_to() -> None:
    """The gap is declared, so it cannot be mistaken for coverage."""
    assert UNBOUND_ALERT_CLASSES == ALERT_CLASSES - set(
        alert_classes.TRIGGER_ALERT_CLASS.values()
    )
    assert UNBOUND_ALERT_CLASSES == ALERT_CLASSES


def test_no_safety_trigger_is_bound_to_a_disableable_class() -> None:
    """A customer preference must not be able to silence a safety trigger.

    Read from the shipped skills rather than from a list here, so a bundled
    skill that later raises a mapped trigger to Tier C or D fails this instead
    of quietly becoming silenceable.
    """
    yaml = pytest.importorskip("yaml")
    offenders = []
    skill_files = sorted(
        (Path(__file__).resolve().parents[1] / "skills").glob("*/skill.yaml")
    )
    assert skill_files, "no bundled skills found; this guard would pass vacuously"
    for path in skill_files:
        data = yaml.safe_load(path.read_text()) or {}
        for trigger in data.get("triggers") or []:
            name = str(trigger.get("name", ""))
            tier = str(trigger.get("action_tier", "")).upper()
            bypass = bool(trigger.get("bypass_llm", False))
            key = (path.parent.name, name)
            if key in alert_classes.TRIGGER_ALERT_CLASS and (
                tier in {"C", "D"} or bypass
            ):
                offenders.append(f"{path.parent.name}:{name} tier={tier}")
    assert offenders == []


def test_an_unmapped_trigger_has_no_class() -> None:
    """A gap fails toward notifying, never toward silence."""
    assert (
        alert_class_for_trigger(SKILL, "dangerous_overcurrent", first_party=True)
        is None
    )
    assert alert_class_for_trigger(SKILL, "", first_party=True) is None
    assert alert_class_for_trigger(SKILL, "not_a_trigger", first_party=True) is None


def test_the_shipped_map_is_empty() -> None:
    """No class is bound, and every class is declared unbound.

    Binding a bare trigger name would be the inference the contract forbids,
    and a bare name is not an identity: trigger names come from `skill.yaml`,
    so any skill declaring the same one would inherit the toggle. An entry
    needs a first-party skill and trigger together, named by the contract.
    """
    assert alert_classes.TRIGGER_ALERT_CLASS == {}
    assert UNBOUND_ALERT_CLASSES == ALERT_CLASSES


def test_a_community_skill_never_resolves_to_a_class(bound) -> None:
    """An untrusted skill cannot take over a customer's toggle by naming."""
    assert alert_class_for_trigger(*bound, first_party=True) == "grid_power_restored"
    assert alert_class_for_trigger(*bound, first_party=False) is None


def test_a_different_skill_with_the_same_trigger_name_does_not_resolve(bound) -> None:
    assert alert_class_for_trigger("other-skill", TRIGGER, first_party=True) is None


# --------------------------------------------------------------------------
# Absence is enablement
# --------------------------------------------------------------------------


def test_a_policy_with_no_alerts_enables_every_class() -> None:
    """An older signed policy predating the toggles must not silence them."""
    policy = _policy()
    assert policy.alerts == {}
    for name in ALERT_CLASSES:
        assert policy.permits_alert_class(name) is True


def test_an_omitted_known_class_is_enabled() -> None:
    policy = _policy(alerts={"grid_power_restored": False})
    assert policy.permits_alert_class("grid_power_restored") is False
    assert policy.permits_alert_class("battery_underperforming") is True


def test_one_disabled_class_suppresses_only_itself() -> None:
    policy = _policy(
        alerts={name: True for name in ALERT_CLASSES} | {"grid_power_restored": False}
    )
    disabled = [n for n in ALERT_CLASSES if not policy.permits_alert_class(n)]
    assert disabled == ["grid_power_restored"]


def test_an_unknown_key_disables_nothing() -> None:
    """A product-side addition must not strand a device or silence a notice."""
    policy = _policy(alerts={"not_a_class": False, "grid_power_restored": True})
    assert policy.alerts == {"grid_power_restored": True}
    assert policy.permits_alert_class("not_a_class") is True


def test_a_non_boolean_toggle_is_not_a_decision_to_disable() -> None:
    policy = _policy(alerts={"grid_power_restored": "false"})
    assert policy.alerts == {}
    assert policy.permits_alert_class("grid_power_restored") is True


def test_the_policy_exempts_tier_d_on_its_own() -> None:
    """The model refuses to withhold a Tier D notice without help from above.

    The runtime short-circuits Tier D before reaching here, so this asserts
    the layer holds by itself rather than because an earlier check held.
    """
    policy = _policy(alerts={name: False for name in ALERT_CLASSES})
    assert policy.permits_alert_class("grid_power_restored", action_tier="D") is True
    assert policy.permits_alert_class("grid_power_restored", action_tier="d") is True
    assert policy.permits_alert_class("grid_power_restored", action_tier="A") is False


def test_the_dispatcher_exempts_tier_d_on_its_own() -> None:
    """The same rule, one layer up."""
    from ori.reasoning.action_dispatcher import ActionDispatcher

    dispatcher = ActionDispatcher()
    dispatcher.update_policy(_policy(alerts={name: False for name in ALERT_CLASSES}))
    assert (
        dispatcher.permits_alert_class("grid_power_restored", action_tier="D") is True
    )
    assert (
        dispatcher.permits_alert_class("grid_power_restored", action_tier="A") is False
    )


def test_a_trigger_with_no_class_is_always_permitted() -> None:
    policy = _policy(alerts={name: False for name in ALERT_CLASSES})
    assert policy.permits_alert_class(None) is True


# --------------------------------------------------------------------------
# The parser
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [None, "", "grid_power_restored", 7, [], ["grid_power_restored"], [("a", True)]],
)
def test_a_malformed_alerts_payload_yields_no_toggle(payload) -> None:
    """Malformed is not a decision to switch anything off, and not an error.

    Refusing the whole policy would strand a device on its last one over a
    field that can only ever remove notices, so the payload is discarded and
    every class stays enabled.
    """
    assert _alert_preferences(payload) == {}


def test_the_parser_keeps_only_boolean_entries() -> None:
    assert _alert_preferences(
        {"grid_power_restored": False, "battery_underperforming": "no", "x": 1}
    ) == {"grid_power_restored": False}


def test_a_parsed_payload_survives_into_the_policy() -> None:
    """The parser and the model agree on what a toggle is.

    Asserted together because each filters, and a filter that only one applies
    would leave the other's guarantee resting on the caller.
    """
    parsed = _alert_preferences({"grid_power_restored": False, "bogus": False})
    policy = dataclasses.replace(DevicePolicy.unrestricted(), alerts=parsed)
    assert policy.alerts == {"grid_power_restored": False}
    assert policy.permits_alert_class("grid_power_restored") is False


# --------------------------------------------------------------------------
# The boundary: a safety notice never reaches a preference
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_safety_notice_that_consulted_a_preference_would_raise() -> None:
    """Drive a mandatory notice with both gates rigged to explode.

    Not a source check. If the safety path is ever joined to the preference or
    cap gate, this raises instead of returning a quiet `False`, so the failure
    names the cause rather than looking like a delivery problem.
    """
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._operator_contact = "+2348000000000"
    runtime._primary_alert_channel = "sms"
    runtime._state_store = None
    runtime._last_alert_timestamps_by_channel = {}
    runtime._last_alert_timestamps_by_trigger = {}

    def _explode(*args, **kwargs):
        raise AssertionError("a mandatory notice consulted a customer preference")

    runtime._policy_permits_alert_class = _explode  # type: ignore[method-assign]
    runtime._policy_permits_external_alert = _explode  # type: ignore[method-assign]
    runtime._record_policy_counted_alert = _explode  # type: ignore[method-assign]

    sent: list[dict] = []

    class _Sender:
        async def send(self, *, message, to_number, preferred_channel):
            sent.append(
                {"message": message, "to": to_number, "channel": preferred_channel}
            )
            return True

    delivered = await runtime._send_or_queue_safety_alert(
        message="SAFETY measurement_loss: zone z1 lost its measurement",
        trigger_name="safety_measurement_loss",
        alert_sender=_Sender(),  # type: ignore[arg-type]
    )

    assert delivered is True
    assert len(sent) == 1


def _runtime_with_policy(policy: DevicePolicy | None) -> OriRuntime:
    """A real runtime holding a real dispatcher holding a real policy.

    Stubbing the gate would leave the chain from a signed toggle to a withheld
    message unproven: every link between `DevicePolicy` and the send is a real
    object here, so removing any of them fails these.
    """
    from ori.reasoning.action_dispatcher import ActionDispatcher

    dispatcher = ActionDispatcher()
    dispatcher.update_policy(policy)
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._dispatcher = dispatcher
    runtime._operator_contact = "+2348000000000"
    runtime._state_store = None
    runtime._last_alert_timestamps_by_channel = {}
    runtime._last_alert_timestamps_by_trigger = {}
    return runtime


class _RecordingSender:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, *, message, to_number, preferred_channel):
        self.sent.append(message)
        return True


SKILL = "energy-anomaly-detector"
TRIGGER = "grid_phcn_restored"


def _dispatch_inputs():
    """A minimal first-party context and reasoning result for `dispatch`."""
    from dataclasses import dataclass, field

    from ori.network.events import OriEvent, ReasoningResult, SensorReading
    from ori.reasoning.elevator import SkillContext

    @dataclass
    class _Skill:
        name: str = SKILL
        config: dict = field(default_factory=dict)
        triggers: list = field(default_factory=list)
        actions: dict = field(default_factory=dict)
        first_party: bool = True

    event = OriEvent.from_reading(
        SensorReading(
            sensor_id="load-current",
            sensor_type="current",
            value=1.0,
            unit="ampere",
            timestamp=1,
            quality=1.0,
        ),
        "dev-01",
    )
    ctx = SkillContext(
        skill=_Skill(), event=event, state_store=None, trigger_name=TRIGGER
    )
    return ctx, ReasoningResult(
        text="", tier="rule", model="", tokens_used=0, latency_ms=0
    )


@pytest.fixture
def bound(monkeypatch: pytest.MonkeyPatch):
    """Bind one identity for the duration of a test.

    The shipped map is empty and must stay so until the contract names its
    entries, so the mechanism is exercised through an injected binding rather
    than by shipping a guess. `test_the_shipped_map_is_empty` is what holds the
    shipped state.
    """
    monkeypatch.setitem(
        alert_classes.TRIGGER_ALERT_CLASS, (SKILL, TRIGGER), "grid_power_restored"
    )
    return (SKILL, TRIGGER)


async def _deliver(
    runtime: OriRuntime,
    sender: _RecordingSender,
    *,
    trigger: str,
    tier: str = "A",
    original_ts: int = 1,
    skill: str = SKILL,
    first_party: bool = True,
) -> bool | str:
    return await runtime._send_or_queue_alert(
        channel="sms",
        message=f"{trigger} fired",
        recipient="+2348000000000",
        action_tier=tier,
        trigger_name=trigger,
        original_ts=original_ts,
        alert_sender=sender,  # type: ignore[arg-type]
        skill_name=skill,
        skill_is_first_party=first_party,
    )


@pytest.mark.asyncio
async def test_a_signed_toggle_withholds_only_its_own_class(bound) -> None:
    """The whole chain: a real policy, a real dispatcher, a real send."""
    runtime = _runtime_with_policy(_policy(alerts={"grid_power_restored": False}))
    sender = _RecordingSender()

    assert await _deliver(runtime, sender, trigger=TRIGGER) == ALERT_SUPPRESSED
    assert sender.sent == []

    # A sibling trigger with no binding is untouched by the same policy.
    assert await _deliver(runtime, sender, trigger="sustained_overdraw") is True
    assert len(sender.sent) == 1


@pytest.mark.asyncio
async def test_a_policy_leaving_the_class_on_delivers(bound) -> None:
    """The counterpart, so suppression cannot pass by nothing being sent."""
    runtime = _runtime_with_policy(_policy(alerts={"grid_power_restored": True}))
    sender = _RecordingSender()

    assert await _deliver(runtime, sender, trigger=TRIGGER) is True
    assert len(sender.sent) == 1


@pytest.mark.asyncio
async def test_no_policy_at_all_delivers(bound) -> None:
    runtime = _runtime_with_policy(None)
    sender = _RecordingSender()

    assert await _deliver(runtime, sender, trigger=TRIGGER) is True
    assert len(sender.sent) == 1


@pytest.mark.asyncio
async def test_a_tier_d_notice_is_never_withheld_by_a_preference(bound) -> None:
    """Named regression test for the criterion that preferences leave Tier D alone.

    A withheld Tier D notice is not merely a missing message: the executor
    returns False, which the dispatcher reads as a safety-critical action that
    failed to execute and answers with an emergency escalation. So the toggle
    is set false and the class is bound, and delivery must still happen.
    """
    runtime = _runtime_with_policy(
        _policy(alerts={name: False for name in ALERT_CLASSES})
    )
    sender = _RecordingSender()

    delivered = await _deliver(runtime, sender, trigger="grid_phcn_restored", tier="D")

    assert delivered is True
    assert len(sender.sent) == 1


@pytest.mark.asyncio
async def test_an_expired_lease_stops_withholding(bound) -> None:
    """A lapsed policy must not hold a notice off forever.

    A device that cannot reach the product API keeps its last policy. If that
    policy could still silence a class, the customer has no way to switch it
    back on while offline, and the failure direction would be silence.
    """
    expired = _policy(alerts={"grid_power_restored": False}, valid_until=1)
    assert expired.is_expired
    runtime = _runtime_with_policy(expired)
    sender = _RecordingSender()

    assert await _deliver(runtime, sender, trigger=TRIGGER) is True
    assert len(sender.sent) == 1


@pytest.mark.asyncio
async def test_a_withheld_alert_reports_no_activity_in_health(bound) -> None:
    """Health must not show a notice the customer switched off as having fired."""
    runtime = _runtime_with_policy(_policy(alerts={"grid_power_restored": False}))
    sender = _RecordingSender()

    await _deliver(runtime, sender, trigger=TRIGGER)

    assert runtime._last_alert_timestamps_by_trigger == {}
    assert runtime._last_alert_timestamps_by_channel == {}


def test_the_safety_path_names_no_preference_symbol_in_its_body() -> None:
    """A source check kept alongside the behavioural one, not instead of it."""
    source = inspect.getsource(OriRuntime._send_or_queue_safety_alert)
    assert "_policy_permits_alert_class" not in source
    assert "alert_class_for_trigger" not in source
    assert "_policy_permits_external_alert" not in source


def test_the_safety_path_reaches_no_policy_gate_through_any_call_it_makes() -> None:
    """A denylist over the calls the safety path makes directly.

    Not transitive, and not a proof: it names six symbols and walks one
    function body, so a consultation routed through a differently named helper
    passes it. The behavioural test above is what carries the weight; this
    catches the direct, likely form early and cheaply.
    """
    runtime_src = (
        Path(__file__).resolve().parents[1] / "ori" / "runtime.py"
    ).read_text()
    tree = ast.parse(runtime_src)
    target = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            node.name == "_send_or_queue_safety_alert"
        ):
            target = node
    assert target is not None, "the safety path was renamed; update this guard"

    forbidden = {
        "_policy_permits_alert_class",
        "_policy_permits_external_alert",
        "permits_alert_class",
        "permits_external_alert",
        "alert_class_for_trigger",
        "_record_policy_counted_alert",
    }
    called = set()
    for node in ast.walk(target):
        if isinstance(node, ast.Call):
            fn = node.func
            name = getattr(fn, "attr", None) or getattr(fn, "id", None)
            if name:
                called.add(name)
    assert not (called & forbidden), sorted(called & forbidden)


def test_the_ordinary_path_does_consult_the_preference() -> None:
    """The counterpart, so the guard above cannot pass by the gate not existing."""
    source = inspect.getsource(OriRuntime._send_or_queue_alert)
    assert "_policy_permits_alert_class" in source


def test_no_safety_notice_names_a_trigger_the_map_can_reach() -> None:
    """A mandatory notice is not addressed by class, so no toggle can name it.

    `_send_or_queue_safety_alert` takes a trigger name and never resolves it to
    a class. Its callers name conditions -- an absent protection, a sensor that
    never connected, a measurement that stopped -- and none is a customer
    preference. This asserts no caller's trigger name is mapped.
    """
    runtime_src = (
        Path(__file__).resolve().parents[1] / "ori" / "runtime.py"
    ).read_text()
    tree = ast.parse(runtime_src)
    safety_trigger_names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if (getattr(fn, "attr", None) or "") != "_send_or_queue_safety_alert":
            continue
        for kw in node.keywords:
            if kw.arg == "trigger_name":
                if isinstance(kw.value, ast.Constant) and isinstance(
                    kw.value.value, str
                ):
                    safety_trigger_names.add(kw.value.value)
                elif isinstance(kw.value, ast.JoinedStr):
                    literal = "".join(
                        v.value
                        for v in kw.value.values
                        if isinstance(v, ast.Constant) and isinstance(v.value, str)
                    )
                    safety_trigger_names.add(literal)
    assert safety_trigger_names, "no safety notice callers found; update this guard"
    for name in safety_trigger_names:
        assert alert_class_for_trigger("", name, first_party=True) is None, name
        assert not any(
            name.startswith(t) for _s, t in alert_classes.TRIGGER_ALERT_CLASS
        ), name


@pytest.mark.asyncio
async def test_a_suppressed_alert_makes_no_provider_call_and_leaves_a_record(
    tmp_path, bound
) -> None:
    """Suppression is durable and silent toward the provider.

    Two halves, and each is load-bearing: nothing is sent, and the reason
    outlives the process, because an operator asking why no message arrived
    cannot be answered by a log line that has rotated away.
    """
    from ori.state.store import StateStore

    store = StateStore(str(tmp_path / "s.db"))
    await store.open()
    try:
        runtime = _runtime_with_policy(_policy(alerts={"grid_power_restored": False}))
        runtime._state_store = store
        sender = _RecordingSender()

        # Distinct event timestamps inside one month: an event-keyed record
        # would write three rows, a month-keyed one writes a single row.
        for original_ts in (1_700_000_000_000, 1_700_000_060_000, 1_700_000_120_000):
            delivered = await _deliver(
                runtime,
                sender,
                trigger=TRIGGER,
                original_ts=original_ts,
            )
            assert delivered == ALERT_SUPPRESSED
        assert sender.sent == []

        # Read the table directly: what matters is that three suppressions
        # produced one row, which no store accessor can show.
        import sqlite3

        with sqlite3.connect(str(tmp_path / "s.db")) as conn:
            rows = conn.execute(
                "SELECT key, value FROM skill_state WHERE skill_name = ?",
                ("__runtime_alert_preferences__",),
            ).fetchall()
        assert len(rows) == 1, rows
        payload = json.loads(rows[0][1])
        assert payload["outcome"] == "disabled"
        assert payload["reason"] == "customer_preference"
        assert payload["alert_class"] == "grid_power_restored"
        assert payload["count"] == 3
        assert payload["last_suppressed_ms"] > 0
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_the_real_dispatcher_logs_a_suppression_as_suppressed(
    tmp_path, bound
) -> None:
    """`action_log` must tell a withheld notice from one that failed to send.

    Both leave `executed` false. Only a failure leaves `action_taken` empty;
    a suppression names itself, so an operator reading the log is not told a
    provider call failed when none was made.
    """
    from ori.reasoning.action_dispatcher import ActionDispatcher
    from ori.state.store import StateStore

    store = StateStore(str(tmp_path / "s.db"))
    await store.open()
    try:
        dispatcher = ActionDispatcher(state_store=store)
        dispatcher.update_policy(_policy(alerts={"grid_power_restored": False}))

        calls: list[str] = []

        async def _suppressing(action: str, ctx) -> str:
            calls.append(action)
            return ALERT_SUPPRESSED

        async def _failing(action: str, ctx) -> bool:
            calls.append(action)
            return False

        dispatcher.register_executor("alert_sms", _suppressing)
        dispatcher.register_executor("alert_whatsapp", _failing)

        ctx, res = _dispatch_inputs()
        suppressed = await dispatcher.dispatch("alert_sms", "A", ctx, res)
        failed = await dispatcher.dispatch("alert_whatsapp", "A", ctx, res)

        assert suppressed.executed is False
        assert suppressed.action_taken == "suppressed"
        assert failed.executed is False
        assert failed.action_taken == ""
        assert suppressed.action_taken != failed.action_taken
        assert calls == ["alert_sms", "alert_whatsapp"]

        import sqlite3

        with sqlite3.connect(str(tmp_path / "s.db")) as conn:
            rows = dict(
                conn.execute(
                    "SELECT action_name, action_taken FROM action_log"
                ).fetchall()
            )
        assert rows["alert_sms"] == "suppressed"
        assert rows["alert_whatsapp"] == ""
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_a_tier_d_action_reporting_itself_suppressed_still_escalates() -> None:
    """Suppression must never be a route around the Tier D failure path.

    Unreachable today, because the preference gate exempts Tier D at three
    layers. Asserted anyway: if it ever became reachable, a suppressed Tier D
    action that skipped the escalation would be a silent missing cutoff.
    """
    from ori.reasoning.action_dispatcher import ActionDispatcher

    dispatcher = ActionDispatcher()
    escalations: list[tuple[str, str]] = []

    async def _emergency(action, device_id):
        escalations.append((action, device_id))

    dispatcher._emergency_sms = _emergency  # type: ignore[method-assign]

    async def _suppressing(action: str, ctx) -> str:
        return ALERT_SUPPRESSED

    dispatcher.register_executor("emergency_cutoff", _suppressing)

    ctx, res = _dispatch_inputs()
    result = await dispatcher.dispatch("emergency_cutoff", "D", ctx, res)

    assert result.executed is False
    assert result.action_taken == ""
    assert len(escalations) == 1


def test_the_identity_resolver_reads_provenance_from_the_loader() -> None:
    """`first_party` comes off the skill the loader built, never a default.

    The loader sets it from the packaged roots and never reads it from
    `skill.yaml`, so a skill cannot claim it. A resolver that assumed it would
    hand a community skill the customer's toggle.
    """
    from dataclasses import dataclass

    from ori.runtime import _resolve_skill_identity

    @dataclass
    class _Skill:
        name: str
        first_party: bool

    class _Ctx:
        def __init__(self, skill):
            self.skill = skill

    resolve = cast("Callable[..., tuple[str, bool]]", _resolve_skill_identity)
    assert resolve(_Ctx(_Skill(SKILL, True))) == (SKILL, True)
    assert resolve(_Ctx(_Skill(SKILL, False))) == (SKILL, False)
    # Anything unresolvable reads as community, which resolves to no class.
    assert resolve(_Ctx(None)) == ("", False)
    assert resolve(None) == ("", False)


@pytest.mark.asyncio
async def test_a_community_skill_is_not_suppressed_end_to_end(bound) -> None:
    """The whole path, with the only difference being who wrote the skill."""
    runtime = _runtime_with_policy(_policy(alerts={"grid_power_restored": False}))
    sender = _RecordingSender()

    assert await _deliver(runtime, sender, trigger=TRIGGER, first_party=False) is True
    assert len(sender.sent) == 1


@pytest.mark.asyncio
async def test_a_disabled_alert_with_no_recipient_is_still_disabled(
    tmp_path, bound
) -> None:
    """A switched-off notice is not a missing-recipient fault.

    The two conditions are ordered, not merely both present: a deployment that
    has not configured a contact and a customer who switched a class off are
    different facts, and recording the second as the first would send an
    operator looking for configuration that is not missing.
    """
    from ori.state.store import StateStore

    store = StateStore(str(tmp_path / "s.db"))
    await store.open()
    try:
        runtime = _runtime_with_policy(_policy(alerts={"grid_power_restored": False}))
        runtime._state_store = store
        sender = _RecordingSender()

        result = await runtime._send_or_queue_alert(
            channel="sms",
            message="grid restored",
            recipient="",
            action_tier="A",
            trigger_name=TRIGGER,
            original_ts=1_700_000_000_000,
            alert_sender=sender,  # type: ignore[arg-type]
            skill_name=SKILL,
            skill_is_first_party=True,
        )

        assert result == ALERT_SUPPRESSED
        assert sender.sent == []

        import sqlite3

        with sqlite3.connect(str(tmp_path / "s.db")) as conn:
            rows = conn.execute(
                "SELECT value FROM skill_state WHERE skill_name = ?",
                ("__runtime_alert_preferences__",),
            ).fetchall()
        assert len(rows) == 1
        assert json.loads(rows[0][0])["outcome"] == "disabled"
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_an_unmapped_alert_with_no_recipient_is_still_a_failure(bound) -> None:
    """Reordering must not swallow the missing-recipient case it moved past."""
    runtime = _runtime_with_policy(_policy())
    sender = _RecordingSender()

    result = await runtime._send_or_queue_alert(
        channel="sms",
        message="anything",
        recipient="",
        action_tier="A",
        trigger_name="sustained_overdraw",
        original_ts=1,
        alert_sender=sender,  # type: ignore[arg-type]
        skill_name=SKILL,
        skill_is_first_party=True,
    )

    assert result is False
    assert sender.sent == []
