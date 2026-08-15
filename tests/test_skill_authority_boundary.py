# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime decides action authority, not the skill.

Skill YAML is untrusted input: it is the thing the Action Tier Framework
exists to constrain, and it arrives from a Hub the runtime does not control.
Before these boundaries existed, a skill could declare a relay action as Tier A
and reach immediate autonomous execution, or define ``value`` in its own config
and decide what a Tier D condition compared against.

Each property below is asserted at every layer that enforces it, separately.
A layer that only holds because an earlier one also held is not a boundary, so
the tests deliberately reach past the outer checks to prove the inner ones.
"""

import ast
import inspect
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

from ori.network.events import ActionTier, OriEvent, ReasoningResult, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher, UngovernedActionError
from ori.reasoning.action_registry import (
    ACTION_REGISTRY,
    enforce_minimum_tier,
    is_safe_default_eligible,
)
from ori.reasoning.elevator import SkillContext, _without_reserved_names
from ori.reasoning.rule_engine import RESERVED_CONTEXT_NAMES, RuleEngine
from ori.skills.loader import SkillLoader, SkillValidationError
from ori.skills.sandbox import SkillSecurityError

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _ms() -> int:
    return int(time.time() * 1000)


def _reading(value: float = 5.0) -> SensorReading:
    return SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=value,
        unit="ampere",
        timestamp=_ms(),
        quality=1.0,
    )


def _event(value: float = 5.0) -> OriEvent:
    return OriEvent.from_reading(_reading(value), "dev-01")


@dataclass
class _Skill:
    """Test double mirroring the real dataclass, including its closed default.

    ``first_party`` defaults to False here for the same reason it does on
    ``Skill``: a double that silently carried authority would let a test pass
    for a reason production never reproduces.
    """

    name: str = "hostile-skill"
    config: dict = field(default_factory=dict)
    triggers: list = field(default_factory=list)
    actions: dict = field(default_factory=dict)
    first_party: bool = False


def _context(actions: dict | None = None, *, first_party: bool = False) -> SkillContext:
    return SkillContext(
        skill=_Skill(actions=actions or {}, first_party=first_party),
        event=_event(),
        state_store=None,
    )


def _packaged_context(actions: dict | None = None) -> SkillContext:
    """A context standing in for a skill that ships with the runtime."""
    return _context(actions, first_party=True)


def _result(tier: str = "A") -> ReasoningResult:
    return ReasoningResult(
        text="observation",
        tier="rule",
        model="none",
        tokens_used=0,
        latency_ms=0,
        action_tier=tier,
    )


def _skill_yaml(
    *,
    action_tier: str = "A",
    action_name: str = "trip_relay",
    action_declared_tier: str = "A",
    safe_default: str | None = None,
    config_block: str = "",
) -> str:
    safe_default_line = (
        f"\n    safe_default_action: {safe_default}" if safe_default else ""
    )
    return f"""\
name: hostile-skill
version: 1.0.0
author: tester
signature: bundled
sensors_required:
  - type: current_clamp
triggers:
  - name: fire
    condition: "value > 1"
    action_tier: {action_tier}{safe_default_line}
actions:
  available:
    - name: {action_name}
      tier: {action_declared_tier}
  defaults:
    fire: [{action_name}]
{config_block}"""


def _write(skill_dir: Path, content: str) -> Path:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "skill.yaml").write_text(content, encoding="utf-8")
    return skill_dir


def _loader() -> SkillLoader:
    """A loader that treats the scratch directory as packaged.

    Provenance is proven separately in ``test_sandbox.py``. Stubbing it here
    keeps these tests about action authority: the skill under test is the most
    trusted kind there is, and the authority boundary must still hold.
    """
    loader = SkillLoader()
    loader._is_core_bundled_skill = lambda skill_dir: True  # type: ignore[method-assign]
    return loader


class _RecordingBus:
    """Minimal EventBus stand-in supporting subscribe and unsubscribe."""

    def __init__(self) -> None:
        self.subscriptions: list[tuple[str, object]] = []

    def subscribe(self, sensor_type, handler):
        self.subscriptions.append((sensor_type, handler))

    def unsubscribe(self, sensor_type, handler):
        self.subscriptions.remove((sensor_type, handler))


# ─── The registry itself ──────────────────────────────────────────────────────


class TestEveryExecutableActionIsGoverned:
    """The registry must cover everything the runtime can actually execute.

    Keeping the registry in step with executor registration was a comment
    asking reviewers to remember. An action becomes able to do something the
    moment an executor is registered for it, and an ungoverned action has no
    tier floor and counts as safe-default eligible — so a forgotten entry
    produces precisely the gap the registry exists to close.
    """

    def test_every_runtime_executor_has_a_capability(self):
        """Read the names OriRuntime registers straight out of the source.

        Parsed rather than executed: starting the runtime needs hardware,
        credentials and a broker, and this must hold for every executor
        including those behind a `if relay_action is not None` branch.
        """
        source = (
            Path(__file__).resolve().parents[1] / "ori" / "runtime.py"
        ).read_text()
        tree = ast.parse(source)

        registered: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr != "register_executor":
                continue
            if node.args and isinstance(node.args[0], ast.Constant):
                value = node.args[0].value
                if isinstance(value, str):
                    registered.add(value)

        assert registered, "no register_executor calls found — did runtime.py move?"
        ungoverned = sorted(registered - set(ACTION_REGISTRY))
        assert not ungoverned, (
            f"OriRuntime registers executors for {ungoverned}, which have no "
            "entry in action_registry.py. An executable action must be governed."
        )

    def test_registering_an_ungoverned_executor_is_refused(self):
        dispatcher = ActionDispatcher()

        async def _exec(action, ctx):  # pragma: no cover - must never run
            raise AssertionError("ungoverned executor ran")

        with pytest.raises(UngovernedActionError, match="action_registry"):
            dispatcher.register_executor("future_physical_action", _exec)

        assert "future_physical_action" not in dispatcher._executors

    def test_registry_has_no_tier_d_floor(self):
        """A Tier D floor would escalate past approval rather than into it."""
        for name, entry in ACTION_REGISTRY.items():
            assert entry.minimum_tier != "D", (
                f"{name} has a Tier D floor; raising an action to Tier D skips "
                "the approval workflow instead of entering it"
            )


class TestRegistryShape:
    def test_every_physical_action_is_above_tier_a(self):
        for name, entry in ACTION_REGISTRY.items():
            if entry.physical:
                assert entry.minimum_tier != "A", (
                    f"{name} actuates but may be dispatched as informational"
                )

    def test_no_physical_action_is_safe_default_eligible(self):
        for name, entry in ACTION_REGISTRY.items():
            if entry.physical:
                assert entry.safe_default_eligible is False, (
                    f"{name} actuates and must never run as a Tier C fallback"
                )

    def test_registry_only_raises_tiers(self):
        for name in ACTION_REGISTRY:
            for tier in ("A", "B", "C", "D"):
                assert enforce_minimum_tier(name, tier) in (tier, "B", "C", "D")

    def test_tier_d_declaration_is_never_lowered(self):
        """A skill may raise a relay action to Tier D; the floor must not undo it."""
        assert enforce_minimum_tier("trip_relay", "D") == "D"

    def test_ungoverned_action_keeps_its_tier(self):
        """An action with no executor cannot actuate, so it is not constrained."""
        assert enforce_minimum_tier("no_such_action", "A") == "A"
        assert is_safe_default_eligible("no_such_action") is True


# ─── Tier floors ──────────────────────────────────────────────────────────────


class TestSkillCannotUnderstateActionTier:
    def test_relay_declared_as_informational_is_refused_at_load(self, tmp_path):
        skill_dir = _write(tmp_path / "s", _skill_yaml(action_declared_tier="A"))
        with pytest.raises(SkillValidationError, match="at least Tier C"):
            _loader().load_one(skill_dir)

    def test_governed_action_without_a_tier_is_refused_at_load(self, tmp_path):
        """Omitting the tier must not be a way to skip declaring one.

        Dispatch would raise the action to its floor anyway, but a skill whose
        action list leaves the field out has the tier decided somewhere the
        operator writing the file never sees. The declaration is what an
        operator reviews, so it has to be present.
        """
        yaml_without_tier = """\
name: hostile-skill
version: 1.0.0
author: tester
signature: bundled
sensors_required:
  - type: current_clamp
triggers:
  - name: fire
    condition: "value > 1"
    action_tier: A
actions:
  available:
    - name: trip_relay
  defaults:
    fire: [trip_relay]
"""
        skill_dir = _write(tmp_path / "s", yaml_without_tier)
        with pytest.raises(SkillValidationError, match="without a tier"):
            _loader().load_one(skill_dir)

    def test_ungoverned_action_without_a_tier_is_not_a_security_error(self, tmp_path):
        """An action the runtime cannot execute is a documentation matter.

        It has no executor, so it cannot actuate. Rejecting it here would turn
        a flat-action-list style issue into a security refusal and say nothing
        true about authority.
        """
        yaml_without_tier = """\
name: hostile-skill
version: 1.0.0
author: tester
signature: bundled
sensors_required:
  - type: current_clamp
triggers:
  - name: fire
    condition: "value > 1"
    action_tier: A
actions:
  available:
    - name: some_future_action
  defaults:
    fire: [some_future_action]
"""
        skill_dir = _write(tmp_path / "s", yaml_without_tier)
        skill = _loader().load_one(skill_dir)
        assert skill.name == "hostile-skill"

    def test_relay_declared_at_tier_c_loads(self, tmp_path):
        skill_dir = _write(
            tmp_path / "s",
            _skill_yaml(
                action_tier="C",
                action_declared_tier="C",
                safe_default="log_to_dashboard",
            ),
        )
        skill = _loader().load_one(skill_dir)
        assert skill.name == "hostile-skill"

    async def test_dispatch_raises_a_tier_a_relay_action(self):
        """Reaching dispatch with an understated tier still does not execute.

        The load-time check is bypassed here on purpose: the dispatcher must
        refuse on its own, because it is also reachable from reasoning output
        and from hook-mutated results that never passed skill validation.
        """
        dispatcher = ActionDispatcher()
        ran = False

        async def _exec(action, ctx):
            nonlocal ran
            ran = True

        dispatcher.register_executor("trip_relay", _exec)

        result = await dispatcher.dispatch(
            "trip_relay", ActionTier.INFORMATIONAL, _context(), _result()
        )

        assert ran is False, "a relay fired without passing the approval workflow"
        assert result.action_name != "trip_relay" or result.executed is False

    async def test_understated_relay_reaches_approval_when_relay_is_enabled(self):
        """With the relay wired, the raised tier lands in the approval workflow.

        The previous test exercises the path where DevicePolicy suppresses the
        relay outright. This one removes that second line of defence so the
        registry escalation is the only thing standing between a Tier A
        declaration and a physical actuation.
        """
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        ran = False

        async def _exec(action, ctx):
            nonlocal ran
            ran = True

        dispatcher.register_executor("trip_relay", _exec)

        result = await dispatcher.dispatch(
            "trip_relay",
            ActionTier.INFORMATIONAL,
            _context(),
            _result(),
            safe_default_action="log_to_dashboard",
            approval_timeout=0,
        )

        assert ran is False, "a relay fired without operator approval"
        assert result.approved is not True
        assert result.tier == ActionTier.HARD_PHYSICAL

    async def test_execute_immediately_refuses_below_the_floor(self):
        """The innermost gate refuses even when called directly."""
        dispatcher = ActionDispatcher()
        ran = False

        async def _exec(action, ctx):
            nonlocal ran
            ran = True

        dispatcher.register_executor("close_gas_valve", _exec)

        result = await dispatcher._execute_immediately(
            "close_gas_valve", ActionTier.INFORMATIONAL, _context()
        )

        assert ran is False
        assert result.executed is False
        assert result.action_taken == "refused_below_minimum_tier"

    async def test_skill_cannot_escalate_an_action_into_tier_d(self):
        """Declaring an action as Tier D must not skip the approval workflow.

        This is the mirror of understating a tier, and it is the more effective
        one: Tier D is not merely higher, it removes the approval step and
        fires immediately. A skill with a Tier A trigger that declared
        ``trip_relay`` as Tier D in its action list previously had the relay
        energised with no operator involvement at all. Tier D comes from the
        trigger, evaluated by the rule engine, and nowhere else.
        """
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        fired = []

        async def _exec(action, ctx):
            fired.append(action)

        dispatcher.register_executor("trip_relay", _exec)

        result = await dispatcher.dispatch(
            "trip_relay",
            ActionTier.INFORMATIONAL,
            _context({"available": [{"name": "trip_relay", "tier": "D"}]}),
            _result(),
            safe_default_action="log_to_dashboard",
            approval_timeout=0,
        )

        assert fired == [], "a Tier D declaration bypassed the approval workflow"
        assert result.tier == ActionTier.HARD_PHYSICAL

    async def test_trigger_declared_tier_d_still_fires_autonomously(self):
        """The legitimate safety path is untouched: Tier D from the trigger."""
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        fired = []

        async def _exec(action, ctx):
            fired.append(action)

        dispatcher.register_executor("trip_relay", _exec)

        result = await dispatcher.dispatch(
            "trip_relay",
            ActionTier.SAFETY_CRITICAL,
            _packaged_context({"available": [{"name": "trip_relay", "tier": "D"}]}),
            _result("D"),
        )

        assert fired == ["trip_relay"], "a Tier D safety action did not fire"
        assert result.executed is True

    async def test_informational_action_is_unaffected(self):
        dispatcher = ActionDispatcher()
        ran = False

        async def _exec(action, ctx):
            nonlocal ran
            ran = True

        dispatcher.register_executor("alert_sms", _exec)
        result = await dispatcher.dispatch(
            "alert_sms", ActionTier.INFORMATIONAL, _context(), _result()
        )
        assert ran is True
        assert result.executed is True


# ─── Safe defaults ────────────────────────────────────────────────────────────


class TestTierDRequiresFirstPartyProvenance:
    """A skill cannot grant itself the tier that removes the operator.

    Tier D fires immediately, before any LLM, and cannot be overridden. Every
    other check in the loader passes for a correctly signed community skill
    that declares an always-true Tier D trigger on a relay action — the
    signature proves who wrote it, not that the runtime granted it that
    authority. Until a capability grant binding skill identity, trigger, action
    and permitted maximum tier exists, Tier D is confined to skills shipped and
    released with the runtime.
    """

    def _tier_d_yaml(self) -> str:
        return """\
name: hostile-skill
version: 1.0.0
author: tester
signature: bundled
sensors_required:
  - type: current_clamp
triggers:
  - name: always
    condition: "value > -1"
    action_tier: D
    bypass_llm: true
actions:
  available:
    - name: trip_relay
      tier: D
  defaults:
    always: [trip_relay]
"""

    def test_community_skill_cannot_declare_tier_d(self, tmp_path):
        skill_dir = _write(tmp_path / "s", self._tier_d_yaml())
        loader = SkillLoader()
        loader._verify_community_signature = lambda raw, sd: None  # type: ignore[method-assign]

        with pytest.raises(SkillSecurityError, match="does not ship with the runtime"):
            loader.load_one(skill_dir)

    def test_first_party_skill_may_declare_tier_d(self, tmp_path):
        """The legitimate case is untouched — packaged safety skills still load."""
        skill_dir = _write(tmp_path / "s", self._tier_d_yaml())
        skill = _loader().load_one(skill_dir)

        assert skill.first_party is True
        assert skill.triggers[0].action_tier == "D"
        assert skill.triggers[0].bypass_llm is True

    def test_packaged_tier_d_skill_still_loads_from_the_real_tree(self):
        """The shipped gas-leak skill keeps its Tier D trigger."""
        packaged = Path(__file__).resolve().parents[1] / "skills"
        skill = SkillLoader().load_one(packaged / "hvac-refrigerant-monitor")

        assert skill.first_party is True
        assert any(t.action_tier == "D" for t in skill.triggers)

    async def test_dispatch_lowers_tier_d_from_a_non_first_party_skill(self):
        """Second layer: a Skill built another way still cannot fire Tier D."""
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        fired = []

        async def _exec(action, ctx):
            fired.append(action)

        dispatcher.register_executor("trip_relay", _exec)

        skill = _Skill(first_party=False)
        context = SkillContext(skill=skill, event=_event(), state_store=None)

        result = await dispatcher.dispatch(
            "trip_relay",
            ActionTier.SAFETY_CRITICAL,
            context,
            _result("D"),
            safe_default_action="log_to_dashboard",
            approval_timeout=0,
        )

        assert fired == [], "a non-first-party skill fired Tier D autonomously"
        assert result.tier == ActionTier.HARD_PHYSICAL

    async def test_absent_provenance_is_not_trusted_provenance(self):
        """A skill-like object with no `first_party` field holds no Tier D grant.

        Distinct from the explicit-False case above, and the one that matters:
        an earlier version defaulted a missing attribute to trusted so test
        doubles kept Tier D, which meant any object that simply lacked the
        field carried autonomous safety authority. Absence of the grant is not
        possession of it.
        """
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        fired = []

        async def _exec(action, ctx):
            fired.append(action)

        dispatcher.register_executor("trip_relay", _exec)

        # Deliberately not a _Skill: no `first_party` attribute exists at all.
        context = SkillContext(
            skill=SimpleNamespace(name="unknown-origin"),
            event=_event(),
            state_store=None,
        )

        result = await dispatcher.dispatch(
            "trip_relay",
            ActionTier.SAFETY_CRITICAL,
            context,
            _result("D"),
            safe_default_action="log_to_dashboard",
            approval_timeout=0,
        )

        assert fired == [], "an object without provenance fired Tier D"
        assert result.tier == ActionTier.HARD_PHYSICAL

    async def test_execute_immediately_refuses_tier_d_without_provenance(self):
        """The innermost gate refuses on its own, without dispatch's help.

        Reached directly, so the outer lowering cannot be what makes this pass.
        It refuses rather than lowering: at this point there is no approval
        workflow left to fall into.
        """
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        fired = []

        async def _exec(action, ctx):
            fired.append(action)

        dispatcher.register_executor("trip_relay", _exec)

        result = await dispatcher._execute_immediately(
            "trip_relay",
            ActionTier.SAFETY_CRITICAL,
            _context(),  # first_party defaults to False
        )

        assert fired == [], "a relay fired for a skill with no Tier D grant"
        assert result.executed is False
        assert result.action_taken == "refused_tier_d_without_provenance"

    async def test_execute_immediately_allows_packaged_tier_d(self):
        """The inner gate must not block the skills that do hold the grant."""
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        fired = []

        async def _exec(action, ctx):
            fired.append(action)

        dispatcher.register_executor("trip_relay", _exec)

        result = await dispatcher._execute_immediately(
            "trip_relay", ActionTier.SAFETY_CRITICAL, _packaged_context()
        )

        assert fired == ["trip_relay"]
        assert result.executed is True

    async def test_dispatch_keeps_tier_d_for_a_first_party_skill(self):
        """The safety path must not be capped for skills that do hold it."""
        dispatcher = ActionDispatcher(config={"relay_enabled": True})
        fired = []

        async def _exec(action, ctx):
            fired.append(action)

        dispatcher.register_executor("trip_relay", _exec)

        skill = _Skill(first_party=True)
        context = SkillContext(skill=skill, event=_event(), state_store=None)

        result = await dispatcher.dispatch(
            "trip_relay", ActionTier.SAFETY_CRITICAL, context, _result("D")
        )

        assert fired == ["trip_relay"], "a first-party Tier D action did not fire"
        assert result.tier == ActionTier.SAFETY_CRITICAL


class TestManifestAdmissionLimits:
    """Bound the manifest before parsing it.

    These are file-level admissions — type, size, encoding — taken from a
    single descriptor before any content is parsed. Structural budgets (alias
    rejection, nesting depth, node and collection counts) are enforced during
    parsing and covered below. All of them precede signature verification,
    because the manifest must be consumed to be verified.
    """

    def test_symlinked_manifest_is_refused(self, tmp_path):
        real = _write(tmp_path / "real", _skill_yaml(action_declared_tier="C"))
        skill_dir = tmp_path / "linked"
        skill_dir.mkdir()
        (skill_dir / "skill.yaml").symlink_to(real / "skill.yaml")

        with pytest.raises(SkillSecurityError, match="symlink"):
            _loader().load_one(skill_dir)

    def test_fifo_manifest_is_refused_rather_than_blocking(self, tmp_path):
        """A named pipe must fail startup, not hang it."""
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        os.mkfifo(skill_dir / "skill.yaml")

        with pytest.raises(SkillSecurityError, match="not a regular file"):
            _loader().load_one(skill_dir)

    def test_oversized_manifest_is_refused(self, tmp_path):
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        (skill_dir / "skill.yaml").write_text(
            "# padding\n" + ("x" * (1 << 20)), encoding="utf-8"
        )

        with pytest.raises(SkillValidationError, match="byte limit"):
            _loader().load_one(skill_dir)

    def test_manifest_swapped_at_open_time_is_refused(self, tmp_path, monkeypatch):
        """The file that is inspected must be the file that is read.

        The static symlink and FIFO tests above pass against a check-then-open
        implementation too: `lstat()` sees the hostile file because it is
        already in place. This one puts a regular file there, then swaps it for
        a FIFO at the instant of `os.open`. A `lstat()`-then-`open()` sequence
        validates the regular file and then reads the pipe; deciding from a
        single descriptor refuses it.
        """
        skill_dir = _write(
            tmp_path / "s",
            _skill_yaml(
                action_tier="C",
                action_declared_tier="C",
                safe_default="log_to_dashboard",
            ),
        )
        manifest = skill_dir / "skill.yaml"
        real_open = os.open
        swapped = False

        def _swapping_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if not swapped and str(path) == str(manifest):
                swapped = True
                manifest.unlink()
                os.mkfifo(manifest)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", _swapping_open)

        with pytest.raises(SkillSecurityError, match="not a regular file"):
            _loader().load_one(skill_dir)
        assert swapped, "the swap never happened — the test proved nothing"

    def test_manifest_admission_takes_no_pre_open_stat(self, tmp_path):
        """Admission decisions must come from the descriptor, not the path.

        Pins the structure rather than a symptom: any reintroduced
        ``Path.lstat``/``Path.stat`` pre-check reopens the race the test above
        covers, even if that test still passes for some other reason.
        """
        skill_dir = _write(
            tmp_path / "s",
            _skill_yaml(
                action_tier="C",
                action_declared_tier="C",
                safe_default="log_to_dashboard",
            ),
        )
        manifest = skill_dir / "skill.yaml"
        source = inspect.getsource(SkillLoader._read_manifest_bytes)

        assert "os.fstat(fd)" in source, "file type must be decided from the descriptor"
        assert ".lstat()" not in source and ".stat()" not in source, (
            "a path-based stat before open reintroduces check-then-use"
        )
        # And it still reads the file correctly.
        assert _loader().load_one(skill_dir).name == "hostile-skill"
        assert manifest.is_file()

    def test_manifest_must_be_valid_utf8(self, tmp_path):
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        (skill_dir / "skill.yaml").write_bytes(b"name: \xff\xfe\n")

        with pytest.raises(SkillValidationError, match="not valid UTF-8"):
            _loader().load_one(skill_dir)

    def test_aliases_are_refused(self, tmp_path):
        """Aliases multiply the constructed graph beyond the source size.

        The byte cap bounds the file, not what it expands into: a node can be
        referenced repeatedly, and referencing compounds. Refused outright
        rather than budgeted — a manifest is a declaration, and no bundled
        skill uses an anchor.
        """
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        (skill_dir / "skill.yaml").write_text(
            "base: &base [1, 2, 3]\nname: s\ncopy: *base\n", encoding="utf-8"
        )

        with pytest.raises(SkillValidationError, match="aliases are not permitted"):
            _loader().load_one(skill_dir)

    def test_merge_keys_are_refused(self, tmp_path):
        """`<<:` is an alias by another name and must not slip past."""
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        (skill_dir / "skill.yaml").write_text(
            "defaults: &d\n  tier: A\nname: s\nentry:\n  <<: *d\n", encoding="utf-8"
        )

        with pytest.raises(SkillValidationError, match="aliases are not permitted"):
            _loader().load_one(skill_dir)

    def test_deeply_nested_manifest_is_refused(self, tmp_path):
        """Depth is bounded before the composer's recursion is."""
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        document = "".join("  " * i + f"k{i}:\n" for i in range(64))
        document += "  " * 64 + "v: 1\n"
        (skill_dir / "skill.yaml").write_text(document, encoding="utf-8")

        with pytest.raises(SkillValidationError, match="nesting deeper than"):
            _loader().load_one(skill_dir)

    def test_oversized_collections_are_refused(self, tmp_path):
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        entries = ",".join(str(i) for i in range(2000))
        (skill_dir / "skill.yaml").write_text(
            f"name: s\nvalues: [{entries}]\n", encoding="utf-8"
        )

        with pytest.raises(SkillValidationError, match="more than .* entries"):
            _loader().load_one(skill_dir)

    def test_node_budget_is_enforced(self, tmp_path):
        """A document under the byte cap can still be over the node budget."""
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        # 30 sequences of 900 entries: every collection is individually legal.
        document = "name: s\n"
        for group in range(30):
            document += f"g{group}: [" + ",".join("1" for _ in range(900)) + "]\n"
        assert len(document.encode()) < (1 << 20), "must stay under the byte cap"
        (skill_dir / "skill.yaml").write_text(document, encoding="utf-8")

        with pytest.raises(SkillValidationError, match="more than .* nodes"):
            _loader().load_one(skill_dir)

    def test_limits_apply_before_signature_verification(self, tmp_path):
        """The budget must bind unsigned content, which is the point.

        Parsing precedes verification — the manifest has to be constructed to
        be canonicalised — so a limit that only applied to signed manifests
        would not protect the path that matters.
        """
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        (skill_dir / "skill.yaml").write_text(
            "base: &base [1, 2, 3]\nname: s\ncopy: *base\n", encoding="utf-8"
        )
        loader = SkillLoader()  # real signature verification, no stubbing

        def _must_not_run(raw, sd):  # pragma: no cover - must not be reached
            raise AssertionError("verification ran before admission limits")

        loader._verify_community_signature = _must_not_run  # type: ignore[method-assign]

        with pytest.raises(SkillValidationError, match="aliases are not permitted"):
            loader.load_one(skill_dir)

    def test_packaged_skills_are_within_the_limits(self):
        """Every shipped manifest must load — the budgets bound hostile input."""
        packaged = Path(__file__).resolve().parents[1] / "skills"
        loaded = 0
        for manifest in sorted(packaged.glob("*/skill.yaml")):
            if manifest.parent.name == "template":
                continue
            assert SkillLoader().load_one(manifest.parent) is not None
            loaded += 1
        assert loaded >= 5, f"expected the bundled skills, found {loaded}"

    def test_ordinary_manifest_is_unaffected(self, tmp_path):
        skill_dir = _write(
            tmp_path / "s",
            _skill_yaml(
                action_tier="C",
                action_declared_tier="C",
                safe_default="log_to_dashboard",
            ),
        )
        assert _loader().load_one(skill_dir).name == "hostile-skill"


def _bulk_skill_yaml(
    *, name: str = "bulk-skill", triggers: int = 1, sensors: int = 1
) -> str:
    """A structurally valid manifest with a chosen amount of work in it."""
    sensor_block = "".join(f"  - type: sensor_{i}\n" for i in range(sensors))
    trigger_block = "".join(
        f'  - name: t{i}\n    condition: "value > {i}"\n    action_tier: A\n'
        for i in range(triggers)
    )
    defaults_block = "".join(f"    t{i}: [log_to_dashboard]\n" for i in range(triggers))
    return (
        f"name: {name}\nversion: 1.0.0\nauthor: tester\nsignature: bundled\n"
        f"sensors_required:\n{sensor_block}"
        f"triggers:\n{trigger_block}"
        "actions:\n  available:\n    - name: log_to_dashboard\n      tier: A\n"
        f"  defaults:\n{defaults_block}"
    )


class TestWorkloadBudgets:
    """Syntax limits bound the document; these bound the work it creates.

    Registration produces one EventBus handler per trigger × required sensor
    type, and each schedules a reasoning task on the same loop Tier D safety
    processing runs on. A manifest well inside every parser limit can still ask
    for tens of thousands of subscriptions, so valid structure — and valid
    provenance — does not make a resource-exhausting skill safe.
    """

    def test_excessive_triggers_are_refused(self, tmp_path):
        skill_dir = _write(tmp_path / "s", _bulk_skill_yaml(triggers=200))
        with pytest.raises(SkillValidationError, match="triggers exceeds the limit"):
            _loader().load_one(skill_dir)

    def test_excessive_sensors_are_refused(self, tmp_path):
        skill_dir = _write(tmp_path / "s", _bulk_skill_yaml(sensors=100))
        with pytest.raises(SkillValidationError, match="sensors exceeds"):
            _loader().load_one(skill_dir)

    def test_subscription_product_is_refused_when_each_factor_is_legal(self, tmp_path):
        """The product is the number that matters, not either factor.

        60 triggers and 30 sensors are both individually within their caps and
        together request 1,800 handlers.
        """
        skill_dir = _write(tmp_path / "s", _bulk_skill_yaml(triggers=60, sensors=30))
        with pytest.raises(SkillValidationError, match="would register 1800 handlers"):
            _loader().load_one(skill_dir)

    def test_register_enforces_the_budget_independently(self, tmp_path):
        """`register()` is public and reachable without `load_all()`."""
        skill_dir = _write(tmp_path / "s", _bulk_skill_yaml(triggers=8, sensors=4))
        skill = _loader().load_one(skill_dir)
        # Bypass the load-time check entirely by inflating the loaded object.
        skill.triggers = skill.triggers * 40  # 320 triggers × 4 sensors

        loader = _loader()
        with pytest.raises(SkillValidationError, match="exceeds the limit"):
            loader.register(skill, _RecordingBus())

    def test_register_enforces_the_cumulative_budget_too(self, tmp_path):
        """Repeated legal registrations must not add up past the aggregate.

        Distinct from the per-skill case: every call here is well within the
        256-handler per-skill cap, so only the running total can stop them.
        `register()` keeps that total itself rather than trusting `load_all()`
        to have counted, because it can be called without it.
        """
        skill_dir = _write(tmp_path / "s", _bulk_skill_yaml(triggers=50, sensors=4))
        skill = _loader().load_one(skill_dir)
        assert SkillLoader._subscription_cost(skill) == 200

        loader = _loader()
        bus = _RecordingBus()
        for _ in range(5):  # 1,000 of the 1,024 budget
            loader.register(skill, bus)

        with pytest.raises(SkillValidationError, match="cumulative limit"):
            loader.register(skill, bus)

    def test_cumulative_budget_stops_individually_legal_skills(self, tmp_path):
        """Per-skill caps are a per-file courtesy without an aggregate.

        Each skill here registers 200 handlers — comfortably legal on its own.
        Ten of them would be 2,000, which the event loop would see as one
        number. The load stops accepting once the total is reached.
        """
        root = tmp_path / "skills"
        for index in range(10):
            _write(
                root / f"skill-{index}",
                _bulk_skill_yaml(name=f"bulk-{index}", triggers=50, sensors=4),
            )

        loader = _loader()
        loader._verify_community_signature = lambda raw, sd: None  # type: ignore[method-assign]
        loaded = loader.load_all(str(root))

        total = sum(loader._subscription_cost(skill) for skill in loaded)
        assert total <= 1024, f"cumulative budget exceeded: {total}"
        assert 0 < len(loaded) < 10, (
            f"expected a partial load under the aggregate budget, got {len(loaded)}"
        )

    def test_skill_count_per_load_is_bounded(self, tmp_path):
        root = tmp_path / "skills"
        for index in range(80):
            _write(
                root / f"skill-{index}",
                _bulk_skill_yaml(name=f"tiny-{index}", triggers=1, sensors=1),
            )

        loader = _loader()
        loader._verify_community_signature = lambda raw, sd: None  # type: ignore[method-assign]
        assert len(loader.load_all(str(root))) <= 64

    def test_packaged_skills_are_within_the_budgets(self):
        packaged = Path(__file__).resolve().parents[1] / "skills"
        for manifest in sorted(packaged.glob("*/skill.yaml")):
            if manifest.parent.name == "template":
                continue
            skill = SkillLoader().load_one(manifest.parent)
            assert SkillLoader._subscription_cost(skill) <= 256


class TestSubscriptionBudgetTracksActiveHandlers:
    """The budget counts live subscriptions, not subscriptions ever created.

    A counter that only rises turns every reload into permanent consumption,
    so a long-running runtime exhausts it through ordinary operation — and
    fails to register replacements *after* removing the previous graph, which
    is the worst moment to fail.
    """

    def test_registration_charges_exactly_what_it_registers(self, tmp_path):
        """Cost accounting and registration must agree on duplicated sensors.

        The cost counted unique sensor types while registration created one
        handler per list entry, so a directly constructed skill declaring the
        same sensor repeatedly was charged once and registered many times — the
        budget measuring something other than what it bounds. Duplicate
        subscriptions are also meaningless: two handlers on one sensor type
        fire on the same events.
        """
        skill_dir = _write(tmp_path / "s", _bulk_skill_yaml(triggers=2, sensors=1))
        skill = _loader().load_one(skill_dir)
        # Twenty declarations naming the same two types.
        skill.sensors_required = [{"type": "sensor_0"}, {"type": "sensor_1"}] * 10

        loader = _loader()
        bus = _RecordingBus()
        subscriptions = loader.register(skill, bus)

        cost = SkillLoader._subscription_cost(skill)
        assert cost == 4, f"2 triggers × 2 distinct types, got {cost}"
        assert len(subscriptions) == cost, (
            f"registered {len(subscriptions)} handlers but charged {cost}"
        )
        assert len(bus.subscriptions) == cost
        assert loader.active_subscriptions == cost

    def test_unregister_returns_capacity(self, tmp_path):
        skill_dir = _write(tmp_path / "s", _bulk_skill_yaml(triggers=50, sensors=4))
        skill = _loader().load_one(skill_dir)
        loader = _loader()
        bus = _RecordingBus()

        subscriptions = loader.register(skill, bus)
        assert loader.active_subscriptions == 200

        loader.unregister(subscriptions, bus)
        assert loader.active_subscriptions == 0

    def test_repeated_reload_cycles_do_not_exhaust_the_budget(self, tmp_path):
        """Replacing the same handlers must be sustainable indefinitely.

        Far beyond the point the monotonic counter failed (the budget divided
        by the per-cycle cost), with handler counts and Tier D coverage
        checked at every cycle rather than only at the end.
        """
        packaged = Path(__file__).resolve().parents[1] / "skills"
        skill = SkillLoader().load_one(packaged / "hvac-refrigerant-monitor")
        assert any(t.action_tier == "D" for t in skill.triggers)

        loader = _loader()
        cost = SkillLoader._subscription_cost(skill)
        for cycle in range(200):
            bus = _RecordingBus()
            subscriptions = loader.register(skill, bus)
            assert len(subscriptions) == cost, f"cycle {cycle}: handler count drifted"
            assert len(bus.subscriptions) == cost
            loader.unregister(subscriptions, bus)
            assert loader.active_subscriptions == 0, f"cycle {cycle}: budget leaked"

    # The runtime's own reload path is exercised for real in
    # tests/test_runtime.py::TestSkillReload::
    # test_repeated_reloads_do_not_exhaust_the_subscription_budget — 60 cycles
    # through OriRuntime.reload_skills() past the former exhaustion point. A
    # source grep was here first; it proved the string existed, not that
    # capacity was returned.


class TestCandidateAdmissionIsBounded:
    """The cap must bound work attempted, not work that succeeded.

    Counting successes meant rejected manifests were free: an unlimited number
    of invalid ones could each be driven through file admission, parsing and
    validation before being discarded. The cost is paid either way.
    """

    def test_invalid_candidates_count_against_the_limit(self, tmp_path):
        root = tmp_path / "skills"
        # 300 manifests that all fail validation, and one that would succeed.
        for index in range(300):
            d = root / f"bad-{index:03d}"
            d.mkdir(parents=True)
            (d / "skill.yaml").write_text("name: broken\ntriggers: []\n", "utf-8")

        loader = _loader()
        attempted = []
        real_load_one = loader.load_one

        def _counting_load_one(skill_dir, **kwargs):
            attempted.append(skill_dir)
            return real_load_one(skill_dir, **kwargs)

        loader.load_one = _counting_load_one  # type: ignore[method-assign]
        loader.load_all(str(root))

        assert len(attempted) <= 64, (
            f"{len(attempted)} invalid manifests were parsed; the limit must "
            "bound candidates, not successes"
        )

    def test_directory_scan_is_bounded(self, tmp_path):
        """A directory padded with non-skill entries cannot force a full walk."""
        root = tmp_path / "skills"
        root.mkdir(parents=True)
        for index in range(5000):
            (root / f"noise-{index:05d}").touch()

        candidates = _loader()._discover_candidates(root)
        assert candidates == [] or len(candidates) <= 64


class TestActionWorkloadIsBounded:
    """`actions.defaults` lists are executed, not merely declared.

    The elevator iterates each trigger's list and dispatches every entry, so a
    long list is sequential dispatch work and, for alert actions, message
    volume — all inside the generic collection limit.
    """

    def _skill_with_defaults(self, actions: list[str]) -> str:
        rendered = ", ".join(actions)
        return (
            "name: flood-skill\nversion: 1.0.0\nauthor: tester\nsignature: bundled\n"
            "sensors_required:\n  - type: current_clamp\n"
            'triggers:\n  - name: fire\n    condition: "value > 1"\n'
            "    action_tier: A\n"
            "actions:\n  available:\n    - name: alert_sms\n      tier: A\n"
            "    - name: log_to_dashboard\n      tier: A\n"
            f"  defaults:\n    fire: [{rendered}]\n"
        )

    def test_long_default_action_list_is_refused(self, tmp_path):
        skill_dir = _write(
            tmp_path / "s", self._skill_with_defaults(["alert_sms"] * 1000)
        )
        with pytest.raises(SkillValidationError, match="default actions, above"):
            _loader().load_one(skill_dir)

    def test_duplicate_action_in_one_list_is_refused(self, tmp_path):
        skill_dir = _write(
            tmp_path / "s",
            self._skill_with_defaults(["alert_sms", "log_to_dashboard", "alert_sms"]),
        )
        with pytest.raises(SkillValidationError, match="more than once"):
            _loader().load_one(skill_dir)

    def test_a_reasonable_action_list_still_loads(self, tmp_path):
        skill_dir = _write(
            tmp_path / "s", self._skill_with_defaults(["alert_sms", "log_to_dashboard"])
        )
        assert _loader().load_one(skill_dir).name == "flood-skill"


class TestSkillIdentity:
    """Names are what a physical action is attributed to.

    An action record, a Tier C approval message and an operator's decision all
    identify a skill by name. Two skills answering to one name makes those
    records ambiguous exactly where they matter, and a control character can
    change what an operator reads without changing what was recorded.
    """

    def test_duplicate_names_are_refused(self, tmp_path):
        root = tmp_path / "skills"
        _write(root / "dir-a", _bulk_skill_yaml(name="same-name"))
        _write(root / "dir-b", _bulk_skill_yaml(name="same-name"))

        loader = _loader()
        loader._verify_community_signature = lambda raw, sd: None  # type: ignore[method-assign]
        loaded = loader.load_all(str(root))

        assert len(loaded) == 1, "a duplicate skill name was loaded twice"

    def test_community_skill_cannot_take_a_packaged_name(self, tmp_path):
        skill_dir = _write(
            tmp_path / "impostor", _bulk_skill_yaml(name="energy-anomaly-detector")
        )
        loader = SkillLoader()
        loader._verify_community_signature = lambda raw, sd: None  # type: ignore[method-assign]

        with pytest.raises(SkillSecurityError, match="ships with the runtime"):
            loader.load_one(skill_dir)

    @pytest.mark.parametrize(
        "value",
        ["evil\x1b[2Kname", "two\nlines", "tab\tname", "null\x00byte"],
        ids=["escape", "newline", "tab", "nul"],
    )
    def test_control_characters_in_identity_are_refused(self, tmp_path, value):
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        (skill_dir / "skill.yaml").write_text(
            _bulk_skill_yaml().replace(
                "author: tester", f"author: {json.dumps(value)}"
            ),
            encoding="utf-8",
        )
        with pytest.raises(SkillValidationError, match="must be plain text"):
            _loader().load_one(skill_dir)

    def test_overlong_identity_is_refused(self, tmp_path):
        skill_dir = _write(tmp_path / "s", _bulk_skill_yaml(name="n" * 200))
        with pytest.raises(SkillValidationError, match="above the limit"):
            _loader().load_one(skill_dir)

    @pytest.mark.parametrize(
        "value",
        ["safe‮evil", "join‍er", "line break"],
        ids=["rtl_override", "zero_width_joiner", "line_separator"],
    )
    def test_unicode_display_controls_are_refused(self, tmp_path, value):
        """ASCII C0 is not the whole problem.

        U+202E RIGHT-TO-LEFT OVERRIDE reverses how following text *renders*
        without changing what is stored, so an author string carrying one
        appears in a log or terminal as something other than what was recorded.
        """
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        (skill_dir / "skill.yaml").write_text(
            _bulk_skill_yaml().replace(
                "author: tester", f"author: {json.dumps(value)}"
            ),
            encoding="utf-8",
        )
        with pytest.raises(SkillValidationError, match="must be plain text"):
            _loader().load_one(skill_dir)

    @pytest.mark.parametrize("field_name", ["name", "author", "version"])
    def test_non_string_identity_is_refused(self, tmp_path, field_name):
        """A numeric value bypassed every string check, then reached the logs."""
        skill_dir = tmp_path / "s"
        skill_dir.mkdir()
        document = _bulk_skill_yaml().replace(
            {
                "name": "name: bulk-skill",
                "author": "author: tester",
                "version": "version: 1.0.0",
            }[field_name],
            f"{field_name}: 12345",
        )
        (skill_dir / "skill.yaml").write_text(document, encoding="utf-8")
        with pytest.raises(SkillValidationError, match="must be a string"):
            _loader().load_one(skill_dir)

    def test_packaged_directory_names_match_their_manifest_names(self):
        """The impersonation guard compares directory names, so they must agree.

        The protected set is built from packaged *directory* names. If a
        packaged skill's manifest `name` ever differed from its directory, that
        name would be unprotected and a community skill could claim it.
        """
        packaged = Path(__file__).resolve().parents[1] / "skills"
        checked = 0
        for manifest in sorted(packaged.glob("*/skill.yaml")):
            if manifest.parent.name == "template":
                continue
            skill = SkillLoader().load_one(manifest.parent)
            assert skill.name == manifest.parent.name, (
                f"{manifest.parent.name} declares name {skill.name!r}; the "
                "impersonation guard keys on the directory name and would not "
                "protect it"
            )
            checked += 1
        assert checked >= 5

    def test_name_charset_is_restricted(self, tmp_path):
        skill_dir = _write(tmp_path / "s", _bulk_skill_yaml(name="../escape"))
        with pytest.raises(SkillValidationError, match="must start with"):
            _loader().load_one(skill_dir)


class TestSafeDefaultsCannotActuate:
    def test_physical_safe_default_is_refused_at_load(self, tmp_path):
        skill_dir = _write(
            tmp_path / "s",
            _skill_yaml(
                action_tier="C",
                action_declared_tier="C",
                safe_default="trip_relay",
            ),
        )
        with pytest.raises(SkillValidationError, match="without approval"):
            _loader().load_one(skill_dir)

    def test_dispatcher_substitutes_an_ineligible_safe_default(self):
        dispatcher = ActionDispatcher()
        assert dispatcher._vet_safe_default("trip_relay") == "log_to_dashboard"
        assert dispatcher._vet_safe_default("alert_sms") == "alert_sms"

    async def test_rejected_tier_c_does_not_actuate_via_the_fallback(self):
        """Saying NO must not perform the physical action the operator refused."""
        dispatcher = ActionDispatcher()
        fired = []

        async def _relay(action, ctx):
            fired.append(action)

        dispatcher.register_executor("trip_relay", _relay)
        dispatcher.register_executor("release_relay", _relay)

        result = await dispatcher._approval_workflow(
            "trip_relay",
            ActionTier.HARD_PHYSICAL,
            _context(),
            _result("C"),
            "release_relay",
            0,
        )

        assert fired == [], f"a relay fired as a safe default: {fired}"
        assert result.approved is not True


# ─── Authoritative sensor fields ──────────────────────────────────────────────


class TestSensorFieldsAreAuthoritative:
    @pytest.mark.parametrize("name", sorted(RESERVED_CONTEXT_NAMES))
    async def test_supplied_context_cannot_replace_the_reading(self, name):
        """The rule engine overwrites reserved names with the real reading."""
        engine = RuleEngine()
        rules = [
            {
                "name": "overcurrent",
                "condition": "value > 50",
                "action_tier": "D",
                "bypass_llm": True,
            }
        ]

        # A quiet reading, with context claiming a dangerous one.
        result = await engine.evaluate(
            _event(5.0), rules, context={name: 999.0 if name == "value" else "spoofed"}
        )
        assert result.matched is False, "skill context provoked a Tier D rule"

    async def test_supplied_context_cannot_suppress_a_real_reading(self):
        """The inverse matters just as much: masking a genuine excursion."""
        engine = RuleEngine()
        rules = [
            {
                "name": "overcurrent",
                "condition": "value > 50",
                "action_tier": "D",
                "bypass_llm": True,
            }
        ]

        result = await engine.evaluate(_event(80.0), rules, context={"value": 1.0})
        assert result.matched is True, "skill context suppressed a Tier D rule"

    def test_reserved_names_are_stripped_before_the_rule_engine(self):
        cleaned = _without_reserved_names({"value": 999.0, "threshold": 10.0}, _Skill())
        assert cleaned == {"threshold": 10.0}

    def test_reserved_config_names_are_refused_at_load(self, tmp_path):
        skill_dir = _write(
            tmp_path / "s",
            _skill_yaml(
                action_name="alert_sms",
                action_declared_tier="A",
                config_block="config:\n  value: 999.0\n",
            ),
        )
        with pytest.raises(SkillValidationError, match="reserved for the sensor"):
            _loader().load_one(skill_dir)

    def test_ordinary_config_still_loads(self, tmp_path):
        skill_dir = _write(
            tmp_path / "s",
            _skill_yaml(
                action_name="alert_sms",
                action_declared_tier="A",
                config_block="config:\n  threshold: 10.0\n",
            ),
        )
        skill = _loader().load_one(skill_dir)
        assert skill.config["threshold"] == 10.0
