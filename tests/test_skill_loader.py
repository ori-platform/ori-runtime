# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import base64
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading
from ori.skills.loader import (
    Skill,
    SkillLoader,
    SkillValidationError,
    Trigger,
    _CooldownTracker,
)
from ori.skills.sandbox import SkillSecurityError
from ori.skills.signing import canonical_skill_payload

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except Exception:  # pragma: no cover - environment without cryptography support
    Ed25519PrivateKey = None
    Encoding = None
    PublicFormat = None

# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _write_skill_yaml(skill_dir: Path, content: str) -> None:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "skill.yaml").write_text(textwrap.dedent(content))


def _write_skill_yaml_mapping(skill_dir: Path, content: dict) -> None:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "skill.yaml").write_text(
        yaml.safe_dump(content, sort_keys=False),
        encoding="utf-8",
    )


def _minimal_yaml(
    name: str = "test-skill",
    action_tier: str = "A",
    bypass_llm: bool | None = None,
    safe_default: str | None = None,
) -> str:
    # 12 spaces keeps indentation correct after textwrap.dedent strips 8 spaces
    bypass_line = (
        f"\n            bypass_llm: {str(bypass_llm).lower()}"
        if bypass_llm is not None
        else ""
    )
    safe_line = (
        f"\n            safe_default_action: {safe_default}" if safe_default else ""
    )
    return f"""\
        name: {name}
        version: 0.1.0
        author: test
        sensors_required:
          - type: current_clamp
            protocol: i2c
        triggers:
          - name: over_threshold
            condition: "value > 5.0"
            cooldown_seconds: 10
            action_tier: {action_tier}{bypass_line}{safe_line}
        actions:
          available:
            - name: alert_whatsapp
              tier: A
          defaults:
            over_threshold: [alert_whatsapp]
    """


def _make_event(sensor_type: str = "current_clamp", value: float = 6.0) -> OriEvent:
    reading = SensorReading(
        sensor_id="load-current",
        sensor_type=sensor_type,
        value=value,
        unit="ampere",
        timestamp=1_000_000,
        quality=1.0,
    )
    return OriEvent.from_reading(reading, "dev-01")


def _community_skill_mapping(name: str = "community-skill") -> dict:
    return {
        "name": name,
        "version": "0.1.0",
        "author": "community-author",
        "sensors_required": [{"type": "current_clamp", "protocol": "i2c"}],
        "triggers": [
            {
                "name": "over_threshold",
                "condition": "value > 5.0",
                "cooldown_seconds": 10,
                "action_tier": "A",
            }
        ],
        "actions": {
            "available": [{"name": "alert_whatsapp", "tier": "A"}],
            "defaults": {"over_threshold": ["alert_whatsapp"]},
        },
    }


def _sign_skill(raw_skill: dict, private_key: Ed25519PrivateKey) -> str:  # type: ignore
    payload = canonical_skill_payload(raw_skill)
    signature = private_key.sign(payload)
    return "ed25519:" + base64.b64encode(signature).decode("ascii")


# ─── Trigger dataclass ────────────────────────────────────────────────────────


class TestTrigger:
    def test_defaults(self):
        t = Trigger(name="t", condition="x > 1", action_tier="A")
        assert t.cooldown_seconds == 0
        assert t.escalate_to == "local_slm"
        assert t.bypass_llm is False
        assert t.approval_timeout_seconds == 300
        assert t.safe_default_action == "log_to_dashboard"

    def test_required_fields(self):
        t = Trigger(name="n", condition="c", action_tier="D")
        assert t.action_tier == "D"


# ─── Skill.get_default_actions ────────────────────────────────────────────────


class TestSkillGetDefaultActions:
    def _skill_with_defaults(self) -> Skill:
        return Skill(
            name="s",
            version="0.1.0",
            author="a",
            sensors_required=[{"type": "current_clamp", "protocol": "i2c"}],
            triggers=[Trigger(name="over_threshold", condition="x>1", action_tier="A")],
            actions={
                "defaults": {"over_threshold": ["alert_whatsapp", "log_to_dashboard"]}
            },
        )

    def test_returns_actions_for_matching_sensor(self):
        skill = self._skill_with_defaults()
        actions = skill.get_default_actions("current_clamp")
        assert actions == ["alert_whatsapp", "log_to_dashboard"]

    def test_returns_empty_for_unknown_sensor(self):
        skill = self._skill_with_defaults()
        assert skill.get_default_actions("voltage") == []

    def test_returns_empty_when_no_defaults_configured(self):
        skill = Skill(
            name="s",
            version="0.1.0",
            author="a",
            sensors_required=[{"type": "current_clamp"}],
            triggers=[Trigger(name="t", condition="x>1", action_tier="A")],
            actions={},
        )
        assert skill.get_default_actions("current_clamp") == []


# ─── _CooldownTracker ────────────────────────────────────────────────────────


class TestCooldownTracker:
    def test_first_call_always_allowed(self):
        tracker = _CooldownTracker()
        assert tracker.can_fire("t", cooldown_seconds=60) is True

    def test_fires_immediately_after_record(self):
        tracker = _CooldownTracker()
        tracker.record_fire("t")
        assert tracker.can_fire("t", cooldown_seconds=60) is False

    def test_fires_after_cooldown_expires(self):
        tracker = _CooldownTracker()
        tracker.record_fire("t")
        # Manually backdate the last_fired time
        tracker._last_fired["t"] -= 61
        assert tracker.can_fire("t", cooldown_seconds=60) is True

    def test_zero_cooldown_always_fires(self):
        tracker = _CooldownTracker()
        tracker.record_fire("t")
        assert tracker.can_fire("t", cooldown_seconds=0) is True

    def test_independent_triggers(self):
        tracker = _CooldownTracker()
        tracker.record_fire("trigger_a")
        assert tracker.can_fire("trigger_b", cooldown_seconds=60) is True


# ─── SkillLoader.load_one ─────────────────────────────────────────────────────


class TestLoadOne:
    def test_loads_valid_skill(self, tmp_path):
        skill_dir = tmp_path / "my-skill"
        _write_skill_yaml(skill_dir, _minimal_yaml())
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.name == "test-skill"
        assert skill.version == "0.1.0"
        assert len(skill.triggers) == 1
        assert skill.triggers[0].name == "over_threshold"

    def test_trigger_action_tier_parsed(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml(action_tier="B"))
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.triggers[0].action_tier == "B"

    def test_tier_d_forces_bypass_llm_true(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml(action_tier="D"))
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.triggers[0].bypass_llm is True

    def test_tier_d_bypass_llm_already_true_is_fine(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml(action_tier="D", bypass_llm=True))
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.triggers[0].bypass_llm is True

    def test_sensors_required_parsed(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.sensors_required == [{"type": "current_clamp", "protocol": "i2c"}]

    def test_actions_defaults_parsed(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.actions["defaults"]["over_threshold"] == ["alert_whatsapp"]

    def test_hooks_none_when_no_hooks_file(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.hooks is None

    def test_hooks_loaded_when_present(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())
        (skill_dir / "hooks.py").write_text("LOADED = True\n")
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.hooks is not None
        assert skill.hooks.LOADED is True

    def test_hooks_none_when_hooks_has_syntax_error(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())
        (skill_dir / "hooks.py").write_text("def bad(:\n")
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)  # must not raise
        assert skill.hooks is None

    def test_raises_file_not_found_when_no_yaml(self, tmp_path):
        skill_dir = tmp_path / "empty"
        skill_dir.mkdir()
        loader = SkillLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_one(skill_dir)

    @pytest.mark.skipif(
        Ed25519PrivateKey is None,
        reason="cryptography ed25519 is unavailable",
    )
    def test_loads_valid_signed_community_skill(self, tmp_path, monkeypatch):
        skill_dir = tmp_path / "community-valid"
        raw = _community_skill_mapping()
        private_key = Ed25519PrivateKey.generate()
        public_key_b64 = base64.b64encode(
            private_key.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
        ).decode("ascii")
        raw["signature"] = _sign_skill(raw, private_key)
        _write_skill_yaml_mapping(skill_dir, raw)

        monkeypatch.setattr(
            "ori.skills.loader._HUB_ROOT_PUBLIC_KEY_B64",
            public_key_b64,
        )
        loader = SkillLoader()
        with patch.object(loader, "_is_bundled_skill", return_value=False):
            skill = loader.load_one(skill_dir)
        assert skill.name == raw["name"]

    @pytest.mark.skipif(
        Ed25519PrivateKey is None,
        reason="cryptography ed25519 is unavailable",
    )
    def test_rejects_tampered_community_skill(self, tmp_path, monkeypatch):
        skill_dir = tmp_path / "community-tampered"
        raw = _community_skill_mapping()
        private_key = Ed25519PrivateKey.generate()
        public_key_b64 = base64.b64encode(
            private_key.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
        ).decode("ascii")
        raw["signature"] = _sign_skill(raw, private_key)
        raw["version"] = "0.2.0"  # tamper after signature
        _write_skill_yaml_mapping(skill_dir, raw)

        monkeypatch.setattr(
            "ori.skills.loader._HUB_ROOT_PUBLIC_KEY_B64",
            public_key_b64,
        )
        loader = SkillLoader()
        with patch.object(loader, "_is_bundled_skill", return_value=False):
            with pytest.raises(
                SkillSecurityError,
                match="signature verification failed",
            ):
                loader.load_one(skill_dir)

    def test_rejects_missing_community_signature(self, tmp_path, monkeypatch):
        skill_dir = tmp_path / "community-missing-signature"
        raw = _community_skill_mapping()
        _write_skill_yaml_mapping(skill_dir, raw)
        monkeypatch.setattr(
            "ori.skills.loader._HUB_ROOT_PUBLIC_KEY_B64",
            "dGVzdA==",
        )
        loader = SkillLoader()
        with patch.object(loader, "_is_bundled_skill", return_value=False):
            with pytest.raises(
                SkillSecurityError,
                match="missing required 'signature' field",
            ):
                loader.load_one(skill_dir)

    def test_rejects_invalid_signature_scheme(self, tmp_path, monkeypatch):
        skill_dir = tmp_path / "community-invalid-scheme"
        raw = _community_skill_mapping()
        raw["signature"] = "rsa:abc"
        _write_skill_yaml_mapping(skill_dir, raw)
        monkeypatch.setattr(
            "ori.skills.loader._HUB_ROOT_PUBLIC_KEY_B64",
            "dGVzdA==",
        )
        loader = SkillLoader()
        with patch.object(loader, "_is_bundled_skill", return_value=False):
            with pytest.raises(
                SkillSecurityError,
                match="unsupported signature scheme",
            ):
                loader.load_one(skill_dir)

    def test_bundled_unsigned_skill_still_loads(self, tmp_path):
        skill_dir = tmp_path / "bundled-unsigned"
        _write_skill_yaml(skill_dir, _minimal_yaml(name="bundled-unsigned"))
        loader = SkillLoader()
        with patch.object(loader, "_is_bundled_skill", return_value=True):
            skill = loader.load_one(skill_dir)
        assert skill.name == "bundled-unsigned"


# ─── SkillLoader validation ───────────────────────────────────────────────────


class TestValidation:
    def test_history_placeholders_above_limit_raise(self, tmp_path):
        placeholders = " ".join(
            [f"{{history.last_n('load-current', {i})}}" for i in range(1, 18)]
        )
        yaml_content = f"""\
            name: too-many-history-placeholders
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: over_threshold
                condition: "value > 5"
                action_tier: A
            prompts:
              over_threshold: "{placeholders}"
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                over_threshold: [alert_whatsapp]
        """
        skill_dir = tmp_path / "too-many-history-placeholders"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(
            SkillValidationError,
            match="contains 17 history placeholders; maximum allowed is 16",
        ):
            loader.load_one(skill_dir)

    def test_history_placeholders_at_limit_loads(self, tmp_path):
        placeholders = " ".join(
            [f"{{history.last_n('load-current', {i})}}" for i in range(1, 17)]
        )
        yaml_content = f"""\
            name: max-history-placeholders
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: over_threshold
                condition: "value > 5"
                action_tier: A
            prompts:
              over_threshold: "{placeholders}"
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                over_threshold: [alert_whatsapp]
        """
        skill_dir = tmp_path / "max-history-placeholders"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.name == "max-history-placeholders"

    def test_missing_action_tier_raises(self, tmp_path):
        yaml_content = """\
            name: bad-skill
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: no_tier
                condition: "value > 5"
                cooldown_seconds: 0
        """
        skill_dir = tmp_path / "bad"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(
            SkillValidationError, match="missing required field 'action_tier'"
        ):
            loader.load_one(skill_dir)

    def test_invalid_action_tier_raises(self, tmp_path):
        yaml_content = """\
            name: bad-skill
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: bad_tier
                condition: "value > 5"
                action_tier: Z
        """
        skill_dir = tmp_path / "bad"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(SkillValidationError, match="invalid action_tier"):
            loader.load_one(skill_dir)

    def test_bypass_llm_without_tier_d_raises(self, tmp_path):
        skill_dir = tmp_path / "bad"
        _write_skill_yaml(skill_dir, _minimal_yaml(action_tier="A", bypass_llm=True))
        loader = SkillLoader()
        with pytest.raises(
            SkillValidationError, match="bypass_llm is reserved for Tier D"
        ):
            loader.load_one(skill_dir)

    def test_tier_c_without_safe_default_raises(self, tmp_path):
        yaml_content = """\
            name: c-skill
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: hard_physical
                condition: "value > 10"
                action_tier: C
                safe_default_action: ""
        """
        skill_dir = tmp_path / "c"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(SkillValidationError, match="safe_default_action"):
            loader.load_one(skill_dir)

    def test_tier_c_with_safe_default_is_valid(self, tmp_path):
        skill_dir = tmp_path / "c"
        _write_skill_yaml(
            skill_dir, _minimal_yaml(action_tier="C", safe_default="log_to_dashboard")
        )
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        assert skill.triggers[0].action_tier == "C"
        assert skill.triggers[0].safe_default_action == "log_to_dashboard"

    def test_missing_name_raises(self, tmp_path):
        yaml_content = """\
            version: 0.1.0
            author: test
            triggers:
              - name: t1
                condition: "value > 5"
                action_tier: A
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                t1: [alert_whatsapp]
        """
        skill_dir = tmp_path / "bad-meta"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(SkillValidationError, match="missing required field 'name'"):
            loader.load_one(skill_dir)

    def test_empty_trigger_name_raises(self, tmp_path):
        yaml_content = """\
            name: bad-trigger
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: "   "
                condition: "value > 5"
                action_tier: A
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                bad_trigger: [alert_whatsapp]
        """
        skill_dir = tmp_path / "bad-trigger"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(SkillValidationError, match="missing/empty name"):
            loader.load_one(skill_dir)

    def test_trigger_name_with_space_raises(self, tmp_path):
        yaml_content = """\
            name: bad-trigger
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: "bad trigger"
                condition: "value > 5"
                action_tier: A
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                bad trigger: [alert_whatsapp]
        """
        skill_dir = tmp_path / "bad-trigger-space"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(SkillValidationError, match="invalid name format"):
            loader.load_one(skill_dir)

    def test_duplicate_trigger_names_raise(self, tmp_path):
        yaml_content = """\
            name: dup-trigger
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: overcurrent
                condition: "value > 5"
                action_tier: A
              - name: overcurrent
                condition: "value > 10"
                action_tier: C
                safe_default_action: log_to_dashboard
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
                - name: log_to_dashboard
                  tier: A
              defaults:
                overcurrent: [alert_whatsapp]
        """
        skill_dir = tmp_path / "dup-trigger"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(SkillValidationError, match="duplicate trigger name"):
            loader.load_one(skill_dir)

    def test_empty_triggers_raises(self, tmp_path):
        yaml_content = """\
            name: bad
            version: 0.1.0
            author: test
            triggers: []
            actions: {}
        """
        skill_dir = tmp_path / "bad-meta"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(
            SkillValidationError, match="triggers must be a non-empty list"
        ):
            loader.load_one(skill_dir)

    def test_missing_defaults_mapping_for_trigger_raises(self, tmp_path):
        yaml_content = """\
            name: bad-defaults
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: t1
                condition: "value > 5"
                action_tier: A
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults: {}
        """
        skill_dir = tmp_path / "bad-defaults"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(
            SkillValidationError, match="missing actions.defaults mapping"
        ):
            loader.load_one(skill_dir)

    def test_extra_defaults_key_without_trigger_raises(self, tmp_path):
        yaml_content = """\
            name: bad-defaults
            version: 0.1.0
            author: test
            sensors_required:
              - type: current_clamp
            triggers:
              - name: t1
                condition: "value > 5"
                action_tier: A
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                t1: [alert_whatsapp]
                t2: [alert_whatsapp]
        """
        skill_dir = tmp_path / "bad-defaults"
        _write_skill_yaml(skill_dir, yaml_content)
        loader = SkillLoader()
        with pytest.raises(SkillValidationError, match="unknown trigger"):
            loader.load_one(skill_dir)


# ─── SkillLoader.load_all ────────────────────────────────────────────────────


class TestLoadAll:
    def test_loads_multiple_skills(self, tmp_path):
        _write_skill_yaml(tmp_path / "skill-a", _minimal_yaml(name="skill-a"))
        _write_skill_yaml(tmp_path / "skill-b", _minimal_yaml(name="skill-b"))
        loader = SkillLoader()
        skills = loader.load_all(str(tmp_path))
        assert len(skills) == 2
        names = {s.name for s in skills}
        assert names == {"skill-a", "skill-b"}

    def test_skips_directories_without_skill_yaml(self, tmp_path):
        _write_skill_yaml(tmp_path / "good-skill", _minimal_yaml())
        (tmp_path / "no-yaml-here").mkdir()
        loader = SkillLoader()
        skills = loader.load_all(str(tmp_path))
        assert len(skills) == 1

    def test_bad_skill_skipped_does_not_abort(self, tmp_path):
        _write_skill_yaml(tmp_path / "good-skill", _minimal_yaml())
        # Skill with missing action_tier — will fail validation
        bad_yaml = """\
            name: bad
            version: 0.1.0
            author: x
            triggers:
              - name: t
                condition: "x > 1"
        """
        _write_skill_yaml(tmp_path / "bad-skill", bad_yaml)
        loader = SkillLoader()
        skills = loader.load_all(str(tmp_path))
        assert len(skills) == 1
        assert skills[0].name == "test-skill"

    def test_returns_empty_for_nonexistent_dir(self, tmp_path):
        loader = SkillLoader()
        skills = loader.load_all(str(tmp_path / "does-not-exist"))
        assert skills == []

    def test_returns_empty_when_no_skills_present(self, tmp_path):
        (tmp_path / "readme.txt").write_text("nothing here")
        loader = SkillLoader()
        skills = loader.load_all(str(tmp_path))
        assert skills == []

    def test_template_directory_is_skipped(self, tmp_path):
        _write_skill_yaml(tmp_path / "template", _minimal_yaml(name="template"))
        _write_skill_yaml(tmp_path / "real-skill", _minimal_yaml(name="real-skill"))
        loader = SkillLoader()
        skills = loader.load_all(str(tmp_path))
        names = {s.name for s in skills}
        assert "real-skill" in names
        assert "template" not in names

    def test_security_failed_skill_is_skipped(self, tmp_path):
        _write_skill_yaml(tmp_path / "good-skill", _minimal_yaml(name="good-skill"))
        _write_skill_yaml(
            tmp_path / "bad-community-skill",
            _minimal_yaml(name="bad-community-skill"),
        )
        loader = SkillLoader()
        original_load_one = loader.load_one

        def _fake_load_one(path):
            if Path(path).name == "bad-community-skill":
                raise SkillSecurityError("signature verification failed")
            return original_load_one(path)

        with patch.object(loader, "load_one", side_effect=_fake_load_one):
            skills = loader.load_all(str(tmp_path))

        assert len(skills) == 1
        assert skills[0].name == "good-skill"


# ─── SkillLoader.register — EventBus handler ─────────────────────────────────


class TestRegister:
    async def test_handler_subscribed_for_each_sensor_type(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())
        loader = SkillLoader()
        skill = loader.load_one(skill_dir)
        bus = EventBus()
        loader.register(skill, bus)
        # One trigger × one sensor_type → one handler
        assert bus.subscriber_count("current_clamp") == 1

    async def test_handler_fires_create_task_when_elevator_present(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())

        mock_elevator = MagicMock()
        mock_elevator.reason_and_dispatch = AsyncMock(return_value=None)

        loader = SkillLoader(elevator=mock_elevator)
        skill = loader.load_one(skill_dir)
        bus = EventBus()
        loader.register(skill, bus)

        event = _make_event()

        # patch asyncio.create_task to capture the coroutine
        created_coros = []

        def fake_create_task(coro, **_kwargs):
            created_coros.append(coro)
            # Schedule it so it actually runs
            return asyncio.ensure_future(coro)

        with patch(
            "ori.skills.loader.asyncio.create_task", side_effect=fake_create_task
        ):
            await bus.publish(event)
            # Flush tasks
            await asyncio.sleep(0)

        assert len(created_coros) == 1
        mock_elevator.reason_and_dispatch.assert_awaited_once()

    async def test_handler_respects_cooldown(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())

        mock_elevator = MagicMock()
        mock_elevator.reason_and_dispatch = AsyncMock(return_value=None)

        loader = SkillLoader(elevator=mock_elevator)
        skill = loader.load_one(skill_dir)
        bus = EventBus()
        loader.register(skill, bus)

        event = _make_event()

        task_calls = []

        def fake_create_task(coro, **_kwargs):
            task_calls.append(coro)
            return asyncio.ensure_future(coro)

        with patch(
            "ori.skills.loader.asyncio.create_task", side_effect=fake_create_task
        ):
            await bus.publish(event)  # first — fires
            await bus.publish(event)  # second — blocked by cooldown (10s)
            await asyncio.sleep(0)

        # Only one task should have been created
        assert len(task_calls) == 1

    async def test_handler_no_elevator_does_not_raise(self, tmp_path):
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())
        loader = SkillLoader(elevator=None)
        skill = loader.load_one(skill_dir)
        bus = EventBus()
        loader.register(skill, bus)
        # Must not raise even without an elevator
        await bus.publish(_make_event())

    async def test_handler_returns_immediately(self, tmp_path):
        """Handler must return before the background task completes."""
        skill_dir = tmp_path / "s"
        _write_skill_yaml(skill_dir, _minimal_yaml())

        finished_order: list[str] = []

        async def slow_reason(*args, **kwargs):
            await asyncio.sleep(0.05)
            finished_order.append("reason_done")

        mock_elevator = MagicMock()
        mock_elevator.reason_and_dispatch = slow_reason

        loader = SkillLoader(elevator=mock_elevator)
        skill = loader.load_one(skill_dir)
        bus = EventBus()
        loader.register(skill, bus)

        await bus.publish(_make_event())
        finished_order.append("publish_returned")

        # publish_returned must appear before reason_done
        assert finished_order == ["publish_returned"]

        # Clean up the background task
        await asyncio.sleep(0.1)


# ─── Integration: load_all + register ────────────────────────────────────────


class TestIntegration:
    async def test_pc_system_health_loads_and_registers(self):
        """Load the real pc-system-health skill and register it."""
        skills_root = Path(__file__).parent.parent / "skills"
        if not (skills_root / "pc-system-health" / "skill.yaml").exists():
            pytest.skip("skills directory not present")

        mock_elevator = MagicMock()
        mock_elevator.reason_and_dispatch = AsyncMock(return_value=None)

        loader = SkillLoader(elevator=mock_elevator)
        skills = loader.load_all(str(skills_root))
        assert any(s.name == "pc-system-health" for s in skills)

        bus = EventBus()
        for skill in skills:
            loader.register(skill, bus)

        # EventBus should have handlers for cpu_percent (first sensor type)
        assert bus.subscriber_count("cpu_percent") >= 1
