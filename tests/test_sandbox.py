# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The in-process hook loader is retired, and provenance is positive.

The retired loader could be shown to block `import os` and to clean up its
`sys.meta_path` finder. Both properties were real, and neither made it a
security boundary — the denylisted namespace left the object graph reachable,
and on Python 3.12 the finder was not consulted at all, so it failed open.
Asserting those properties would therefore describe a boundary that was not
one.

What is asserted here instead is the replacement: nothing executes community
hook code in this interpreter, and a skill is trusted only because it ships
with the runtime.
"""

import textwrap
from pathlib import Path

import pytest

from ori.skills.loader import SkillLoader
from ori.skills.os_sandbox import load_community_hooks
from ori.skills.sandbox import SkillSecurityError, load_hooks_restricted

_MINIMAL_SKILL = """\
name: probe-skill
version: 1.0.0
author: tester
signature: bundled
sensors_required:
  - type: temperature
triggers:
  - name: warm
    condition: "value > 30"
    action_tier: A
actions:
  available:
    - name: log_to_dashboard
      tier: A
  defaults:
    warm: [log_to_dashboard]
"""


def _write_skill(skill_dir: Path, *, hooks: str | None = None) -> Path:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "skill.yaml").write_text(_MINIMAL_SKILL, encoding="utf-8")
    if hooks is not None:
        (skill_dir / "hooks.py").write_text(textwrap.dedent(hooks), encoding="utf-8")
    return skill_dir


def test_in_process_loader_refuses_every_path(tmp_path):
    """It refuses regardless of content — there is no allowed hook source."""
    hooks_file = tmp_path / "hooks.py"
    hooks_file.write_text("import math\nresult = math.sqrt(16)\n", encoding="utf-8")
    with pytest.raises(SkillSecurityError, match="in-process execution"):
        load_hooks_restricted(str(hooks_file))


def test_in_process_loader_refuses_before_reading_the_file(tmp_path):
    """A path that does not exist must still refuse, not return None.

    The old loader returned None for a missing file. Anything that treats
    "no hooks" and "hooks refused" as the same outcome would let a caller
    silently continue past the refusal.
    """
    with pytest.raises(SkillSecurityError):
        load_hooks_restricted(str(tmp_path / "absent.py"))


def test_community_hooks_never_fall_back_in_process(tmp_path):
    """With the OS sandbox disabled there is no fallback, only refusal."""
    hooks_file = _write_skill(tmp_path / "community", hooks="x = 1\n") / "hooks.py"
    with pytest.raises(SkillSecurityError, match="no in-process fallback"):
        load_community_hooks(
            hooks_path=hooks_file,
            state_store=None,
            skill_name="community",
            os_sandbox_config={"enabled": False},
        )


def test_community_hooks_refuse_on_a_fully_supported_host(tmp_path, monkeypatch):
    """Even where kernel isolation is available, no runner is produced.

    Exhaustive configuration coverage lives in ``test_os_sandbox.py``; this
    pins the case that would otherwise be the quiet exception — a supported
    Linux host, isolation enabled, which is the normal production shape.
    """

    class _Supported:
        supported = True
        reason = "ok"

    monkeypatch.setattr(
        "ori.skills.os_sandbox.probe_os_sandbox_support", lambda: _Supported()
    )
    hooks_file = _write_skill(tmp_path / "community", hooks="x = 1\n") / "hooks.py"
    with pytest.raises(SkillSecurityError, match="disabled in this release"):
        load_community_hooks(
            hooks_path=hooks_file,
            state_store=None,
            skill_name="community",
            os_sandbox_config={"enabled": True, "require_for_community": False},
        )


def _loader_without_signature_check() -> SkillLoader:
    """A loader with signature verification stubbed out.

    The hook boundary is tested on its own so that it is proven to hold by
    itself. In a real load the signature layer refuses first — which
    ``test_community_skill_is_refused_by_signature_layer_alone`` covers — but a
    boundary that only works because something upstream also works is not a
    boundary.
    """
    loader = SkillLoader()
    loader._verify_community_signature = lambda raw, skill_dir: None  # type: ignore[method-assign]
    return loader


def test_community_skill_is_refused_by_signature_layer_alone(tmp_path):
    """Signature verification refuses non-first-party skills on its own."""
    skill_dir = _write_skill(tmp_path / "community")
    with pytest.raises(SkillSecurityError, match="bundled signature sentinel"):
        SkillLoader().load_one(skill_dir)


def test_non_core_skill_with_hooks_is_refused_entirely(tmp_path):
    """A community skill carrying hooks.py does not load at all.

    Loading it without its hooks would activate a skill whose conditions
    reference derived values that will never be produced.
    """
    skill_dir = _write_skill(tmp_path / "community", hooks="MARKER = 1\n")
    with pytest.raises(SkillSecurityError, match="not first-party"):
        _loader_without_signature_check().load_one(skill_dir)


def test_non_core_skill_hooks_are_not_executed_on_refusal(tmp_path):
    """The refusal happens before the file is executed, not after."""
    sentinel = tmp_path / "executed.marker"
    skill_dir = _write_skill(
        tmp_path / "community",
        hooks=f"""\
        from pathlib import Path
        Path({str(sentinel)!r}).write_text("executed")
        """,
    )
    with pytest.raises(SkillSecurityError):
        _loader_without_signature_check().load_one(skill_dir)
    assert not sentinel.exists(), "community hooks.py was executed despite refusal"


def test_community_skill_without_hooks_still_reaches_the_hook_boundary(tmp_path):
    """A YAML-only community skill is not blocked by the hook rule itself."""
    skill_dir = _write_skill(tmp_path / "community")
    skill = _loader_without_signature_check().load_one(skill_dir)
    assert skill.hooks is None


def test_provenance_is_not_decided_by_path_negation(tmp_path):
    """A skill outside ~/.ori/skills is community, not bundled.

    The previous predicate treated everything not under ~/.ori/skills as
    first-party — including the operator-managed directory beside ori.yaml,
    temporary paths and removable media.
    """
    loader = SkillLoader()
    assert loader._is_core_bundled_skill(tmp_path / "anywhere") is False
    assert loader._is_core_bundled_skill(Path("/opt/ori/data/skills/x")) is False


def test_packaged_skills_are_recognised_as_first_party():
    """The positive case still holds: shipped skills are first-party."""
    loader = SkillLoader()
    packaged = Path(__file__).resolve().parents[1] / "skills" / "pc-system-health"
    assert loader._is_core_bundled_skill(packaged) is True


def test_validate_one_does_not_execute_hooks(tmp_path):
    """Inspecting a skill must never run it — even a first-party one.

    Provenance is injected rather than obtained by writing into the packaged
    ``skills/`` tree: a test that creates files inside the source checkout
    leaves them behind if it is interrupted or run in parallel.
    """
    sentinel = tmp_path / "executed.marker"
    skill_dir = _write_skill(
        tmp_path / "packaged-probe",
        hooks=f"""\
        from pathlib import Path
        Path({str(sentinel)!r}).write_text("executed")
        """,
    )
    loader = SkillLoader()
    loader._is_core_bundled_skill = lambda candidate: True  # type: ignore[method-assign]

    skill = loader.validate_one(skill_dir)

    assert skill.name == "probe-skill"
    assert skill.hooks is None
    assert not sentinel.exists(), "validate_one executed hooks.py"


def test_validate_matches_activation_for_community_hooks(tmp_path):
    """Validation must reach the same verdict the runtime will.

    Validation previously skipped the hook policy entirely, so it approved
    skills the runtime then refused to activate — the disagreement showing up
    at precisely the moment someone was deciding whether a skill was safe.
    """
    skill_dir = _write_skill(tmp_path / "community", hooks="MARKER = 1\n")
    loader = _loader_without_signature_check()

    with pytest.raises(SkillSecurityError, match="not first-party"):
        loader.validate_one(skill_dir)
    with pytest.raises(SkillSecurityError, match="not first-party"):
        loader.load_one(skill_dir)


def test_inspect_one_reports_metadata_without_the_activation_policy(tmp_path):
    """Listing still describes a skill the runtime will not activate."""
    sentinel = tmp_path / "executed.marker"
    skill_dir = _write_skill(
        tmp_path / "community",
        hooks=f"""\
        from pathlib import Path
        Path({str(sentinel)!r}).write_text("executed")
        """,
    )
    skill = _loader_without_signature_check().inspect_one(skill_dir)

    assert skill.name == "probe-skill"
    assert skill.hooks is None
    assert not sentinel.exists(), "inspect_one executed hooks.py"
