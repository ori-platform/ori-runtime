# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json
import textwrap
from pathlib import Path

import pytest

from ori.cli import EXIT_FAILED, EXIT_OK, EXIT_UNUSABLE, main
from ori.skills.loader import (
    _ACTION_ALLOWED_KEYS,
    _TRIGGER_ALLOWED_KEYS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _a_key_outside(allowed: frozenset[str]) -> str:
    """Return a key string that is definitely not in *allowed*."""
    candidate = "unknown_key"
    while candidate in allowed:
        candidate = "_" + candidate
    return candidate


_UNKNOWN_TRIGGER_KEY = _a_key_outside(_TRIGGER_ALLOWED_KEYS)
_UNKNOWN_ACTION_KEY = _a_key_outside(_ACTION_ALLOWED_KEYS)


def _write_valid_skill(skill_dir: Path, name: str = "my-skill") -> None:
    """Write a minimal, first-party-signed skill.yaml to *skill_dir*.

    ``signature: bundled`` is accepted only for skills inside a first-party
    root.  Tests that exercise the signed community-skill path must NOT use
    this helper and must NOT monkeypatch ``_is_core_bundled_skill``.
    """
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent(
            f"""\
            name: {name}
            version: 0.1.0
            author: test
            signature: bundled
            sensors_required:
              - type: current_clamp
                protocol: i2c
            triggers:
              - name: over_threshold
                condition: "value > 5.0"
                action_tier: A
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                over_threshold: [alert_whatsapp]
            """
        ),
        encoding="utf-8",
    )


def _write_skill_with_bad_trigger_key(skill_dir: Path, bad_key: str) -> None:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent(
            f"""\
            name: my-skill
            version: 0.1.0
            author: test
            signature: bundled
            sensors_required:
              - type: current_clamp
                protocol: i2c
            triggers:
              - name: over_threshold
                condition: "value > 5.0"
                action_tier: A
                {bad_key}: true
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                over_threshold: [alert_whatsapp]
            """
        ),
        encoding="utf-8",
    )


def _write_skill_with_bad_action_key(skill_dir: Path, bad_key: str) -> None:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent(
            f"""\
            name: my-skill
            version: 0.1.0
            author: test
            signature: bundled
            sensors_required:
              - type: current_clamp
                protocol: i2c
            triggers:
              - name: over_threshold
                condition: "value > 5.0"
                action_tier: A
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
                  {bad_key}: false
              defaults:
                over_threshold: [alert_whatsapp]
            """
        ),
        encoding="utf-8",
    )


def _assert_no_traceback(captured) -> None:
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


def _read_json(captured) -> dict:
    """Parse stdout as a JSON document; assert it is the only content there."""
    doc = json.loads(captured.out)
    assert isinstance(doc, dict)
    return doc


# ---------------------------------------------------------------------------
# Single-skill — valid
# ---------------------------------------------------------------------------


def test_valid_skill_exits_ok(tmp_path: Path, monkeypatch, capsys) -> None:
    """A valid first-party skill exits 0 with no traceback."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    skill_dir = tmp_path / "my-skill"
    _write_valid_skill(skill_dir)

    rc = main(["skills", "validate", str(skill_dir)])

    captured = capsys.readouterr()
    assert rc == EXIT_OK
    _assert_no_traceback(captured)


def test_valid_skill_json(tmp_path: Path, monkeypatch, capsys) -> None:
    """--json emits exactly one JSON document with status 'valid'."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    skill_dir = tmp_path / "my-skill"
    _write_valid_skill(skill_dir)

    rc = main(["skills", "validate", str(skill_dir), "--json"])

    captured = capsys.readouterr()
    assert rc == EXIT_OK
    doc = _read_json(captured)
    assert doc["status"] == "valid"
    assert doc["name"] == "my-skill"
    _assert_no_traceback(captured)


# ---------------------------------------------------------------------------
# Single-skill — unknown trigger keys (three cases per the review)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_key",
    [
        _UNKNOWN_TRIGGER_KEY,
        "Requires_Approval",
        "requiresApproval",
    ],
)
def test_unknown_trigger_key_exits_failed(
    tmp_path: Path, bad_key: str, monkeypatch, capsys
) -> None:
    """An unrecognised trigger key exits 1 with no traceback."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    skill_dir = tmp_path / "my-skill"
    _write_skill_with_bad_trigger_key(skill_dir, bad_key)

    rc = main(["skills", "validate", str(skill_dir)])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    _assert_no_traceback(captured)


@pytest.mark.parametrize(
    "bad_key",
    [
        _UNKNOWN_TRIGGER_KEY,
        "Requires_Approval",
        "requiresApproval",
    ],
)
def test_unknown_trigger_key_json(
    tmp_path: Path, bad_key: str, monkeypatch, capsys
) -> None:
    """--json emits exactly one JSON document with status 'invalid' for a bad trigger key."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    skill_dir = tmp_path / "my-skill"
    _write_skill_with_bad_trigger_key(skill_dir, bad_key)

    rc = main(["skills", "validate", str(skill_dir), "--json"])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    doc = _read_json(captured)
    assert doc["status"] == "invalid"
    _assert_no_traceback(captured)


# ---------------------------------------------------------------------------
# Single-skill — unknown action keys (three cases per the review)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_key",
    [
        _UNKNOWN_ACTION_KEY,
        "Requires_Approval",
        "requiresApproval",
    ],
)
def test_unknown_action_key_exits_failed(
    tmp_path: Path, bad_key: str, monkeypatch, capsys
) -> None:
    """An unrecognised action key exits 1 with no traceback."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    skill_dir = tmp_path / "my-skill"
    _write_skill_with_bad_action_key(skill_dir, bad_key)

    rc = main(["skills", "validate", str(skill_dir)])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    _assert_no_traceback(captured)


@pytest.mark.parametrize(
    "bad_key",
    [
        _UNKNOWN_ACTION_KEY,
        "Requires_Approval",
        "requiresApproval",
    ],
)
def test_unknown_action_key_json(
    tmp_path: Path, bad_key: str, monkeypatch, capsys
) -> None:
    """--json emits exactly one JSON document with status 'invalid' for a bad action key."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    skill_dir = tmp_path / "my-skill"
    _write_skill_with_bad_action_key(skill_dir, bad_key)

    rc = main(["skills", "validate", str(skill_dir), "--json"])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    doc = _read_json(captured)
    assert doc["status"] == "invalid"
    _assert_no_traceback(captured)


# ---------------------------------------------------------------------------
# Single-skill — SkillSecurityError (unsigned community skill)
# ---------------------------------------------------------------------------


def test_unsigned_community_skill_exits_failed(tmp_path: Path, capsys) -> None:
    """A skill outside the first-party roots is refused with exit 1, no traceback.

    ``tmp_path`` is never under a packaged first-party root, so
    ``_is_core_bundled_skill`` returns False naturally.  ``signature: bundled``
    is then refused by ``_verify_community_signature``, raising
    ``SkillSecurityError``.  No monkeypatch is needed; this exercises the real
    community-signature code path.
    """
    skill_dir = tmp_path / "community-skill"
    _write_valid_skill(skill_dir, name="community-skill")

    rc = main(["skills", "validate", str(skill_dir)])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    _assert_no_traceback(captured)


def test_unsigned_community_skill_json(tmp_path: Path, capsys) -> None:
    """--json emits exactly one JSON document for an unsigned community skill."""
    skill_dir = tmp_path / "community-skill"
    _write_valid_skill(skill_dir, name="community-skill")

    rc = main(["skills", "validate", str(skill_dir), "--json"])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    doc = _read_json(captured)
    assert doc["status"] == "invalid"
    _assert_no_traceback(captured)


# ---------------------------------------------------------------------------
# Single-skill — OSError (file path where a directory is expected)
# ---------------------------------------------------------------------------


def test_file_path_exits_unusable(tmp_path: Path, capsys) -> None:
    """Passing a file path (not a directory) exits 2 with no traceback.

    ``target.iterdir()`` raises ``NotADirectoryError`` (a subclass of
    ``OSError``) when the path is a regular file.  The path contains no
    ``skill.yaml`` child so the handler reaches the directory branch, which
    wraps ``iterdir()`` in the OSError handler.
    """
    file_path = tmp_path / "skill.yaml"
    file_path.write_text("name: x\n", encoding="utf-8")

    rc = main(["skills", "validate", str(file_path)])

    captured = capsys.readouterr()
    assert rc == EXIT_UNUSABLE
    _assert_no_traceback(captured)


# ---------------------------------------------------------------------------
# Single-skill — missing path
# ---------------------------------------------------------------------------


def test_missing_path_exits_unusable(tmp_path: Path, capsys) -> None:
    """A non-existent path exits 2 and mentions 'not found'."""
    missing = tmp_path / "does-not-exist"

    rc = main(["skills", "validate", str(missing)])

    captured = capsys.readouterr()
    assert rc == EXIT_UNUSABLE
    assert "not found" in captured.out + captured.err
    _assert_no_traceback(captured)


# ---------------------------------------------------------------------------
# Single-skill — malformed YAML
# ---------------------------------------------------------------------------


def test_malformed_yaml_exits_failed(tmp_path: Path, monkeypatch, capsys) -> None:
    """A skill.yaml with invalid YAML exits 1 with no traceback."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    skill_dir = tmp_path / "broken-skill"
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").write_text(
        "name: broken\nkey: [\nbad yaml",
        encoding="utf-8",
    )

    rc = main(["skills", "validate", str(skill_dir)])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    _assert_no_traceback(captured)


def test_malformed_yaml_json(tmp_path: Path, monkeypatch, capsys) -> None:
    """--json emits exactly one JSON document for a malformed skill.yaml."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    skill_dir = tmp_path / "broken-skill"
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").write_text(
        "name: broken\nkey: [\nbad yaml",
        encoding="utf-8",
    )

    rc = main(["skills", "validate", str(skill_dir), "--json"])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    doc = _read_json(captured)
    assert doc["status"] == "invalid"
    _assert_no_traceback(captured)


# ---------------------------------------------------------------------------
# Directory mode — one valid, one invalid skill
# ---------------------------------------------------------------------------


def test_directory_one_valid_one_invalid(tmp_path: Path, monkeypatch, capsys) -> None:
    """Directory mode exits 1; valid skill is reported; no traceback."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    parent = tmp_path / "skills"
    _write_valid_skill(parent / "good-skill", name="good-skill")
    _write_skill_with_bad_trigger_key(parent / "bad-skill", "Requires_Approval")

    rc = main(["skills", "validate", str(parent)])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    # The valid skill name must appear somewhere in the human output.
    assert "good-skill" in captured.out
    _assert_no_traceback(captured)


def test_directory_json_is_valid_json(tmp_path: Path, monkeypatch, capsys) -> None:
    """--json in directory mode emits exactly one parseable JSON document."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    parent = tmp_path / "skills"
    _write_valid_skill(parent / "good-skill", name="good-skill")
    _write_skill_with_bad_trigger_key(parent / "bad-skill", "Requires_Approval")

    rc = main(["skills", "validate", str(parent), "--json"])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    doc = _read_json(captured)
    assert "results" in doc
    names = {r["name"] for r in doc["results"]}
    assert "good-skill" in names
    _assert_no_traceback(captured)


def test_directory_json_no_extra_stdout(tmp_path: Path, monkeypatch, capsys) -> None:
    """--json stdout is exactly one JSON document; no human-readable prefix lines."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    parent = tmp_path / "skills"
    _write_valid_skill(parent / "good-skill", name="good-skill")
    _write_skill_with_bad_trigger_key(parent / "bad-skill", "requiresApproval")

    main(["skills", "validate", str(parent), "--json"])

    captured = capsys.readouterr()
    # Strip trailing newline and verify there is exactly one JSON object.
    stdout = captured.out.strip()
    assert stdout.startswith("{"), (
        f"stdout must start with '{{', not with human-readable text.\n"
        f"stdout was: {stdout[:200]!r}"
    )
    # Must parse as a single document (not multiple concatenated ones).
    doc = json.loads(stdout)
    assert isinstance(doc, dict)


def test_directory_unsigned_community_skill(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Directory mode flags a skill outside the package with no valid signature (SkillSecurityError)."""
    parent = tmp_path / "skills"

    good_skill = parent / "good-skill"
    community_skill = parent / "community-skill"

    _write_valid_skill(good_skill, name="good-skill")
    _write_valid_skill(community_skill, name="community-skill")

    def mocked_is_core(self, skill_dir: Path) -> bool:
        if skill_dir.name == "good-skill":
            return True
        return False

    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        mocked_is_core,
    )

    rc = main(["skills", "validate", str(parent)])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    assert "good-skill" in captured.out
    _assert_no_traceback(captured)


def test_directory_unsigned_community_skill_json(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Directory mode --json flags a community skill as invalid due to SkillSecurityError."""
    parent = tmp_path / "skills"
    good_skill = parent / "good-skill"
    community_skill = parent / "community-skill"
    _write_valid_skill(good_skill, name="good-skill")
    _write_valid_skill(community_skill, name="community-skill")

    def mocked_is_core(self, skill_dir: Path) -> bool:
        if skill_dir.name == "good-skill":
            return True
        return False

    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        mocked_is_core,
    )

    rc = main(["skills", "validate", str(parent), "--json"])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    doc = _read_json(captured)
    results = {r["name"]: r for r in doc["results"]}
    assert results["good-skill"]["status"] == "valid"
    assert results["community-skill"]["status"] == "invalid"
    _assert_no_traceback(captured)


def test_directory_malformed_yaml(tmp_path: Path, monkeypatch, capsys) -> None:
    """Directory mode catches yaml.YAMLError, flags skill as invalid, and continues."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    parent = tmp_path / "skills"
    good_skill = parent / "good-skill"
    broken_skill = parent / "broken-skill"

    _write_valid_skill(good_skill, name="good-skill")

    broken_skill.mkdir(parents=True)
    (broken_skill / "skill.yaml").write_text(
        "name: broken\nkey: [\nbad yaml",
        encoding="utf-8",
    )

    rc = main(["skills", "validate", str(parent)])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    assert "good-skill" in captured.out
    _assert_no_traceback(captured)


def test_directory_malformed_yaml_json(tmp_path: Path, monkeypatch, capsys) -> None:
    """Directory mode --json handles yaml.YAMLError."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )
    parent = tmp_path / "skills"
    good_skill = parent / "good-skill"
    broken_skill = parent / "broken-skill"

    _write_valid_skill(good_skill, name="good-skill")
    broken_skill.mkdir(parents=True)
    (broken_skill / "skill.yaml").write_text(
        "name: broken\nkey: [\nbad yaml",
        encoding="utf-8",
    )

    rc = main(["skills", "validate", str(parent), "--json"])

    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    doc = _read_json(captured)
    results = {r["name"]: r for r in doc["results"]}
    assert results["good-skill"]["status"] == "valid"
    assert results["broken-skill"]["status"] == "invalid"
    _assert_no_traceback(captured)


def test_single_skill_unreadable_file_exits_unusable(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Single skill unreadable file exits 2 with a message."""
    skill_dir = tmp_path / "bad-skill"
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").touch()

    def mock_load_one(self, target):
        import errno

        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr("ori.skills.loader.SkillLoader.load_one", mock_load_one)

    rc = main(["skills", "validate", str(skill_dir)])

    captured = capsys.readouterr()
    assert rc == EXIT_UNUSABLE
    assert "could not read" in captured.err
    _assert_no_traceback(captured)


def test_single_skill_unreadable_file_json(tmp_path: Path, monkeypatch, capsys) -> None:
    """Single skill unreadable file with --json exits 2 with JSON error document."""
    skill_dir = tmp_path / "bad-skill"
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").touch()

    def mock_load_one(self, target):
        import errno

        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr("ori.skills.loader.SkillLoader.load_one", mock_load_one)

    rc = main(["skills", "validate", str(skill_dir), "--json"])

    captured = capsys.readouterr()
    assert rc == EXIT_UNUSABLE
    doc = _read_json(captured)
    assert doc["status"] == "error"
    assert "could not read" in doc["error"]
    _assert_no_traceback(captured)
