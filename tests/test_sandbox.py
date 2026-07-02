# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import textwrap

import pytest

from ori.skills.loader import SkillLoader
from ori.skills.sandbox import (
    RestrictedImportFinder,
    SkillSecurityError,
    load_hooks_restricted,
)


def _write_hooks(tmp_path, source: str) -> str:
    hooks_file = tmp_path / "hooks.py"
    hooks_file.write_text(textwrap.dedent(source), encoding="utf-8")
    return str(hooks_file)


def test_allowed_import_math_loads(tmp_path):
    path = _write_hooks(
        tmp_path,
        """\
        import math
        result = math.sqrt(16)
    """,
    )
    module = load_hooks_restricted(path)
    assert module is not None
    assert module.result == 4.0


def test_blocked_import_os_raises(tmp_path):
    path = _write_hooks(
        tmp_path,
        """\
        import os
    """,
    )
    with pytest.raises(SkillSecurityError):
        load_hooks_restricted(path)


def test_blocked_import_subprocess_raises(tmp_path):
    path = _write_hooks(
        tmp_path,
        """\
        import subprocess
    """,
    )
    with pytest.raises(SkillSecurityError):
        load_hooks_restricted(path)


def test_blocked_builtin_open_raises(tmp_path):
    path = _write_hooks(
        tmp_path,
        """\
        data = open("/etc/passwd", "r")
    """,
    )
    with pytest.raises((NameError, SkillSecurityError)):
        load_hooks_restricted(path)


def test_nonexistent_path_returns_none():
    result = load_hooks_restricted("/nonexistent/path/hooks.py")
    assert result is None


def test_meta_path_not_polluted_after_success(tmp_path):
    """RestrictedImportFinder must be removed even on successful load."""
    before = list(sys.meta_path)
    path = _write_hooks(tmp_path, "import math\n")
    load_hooks_restricted(path)
    after = list(sys.meta_path)
    assert not any(isinstance(f, RestrictedImportFinder) for f in after)
    assert len(before) == len(after)


def test_meta_path_not_polluted_after_failure(tmp_path):
    """RestrictedImportFinder must be removed even when loading fails."""
    path = _write_hooks(tmp_path, "import os\n")
    with pytest.raises(SkillSecurityError):
        load_hooks_restricted(path)
    assert not any(isinstance(f, RestrictedImportFinder) for f in sys.meta_path)


def test_meta_path_not_polluted_after_runtime_error(tmp_path):
    """RestrictedImportFinder must be removed when exec raises a non-import error.

    This covers the case where the module passes the import check but then
    crashes mid-execution (e.g. a ValueError, ZeroDivisionError, etc.).
    The finder must still be cleaned up even though the failure is not an
    ImportError caught by the SkillSecurityError path.
    """
    path = _write_hooks(
        tmp_path,
        """\
        import math          # allowed — clears the import gate
        x = 1 / 0            # raises ZeroDivisionError during exec
    """,
    )
    with pytest.raises(ZeroDivisionError):
        load_hooks_restricted(path)
    assert not any(isinstance(f, RestrictedImportFinder) for f in sys.meta_path)


def test_meta_path_not_polluted_after_nonexistent():
    """No finder should be installed when the file does not exist."""
    before_count = len(sys.meta_path)
    load_hooks_restricted("/no/such/file.py")
    assert len(sys.meta_path) == before_count
    assert not any(isinstance(f, RestrictedImportFinder) for f in sys.meta_path)


def test_is_bundled_skill_symlink_resolves_correctly(tmp_path):
    """_is_bundled_skill returns False when the home path itself is a symlink.

    On macOS (and some Linux setups) os.path.expanduser("~") returns a path
    like /Users/alice that is itself a symlink to /private/var/...  Without
    .resolve() on both sides, relative_to() sees mismatched prefixes and
    wrongly classifies a legitimate community skill as bundled.

    Setup
    -----
    real_home/           ← the actual directory on disk
      .ori/skills/
        my-community-skill/   ← real skill directory

    symlinked_home  →  real_home   ← simulates the macOS /Users/alice symlink

    expanduser("~") is patched to return symlinked_home (the unresolved path).
    skill_dir is the REAL path (real_home / .ori / skills / my-community-skill).

    Without resolve(): relative_to() compares real_home prefix against
      symlinked_home prefix → ValueError → wrongly returns True (bundled).
    With resolve():    both sides canonicalise to real_home → succeeds →
      correctly returns False (community skill).
    """
    # The real filesystem home directory (no symlinks involved here)
    real_home = tmp_path / "real_home"
    skill_dir = real_home / ".ori" / "skills" / "my-community-skill"
    skill_dir.mkdir(parents=True)

    # A symlink that points to real_home — simulates the macOS /Users/alice → /private/...
    symlinked_home = tmp_path / "symlinked_home"
    symlinked_home.symlink_to(real_home)

    loader = SkillLoader()

    # Patch expanduser to return the SYMLINKED path (unresolved), as macOS does
    original_expanduser = os.path.expanduser

    def patched_expanduser(path):
        return str(symlinked_home) if path == "~" else original_expanduser(path)

    os.path.expanduser = patched_expanduser
    try:
        # skill_dir uses the real (resolved) path — this is the mismatch case
        result = loader._is_bundled_skill(skill_dir)
    finally:
        os.path.expanduser = original_expanduser

    assert result is False, (
        "A skill under ~/.ori/skills/ must be identified as a community skill "
        "(False) even when the home path returned by expanduser is a symlink."
    )
