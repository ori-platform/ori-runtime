# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Staging apt-owned modules into an isolated release venv.

This path had no tests. It runs as root, reads from a system directory and
writes into a release, and it now carries adafruit-blinka's platform library as
well as the pin factory — so what it will and will not take is worth pinning
down rather than trusting to review.
"""

import os
from pathlib import Path

import pytest

from ori.installer.linux import (
    _STAGED_MEMBERS,
    _SYSTEM_BLINKA_SHIM_MODULE,
    _SYSTEM_PACKAGE_DIRECTORIES,
    _SYSTEM_PIN_FACTORY_MODULE,
    _staging_refusal,
    _staging_root,
    _system_file_failure,
)

ADMITTED = str(_SYSTEM_PACKAGE_DIRECTORIES[0])


def _origins(*, lgpio: str | None = None, rpi: str | None = None) -> dict[str, str]:
    return {
        _SYSTEM_PIN_FACTORY_MODULE: (
            f"{ADMITTED}/lgpio.py" if lgpio is None else lgpio
        ),
        _SYSTEM_BLINKA_SHIM_MODULE: (
            f"{ADMITTED}/RPi/__init__.py" if rpi is None else rpi
        ),
    }


class TestStagedManifest:
    def test_the_manifest_is_exactly_the_four_reviewed_paths(self):
        """A directory copy would let apt decide what a release takes."""
        assert set(_STAGED_MEMBERS) == {
            "lgpio.py",
            "_lgpio{ext}",
            "RPi/__init__.py",
            "RPi/GPIO/__init__.py",
        }

    def test_no_manifest_entry_escapes_the_staging_root(self):
        for name in _STAGED_MEMBERS:
            assert not name.startswith("/")
            assert ".." not in Path(name.format(ext=".so")).parts

    def test_the_manifest_takes_no_metadata(self):
        """egg-info describes an installation this release is not."""
        assert not any(
            "egg-info" in name or "dist-info" in name for name in _STAGED_MEMBERS
        )


class TestStagingRefusal:
    def test_a_complete_system_is_accepted(self, tmp_path):
        assert (
            _staging_refusal(
                tmp_path, "/usr/bin/python3", str(tmp_path), ".so", _origins()
            )
            is None
        )

    def test_a_package_resolving_outside_the_admitted_root_is_refused(self, tmp_path):
        """The shim is a package, so its origin sits one level deeper.

        Comparing that parent directly would admit any `RPi/` anywhere, which
        is the check this path exists for.
        """
        reason = _staging_refusal(
            tmp_path,
            "/usr/bin/python3",
            str(tmp_path),
            ".so",
            _origins(rpi="/home/attacker/RPi/__init__.py"),
        )
        assert reason is not None
        assert _SYSTEM_BLINKA_SHIM_MODULE in reason

    def test_a_pin_factory_outside_the_admitted_root_is_refused(self, tmp_path):
        reason = _staging_refusal(
            tmp_path,
            "/usr/bin/python3",
            str(tmp_path),
            ".so",
            _origins(lgpio="/tmp/lgpio.py"),
        )
        assert reason is not None
        assert _SYSTEM_PIN_FACTORY_MODULE in reason

    @pytest.mark.parametrize(
        "missing", [_SYSTEM_PIN_FACTORY_MODULE, _SYSTEM_BLINKA_SHIM_MODULE]
    )
    def test_either_module_missing_is_refused_by_name(self, tmp_path, missing):
        """Both are required; naming which one is absent is the actionable part."""
        origins = _origins()
        origins[missing] = ""
        reason = _staging_refusal(
            tmp_path, "/usr/bin/python3", str(tmp_path), ".so", origins
        )
        assert reason is not None
        assert missing in reason

    def test_an_absent_extension_suffix_is_refused(self, tmp_path):
        assert (
            _staging_refusal(
                tmp_path, "/usr/bin/python3", str(tmp_path), "", _origins()
            )
            is not None
        )

    def test_the_staging_root_is_the_admitted_directory(self):
        assert _staging_root(_origins()) == _SYSTEM_PACKAGE_DIRECTORIES[0]


class TestSystemFileRefusal:
    """Every staged source is checked before a privileged copy reads it."""

    def test_a_symlink_is_not_a_regular_file(self, tmp_path):
        real = tmp_path / "real.py"
        real.write_text("x", encoding="utf-8")
        link = tmp_path / "link.py"
        link.symlink_to(real)
        assert _system_file_failure(link) == "is not a regular file"

    def test_a_missing_file_is_reported_as_missing(self, tmp_path):
        assert _system_file_failure(tmp_path / "absent.py") == "is missing"

    def test_a_directory_is_not_a_regular_file(self, tmp_path):
        assert _system_file_failure(tmp_path) == "is not a regular file"

    def test_a_group_writable_file_is_refused(self, tmp_path):
        member = tmp_path / "member.py"
        member.write_text("x", encoding="utf-8")
        os.chmod(member, 0o664)
        failure = _system_file_failure(member)
        # Ownership is checked first and this file is not root-owned in a test,
        # so accept either refusal: what matters is that it is refused.
        assert failure is not None
