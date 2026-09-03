# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Staging apt-owned modules into an isolated release venv.

This path had no tests. It runs as root, reads from a system directory and
writes into a release, and it now carries adafruit-blinka's platform library as
well as the pin factory — so what it will and will not take is worth pinning
down rather than trusting to review.
"""

import os
from pathlib import Path, PurePosixPath

from ori.installer.linux import (
    _BLINKA_SHIM_MEMBERS,
    _PIN_FACTORY_MEMBERS,
    _SYSTEM_BLINKA_SHIM_MODULE,
    _SYSTEM_PACKAGE_DIRECTORIES,
    _SYSTEM_PIN_FACTORY_MODULE,
    _escapes_root,
    _shim_refusal,
    _staging_refusal,
    _staging_root,
    _system_file_failure,
)

_STAGED_MEMBERS = _PIN_FACTORY_MEMBERS + _BLINKA_SHIM_MEMBERS

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

    def test_a_shim_outside_the_pin_factory_directory_is_not_staged(self, tmp_path):
        """The shim is a package, so its origin sits one level deeper.

        The lift to the package's own parent is a correctness fix, not a
        security check — comparing the origin's parent directly would refuse
        every legitimate case. What this asserts is that a shim found somewhere
        other than where the pin factory came from is not read.
        """
        reason = _shim_refusal(
            _origins(rpi="/home/attacker/RPi/__init__.py"),
            _SYSTEM_PACKAGE_DIRECTORIES[0],
        )
        assert reason is not None
        assert _SYSTEM_BLINKA_SHIM_MODULE in reason

    def test_a_shim_in_the_pin_factory_directory_is_staged(self):
        assert _shim_refusal(_origins(), _SYSTEM_PACKAGE_DIRECTORIES[0]) is None

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

    def test_a_missing_pin_factory_names_its_apt_package(self, tmp_path):
        """A refusal that names the module leaves an operator searching."""
        origins = _origins()
        origins[_SYSTEM_PIN_FACTORY_MODULE] = ""
        reason = _staging_refusal(
            tmp_path, "/usr/bin/python3", str(tmp_path), ".so", origins
        )
        assert reason is not None
        assert "python3-lgpio" in reason

    def test_a_missing_shim_does_not_fail_the_install(self, tmp_path):
        """Images shipping the classic RPi.GPIO, or neither, install today.

        Refusing them would break working deployments to add a capability they
        may not use, so the shim's absence is reported and never fatal.
        """
        origins = _origins()
        origins[_SYSTEM_BLINKA_SHIM_MODULE] = ""
        assert (
            _staging_refusal(
                tmp_path, "/usr/bin/python3", str(tmp_path), ".so", origins
            )
            is None
        )
        reason = _shim_refusal(origins, _SYSTEM_PACKAGE_DIRECTORIES[0])
        assert reason is not None
        assert "python3-rpi-lgpio" in reason

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

    def test_a_group_writable_file_is_refused_for_being_writable(
        self, tmp_path, monkeypatch
    ):
        """Asserted on the writability branch, not the ownership one.

        A test that accepts either refusal passes on a developer machine
        through ownership alone, and would not notice the writability check
        being deleted.
        """
        member = tmp_path / "member.py"
        member.write_text("x", encoding="utf-8")
        os.chmod(member, 0o664)
        real_lstat = os.lstat

        def as_root(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            return os.stat_result(
                (info.st_mode, info.st_ino, info.st_dev, info.st_nlink, 0, 0)
                + tuple(info)[6:]
            )

        monkeypatch.setattr(os, "lstat", as_root)
        assert _system_file_failure(member) == "is writable beyond its owner"


class TestIntermediateComponents:
    """A package member has a directory between the root and the file.

    `find_spec` answers with an unresolved origin and only a path's final
    component is `lstat`ed, so a symlink one level up reads from wherever it
    points. The single-file members never had an intermediate component; the
    shim introduced one.
    """

    def test_a_symlinked_intermediate_directory_escapes_and_is_caught(self, tmp_path):
        root = tmp_path / "dist"
        (root / "real").mkdir(parents=True)
        outside = tmp_path / "outside"
        (outside / "GPIO").mkdir(parents=True)
        (outside / "GPIO" / "__init__.py").write_text("HOSTILE", encoding="utf-8")
        (root / "RPi").symlink_to(outside)

        member = PurePosixPath("RPi/GPIO/__init__.py")
        # The file itself passes every check made on the final component.
        assert _system_file_failure(root / member) != "is missing"
        assert _escapes_root(root, member, root.resolve())

    def test_a_member_inside_the_root_does_not_escape(self, tmp_path):
        root = tmp_path / "dist"
        (root / "RPi" / "GPIO").mkdir(parents=True)
        (root / "RPi" / "GPIO" / "__init__.py").write_text("ok", encoding="utf-8")
        assert not _escapes_root(
            root, PurePosixPath("RPi/GPIO/__init__.py"), root.resolve()
        )
