# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import re
import tomllib
from pathlib import Path

_DEP_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+")


def _dependency_name(requirement: str) -> str:
    match = _DEP_NAME_RE.match(requirement)
    assert match is not None
    return match.group(0).lower()


def test_base_package_dependencies_stay_slim_for_integration_consumers() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    dependencies = {
        _dependency_name(dep) for dep in pyproject["project"]["dependencies"]
    }

    assert dependencies == {"pyyaml"}


def test_runtime_extra_carries_transport_provider_and_crypto_dependencies() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    runtime_deps = {
        _dependency_name(dep)
        for dep in pyproject["project"]["optional-dependencies"]["runtime"]
    }

    assert "paho-mqtt" in runtime_deps
    assert "cryptography" in runtime_deps
    assert "africastalking" in runtime_deps
    assert "twilio" in runtime_deps
    assert "psutil" in runtime_deps


def test_phone_extra_carries_only_phone_wedge_dependencies() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    phone_deps = {
        _dependency_name(dep)
        for dep in pyproject["project"]["optional-dependencies"]["phone"]
    }

    assert phone_deps == {
        "africastalking",
        "cryptography",
        "httpx",
        "pyserial",
        "tzdata",
        "twilio",
    }


def test_phone_inverter_extras_extend_phone_without_bloating_base() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    optional = pyproject["project"]["optional-dependencies"]
    phone_deps = {_dependency_name(dep) for dep in optional["phone"]}
    growatt_deps = {_dependency_name(dep) for dep in optional["phone-growatt"]}
    victron_deps = {_dependency_name(dep) for dep in optional["phone-victron"]}

    assert "pysolarmanv5" not in phone_deps
    assert "aiomqtt" not in phone_deps
    assert phone_deps < growatt_deps
    assert growatt_deps - phone_deps == {"pysolarmanv5"}
    assert phone_deps < victron_deps
    assert victron_deps - phone_deps == {"aiomqtt"}


def test_inverter_profiles_are_packaged_with_runtime_wheel() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]["ori"]

    assert "py.typed" in package_data
    assert "hal/inverter_profiles/*.yaml" in package_data


def test_inverter_profile_doctor_entrypoint_is_packaged() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    scripts = pyproject["project"]["scripts"]

    assert scripts["ori-inverter-profile-doctor"] == "ori.inverter_profile_doctor:main"


def test_all_bundled_skills_are_packaged_as_data_files() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    data_files = pyproject["tool"]["setuptools"]["data-files"]
    packaged_skill_dirs = {
        key.removeprefix("share/ori-runtime/skills/")
        for key in data_files
        if key.startswith("share/ori-runtime/skills/")
    }
    bundled_skill_dirs = {
        path.parent.name
        for path in Path("skills").glob("*/skill.yaml")
        if path.parent.name != "template"
    }

    assert bundled_skill_dirs <= packaged_skill_dirs

    for skill_name in bundled_skill_dirs:
        files = set(data_files[f"share/ori-runtime/skills/{skill_name}"])
        assert f"skills/{skill_name}/skill.yaml" in files
        assert f"skills/{skill_name}/hooks.py" in files


def test_phone_requirements_input_excludes_gateway_pi_and_pc_deps() -> None:
    deps = {
        _dependency_name(line.strip())
        for line in Path("requirements/phone.in")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert {"pyyaml", "pyserial", "tzdata", "httpx", "cryptography"} <= deps
    assert "paho-mqtt" not in deps
    assert "asyncua" not in deps
    assert "pysolarmanv5" not in deps
    assert "psutil" not in deps
    assert "gpiozero" not in deps


def test_phone_requirements_lockfile_is_hashed_and_excludes_broad_runtime_deps() -> (
    None
):
    lockfile = Path("requirements/phone.txt").read_text(encoding="utf-8")
    deps = {
        _dependency_name(line.strip())
        for line in lockfile.splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and not line.startswith(" ")
    }

    assert "sha256:" in lockfile
    assert {"pyyaml", "pyserial", "tzdata", "httpx", "cryptography"} <= deps
    assert "paho-mqtt" not in deps
    assert "asyncua" not in deps
    assert "pysolarmanv5" not in deps
    assert "psutil" not in deps
    assert "gpiozero" not in deps


def test_phone_inverter_profile_lockfiles_are_additive_and_hashed() -> None:
    growatt = Path("requirements/phone-growatt.txt").read_text(encoding="utf-8")
    victron = Path("requirements/phone-victron.txt").read_text(encoding="utf-8")
    growatt_deps = {
        _dependency_name(line.strip())
        for line in growatt.splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and not line.startswith(" ")
    }
    victron_deps = {
        _dependency_name(line.strip())
        for line in victron.splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and not line.startswith(" ")
    }

    assert "sha256:" in growatt
    assert "pysolarmanv5" in growatt_deps
    assert "gpiozero" not in growatt_deps

    assert "sha256:" in victron
    assert "aiomqtt" in victron_deps
    assert "pyserial" not in victron_deps
    assert "gpiozero" not in victron_deps


def test_phone_wheelhouse_build_allows_platform_local_wheels() -> None:
    script = Path("scripts/build-wheelhouse.sh").read_text(encoding="utf-8")

    assert 'if [[ "${TARGET}" == phone* ]]; then' in script
    assert "phone-growatt" in script
    assert "phone-victron" in script
    assert "PROFILE_REQUIREMENTS" in script
    assert "Building phone dependency wheels from hash-locked inputs" in script
    assert "Building phone profile dependency wheels" in script
    assert "--no-build-isolation" in script
    assert "Writing phone install requirements from built wheels" in script
    assert "requirements/phone.txt is the source/build lockfile" in script
    assert "--only-binary=:all:" in script


def test_termux_phone_smoke_script_keeps_install_and_runtime_startup_opt_in() -> None:
    script = Path("scripts/termux-phone-smoke.sh").read_text(encoding="utf-8")

    assert "INSTALL_WHEELHOUSE=false" in script
    assert "--install-wheelhouse" in script
    assert "RUNTIME_STARTUP_SECONDS=0" in script
    assert "--runtime-startup-seconds" in script
    assert 'PYTHON_BIN="${ORI_PYTHON:-python}"' in script
    assert "python -m pip install --break-system-packages --no-index" not in script
    assert '"${PYTHON_BIN}" -m pip install --break-system-packages --no-index' in script


def test_eval_extra_is_intentionally_empty() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["optional-dependencies"]["eval"] == []
