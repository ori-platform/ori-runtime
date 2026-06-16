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


def test_eval_extra_is_intentionally_empty() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["optional-dependencies"]["eval"] == []
