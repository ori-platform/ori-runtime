# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterator

import pytest

from ori.installer.linux import (
    InstallerInputOptions,
    LinuxInstallError,
    collect_installer_config,
)


def _prompter(responses: Iterator[str], labels: list[str]):
    def prompt(label: str) -> str:
        labels.append(label)
        return next(responses)

    return prompt


def test_unattended_collection_never_prompts() -> None:
    def unexpected_prompt(_label: str) -> str:
        raise AssertionError("unattended collection must not prompt")

    result = collect_installer_config(
        InstallerInputOptions(
            unattended=True,
            device_id="ori-01",
            name="Lagos Office",
            location="Lagos, Nigeria",
            deployment_type="server",
            operator_contact="+2348012345678",
        ),
        prompt=unexpected_prompt,
    )

    assert result.device_id == "ori-01"
    assert result.name == "Lagos Office"
    assert result.location == "Lagos, Nigeria"
    assert result.deployment_type == "server"
    assert result.operator_contact == "+2348012345678"


@pytest.mark.parametrize("missing", ["device_id", "name", "location"])
def test_unattended_collection_requires_every_identity_field(missing: str) -> None:
    values: dict[str, object] = {
        "unattended": True,
        "device_id": "ori-01",
        "name": "Lagos Office",
        "location": "Lagos, Nigeria",
    }
    values[missing] = None

    with pytest.raises(LinuxInstallError) as error:
        collect_installer_config(InstallerInputOptions(**values))  # type: ignore[arg-type]

    assert error.value.code == "config_validation_failed"
    assert f"--{missing.replace('_', '-')}" in error.value.detail


def test_interactive_collection_prompts_only_for_missing_values() -> None:
    labels: list[str] = []
    result = collect_installer_config(
        InstallerInputOptions(device_id="ori-01", name="Lagos Office"),
        prompt=_prompter(iter(["Lagos, Nigeria", "", "y"]), labels),
    )

    assert result.location == "Lagos, Nigeria"
    assert result.operator_contact == ""
    # Neither location nor contact can be derived from the host, so neither
    # offers a default; the last prompt reads the collected values back.
    assert labels[:2] == ["Device location: ", "Operator contact (optional): "]
    assert "Proceed with these values?" in labels[2]


def test_interactive_collection_retries_invalid_values_without_echoing_them() -> None:
    labels: list[str] = []
    messages: list[str] = []
    result = collect_installer_config(
        InstallerInputOptions(),
        prompt=_prompter(
            iter(["BAD SECRET", "ori-01", "Office", "Lagos", "", "y"]), labels
        ),
        write=messages.append,
    )

    assert result.device_id == "ori-01"
    assert labels[0] == labels[1]
    assert labels[0].startswith("Device ID")
    shown = "\n".join(messages)
    assert (
        "device ID must be 1-64 lowercase letters, digits, dots, dashes, or "
        "underscores, starting with a letter or digit"
    ) in shown
    assert "BAD SECRET" not in shown
    assert "BAD SECRET" not in "\n".join(labels)


def test_interactive_collection_is_bounded() -> None:
    with pytest.raises(LinuxInstallError) as error:
        collect_installer_config(
            InstallerInputOptions(),
            prompt=lambda _label: "invalid device id",
            write=lambda _message: None,
        )

    assert error.value.code == "config_validation_failed"
    assert error.value.detail == "interactive input failed after 3 attempts"


@pytest.mark.parametrize("failure", [EOFError(), KeyboardInterrupt()])
def test_interactive_collection_maps_cancellation(failure: BaseException) -> None:
    def cancelled(_label: str) -> str:
        raise failure

    with pytest.raises(LinuxInstallError) as error:
        collect_installer_config(InstallerInputOptions(), prompt=cancelled)

    assert error.value.code == "config_validation_failed"
    assert error.value.detail == "interactive input was cancelled"


def test_supplied_interactive_value_fails_without_retry_or_value_disclosure() -> None:
    with pytest.raises(LinuxInstallError) as error:
        collect_installer_config(
            InstallerInputOptions(device_id="BAD SECRET"),
            prompt=lambda _label: "ori-01",
        )

    assert error.value.detail == (
        "device ID must be 1-64 lowercase letters, digits, dots, dashes, or "
        "underscores, starting with a letter or digit"
    )
    assert "BAD SECRET" not in str(error.value)


def test_device_id_whitespace_error_explains_constraint_without_echoing_value() -> None:
    with pytest.raises(LinuxInstallError) as error:
        collect_installer_config(
            InstallerInputOptions(
                unattended=True,
                device_id="ori-01 ",
                name="Office",
                location="Lagos",
            )
        )

    assert (
        "lowercase letters, digits, dots, dashes, or underscores" in error.value.detail
    )
    assert "ori-01 " not in str(error.value)


@pytest.mark.parametrize("device_id", [".ori-01", "-ori-01", "_ori-01"])
def test_device_id_leading_punctuation_error_explains_first_character(
    device_id: str,
) -> None:
    with pytest.raises(LinuxInstallError) as error:
        collect_installer_config(
            InstallerInputOptions(
                unattended=True,
                device_id=device_id,
                name="Office",
                location="Lagos",
            )
        )

    assert "starting with a letter or digit" in error.value.detail
    assert device_id not in str(error.value)


@pytest.mark.parametrize("unattended", [False, True])
def test_collection_rejects_control_characters_before_normalizing(
    unattended: bool,
) -> None:
    with pytest.raises(LinuxInstallError) as error:
        collect_installer_config(
            InstallerInputOptions(
                unattended=unattended,
                device_id="ori-01",
                name="Office\n",
                location="Lagos",
                operator_contact="",
            )
        )

    assert error.value.code == "config_validation_failed"
    assert error.value.detail == "device name is invalid"
