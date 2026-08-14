# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Suggested device identity, and the prompts that offer it."""

from __future__ import annotations

import pytest

from ori.installer import identity
from ori.installer.linux import (
    InstallerInputOptions,
    LinuxInstallError,
    collect_installer_config,
)


class _Operator:
    """A scripted operator, recording everything it was shown."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []
        self.messages: list[str] = []

    def prompt(self, message: str) -> str:
        self.prompts.append(message)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def write(self, message: str) -> None:
        self.messages.append(message)

    @property
    def shown(self) -> str:
        return "\n".join(self.prompts + self.messages)


def _collect(operator: _Operator, **overrides: object) -> object:
    options = InstallerInputOptions(**overrides)  # type: ignore[arg-type]
    return collect_installer_config(
        options, prompt=operator.prompt, write=operator.write
    )


# --- deriving identity from the host --------------------------------------


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("pi-ikeja-01", "pi-ikeja-01"),
        ("PI-Ikeja-01", "pi-ikeja-01"),
        ("pi-ikeja-01.local", "pi-ikeja-01"),
        ("Wasiu's MacBook", "wasiu-s-macbook"),
        ("--weird--", "weird"),
    ],
)
def test_a_named_host_needs_nothing_invented(hostname: str, expected: str) -> None:
    suggestion = identity.suggest(hostname)
    assert suggestion is not None
    assert suggestion.device_id == expected
    assert suggestion.deterministic is True


@pytest.mark.parametrize("hostname", ["raspberrypi", "localhost", "ubuntu", "", "   "])
def test_a_stock_image_hostname_gets_a_suffix(hostname: str) -> None:
    """Every device flashed from one image would otherwise share an identity."""
    suggestion = identity.suggest(hostname)
    assert suggestion is not None
    assert suggestion.generated_suffix is True
    assert suggestion.device_id != identity.normalise(hostname)
    assert identity.suggest(hostname).device_id != suggestion.device_id


def test_a_suggested_id_always_satisfies_the_device_id_rules() -> None:
    from ori.installer.linux import _validate_device_id

    for hostname in ("pi-ikeja-01", "raspberrypi", "", "X" * 200, "!!!"):
        suggestion = identity.suggest(hostname)
        assert suggestion is not None
        _validate_device_id(suggestion.device_id)  # raises if unusable


def test_nothing_is_generated_when_reproducibility_is_required() -> None:
    """Automation must not get a different device on each run."""
    assert identity.suggest("raspberrypi", allow_generated=False) is None
    assert identity.suggest("pi-ikeja-01", allow_generated=False) is not None


# --- what the operator is shown -------------------------------------------


def test_the_device_id_prompt_shows_constraints_and_examples(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "host_name", lambda: "pi-ikeja-01")
    operator = _Operator("", "", "Lagos", "", "y")
    _collect(operator)
    assert "lowercase letters, digits" in operator.shown
    assert "pi-ikeja-01" in operator.shown
    assert "hvac.roof.3" in operator.shown


def test_pressing_enter_accepts_the_suggested_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "host_name", lambda: "pi-ikeja-01")
    operator = _Operator("", "", "Lagos", "", "y")
    values = _collect(operator)
    assert values.device_id == "pi-ikeja-01"
    assert values.name == "pi-ikeja-01"
    assert "[pi-ikeja-01]" in operator.shown


def test_location_and_contact_are_never_invented(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plausible-looking location is worse than a blank one."""
    monkeypatch.setattr(identity, "host_name", lambda: "pi-ikeja-01")
    operator = _Operator("", "", "Lagos", "", "y")
    values = _collect(operator)
    assert values.operator_contact == ""
    location_prompt = next(p for p in operator.prompts if "location" in p.lower())
    assert "[" not in location_prompt  # no default offered
    contact_prompt = next(p for p in operator.prompts if "contact" in p.lower())
    assert "[" not in contact_prompt


def test_a_typed_value_overrides_the_suggestion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "host_name", lambda: "raspberrypi")
    operator = _Operator("meter-02", "Meter 2", "Lagos", "", "y")
    values = _collect(operator)
    assert values.device_id == "meter-02"


def test_rejected_input_is_never_echoed_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mistyped answer can be anything, including a pasted credential."""
    monkeypatch.setattr(identity, "host_name", lambda: "pi-ikeja-01")
    secret = "hunter2-SHOULD-NOT-APPEAR"
    operator = _Operator(secret, "pi-01", "Site", "Lagos", "", "y")
    _collect(operator)
    assert secret not in operator.shown
    assert "device ID must be" in operator.shown


# --- confirmation ---------------------------------------------------------


def test_the_values_are_read_back_before_anything_is_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "host_name", lambda: "pi-ikeja-01")
    operator = _Operator("", "", "Lagos", "ops@example.com", "y")
    _collect(operator)
    shown = operator.shown
    assert "This device will be installed as:" in shown
    assert "pi-ikeja-01" in shown
    assert "Lagos" in shown
    assert "ops@example.com" in shown
    assert "Proceed with these values?" in shown


def test_declining_the_confirmation_cancels_before_any_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "host_name", lambda: "pi-ikeja-01")
    operator = _Operator("", "", "Lagos", "", "n")
    with pytest.raises(LinuxInstallError) as excinfo:
        _collect(operator)
    assert excinfo.value.code == "config_validation_failed"
    assert "before any change was made" in str(excinfo.value)


def test_confirmation_defaults_to_proceeding_on_a_bare_enter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "host_name", lambda: "pi-ikeja-01")
    operator = _Operator("", "", "Lagos", "", "")
    assert _collect(operator).device_id == "pi-ikeja-01"


def test_cancelling_the_confirmation_is_not_consent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "host_name", lambda: "pi-ikeja-01")
    operator = _Operator("", "", "Lagos", "")  # nothing left for the confirmation
    with pytest.raises(LinuxInstallError):
        _collect(operator)


# --- unattended stays deterministic ---------------------------------------


def test_unattended_never_prompts_and_never_invents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "host_name", lambda: "raspberrypi")
    operator = _Operator()  # any prompt raises EOFError
    with pytest.raises(LinuxInstallError) as excinfo:
        _collect(operator, unattended=True)
    assert "unattended mode requires" in str(excinfo.value)
    assert operator.prompts == []


def test_unattended_with_explicit_values_is_reproducible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(identity, "host_name", lambda: "raspberrypi")
    operator = _Operator()
    first = _collect(
        operator,
        unattended=True,
        device_id="meter-02",
        name="Meter 2",
        location="Lagos",
    )
    second = _collect(
        operator,
        unattended=True,
        device_id="meter-02",
        name="Meter 2",
        location="Lagos",
    )
    assert first.device_id == second.device_id == "meter-02"
    assert operator.prompts == []
