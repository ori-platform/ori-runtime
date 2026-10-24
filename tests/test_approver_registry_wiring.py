# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Where the approver registry's run context comes from.

A verified site is the signed configuration's `device.site_id`, or an unsigned
development configuration's own value; a hardened posture without a verified
signature has none. Only a verified configuration has a usable anchor, so only
it can apply a revocation. No phone channel is authenticated in this version.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.config import ConfigValidationError
from ori.config._device import parse_device as _parse_device
from ori.security.approvers.forms import spki_sha256
from ori.security.approvers.wiring import (
    PREVIOUS_PROVISIONING_ANCHOR_ENV,
    anchors_for,
    run_context_for,
    verified_site_for,
)
from ori.security.commissioning.anchors import COMMISSIONING_ANCHOR_ENV

ANCHOR_ENV = "ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64"


def _key(label: str) -> str:
    seed = label.encode().ljust(32, b".")
    raw = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return base64.b64encode(raw.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _config(
    *,
    site: str = "site-1",
    verified: bool = True,
    profile: str = "production",
    enforce: bool = False,
    device_id: str = "edge-1",
    policy_key: str = "",
) -> Any:
    return SimpleNamespace(
        device=SimpleNamespace(id=device_id, site_id=site, deployment_profile=profile),
        security={
            "config_signature": {"verified": verified, "trust_anchor_env": ANCHOR_ENV},
            "enforce_production_posture": enforce,
        },
        device_policy={"public_key_b64": policy_key},
    )


@pytest.mark.parametrize(
    ("config", "site"),
    [
        (_config(), "site-1"),
        (_config(verified=False, profile="development"), "site-1"),
        (_config(verified=False), None),
        (_config(verified=False, profile="staging"), None),
        (_config(verified=False, profile="development", enforce=True), None),
        (_config(site=""), None),
        (_config(device_id="d" * 128), "site-1"),
        (_config(device_id="d" * 129), None),
    ],
    ids=[
        "signed",
        "unsigned_development",
        "unsigned_production",
        "unsigned_staging",
        "unsigned_development_enforcing",
        "no_site",
        "device_id_at_the_registry_form",
        "device_id_past_the_registry_form",
    ],
)
def test_the_verified_site(config: Any, site: str | None) -> None:
    assert verified_site_for(config) == site


def test_only_a_verified_configuration_has_a_usable_anchor() -> None:
    env = {ANCHOR_ENV: _key("current")}
    assert anchors_for(_config(), env).usable()
    assert not anchors_for(_config(verified=False, profile="development"), env).usable()
    assert not anchors_for(_config(), {}).usable()


def test_every_other_configured_key_is_another_class_or_the_previous() -> None:
    env = {
        ANCHOR_ENV: _key("current"),
        PREVIOUS_PROVISIONING_ANCHOR_ENV: _key("previous"),
        COMMISSIONING_ANCHOR_ENV: _key("commissioning"),
    }
    anchors = anchors_for(_config(policy_key=_key("commercial")), env)
    assert anchors.usable()
    assert anchors.recognise(base64.b64decode(_key("previous"))) == "previous"
    assert anchors.recognise(base64.b64decode(_key("commissioning"))) == "other"
    assert anchors.recognise(base64.b64decode(_key("commercial"))) == "other"


@pytest.mark.parametrize(
    "env_or_policy",
    [
        {COMMISSIONING_ANCHOR_ENV: "not base64"},
        {PREVIOUS_PROVISIONING_ANCHOR_ENV: _key("current")},
        {"policy": _key("current")},
        {"ORI_DEVICE_POLICY_PUBLIC_KEY_B64": _key("current")},
    ],
    ids=[
        "malformed_other_anchor",
        "previous_is_current",
        "policy_key_is_current",
        "entitlement_env_is_current",
    ],
)
def test_an_anchor_set_that_cannot_be_told_apart_is_unusable(
    env_or_policy: dict[str, str],
) -> None:
    policy = env_or_policy.pop("policy", "")
    env = {ANCHOR_ENV: _key("current"), **env_or_policy}
    assert not anchors_for(_config(policy_key=policy), env).usable()


def test_no_phone_channel_is_authenticated_and_each_run_is_its_own() -> None:
    first = run_context_for(_config(), {})
    second = run_context_for(_config(), {})
    assert first.authenticated_phone_channels == frozenset()
    assert first.run_id != second.run_id


@pytest.mark.parametrize("site", ["site 1", "s" * 65, "site/1", "Sité"])
def test_a_site_id_outside_its_form_is_refused_at_load(site: str) -> None:
    with pytest.raises(ConfigValidationError):
        _parse_device({"id": "edge-1", "name": "n", "location": "l", "site_id": site})


def test_a_site_id_is_not_coerced() -> None:
    with pytest.raises(ConfigValidationError):
        _parse_device({"id": "edge-1", "name": "n", "location": "l", "site_id": 7})
    device = _parse_device({"id": "edge-1", "name": "n", "location": "l"})
    assert device.site_id == ""


def test_a_lan_credential_records_its_spki_digest() -> None:
    wire = json.loads(
        (
            Path(__file__).parent / "vectors" / "tier_c_approvers" / "transitions.json"
        ).read_text(encoding="utf-8")
    )["wire"]
    raw = base64.b64decode(wire["candidate_public_key_b64"])
    assert spki_sha256(raw) == wire["candidate_spki_sha256"]
