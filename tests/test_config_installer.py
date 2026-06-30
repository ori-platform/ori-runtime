# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import base64
import os
import textwrap
from pathlib import Path

import pytest
import yaml

from ori.config_installer import (
    ConfigInstallError,
    install_signed_config,
    main,
)
from ori.security.config_signatures import (
    CONFIG_SIGNATURE_SCHEMA,
    canonical_config_signature_payload,
)


def _ed25519_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return private_key, public_key_b64


def _sign_config_yaml(content: str, private_key) -> str:
    raw = yaml.safe_load(textwrap.dedent(content))
    raw["config_signature"] = {
        "schema": CONFIG_SIGNATURE_SCHEMA,
        "signer_id": "product-provisioning-test",
        "signed_at_ms": 1_800_000_000_000,
        "signature": "ed25519:",
    }
    signature = private_key.sign(canonical_config_signature_payload(raw))
    raw["config_signature"]["signature"] = "ed25519:" + base64.b64encode(
        signature
    ).decode("ascii")
    return yaml.safe_dump(raw, sort_keys=False)


def _minimal_config(device_id: str = "phone-01") -> str:
    return f"""
    device:
      id: {device_id}
      name: Phone Starter
      location: Lagos
      deployment_type: phone
    sensors: []
    skills: []
    reasoning: {{}}
    gateway:
      enabled: false
    actions:
      primary_alert_channel: sms
      operator_contact: "+2348012345678"
      sms:
        enabled: false
      relay:
        enabled: false
    security:
      config_signature:
        require_signed: true
      skills:
        require_signed: false
    """


def _write_signed_config(tmp_path: Path, monkeypatch, *, device_id: str = "phone-01"):
    private_key, public_key_b64 = _ed25519_keypair()
    monkeypatch.setenv("ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64", public_key_b64)
    source = tmp_path / "generated.yaml"
    source.write_text(
        _sign_config_yaml(_minimal_config(device_id), private_key),
        encoding="utf-8",
    )
    return source


def test_install_signed_config_writes_verified_config_atomically(tmp_path, monkeypatch):
    source = _write_signed_config(tmp_path, monkeypatch, device_id="phone-live-01")
    destination = tmp_path / "ori.yaml"

    result = install_signed_config(source=str(source), destination=destination)

    assert result.device_id == "phone-live-01"
    assert result.signer_id == "product-provisioning-test"
    assert result.signed_at_ms == 1_800_000_000_000
    assert result.dry_run is False
    assert destination.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")
    assert destination.stat().st_mode & 0o777 == 0o600


def test_install_signed_config_dry_run_verifies_without_writing(tmp_path, monkeypatch):
    source = _write_signed_config(tmp_path, monkeypatch)
    destination = tmp_path / "ori.yaml"

    result = install_signed_config(
        source=str(source),
        destination=destination,
        dry_run=True,
    )

    assert result.dry_run is True
    assert result.device_id == "phone-01"
    assert not destination.exists()


def test_install_signed_config_rejects_unsigned_generated_config(tmp_path):
    source = tmp_path / "generated.yaml"
    source.write_text(textwrap.dedent(_minimal_config()), encoding="utf-8")
    destination = tmp_path / "ori.yaml"
    destination.write_text("existing: true\n", encoding="utf-8")

    with pytest.raises(ConfigInstallError, match="missing config_signature"):
        install_signed_config(source=str(source), destination=destination)

    assert destination.read_text(encoding="utf-8") == "existing: true\n"


def test_install_signed_config_rejects_tampered_generated_config(tmp_path, monkeypatch):
    source = _write_signed_config(tmp_path, monkeypatch)
    source.write_text(
        source.read_text(encoding="utf-8").replace("location: Lagos", "location: X"),
        encoding="utf-8",
    )
    destination = tmp_path / "ori.yaml"

    with pytest.raises(ConfigInstallError, match="signature verification failed"):
        install_signed_config(source=str(source), destination=destination)

    assert not destination.exists()


def test_install_signed_config_requires_verified_signature_even_when_not_required(
    tmp_path, monkeypatch
):
    private_key, public_key_b64 = _ed25519_keypair()
    monkeypatch.setenv("ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64", public_key_b64)
    source = tmp_path / "generated.yaml"
    source.write_text(
        _sign_config_yaml(
            _minimal_config().replace("require_signed: true", "require_signed: false"),
            private_key,
        ),
        encoding="utf-8",
    )

    result = install_signed_config(
        source=str(source), destination=tmp_path / "ori.yaml"
    )

    assert result.signer_id == "product-provisioning-test"


def test_install_signed_config_rejects_non_https_remote_source(tmp_path):
    with pytest.raises(ConfigInstallError, match="remote generated configs"):
        install_signed_config(
            source="http://example.com/ori.yaml",
            destination=tmp_path / "ori.yaml",
        )


def test_install_signed_config_rejects_bearer_env_for_local_source(tmp_path):
    source = tmp_path / "generated.yaml"
    source.write_text("device: {}\n", encoding="utf-8")

    with pytest.raises(ConfigInstallError, match="only valid for URL"):
        install_signed_config(
            source=str(source),
            destination=tmp_path / "ori.yaml",
            bearer_token_env="ORI_PROVISIONING_TOKEN",
        )


def test_config_installer_cli_json_reports_verified_dry_run(
    tmp_path, monkeypatch, capsys
):
    source = _write_signed_config(tmp_path, monkeypatch, device_id="phone-cli-01")

    rc = main(
        [
            "--source",
            str(source),
            "--destination",
            str(tmp_path / "ori.yaml"),
            "--dry-run",
            "--json",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert '"ok": true' in captured.out
    assert '"device_id": "phone-cli-01"' in captured.out
    assert not (tmp_path / "ori.yaml").exists()


def test_config_installer_cli_error_returns_nonzero(tmp_path, capsys):
    source = tmp_path / "generated.yaml"
    source.write_text(textwrap.dedent(_minimal_config()), encoding="utf-8")

    rc = main(
        [
            "--source",
            str(source),
            "--destination",
            str(tmp_path / "ori.yaml"),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 2
    assert '"ok": false' in captured.out
    assert "missing config_signature" in captured.out
    assert not (tmp_path / "ori.yaml").exists()


def test_install_signed_config_replaces_existing_symlink_not_target(
    tmp_path, monkeypatch
):
    if not hasattr(os, "symlink"):
        pytest.skip("symlink not supported on this platform")
    source = _write_signed_config(tmp_path, monkeypatch)
    target = tmp_path / "target.yaml"
    target.write_text("target: true\n", encoding="utf-8")
    destination = tmp_path / "ori.yaml"
    destination.symlink_to(target)

    install_signed_config(source=str(source), destination=destination)

    assert destination.is_file()
    assert not destination.is_symlink()
    assert target.read_text(encoding="utf-8") == "target: true\n"
