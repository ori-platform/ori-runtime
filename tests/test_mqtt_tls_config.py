# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""TLS material resolution for the MQTT adapter family.

Every spelling the runtime documents must reach `ssl`. A path that resolves to
nothing does not fail: the context falls back to the system trust store, so the
broker is verified against public CAs while the operator believes their private
one is in force.
"""

from __future__ import annotations

import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ori.hal.base import AdapterConnectionError
from ori.hal.mqtt_adapter import MqttAdapter

NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
CA_COMMON_NAME = "Ori Site Broker CA"


def _self_signed(common_name: str, *, is_ca: bool) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


@pytest.fixture
def ca_certfile(tmp_path: Path) -> Path:
    certificate, _ = _self_signed(CA_COMMON_NAME, is_ca=True)
    path = tmp_path / "site-ca.crt"
    path.write_bytes(certificate)
    return path


@pytest.fixture
def client_material(tmp_path: Path) -> tuple[Path, Path]:
    certificate, key = _self_signed("ori-runtime-01", is_ca=False)
    certfile = tmp_path / "client.crt"
    keyfile = tmp_path / "client.key"
    certfile.write_bytes(certificate)
    keyfile.write_bytes(key)
    return certfile, keyfile


def _trusted_common_names(context: ssl.SSLContext) -> list[str]:
    names = []
    for entry in context.get_ca_certs():
        for rdn in entry.get("subject", ()):
            for attribute, value in rdn:
                if attribute == "commonName":
                    names.append(value)
    return names


def _kwargs(config: dict) -> dict:
    return MqttAdapter()._build_mqtt_client_kwargs(config)


def _ca_configs(ca: str) -> dict[str, dict]:
    """Every spelling `ori.yaml.example` and the adapters accept for one CA."""
    return {
        "nested-under-mqtt-tls": {
            "mqtt": {"tls": {"enabled": True, "ca_certfile": ca}}
        },
        "flat-under-mqtt": {"mqtt": {"tls": {"enabled": True}, "tls_ca_certfile": ca}},
        "flat-on-the-sensor": {"mqtt_tls_enabled": True, "mqtt_tls_ca_certfile": ca},
        "short-flat-on-the-sensor": {"mqtt_tls_enabled": True, "tls_ca_certfile": ca},
    }


@pytest.mark.parametrize("spelling", list(_ca_configs("/unused").keys()))
def test_every_documented_ca_spelling_reaches_the_trust_store(
    spelling: str, ca_certfile: Path
) -> None:
    """The operator's CA is loaded, and it is the only one trusted."""
    context = _kwargs(_ca_configs(str(ca_certfile))[spelling])["tls_context"]

    assert _trusted_common_names(context) == [CA_COMMON_NAME]


def test_a_nested_client_certificate_path_is_read(
    tmp_path: Path, client_material: tuple[Path, Path]
) -> None:
    """Driven by absence: `ssl` exposes no way to read back a loaded chain."""
    _, keyfile = client_material

    with pytest.raises(AdapterConnectionError, match="invalid MQTT TLS configuration"):
        _kwargs(
            {
                "mqtt": {
                    "tls": {
                        "enabled": True,
                        "certfile": str(tmp_path / "absent.crt"),
                        "keyfile": str(keyfile),
                    }
                }
            }
        )


def test_a_nested_keyfile_that_does_not_match_its_certificate_is_refused(
    tmp_path: Path, client_material: tuple[Path, Path]
) -> None:
    certfile, _ = client_material
    _, other_key = _self_signed("someone-else", is_ca=False)
    mismatched = tmp_path / "other.key"
    mismatched.write_bytes(other_key)

    with pytest.raises(AdapterConnectionError, match="invalid MQTT TLS configuration"):
        _kwargs(
            {
                "mqtt": {
                    "tls": {
                        "enabled": True,
                        "certfile": str(certfile),
                        "keyfile": str(mismatched),
                    }
                }
            }
        )


def test_a_nested_ca_path_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    with pytest.raises(AdapterConnectionError, match="invalid MQTT TLS configuration"):
        _kwargs(
            {"mqtt": {"tls": {"enabled": True, "ca_certfile": str(tmp_path / "nope")}}}
        )


def test_two_spellings_of_one_trust_anchor_are_refused(
    ca_certfile: Path, tmp_path: Path
) -> None:
    """Choosing between two declared trust anchors decides which broker is believed."""
    other = tmp_path / "other-ca.crt"
    other.write_bytes(_self_signed("Other CA", is_ca=True)[0])

    with pytest.raises(AdapterConnectionError, match="mqtt.tls.ca_certfile"):
        _kwargs(
            {
                "mqtt_tls_enabled": True,
                "mqtt_tls_ca_certfile": str(ca_certfile),
                "mqtt": {"tls": {"ca_certfile": str(other)}},
            }
        )


def test_agreeing_spellings_are_refused_too(ca_certfile: Path) -> None:
    """Agreement today is not agreement after the next edit."""
    with pytest.raises(AdapterConnectionError, match="mqtt.tls.ca_certfile"):
        _kwargs(
            {
                "mqtt_tls_enabled": True,
                "mqtt_tls_ca_certfile": str(ca_certfile),
                "mqtt": {"tls": {"ca_certfile": str(ca_certfile)}},
            }
        )


def test_the_refusal_names_every_spelling_that_supplied_the_setting(
    ca_certfile: Path,
) -> None:
    with pytest.raises(AdapterConnectionError) as excinfo:
        _kwargs(
            {
                "mqtt_tls_enabled": True,
                "mqtt_tls_ca_certfile": str(ca_certfile),
                "tls_ca_certfile": str(ca_certfile),
                "mqtt": {"tls": {"ca_certfile": str(ca_certfile)}},
            }
        )

    message = str(excinfo.value)
    for spelling in ("mqtt.tls.ca_certfile", "mqtt_tls_ca_certfile", "tls_ca_certfile"):
        assert spelling in message


def test_an_alias_inside_the_mqtt_block_conflicts_with_the_canonical_one(
    ca_certfile: Path,
) -> None:
    """`mqtt.tls_ca_certfile` and `mqtt.tls.ca_certfile` are two spellings."""
    with pytest.raises(AdapterConnectionError, match="mqtt.tls.ca_certfile"):
        _kwargs(
            {
                "mqtt": {
                    "tls_ca_certfile": str(ca_certfile),
                    "tls": {"enabled": True, "ca_certfile": str(ca_certfile)},
                }
            }
        )


def test_an_alias_written_as_null_still_conflicts(ca_certfile: Path) -> None:
    """Presence is judged on the document as written."""
    with pytest.raises(AdapterConnectionError, match="mqtt.tls.ca_certfile"):
        _kwargs(
            {
                "mqtt_tls_ca_certfile": None,
                "mqtt": {"tls": {"enabled": True, "ca_certfile": str(ca_certfile)}},
            }
        )


def test_a_null_written_alone_is_left_to_value_handling(ca_certfile: Path) -> None:
    """One spelling is never a conflict; the schema layer refuses the null."""
    assert "tls_context" not in _kwargs({"mqtt_tls_ca_certfile": None})


def test_different_settings_in_different_spellings_do_not_conflict(
    ca_certfile: Path,
) -> None:
    """Only one setting written twice is a conflict, not two settings."""
    context = _kwargs(
        {
            "mqtt_tls_enabled": True,
            "mqtt": {"tls": {"ca_certfile": str(ca_certfile)}},
        }
    )["tls_context"]

    assert _trusted_common_names(context) == [CA_COMMON_NAME]


def test_nested_insecure_still_disables_verification() -> None:
    context = _kwargs({"mqtt": {"tls": {"enabled": True, "insecure": True}}})[
        "tls_context"
    ]

    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_material_declared_without_enabled_still_builds_a_context(
    ca_certfile: Path,
) -> None:
    """Declaring a CA is asking for TLS, whether or not `enabled` is written."""
    context = _kwargs({"mqtt": {"tls": {"ca_certfile": str(ca_certfile)}}})[
        "tls_context"
    ]

    assert _trusted_common_names(context) == [CA_COMMON_NAME]


def test_no_tls_configuration_builds_no_context() -> None:
    assert "tls_context" not in _kwargs({"broker_host": "192.168.1.50"})
