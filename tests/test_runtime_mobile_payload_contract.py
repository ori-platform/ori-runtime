# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "mobile" / "ori-runtime-mobile" / "src" / "main.rs"
CARGO = ROOT / "mobile" / "ori-runtime-mobile" / "Cargo.toml"
BUILD_SCRIPT = ROOT / "scripts" / "build-android-runtime-mobile.sh"
DOC = ROOT / "docs" / "android-runtime-mobile.md"
RUST_SUPPLY_CHAIN_GUARD = ROOT / "scripts" / "check_rust_supply_chain.sh"


def test_runtime_mobile_payload_contract_files_exist():
    assert SOURCE.exists()
    assert CARGO.exists()
    assert BUILD_SCRIPT.exists()
    assert DOC.exists()
    assert RUST_SUPPLY_CHAIN_GUARD.exists()


def test_runtime_mobile_payload_enforces_phone_authority_boundary():
    source = SOURCE.read_text()

    assert "device.deployment_type=phone" in source
    assert 'deployment_type != "phone"' in source
    assert "Tier C" not in source
    assert "Tier D" not in source


def test_runtime_mobile_payload_uses_runtime_telemetry_contract():
    source = SOURCE.read_text()

    assert "runtime.telemetry.v1" in source
    assert '"sensor.reading"' in source
    assert '"X-Ori-Device-Id"' in source
    assert '"X-Ori-Timestamp-Ms"' in source
    assert '"X-Ori-Signature"' in source
    assert 'format!("v1={signature}")' in source
    assert "Hmac<Sha256>" in source


def test_runtime_mobile_payload_requires_signed_config_without_embedded_secrets():
    source = SOURCE.read_text()
    cargo = CARGO.read_text()

    assert "ori.config_signature.v1" in source
    assert "ed25519" in source.lower()
    assert "ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64" in source
    assert "ORI_CONFIG_REQUIRE_SIGNED" in source
    assert "ed25519-dalek" in cargo
    assert "PRIVATE KEY" not in source
    assert "PAYSTACK" not in source


def test_runtime_mobile_payload_keeps_android_usb_permission_in_java_bridge():
    source = SOURCE.read_text()
    doc = DOC.read_text()

    assert "socket://" in source
    assert "Android USB permission must stay in the Java bridge" in source
    assert "Android owns USB permission" in doc
    assert "socket://127.0.0.1:7000" in doc


def test_android_runtime_payload_builds_all_release_abis():
    script = BUILD_SCRIPT.read_text()

    assert "arm64-v8a" in script
    assert "armeabi-v7a" in script
    assert "x86_64" in script
    assert "libori_runtime_exec.so" in script
    assert "cargo ndk" in script
    assert "--locked" in script
    assert 'grep -q "ELF"' in script


def test_rust_supply_chain_guard_checks_lockfile_and_forbidden_sources():
    guard = RUST_SUPPLY_CHAIN_GUARD.read_text()

    assert "Cargo.lock" in guard
    assert "checksum" in guard
    assert "forbidden git source" in guard
    assert "forbidden non-registry source" in guard
    assert "Android runtime payload build must use cargo --locked" in guard
