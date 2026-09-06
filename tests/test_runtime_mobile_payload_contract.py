# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

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


def test_android_runtime_payload_pins_the_api_level():
    """cargo-ndk's default is its own to change; the payload's floor is not.

    The flag is `-P`. Lowercase `-p` reaches cargo as `--package` and fails
    with `unknown package`, which is why it is asserted rather than assumed.
    """
    script = BUILD_SCRIPT.read_text()

    assert '-P "${PLATFORM}"' in script
    assert "ORI_ANDROID_RUNTIME_PAYLOAD_PLATFORM" in script


def test_android_runtime_payload_refuses_what_the_apk_gate_refuses():
    """A payload the consuming APK would refuse must fail where it was built.

    The consuming release gate refuses a payload lacking ELF magic, carrying a
    shell interpreter line, or carrying the placeholder marker. Each is checked
    here so the failure names the toolchain that produced it rather than
    surfacing at packaging in another repository.
    """
    script = BUILD_SCRIPT.read_text()

    assert "7f454c46" in script
    assert "system/bin/sh" in script
    assert "ORI_ANDROID_RUNTIME_PAYLOAD_SHIM" in script


def test_android_runtime_payload_identifies_an_abi_by_elf_header():
    """The ABI is decided from the header, never from `file`'s prose.

    The prose nests: an arm64 binary is described "ARM aarch64", so a
    substring test for the 32-bit "ARM" accepts it. That puts an arm64 payload
    in the armeabi-v7a slot, where it packages cleanly and fails only once it
    reaches a 32-bit handset.
    """
    script = BUILD_SCRIPT.read_text()

    # EI_CLASS at offset 4, EI_DATA at 5, e_machine at 18.
    assert 'elf_byte "${path}" 4' in script
    assert 'elf_byte "${path}" 5' in script
    assert 'elf_byte "${path}" 18' in script
    assert "e_machine" in script

    # EM_AARCH64 183, EM_ARM 40, EM_X86_64 62, with the 64/32-bit class.
    assert 'build_one "arm64-v8a" "aarch64-linux-android" 2 183' in script
    assert 'build_one "armeabi-v7a" "armv7-linux-androideabi" 1 40' in script
    assert 'build_one "x86_64" "x86_64-linux-android" 2 62' in script

    # A guard reading the description would reintroduce the nesting.
    assert "want_arch" not in script


def test_android_runtime_payload_refuses_to_silently_skip_stripping():
    """An artefact must not differ from what the run was asked to produce.

    Stripping that quietly turns itself off when a tool is missing makes a
    reported size and digest describe a build nobody asked for. Absent tooling
    refuses; keeping symbols stays available, deliberately.
    """
    script = BUILD_SCRIPT.read_text()

    assert "ERROR: stripping was requested and no llvm-strip was found." in script
    assert "ORI_ANDROID_RUNTIME_PAYLOAD_STRIP=0" in script
    # cargo-ndk resolves its NDK from several variables and can build with
    # none of them set, so one variable is not where the toolchain lives.
    for variable in ("ANDROID_NDK_ROOT", "NDK_HOME", "ANDROID_SDK_ROOT"):
        assert variable in script
    # Reported per artefact rather than assumed for the run.
    assert "${abi}: ${symbols}" in script


def test_rust_supply_chain_guard_checks_lockfile_and_forbidden_sources():
    guard = RUST_SUPPLY_CHAIN_GUARD.read_text()

    assert "Cargo.lock" in guard
    assert "checksum" in guard
    assert "forbidden git source" in guard
    assert "forbidden non-registry source" in guard
    assert "Android runtime payload build must use cargo --locked" in guard


def _run_verifier(tmp_path, payload: bytes, want_class: int, want_machine: int):
    """Drive the script's own verifier over a payload, and report its verdict.

    The script's functions are extracted and executed rather than reimplemented,
    so this tests the shipped logic. A test that asserted only that the header
    offsets appear in the source would pass with every comparison removed.
    """
    import subprocess

    target = tmp_path / "payload.bin"
    target.write_bytes(payload)
    harness = tmp_path / "harness.sh"
    harness.write_text(
        "set -euo pipefail\n"
        f'eval "$(sed -n \'/^elf_byte()/,/^}}/p;/^verify_payload()/,/^}}/p\' "{BUILD_SCRIPT}")"\n'
        f'verify_payload "{target}" "{want_class}" "{want_machine}"\n'
    )
    return subprocess.run(
        ["bash", str(harness)], capture_output=True, text=True
    ).returncode


def _elf_header(elf_class: int, machine: int, *, data: int = 1) -> bytes:
    """The leading bytes of an ELF the verifier reads, and nothing more."""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = data
    header[18] = machine & 0xFF
    header[19] = (machine >> 8) & 0xFF
    return bytes(header)


AARCH64 = (2, 183)
ARM32 = (1, 40)
X86_64 = (2, 62)


@pytest.mark.parametrize(
    "payload_abi,slot_abi,accepted",
    [
        (AARCH64, AARCH64, True),
        (ARM32, ARM32, True),
        (X86_64, X86_64, True),
        # The reported bypass: `file` describes arm64 as "ARM aarch64", so a
        # substring test for the 32-bit "ARM" accepted it into this slot.
        (AARCH64, ARM32, False),
        (ARM32, AARCH64, False),
        (X86_64, AARCH64, False),
        (AARCH64, X86_64, False),
        (ARM32, X86_64, False),
        (X86_64, ARM32, False),
    ],
)
def test_the_verifier_accepts_only_its_own_abi(
    tmp_path, payload_abi, slot_abi, accepted
):
    """Every ABI substitution, in both directions."""
    rc = _run_verifier(tmp_path, _elf_header(*payload_abi), *slot_abi)
    assert (rc == 0) is accepted


@pytest.mark.parametrize(
    "payload,slot",
    [
        # The machine matches and only the class does not. No pair of the three
        # real ABIs differs this way, so without these the class check decides
        # nothing and could be removed unnoticed.
        ((1, 183), AARCH64),
        ((2, 40), ARM32),
        ((1, 62), X86_64),
    ],
)
def test_the_verifier_checks_the_elf_class_on_its_own(tmp_path, payload, slot):
    """A payload naming the right machine at the wrong width is still wrong."""
    assert _run_verifier(tmp_path, _elf_header(*payload), *slot) != 0


def test_the_verifier_refuses_a_payload_that_is_not_an_elf(tmp_path):
    assert _run_verifier(tmp_path, b"#!/system/bin/sh\nexit 0\n", *AARCH64) != 0


def test_the_verifier_refuses_a_big_endian_payload(tmp_path):
    """e_machine is read as two bytes, so its byte order has to be known."""
    assert _run_verifier(tmp_path, _elf_header(*AARCH64, data=2), *AARCH64) != 0


def test_the_verifier_refuses_an_elf_carrying_the_placeholder_marker(tmp_path):
    payload = _elf_header(*AARCH64) + b"ORI_ANDROID_RUNTIME_PAYLOAD_SHIM"
    assert _run_verifier(tmp_path, payload, *AARCH64) != 0


def test_the_verifier_refuses_an_elf_carrying_a_shell_interpreter_line(tmp_path):
    payload = _elf_header(*AARCH64) + b"#!/system/bin/sh\n"
    assert _run_verifier(tmp_path, payload, *AARCH64) != 0
