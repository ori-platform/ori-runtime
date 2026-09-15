# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Signed Android payload publication, held to the runtime-mobile/v2 corpus.

The corpus drives the reference verifier through every case, at the stage and
for the reason each records, and drives the producer too: its accepted
envelopes are what the producer makes from their seeds, and what it refuses at
the ABI and content stages the producer refuses to sign. The scripts are then
run through their entry points, since a verifier that crashes has not refused.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import runpy
import struct
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.android_payloads import (
    PUBLISHED_TEST_PUBLIC_KEYS,
    STAGES,
    TARGETS,
    AndroidPayloadError,
    PayloadBuild,
    canonical_signature_message,
    create_payload_envelope,
    encode_signature_envelope,
    inspect_payload_build,
    load_payload_key_registry,
    payload_artifact_name,
    read_staged_payload,
    sign_payload_fields,
    verify_payload,
)
from ori.security.release_bundles import SIGNATURE_DOMAIN as BUNDLE_DOMAIN
from ori.security.release_bundles import ReleaseKey, load_release_key_registry

ROOT = Path(__file__).resolve().parents[1]
VECTOR_DIR = ROOT / "tests" / "vectors" / "runtime_mobile_payload"
VECTOR_PATH = VECTOR_DIR / "payload-vectors-v2.json"
CORPUS = json.loads(VECTOR_PATH.read_text())
CASES: list[dict[str, Any]] = CORPUS["cases"]
REGISTRY_CASES: list[dict[str, Any]] = CORPUS["registry_cases"]
SHIPPED_REGISTRY = ROOT / "ori" / "installer" / "android-payload-keys.json"
BUNDLE_REGISTRY = ROOT / "ori" / "installer" / "release-keys.json"
VERSION = "2.6.0"


def _corpus_registry() -> dict[str, ReleaseKey]:
    """The corpus registry, built without the strict loader on purpose.

    It carries a release-bundle entry for the active key, which the loader
    refuses. Building the mapping directly is how the corpus proves that
    verification refuses that entry on its own rather than relying on load.
    """
    return {
        entry["key_id"]: ReleaseKey(
            key_id=entry["key_id"],
            public_key_b64=entry["public_key_b64"],
            purpose=entry["purpose"],
            status=entry["status"],
        )
        for entry in CORPUS["registry"]["keys"]
    }


def _artifact(case: dict[str, Any]) -> bytes | None:
    encoded = case["artifact_b64"]
    return None if encoded is None else base64.b64decode(encoded)


def test_the_vendored_corpus_is_the_pinned_bytes() -> None:
    manifest = json.loads((VECTOR_DIR / "MANIFEST.json").read_text())
    assert manifest["source_repository"] == "ori-platform/ori-specs"
    assert len(manifest["source_commit"]) == 40 and all(
        char in "0123456789abcdef" for char in manifest["source_commit"]
    ), "the corpus must be vendored from a commit on ori-specs main"
    recorded = manifest["files"][VECTOR_PATH.name]
    assert hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest() == recorded, (
        "the vendored corpus has been edited locally; re-vendor it from ori-specs"
    )


def test_the_corpus_and_the_verifier_name_the_same_stages() -> None:
    assert tuple(CORPUS["acceptance_order"]) == STAGES


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_every_corpus_case_reaches_its_recorded_outcome(case: dict[str, Any]) -> None:
    expect = case["expect"]

    def run() -> object:
        return verify_payload(
            envelope_text=case["envelope_text"],
            registry=_corpus_registry(),
            artifact=_artifact(case),
            downloaded_basename=case["downloaded_basename"],
            runtime_version=case["selected_runtime_version"],
            target=case["slot_target"],
        )

    if expect["outcome"] == "accept":
        verified = run()
        assert verified is not None
        return

    with pytest.raises(AndroidPayloadError) as refused:
        run()
    assert (refused.value.stage, refused.value.reason) == (
        expect["stage"],
        expect["reason"],
    ), f"{case['name']}: {case['note']}\ngot {refused.value}"


def test_every_stage_is_exercised_by_the_corpus() -> None:
    stopped = {
        c["expect"].get("stage") for c in CASES if c["expect"]["outcome"] == "reject"
    }
    assert stopped == set(STAGES)


@pytest.mark.parametrize(
    "case", REGISTRY_CASES, ids=[c["name"] for c in REGISTRY_CASES]
)
def test_every_registry_case_loads_or_is_refused_as_recorded(
    case: dict[str, Any],
) -> None:
    text = case["registry_text"].encode("utf-8")
    if case["expect"] == "load":
        assert load_payload_key_registry(text)
        return
    with pytest.raises(AndroidPayloadError) as refused:
        load_payload_key_registry(text)
    assert refused.value.reason == "untrusted_release_key"


def test_the_refused_test_keys_are_exactly_the_corpus_keys() -> None:
    """A key the corpus publishes and the loader admits is a forgery anyone can make."""
    assert set(CORPUS["known_test_public_keys_b64"]) == PUBLISHED_TEST_PUBLIC_KEYS


def test_the_payload_key_is_the_release_key_under_its_own_purpose_and_id() -> None:
    """The contract permits one key under two purposes, never one entry for both."""
    payload = load_payload_key_registry(SHIPPED_REGISTRY)
    bundle = load_release_key_registry(BUNDLE_REGISTRY)
    assert set(payload).isdisjoint(bundle), (
        "a key_id is shared across the two registries"
    )
    bundle_keys = {key.public_key_b64 for key in bundle.values()}
    for key in payload.values():
        assert key.purpose == "android_runtime_payload"
        assert key.public_key_b64 in bundle_keys


def test_a_mapping_whose_entry_names_another_key_id_is_not_trusted() -> None:
    case = next(c for c in CASES if c["name"] == "accept_android-arm64-v8a-api21")
    registry = _corpus_registry()
    active = registry["ori-test-android-payload-active"]
    registry["ori-test-android-payload-active"] = ReleaseKey(
        key_id="another-key",
        public_key_b64=active.public_key_b64,
        purpose=active.purpose,
        status=active.status,
    )
    with pytest.raises(AndroidPayloadError) as refused:
        verify_payload(
            envelope_text=case["envelope_text"],
            registry=registry,
            artifact=_artifact(case),
            downloaded_basename=case["downloaded_basename"],
            runtime_version=case["selected_runtime_version"],
            target=case["slot_target"],
        )
    assert refused.value.reason == "untrusted_release_key"


# --- inputs that crash a parser rather than failing a rule --------------------


def _accepted() -> dict[str, Any]:
    return next(c for c in CASES if c["name"] == "accept_android-arm64-v8a-api21")


@pytest.mark.parametrize(
    "envelope_text",
    [
        '{"artifact_size": ' + "9" * 5000 + "}",
        '{"stripped": ' + "[" * 30000 + "]" * 30000 + "}",
        '{"artifact": "\udc80"}',
        b'{"artifact": "\xff"}',
    ],
    ids=["long_integer", "deep_nesting", "raw_surrogate_str", "invalid_utf8"],
)
def test_hostile_envelopes_are_refused_not_raised(envelope_text: str | bytes) -> None:
    case = _accepted()
    with pytest.raises(AndroidPayloadError) as refused:
        verify_payload(
            envelope_text=envelope_text,
            registry=_corpus_registry(),
            artifact=_artifact(case),
            downloaded_basename=case["downloaded_basename"],
            runtime_version=case["selected_runtime_version"],
            target=case["slot_target"],
        )
    assert refused.value.stage == "envelope"


def test_a_registry_status_that_is_not_a_string_is_refused_not_raised() -> None:
    document = json.loads(SHIPPED_REGISTRY.read_text())
    document["keys"][0]["status"] = ["active"]
    with pytest.raises(AndroidPayloadError):
        load_payload_key_registry(json.dumps(document).encode())


# --- the verify CLI ------------------------------------------------------------

_CLI_TARGET = "android-arm64-v8a-api21"


def _cli_inputs(tmp_path: Path) -> dict[str, Path]:
    """A payload the producer signed, its envelope, and a registry trusting it."""
    image = _built_elf(_CLI_TARGET)
    name = payload_artifact_name(VERSION, _CLI_TARGET)
    envelope = _create(target=_CLI_TARGET, artifact=image)
    key = _PRODUCER_REGISTRY["ori-test-producer"]
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": key.key_id,
                        "public_key_b64": key.public_key_b64,
                        "purpose": key.purpose,
                        "status": key.status,
                    }
                ],
                "schema": "ori.android_runtime_payload_keys.v1",
            }
        )
    )
    (tmp_path / name).write_bytes(image)
    signature = tmp_path / f"{name}.signature.json"
    signature.write_bytes(encode_signature_envelope(envelope))
    return {"registry": registry, "artifact": tmp_path / name, "signature": signature}


def _verify_cli(inputs: dict[str, Path]) -> int:
    script = runpy.run_path(str(ROOT / "scripts" / "verify-android-runtime-payload.py"))
    return script["main"](
        [
            "--artifact",
            str(inputs["artifact"]),
            "--signature",
            str(inputs["signature"]),
            "--runtime-version",
            VERSION,
            "--target",
            _CLI_TARGET,
            "--key-registry",
            str(inputs["registry"]),
        ]
    )


def test_the_verify_cli_accepts_a_signed_payload(tmp_path: Path) -> None:
    assert _verify_cli(_cli_inputs(tmp_path)) == 0


@pytest.mark.parametrize(
    "envelope_text",
    [
        '{"artifact_size": ' + "9" * 5000 + "}",
        '{"stripped": ' + "[" * 30000 + "]" * 30000 + "}",
        "not json",
    ],
    ids=["long_integer", "deep_nesting", "not_json"],
)
def test_the_verify_cli_exits_2_on_hostile_envelopes(
    tmp_path: Path, envelope_text: str
) -> None:
    inputs = _cli_inputs(tmp_path)
    inputs["signature"].write_text(envelope_text)
    assert _verify_cli(inputs) == 2


def test_the_verify_cli_refuses_a_registry_holding_a_published_test_key(
    tmp_path: Path,
) -> None:
    inputs = _cli_inputs(tmp_path)
    published = next(
        c for c in REGISTRY_CASES if c["name"] == "refuse_published_active_test_key"
    )
    inputs["registry"].write_text(published["registry_text"])
    assert _verify_cli(inputs) == 2


def test_the_verify_cli_refuses_a_missing_payload_as_absent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inputs = _cli_inputs(tmp_path)
    inputs["artifact"].unlink()
    assert _verify_cli(inputs) == 2
    assert "presence/invalid_artifact" in capsys.readouterr().err


def test_the_verify_cli_exits_2_when_the_payload_is_a_directory(
    tmp_path: Path,
) -> None:
    inputs = _cli_inputs(tmp_path)
    inputs["artifact"].unlink()
    inputs["artifact"].mkdir()
    assert _verify_cli(inputs) == 2


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads anything"
)
def test_the_verify_cli_exits_2_when_the_payload_is_unreadable(
    tmp_path: Path,
) -> None:
    inputs = _cli_inputs(tmp_path)
    inputs["artifact"].chmod(0)
    try:
        assert _verify_cli(inputs) == 2
    finally:
        inputs["artifact"].chmod(0o600)


# --- the producer, driven by the corpus ---------------------------------------


def _corpus_signer(key_id: str) -> Any:
    public = next(
        e["public_key_b64"] for e in CORPUS["registry"]["keys"] if e["key_id"] == key_id
    )
    seed = next(
        k["test_seed_hex"]
        for k in CORPUS["test_keys"].values()
        if k["public_key_b64"] == public
    )
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).sign


@pytest.mark.parametrize(
    "case",
    [c for c in CASES if c["expect"]["outcome"] == "accept"],
    ids=[c["name"] for c in CASES if c["expect"]["outcome"] == "accept"],
)
def test_the_producer_reproduces_every_accepted_envelope(case: dict[str, Any]) -> None:
    recorded = json.loads(case["envelope_text"])
    artifact = _artifact(case)
    assert artifact is not None
    produced = sign_payload_fields(
        artifact=artifact,
        runtime_version=recorded["runtime_version"],
        target=recorded["target"],
        key_id=recorded["key_id"],
        stripped=recorded["stripped"],
        signer=_corpus_signer(recorded["key_id"]),
    )
    assert produced == recorded


_BYTE_STAGES = {"abi", "content"}


@pytest.mark.parametrize(
    "case",
    [c for c in CASES if c["expect"].get("stage") in _BYTE_STAGES],
    ids=[c["name"] for c in CASES if c["expect"].get("stage") in _BYTE_STAGES],
)
def test_the_producer_refuses_what_the_corpus_refuses_in_the_bytes(
    case: dict[str, Any],
) -> None:
    artifact = _artifact(case)
    assert artifact is not None
    signed: list[bytes] = []
    with pytest.raises(AndroidPayloadError) as refused:
        sign_payload_fields(
            artifact=artifact,
            runtime_version=case["selected_runtime_version"],
            target=case["slot_target"],
            key_id="ori-test-producer",
            stripped=True,
            signer=lambda message: signed.append(message) or bytes(64),
        )
    assert (refused.value.stage, refused.value.reason) == (
        case["expect"]["stage"],
        case["expect"]["reason"],
    )
    assert signed == []


# --- the producer, on built images --------------------------------------------

# Generated rather than seeded: a seed committed here would be a published seed,
# and the rule a registry is held to is that it holds none.
_PRODUCER_KEY = Ed25519PrivateKey.generate()
_PRODUCER_REGISTRY = {
    "ori-test-producer": ReleaseKey(
        key_id="ori-test-producer",
        public_key_b64=base64.b64encode(
            _PRODUCER_KEY.public_key().public_bytes_raw()
        ).decode(),
        purpose="android_runtime_payload",
        status="active",
    )
}


def _android_note(api_level: int) -> bytes:
    name = b"Android\0"
    desc = struct.pack("<I", api_level) + bytes(128)
    return struct.pack("<III", len(name), len(desc), 1) + name + desc


def _section_offset(image: bytes, index: int) -> int:
    """Where one section header entry starts, for corrupting exactly one field."""
    shoff = struct.unpack_from("<Q", image, 40)[0]
    entry_size = struct.unpack_from("<H", image, 58)[0]
    return int(shoff + index * entry_size)


def _built_elf(
    target: str,
    *,
    api_level: int | None = 21,
    note: bytes | None = None,
    sections: tuple[str, ...] = (),
    extra: bytes = b"",
) -> bytes:
    """An ELF image with a real section table, as a linker writes one."""
    ei_class, machine = TARGETS[target]
    wide = ei_class == 2
    header_size, entry_size = (64, 64) if wide else (52, 40)
    contents: list[tuple[str, bytes]] = [("", b"")]
    if api_level is not None:
        note = _android_note(api_level)
    if note is not None:
        contents.append((".note.android.ident", note))
    contents.extend((name, b"\0" * 16) for name in sections)
    contents.append((".text", extra + bytes(range(256)) * 4))
    names = b"\0"
    name_offsets = []
    for name, _ in contents:
        if name:
            name_offsets.append(len(names))
            names += name.encode() + b"\0"
        else:
            name_offsets.append(0)
    shstrtab_name = len(names)
    names += b".shstrtab\0"
    contents.append((".shstrtab", names))
    name_offsets.append(shstrtab_name)

    body = b""
    placed = []
    for _, data in contents:
        placed.append((header_size + len(body), len(data)))
        body += data
    shoff = header_size + len(body)
    table = b""
    for index, (offset, size) in enumerate(placed):
        kind = 0 if index == 0 else 1
        if wide:
            table += struct.pack(
                "<IIQQQQIIQQ", name_offsets[index], kind, 0, 0, offset, size, 0, 0, 1, 0
            )
        else:
            table += struct.pack(
                "<IIIIIIIIII", name_offsets[index], kind, 0, 0, offset, size, 0, 0, 1, 0
            )
    ident = b"\x7fELF" + bytes([ei_class, 1, 1, 0]) + bytes(8)
    if wide:
        header = ident + struct.pack(
            "<HHIQQQIHHHHHH",
            3,
            machine,
            1,
            0,
            0,
            shoff,
            0,
            64,
            0,
            0,
            entry_size,
            len(contents),
            len(contents) - 1,
        )
    else:
        header = ident + struct.pack(
            "<HHIIIIIHHHHHH",
            3,
            machine,
            1,
            0,
            0,
            shoff,
            0,
            52,
            0,
            0,
            entry_size,
            len(contents),
            len(contents) - 1,
        )
    assert len(header) == header_size
    return header + body + table


def _create(**overrides: Any) -> dict[str, Any]:
    target = overrides.pop("target", "android-arm64-v8a-api21")
    version = overrides.pop("runtime_version", VERSION)
    shape = target if target in TARGETS else "android-arm64-v8a-api21"
    arguments: dict[str, Any] = {
        "artifact": _built_elf(shape),
        "artifact_name": payload_artifact_name(version, target),
        "runtime_version": version,
        "target": target,
        "key_id": "ori-test-producer",
        "signer": _PRODUCER_KEY.sign,
        "require_stripped": True,
    }
    arguments.update(overrides)
    return create_payload_envelope(**arguments)


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_what_the_producer_signs_a_consumer_accepts(target: str) -> None:
    artifact = _built_elf(target)
    envelope = _create(target=target, artifact=artifact)
    verified = verify_payload(
        envelope_text=encode_signature_envelope(envelope),
        registry=_PRODUCER_REGISTRY,
        artifact=artifact,
        downloaded_basename=payload_artifact_name(VERSION, target),
        runtime_version=VERSION,
        target=target,
    )
    assert verified.target == target
    assert verified.artifact_size == len(artifact)
    assert verified.stripped is True


@pytest.mark.parametrize(
    ("sections", "stripped"),
    [
        ((), True),
        ((".symtab",), False),
        ((".debug_info",), False),
        ((".dynsym",), True),
    ],
    ids=["none", "symtab", "debug_info", "dynsym_only"],
)
def test_the_strip_state_is_measured_from_the_sections(
    sections: tuple[str, ...], stripped: bool
) -> None:
    artifact = _built_elf("android-armeabi-v7a-api21", sections=sections)
    assert inspect_payload_build(artifact).stripped is stripped
    envelope = _create(
        target="android-armeabi-v7a-api21", artifact=artifact, require_stripped=False
    )
    assert envelope["stripped"] is stripped


@pytest.mark.parametrize(
    ("overrides", "stage", "reason"),
    [
        ({"artifact": _built_elf("android-x86_64-api21")}, "abi", "unsupported_target"),
        (
            {
                "artifact": _built_elf(
                    "android-arm64-v8a-api21", extra=b"#!/system/bin/sh\n"
                )
            },
            "content",
            "invalid_artifact",
        ),
        (
            {
                "artifact": _built_elf(
                    "android-arm64-v8a-api21", extra=b"ORI_ANDROID_RUNTIME_PAYLOAD_SHIM"
                )
            },
            "content",
            "invalid_artifact",
        ),
        ({"artifact": b""}, "presence", "invalid_artifact"),
        (
            {"artifact": _built_elf("android-arm64-v8a-api21", api_level=24)},
            "abi",
            "unsupported_target",
        ),
        (
            {"artifact": _built_elf("android-arm64-v8a-api21", api_level=18)},
            "abi",
            "unsupported_target",
        ),
        (
            {"artifact": _built_elf("android-arm64-v8a-api21", api_level=None)},
            "abi",
            "unsupported_target",
        ),
        (
            {"artifact": _built_elf("android-arm64-v8a-api21", sections=(".symtab",))},
            "content",
            "invalid_artifact",
        ),
        (
            {"artifact_name": "libori_runtime_exec.so"},
            "artifact_name",
            "artifact_integrity_mismatch",
        ),
        (
            {"target": "android-riscv64-api21", "artifact_name": "x.so"},
            "identity",
            "unsupported_target",
        ),
        ({"runtime_version": "v2.6.0"}, "envelope", "invalid_signature_envelope"),
        ({"key_id": "ori/producer"}, "envelope", "invalid_signature_envelope"),
    ],
    ids=[
        "wrong_abi",
        "shell_line",
        "placeholder",
        "empty",
        "api_level_above_the_target",
        "api_level_below_the_target",
        "no_api_note",
        "unstripped_when_required",
        "wrong_name",
        "unknown_target",
        "bad_version",
        "bad_key_id",
    ],
)
def test_the_producer_refuses_to_sign_what_a_release_must_not_publish(
    overrides: dict[str, Any], stage: str, reason: str
) -> None:
    signed: list[bytes] = []

    def signer(message: bytes) -> bytes:
        signed.append(message)
        return _PRODUCER_KEY.sign(message)

    with pytest.raises(AndroidPayloadError) as refused:
        _create(signer=signer, **overrides)
    assert (refused.value.stage, refused.value.reason) == (stage, reason)
    assert signed == [], "nothing reached the signer"


def test_the_producer_refuses_a_payload_above_the_size_ceiling() -> None:
    artifact = _built_elf("android-arm64-v8a-api21") + bytes(64 * 1024 * 1024)
    with pytest.raises(AndroidPayloadError) as refused:
        _create(artifact=artifact)
    assert refused.value.stage == "integrity"


@pytest.mark.parametrize("length", [0, 63, 65])
def test_the_producer_refuses_a_signer_that_does_not_return_64_bytes(
    length: int,
) -> None:
    with pytest.raises(AndroidPayloadError) as refused:
        _create(signer=lambda message: bytes(length))
    assert refused.value.reason == "invalid_signature"


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda image: image[:40] + struct.pack("<Q", 1 << 40) + image[48:],
        lambda image: image[:62] + struct.pack("<H", 0xFFFF) + image[64:],
    ],
    ids=["section_table_offset_past_the_end", "name_table_index_out_of_range"],
)
def test_a_section_table_outside_the_image_is_refused_not_guessed(corrupt: Any) -> None:
    image = corrupt(_built_elf("android-arm64-v8a-api21"))
    with pytest.raises(AndroidPayloadError) as refused:
        inspect_payload_build(image)
    assert refused.value.stage == "abi"


@pytest.mark.parametrize(
    ("corrupt", "what"),
    [
        (
            lambda i: i[:58] + struct.pack("<H", 8) + i[60:],
            "section entry size below the ELF minimum",
        ),
        (
            lambda i: i[:40] + struct.pack("<Q", 1 << 40) + i[48:],
            "section table past the end",
        ),
        (
            lambda i: i[:62] + struct.pack("<H", 0xFFFF) + i[64:],
            "name table index out of range",
        ),
        (lambda i: i[:40], "truncated ELF header"),
        (
            lambda i: (
                i[: _section_offset(i, 1) + 24]
                + struct.pack("<Q", 1 << 40)
                + i[_section_offset(i, 1) + 32 :]
            ),
            "section contents past the end",
        ),
        (
            lambda i: (
                i[: _section_offset(i, 1)]
                + struct.pack("<I", 1 << 24)
                + i[_section_offset(i, 1) + 4 :]
            ),
            "section name past the name table",
        ),
    ],
    ids=[
        "entry_size",
        "table_offset",
        "name_table_index",
        "truncated_header",
        "contents_offset",
        "name_offset",
    ],
)
def test_a_hostile_section_table_is_refused_rather_than_read(
    corrupt: Any, what: str
) -> None:
    image = corrupt(_built_elf("android-arm64-v8a-api21"))
    with pytest.raises(AndroidPayloadError) as refused:
        inspect_payload_build(image)
    assert refused.value.stage == "abi", what


def test_an_image_with_no_section_table_records_no_api_level() -> None:
    """A section-table-less image is not malformed; it just says nothing."""
    image = _built_elf("android-arm64-v8a-api21")
    stripped_table = image[:40] + bytes(8) + image[48:]
    assert inspect_payload_build(stripped_table) == PayloadBuild(
        api_level=None, stripped=True
    )
    with pytest.raises(AndroidPayloadError) as refused:
        _create(artifact=stripped_table)
    assert refused.value.stage == "abi"


@pytest.mark.parametrize(
    ("note", "api_level"),
    [
        (lambda: _android_note(21), 21),
        (lambda: _android_note(21)[:-1], None),
        (lambda: struct.pack("<III", 8, 132, 1) + b"Linux\0\0\0" + bytes(132), None),
        (lambda: struct.pack("<III", 8, 132, 2) + b"Android\0" + bytes(132), None),
        (lambda: struct.pack("<III", 8, 2, 1) + b"Android\0" + bytes(2), None),
        (lambda: struct.pack("<III", 8, 132, 1) + b"Android\0", None),
        (
            lambda: (
                struct.pack("<III", 5, 4, 1)
                + b"Note\0\0\0\0"
                + bytes(4)
                + _android_note(21)
            ),
            21,
        ),
    ],
    ids=[
        "android_note",
        "truncated_descriptor",
        "another_owner",
        "another_type",
        "descriptor_too_short",
        "descriptor_absent",
        "second_note_after_a_padded_one",
    ],
)
def test_the_api_level_is_read_only_from_a_whole_android_note(
    note: Any, api_level: int | None
) -> None:
    image = _built_elf("android-arm64-v8a-api21", api_level=None, note=note())
    assert inspect_payload_build(image).api_level == api_level


def test_a_staged_payload_that_is_a_symlink_is_refused(tmp_path: Path) -> None:
    target = "android-arm64-v8a-api21"
    name = payload_artifact_name(VERSION, target)
    _stage(tmp_path / "real", VERSION, {target: _built_elf(target)})
    (tmp_path / name).symlink_to(tmp_path / "real" / name)
    (tmp_path / f"{name}.sha256").write_text(
        (tmp_path / "real" / f"{name}.sha256").read_text()
    )
    with pytest.raises(AndroidPayloadError) as refused:
        read_staged_payload(tmp_path, name)
    assert refused.value.stage == "presence"


def _signed_envelope(payload: bytes, **overrides: Any) -> bytes:
    """An envelope signed over fields the producer would not have built."""
    artifact = payload
    target = overrides.pop("target", "android-arm64-v8a-api21")
    fields: dict[str, Any] = {
        "artifact": payload_artifact_name(VERSION, target),
        "artifact_sha256": "sha256:" + hashlib.sha256(artifact).hexdigest(),
        "artifact_size": len(artifact),
        "key_id": "ori-test-producer",
        "runtime_version": VERSION,
        "schema": "ori.android_runtime_payload_signature.v1",
        "stripped": True,
        "target": target,
    }
    fields.update(overrides)
    signature = _PRODUCER_KEY.sign(canonical_signature_message(fields))
    fields["signature"] = "ed25519:" + base64.b64encode(signature).decode()
    return encode_signature_envelope(fields)


@pytest.mark.parametrize("length", [255, 256])
def test_the_artifact_name_length_bound_is_the_contracts(length: int) -> None:
    name = "a" * (length - len(".so")) + ".so"
    with pytest.raises(AndroidPayloadError) as refused:
        verify_payload(
            envelope_text=_signed_envelope(
                _built_elf("android-arm64-v8a-api21"), artifact=name
            ),
            registry=_PRODUCER_REGISTRY,
            artifact=_built_elf("android-arm64-v8a-api21"),
            downloaded_basename=name,
            runtime_version=VERSION,
            target="android-arm64-v8a-api21",
        )
    # 255 characters is a form the envelope admits, so it reaches the name
    # comparison; 256 is not a plain filename at all.
    expected = "artifact_name" if length == 255 else "envelope"
    assert refused.value.stage == expected


def test_a_payload_signature_does_not_verify_as_a_bundle_signature() -> None:
    """The domain separator is what keeps the two protocols apart."""
    message = canonical_signature_message(_create())
    assert message.startswith(b"ori.android_runtime_payload_signature.v1\0")
    assert not message.startswith(BUNDLE_DOMAIN)


# --- the signing CLI, with KMS replaced -----------------------------------------

_KMS_ARN = "arn:aws:kms:eu-west-1:111122223333:key/12345678-1234-1234-1234-1234567890ab"


def _stage(directory: Path, version: str, images: dict[str, bytes]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for target, image in images.items():
        name = payload_artifact_name(version, target)
        (directory / name).write_bytes(image)
        digest = hashlib.sha256(image).hexdigest()
        (directory / f"{name}.sha256").write_text(f"{digest}  {name}\n")


def _signing_cli(
    tmp_path: Path, *, fail_on_call: int | None = None
) -> tuple[dict[str, Any], Path, list[str]]:
    script = runpy.run_path(
        str(ROOT / "scripts" / "sign-android-runtime-payload-aws-kms.py")
    )
    calls: list[str] = []

    class FakeSigner:
        def __init__(self, **kwargs: Any) -> None:
            assert kwargs["key_arn"] == _KMS_ARN

        def validate_identity(self) -> None:
            calls.append("validate")

        def sign(self, message: bytes) -> bytes:
            calls.append("sign")
            if fail_on_call is not None and calls.count("sign") == fail_on_call:
                from ori.security.release_bundles import ReleaseBundleError

                raise ReleaseBundleError("signing_failed", "KMS refused")
            return _PRODUCER_KEY.sign(message)

    script["AwsKmsReleaseSigner"] = FakeSigner
    main_globals = script["main"].__globals__
    main_globals["AwsKmsReleaseSigner"] = FakeSigner
    main_globals["load_payload_key_registry"] = lambda path: _PRODUCER_REGISTRY
    return script, tmp_path / "payloads", calls


def _sign_cli(script: dict[str, Any], directory: Path) -> int:
    return script["main"](
        [
            "--payload-dir",
            str(directory),
            "--runtime-version",
            VERSION,
            "--key-id",
            "ori-test-producer",
            "--key-registry",
            "unused.json",
            "--kms-key-arn",
            _KMS_ARN,
            "--aws-region",
            "eu-west-1",
        ]
    )


def _all_targets() -> dict[str, bytes]:
    return {target: _built_elf(target) for target in TARGETS}


def test_the_signing_cli_signs_the_complete_set(tmp_path: Path) -> None:
    script, directory, calls = _signing_cli(tmp_path)
    _stage(directory, VERSION, _all_targets())
    assert _sign_cli(script, directory) == 0
    assert calls[0] == "validate" and calls.count("sign") == len(TARGETS)
    for target in TARGETS:
        name = payload_artifact_name(VERSION, target)
        verify_payload(
            envelope_text=(directory / f"{name}.signature.json").read_bytes(),
            registry=_PRODUCER_REGISTRY,
            artifact=(directory / name).read_bytes(),
            downloaded_basename=name,
            runtime_version=VERSION,
            target=target,
        )


def _no_envelopes(directory: Path) -> bool:
    return not list(directory.glob("*.signature.json"))


@pytest.mark.parametrize(
    "fault",
    ["missing_target", "checksum_mismatch", "unstripped", "wrong_api", "extra_space"],
)
def test_the_signing_cli_writes_nothing_unless_every_target_signs(
    tmp_path: Path, fault: str
) -> None:
    script, directory, _ = _signing_cli(tmp_path)
    images = _all_targets()
    armv7 = "android-armeabi-v7a-api21"
    if fault == "unstripped":
        images[armv7] = _built_elf(armv7, sections=(".symtab",))
    if fault == "wrong_api":
        images[armv7] = _built_elf(armv7, api_level=23)
    _stage(directory, VERSION, images)
    name = payload_artifact_name(VERSION, armv7)
    if fault == "missing_target":
        (directory / name).unlink()
    if fault == "checksum_mismatch":
        (directory / name).write_bytes(images[armv7] + b"\0")
    if fault == "extra_space":
        text = (directory / f"{name}.sha256").read_text()
        (directory / f"{name}.sha256").write_text(text.replace("  ", "   "))
    assert _sign_cli(script, directory) == 2
    assert _no_envelopes(directory)


def test_the_signing_cli_writes_nothing_when_kms_fails_part_way(tmp_path: Path) -> None:
    script, directory, _ = _signing_cli(tmp_path, fail_on_call=3)
    _stage(directory, VERSION, _all_targets())
    assert _sign_cli(script, directory) == 2
    assert _no_envelopes(directory)


def test_the_signing_cli_refuses_a_key_that_is_not_active(tmp_path: Path) -> None:
    script, directory, calls = _signing_cli(tmp_path)
    _stage(directory, VERSION, _all_targets())
    key = _PRODUCER_REGISTRY["ori-test-producer"]
    script["main"].__globals__["load_payload_key_registry"] = lambda path: {
        key.key_id: ReleaseKey(
            key_id=key.key_id,
            public_key_b64=key.public_key_b64,
            purpose=key.purpose,
            status="verify_only",
        )
    }
    assert _sign_cli(script, directory) == 2
    assert calls == [] and _no_envelopes(directory)


# --- fetching and verifying a published payload -------------------------------


def _published_verifier(tmp_path: Path) -> dict[str, Any]:
    script = runpy.run_path(str(ROOT / "scripts" / "verify_published_release.py"))
    script["verify_android_payload"].__globals__["load_payload_key_registry"] = (
        lambda path: _PRODUCER_REGISTRY
    )
    return script


def _stage_signed(directory: Path) -> None:
    _stage(directory, VERSION, _all_targets())
    for target in TARGETS:
        name = payload_artifact_name(VERSION, target)
        envelope = create_payload_envelope(
            artifact=(directory / name).read_bytes(),
            artifact_name=name,
            runtime_version=VERSION,
            target=target,
            key_id="ori-test-producer",
            signer=_PRODUCER_KEY.sign,
        )
        (directory / f"{name}.signature.json").write_bytes(
            encode_signature_envelope(envelope)
        )


def _published_main(script: dict[str, Any], directory: Path, *targets: str) -> int:
    arguments = ["--version", VERSION, "--from-staged", "--workspace", str(directory)]
    for target in targets:
        arguments += ["--android-target", target]
    return script["main"](arguments)


def test_published_verification_accepts_every_signed_payload(tmp_path: Path) -> None:
    script = _published_verifier(tmp_path)
    _stage_signed(tmp_path)
    assert _published_main(script, tmp_path, *TARGETS) == 0


@pytest.mark.parametrize("fault", ["no_envelope", "no_checksum", "tampered", "unknown"])
def test_published_verification_refuses_with_exit_2(tmp_path: Path, fault: str) -> None:
    script = _published_verifier(tmp_path)
    _stage_signed(tmp_path)
    target = "android-x86_64-api21"
    name = payload_artifact_name(VERSION, target)
    if fault == "no_envelope":
        (tmp_path / f"{name}.signature.json").unlink()
    if fault == "no_checksum":
        (tmp_path / f"{name}.sha256").unlink()
    if fault == "tampered":
        data = bytearray((tmp_path / name).read_bytes())
        data[-1] ^= 1
        (tmp_path / name).write_bytes(bytes(data))
        digest = hashlib.sha256(bytes(data)).hexdigest()
        (tmp_path / f"{name}.sha256").write_text(f"{digest}  {name}\n")
    if fault == "unknown":
        target = "android-riscv64-api21"
    assert _published_main(script, tmp_path, target) == 2
