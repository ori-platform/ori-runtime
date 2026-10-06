# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Every Ed25519 trust anchor refuses a key that binds a signature to no holder.

The keyless signature is R = the base point, S = 1. Under the identity key the
library accepts it for every message; under the all-zero key (order 4) for some.
Each consumer test first shows the library alone accepts the exact signed bytes,
then that the consumer refuses them for the key, while an honest key still works.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.security.ed25519_keys import (
    CLAUSE_SMALL_ORDER,
    RefusedPublicKeyError,
    admit_public_key,
    refused_public_key_clause,
)

IDENTITY = b"\x01" + bytes(31)
ZERO = bytes(32)
BASE_POINT = bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"
)
KEYLESS = BASE_POINT + (1).to_bytes(32, "little")
HONEST_SEED = bytes(range(1, 33))
REPO = Path(__file__).resolve().parents[1]


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _honest() -> tuple[Ed25519PrivateKey, bytes]:
    key = Ed25519PrivateKey.from_private_bytes(HONEST_SEED)
    return key, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _library_accepts(public_key: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(KEYLESS, message)
    except Exception:
        return False
    return True


def test_library_alone_accepts_the_keyless_signature() -> None:
    messages = [f"message-{i}".encode() for i in range(16)]
    assert all(_library_accepts(IDENTITY, m) for m in messages)
    assert any(_library_accepts(ZERO, m) for m in messages)
    _, honest = _honest()
    assert not any(_library_accepts(honest, m) for m in messages)


@pytest.mark.parametrize("key", [IDENTITY, ZERO], ids=["identity", "all_zero"])
def test_admission_refuses_small_order_keys(key: bytes) -> None:
    assert refused_public_key_clause(key) == CLAUSE_SMALL_ORDER
    with pytest.raises(RefusedPublicKeyError) as caught:
        admit_public_key(key)
    assert caught.value.clause == CLAUSE_SMALL_ORDER
    assert isinstance(caught.value, ValueError)


@pytest.mark.parametrize("value", [b"", bytes(31), bytes(33), "not-bytes"])
def test_admission_refuses_wrong_length_and_type(value: Any) -> None:
    with pytest.raises(ValueError):
        admit_public_key(value)


def test_admission_accepts_an_honest_key() -> None:
    private, public = _honest()
    admit_public_key(public).verify(private.sign(b"m"), b"m")


# --- firmware telemetry: device registration through the manifest -----------


def _manifest_message(public_key: bytes, sign: Any) -> dict[str, Any]:
    from ori.security.firmware.telemetry import canonical_json_bytes
    from tests.firmware.test_telemetry import signed_manifest_for_key

    message = signed_manifest_for_key(HONEST_SEED, device_id="ori-fw-dev00001")
    manifest = message["manifest"]
    manifest["public_key_b64"] = _b64(public_key)
    canonical = canonical_json_bytes(manifest)
    message["manifest_hash"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    message["signature"] = "ed25519:" + _b64(sign(canonical))
    message["public_key_b64"] = _b64(public_key)
    return message


async def test_device_registration_refuses_a_small_order_key(tmp_path: Path) -> None:
    from ori.security.firmware.ingest import FirmwareTelemetryGate
    from ori.security.firmware.telemetry import (
        ERR_PUBLIC_KEY_MISMATCH,
        FirmwareVerificationError,
        canonical_json_bytes,
    )
    from ori.state.store import StateStore

    message = _manifest_message(IDENTITY, lambda _canonical: KEYLESS)
    assert _library_accepts(IDENTITY, canonical_json_bytes(message["manifest"]))

    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        gate = FirmwareTelemetryGate(store)
        with pytest.raises(FirmwareVerificationError) as caught:
            await gate.register_device(
                device_id="ori-fw-dev00001",
                public_key_b64=_b64(IDENTITY),
                posture="development",
                manifest_message=message,
            )
        assert caught.value.code == ERR_PUBLIC_KEY_MISMATCH
        assert CLAUSE_SMALL_ORDER in str(caught.value)
        assert await store.get_firmware_device("ori-fw-dev00001") is None

        private, public = _honest()
        honest = _manifest_message(public, private.sign)
        await gate.register_device(
            device_id="ori-fw-dev00001",
            public_key_b64=_b64(public),
            posture="development",
            manifest_message=honest,
        )
        assert await store.get_firmware_device("ori-fw-dev00001") is not None
    finally:
        await store.close()


def test_telemetry_signature_check_refuses_a_small_order_key() -> None:
    from ori.security.firmware.telemetry import (
        ERR_PUBLIC_KEY_MISMATCH,
        FirmwareVerificationError,
        _verify_signature,
    )

    assert _library_accepts(IDENTITY, b"reading")
    with pytest.raises(FirmwareVerificationError) as caught:
        _verify_signature(IDENTITY, b"reading", KEYLESS)
    assert caught.value.code == ERR_PUBLIC_KEY_MISMATCH


# --- firmware MQTT provisioning: device responses ----------------------------


def test_device_response_refuses_a_small_order_key() -> None:
    from ori.security.firmware.mqtt_provisioning import (
        FirmwareMqttProvisioningError,
        verify_device_message,
    )
    from tests.firmware.test_mqtt_provisioning import (
        CASES,
        DEVICE_PUBLIC_KEY,
        _wire_message,
    )

    case = dict(CASES["status_response"])
    signed = case["signed_object"].encode()
    assert _library_accepts(IDENTITY, signed)
    case["signature"] = "ed25519:" + _b64(KEYLESS)
    with pytest.raises(FirmwareMqttProvisioningError) as caught:
        verify_device_message(_wire_message(case), device_public_key_bytes=IDENTITY)
    assert caught.value.code == "invalid_device_key"
    verify_device_message(
        _wire_message(CASES["status_response"]),
        device_public_key_bytes=DEVICE_PUBLIC_KEY,
    )


# --- firmware approval: the runtime never grants authority to such a key -----


@pytest.mark.parametrize("field", ["public_key_b64", "runtime_public_key_b64"])
def test_approval_refuses_a_small_order_key(field: str) -> None:
    from ori.security.firmware.commands import (
        FirmwareCommandError,
        _build_approval_object_bytes,
    )

    _, honest = _honest()
    fields = {
        "capability_hash": "sha256:" + "a" * 64,
        "device_id": "ori-fw-dev00001",
        "posture": "development",
        "public_key_b64": _b64(honest),
        "runtime_public_key_b64": _b64(honest),
    }
    _build_approval_object_bytes(**fields)
    fields[field] = _b64(IDENTITY)
    with pytest.raises(FirmwareCommandError, match=CLAUSE_SMALL_ORDER):
        _build_approval_object_bytes(**fields)


# --- skills, offline tokens, config signatures --------------------------------


def test_skill_signature_refuses_a_small_order_anchor() -> None:
    from ori.skills.sandbox import SkillSecurityError
    from ori.skills.signing import canonical_signed_payload, verify_signed_payload

    payload = {"name": "skill", "version": "1.0.0"}
    assert _library_accepts(IDENTITY, canonical_signed_payload(payload))
    signed = {**payload, "signature": "ed25519:" + _b64(KEYLESS)}
    with pytest.raises(SkillSecurityError, match="trust anchor is refused"):
        verify_signed_payload(signed, _b64(IDENTITY))

    private, public = _honest()
    good = {
        **payload,
        "signature": "ed25519:" + _b64(private.sign(canonical_signed_payload(payload))),
    }
    verify_signed_payload(good, _b64(public))


def test_offline_tokens_refuse_a_small_order_anchor() -> None:
    from ori.security.offline_tokens import (
        V2_SIGNATURE_DOMAIN,
        v1_signature_valid,
        v2_domain_signature_valid,
    )
    from ori.skills.signing import canonical_signed_payload

    unsigned = {"token_version": 2, "device_id": "d"}
    v1 = canonical_signed_payload(unsigned)
    v2 = V2_SIGNATURE_DOMAIN + b"\x00" + v1
    assert _library_accepts(IDENTITY, v1) and _library_accepts(IDENTITY, v2)
    payload = {**unsigned, "signature": "ed25519:" + _b64(KEYLESS)}
    assert not v1_signature_valid(payload, _b64(IDENTITY))
    assert not v2_domain_signature_valid(payload, _b64(IDENTITY))

    private, public = _honest()
    assert v1_signature_valid(
        {**unsigned, "signature": "ed25519:" + _b64(private.sign(v1))}, _b64(public)
    )
    assert v2_domain_signature_valid(
        {**unsigned, "signature": "ed25519:" + _b64(private.sign(v2))}, _b64(public)
    )


def test_config_signature_refuses_a_small_order_anchor() -> None:
    from ori.security.config_signatures import (
        ConfigSignatureError,
        _verify_ed25519_signature,
    )

    payload = b"config"
    assert _library_accepts(IDENTITY, payload)
    with pytest.raises(ConfigSignatureError, match="trust anchor is refused"):
        _verify_ed25519_signature(
            signature="ed25519:" + _b64(KEYLESS),
            public_key_b64=_b64(IDENTITY),
            payload=payload,
            anchor_env="ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64",
        )
    private, public = _honest()
    _verify_ed25519_signature(
        signature="ed25519:" + _b64(private.sign(payload)),
        public_key_b64=_b64(public),
        payload=payload,
        anchor_env="ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64",
    )


# --- commissioning binding, evidence ingest, release and Android payloads ----


def test_binding_signature_refuses_a_small_order_signing_key() -> None:
    from ori.security.commissioning.binding import (
        BindingRefusedError,
        canonical_bytes,
        st_signature,
    )

    body = {"signing_key": "ed25519:" + _b64(IDENTITY), "zone": "z1"}
    assert _library_accepts(IDENTITY, canonical_bytes(body))
    with pytest.raises(BindingRefusedError) as caught:
        st_signature(body, _b64(KEYLESS))
    assert (caught.value.stage, caught.value.reason) == ("signature", "bad_signature")

    private, public = _honest()
    honest = {"signing_key": "ed25519:" + _b64(public), "zone": "z1"}
    st_signature(honest, _b64(private.sign(canonical_bytes(honest))))


def test_evidence_ingest_refuses_a_small_order_authority_key() -> None:
    from ori.security.evidence.authority_keys import AuthorityKey
    from ori.security.evidence.ingest import IngestRejectedError, _verify_ed25519

    key = AuthorityKey(
        key_id="sha256:" + hashlib.sha256(IDENTITY).hexdigest(),
        public_key_hex=IDENTITY.hex(),
        purpose="evidence_authority_receipt",
        status="active",
    )
    assert _library_accepts(IDENTITY, b"receipt")
    with pytest.raises(IngestRejectedError) as caught:
        _verify_ed25519(key, KEYLESS, b"receipt", "receipt")
    assert isinstance(caught.value.__cause__, RefusedPublicKeyError)


def test_release_bundle_refuses_a_small_order_release_key(tmp_path: Path) -> None:
    from ori.security.release_bundles import (
        RELEASE_KEY_PURPOSE,
        ReleaseBundleError,
        ReleaseKey,
        canonical_signature_message,
        verify_release_bundle,
    )
    from tests.test_release_bundles import (
        KEY_ID,
        TARGET,
        VERSION,
        _write_archive,
        _write_envelope,
    )

    artifact = _write_archive(tmp_path)
    envelope_path = _write_envelope(tmp_path, artifact, resign=False)
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    envelope["signature"] = "ed25519:" + _b64(KEYLESS)
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
    assert _library_accepts(IDENTITY, canonical_signature_message(envelope))
    key = ReleaseKey(
        key_id=KEY_ID,
        public_key_b64=_b64(IDENTITY),
        purpose=RELEASE_KEY_PURPOSE,
        status="active",
    )
    with pytest.raises(ReleaseBundleError) as caught:
        verify_release_bundle(
            artifact_path=artifact,
            envelope_path=envelope_path,
            key_registry={KEY_ID: key},
            expected_version=VERSION,
            expected_target=TARGET,
        )
    assert caught.value.code == "untrusted_release_key"
    assert CLAUSE_SMALL_ORDER in str(caught.value)


def test_android_payload_key_decoder_refuses_a_small_order_key() -> None:
    from ori.security.android_payloads import _decode_public_key

    _, honest = _honest()
    assert _decode_public_key(_b64(IDENTITY)) is None
    assert _decode_public_key(_b64(ZERO)) is None
    assert _decode_public_key(_b64(honest)) is not None


# --- inventory: no verifier is built outside the shared admission -----------

_ADMISSION = ("ori/security/ed25519_keys.py", "admit_public_key")
# Loads that build no verifier: the KMS identity check compares raw bytes only.
_CLASSIFIED: dict[tuple[str, str], str] = {
    (
        "ori/security/aws_kms_release_signer.py",
        "load_der_public_key",
    ): "identity comparison against the pinned registry; nothing is verified",
}
_LOADERS = {
    "from_public_bytes",
    "load_der_public_key",
    "load_pem_public_key",
    "load_ssh_public_key",
    "VerifyKey",
}


def _loader_uses() -> list[tuple[str, str, int]]:
    found: list[tuple[str, str, int]] = []
    for path in sorted((REPO / "ori").rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = None
            if isinstance(node, ast.Attribute) and node.attr in _LOADERS:
                name = node.attr
            elif isinstance(node, ast.Name) and node.id in _LOADERS:
                name = node.id
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value in _LOADERS
            ):
                name = node.value
            elif isinstance(node, ast.alias) and node.name.split(".")[-1] in _LOADERS:
                name = node.name.split(".")[-1]
            if name is not None:
                found.append((rel, name, getattr(node, "lineno", 0)))
    return found


def test_every_public_key_loader_is_the_shared_admission_or_classified() -> None:
    unclassified = []
    for rel, name, line in _loader_uses():
        if rel == _ADMISSION[0] and name == "from_public_bytes":
            continue
        if (rel, name) in _CLASSIFIED:
            continue
        unclassified.append(f"{rel}:{line} {name}")
    assert not unclassified, (
        "An Ed25519 public key is loaded outside "
        "ori.security.ed25519_keys.admit_public_key, so a small-order key "
        "reaches the library unrefused. Route it through admit_public_key, or "
        "classify it here with the reason it builds no verifier. This guard "
        "sees these spellings only: " + ", ".join(sorted(_LOADERS)) + "; "
        f"unclassified: {unclassified}"
    )


def test_inventory_guard_sees_the_admission_itself() -> None:
    assert any(
        rel == _ADMISSION[0] and name == "from_public_bytes"
        for rel, name, _ in _loader_uses()
    ), "the guard no longer sees the one permitted loader; it is blind"


# The Rust runtime decodes keys with ed25519-dalek, whose from_bytes accepts a
# small-order point and a non-canonical y. Outside test modules the key type and
# the crate path may appear only in admit_public_key and on a plain `use` line,
# so an alias, a qualified path or a conversion inferred to the key type all
# name the type somewhere this guard sees.
_RUST_ADMISSION = ("mobile/ori-runtime-mobile/src/main.rs", "admit_public_key")
_RUST_KEY_NAMES = re.compile(
    r"\b(?:VerifyingKey|ed25519_dalek|CompressedEdwardsY|EdwardsPoint)\b"
)
_RUST_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)", re.MULTILINE)


def _rust_code_only(text: str) -> str:
    """Comments and string and char literals blanked, offsets and newlines kept."""
    out = list(text)
    i, n = 0, len(text)

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            blank(i, end)
            i = end
        elif raw := re.match(r'r(#*)"', text[i : i + 64]):
            close = '"' + raw.group(1)
            end = text.find(close, i + raw.end())
            end = n if end < 0 else end + len(close)
            blank(i, end)
            i = end
        elif text[i] == '"':
            k = i + 1
            while k < n and text[k] != '"':
                k += 2 if text[k] == "\\" else 1
            blank(i, k + 1)
            i = k + 1
        elif char := re.match(r"'(?:\\.|[^\\'\n])'", text[i : i + 8]):
            blank(i, i + char.end())
            i += char.end()
        else:
            i += 1
    return "".join(out)


def _rust_test_spans(code: str) -> list[tuple[int, int]]:
    """The braces of each #[cfg(test)] module, in code with literals blanked."""
    spans = []
    for match in re.finditer(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{", code):
        depth, end = 1, match.end()
        while depth and end < len(code):
            depth += {"{": 1, "}": -1}.get(code[end], 0)
            end += 1
        spans.append((match.start(), end))
    return spans


def _rust_key_name_uses() -> list[tuple[str, str, int, str]]:
    """(file, enclosing function, line, source line) for each key name outside tests."""
    found = []
    for path in sorted((REPO / "mobile").rglob("*.rs")):
        if "target" in path.parts:
            continue
        rel = path.relative_to(REPO).as_posix()
        code = _rust_code_only(path.read_text(encoding="utf-8"))
        spans = _rust_test_spans(code)
        for match in _RUST_KEY_NAMES.finditer(code):
            if any(a <= match.start() < b for a, b in spans):
                continue
            line_start = code.rfind("\n", 0, match.start()) + 1
            line_end = code.find("\n", match.start())
            line = code[line_start : None if line_end < 0 else line_end].strip()
            enclosing = [m.group(1) for m in _RUST_FN.finditer(code, 0, match.start())]
            found.append(
                (
                    rel,
                    enclosing[-1] if enclosing else "",
                    code.count("\n", 0, match.start()) + 1,
                    line,
                )
            )
    return found


def _plain_use(line: str) -> bool:
    """A `use` that names the type without renaming it or globbing the crate."""
    return line.startswith("use ") and " as " not in line and "*" not in line


def test_every_rust_public_key_decode_is_the_shared_admission() -> None:
    outside = [
        f"{rel}:{line_no} in {fn or 'module scope'}: {line}"
        for rel, fn, line_no, line in _rust_key_name_uses()
        if (rel, fn) != _RUST_ADMISSION and not _plain_use(line)
    ]
    assert not outside, (
        "The Rust runtime names ed25519-dalek's key type outside admit_public_key, "
        "so a small-order or non-canonical key can reach it unrefused. This guard "
        "is textual: it sees VerifyingKey, ed25519_dalek, CompressedEdwardsY and "
        "EdwardsPoint outside #[cfg(test)] modules and plain `use` lines, after "
        "blanking comments and literals; a decode that never names any of them "
        f"is invisible to it. Outside: {outside}"
    )


def test_rust_inventory_guard_sees_the_admission_itself() -> None:
    assert _RUST_ADMISSION in {(rel, fn) for rel, fn, _, _ in _rust_key_name_uses()}, (
        "the Rust guard no longer sees the one permitted decode; it is blind"
    )


def _le(prefix: list[int], fill: int = 0, top: int | None = None) -> bytes:
    raw = bytearray([fill] * 32)
    raw[: len(prefix)] = bytes(prefix)
    if top is not None:
        raw[31] = top
    return bytes(raw)


# The edge firmware's low-order class (test/host/test_signer.c): the eight
# points of low order, then the non-canonical encodings of them its decoder
# accepts. Every one must be refused here too, or the two sides disagree.
_ORDER8_A = bytes.fromhex(
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
)
_ORDER8_B = bytes.fromhex(
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
)
FIRMWARE_LOW_ORDER_CLASS = [
    _le([0x01]),
    _le([0xEC], 0xFF, 0x7F),
    _le([0x00]),
    _le([], 0x00, 0x80),
    _ORDER8_A,
    _ORDER8_A[:31] + bytes([0x85]),
    _ORDER8_B,
    _ORDER8_B[:31] + bytes([0xFA]),
    _le([0x01], 0x00, 0x80),
    _le([0xEC], 0xFF, 0xFF),
    _le([0xED], 0xFF, 0x7F),
    _le([0xED], 0xFF, 0xFF),
    _le([0xEE], 0xFF, 0x7F),
    _le([0xEE], 0xFF, 0xFF),
]


@pytest.mark.parametrize(
    "key", FIRMWARE_LOW_ORDER_CLASS, ids=lambda key: key.hex()[:8] + key.hex()[-2:]
)
def test_runtime_refuses_the_firmware_low_order_class(key: bytes) -> None:
    assert refused_public_key_clause(key) is not None
    with pytest.raises(RefusedPublicKeyError):
        admit_public_key(key)


# --- refusal at each layer and load site, on its own -----------------------


def test_device_key_decode_refuses_a_small_order_key_by_itself() -> None:
    from ori.security.firmware.telemetry import (
        ERR_PUBLIC_KEY_MISMATCH,
        FirmwareVerificationError,
        _decode_public_key,
    )

    with pytest.raises(FirmwareVerificationError) as caught:
        _decode_public_key(_b64(IDENTITY))
    assert caught.value.code == ERR_PUBLIC_KEY_MISMATCH
    assert CLAUSE_SMALL_ORDER in str(caught.value)
    _, honest = _honest()
    assert _decode_public_key(_b64(honest)) == honest


async def test_a_provisioning_response_under_a_small_order_key_is_named() -> None:
    from ori.security.firmware.mqtt_provisioning import (
        FirmwareMqttProvisioningError,
        FirmwareMqttProvisioningService,
    )
    from tests.firmware.test_mqtt_provisioning import (
        CASES,
        PA_SEED,
        _IssuerStore,
        _wire_message,
    )

    store = _IssuerStore()
    store.row = {
        "device_id": "ori-fw-7c9f2b3a",
        "anchor_epoch_id": "sha256:" + "aa" * 32,
        "public_key_b64": _b64(IDENTITY),
        "approved": True,
        "revoked": False,
    }
    store.seq = 40
    service = FirmwareMqttProvisioningService(
        store=store, provisioner_key_bytes=PA_SEED
    )
    issued = await service.create_csr(
        device_id="ori-fw-7c9f2b3a", actor="operator-17", reason="enrollment"
    )
    case = dict(CASES["csr_response"])
    case["signature"] = "ed25519:" + _b64(KEYLESS)
    with pytest.raises(FirmwareMqttProvisioningError) as caught:
        await service.verify_response(issued, _wire_message(case))
    assert caught.value.code == "invalid_device_key"


def test_a_commissioning_anchor_is_refused_where_it_is_loaded() -> None:
    from ori.security.commissioning.anchors import AnchorError, _decode_anchor

    with pytest.raises(AnchorError, match=CLAUSE_SMALL_ORDER):
        _decode_anchor("ORI_COMMISSIONING_ANCHOR_PUBLIC_KEY_B64", _b64(IDENTITY))
    _, honest = _honest()
    assert _decode_anchor("ORI_COMMISSIONING_ANCHOR_PUBLIC_KEY_B64", _b64(honest))


def test_a_skill_trust_anchor_is_reported_as_the_fault() -> None:
    from ori.skills.loader import _anchor_fault

    fault = _anchor_fault(_b64(IDENTITY), "the Hub anchor")
    assert fault is not None and CLAUSE_SMALL_ORDER in fault
    _, honest = _honest()
    assert _anchor_fault(_b64(honest), "the Hub anchor") is None


def test_an_offline_token_anchor_is_named_as_refused() -> None:
    from ori.security import offline_tokens as tokens
    from tests.test_offline_tokens_v2_vectors import DOMAIN

    verifier = tokens.OfflineTierCTokenVerifier(public_key_b64=_b64(IDENTITY))
    result = verifier.verify_tier_c_token(
        json.dumps(DOMAIN["cases"][0]["token"]),
        proposal=tokens.ProposalClaims(
            proposal_id="AB12CD34",
            device_id="energy-monitor-ikeja-01",
            action="trip_relay",
            target="relay-gpio-26",
            zone_id="zone-feeder-a",
        ),
    )
    assert result.approved is False
    assert result.reason == "trust_anchor_refused"


def test_every_published_key_check_also_refuses_small_order_keys() -> None:
    """A load site that refuses published keys must refuse small-order ones too."""
    admitting = {"refused_public_key_clause", "admit_public_key"}
    # Sites whose function admits through another helper, or checks seeds.
    classified = {
        ("ori/security/published_test_keys.py", "is_published_seed"): "a seed",
        ("ori/security/evidence/authority_keys.py", "refuse_published_test_keys"): (
            "the registry parser applies the clause to every key first"
        ),
        ("ori/security/android_payloads.py", "load_payload_key_registry"): (
            "_decode_public_key admits through admit_public_key"
        ),
        ("ori/security/offline_tokens.py", "_anchor_is_published"): (
            "verify_tier_c_token checks _anchor_refused_clause next"
        ),
    }
    unpaired = []
    for path in sorted((REPO / "ori").rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            names = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)} | {
                n.attr for n in ast.walk(func) if isinstance(n, ast.Attribute)
            }
            if "PUBLISHED_TEST_KEYS" not in names:
                continue
            if names & admitting or (rel, func.name) in classified:
                continue
            unpaired.append(f"{rel}:{func.lineno} {func.name}")
    assert not unpaired, (
        "These functions refuse a published test key but not a small-order "
        "key, so the anchor they load is refused only later, at verification, "
        "and reported as a bad signature. Apply refused_public_key_clause "
        "beside the published-key check, or classify the site here with the "
        "helper that does. This guard sees only a function that names "
        "PUBLISHED_TEST_KEYS directly: an aliased import, the _B64 tuple, a "
        "lambda, or a clause applied only later at verification pass it. "
        f"Unpaired: {unpaired}"
    )


def test_a_release_key_registry_refuses_a_small_order_key(tmp_path: Path) -> None:
    from ori.security.release_bundles import (
        KEY_REGISTRY_SCHEMA,
        RELEASE_KEY_PURPOSE,
        ReleaseBundleError,
        load_release_key_registry,
    )
    from tests.test_release_bundles import KEY_ID

    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "schema": KEY_REGISTRY_SCHEMA,
                "keys": [
                    {
                        "key_id": KEY_ID,
                        "public_key_b64": _b64(IDENTITY),
                        "purpose": RELEASE_KEY_PURPOSE,
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseBundleError, match=CLAUSE_SMALL_ORDER):
        load_release_key_registry(path)


def test_a_small_order_provisioning_anchor_reads_as_absent() -> None:
    from ori.security.commissioning.anchors import provisioning_anchor

    security = {"config_signature": {"trust_anchor_env": "ORI_TEST_ANCHOR"}}
    _, honest = _honest()
    assert provisioning_anchor(security, {"ORI_TEST_ANCHOR": _b64(honest)}) == honest
    assert provisioning_anchor(security, {"ORI_TEST_ANCHOR": _b64(IDENTITY)}) is None


def test_a_signed_payload_names_a_small_order_anchor() -> None:
    from ori.skills.sandbox import SkillSecurityError
    from ori.skills.signing import verify_signed_payload

    signed = {"name": "x", "signature": "ed25519:" + _b64(KEYLESS)}
    with pytest.raises(SkillSecurityError, match="trust anchor is refused"):
        verify_signed_payload(signed, _b64(IDENTITY))


def _shipped_release_keys() -> list[tuple[str, str]]:
    keys = []
    for name in ("release-keys.json", "android-payload-keys.json"):
        registry = json.loads((REPO / "ori" / "installer" / name).read_text())
        keys += [
            (f"{name} {k['key_id']}", k["public_key_b64"]) for k in registry["keys"]
        ]
    installer = (REPO / "scripts" / "install-linux.sh").read_text(encoding="utf-8")
    pinned = re.search(
        r'^PUBLIC_KEY_B64 = "([A-Za-z0-9+/=]+)"$', installer, re.MULTILINE
    )
    assert pinned, (
        "install-linux.sh no longer pins PUBLIC_KEY_B64 where this test reads it"
    )
    keys.append(("install-linux.sh PUBLIC_KEY_B64", pinned.group(1)))
    return keys


@pytest.mark.parametrize(("where", "key_b64"), _shipped_release_keys())
def test_every_shipped_release_key_passes_admission(where: str, key_b64: str) -> None:
    """The installer verifies with openssl, outside admission, so the keys it pins are held here."""
    clause = refused_public_key_clause(base64.b64decode(key_b64, validate=True))
    assert clause is None, f"{where} is refused: {clause}"


_CORPUS = json.loads(
    (REPO / "tests/vectors/ed25519_key_admission/vectors-v1.json").read_text(
        encoding="utf-8"
    )
)


@pytest.mark.parametrize(
    "case",
    _CORPUS["public_keys"] + _CORPUS["mixed_order"],
    ids=lambda c: (
        c["public_key_hex"][:16] + ("-" + c["why"][:24] if c.get("why") else "")
    ),
)
def test_admission_matches_the_contract_corpus(case: dict[str, str]) -> None:
    """ed25519-key-admission/v1, vendored: each key's verdict and refusing clause."""
    clause = refused_public_key_clause(bytes.fromhex(case["public_key_hex"]))
    expected = case["clause"] if case["expected"] == "refused" else None
    assert clause == expected, case.get("why")


@pytest.mark.parametrize(
    "case", _CORPUS["keyless_signatures"], ids=lambda c: c["public_key_hex"][:16]
)
def test_every_keyless_signature_is_refused_for_its_key(case: dict[str, str]) -> None:
    with pytest.raises(RefusedPublicKeyError) as refused:
        admit_public_key(bytes.fromhex(case["public_key_hex"]))
    assert refused.value.clause == CLAUSE_SMALL_ORDER


# --- mixed order: a prime-order key shifted by a point of small order ---------
#
# The shifted key's holder is the unshifted key's: signing with that scalar and
# the shifted key in the challenge verifies cofactorlessly whenever the
# challenge is a multiple of 8. The forgeries below are for the library, which
# reduces the challenge modulo L; RFC 8032 section 5.1.7 uses the full hash. So a check that knows a key by its bytes (a
# published key, a collision, a key not to be reused) is passed by shifting.
# The arithmetic below is affine and shares nothing with ori.security.

_Q = 2**255 - 19
_CURVE_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_ORDER = 2**252 + 27742317777372353535851937790883648493
ORDER_8 = bytes.fromhex(
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
)


def _affine(raw: bytes) -> tuple[int, int]:
    n = int.from_bytes(raw, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    xx = (y * y - 1) * pow(_CURVE_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q:
        x = x * pow(2, (_Q - 1) // 4, _Q) % _Q
    return ((_Q - x) % _Q if x & 1 != sign else x, y)


def _affine_add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    (x1, y1), (x2, y2) = a, b
    t = _CURVE_D * x1 * x2 * y1 * y2 % _Q
    return (
        (x1 * y2 + x2 * y1) * pow(1 + t, _Q - 2, _Q) % _Q,
        (y1 * y2 + x1 * x2) * pow(1 - t, _Q - 2, _Q) % _Q,
    )


def _affine_mul(k: int, point: tuple[int, int]) -> tuple[int, int]:
    result = (0, 1)
    while k:
        if k & 1:
            result = _affine_add(result, point)
        point = _affine_add(point, point)
        k >>= 1
    return result


def _encode(point: tuple[int, int]) -> bytes:
    return (point[1] | ((point[0] & 1) << 255)).to_bytes(32, "little")


def _shifted(seed: bytes) -> bytes:
    """The seed's public key plus a point of order 8: mixed order."""
    public = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return _encode(_affine_add(_affine(public), _affine(ORDER_8)))


def _forge_under_shift(seed: bytes, message: bytes) -> bytes:
    """A signature by *seed*'s scalar that the library verifies under its shifted key."""
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    shifted = _shifted(seed)
    base = _affine(BASE_POINT)
    for counter in range(512):
        r = (
            int.from_bytes(
                hashlib.sha512(
                    digest[32:] + message + counter.to_bytes(4, "little")
                ).digest(),
                "little",
            )
            % _ORDER
        )
        big_r = _encode(_affine_mul(r, base))
        k = (
            int.from_bytes(hashlib.sha512(big_r + shifted + message).digest(), "little")
            % _ORDER
        )
        if k % 8 == 0:
            return big_r + ((r + k * scalar) % _ORDER).to_bytes(32, "little")
    raise AssertionError("no nonce gave a challenge divisible by 8")


def _library_accepts_signature(
    public_key: bytes, signature: bytes, message: bytes
) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except Exception:
        return False
    return True


def test_a_shifted_published_key_is_refused_though_its_seed_signs_under_it() -> None:
    from ori.security.config_signatures import (
        ConfigSignatureError,
        _verify_ed25519_signature,
    )
    from ori.security.ed25519_keys import CLAUSE_MIXED_ORDER
    from ori.security.published_test_keys import (
        PUBLISHED_TEST_KEYS,
        is_published_seed,
    )

    published_seed = bytes(32)
    assert is_published_seed(published_seed)
    shifted = _shifted(published_seed)
    payload = b"config"
    forged = _forge_under_shift(published_seed, payload)
    # The published set knows keys by their bytes, and the library verifies.
    assert shifted not in PUBLISHED_TEST_KEYS
    assert _library_accepts_signature(shifted, forged, payload)
    assert refused_public_key_clause(shifted) == CLAUSE_MIXED_ORDER
    with pytest.raises(ConfigSignatureError, match="trust anchor is refused"):
        _verify_ed25519_signature(
            signature="ed25519:" + _b64(forged),
            public_key_b64=_b64(shifted),
            payload=payload,
            anchor_env="ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64",
        )


def test_one_key_cannot_be_both_anchors_by_shifting_one_of_them() -> None:
    from ori.security.commissioning.anchors import (
        AnchorError,
        _decode_anchor,
        anchor_collision,
        load_commissioning_anchors,
        provisioning_anchor,
    )
    from ori.security.ed25519_keys import CLAUSE_MIXED_ORDER

    _, honest = _honest()
    shifted = _shifted(HONEST_SEED)
    assert shifted != honest and _library_accepts_signature(
        shifted, _forge_under_shift(HONEST_SEED, b"binding"), b"binding"
    )
    security = {"config_signature": {"trust_anchor_env": "ORI_PROVISIONING_ANCHOR"}}
    env = {
        "ORI_COMMISSIONING_ANCHOR_PUBLIC_KEY_B64": _b64(honest),
        "ORI_PROVISIONING_ANCHOR": _b64(shifted),
    }
    # Compared as bytes the two anchors differ, so the shift must be refused
    # where each anchor is read, not left to the comparison.
    assert provisioning_anchor(security, env) is None
    with pytest.raises(AnchorError, match=CLAUSE_MIXED_ORDER):
        _decode_anchor("ORI_COMMISSIONING_ANCHOR_PUBLIC_KEY_B64", _b64(shifted))
    anchors = load_commissioning_anchors(env)
    assert anchor_collision(anchors, honest)


async def test_a_rotated_away_key_cannot_return_shifted(tmp_path: Path) -> None:
    from ori.security.firmware.ingest import FirmwareTelemetryGate
    from ori.security.firmware.telemetry import (
        FirmwareVerificationError,
        canonical_json_bytes,
        key_epoch_id,
    )
    from ori.state.store import StateStore
    from tests.firmware.test_telemetry import (
        GOLDEN_SEED,
        PUBLIC_KEY_B64,
        SEALED_DEVICE,
        provision_and_approve,
        signed_manifest_for_key,
    )

    sealed = {
        "posture": "sealed_flash",
        "secure_boot_enabled": True,
        "flash_encryption_enabled": True,
        "key_storage": "efuse_derived",
    }
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        gate = FirmwareTelemetryGate(store)
        await provision_and_approve(gate, "manifest_full_sealed")
        rotated = signed_manifest_for_key(
            bytes([0x55]) * 32, device_id=SEALED_DEVICE, **sealed
        )
        await gate.reprovision_device(
            device_id=SEALED_DEVICE,
            public_key_b64=rotated["public_key_b64"],
            posture="sealed_flash",
            manifest_message=rotated,
            actor="op",
            reason="key compromised",
        )
        assert await gate.approve_device(SEALED_DEVICE, actor="op", reason="rotation")

        # The compromised key, shifted: a new key epoch to the reuse check.
        shifted = _shifted(GOLDEN_SEED)
        assert key_epoch_id(device_id=SEALED_DEVICE, public_key_b64=_b64(shifted)) != (
            key_epoch_id(device_id=SEALED_DEVICE, public_key_b64=PUBLIC_KEY_B64)
        )
        manifest = dict(rotated["manifest"], public_key_b64=_b64(shifted))
        canonical = canonical_json_bytes(manifest)
        forged = _forge_under_shift(GOLDEN_SEED, canonical)
        assert _library_accepts_signature(shifted, forged, canonical)
        message = {
            "manifest": manifest,
            "manifest_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
            "signature": "ed25519:" + _b64(forged),
        }
        with pytest.raises(FirmwareVerificationError):
            await gate.reprovision_device(
                device_id=SEALED_DEVICE,
                public_key_b64=_b64(shifted),
                posture="sealed_flash",
                manifest_message=message,
                actor="op",
                reason="return the old key",
            )
        assert await store.get_pending_firmware_anchor(SEALED_DEVICE) is None
        row = await store.get_firmware_device(SEALED_DEVICE)
        assert row is not None and row["public_key_b64"] == rotated["public_key_b64"]
    finally:
        await store.close()


# --- negation: the same holder's key under the other sign of x ---------------
#
# -A has prime order, so admission refuses nothing about it, and the holder of
# a signs under it with -a every time. A check that recognises a key compares
# its identity, y with the sign bit cleared, never its encoding.


def _negated(public_key: bytes) -> bytes:
    return public_key[:31] + bytes([public_key[31] ^ 0x80])


def _sign_under_negation(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """The negated key, and a signature by -a that the library verifies under it."""
    public = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    negated = _negated(public)
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    r = (
        int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little")
        % _ORDER
    )
    big_r = _encode(_affine_mul(r, _affine(BASE_POINT)))
    k = int.from_bytes(hashlib.sha512(big_r + negated + message).digest(), "little")
    s = (r + k * (-scalar)) % _ORDER
    return negated, big_r + s.to_bytes(32, "little")


def test_a_negated_published_key_is_refused_though_its_seed_signs_under_it() -> None:
    from ori.security.config_signatures import (
        ConfigSignatureError,
        _verify_ed25519_signature,
    )
    from ori.security.published_test_keys import PUBLISHED_TEST_KEYS

    payload = b"config"
    negated, signature = _sign_under_negation(bytes(32), payload)
    assert refused_public_key_clause(negated) is None
    assert _library_accepts_signature(negated, signature, payload)
    assert negated in PUBLISHED_TEST_KEYS
    with pytest.raises(ConfigSignatureError):
        _verify_ed25519_signature(
            signature="ed25519:" + _b64(signature),
            public_key_b64=_b64(negated),
            payload=payload,
            anchor_env="ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64",
        )


def test_every_published_key_is_refused_under_both_signs() -> None:
    from ori.security.published_test_keys import (
        PUBLISHED_TEST_KEYS,
        PUBLISHED_TEST_KEYS_B64,
    )

    for key_b64 in PUBLISHED_TEST_KEYS_B64:
        raw = base64.b64decode(key_b64)
        assert raw in PUBLISHED_TEST_KEYS and _negated(raw) in PUBLISHED_TEST_KEYS


def test_a_negated_anchor_is_the_same_anchor() -> None:
    from ori.security.commissioning.anchors import (
        AnchorError,
        anchor_collision,
        load_commissioning_anchors,
        provisioning_anchor,
    )

    _, honest = _honest()
    negated, _ = _sign_under_negation(HONEST_SEED, b"binding")
    env = {
        "ORI_COMMISSIONING_ANCHOR_PUBLIC_KEY_B64": _b64(honest),
        "ORI_PROVISIONING_ANCHOR": _b64(negated),
    }
    security = {"config_signature": {"trust_anchor_env": "ORI_PROVISIONING_ANCHOR"}}
    provisioning = provisioning_anchor(security, env)
    assert provisioning == negated
    assert anchor_collision(load_commissioning_anchors(env), provisioning)
    with pytest.raises(AnchorError, match="rotation demotes a key"):
        load_commissioning_anchors(
            {
                "ORI_COMMISSIONING_ANCHOR_PUBLIC_KEY_B64": _b64(honest),
                "ORI_COMMISSIONING_ANCHOR_PREVIOUS_PUBLIC_KEY_B64": _b64(negated),
            }
        )


async def test_a_rotated_away_or_current_key_cannot_return_negated(
    tmp_path: Path,
) -> None:
    from ori.security.firmware.ingest import FirmwareTelemetryGate
    from ori.security.firmware.telemetry import (
        ERR_KEY_EPOCH_REUSED,
        ERR_SAME_KEY_NOT_A_ROTATION,
        FirmwareVerificationError,
        canonical_json_bytes,
    )
    from ori.state.store import StateStore
    from tests.firmware.test_telemetry import (
        GOLDEN_SEED,
        SEALED_DEVICE,
        provision_and_approve,
        signed_manifest_for_key,
    )

    sealed = {
        "posture": "sealed_flash",
        "secure_boot_enabled": True,
        "flash_encryption_enabled": True,
        "key_storage": "efuse_derived",
    }
    rotated_seed = bytes([0x55]) * 32

    def negated_manifest(seed: bytes, template: dict) -> tuple[str, dict]:
        negated, _ = _sign_under_negation(seed, b"")
        manifest = dict(template["manifest"], public_key_b64=_b64(negated))
        canonical = canonical_json_bytes(manifest)
        _, signature = _sign_under_negation(seed, canonical)
        assert _library_accepts_signature(negated, signature, canonical)
        return _b64(negated), {
            "manifest": manifest,
            "manifest_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
            "signature": "ed25519:" + _b64(signature),
        }

    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        gate = FirmwareTelemetryGate(store)
        await provision_and_approve(gate, "manifest_full_sealed")
        rotated = signed_manifest_for_key(
            rotated_seed, device_id=SEALED_DEVICE, **sealed
        )
        await gate.reprovision_device(
            device_id=SEALED_DEVICE,
            public_key_b64=rotated["public_key_b64"],
            posture="sealed_flash",
            manifest_message=rotated,
            actor="op",
            reason="key compromised",
        )
        assert await gate.approve_device(SEALED_DEVICE, actor="op", reason="rotation")

        for seed, code in (
            (GOLDEN_SEED, ERR_KEY_EPOCH_REUSED),
            (rotated_seed, ERR_SAME_KEY_NOT_A_ROTATION),
        ):
            key_b64, message = negated_manifest(seed, rotated)
            with pytest.raises(FirmwareVerificationError) as caught:
                await gate.reprovision_device(
                    device_id=SEALED_DEVICE,
                    public_key_b64=key_b64,
                    posture="sealed_flash",
                    manifest_message=message,
                    actor="op",
                    reason="negated",
                )
            assert caught.value.code == code
        assert await store.get_pending_firmware_anchor(SEALED_DEVICE) is None
        row = await store.get_firmware_device(SEALED_DEVICE)
        assert row is not None and row["public_key_b64"] == rotated["public_key_b64"]
    finally:
        await store.close()


@pytest.mark.parametrize("case", _CORPUS["negated_keys"])
def test_a_key_and_its_negation_share_one_identity(case: dict[str, str]) -> None:
    """ed25519-key-admission/v1, vendored: both admitted, one identity, one holder."""
    from ori.security.ed25519_keys import key_identity

    public = bytes.fromhex(case["public_key_hex"])
    negated = bytes.fromhex(case["negated_public_key_hex"])
    identity = bytes.fromhex(case["identity_hex"])
    assert refused_public_key_clause(public) is None
    assert refused_public_key_clause(negated) is None
    assert key_identity(public) == key_identity(negated) == identity
    assert _library_accepts_signature(
        negated,
        bytes.fromhex(case["signature_hex"]),
        bytes.fromhex(case["message_hex"]),
    )
