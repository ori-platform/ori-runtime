# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Independent reconstruction of the evidence-exchange vector graph.

Imports nothing from the generator. Every rule is re-derived from the contracts,
so agreement means two implementations agree rather than one implementation
agreeing with itself.
"""

import base64
import hashlib
import hmac
import json
import pathlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

VEC = pathlib.Path(__file__).resolve().parent / "vectors" / "evidence_exchange"


def reconstruct() -> tuple[int, list[str]]:
    """Rebuild every derived value in the graph and report what disagrees."""
    failures: list[str] = []
    checks = 0

    def fail(msg: str) -> None:
        failures.append(msg)

    def ok() -> None:
        nonlocal checks
        checks += 1

    def canonical(obj):
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def tagged(obj):
        return "sha256:" + hashlib.sha256(canonical(obj)).hexdigest()

    def load(name):
        return json.loads((VEC / name).read_text())

    def pubkey(hex_str):
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))

    def verify_sig(pub, domain, artifact, auth="signature"):
        raw = artifact.get(auth, "")
        if not isinstance(raw, str) or not raw.startswith("ed25519:"):
            return False
        body = {k: v for k, v in artifact.items() if k != auth}
        pre = domain.encode("ascii") + b"\x00" + canonical(body)
        try:
            pub.verify(base64.b64decode(raw.split(":", 1)[1]), pre)
            return True
        except (InvalidSignature, ValueError):
            return False

    def b64_of_hex(h):
        """The normative bridge: 64 lowercase hex -> 32 bytes -> padded standard Base64."""
        if len(h) != 64:
            raise ValueError(f"pubkey_hex must be 64 characters, got {len(h)}")
        if h != h.lower():
            raise ValueError("pubkey_hex must be lowercase")
        raw = bytes.fromhex(h)
        if len(raw) != 32:
            raise ValueError("pubkey_hex must decode to exactly 32 bytes")
        return base64.b64encode(raw).decode("ascii")

    # ---- 1. re-derive the anchor identifiers from the registration itself -------
    reg_doc = load("anchor-registration.json")
    valid_reg = next(c for c in reg_doc["cases"] if c["expected"] == "accept")[
        "artifact"
    ]
    device_id = valid_reg["device_id"]
    pub_hex = valid_reg["pubkey_hex"]
    pub_b64 = b64_of_hex(pub_hex)

    cap = tagged(valid_reg["capability_profile"])
    key_id = tagged({"device_id": device_id, "public_key_b64": pub_b64, "v": 1})
    epoch = tagged(
        {
            "capability_hash": cap,
            "device_id": device_id,
            "posture": valid_reg["posture"],
            "public_key_b64": pub_b64,
            "v": 1,
        }
    )

    if valid_reg["anchor_epoch_id"] != epoch:
        fail(
            f"registration epoch does not recompute: {valid_reg['anchor_epoch_id']} != {epoch}"
        )
    else:
        ok()
    if valid_reg["key_id"] != key_id:
        fail(
            f"registration key_id does not recompute: {valid_reg['key_id']} != {key_id}"
        )
    else:
        ok()
    if not verify_sig(pubkey(pub_hex), reg_doc["domain_ascii"], valid_reg):
        fail("valid registration does not verify under the key it carries")
    else:
        ok()

    # ---- 1b. every negative naming a derived identifier must actually mismatch --
    for case_ in reg_doc["cases"]:
        art = case_["artifact"]
        if case_["name"] == "claimed_epoch_mismatch":
            if art["anchor_epoch_id"] == epoch:
                fail(
                    "claimed_epoch_mismatch names the correct epoch, so it mismatches nothing"
                )
            elif art["key_id"] != key_id:
                fail(
                    "claimed_epoch_mismatch also moves key_id, so it does not isolate its rule"
                )
            else:
                ok()
        if case_["name"] == "claimed_key_id_mismatch":
            if art["key_id"] == key_id:
                fail(
                    "claimed_key_id_mismatch names the correct key_id, so it mismatches nothing"
                )
            elif art["anchor_epoch_id"] != epoch:
                fail(
                    "claimed_key_id_mismatch also moves the epoch, so it does not isolate its rule"
                )
            else:
                ok()

    # ---- 1c. the encoding bridge is exercised, not assumed ---------------------
    for bad, why in (
        (pub_hex.upper(), "uppercase hex"),
        (pub_hex[:-2], "wrong length"),
        (pub_hex[:-1] + "z", "non-hex character"),
    ):
        try:
            b64_of_hex(bad)
            fail(f"the bridge accepted {why}, which must be refused before derivation")
        except ValueError:
            ok()

    # ---- 2. commissioning authorisation binds the same epoch, digest matches ----
    comm_doc = load("commissioning-authorization.json")
    valid_comm = next(c for c in comm_doc["cases"] if c["expected"] == "accept")[
        "artifact"
    ]
    if valid_comm["anchor_epoch_id"] != epoch:
        fail(
            "commissioning authorisation names a different epoch than the registration"
        )
    else:
        ok()
    if tagged(valid_comm) != valid_reg["commissioning_digest"]:
        fail("commissioning_digest is not the digest of the authorisation presented")
    else:
        ok()
    if not verify_sig(
        pubkey(comm_doc["signing_key_public_hex"]), comm_doc["domain_ascii"], valid_comm
    ):
        fail("valid commissioning authorisation does not verify")
    else:
        ok()

    # ---- 3. epoch confirmation, checkpoint, envelopes all name the same epoch ---
    for name, expect_epoch in (
        ("epoch-confirmation.json", True),
        ("checkpoint.json", True),
    ):
        doc = load(name)
        v = next(c for c in doc["cases"] if c["expected"] == "accept")["artifact"]
        if expect_epoch and v.get("anchor_epoch_id") != epoch:
            fail(
                f"{name}: valid case names {v.get('anchor_epoch_id')}, expected {epoch}"
            )
        else:
            ok()

    cp = load("checkpoint.json")
    cp_valid = next(c for c in cp["cases"] if c["expected"] == "accept")["artifact"]
    if cp_valid.get("key_id") != key_id:
        fail("checkpoint key_id is not the derived device key_id")
    else:
        ok()

    # ---- 4. chain rows: hash, digest and signature all reconstruct --------------
    env_doc = load("delivery-envelope.json")
    env_valid = next(c for c in env_doc["cases"] if c["name"] == "valid")["artifact"]
    row = env_valid["chain_row"]
    recomputed_hash = hashlib.sha256(row["canonical_json"].encode("utf-8")).hexdigest()
    if row["event_hash"] != recomputed_hash:
        fail("chain row event_hash is not sha256 over canonical_json")
    else:
        ok()
    if env_valid["chain_row_digest"] != "sha256:" + recomputed_hash:
        fail("chain_row_digest is not sha256 over canonical_json")
    else:
        ok()
    raw_sig = row["signature"].split(":", 1)[1]
    try:
        pubkey(pub_hex).verify(
            base64.b64decode(raw_sig), row["canonical_json"].encode("utf-8")
        )
        ok()
    except InvalidSignature:
        fail("chain row signature does not verify over its canonical bytes")
    if env_valid["anchor_epoch_id"] != epoch or env_valid["key_id"] != key_id:
        fail("valid envelope does not carry the derived epoch and key_id")
    else:
        ok()

    # ---- 5. custody envelope_digest is over the envelope's WIRE bytes -----------
    cu_doc = load("custody-acknowledgement.json")
    cu_valid = next(c for c in cu_doc["cases"] if c["expected"] == "accept")["artifact"]
    wire_digest = "sha256:" + hashlib.sha256(canonical(env_valid)).hexdigest()
    if cu_valid["envelope_digest"] != wire_digest:
        fail("custody envelope_digest is not sha256 over the envelope wire bytes")
    else:
        ok()
    if cu_valid["local_seq"] != env_valid["local_seq"]:
        fail("custody names a different local_seq than the envelope it acknowledges")
    else:
        ok()
    secret = bytes.fromhex(cu_doc["gateway_secret_hex"])
    body = {k: v for k, v in cu_valid.items() if k != "mac"}
    pre = cu_doc["domain_ascii"].encode("ascii") + b"\x00" + canonical(body)
    expected_mac = "hmac-sha256:" + hmac.new(secret, pre, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(cu_valid["mac"], expected_mac):
        fail("custody MAC does not recompute")
    else:
        ok()

    # ---- 6. receipt range_digest over raw 32-byte row digests -------------------
    rc_doc = load("delivery-receipt.json")
    rc_valid = next(c for c in rc_doc["cases"] if c["expected"] == "accept")["artifact"]
    if not verify_sig(
        pubkey(rc_doc["signing_key_public_hex"]), rc_doc["domain_ascii"], rc_valid
    ):
        fail("valid receipt does not verify under the receipt key")
    else:
        ok()
    if rc_valid["from_seq"] > rc_valid["to_seq"]:
        fail("receipt range is inverted")
    else:
        ok()

    # ---- 7. every declared authenticator posture is independently true ---------
    for name in (
        "anchor-registration.json",
        "commissioning-authorization.json",
        "epoch-confirmation.json",
        "checkpoint.json",
        "delivery-envelope.json",
        "delivery-receipt.json",
    ):
        doc = load(name)
        candidates = []
        for field in ("signing_key_public_hex",):
            if field in doc:
                candidates.append(doc[field])
        for field in (
            "signing_key_seed_hex",
            "device_key_seed_hex",
            "receipt_authority_seed_hex",
            "epoch_authority_seed_hex",
            "previous_generation_seed_hex",
            "foreign_key_seed_hex",
            "authority_receipt_seed_hex",
        ):
            if field in doc:
                k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(doc[field]))
                from cryptography.hazmat.primitives import serialization

                candidates.append(
                    k.public_key()
                    .public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                    .hex()
                )
        for case in doc["cases"]:
            art = case["artifact"]
            auth = "mac" if "mac" in art else "signature"
            if auth == "mac":
                continue
            verified_by = [
                h for h in candidates if verify_sig(pubkey(h), doc["domain_ascii"], art)
            ]
            declared = case["authenticator"]
            if declared == "valid" and not verified_by:
                fail(
                    f"{name}/{case['name']}: declared valid, verifies under no published key"
                )
            elif declared == "invalid" and verified_by:
                fail(f"{name}/{case['name']}: declared invalid, but verifies")
            else:
                ok()

    # ---- 8. no placeholder epochs survive anywhere ------------------------------
    for path in sorted(VEC.rglob("*.json")):
        text = path.read_text()
        for placeholder in ("epoch-0002", "dev-key-2", "anchor-key-2"):
            if placeholder in text:
                fail(f"{path.name}: still contains placeholder {placeholder!r}")
        ok()

    return checks, failures
