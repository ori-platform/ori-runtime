# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The refused set must cover every private seed this repository publishes.

The scan is over tracked files rather than one directory, because a seed is
published wherever it is committed: a JSON vector, a fixture, or a Python
literal are all equally readable by anyone with a clone. It also covers seeds
nobody committed but everybody can guess -- a single hex digit repeated, and the
first thirty-two integers -- because those are forgeable whether or not this
repository happens to spell them today.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.security.published_test_keys import PUBLISHED_TEST_KEYS

_ROOT = Path(__file__).resolve().parent.parent
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_B64_32 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_REPEATED_HEX = re.compile(r"""["']([0-9a-fA-F])["'] ?\* ?64""")
_REPEATED_BYTE = re.compile(r'b["\']\\x([0-9a-fA-F]{2})["\'] ?\* ?32')
_FROM_HEX = re.compile(r'bytes\.fromhex\(\s*["\']([0-9a-fA-F]{64})["\']\s*\)')
_RANGE_32 = re.compile(r"bytes\(range\(32\)\)")


def _tracked_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        # Failing loudly matters: the vacuity guard below only means anything
        # if this actually ran. A container bind-mounting the repo under a
        # different uid trips git's safe.directory and exits 128.
        raise AssertionError(
            "cannot list tracked files, so the published-seed scan cannot run: "
            f"`git ls-files` failed in {_ROOT} ({exc}). This needs a git "
            "checkout; in a container, mark the mount safe.directory."
        ) from exc
    return [_ROOT / name for name in result.stdout.split("\0") if name]


def _seeds_in_json(text: str) -> set[bytes]:
    """A 32-byte value under a field whose name says seed."""
    try:
        document = json.loads(text)
    except ValueError:
        return set()
    found: set[bytes] = set()

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
        elif isinstance(node, str) and "seed" in path.lower():
            if _HEX64.match(node):
                found.add(bytes.fromhex(node))
            elif _B64_32.match(node):
                try:
                    raw = base64.b64decode(node, validate=True)
                except ValueError:
                    return None
                if len(raw) == 32:
                    found.add(raw)

    walk(document, "")
    return found


def _seeds_in_source(text: str) -> set[bytes]:
    """The literal forms this repository actually uses to spell a seed."""
    found: set[bytes] = set()
    for digit in _REPEATED_HEX.findall(text):
        found.add(bytes.fromhex(digit * 64))
    for pair in _REPEATED_BYTE.findall(text):
        found.add(bytes([int(pair, 16)]) * 32)
    for value in _FROM_HEX.findall(text):
        found.add(bytes.fromhex(value))
    if _RANGE_32.search(text):
        found.add(bytes(range(32)))
    return found


_ANY_HEX64 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_ANY_B64_32 = re.compile(r"\b[A-Za-z0-9+/]{43}=")


def _key_material(text: str) -> set[bytes]:
    """Every 32-byte value spelled anywhere in this text, whatever it is called."""
    found: set[bytes] = set()
    for token in _ANY_HEX64.findall(text):
        found.add(bytes.fromhex(token))
    for token in _ANY_B64_32.findall(text):
        try:
            raw = base64.b64decode(token, validate=True)
        except ValueError:
            continue
        if len(raw) == 32:
            found.add(raw)
    return found


def _paired_seeds(material: set[bytes]) -> set[bytes]:
    """Values whose derived public key is written down in the same corpus.

    That pairing is what separates a seed from a digest: a published test seed
    is committed beside the key it derives, because that is what makes it usable
    to verify against. A sha256 digest derives a key that appears nowhere.
    """
    return {candidate for candidate in material if public_key(candidate) in material}


@lru_cache(maxsize=1)
def published_seeds() -> frozenset[bytes]:
    """Every seed a clone of this repository hands you, plus the guessable ones."""
    seeds: set[bytes] = {bytes.fromhex(digit * 64) for digit in "0123456789abcdef"}
    seeds.add(bytes(range(32)))
    material: set[bytes] = set()
    for path in _tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            # Undecodable means no readable literal; a binary blob carrying a
            # seed would be a different finding than this scan is looking for.
            continue
        seeds |= _seeds_in_source(text)
        seeds |= _seeds_in_json(text)
        material |= _key_material(text)
    # Any 32-byte value whose derived public key is also written down here was
    # published to be verified against, whatever field or format spelled it.
    # A digest derives a key that appears nowhere, so this admits seeds without
    # sweeping in every sha256 in the tree.
    seeds |= _paired_seeds(material)
    return frozenset(seeds)


def public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


GUESSABLE = {bytes.fromhex(digit * 64) for digit in "0123456789abcdef"} | {
    bytes(range(32))
}


def test_the_file_scan_contributes_seeds_of_its_own() -> None:
    """A scan that silently read nothing would still return GUESSABLE and pass.

    Asserting a total would not catch that, so this asserts what only reading
    tracked files can supply.
    """
    from_files = published_seeds() - GUESSABLE
    assert len(from_files) >= 8


def test_the_default_test_signer_is_refused() -> None:
    """A scan of tests/vectors alone missed this one, and it was the default.

    It signed commissioning documents across the test tree, so a runtime that
    accepted it accepted documents from anyone holding a clone.
    """
    assert public_key(bytes.fromhex("7" * 64)) in PUBLISHED_TEST_KEYS


def test_every_published_seed_derives_a_refused_key() -> None:
    missing = sorted(
        base64.b64encode(public_key(seed)).decode("ascii")
        for seed in published_seeds()
        if public_key(seed) not in PUBLISHED_TEST_KEYS
    )
    assert not missing, (
        "these keys have published or guessable private seeds and would be "
        f"accepted as trust anchors: {missing}. Add them to "
        "PUBLISHED_TEST_KEYS_B64 in ori/security/published_test_keys.py."
    )


def test_the_refused_set_carries_only_thirty_two_byte_keys() -> None:
    """A typo'd entry would decode to something no anchor can ever equal."""
    assert all(len(key) == 32 for key in PUBLISHED_TEST_KEYS)


def test_a_published_key_cannot_verify_a_configuration_signature() -> None:
    """The config anchor carries the Tier D threshold input, so it is not exempt.

    `device.rated_capacity_amps` scales the Tier D trip point, and production
    posture requires a verified signature -- a mandated gate that a key anyone
    can sign with would satisfy.
    """
    from ori.security.config_signatures import (
        ConfigSignatureError,
        _verify_ed25519_signature,
    )

    seed = bytes.fromhex("5" * 64)
    signing = Ed25519PrivateKey.from_private_bytes(seed)
    payload = b"a configuration this runtime would otherwise trust"

    with pytest.raises(ConfigSignatureError) as refusal:
        _verify_ed25519_signature(
            signature="ed25519:" + base64.b64encode(signing.sign(payload)).decode(),
            public_key_b64=base64.b64encode(public_key(seed)).decode(),
            payload=payload,
            anchor_env="ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64",
        )
    assert "private seed is published" in str(refusal.value)
    assert "ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64" in str(refusal.value)


def test_a_published_key_is_not_read_as_a_provisioning_anchor() -> None:
    from ori.security.commissioning.anchors import provisioning_anchor

    security = {"config_signature": {"trust_anchor_env": "ORI_TEST_PROV_ANCHOR"}}
    published = base64.b64encode(next(iter(PUBLISHED_TEST_KEYS))).decode("ascii")
    assert provisioning_anchor(security, {"ORI_TEST_PROV_ANCHOR": published}) is None


def test_the_source_scan_reads_every_seed_form_this_repository_uses() -> None:
    """Proven against synthetic text, not repository contents.

    Every seed committed today is either a repeated hex digit or lives in a
    vector file, so no tracked file distinguishes a working scan from a broken
    one. These assert the logic directly, so a future seed in a new place is
    caught rather than discovered by an attacker.
    """
    assert bytes.fromhex("3" * 64) in _seeds_in_source('SEED = "3" * 64')
    assert bytes.fromhex("3" * 64) in _seeds_in_source("SEED = '3'*64")
    assert bytes([0x22]) * 32 in _seeds_in_source('key = b"\\x22" * 32')
    assert bytes(range(32)) in _seeds_in_source("key = bytes(range(32))")
    novel = "9f" + "0" * 62
    assert bytes.fromhex(novel) in _seeds_in_source(f'seed = bytes.fromhex("{novel}")')
    assert _seeds_in_source("nothing to see here") == set()


def test_the_json_scan_reads_hex_and_base64_under_a_seed_named_field() -> None:
    novel = bytes.fromhex("ab" + "0" * 62)
    assert novel in _seeds_in_json(json.dumps({"signing_seed_hex": novel.hex()}))
    assert novel in _seeds_in_json(
        json.dumps({"nested": {"key_seed": base64.b64encode(novel).decode()}})
    )
    assert _seeds_in_json(json.dumps({"public_key_hex": novel.hex()})) == set()
    assert _seeds_in_json("not json at all") == set()


def test_a_seed_is_found_by_its_derived_key_whatever_spelled_it() -> None:
    """The scan must not depend on a field name or a file format.

    A seed committed in Markdown, in a shell script, or under a JSON key that
    does not say "seed" is published just the same. What makes it findable is
    that the key it derives is written down beside it, which is what makes a
    published test key usable in the first place.
    """
    seed = bytes.fromhex("c7" + "3d" * 31)
    spelled_beside_its_key = (
        f"the bench signer is {seed.hex()} and its anchor is "
        f"{base64.b64encode(public_key(seed)).decode()}"
    )
    material = _key_material(spelled_beside_its_key)
    assert seed in material and public_key(seed) in material
    assert seed in _paired_seeds(material)


def test_a_lone_value_with_no_matching_key_is_not_treated_as_a_seed() -> None:
    """Otherwise every sha256 digest in the tree would be refused as a key."""
    digest = bytes.fromhex("ab" * 32)
    material = _key_material(f"sha256:{digest.hex()}")
    assert digest in material
    assert _paired_seeds(material) == set()
