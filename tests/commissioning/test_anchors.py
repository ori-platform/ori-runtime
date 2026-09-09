# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Commissioning anchors: read from the fixed environment locations, as key material."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.security.commissioning.anchors import (
    COMMISSIONING_ANCHOR_ENV,
    COMMISSIONING_ANCHOR_PREVIOUS_ENV,
    AnchorError,
    anchor_collision,
    load_commissioning_anchors,
)
from ori.security.published_test_keys import PUBLISHED_TEST_KEYS


def _key() -> bytes:
    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def test_no_anchor_configured_is_not_an_error() -> None:
    anchors = load_commissioning_anchors({})
    assert anchors.current is None and anchors.previous is None
    assert not anchors.configured


def test_both_generations_are_read_as_raw_key_material() -> None:
    current, previous = _key(), _key()
    anchors = load_commissioning_anchors(
        {
            COMMISSIONING_ANCHOR_ENV: _b64(current),
            COMMISSIONING_ANCHOR_PREVIOUS_ENV: _b64(previous),
        }
    )
    assert anchors.current == current
    assert anchors.previous == previous
    assert anchors.configured


@pytest.mark.parametrize(
    "text",
    [
        "not base64!",
        base64.b64encode(b"short").decode(),
        base64.b64encode(b"x" * 33).decode(),
        "",
    ],
    ids=["not-base64", "too-short", "too-long", "blank-previous-only"],
)
def test_a_key_that_is_not_a_canonical_32_byte_key_is_refused(text: str) -> None:
    env = {COMMISSIONING_ANCHOR_ENV: text or _b64(_key())}
    if text == "":
        env[COMMISSIONING_ANCHOR_PREVIOUS_ENV] = "   "
        anchors = load_commissioning_anchors(env)
        assert anchors.previous is None
        return
    with pytest.raises(AnchorError):
        load_commissioning_anchors(env)


def test_an_alternative_spelling_of_the_same_key_is_refused() -> None:
    """Round-trip equality, like the key inside a binding: one spelling only."""
    raw = _key()
    text = _b64(raw)
    # Flip an unused low bit of the final character; the bytes decode the same.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    index = len(text.rstrip("=")) - 1
    for candidate in alphabet:
        variant = text[:index] + candidate + text[index + 1 :]
        if candidate != text[index] and base64.b64decode(variant, validate=True) == raw:
            with pytest.raises(AnchorError):
                load_commissioning_anchors({COMMISSIONING_ANCHOR_ENV: variant})
            return
    pytest.fail(
        "no alternative spelling found; the canonical rule has nothing to refuse"
    )


def test_a_previous_generation_needs_a_current_one() -> None:
    with pytest.raises(AnchorError):
        load_commissioning_anchors({COMMISSIONING_ANCHOR_PREVIOUS_ENV: _b64(_key())})


def test_the_previous_generation_cannot_be_the_current_one() -> None:
    key = _b64(_key())
    with pytest.raises(AnchorError):
        load_commissioning_anchors(
            {COMMISSIONING_ANCHOR_ENV: key, COMMISSIONING_ANCHOR_PREVIOUS_ENV: key}
        )


def test_collision_is_compared_as_key_material_across_generations() -> None:
    provisioning, current, previous = _key(), _key(), _key()
    anchors = load_commissioning_anchors(
        {
            COMMISSIONING_ANCHOR_ENV: _b64(current),
            COMMISSIONING_ANCHOR_PREVIOUS_ENV: _b64(previous),
        }
    )
    assert not anchor_collision(anchors, provisioning)
    assert anchor_collision(anchors, current)
    assert anchor_collision(anchors, previous)
    assert not anchor_collision(anchors, None)
    assert not anchor_collision(load_commissioning_anchors({}), provisioning)


def test_a_published_test_key_is_refused_as_the_current_anchor() -> None:
    """Its private seed ships in this repository, so it authenticates nobody."""
    published = _b64(next(iter(PUBLISHED_TEST_KEYS)))
    with pytest.raises(AnchorError) as refusal:
        load_commissioning_anchors({COMMISSIONING_ANCHOR_ENV: published})
    assert COMMISSIONING_ANCHOR_ENV in str(refusal.value)
    assert "private seed is published" in str(refusal.value)


def test_a_published_test_key_is_refused_in_the_previous_slot() -> None:
    """A verify-only generation still accepts documents, so it is not exempt."""
    published = _b64(next(iter(PUBLISHED_TEST_KEYS)))
    with pytest.raises(AnchorError) as refusal:
        load_commissioning_anchors(
            {
                COMMISSIONING_ANCHOR_ENV: _b64(_key()),
                COMMISSIONING_ANCHOR_PREVIOUS_ENV: published,
            }
        )
    assert COMMISSIONING_ANCHOR_PREVIOUS_ENV in str(refusal.value)


def test_every_published_test_key_is_refused() -> None:
    """One refused key does not establish that the set is consulted."""
    for raw in PUBLISHED_TEST_KEYS:
        with pytest.raises(AnchorError):
            load_commissioning_anchors({COMMISSIONING_ANCHOR_ENV: _b64(raw)})


def test_a_key_that_was_never_published_is_still_accepted() -> None:
    """The guard refuses published material, not every key it has not seen."""
    fresh = _key()
    anchors = load_commissioning_anchors({COMMISSIONING_ANCHOR_ENV: _b64(fresh)})
    assert anchors.current == fresh
