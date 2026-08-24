# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime's half of the shared cross-store lifecycle vectors.

The corpus (``tests/fixtures/device_lifecycle_vectors.json``) is the
contract in executable form: ori-specs/device-provisioning/v1.md requires
lifecycle vectors "agreed byte-for-byte by every implementing repository"
before an implementation may claim the contract. The independent verifier holds the
same bytes and derives the same epoch identifiers from them with its own
canonicalizer. It does not yet implement the anchor lifecycle, so it
executes the epoch half of this corpus and declares the scenario half
explicitly unimplemented.

These tests drive the **real** ``StateStore``. No scenario expectation
is derived from the store: the generator never observes it, and every
``expect`` and ``final_state`` was written from the contract section
named in the scenario's ``contract_ref``. A store that deviates
therefore fails here instead of silently redefining the corpus, which a
corpus recorded from the implementation could never do -- that kind
certifies whatever the code does today, including its bugs.

One test does call the generator, but only to confirm the committed
fixture is exactly what the generator produces.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from ori.security.firmware_telemetry import anchor_epoch_id, key_epoch_id
from ori.state.store import StateStore

FIXTURE = Path(__file__).parent / "fixtures" / "device_lifecycle_vectors.json"
VECTORS = json.loads(FIXTURE.read_text())

# SHA-256 of the complete corpus. The independent verifier pins this same constant over
# its own copy, and both must be updated together. Pinning it in only one
# repository would not catch drift: each copy would still match its own
# stale constant while the two files diverged. Asserting the identical
# digest on both sides means a regeneration that is not mirrored fails on
# the side that moved.
FIXTURE_SHA256 = "360f240ab321941bbb8134bbb6e82ac4bdea086cd03fc6013e8b2929a9a8bfac"

ANCHORS = VECTORS["anchors"]
DEVICE_ID = VECTORS["device_id"]

# Transitions that change what a receiver will accept. These are the ones
# the contract requires to be attributed; `registered`, `superseded` and
# `discarded` are bookkeeping consequences, not operator decisions.
AUDITED = {"promoted", "revoked", "reinstated", "reprovisioned"}

ACTOR = "uid=0:test-operator (lifecycle vectors)"
REASON = "cross-store lifecycle vector"


def anchor_call_fields(name: str) -> dict[str, str]:
    """The store arguments for a named anchor.

    ``manifest_json`` carries the capability hash so the stored manifest
    and the anchor cannot drift apart in a fixture, even though the
    lifecycle itself treats the manifest as opaque.
    """
    a = ANCHORS[name]
    return {
        "public_key_b64": a["public_key_b64"],
        "posture": a["posture"],
        "capability_hash": a["capability_hash"],
        "manifest_json": json.dumps(
            {"capability_hash": a["capability_hash"], "posture": a["posture"]},
            sort_keys=True,
        ),
        "channel_map_json": "{}",
    }


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "lifecycle.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def test_fixture_digest_is_pinned():
    """Changing the corpus must be a deliberate, cross-repo act.

    The independent verifier consumes these exact bytes. Regenerating here without
    mirroring there would leave the two stores disagreeing about the
    contract while both test suites stayed green.
    """
    digest = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert digest == FIXTURE_SHA256, (
        "the lifecycle corpus changed. Copy it to the verifier's "
        "tests/fixtures/ and update the pinned digest in BOTH "
        f"repositories to {digest}"
    )


def test_fixture_matches_its_generator():
    """The committed corpus must be exactly what the generator produces.

    The independent verifier consumes this file byte-for-byte. If it could drift
    from its generator, a hand-edit would become the cross-store contract
    without anything noticing, and regenerating would then silently
    revert another repository's expectations.
    """
    # Loaded by path rather than imported: `scripts/` is not a package
    # and is only importable because of where pytest happens to put the
    # rootdir, which is not a property worth depending on.
    spec = importlib.util.spec_from_file_location(
        "_lifecycle_vector_generator",
        Path(__file__).parents[1] / "scripts" / "generate_device_lifecycle_vectors.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert VECTORS == module.build(), (
        "tests/fixtures/device_lifecycle_vectors.json is stale; "
        "re-run scripts/generate_device_lifecycle_vectors.py"
    )


# ── Epoch identifiers ────────────────────────────────────────────────


@pytest.mark.parametrize("vector", VECTORS["epoch_vectors"], ids=lambda v: v["anchor"])
def test_epoch_ids_match_the_corpus(vector):
    """Independent derivations must agree.

    ``anchor_epoch_id`` is the value cross-store agreement is expressed
    in, so if the runtime and the verifier derive it differently, "both stores
    accepted the same epoch" becomes unfalsifiable.
    """
    i = vector["input"]
    assert (
        key_epoch_id(device_id=i["device_id"], public_key_b64=i["public_key_b64"])
        == vector["key_epoch_id"]
    )
    assert anchor_epoch_id(**i) == vector["anchor_epoch_id"]


def test_epoch_canonical_preimages_hash_to_the_declared_ids():
    """The recorded pre-image bytes must actually produce the recorded id.

    Without this, the canonical bytes and the hash could disagree and
    every implementation reading only the hash would still pass, leaving
    another language no way to localise a mismatch.
    """
    for v in VECTORS["epoch_vectors"]:
        for pre_key, id_key in (
            ("key_epoch_canonical_hex", "key_epoch_id"),
            ("anchor_epoch_canonical_hex", "anchor_epoch_id"),
        ):
            digest = hashlib.sha256(bytes.fromhex(v[pre_key])).hexdigest()
            assert v[id_key] == f"sha256:{digest}", (v["anchor"], pre_key)


def test_key_epoch_ignores_manifest_and_posture():
    """Freshness is scoped to the key epoch, so it must not move when only
    the manifest or posture changes -- otherwise a manifest update would
    reopen the replay window."""
    same_key = [
        v
        for v in VECTORS["epoch_vectors"]
        if v["input"]["public_key_b64"] == ANCHORS["A1"]["public_key_b64"]
    ]
    assert len({v["key_epoch_id"] for v in same_key}) == 1
    # ...while the anchor epoch does distinguish them.
    assert len({v["anchor_epoch_id"] for v in same_key}) == len(same_key)


# ── Lifecycle scenarios ──────────────────────────────────────────────


async def run_step(store: StateStore, step: dict) -> None:
    op = step["op"]

    if op == "register":
        outcome = await store.upsert_firmware_device_anchor(
            device_id=DEVICE_ID, **anchor_call_fields(step["anchor"])
        )
    elif op == "reprovision":
        outcome = await store.reprovision_firmware_device(
            device_id=DEVICE_ID,
            actor=ACTOR,
            reason=REASON,
            **anchor_call_fields(step["anchor"]),
        )
    elif op == "promote":
        outcome = await store.approve_firmware_device(
            DEVICE_ID, actor=ACTOR, reason=REASON
        )
    elif op == "revoke":
        outcome = await store.revoke_firmware_device(
            DEVICE_ID, actor=ACTOR, reason=REASON
        )
    elif op == "reinstate":
        outcome = await store.reinstate_firmware_device(
            DEVICE_ID, actor=ACTOR, reason=REASON
        )
    elif op == "advance_freshness":
        outcome = await store.advance_firmware_freshness(
            DEVICE_ID, boot_id=step["boot_id"], seq=step["seq"]
        )
    elif op == "allocate_cmd_seq":
        outcome = await store.allocate_firmware_command_seq(DEVICE_ID)
    elif op == "assert_active":
        row = await store.get_firmware_device(DEVICE_ID)
        expected = anchor_epoch_id(device_id=DEVICE_ID, **_epoch_input(step["anchor"]))
        assert row["anchor_epoch_id"] == expected, (
            f"active anchor should still be {step['anchor']}"
        )
        return
    else:  # pragma: no cover - a typo in the corpus must not pass silently
        raise AssertionError(f"unknown op {op!r}")

    assert outcome == step["expect"], (
        f"{op}: expected {step['expect']!r}, got {outcome!r}"
    )


def _epoch_input(name: str) -> dict[str, str]:
    a = ANCHORS[name]
    return {
        "public_key_b64": a["public_key_b64"],
        "posture": a["posture"],
        "capability_hash": a["capability_hash"],
    }


def epoch_of(name: str) -> str:
    return anchor_epoch_id(device_id=DEVICE_ID, **_epoch_input(name))


@pytest.mark.parametrize("scenario", VECTORS["scenarios"], ids=lambda s: s["name"])
async def test_lifecycle_scenario(store, scenario):
    for step in scenario["steps"]:
        await run_step(store, step)

    expected = scenario["final_state"]
    row = await store.get_firmware_device(DEVICE_ID)
    assert row is not None

    assert bool(row["approved"]) is expected["approved"]
    assert bool(row["revoked"]) is expected["revoked"]

    history = await store.list_firmware_anchor_history(DEVICE_ID)

    # The registry must point at the active anchor, or at nothing when
    # there is no active anchor. A registry pointing at a superseded or
    # discarded anchor is the split-brain this contract exists to prevent.
    actives = [h for h in history if h["state"] == "active"]
    assert len(actives) <= 1, "an identity may hold at most one active anchor"
    if expected["active"] is None:
        assert actives == []
    else:
        assert len(actives) == 1
        assert actives[0]["anchor_epoch_id"] == epoch_of(expected["active"])
        assert row["anchor_epoch_id"] == actives[0]["anchor_epoch_id"]

    pending = await store.get_pending_firmware_anchor(DEVICE_ID)
    if expected["pending"] is None:
        assert pending is None
    else:
        assert pending is not None
        assert pending["anchor_epoch_id"] == epoch_of(expected["pending"])

    # One row per anchor epoch. Keying the comparison below by epoch id
    # would otherwise collapse duplicates and hide a store that inserted
    # a second row for an anchor it already held.
    ids = [h["anchor_epoch_id"] for h in history]
    assert len(ids) == len(set(ids)), "duplicate anchor rows in history"

    # Anchor history is compared as a COMPLETE mapping. A subset check
    # would let an implementation delete a superseded anchor and still
    # pass, destroying the history that evidence resolves against.
    got = {h["anchor_epoch_id"]: h["state"] for h in history}
    want = {epoch_of(n): s for n, s in expected["anchor_states"].items()}
    assert got == want

    # "Was this anchor ever active, and over which intervals" must survive
    # the anchor's current state changing. This is compared as a COMPLETE
    # mapping over every anchor the scenario touches: an anchor absent
    # from the expectation must have no activation intervals at all, so a
    # store that invented one could not pass by omission.
    want_counts = expected["activation_counts"]
    for name in scenario["anchors_used"]:
        epoch = epoch_of(name)
        intervals = await store.firmware_anchor_activation_intervals(DEVICE_ID, epoch)
        assert len(intervals) == want_counts.get(name, 0), (
            f"{name}: expected {want_counts.get(name, 0)} activation "
            f"interval(s), got {len(intervals)}"
        )

        ever = await store.firmware_anchor_was_ever_active(DEVICE_ID, epoch)
        assert ever is (name in want_counts)

        for iv in intervals:
            # Receiver-anchored ordering: the log's own append order and a
            # timestamp this store assigned. The contract forbids deciding
            # this from device wall-clock time.
            assert iv["activated_seq"] is not None
            assert iv["activated_at_ms"] is not None
            if iv["deactivated_seq"] is not None:
                assert iv["deactivated_seq"] > iv["activated_seq"]

        # An interval must be open exactly while the anchor is active, and
        # closed otherwise. Without this the intervals could end at the
        # wrong moment and still have the right count -- an implementation
        # that closed one at re-provisioning rather than at the promotion
        # that followed would look identical in every scenario that
        # promotes afterwards.
        open_intervals = [i for i in intervals if i["deactivated_seq"] is None]
        is_active_now = expected["active"] == name
        assert len(open_intervals) == (1 if is_active_now else 0), (
            f"{name}: active={is_active_now} but {len(open_intervals)} open interval(s)"
        )

    if "last_boot_id" in expected:
        assert row["last_boot_id"] == expected["last_boot_id"]
    if "last_seq" in expected:
        assert row["last_seq"] == expected["last_seq"]
    transitions = await store.list_firmware_anchor_transitions(DEVICE_ID)
    audited = [t for t in transitions if t["transition"] in AUDITED]
    assert [t["transition"] for t in audited] == expected["transitions"]
    for t in audited:
        assert t["actor"].strip(), f"{t['transition']} recorded without an actor"
        assert t["reason"].strip(), f"{t['transition']} recorded without a reason"


def test_every_scenario_declares_activation_counts():
    """No scenario may opt out of the ever-active assertion.

    Without this, a scenario could quietly drop the field and stop
    checking the property #245 exists to protect.
    """
    for s in VECTORS["scenarios"]:
        assert "activation_counts" in s["final_state"], s["name"]


def test_a_superseded_anchor_that_is_re_registered_is_covered():
    """The contract requires evidence for this specific case, and it is
    the one where current state and history disagree."""
    names = {s["name"] for s in VECTORS["scenarios"]}
    assert "superseded_anchor_re_registered_stays_ever_active" in names
    assert "discarded_anchor_re_registered_returns_to_pending" in names


def test_scenario_names_are_unique():
    """Two scenarios sharing a name makes one invisible to every check
    keyed on it, here and in the verifier's unimplemented-scenario list."""
    names = [s["name"] for s in VECTORS["scenarios"]]
    assert len(names) == len(set(names))


async def test_every_contract_operation_is_covered():
    """The corpus must exercise each lifecycle operation.

    A vector set that quietly stopped covering revocation would still be
    green, which is the failure mode golden corpora are most prone to.
    """
    ops = {step["op"] for s in VECTORS["scenarios"] for step in s["steps"]}
    assert {
        "register",
        "promote",
        "revoke",
        "reinstate",
        "reprovision",
    } <= ops


async def test_every_outcome_code_is_exercised():
    """Every refusal code the store can return must appear in the corpus.

    Refusals are the security-relevant half of this contract; an
    unexercised refusal is an untested one.
    """
    expected_outcomes = {
        step["expect"]
        for s in VECTORS["scenarios"]
        for step in s["steps"]
        if isinstance(step.get("expect"), str)
    }
    assert {
        "registered",
        "unchanged",
        "pending_manifest_epoch",
        "refused_revoked",
        "refused_key_change",
        "reprovisioned",
        "revoked",
        "refused_same_key",
        "refused_key_reuse",
    } <= expected_outcomes


async def test_active_promotion_attribution_is_the_exact_transition(store):
    """The provenance a coordinating store mirrors must be the promotion
    that made the CURRENT active anchor active -- not a later one, and not
    a generic latest transition."""
    d = "ori-edge-attrib-01"

    async def reg(anchor):
        a = ANCHORS[anchor]
        return await store.upsert_firmware_device_anchor(
            device_id=d,
            public_key_b64=a["public_key_b64"],
            posture=a["posture"],
            capability_hash=a["capability_hash"],
            manifest_json="{}",
            channel_map_json="{}",
        )

    # Unknown device: no attribution.
    assert await store.firmware_active_promotion_attribution(d) is None

    await reg("A1")
    # Registered but not promoted: still none.
    assert await store.firmware_active_promotion_attribution(d) is None

    await store.approve_firmware_device(d, actor="uid=1:alice", reason="bring-up")
    got = await store.firmware_active_promotion_attribution(d)
    assert got["actor"] == "uid=1:alice"
    assert got["reason"] == "bring-up"

    # Promote a new manifest epoch with different attribution. The active
    # anchor is now A2, so the attribution must follow it.
    await reg("A2")
    await store.approve_firmware_device(d, actor="uid=2:bob", reason="manifest update")
    got = await store.firmware_active_promotion_attribution(d)
    assert got["actor"] == "uid=2:bob"
    assert got["reason"] == "manifest update"

    # The query is anchored to the ACTIVE anchor, not merely the latest
    # promotion. Inject a spurious later `promoted` transition targeting a
    # DIFFERENT epoch than the registry's active one -- the kind of split
    # this model exists to refuse -- and confirm the attribution still
    # follows the active anchor (A2/bob), not the newer row.
    def _inject() -> None:
        store._conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'promoted', NULL, 'sha256:deadbeef', '',
                    'uid=9:intruder', 'not the active anchor', 99999999999999)
            """,
            (d,),
        )
        store._conn.commit()

    await store._run_write(_inject)
    got = await store.firmware_active_promotion_attribution(d)
    assert got is not None
    assert got["actor"] == "uid=2:bob", "attribution must follow the active anchor"

    # Revoked: no active anchor, so no attribution to mirror.
    await store.revoke_firmware_device(d, actor="uid=2:bob", reason="compromised")
    assert await store.firmware_active_promotion_attribution(d) is None
