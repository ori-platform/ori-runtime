# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""gateway-api/v2 Payload Member Rule, driven from the vendored corpus.

Every case goes through the runtime's scanner, and the cases for each topic the
runtime receives on go through that topic's real entry point: a refused case
reaches no verifier and changes nothing, an admitted one gets past the rule.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from ori.gateway.evidence_inbound import (
    EvidenceInboundRouter,
    InboundRefusal,
    _decode,
)
from ori.gateway.evidence_outbound import ROUTED_REFUSED, EvidenceOutboundAckRouter
from ori.gateway.export import GatewayExportResponder
from ori.gateway.heartbeat import MqttGatewayHeartbeatSubscriber
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
    GatewayMessageEncryptionConfig,
    GatewayMessageEncryptionError,
    GatewayMessageEncryptor,
)
from ori.security.payload_members import (
    CASE_VARIANT_MEMBER,
    DUPLICATE_MEMBER,
    EVIDENCE_INBOUND_MEMBERS,
    EVIDENCE_OUTBOUND_ACK_MEMBERS,
    EXPORT_REQUEST_MEMBERS,
    EXPORT_RESPONSE_ITEM_MEMBERS,
    EXPORT_RESPONSE_MEMBERS,
    GATEWAY_HEALTH_MEMBERS,
    REASONING_RESPONSE_MEMBERS,
    REASONS,
    PayloadMemberError,
    admitted_object,
    fold,
    refusal,
)
from tests.gateway_auth_helpers import cache_for
from tests.waiting import latency_bounds_apply

#: Generous: a megabyte scans in milliseconds; a quadratic scan in minutes.
_BOUND_S = 2.0

CORPUS = json.loads(
    (
        Path(__file__).parent / "vectors" / "gateway_api" / "payload-members-v2.json"
    ).read_text()
)
CASES = CORPUS["cases"]

#: The runtime's own sets for the topics it reads, by topic.
RUNTIME_SETS = {
    "ori/gateway/health": GATEWAY_HEALTH_MEMBERS,
    "ori/{device_id}/reasoning/response": REASONING_RESPONSE_MEMBERS,
    "ori/{device_id}/export/request": EXPORT_REQUEST_MEMBERS,
    "ori/{device_id}/export/response/{request_id}": EXPORT_RESPONSE_MEMBERS,
    "ori/{device_id}/evidence/outbound/ack": EVIDENCE_OUTBOUND_ACK_MEMBERS,
    "ori/{device_id}/evidence/inbound": EVIDENCE_INBOUND_MEMBERS,
}


#: The runtime's own item member sets, by topic.
RUNTIME_ITEM_SETS = {
    "ori/{device_id}/export/response/{request_id}": EXPORT_RESPONSE_ITEM_MEMBERS,
}


def _item_defined(case: dict[str, Any]) -> frozenset[str]:
    family = case["family"]
    if family is None:
        return frozenset()
    return RUNTIME_ITEM_SETS.get(
        family, frozenset(CORPUS["item_members"].get(family, ()))
    )


def _defined(case: dict[str, Any]) -> frozenset[str]:
    family = case["family"]
    if family is None:
        return frozenset()
    return RUNTIME_SETS.get(family, frozenset(CORPUS["families"][family]))


def _cases_for(topic: str) -> list[dict[str, Any]]:
    return [case for case in CASES if case["family"] == topic]


def test_the_reasons_are_the_contract_reasons_in_its_order():
    assert list(REASONS) == CORPUS["reasons"]


@pytest.mark.parametrize("topic", sorted(RUNTIME_SETS))
def test_the_runtimes_member_sets_are_the_contracts(topic):
    assert sorted(RUNTIME_SETS[topic]) == CORPUS["families"][topic]


def test_the_runtimes_item_member_sets_are_the_contracts():
    assert {topic: sorted(names) for topic, names in RUNTIME_ITEM_SETS.items()} == (
        CORPUS["item_members"]
    )


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_every_case_reaches_its_verdict(case):
    got = refusal(
        bytes.fromhex(case["payload_hex"]),
        defined=_defined(case),
        item_defined=_item_defined(case),
    )
    assert (got or "accept") == case["expected"], case["description"]


def test_the_corpus_covers_every_reason():
    assert {case["expected"] for case in CASES} == {"accept", *REASONS}


def test_the_closed_fold_is_closed():
    assert fold("STATUS") == "status"
    assert fold("ſtatus") == "status" and fold("Key") == "key"
    # Unicode case folding is deliberately not used.
    for name in ("ß", "ẞ", "ς", "σ", "Σ", "İ", "ı"):
        assert fold(name) == name


def test_an_admitted_payload_is_read_with_one_reading():
    assert admitted_object(b'{"a":1,"b":[{"c":2}]}') == {"a": 1, "b": [{"c": 2}]}
    with pytest.raises(PayloadMemberError) as refused:
        admitted_object(b'{"a":1,"a":2}')
    assert refused.value.reason == DUPLICATE_MEMBER
    with pytest.raises(PayloadMemberError) as refused:
        admitted_object(b'{"status":1}', defined=frozenset({"STATUS"}))
    assert refused.value.reason == CASE_VARIANT_MEMBER


_ITEM = frozenset({"status"})


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b'{"items":[{"STATUS":1}]}', CASE_VARIANT_MEMBER),
        (b'{"items":[1,{"Status":1}]}', CASE_VARIANT_MEMBER),
        (b'{"x":1,"items":[{"STATUS":1}],"y":2}', CASE_VARIANT_MEMBER),
        # Only an element of the root object's own items array.
        (b'{"STATUS":1}', None),
        (b'{"items":{"STATUS":1}}', None),
        (b'{"items":[[{"STATUS":1}]]}', None),
        (b'{"items":[{"inner":{"STATUS":1}}]}', None),
        (b'{"other":[{"STATUS":1}]}', None),
        (b'{"a":{"items":[{"STATUS":1}]}}', None),
        (b'[{"items":[{"STATUS":1}]}]', "not_an_object"),
        (b'{"items":[],"x":[{"STATUS":1}]}', None),
    ],
)
def test_item_members_hold_only_in_root_item_elements(payload, expected):
    got = refusal(payload, defined=frozenset({"items"}), item_defined=_ITEM)
    assert got == expected


def test_an_integer_python_cannot_convert_reaches_its_section_as_infinite():
    assert admitted_object(b'{"n":' + b"9" * 5000 + b"}") == {"n": float("inf")}


def _variants(count: int) -> bytes:
    """*count* case variants of one name in one object."""
    names = (
        "".join(
            c.upper() if (i >> b) & 1 else c for b, c in enumerate("abcdefghijklmnopq")
        )
        for i in range(count)
    )
    return b"{" + b",".join(b'"%s":1' % n.encode() for n in names) + b"}"


#: Shapes a hostile payload of the largest family's size can take.
_SHAPES = {
    "one_long_string": lambda n: b'{"artifact_b64":"' + b"A" * n + b'"}',
    "case_variants": lambda n: _variants(n // 22),
    "repeats": lambda n: b"{" + b'"a":1,' * (n // 6) + b'"a":1}',
    "deep_arrays": lambda n: b"[" * n,
    "deep_objects": lambda n: b'{"a":' * (n // 5),
    "short_strings": lambda n: b"[" + b'"a",' * (n // 4) + b'"a"]',
    "numbers": lambda n: b"[" + b"1," * (n // 2) + b"1]",
}


@pytest.mark.parametrize("shape", sorted(_SHAPES))
def test_a_large_payload_is_scanned_in_linear_time(shape):
    """An inbound evidence payload may be a megabyte; the scan must not be
    quadratic in it, whatever the payload's shape. Four times the bytes may
    cost no more than eight times the time: quadratic would be sixteen."""
    import time

    build = _SHAPES[shape]
    small, large = build(1_114_112 // 4), build(1_114_112)

    def cost(payload: bytes) -> float:
        started = time.perf_counter()
        refusal(payload)
        return time.perf_counter() - started

    small_s = min(cost(small) for _ in range(3))
    large_s = cost(large)
    if latency_bounds_apply():
        assert large_s < _BOUND_S
        assert large_s < 8 * small_s + 0.05, (small_s, large_s)


# -- through each entry point ---------------------------------------------


def _expected_refusal(case: dict[str, Any]) -> str | None:
    return None if case["expected"] == "accept" else case["expected"]


_INBOUND = _cases_for("ori/{device_id}/evidence/inbound")


@pytest.mark.parametrize("case", _INBOUND, ids=[c["name"] for c in _INBOUND])
def test_the_inbound_route_refuses_each_case_for_its_reason(case):
    router = EvidenceInboundRouter(device_id="site-a-edge-01", ingest=None)
    outcome = router.handle_payload(bytes.fromhex(case["payload_hex"])).outcome
    expected = _expected_refusal(case)
    if expected is None:
        assert not (isinstance(outcome, InboundRefusal) and outcome.reason in REASONS)
    else:
        assert isinstance(outcome, InboundRefusal) and outcome.reason == expected


_ACKS = _cases_for("ori/{device_id}/evidence/outbound/ack")


@pytest.mark.parametrize("case", _ACKS, ids=[c["name"] for c in _ACKS])
def test_the_ack_route_refuses_each_case_for_its_reason(case):
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="s"),
        replay_cache=cache_for(GatewayMessageAuthConfig(shared_secret="s")),
    )
    router = EvidenceOutboundAckRouter(
        device_id="site-a-edge-01",
        outbox=None,  # type: ignore[arg-type]
        message_auth=auth,  # type: ignore[arg-type]
    )
    with patch.object(auth, "authenticate", side_effect=AssertionError("read")):
        expected = _expected_refusal(case)
        if expected is None:
            with pytest.raises(AssertionError, match="read"):
                asyncio.run(router.handle_ack(bytes.fromhex(case["payload_hex"])))
        else:
            routed = asyncio.run(router.handle_ack(bytes.fromhex(case["payload_hex"])))
            assert routed.outcome == ROUTED_REFUSED and routed.reason == expected


_EXPORTS = _cases_for("ori/{device_id}/export/request")


@pytest.mark.parametrize("case", _EXPORTS, ids=[c["name"] for c in _EXPORTS])
def test_the_export_responder_reads_no_refused_request(case):
    responder = GatewayExportResponder(
        device_id="site-a-edge-01",
        state_store=None,
        health_snapshot_provider=dict,
    )
    served = AsyncMock(return_value=None)
    with patch.object(responder, "handle_request", served):
        asyncio.run(responder.handle_payload(bytes.fromhex(case["payload_hex"])))
    if case["expected"] != "accept":
        assert served.await_count == 0, "a refused request reached a reader"
    elif not _routing_id_missing(case):
        assert served.await_count == 1, "an admitted request was not served"


def _routing_id_missing(case: dict[str, Any]) -> bool:
    """An admitted request with no routable request_id is not answered either."""
    if case["expected"] != "accept":
        return False
    payload = json.loads(bytes.fromhex(case["payload_hex"]))
    return not isinstance(payload.get("request_id"), str)


_HEALTH = _cases_for("ori/gateway/health")


@pytest.mark.parametrize("case", _HEALTH, ids=[c["name"] for c in _HEALTH])
def test_the_heartbeat_subscriber_reads_no_refused_heartbeat(case):
    auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="s"),
        replay_cache=cache_for(GatewayMessageAuthConfig(shared_secret="s")),
    )
    sub = MqttGatewayHeartbeatSubscriber(
        broker_url="mqtt://localhost",
        posture_tracker=SimpleNamespace(),  # type: ignore[arg-type]
        device_id="site-a-edge-01",
        authenticator=auth,
        client_factory=lambda **_: None,
    )
    sub._loop = SimpleNamespace()  # type: ignore[assignment]
    message = SimpleNamespace(payload=bytes.fromhex(case["payload_hex"]))
    with patch.object(auth, "verify_broadcast", side_effect=AssertionError("read")):
        if case["expected"] == "accept":
            with pytest.raises(AssertionError, match="read"):
                sub._on_message(None, None, message)
        else:
            sub._on_message(None, None, message)


_EXPORT_RESPONSES = _cases_for("ori/{device_id}/export/response/{request_id}")


@pytest.mark.parametrize(
    "case", _EXPORT_RESPONSES, ids=[c["name"] for c in _EXPORT_RESPONSES]
)
def test_a_decrypted_plaintext_is_admitted_under_the_rule(case):
    """The plaintext is a JSON text in its own right, judged under the rule
    before any member of it is read. Each case is truly encrypted under the
    encryptor's own key and authenticated metadata, then decrypted."""
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from ori.security.gateway_messages import (
        _b64encode,
        _derive_encryption_key,
        _encryption_aad,
    )

    secret = "gateway-secret"
    encryptor = GatewayMessageEncryptor(
        GatewayMessageEncryptionConfig(shared_secret=secret)
    )
    metadata = {
        "request_id": "req-1",
        "device_id": "site-a-edge-01",
        "export_type": "health",
    }
    nonce = os.urandom(12)
    ciphertext = AESGCM(_derive_encryption_key(secret)).encrypt(
        nonce,
        bytes.fromhex(case["payload_hex"]),
        _encryption_aad(metadata, message_type="export_response"),
    )
    payload = {
        **metadata,
        "encrypted": True,
        "encryption": {
            "scheme": "aes-256-gcm",
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        },
    }
    try:
        encryptor.decrypt(
            payload,
            message_type="export_response",
            expected_device_id="site-a-edge-01",
        )
        refused = None
    except GatewayMessageEncryptionError as exc:
        refused = str(exc)
    if case["expected"] == "accept":
        # Admitted, it may still fail its metadata check, never the rule.
        assert refused is None or not refused.startswith("invalid_plaintext")
    else:
        assert refused == f"invalid_plaintext: {case['expected']}"


async def test_the_inbound_route_scans_off_the_event_loop():
    """A megabyte under the rule is CPU work; the loop Tier D runs on is not
    where it happens."""
    import threading

    loop_thread = threading.current_thread()
    seen: list[threading.Thread] = []
    real = _decode

    def recorded(payload):
        seen.append(threading.current_thread())
        return real(payload)

    router = EvidenceInboundRouter(device_id="site-a-edge-01", ingest=None)
    with patch("ori.gateway.evidence_inbound._decode", recorded):
        routed = await router.route(b'{"a":1,"a":2}')
    assert isinstance(routed.outcome, InboundRefusal)
    assert routed.outcome.reason == DUPLICATE_MEMBER
    assert seen and all(thread is not loop_thread for thread in seen)


@pytest.mark.parametrize(
    "inner, defined, expected",
    [
        (b'{"a":1,"a":2}', frozenset(), DUPLICATE_MEMBER),
        (b'{"a":1,"A":2}', frozenset(), CASE_VARIANT_MEMBER),
        (b'{"STATUS":1}', frozenset({"status"}), CASE_VARIANT_MEMBER),
    ],
)
def test_names_are_judged_at_the_deepest_allowed_depth(inner, defined, expected):
    """An object at depth 32 is within the limit, so its names are judged; one
    at depth 33 is too deep, which outranks them."""
    at_32 = b"[" * 31 + inner + b"]" * 31
    assert refusal(at_32, defined=defined) == expected
    assert refusal(b"[" + at_32 + b"]", defined=defined) == "nesting_too_deep"


def test_an_unconvertible_integer_follows_the_interpreters_own_limit():
    import sys

    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        assert admitted_object(b'{"n":' + b"9" * 1000 + b"}") == {"n": float("inf")}
        assert admitted_object(b'{"n":' + b"9" * 600 + b"}") == {"n": int("9" * 600)}
    finally:
        sys.set_int_max_str_digits(previous)
