# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The shared delivery vectors, read by the Python producer.

`tests/vectors/telemetry_delivery/delivery_cases.json` is one decision table
for how a producer reads a receiver's answer. The Android payload evaluates the
same file in its own crate tests, so a rule can only be implemented one way in
each and a disagreement fails somewhere rather than being argued about.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from ori.telemetry.delivery import (
    MAX_RESPONSE_BYTES,
    TERMINAL_REFUSALS,
    DeliveryOutcome,
    body_is_wanted,
    read_answer,
    read_batch_response,
)

VECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "vectors"
    / "telemetry_delivery"
    / "delivery_cases.json"
)
CONTRACT = json.loads(VECTOR_PATH.read_text())
CASES: list[dict[str, Any]] = CONTRACT["cases"]


def _parse_with_h11(raw: bytes) -> tuple[int | None, list, bytes | None]:
    """Read a whole response as the exporter's client does: h11 under httpcore.

    Interim responses are read past except 101, the body is read only when
    `body_is_wanted`, and reading stops past the ceiling. A response h11
    refuses is no answer.
    """
    import h11

    connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=102_400)
    connection.send(
        h11.Request(
            method="POST",
            target="/",
            headers=[("Host", "receiver"), ("Content-Length", "0")],
        )
    )
    connection.send(h11.EndOfMessage())
    connection.receive_data(raw)
    connection.receive_data(b"")
    status: int | None = None
    fields: list = []
    body = bytearray()
    try:
        while True:
            event = connection.next_event()
            if isinstance(event, h11.InformationalResponse):
                if event.status_code == 101:
                    return 101, list(event.headers.raw_items()), None
                continue
            if isinstance(event, h11.Response):
                status = event.status_code
                fields = list(event.headers.raw_items())
                if not body_is_wanted(fields):
                    return status, fields, None
            elif isinstance(event, h11.Data):
                body += event.data
                if len(body) > MAX_RESPONSE_BYTES:
                    return status, fields, None
            elif isinstance(event, h11.EndOfMessage):
                return status, fields, bytes(body)
            else:
                return None, [], None
    except h11.RemoteProtocolError:
        return None, [], None


def _invoke(case: dict[str, Any]):
    response = case["response"]
    batch_events = case["batch_events"]
    if "transport_error" in response:
        return read_batch_response(status=None, batch_events=batch_events)
    if "raw_response_b64" in response:
        status, fields, body = _parse_with_h11(
            base64.b64decode(response["raw_response_b64"])
        )
        return read_answer(
            status=status, fields=fields, body=body, batch_events=batch_events
        )
    if "body_b64" in response:
        body = base64.b64decode(response["body_b64"])
    elif "body_raw" in response:
        body = response["body_raw"].encode()
    elif "body" in response:
        body = json.dumps(response["body"]).encode()
    else:
        body = None
    fields = []
    for key, name in (
        ("content_type", "Content-Type"),
        ("www_authenticate", "WWW-Authenticate"),
        ("content_encoding", "Content-Encoding"),
    ):
        value = response.get(key)
        for item in (
            value if isinstance(value, list) else ([] if value is None else [value])
        ):
            fields.append((name.encode(), item.encode("latin-1")))
    return read_answer(
        status=response["status"], fields=fields, body=body, batch_events=batch_events
    )


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_every_delivery_vector_reaches_its_recorded_outcome(
    case: dict[str, Any],
) -> None:
    verdict = _invoke(case)
    expected = case["expect"]

    assert verdict.outcome == DeliveryOutcome(expected["outcome"]), (
        f"{case['name']}: {case['why']}\ngot reason: {verdict.reason}"
    )
    assert verdict.declined_events == expected["declined_events"], case["name"]
    assert verdict.refused_events == expected["refused_events"], case["name"]
    assert verdict.receiver_answered is expected["receiver_answered"], case["name"]
    if "body_unreadable" in expected:
        assert verdict.body_unreadable is expected["body_unreadable"], case["name"]
    if "duplicate_events" in expected:
        assert verdict.duplicate_events == expected["duplicate_events"], case["name"]
    if "nonconformant_body" in expected:
        assert verdict.nonconformant_body is expected["nonconformant_body"], case[
            "name"
        ]


def test_the_vector_set_covers_all_three_outcomes() -> None:
    """A table that exercised one branch would pass while two went unread."""
    reached = {DeliveryOutcome(c["expect"]["outcome"]) for c in CASES}
    assert reached == set(DeliveryOutcome)


def test_declined_and_refused_are_never_counted_together() -> None:
    """The contract requires the two counters be distinct, so no case feeds both."""
    for case in CASES:
        expected = case["expect"]
        assert not (expected["declined_events"] and expected["refused_events"]), case[
            "name"
        ]


def test_case_names_are_unique() -> None:
    """A duplicate name silently drops a case from a parametrised run."""
    names = [c["name"] for c in CASES]
    assert len(names) == len(set(names))


def test_an_empty_batch_is_refused_without_raising() -> None:
    """A 200 for nothing sent cannot be told from a 200 for everything discarded.

    It returns a verdict rather than raising, and both producers return the same
    one. Raising here would reach the flush loop's own exception handler, which
    logs and continues -- losing the batch the flush had already drained.
    """
    verdict = read_batch_response(status=200, batch_events=0)
    assert verdict.outcome is DeliveryOutcome.RETAIN


def test_suspension_needs_every_recorded_property_of_the_refusal() -> None:
    """Each property dropped in turn must stop suspending.

    Written as the loss of one property at a time rather than as one happy
    case, because a check that required only the status would pass a test that
    supplied all four.
    """
    detail = TERMINAL_REFUSALS[403]
    body = json.dumps({"detail": detail}).encode()
    complete: dict[str, Any] = dict(
        status=403,
        content_type="application/json",
        www_authenticate=None,
        body=body,
        batch_events=1,
    )
    assert read_batch_response(**complete).outcome is DeliveryOutcome.SUSPEND

    for field, value in (
        ("status", 401),
        ("content_type", "text/html"),
        ("www_authenticate", 'Bearer realm="api"'),
        ("body", json.dumps({"detail": "access denied"}).encode()),
        ("body", b""),
    ):
        weakened: dict[str, Any] = {**complete, field: value}
        assert read_batch_response(**weakened).outcome is not DeliveryOutcome.SUSPEND, (
            field
        )


def test_no_answer_is_ever_a_reason_to_stop() -> None:
    """Every status a receiver or an intermediary can return yields a verdict."""
    for status in (
        200,
        201,
        204,
        301,
        400,
        401,
        403,
        404,
        410,
        415,
        422,
        429,
        500,
        503,
    ):
        verdict = read_batch_response(
            status=status, content_type="text/plain", body=b"x", batch_events=1
        )
        assert verdict.outcome in set(DeliveryOutcome)


def test_a_header_section_is_readable_up_to_its_field_limit() -> None:
    from ori.telemetry.delivery import MAX_HEADER_FIELD_BYTES, readable_header_section

    def padded(total: int) -> list[tuple[bytes, bytes]]:
        return [(b"X-Pad", b"a" * (total - len(b"X-Pad")))]

    assert readable_header_section(padded(MAX_HEADER_FIELD_BYTES))
    assert not readable_header_section(padded(MAX_HEADER_FIELD_BYTES + 1))
