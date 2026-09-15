# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""How a producer reads a receiver's answer to a telemetry batch.

`runtime-telemetry/v2` makes the ingest response the only thing that says
whether readings were stored. Reading it is a pure decision over the status
line, the media type, the authentication challenge and the body, so it lives
apart from the transport that fetched them: the exporter cannot then reach a
verdict the Android payload would not reach from the same answer, and the shared
vector set drives this function rather than the HTTP client around it.
"""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# The refusals the endpoint repeats for as long as this credential is presented,
# as the (status, detail) pairs the contract states them in. The enumeration
# belongs to the receiver; the vendored fixture under
# tests/vectors/telemetry_refusals pins both halves.
TERMINAL_REFUSALS: dict[int, str] = {403: "device is suspended"}
TERMINAL_REFUSAL_STATUSES = frozenset(TERMINAL_REFUSALS)

_BATCH_STATUSES = frozenset({"accepted", "duplicate", "partial"})

# A response body is remote input. The conformant answer is a few hundred bytes
# and three containers deep; these are ceilings, not sizes. They are checked by
# this code rather than left to a JSON library, because the two producers' JSON
# libraries disagree beyond them: CPython accepts NaN, Infinity, 1e400, an
# escaped lone surrogate, a byte-order mark, UTF-16 and nesting until it raises
# RecursionError, and serde_json refuses every one. A body one producer reads and
# the other refuses is a disagreement about whether readings were stored -- and
# for a refusal body, about whether export is suspended for good.
MAX_RESPONSE_BYTES = 64 * 1024
MAX_JSON_DEPTH = 32
# The most bytes of field names and values a readable header section holds.
MAX_HEADER_FIELD_BYTES = 100 * 1024

_OPEN = frozenset(b"[{")
_CLOSE = frozenset(b"]}")


def join_header_values(values: list[str]) -> str | None:
    """A header's values as one, in order, or None when it was absent.

    Joined with ", " as HTTP permits and as httpx already presents them, so a
    header sent twice is read the same way by both producers: a JSON media type
    followed by another is not a JSON media type, whichever came first.
    """
    return ", ".join(values) if values else None


def readable_content_coding(content_encoding: str | None) -> bool:
    """Whether a body under this `Content-Encoding` is read at all.

    Only an absent or `identity` coding is. A producer requests no coding, so a
    coded body is an intermediary's choice; decoding it would put the size
    ceiling on bytes that were never received and let a small compressed body
    occupy memory without bound, and the two producers' clients do not decode
    the same codings.
    """
    if content_encoding is None:
        return True
    return content_encoding.strip(" \t").lower() in {"", "identity"}


_VISIBLE_FIELD_BYTES = frozenset(range(0x21, 0x7F)) | {0x20, 0x09}

# The fields the verdict reads, or frames the body by.
_VERDICT_FIELDS = frozenset(
    {
        "content-type",
        "www-authenticate",
        "content-encoding",
        "content-length",
        "transfer-encoding",
    }
)

HeaderFields = Sequence[tuple[str | bytes, bytes]]


def _field_name(name: str | bytes) -> str:
    return (name.decode("latin-1") if isinstance(name, bytes) else name).lower()


def readable_header_section(fields: HeaderFields) -> bool:
    """Whether a parsed response's header section can be read alike by every producer.

    Parsing has already refused what h11 refuses. Two things remain that a
    parser accepts and producers would still read differently: a byte outside
    visible ASCII, space and tab in a field the verdict reads -- decoded one way
    by one client's header text and another way by the next -- and a response
    framed by both a transfer coding and a length. Bytes in any other field are
    left alone: an unrelated header carrying a site name in UTF-8 is not a
    reason to hold readings for good.
    """
    # Measured on the parsed fields rather than the bytes received: h11 enforces
    # its own limit only while a section is still incomplete, which depends on
    # how the bytes arrived, and a section it read whole cannot be measured here
    # any other way.
    size = sum(len(name) + len(value) for name, value in fields)
    if size > MAX_HEADER_FIELD_BYTES:
        return False
    names = {_field_name(name) for name, _ in fields}
    if "transfer-encoding" in names and "content-length" in names:
        return False
    return all(
        _field_name(name) not in _VERDICT_FIELDS
        or all(byte in _VISIBLE_FIELD_BYTES for byte in value)
        for name, value in fields
    )


def _field(fields: HeaderFields, wanted: str) -> str | None:
    # Only called for verdict fields, whose bytes readable_header_section has
    # already held to visible ASCII.
    return join_header_values(
        [
            value.decode("latin-1")
            for name, value in fields
            if _field_name(name) == wanted
        ]
    )


def _declared_past_ceiling(fields: HeaderFields) -> bool:
    length = (_field(fields, "content-length") or "").strip()
    return length.isascii() and length.isdigit() and int(length) > MAX_RESPONSE_BYTES


def body_is_wanted(fields: HeaderFields) -> bool:
    """Whether a transport should read this response's body at all.

    Not when the header section cannot be read alike, when the body is
    content-coded, or when it declares more than the ceiling: each is decided
    before a byte of the body is read, by both producers.
    """
    return (
        readable_header_section(fields)
        and readable_content_coding(_field(fields, "content-encoding"))
        and not _declared_past_ceiling(fields)
    )


def read_answer(
    *,
    status: int | None,
    fields: HeaderFields,
    body: bytes | None,
    batch_events: int,
) -> DeliveryVerdict:
    """Read one parsed answer to a batch.

    `status` is None when nothing a parser would read arrived. `body` is None
    when it was not read or ran past the ceiling.
    """
    if status is None or not readable_header_section(fields):
        return read_batch_response(status=None, batch_events=batch_events)
    return read_batch_response(
        status=status,
        content_type=_field(fields, "content-type") or "",
        www_authenticate=_field(fields, "www-authenticate"),
        body=body if body_is_wanted(fields) else None,
        batch_events=batch_events,
    )


def _nesting_exceeds(body: bytes, limit: int) -> bool:
    """Whether more than `limit` containers are ever open at once.

    Scanned over bytes outside strings, before any parser runs, so a deep body is
    refused without recursing into it. Depth counts every `[` or `{` that is open,
    the outermost included.
    """
    depth = 0
    in_string = False
    escaped = False
    for byte in body:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in _OPEN:
            depth += 1
            if depth > limit:
                return True
        elif byte in _CLOSE:
            depth -= 1
    return False


def _refuse_constant(name: str) -> object:
    raise ValueError(f"non-standard constant {name}")


def _finite_float(literal: str) -> float:
    value = float(literal)
    if not math.isfinite(value):
        raise ValueError(f"number out of range {literal}")
    return value


def _integer_token(literal: str) -> int | float:
    # serde_json reads an integer beyond 64 bits as a float and refuses one with
    # no finite float value; it reads `-0` as a float too. Both are mirrored, so
    # no body is readable in one producer only and no `-0` is taken for a count.
    if not math.isfinite(float(literal)):
        raise ValueError(f"number out of range {literal[:16]}")
    return -0.0 if literal == "-0" else int(literal)


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Which occurrence of a repeated name a parser keeps is the library's choice,
    # not the contract's, and a body reading `accepted_events` as 0 in one
    # producer and 1 in another disagrees about whether readings were stored.
    members: dict[str, Any] = {}
    for name, value in pairs:
        if name in members:
            raise ValueError("repeated member name")
        members[name] = value
    return members


def _carries_lone_surrogate(value: object) -> bool:
    """Whether any string or key decoded to an unpaired surrogate code point."""
    pending: list[object] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if any("\ud800" <= char <= "\udfff" for char in item):
                return True
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False


def _parse_strict_json(body: bytes) -> object | None:
    """Parse a response body the way both producers must, or None.

    None means unreadable. Nothing a body contains can raise out of here: a
    parser error escaping the flush loop would drop a drained batch from every
    counter, which is the loss this module exists to make visible.
    """
    if len(body) > MAX_RESPONSE_BYTES or body.startswith(b"\xef\xbb\xbf"):
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _nesting_exceeds(body, MAX_JSON_DEPTH):
        return None
    try:
        value = json.loads(
            text,
            parse_constant=_refuse_constant,
            parse_float=_finite_float,
            parse_int=_integer_token,
            object_pairs_hook=_unique_members,
        )
    except (ValueError, RecursionError):
        return None
    return None if _carries_lone_surrogate(value) else value


class DeliveryOutcome(str, Enum):
    """What a producer does with the batch it just sent."""

    DELIVERED = "delivered"
    RETAIN = "retain"
    SUSPEND = "suspend"


@dataclass(frozen=True)
class DeliveryVerdict:
    """One answer read. `reason` is for logs and carries no credential."""

    outcome: DeliveryOutcome
    declined_events: int = 0
    # Events the receiver already held. Delivered, and counted apart so a
    # producer restarting against a receiver can say how much it re-sent.
    duplicate_events: int = 0
    refused_events: int = 0
    nonconformant_body: bool = False
    reason: str = ""
    # Whether the answer itself could not be read, as opposed to being read and
    # saying the batch was not delivered. Carried as a field because the
    # alternative -- a caller matching on `reason` -- makes a counter depend on
    # log wording, and rewording a message would silently zero it.
    body_unreadable: bool = False
    # Whether the receiver's application answered: a 2xx over a JSON media type
    # whose readable object carries a `status` this contract defines. Such an
    # answer is deterministic, so a batch it keeps failing to confirm is
    # abandoned after a bounded number of attempts rather than holding the queue
    # for good. Any other answer is not evidence the receiver spoke, and a batch
    # waiting on one is retried for as long as memory allows.
    receiver_answered: bool = False
    refusal_status: int | None = None
    refusal_detail: str | None = None
    declined_event_ids: tuple[str, ...] = field(default_factory=tuple)


def _retain(
    reason: str, *, body_unreadable: bool = False, receiver_answered: bool = False
) -> DeliveryVerdict:
    return DeliveryVerdict(
        outcome=DeliveryOutcome.RETAIN,
        reason=reason,
        body_unreadable=body_unreadable,
        receiver_answered=receiver_answered,
    )


def _is_json_media_type(content_type: str) -> bool:
    base = content_type.split(";", 1)[0].strip().lower()
    return base == "application/json" or base.endswith("+json")


def _count(body: dict[str, Any], key: str, batch_events: int) -> int | None:
    """A count member read strictly, or None when it is not a count.

    An integer token -- not a boolean, not a number written with a fraction or an
    exponent -- between zero and the batch size. No count of a batch's events can
    exceed the batch, and holding every term to that bound is what keeps the sum
    below from overflowing, wrapping or truncating in either producer.
    """
    value = body.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > batch_events:
        return None
    return value


def _is_terminal_refusal(
    status: int,
    content_type: str,
    www_authenticate: str | None,
    body: object,
) -> bool:
    """Whether this is the endpoint refusing this credential for good.

    Suspension is irreversible for the process, so it needs positive evidence
    that the endpoint answered rather than merely that nothing contradicted it.
    Any intermediary can return a bare 403 -- a proxy or WAF does so without a
    challenge and with an HTML body -- and an absent header proves nothing about
    origin. So every recorded property must hold: the status, a JSON media type,
    no authentication challenge, and the exact detail the contract records.
    """
    if status not in TERMINAL_REFUSAL_STATUSES:
        return False
    if www_authenticate:
        return False
    if not _is_json_media_type(content_type):
        return False
    if not isinstance(body, dict):
        return False
    detail = body.get("detail")
    if not isinstance(detail, str):
        return False
    # Trimmed of ASCII space, tab, CR and LF only. Each language's own notion of
    # whitespace differs -- Python's strip() removes separator control characters
    # that Rust's trim() keeps -- and a detail one producer matches and the other
    # does not is a suspension on one device and not the next.
    return detail.strip(" \t\r\n") == TERMINAL_REFUSALS[status]


def read_batch_response(
    *,
    status: int | None,
    content_type: str = "",
    www_authenticate: str | None = None,
    body: bytes | None = None,
    batch_events: int,
) -> DeliveryVerdict:
    """Read one answer to a batch of `batch_events` events.

    `status` is None when no answer arrived at all. Every path returns a
    verdict: there is no answer a producer may treat as a reason to stop.
    """
    if batch_events <= 0:
        # The contract forbids posting an empty batch and `_take_pending` never
        # forms one, so this is a programming error rather than an answer. It
        # returns a verdict rather than raising: the flush loop's own handler
        # would log the exception and continue, and the batch it had already
        # drained would be gone. The other producer returns the same verdict,
        # so neither can be given an input that ends its loop.
        return _retain("empty batch was not sent")

    if status is None:
        return _retain("no response")

    decoded: object = _parse_strict_json(body) if body else None

    if _is_terminal_refusal(status, content_type, www_authenticate, decoded):
        return DeliveryVerdict(
            outcome=DeliveryOutcome.SUSPEND,
            refused_events=batch_events,
            reason=f"terminal refusal HTTP {status}",
            # Both taken from the enumeration keyed by the status that matched,
            # never from the response. The caller needs the status too: reading
            # it back from the enumeration by taking an arbitrary element is
            # correct only while there is exactly one, and would name the wrong
            # refusal the moment the receiver records a second.
            refusal_status=status,
            refusal_detail=TERMINAL_REFUSALS[status],
        )

    if not 200 <= status < 300:
        return _retain(f"HTTP {status}")

    # A 2xx says nothing on its own. The body is what reports whether the
    # readings were stored, so a body that cannot be read is a transport
    # failure rather than an assumed delivery.
    if not isinstance(decoded, dict):
        return _retain(f"HTTP {status} with an unreadable body", body_unreadable=True)

    # A body counts toward abandoning the batch only when it is this contract's
    # answer: a JSON media type and a `status` the contract defines. Abandonment
    # discards readings, and a captive portal or proxy answering 200 with some
    # JSON object of its own is not the receiver declining to confirm them.
    batch_status = decoded.get("status")
    if batch_status not in _BATCH_STATUSES:
        return _retain("response status is absent or not a defined value")
    speaks_contract = _is_json_media_type(content_type)

    def unconfirmed(reason: str) -> DeliveryVerdict:
        return _retain(reason, receiver_answered=speaks_contract)

    accepted = _count(decoded, "accepted_events", batch_events)
    if accepted is None:
        return unconfirmed("accepted_events is absent or not a count")

    # `rejected_events` and `duplicate_events` are required of a receiver and
    # tolerated when absent: an absent one is read as zero, the body is recorded
    # as non-conformant, and the invariant must still hold on that reading. So a
    # receiver mid-migration that omits one member is read exactly, and the
    # answer an unmigrated receiver gives when it rejects a batch on `sequence`
    # -- `{"status": "duplicate", "accepted_events": 0}` -- sums to nothing and is
    # not a delivery of readings it stored none of.
    nonconformant = False

    declined_ids: list[str] = []
    if "rejected_events" in decoded:
        rejected = decoded["rejected_events"]
        if not isinstance(rejected, list):
            return unconfirmed("rejected_events is not a list")
        for entry in rejected:
            if not isinstance(entry, dict):
                return unconfirmed("a rejected_events entry is not an object")
            event_id = entry.get("event_id")
            if not isinstance(event_id, str) or not event_id:
                return unconfirmed("a rejected_events entry does not name an event")
            if event_id in declined_ids:
                return unconfirmed("a rejected_events entry repeats an event")
            declined_ids.append(event_id)
    else:
        nonconformant = True

    duplicate = 0
    if "duplicate_events" in decoded:
        counted = _count(decoded, "duplicate_events", batch_events)
        if counted is None:
            return unconfirmed("duplicate_events is present and not a count")
        duplicate = counted
    else:
        nonconformant = True

    if accepted + duplicate + len(declined_ids) != batch_events:
        return unconfirmed("response counts do not account for the batch")

    return DeliveryVerdict(
        outcome=DeliveryOutcome.DELIVERED,
        declined_events=len(declined_ids),
        duplicate_events=duplicate,
        nonconformant_body=nonconformant,
        receiver_answered=True,
        reason=f"{batch_status}",
        declined_event_ids=tuple(declined_ids),
    )
