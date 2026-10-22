# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""gateway-api/v2 Payload Member Rule: one reading for every payload.

Every payload between a runtime and a gateway is admitted here, after Payload
Size and before any member is read, verified or routed. Two readers that
resolve one byte sequence differently give one signature two meanings: one
keeps the last of two same-named members, another the first, and a decoder
that ignores case reads `STATUS` as `status`. A payload any row of the table
applies to is refused, and the earliest row names the reason, wherever in the
payload each violation sits.

The scan is iterative and judges the bytes, not a parsed dictionary: Python's
`json.loads` keeps the last duplicate, accepts NaN, and raises on deep input.
Only an admitted payload is handed to it.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

INVALID_UNICODE = "invalid_unicode"
MALFORMED_JSON = "malformed_json"
NESTING_TOO_DEEP = "nesting_too_deep"
TRAILING_DATA = "trailing_data"
DUPLICATE_MEMBER = "duplicate_member"
CASE_VARIANT_MEMBER = "case_variant_member"
NOT_AN_OBJECT = "not_an_object"

#: The table's rows, in order: the earliest that applies names the reason.
REASONS = (
    INVALID_UNICODE,
    MALFORMED_JSON,
    NESTING_TOO_DEEP,
    TRAILING_DATA,
    DUPLICATE_MEMBER,
    CASE_VARIANT_MEMBER,
    NOT_AN_OBJECT,
)

MAX_DEPTH = 32


# The members gateway-api/v2 defines for each topic the runtime receives on:
# the keys of its JSON examples and the names in its Field tables, in the
# sections the Payload Member Rule names for the topic, with the Envelope
# Members example. Checked against the vendored corpus, whose sets the
# contract generates independently.
GATEWAY_HEALTH_MEMBERS: frozenset[str] = frozenset(
    {
        "auth",
        "body_limit_bytes",
        "ciphertext",
        "enabled",
        "encrypted",
        "encryption",
        "loopback_only",
        "nonce",
        "provider",
        "provider_cidr_count",
        "ready",
        "request_timeout_ms",
        "runtime_target_configured",
        "scheme",
        "signature",
        "signed_at_ms",
        "sim_available",
        "source_cidrs_configured",
        "status",
        "timestamp_ms",
        "uptime_s",
        "webhook_bridge",
    }
)
REASONING_RESPONSE_MEMBERS: frozenset[str] = frozenset(
    {
        "action_tier",
        "auth",
        "ciphertext",
        "confidence",
        "device_id",
        "encrypted",
        "encryption",
        "error",
        "latency_ms",
        "model",
        "nonce",
        "proposed_action",
        "request_id",
        "scheme",
        "signature",
        "signed_at_ms",
        "text",
        "tokens_used",
    }
)
EXPORT_REQUEST_MEMBERS: frozenset[str] = frozenset(
    {
        "action_name",
        "action_taken",
        "action_tier",
        "auth",
        "avg_value",
        "bucket_ms",
        "ciphertext",
        "contributed_to",
        "correlation_id",
        "device_id",
        "encrypted",
        "encryption",
        "end_ms",
        "executed",
        "export_type",
        "limit",
        "max_value",
        "min_value",
        "nonce",
        "page_token",
        "params",
        "producer_time",
        "quality",
        "reasoning_status",
        "received_at_ms",
        "record_key",
        "record_kind",
        "request_id",
        "sample_count",
        "scheme",
        "sensor_id",
        "sensor_type",
        "signature",
        "signed_at_ms",
        "since_ms",
        "start_ms",
        "tier",
        "tier_used",
        "timestamp",
        "unit",
        "until_ms",
        "value",
    }
)
EVIDENCE_OUTBOUND_ACK_MEMBERS: frozenset[str] = frozenset(
    {
        "acknowledged_at_ms",
        "artifact_digest",
        "artifact_type",
        "auth",
        "ciphertext",
        "device_id",
        "encrypted",
        "encryption",
        "nonce",
        "outcome",
        "reason",
        "scheme",
        "signature",
        "signed_at_ms",
    }
)
EVIDENCE_INBOUND_MEMBERS: frozenset[str] = frozenset(
    {
        "artifact",
        "artifact_type",
        "auth",
        "ciphertext",
        "custody_at_ms",
        "device_id",
        "encrypted",
        "encryption",
        "envelope_digest",
        "key_id",
        "local_seq",
        "mac",
        "nonce",
        "scheme",
        "signature",
        "signed_at_ms",
        "v",
    }
)

_WHITESPACE = frozenset(b" \t\n\r")
_DIGITS = frozenset(b"0123456789")
_HEX = frozenset(b"0123456789abcdefABCDEF")
_ESCAPES = {
    ord('"'): '"',
    ord("\\"): "\\",
    ord("/"): "/",
    ord("b"): "\b",
    ord("f"): "\f",
    ord("n"): "\n",
    ord("r"): "\r",
    ord("t"): "\t",
}
#: The closed fold's two non-ASCII rows; ASCII capitals fold to small letters.
_FOLD = {"ſ": "s", "K": "k"}


#: RFC 8259's number, whole: a lone leading zero, fraction and exponent.
_NUMBER = re.compile(rb"-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?")
#: The next byte a string scan has to look at: its end, an escape, or a byte
#: the grammar forbids inside a string.
_STRING_STOP = re.compile(rb'["\\\x00-\x1f]')


EXPORT_RESPONSE_MEMBERS: frozenset[str] = frozenset(
    {
        "action_name",
        "action_taken",
        "action_tier",
        "auth",
        "avg_value",
        "bucket_ms",
        "ciphertext",
        "complete",
        "contributed_to",
        "correlation_id",
        "device_id",
        "encrypted",
        "encryption",
        "end_ms",
        "error",
        "executed",
        "export_type",
        "items",
        "max_value",
        "min_value",
        "next_page_token",
        "nonce",
        "producer_time",
        "quality",
        "reasoning_status",
        "received_at_ms",
        "record_key",
        "record_kind",
        "request_id",
        "sample_count",
        "scheme",
        "sensor_id",
        "sensor_type",
        "signature",
        "signed_at_ms",
        "start_ms",
        "tier",
        "tier_used",
        "timestamp",
        "unit",
        "value",
    }
)


#: Further defined members for the objects that are elements of the root
#: object's `items` array, and for no other object of the payload.
EXPORT_RESPONSE_ITEM_MEMBERS: frozenset[str] = frozenset(
    {
        "action_log_records",
        "alert_outbox",
        "capability_posture",
        "commissioning",
        "community_skills",
        "config_authority",
        "critical",
        "degradation_reasons",
        "device_id",
        "device_policy",
        "evidence",
        "firmware_controller_profiles",
        "firmware_liveness",
        "firmware_mqtt_operator",
        "firmware_reading_age",
        "gateway_broker_posture",
        "health_socket_path",
        "last_alert_timestamps",
        "projection",
        "remote_command_lockout",
        "safety",
        "safety_registry",
        "safety_zones",
        "sensors",
        "skill_hooks",
        "state_store_encryption",
        "status",
        "telemetry_export",
        "unknown_critical_blocks",
        "uptime_s",
    }
)


class PayloadMemberError(ValueError):
    """The payload is refused under the Payload Member Rule, for *reason*."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def fold(name: str) -> str:
    """The closed fold: ASCII capitals, U+017F and U+212A; nothing else."""
    return "".join(_FOLD.get(ch, ch.lower() if "A" <= ch <= "Z" else ch) for ch in name)


class _GrammarBreakError(Exception):
    """The grammar broke inside the first value."""


class _Object:
    __slots__ = ("defined", "exact", "folded", "last")

    def __init__(self, defined: dict[str, str]) -> None:
        #: The defined members that hold here, by their folded spelling.
        self.defined = defined
        # Sets, so a flood of variants of one name costs constant time each.
        self.exact: set[str] = set()
        self.folded: set[str] = set()
        #: The name the value being read is under.
        self.last: str | None = None


class _Array:
    __slots__ = ("root_items",)

    def __init__(self, root_items: bool = False) -> None:
        #: The root object's `items` array, whose element objects take the
        #: item members as well.
        self.root_items = root_items


# Past MAX_DEPTH nesting_too_deep is already found and outranks every member
# row, so deeper containers share one entry each and record no names.
_DEEP_OBJECT = _Object({})
_DEEP_ARRAY = _Array()


class _Scan:
    """One pass over the first value, collecting every row that applies.

    A stack of open containers, one entry each, stands in for recursion, so
    depth is counted rather than overflowing; it is bounded by the payload's
    size, which Payload Size has already bounded.
    """

    def __init__(
        self, data: bytes, defined: frozenset[str], item_defined: frozenset[str]
    ) -> None:
        self.data = data
        self.pos = 0
        self.found: set[str] = set()
        self.max_depth = 0
        self.stack: list[_Object | _Array] = []
        self._defined = {fold(name): name for name in defined}
        self._item_defined = {
            **self._defined,
            **{fold(name): name for name in item_defined},
        }

    def _open(self, opener: int) -> _Object | _Array:
        """The container *opener* begins, knowing which members hold in it."""
        if len(self.stack) >= MAX_DEPTH:
            return _DEEP_OBJECT if opener == 0x7B else _DEEP_ARRAY
        parent = self.stack[-1] if self.stack else None
        if opener == 0x5B:
            # Decided by container type: only an array under the root
            # object's own `items` name is the items array.
            return _Array(
                len(self.stack) == 1
                and isinstance(parent, _Object)
                and parent.last == "items"
            )
        if isinstance(parent, _Array) and parent.root_items:
            return _Object(self._item_defined)
        return _Object(self._defined)

    def peek(self) -> int | None:
        return self.data[self.pos] if self.pos < len(self.data) else None

    def skip_ws(self) -> None:
        data, pos = self.data, self.pos
        while pos < len(data) and data[pos] in _WHITESPACE:
            pos += 1
        self.pos = pos

    def _hex4_at(self, at: int) -> int | None:
        digits = self.data[at : at + 4]
        if len(digits) < 4 or any(b not in _HEX for b in digits):
            return None
        return int(digits, 16)

    def string(self) -> str:
        """Read a string; return its unescaped value. A lone or misordered
        surrogate escape is recorded, and stands in as U+FFFD."""
        data = self.data
        self.pos += 1  # the opening quote
        out: list[str] = []
        start = self.pos
        while True:
            stop = _STRING_STOP.search(data, self.pos)
            if stop is None:
                raise _GrammarBreakError
            self.pos = stop.start()
            b = data[self.pos]
            if b == 0x22:  # "
                out.append(data[start : self.pos].decode("utf-8", "replace"))
                self.pos += 1
                return "".join(out)
            if b < 0x20:
                raise _GrammarBreakError
            out.append(data[start : self.pos].decode("utf-8", "replace"))
            self.pos += 1
            if self.pos >= len(data):
                raise _GrammarBreakError
            esc = data[self.pos]
            if esc in _ESCAPES:
                out.append(_ESCAPES[esc])
                self.pos += 1
            elif esc == ord("u"):
                unit = self._hex4_at(self.pos + 1)
                if unit is None:
                    raise _GrammarBreakError
                self.pos += 5
                if 0xD800 <= unit <= 0xDBFF:
                    low = (
                        self._hex4_at(self.pos + 2)
                        if data[self.pos : self.pos + 2] == b"\\u"
                        else None
                    )
                    if low is not None and 0xDC00 <= low <= 0xDFFF:
                        self.pos += 6
                        out.append(
                            chr(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))
                        )
                    else:
                        self.found.add(INVALID_UNICODE)
                        out.append("�")
                elif 0xDC00 <= unit <= 0xDFFF:
                    self.found.add(INVALID_UNICODE)
                    out.append("�")
                else:
                    out.append(chr(unit))
            else:
                raise _GrammarBreakError
            start = self.pos

    def number(self) -> None:
        match = _NUMBER.match(self.data, self.pos)
        if match is None:
            raise _GrammarBreakError
        self.pos = match.end()
        # A fraction or exponent begun and cut short ("1.", "1e+") breaks here;
        # one after a complete part ("1.5.", "1e5e") is the next byte's to judge.
        fraction, exponent = match.groups()
        after = self.peek()
        if exponent is None and (
            after in (0x65, 0x45) or (after == 0x2E and fraction is None)
        ):
            raise _GrammarBreakError

    def literal(self, text: bytes) -> None:
        if self.data[self.pos : self.pos + len(text)] != text:
            raise _GrammarBreakError
        self.pos += len(text)

    def key(self, obj: _Object) -> None:
        """Read a member name and its colon, and judge the name."""
        self.skip_ws()
        if self.peek() != 0x22:
            raise _GrammarBreakError
        name = self.string()
        if obj is not _DEEP_OBJECT:
            folded = fold(name)
            if name in obj.exact:
                self.found.add(DUPLICATE_MEMBER)
            elif folded in obj.folded:
                self.found.add(CASE_VARIANT_MEMBER)
            named = obj.defined.get(folded)
            if named is not None and named != name:
                self.found.add(CASE_VARIANT_MEMBER)
            obj.exact.add(name)
            obj.folded.add(folded)
            obj.last = name
        self.skip_ws()
        if self.peek() != 0x3A:  # :
            raise _GrammarBreakError
        self.pos += 1

    def first_value(self) -> int:
        """Scan the first value to its end; return the byte that opened it."""
        self.skip_ws()
        opener = self.peek()
        if opener is None:
            raise _GrammarBreakError
        while True:
            # Read one value, opening containers as they come.
            self.skip_ws()
            b = self.peek()
            if b is None:
                raise _GrammarBreakError
            if b in (0x7B, 0x5B):  # { [
                self.pos += 1
                container = self._open(b)
                self.stack.append(container)
                self.max_depth = max(self.max_depth, len(self.stack))
                self.skip_ws()
                closer = 0x7D if isinstance(container, _Object) else 0x5D
                if self.peek() == closer:
                    self.pos += 1
                    self.stack.pop()
                else:
                    if isinstance(container, _Object):
                        self.key(container)
                    continue
            elif b == 0x22:
                self.string()
            elif b == 0x2D or b in _DIGITS:
                self.number()
            elif b == 0x74:
                self.literal(b"true")
            elif b == 0x66:
                self.literal(b"false")
            elif b == 0x6E:
                self.literal(b"null")
            else:
                raise _GrammarBreakError
            # A value ended: a comma asks for the next, a closer ends a container.
            while self.stack:
                top = self.stack[-1]
                self.skip_ws()
                b = self.peek()
                if b == 0x2C:  # ,
                    self.pos += 1
                    if isinstance(top, _Object):
                        self.key(top)
                    break
                if b == (0x7D if isinstance(top, _Object) else 0x5D):
                    self.pos += 1
                    self.stack.pop()
                    continue
                raise _GrammarBreakError
            if not self.stack:
                return opener


def refusal(
    payload: bytes,
    *,
    defined: frozenset[str] = frozenset(),
    item_defined: frozenset[str] = frozenset(),
) -> str | None:
    """The reason *payload* is refused, or None when it is admitted.

    *defined* is the set of member names the contract defines for the
    payload's topic: a name that folds to one of them without equalling it is
    a case variant, wherever it sits. *item_defined* holds as well, and only,
    in the objects that are elements of the root object's `items` array.
    """
    data = bytes(payload)
    found: set[str] = set()
    try:
        data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        found.add(INVALID_UNICODE)
    scan = _Scan(data, defined, item_defined)
    opener: int | None = None
    try:
        opener = scan.first_value()
        scan.skip_ws()
        if scan.pos != len(data):
            found.add(TRAILING_DATA)
    except _GrammarBreakError:
        found.add(MALFORMED_JSON)
    found |= scan.found
    if scan.max_depth > MAX_DEPTH:
        found.add(NESTING_TOO_DEEP)
    if opener is not None and opener != 0x7B:
        found.add(NOT_AN_OBJECT)
    for reason in REASONS:
        if reason in found:
            return reason
    return None


def _integer(text: str) -> int | float:
    """An admitted integer. One too long for Python to convert reads as the
    infinity `1e400` already reads as: its range is the reading section's to
    judge (gateway-api/v2), so it must reach that section rather than raise."""
    limit = sys.get_int_max_str_digits()  # 0 is no limit
    if limit and len(text.lstrip("-")) > limit:
        return float("-inf") if text.startswith("-") else float("inf")
    return int(text)


def admitted_object(
    payload: bytes,
    *,
    defined: frozenset[str] = frozenset(),
    item_defined: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """The payload's object, read only once the rule admits it.

    Raises PayloadMemberError with the reason otherwise.
    """
    reason = refusal(payload, defined=defined, item_defined=item_defined)
    if reason is not None:
        raise PayloadMemberError(reason)
    value = json.loads(bytes(payload).decode("utf-8"), parse_int=_integer)
    if not isinstance(value, dict):  # unreachable: not_an_object refused it
        raise PayloadMemberError(NOT_AN_OBJECT)
    return value


def admitted_text(
    payload: bytes | str,
    *,
    defined: frozenset[str] = frozenset(),
    item_defined: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """`admitted_object` for a payload that may arrive as text: text that
    cannot be UTF-8 encoded, such as one holding a lone surrogate, is
    `invalid_unicode`."""
    if isinstance(payload, str):
        try:
            payload = payload.encode("utf-8")
        except UnicodeEncodeError:
            raise PayloadMemberError(INVALID_UNICODE) from None
    return admitted_object(payload, defined=defined, item_defined=item_defined)
