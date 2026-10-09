# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Controller profile documents and foreign-controller alarm state.

Implements the receiver half of ``ori-specs/firmware-telemetry/v2.md``
Controller Profiles. A document is held as bytes and used only when those
bytes are exactly its canonical form, it is valid under the grammar, and it
agrees with the manifest channel that names it by digest. An alarm word is
interpreted only through that document, and its state is a snapshot as of the
reading it came from, never the controller's state now.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import sys
import time
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, Mapping

from ori.security.firmware.telemetry import (
    ALARM_WORD_SENSOR_TYPE,
    ALARM_WORD_UNIT,
    FirmwareVerificationError,
    canonical_json_bytes,
    is_fleet_identifier,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AlarmInterpretation",
    "ControllerAlarmTracker",
    "ControllerProfileLibrary",
    "ProfileDocument",
    "agreement",
    "interpret_alarm_word",
    "load_profile_document",
    "measurement_in_range",
    "silence_bound_ms",
    "suspend_counting_clock",
]

ERR_INVALID_PROFILE_DOCUMENT = "invalid_profile_document"
ERR_NON_CANONICAL_DOCUMENT = "non_canonical_document"

_TOP_FIELDS = frozenset(
    {"v", "id", "source", "baud_rate", "poll_interval_ms", "channels"}
)
_COMMON_FIELDS = frozenset(
    {"name", "kind", "function", "start_register", "register_count", "word_order"}
)
_MEASUREMENT_FIELDS = _COMMON_FIELDS | {
    "raw_signed",
    "raw_min",
    "raw_max",
    "scale",
    "offset",
    "sensor_type",
    "unit",
}
_ALARM_WORD_FIELDS = _COMMON_FIELDS | {"alarms"}
_ALARM_FIELDS = frozenset({"bit", "active", "id", "meaning"})
_DECIMAL_FIELDS = frozenset({"mantissa", "exponent"})
_BAUD_RATES = frozenset({1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200})
_FUNCTIONS = frozenset({"read_holding_registers", "read_input_registers"})
_POLL_MIN_MS = 100
_POLL_MAX_MS = 3_600_000
_ALARM_POLL_MAX_MS = 1_190_000
_MAX_CHANNELS = 16
_TEXT_MAX_LEN = 256
_MANTISSA_MAX = 2_147_483_647
_EXPONENT_MIN = -4
_EXPONENT_MAX = 6
_DECODE_TERM_MAX = 999_999_999_999_999
_DECODED_MAX = 10**15
# Three missed polls and a transport allowance (firmware-telemetry/v2 Receivers).
_SILENCE_POLLS = 3
_SILENCE_ALLOWANCE_MS = 30_000


@dataclass(frozen=True)
class ProfileDocument:
    """A canonical, grammar-valid profile document and its digest."""

    digest: str
    id: str
    poll_interval_ms: int
    channels: Mapping[str, Mapping[str, Any]]
    canonical: bytes = field(repr=False)


@dataclass(frozen=True)
class AlarmInterpretation:
    """One alarm word read through its document."""

    word: int
    asserted: tuple[str, ...]
    not_asserted: tuple[str, ...]
    unmapped_set_bits: tuple[int, ...]
    meanings: Mapping[str, str]


class ProfileGrammarError(FirmwareVerificationError):
    """A document that breaks the profile grammar, naming the rule it breaks."""

    def __init__(self, rule: str, why: str) -> None:
        super().__init__(ERR_INVALID_PROFILE_DOCUMENT, f"{rule}: {why}")
        self.rule = rule


def _invalid(rule: str, why: str) -> ProfileGrammarError:
    return ProfileGrammarError(rule, why)


def _is_int(value: Any) -> bool:
    return type(value) is int


def _is_printable_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= _TEXT_MAX_LEN
        and all(" " <= ch <= "~" for ch in value)
    )


def _refuse_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def load_profile_document(data: object) -> ProfileDocument:
    """Parse held bytes into a document, refusing anything but canonical bytes.

    The digest is over the bytes held, never a re-serialization: a document a
    canonical serializer would write differently is refused, because two
    parsers could read two interpretations from it.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise FirmwareVerificationError(
            ERR_NON_CANONICAL_DOCUMENT, "a document is held as bytes"
        )
    raw = bytes(data)
    try:
        text = raw.decode("utf-8", errors="strict")
        parsed = json.loads(text, object_pairs_hook=_refuse_duplicate_keys)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise FirmwareVerificationError(ERR_NON_CANONICAL_DOCUMENT, str(exc)) from exc
    try:
        canonical = canonical_json_bytes(parsed)
    except FirmwareVerificationError as exc:
        raise FirmwareVerificationError(ERR_NON_CANONICAL_DOCUMENT, exc.detail) from exc
    except (RecursionError, UnicodeError, TypeError, ValueError) as exc:
        # Nesting past the serializer's depth, or a lone surrogate escape:
        # a canonical serializer writes nothing for it.
        raise FirmwareVerificationError(
            ERR_NON_CANONICAL_DOCUMENT, f"{type(exc).__name__}: {exc}"
        ) from exc
    if canonical != raw:
        raise FirmwareVerificationError(
            ERR_NON_CANONICAL_DOCUMENT,
            "the bytes are not the canonical bytes of the object they parse to",
        )
    channels = validate_profile_document(parsed)
    return ProfileDocument(
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        id=parsed["id"],
        poll_interval_ms=parsed["poll_interval_ms"],
        channels=channels,
        canonical=raw,
    )


def validate_profile_document(document: Any) -> dict[str, dict[str, Any]]:
    """Apply the profile grammar; return the channels by name."""
    if not isinstance(document, dict) or set(document) != _TOP_FIELDS:
        raise _invalid(
            "top_fields", "the document is not an object with exactly its six fields"
        )
    if not (_is_int(document["v"]) and document["v"] == 1):
        raise _invalid("version", "v is not 1")
    if not is_fleet_identifier(document["id"]):
        raise _invalid("id", "id is not a fleet identifier")
    if not _is_printable_text(document["source"]):
        raise _invalid("source", "source is not 1 to 256 printable ASCII characters")
    if not (_is_int(document["baud_rate"]) and document["baud_rate"] in _BAUD_RATES):
        raise _invalid("baud_rate", "baud_rate is not a supported rate")
    poll = document["poll_interval_ms"]
    if not (_is_int(poll) and _POLL_MIN_MS <= poll <= _POLL_MAX_MS):
        raise _invalid("poll_interval_ms", "poll_interval_ms is outside 100 to 3600000")
    channels = document["channels"]
    if not isinstance(channels, list) or not 1 <= len(channels) <= _MAX_CHANNELS:
        raise _invalid("channels", "channels is not 1 to 16 channel objects")
    out: dict[str, dict[str, Any]] = {}
    alarm_ids: set[str] = set()
    for index, channel in enumerate(channels):
        name = _validate_channel(index, channel, alarm_ids)
        if name in out:
            raise _invalid("channel_name", f"channel name {name!r} is not unique")
        out[name] = channel
    if (
        any(channel["kind"] == "alarm_word" for channel in out.values())
        and poll > _ALARM_POLL_MAX_MS
    ):
        raise _invalid(
            "poll_interval_ms",
            "poll_interval_ms exceeds 1190000 in a profile with an alarm word",
        )
    return out


def _validate_channel(index: int, channel: Any, alarm_ids: set[str]) -> str:
    if not isinstance(channel, dict):
        raise _invalid("channel_fields", f"channel {index} is not an object")
    if not is_fleet_identifier(channel.get("name")):
        raise _invalid(
            "channel_name", f"channel {index} name is not a fleet identifier"
        )
    kind = channel.get("kind")
    if kind == "measurement":
        expected = _MEASUREMENT_FIELDS
    elif kind == "alarm_word":
        expected = _ALARM_WORD_FIELDS
    else:
        raise _invalid(
            "kind", f"channel {index} kind is neither measurement nor alarm_word"
        )
    if set(channel) != expected:
        raise _invalid(
            "channel_fields",
            f"channel {index} does not carry exactly its kind's fields",
        )
    if (
        not isinstance(channel["function"], str)
        or channel["function"] not in _FUNCTIONS
    ):
        raise _invalid("function", f"channel {index} function is not a register read")
    start = channel["start_register"]
    if not (_is_int(start) and 0 <= start <= 65535):
        raise _invalid(
            "start_register", f"channel {index} start_register is outside 0 to 65535"
        )
    count = channel["register_count"]
    if not (_is_int(count) and count in (1, 2)):
        raise _invalid(
            "register_count", f"channel {index} register_count is not 1 or 2"
        )
    if start + count > 65536:
        raise _invalid("register_span", f"channel {index} runs past register 65535")
    order = channel["word_order"]
    if count == 1 and order is not None:
        raise _invalid(
            "word_order", f"channel {index} word_order is set for one register"
        )
    if count == 2 and order not in ("high_first", "low_first"):
        raise _invalid(
            "word_order",
            f"channel {index} word_order is not declared for two registers",
        )
    if kind == "measurement":
        _validate_measurement(index, channel, count)
    else:
        _validate_alarms(index, channel, count, alarm_ids)
    return str(channel["name"])


def _decimal(value: Any, *, nonzero: bool) -> tuple[int, int] | None:
    if not isinstance(value, dict) or set(value) != _DECIMAL_FIELDS:
        return None
    mantissa, exponent = value["mantissa"], value["exponent"]
    if not (_is_int(mantissa) and -_MANTISSA_MAX <= mantissa <= _MANTISSA_MAX):
        return None
    if nonzero and mantissa == 0:
        return None
    if not (_is_int(exponent) and _EXPONENT_MIN <= exponent <= _EXPONENT_MAX):
        return None
    return mantissa, exponent


def _validate_measurement(index: int, channel: dict[str, Any], count: int) -> None:
    signed = channel["raw_signed"]
    if not isinstance(signed, bool):
        raise _invalid("raw_signed", f"channel {index} raw_signed is not a boolean")
    bits = 16 * count
    low, high = (
        (-(2 ** (bits - 1)), 2 ** (bits - 1) - 1) if signed else (0, 2**bits - 1)
    )
    raw_min, raw_max = channel["raw_min"], channel["raw_max"]
    if not (
        _is_int(raw_min) and _is_int(raw_max) and low <= raw_min <= raw_max <= high
    ):
        raise _invalid(
            "raw_range", f"channel {index} raw range is not representable or ordered"
        )
    scale = _decimal(channel["scale"], nonzero=True)
    if scale is None:
        raise _invalid(
            "scale", f"channel {index} scale is not a nonzero decimal in bounds"
        )
    offset = _decimal(channel["offset"], nonzero=False)
    if offset is None:
        raise _invalid("offset", f"channel {index} offset is not a decimal in bounds")
    for key in ("sensor_type", "unit"):
        value = channel[key]
        if not is_fleet_identifier(value) or value in (
            ALARM_WORD_SENSOR_TYPE,
            ALARM_WORD_UNIT,
        ):
            raise _invalid(
                key, f"channel {index} {key} is not a measurement identifier"
            )
    if not _decode_within_bounds(raw_min, raw_max, scale, offset):
        raise _invalid(
            "decode", f"channel {index} decode leaves fifteen digits or 10^15"
        )


def _decode_terms(
    scale: tuple[int, int], offset: tuple[int, int]
) -> tuple[int, int, int]:
    """Scale and offset as integers over 10^f, f the smaller exponent."""
    f = min(scale[1], offset[1])
    return scale[0] * 10 ** (scale[1] - f), offset[0] * 10 ** (offset[1] - f), f


def _decode_within_bounds(
    raw_min: int, raw_max: int, scale: tuple[int, int], offset: tuple[int, int]
) -> bool:
    s, o, f = _decode_terms(scale, offset)
    if abs(s) > _DECODE_TERM_MAX or abs(o) > _DECODE_TERM_MAX:
        return False
    for raw in (raw_min, raw_max):
        term = raw * s
        total = term + o
        if abs(term) > _DECODE_TERM_MAX or abs(total) > _DECODE_TERM_MAX:
            return False
        if abs(Fraction(total) * Fraction(10) ** f) > _DECODED_MAX:
            return False
    return True


def _validate_alarms(
    index: int, channel: dict[str, Any], count: int, alarm_ids: set[str]
) -> None:
    alarms = channel["alarms"]
    if not isinstance(alarms, list) or not alarms:
        raise _invalid("alarms", f"channel {index} alarms is not a non-empty list")
    bits: set[int] = set()
    for position, alarm in enumerate(alarms):
        where = f"channel {index} alarm {position}"
        if not isinstance(alarm, dict) or set(alarm) != _ALARM_FIELDS:
            raise _invalid(
                "alarm_fields",
                f"{where} does not carry exactly bit, active, id, meaning",
            )
        bit = alarm["bit"]
        if not (_is_int(bit) and 0 <= bit < 16 * count) or bit in bits:
            raise _invalid("alarm_bit", f"{where} bit is outside the word or repeated")
        bits.add(bit)
        if alarm["active"] not in ("set", "clear"):
            raise _invalid("alarm_active", f"{where} active is neither set nor clear")
        if not is_fleet_identifier(alarm["id"]) or alarm["id"] in alarm_ids:
            raise _invalid(
                "alarm_id",
                f"{where} id is not a fleet identifier unique in the profile",
            )
        alarm_ids.add(alarm["id"])
        if not _is_printable_text(alarm["meaning"]):
            raise _invalid(
                "alarm_meaning",
                f"{where} meaning is not 1 to 256 printable ASCII characters",
            )


def agreement(
    document: ProfileDocument, binding: Mapping[str, Any], channel: Mapping[str, Any]
) -> str | None:
    """Why *document* may not be used for a manifest channel, or None.

    *binding* is the channel's ``controller_profile``; *channel* carries the
    manifest channel's ``sensor_type`` and ``unit``.
    """
    if binding.get("digest") != document.digest:
        return "the document is not the one the manifest names"
    if binding.get("id") != document.id:
        return "the document's id is not the manifest's"
    profile_channel = document.channels.get(str(binding.get("profile_channel")))
    if profile_channel is None:
        return "the document has no channel by that name"
    if profile_channel["kind"] == "alarm_word":
        if (channel.get("sensor_type"), channel.get("unit")) != (
            ALARM_WORD_SENSOR_TYPE,
            ALARM_WORD_UNIT,
        ):
            return "an alarm word is read as a measurement"
        return None
    if (channel.get("sensor_type"), channel.get("unit")) != (
        profile_channel["sensor_type"],
        profile_channel["unit"],
    ):
        return "the manifest channel does not declare what the profile channel decodes"
    return None


def measurement_in_range(profile_channel: Mapping[str, Any], value: object) -> bool:
    """Whether *value* is the decode of some raw count in the channel's range.

    Every decode the grammar admits is a decimal of at most fifteen digits that
    is recovered exactly from the double nearest it, so the count is found by
    rounding and confirmed by decoding it again.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        exact = Fraction(value)
    except (OverflowError, ValueError):
        return False
    scale = (profile_channel["scale"]["mantissa"], profile_channel["scale"]["exponent"])
    offset = (
        profile_channel["offset"]["mantissa"],
        profile_channel["offset"]["exponent"],
    )
    s, o, f = _decode_terms(scale, offset)
    unit = Fraction(10) ** f
    total = round(exact / unit)
    if float(Fraction(total) * unit) != float(value):
        return False
    raw, remainder = divmod(total - o, s)
    if remainder != 0:
        return False
    return bool(profile_channel["raw_min"] <= raw <= profile_channel["raw_max"])


def interpret_alarm_word(
    profile_channel: Mapping[str, Any], value: object
) -> AlarmInterpretation | None:
    """Read an alarm word's value through its channel, or None if it is not one.

    The value is read by value, so ``5`` and ``5.0`` are one word; anything
    that is not an integer in the word's range is not interpreted.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    word = int(value)
    if not 0 <= word < 2 ** (16 * profile_channel["register_count"]):
        return None
    asserted: list[str] = []
    not_asserted: list[str] = []
    meanings: dict[str, str] = {}
    mapped: set[int] = set()
    for alarm in profile_channel["alarms"]:
        bit_set = bool((word >> alarm["bit"]) & 1)
        mapped.add(alarm["bit"])
        meanings[alarm["id"]] = alarm["meaning"]
        if bit_set == (alarm["active"] == "set"):
            asserted.append(alarm["id"])
        else:
            not_asserted.append(alarm["id"])
    unmapped = tuple(
        bit
        for bit in range(16 * profile_channel["register_count"])
        if (word >> bit) & 1 and bit not in mapped
    )
    return AlarmInterpretation(
        word=word,
        asserted=tuple(asserted),
        not_asserted=tuple(not_asserted),
        unmapped_set_bits=unmapped,
        meanings=meanings,
    )


def silence_bound_ms(poll_interval_ms: int) -> int:
    """The longest silence after which an alarm state still stands."""
    return _SILENCE_POLLS * poll_interval_ms + _SILENCE_ALLOWANCE_MS


class ControllerProfileLibrary:
    """Profile documents held locally, by digest.

    Only documents whose held bytes are canonical and valid are held; the rest
    are recorded with the reason, so a refused file is visible rather than
    silently missing.
    """

    def __init__(self, documents: Iterable[ProfileDocument] = ()) -> None:
        self._documents: dict[str, ProfileDocument] = {}
        self.refused: list[dict[str, str]] = []
        for document in documents:
            self._documents[document.digest] = document

    @classmethod
    def from_directory(cls, directory: str | Path | None) -> ControllerProfileLibrary:
        """Hold every valid document in *directory*; record every other entry.

        Nothing here raises: one hostile file must not stop the runtime, whose
        start reads this before Tier D is running.
        """
        library = cls()
        if directory is None or str(directory) == "":
            return library
        root = Path(directory)
        try:
            entries = sorted(root.iterdir())
        except (OSError, ValueError) as exc:
            library._refuse(str(root), f"unreadable: {exc}")
            return library
        for path in entries:
            if path.suffix != ".json":
                library._refuse(path.name, "not_a_json_file")
                continue
            try:
                document = load_profile_document(_read_regular_file(path))
            except FirmwareVerificationError as exc:
                library._refuse(path.name, exc.code, exc.detail)
                continue
            except OSError as exc:
                library._refuse(path.name, f"unreadable: {exc}")
                continue
            except Exception as exc:  # noqa: BLE001 - fail closed per file
                library._refuse(path.name, f"refused: {type(exc).__name__}")
                continue
            library._documents[document.digest] = document
        return library

    def _refuse(self, name: str, reason: str, detail: str = "") -> None:
        self.refused.append({"file": name, "reason": reason})
        logger.warning("controller profile %s refused: %s %s", name, reason, detail)

    def get(self, digest: str) -> ProfileDocument | None:
        return self._documents.get(digest)

    def held(self) -> list[dict[str, str]]:
        return [
            {"id": document.id, "digest": digest}
            for digest, document in sorted(self._documents.items())
        ]

    def resolve(
        self, binding: Mapping[str, Any], channel: Mapping[str, Any]
    ) -> tuple[str, ProfileDocument | None, Mapping[str, Any] | None]:
        """The document for a manifest channel: ``usable``, ``unknown`` or ``disagrees``."""
        document = self.get(str(binding.get("digest")))
        if document is None:
            return "unknown", None, None
        reason = agreement(document, binding, channel)
        if reason is not None:
            logger.warning(
                "controller profile %s disagrees with its manifest channel: %s",
                document.digest,
                reason,
            )
            return "disagrees", None, None
        return "usable", document, document.channels[str(binding["profile_channel"])]


# A profile holds at most 16 channels of at most 32 alarms of 256 characters.
_DOCUMENT_MAX_BYTES = 1 << 20


def _read_regular_file(path: Path) -> bytes:
    """A regular file's bytes, opened without blocking and bounded in size.

    A FIFO would block the read for ever and a device file would never end,
    so anything but a regular file is refused before it is read.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path.name} is not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(_DOCUMENT_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > _DOCUMENT_MAX_BYTES:
        raise OSError(f"{path.name} is larger than {_DOCUMENT_MAX_BYTES} bytes")
    return data


def suspend_counting_clock() -> Callable[[], int] | None:
    """A millisecond monotonic clock that keeps counting while the host sleeps.

    CLOCK_BOOTTIME on Linux; CLOCK_MONOTONIC on macOS, where it includes sleep.
    None elsewhere, and then no alarm state stands at all.
    """
    clock_id = getattr(time, "CLOCK_BOOTTIME", None)
    if clock_id is None and sys.platform == "darwin":
        clock_id = getattr(time, "CLOCK_MONOTONIC", None)
    if clock_id is None:
        return None
    chosen: int = clock_id
    return lambda: time.clock_gettime_ns(chosen) // 1_000_000


@dataclass
class _Latest:
    activation: tuple[str, int]
    key_epoch_id: str
    boot_id: int
    seq: int
    accepted_ms: int
    received_at_ms: int
    value: float
    poll_interval_ms: int | None
    interpretation: AlarmInterpretation | None
    not_interpreted: str
    profile: Mapping[str, Any]
    profile_status: str


@dataclass
class _ChannelState:
    latest: _Latest | None = None
    fault_activation: tuple[str, int] | None = None


class ControllerAlarmTracker:
    """Each bridged alarm-word channel's latest reading, held in memory only.

    A restarted receiver has accepted nothing, so nothing here survives one.
    State is scoped to the activation it was accepted under: any promotion,
    rotation or revocation leaves the channel with no latest reading.
    """

    def __init__(self, clock: Callable[[], int] | None = None) -> None:
        self._clock = clock if clock is not None else suspend_counting_clock()
        self._channels: dict[tuple[str, str], _ChannelState] = {}

    def _now(self) -> int | None:
        return None if self._clock is None else int(self._clock())

    def note_reading(
        self,
        *,
        device_id: str,
        channel: str,
        activation: tuple[str, int],
        key_epoch_id: str,
        boot_id: int,
        seq: int,
        received_at_ms: int,
        value: float,
        poll_interval_ms: int | None,
        interpretation: AlarmInterpretation | None,
        not_interpreted: str,
        profile: Mapping[str, Any],
        profile_status: str,
    ) -> None:
        now = self._now()
        state = self._channels.setdefault((device_id, channel), _ChannelState())
        state.fault_activation = None
        state.latest = (
            None
            if now is None
            else _Latest(
                activation=activation,
                key_epoch_id=key_epoch_id,
                boot_id=boot_id,
                seq=seq,
                accepted_ms=now,
                received_at_ms=received_at_ms,
                value=value,
                poll_interval_ms=poll_interval_ms,
                interpretation=interpretation,
                not_interpreted=not_interpreted,
                profile=dict(profile),
                profile_status=profile_status,
            )
        )

    async def states(
        self, lookup: Callable[[str], Awaitable[Mapping[str, Any] | None]]
    ) -> list[dict[str, Any]]:
        """Every tracked channel's state against its device's active anchor."""
        out: list[dict[str, Any]] = []
        for device_id, channel in self.channels():
            out.append(
                {
                    "device_id": device_id,
                    "channel": channel,
                    **self.state(device_id, channel, await lookup(device_id)),
                }
            )
        return out

    def note_fault(
        self, *, device_id: str, channel: str, activation: tuple[str, int]
    ) -> None:
        state = self._channels.setdefault((device_id, channel), _ChannelState())
        state.fault_activation = activation

    def channels(self) -> list[tuple[str, str]]:
        return sorted(self._channels)

    def state(
        self, device_id: str, channel: str, active: Mapping[str, Any] | None
    ) -> dict[str, Any]:
        """The channel's alarms: unknown, or as of a named reading."""
        state = self._channels.get((device_id, channel))
        latest = state.latest if state is not None else None
        unknown: dict[str, Any] = {"state": "unknown"}
        activation = _activation(active)
        if latest is None or activation is None or latest.activation != activation:
            return unknown
        reading = {
            "key_epoch_id": latest.key_epoch_id,
            "boot_id": latest.boot_id,
            "seq": latest.seq,
            "receiver_accepted_at_ms": latest.received_at_ms,
            # The word read by value when it was one; otherwise exactly what
            # the device sent, never coerced into a word it was not.
            "word": (
                latest.interpretation.word
                if latest.interpretation is not None
                else latest.value
            ),
            "profile": dict(latest.profile),
            "profile_status": latest.profile_status,
        }
        if state is not None and state.fault_activation == activation:
            return {**unknown, "reason": "sensor_fault", "latest_reading": reading}
        if latest.interpretation is None:
            return {
                **unknown,
                "reason": latest.not_interpreted,
                "latest_reading": reading,
            }
        now = self._now()
        if (
            now is None
            or latest.poll_interval_ms is None
            or now - latest.accepted_ms > silence_bound_ms(latest.poll_interval_ms)
        ):
            return {**unknown, "reason": "silent", "latest_reading": reading}
        interpretation = latest.interpretation
        return {
            "state": "as_of",
            "reading": reading,
            "asserted": [
                {"id": alarm_id, "meaning": interpretation.meanings[alarm_id]}
                for alarm_id in interpretation.asserted
            ],
            "not_asserted_at_that_poll": list(interpretation.not_asserted),
            "unmapped_set_bits": list(interpretation.unmapped_set_bits),
        }


def _activation(active: Mapping[str, Any] | None) -> tuple[str, int] | None:
    """The active anchor's activation, or None while no anchor is active."""
    if active is None or active.get("revoked") or not active.get("approved"):
        return None
    activation_id = active.get("activation_id")
    anchor = active.get("anchor_epoch_id")
    if not isinstance(activation_id, int) or not isinstance(anchor, str):
        return None
    return anchor, activation_id
