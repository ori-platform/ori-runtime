# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Shared operator-message composer helpers for bundled skills."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

FALLBACK_UTC = timezone.utc
DEFAULT_SMS_MAX_CHARS = 160
DEFAULT_DIAGNOSIS_MAX_CHARS = 66
DEFAULT_DIAGNOSIS_FALLBACK = "Something changed in a way that needs quick attention."

DEFAULT_JARGON_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    (r"\bthresholds?\b", "limit"),
    (r"\banomal(y|ies)\b", "issue"),
    (r"\bbaseline\b", "usual level"),
    (r"\bdeviations?\b", "difference"),
    (r"\bsensors?\b", "device"),
    (r"\breadings?\b", "measure"),
    (r"\bvalues?\b", "level"),
    (r"\bcurrent\b", "power"),
    (r"\bvoltage\b", "power"),
)


def resolve_timezone(tz_name: str | None):
    """Resolve timezone from explicit name, then host timezone, then UTC."""
    if tz_name:
        try:
            return ZoneInfo(str(tz_name).strip())
        except Exception:
            pass
    try:
        local_tz = datetime.now().astimezone().tzinfo
        if local_tz is not None:
            return local_tz
    except Exception:
        pass
    return FALLBACK_UTC


def format_event_time_hhmm(*, timestamp_ms: int, tz_name: str | None) -> str:
    ts_sec = max(0, int(timestamp_ms)) / 1000.0
    dt = datetime.fromtimestamp(ts_sec, tz=resolve_timezone(tz_name))
    return dt.strftime("%H:%M")


def one_sentence_diagnosis(
    text: str,
    *,
    jargon_replacements: tuple[tuple[str, str], ...] = DEFAULT_JARGON_REPLACEMENTS,
    max_chars: int = DEFAULT_DIAGNOSIS_MAX_CHARS,
    fallback: str = DEFAULT_DIAGNOSIS_FALLBACK,
) -> str:
    """Normalize LLM diagnosis into one plain sentence for operators."""
    normalized = " ".join(str(text or "").split()).strip()
    if not normalized:
        return fallback
    parts = re.split(r"[.!?]+", normalized, maxsplit=1)
    sentence = parts[0].strip() if parts else normalized
    if not sentence:
        sentence = normalized
    for pattern, replacement in jargon_replacements:
        sentence = re.sub(pattern, replacement, sentence, flags=re.IGNORECASE)
    sentence = " ".join(sentence.split()).strip(" -,:;")
    if not sentence:
        sentence = fallback
    if len(sentence) > max_chars:
        sentence = sentence[: max_chars - 1].rstrip() + "…"
    if not sentence.endswith("."):
        sentence = f"{sentence}."
    return sentence


def as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def sms_cap(message: str, *, max_chars: int = DEFAULT_SMS_MAX_CHARS) -> str:
    compact = " ".join(str(message or "").split())
    if len(compact) <= max_chars:
        return compact
    return compact[: max_chars - 1].rstrip() + "…"
