# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Runtime-local ContextEnricher for bounded, stale-aware prompt snapshots.

At prompt-assembly time the enricher queries the StateStore for the latest
reading of every *other* sensor on the device and appends a sanitized,
deterministic snapshot to the prompt before it reaches the local SLM or
gateway reasoner.  Enrichment is disabled by default and never fires on
Tier D paths — those exit before _build_prompt is called.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from ori.network.events import OriEvent, SensorReading
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

_MAX_FIELD_CHARS = 200
_SAFE_TEXT_RE = re.compile(r"[^\w\s\-\./°%]")

_SNAPSHOT_HEADER = "Other sensors on this device (snapshot):"


@dataclass(frozen=True)
class ContextEnricherConfig:
    enabled: bool = False
    staleness_window_ms: int = 60_000
    max_entries: int = 5
    include_sources: list[str] = field(default_factory=list)


class ContextEnricher:
    """Appends a bounded, stale-aware cross-sensor snapshot to prompts.

    The snapshot is purely additive — enrichment failure is silent and
    always returns the original prompt unchanged so the runtime can never
    halt because enrichment broke.

    ``now_ms`` is evaluated at enrich-call time (not at event-emit time) so
    staleness reflects when the prompt is built, not when the sensor fired.
    """

    def __init__(self, config: ContextEnricherConfig) -> None:
        self._config = config

    async def enrich(
        self,
        prompt: str,
        event: OriEvent,
        state_store: Any,
    ) -> str:
        """Return prompt with a sanitized cross-sensor snapshot appended.

        Returns the original prompt unchanged if:
        - enrichment is disabled
        - the snapshot is empty after staleness/source filtering
        - any exception occurs during the store query or formatting
        """
        if not self._config.enabled:
            return prompt
        try:
            cutoff_ms = now_ms() - self._config.staleness_window_ms
            readings: list[
                SensorReading
            ] = await state_store.get_latest_readings_snapshot(
                exclude_sensor_id=event.sensor_id,
                since_ms=cutoff_ms,
                max_entries=self._config.max_entries,
            )
            if self._config.include_sources:
                allowed = set(self._config.include_sources)
                readings = [
                    r for r in readings if str(r.metadata.get("source", "")) in allowed
                ]
            if not readings:
                return prompt
            lines = self._format_snapshot_lines(readings)
            return f"{prompt}\n\n{_SNAPSHOT_HEADER}\n" + "\n".join(lines)
        except Exception:
            logger.warning(
                "ContextEnricher: snapshot enrichment failed for sensor_id=%s"
                " — continuing with original prompt",
                event.sensor_id,
                exc_info=True,
            )
            return prompt

    def _format_snapshot_lines(self, readings: list[SensorReading]) -> list[str]:
        lines = []
        for r in readings:
            sid = _sanitize(r.sensor_id)
            stype = _sanitize(r.sensor_type)
            val = _sanitize(str(r.value))
            unit = _sanitize(r.unit)
            quality = _sanitize(str(round(r.quality, 2)))
            lines.append(f"- {sid} ({stype}): {val} {unit}  quality={quality}")
        return lines


def _sanitize(text: str) -> str:
    return _SAFE_TEXT_RE.sub("", str(text or "").strip())[:_MAX_FIELD_CHARS].strip()
