#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""
Ori PC Health Report — Live Smoke Test
=======================================
Runs the real pc-system-health skill against your actual machine right now.
No mocks. No fakes. Uses the real PsutilAdapter to read live sensor data,
then evaluates every trigger through the RuleEngine exactly as the runtime
would during a polling loop.

Usage:
    .venv/bin/python scripts/pc_health_report.py

What it does:
    1. Reads every psutil sensor type in parallel
    2. Runs the skill's triggers through the rule engine
    3. Shows what Ori would observe — and what it would do
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

# ── Make sure ori package is importable without installing ───────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from ori.hal.psutil_adapter import PsutilAdapter  # noqa: E402
from ori.network.events import OriEvent, SensorReading  # noqa: E402
from ori.reasoning.rule_engine import RuleEngine  # noqa: E402
from ori.skills.loader import SkillLoader  # noqa: E402

# ── ANSI colour helpers ───────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"


def c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + RESET


# ── Sensor definitions ────────────────────────────────────────────────────────
# Each entry: (sensor_id, sensor_type, unit_label)
SENSORS: list[tuple[str, str, str]] = [
    ("cpu_percent", "cpu_percent", "%"),
    ("cpu_temp", "cpu_temp", "°C"),
    ("memory_percent", "memory_percent", "%"),
    ("memory_used_mb", "memory_used_mb", "MB"),
    ("disk_percent", "disk_percent", "%"),
    ("disk_write_mb", "disk_write_mb", "MB"),
    ("disk_read_mb", "disk_read_mb", "MB"),
    ("net_bytes_sent_mb", "net_bytes_sent_mb", "MB"),
    ("net_bytes_recv_mb", "net_bytes_recv_mb", "MB"),
    ("battery_percent", "battery_percent", "%"),
    ("battery_time_remaining", "battery_time_remaining", "min"),
    ("sleep_blocking_process", "sleep_blocking_process", "procs"),
]

SKILL_DIR = Path(__file__).parent.parent / "skills" / "pc-system-health"

TIER_LABEL = {
    "A": c("● Tier A  INFO", GREEN),
    "B": c("● Tier B  SOFT", YELLOW),
    "C": c("● Tier C  HARD", RED),
    "D": c("● Tier D  SAFE", BOLD + RED),
}

ACTION_LABEL = {
    "A": "Would send WhatsApp / log to dashboard",
    "B": "Would switch source / soft physical action",
    "C": "Would propose action — awaiting operator YES/NO",
    "D": "⚡ IMMEDIATE AUTONOMOUS CUTOFF — no LLM, no approval",
}


# ── Core helpers ──────────────────────────────────────────────────────────────


async def read_sensor(sensor_id: str, sensor_type: str) -> SensorReading | None:
    adapter = PsutilAdapter()
    try:
        await adapter.connect({"sensor_id": sensor_id, "sensor_type": sensor_type})
        reading = await adapter.read(sensor_id)
        await adapter.close()
        return reading
    except Exception as exc:
        print(c(f"  [WARN] Could not read {sensor_type}: {exc}", DIM))
        return None


def _bar(value: float, max_value: float = 100.0, width: int = 20) -> str:
    filled = int(min(value, max_value) / max_value * width)
    pct = value / max_value
    colour = GREEN if pct < 0.6 else (YELLOW if pct < 0.85 else RED)
    bar = colour + "█" * filled + DIM + "░" * (width - filled) + RESET
    return f"[{bar}]"


def _format_capacity(value: float, unit_label: str) -> tuple[str, str]:
    """Format MB values as GB once they cross 1000 MB for readability."""
    if unit_label != "MB":
        return f"{value:,.1f}", unit_label
    if abs(value) >= 1000:
        return f"{value / 1000.0:,.2f}", "GB"
    return f"{value:,.1f}", "MB"


def _format_duration_minutes(value: float) -> str:
    """Render minute values as human-friendly hours/minutes."""
    total_minutes = max(0, int(round(value)))
    hours, minutes = divmod(total_minutes, 60)
    if hours > 0:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m"


def _reading_row(
    sensor_type: str,
    reading: SensorReading | None,
    unit_label: str,
) -> str:
    label = sensor_type.replace("_", " ").title()

    if reading is None:
        return f"  {c(label.ljust(28), DIM)} {c('—  unavailable', DIM)}"

    v = reading.value
    q = reading.quality

    # Quality indicator
    if q == 0.0:
        v_str = c("—  (no sensor / unavailable)", DIM)
    elif sensor_type in ("cpu_percent", "memory_percent", "disk_percent"):
        v_str = f"{c(f'{v:6.1f}', WHITE)} {unit_label}  {_bar(v)}"
    elif sensor_type == "battery_percent":
        if q == 0.0:
            v_str = c("—  (no battery)", DIM)
        else:
            v_str = f"{c(f'{v:6.1f}', WHITE)} {unit_label}  {_bar(v)}"
    elif sensor_type == "battery_time_remaining":
        if q == 0.0:
            v_str = c("—  (no battery)", DIM)
        elif v == -1.0:
            v_str = c("  plugged in / charging", GREEN)
        else:
            v_str = c(f"  {_format_duration_minutes(v)}", WHITE)
    elif sensor_type == "cpu_temp":
        if q == 0.0:
            v_str = c("—  (sensor unavailable)", DIM)
        else:
            colour = GREEN if v < 70 else (YELLOW if v < 85 else RED)
            v_str = f"{c(f'{v:6.1f}', colour)} {unit_label}"

    elif sensor_type == "sleep_blocking_process":
        if v == 0.0:
            v_str = c("  0 — no processes blocking sleep", GREEN)
        else:
            procs = reading.metadata.get("processes", [])
            names = ", ".join(p.get("name", "?") for p in procs[:3])
            extra = f"  (+{len(procs) - 3} more)" if len(procs) > 3 else ""
            v_str = f"{c(f'{int(v)}', YELLOW)} processes: {c(names, YELLOW)}{extra}"
    else:
        formatted_value, formatted_unit = _format_capacity(v, unit_label)
        v_str = f"{c(formatted_value, WHITE)} {formatted_unit}"

    return f"  {c(label.ljust(28), CYAN)} {v_str}"


async def evaluate_triggers(
    readings: dict[str, SensorReading | None],
    skill,
) -> list[tuple]:
    """Run every trigger against every reading. Return list of (trigger, reading, RuleResult)."""
    engine = RuleEngine()
    hits: list[tuple] = []

    for sensor_id, reading in readings.items():
        if reading is None or reading.quality == 0.0:
            continue

        event = OriEvent.from_reading(reading, "dev-localhost")

        # Build context — named sensor vars + raw quality fields
        ctx: dict = {
            reading.sensor_type: reading.value,
            "sensor_type": reading.sensor_type,
            "value": reading.value,
            "quality": reading.quality,
        }
        # cpu_temp_quality is a special guard in the condition
        if reading.sensor_type == "cpu_temp":
            ctx["cpu_temp_quality"] = reading.quality

        for trigger in skill.triggers:
            try:
                result = await engine.evaluate(event, [trigger], context=ctx)
                if result.matched:
                    hits.append((trigger, reading, result))
            except Exception:
                pass  # sensor not relevant to this trigger — skip

    return hits


# ── Main ──────────────────────────────────────────────────────────────────────


async def main() -> None:
    width = 65

    print()
    print(c("╔" + "═" * (width - 2) + "╗", BOLD + CYAN))
    print(
        c("║", BOLD + CYAN)
        + c("  ORI  PC HEALTH REPORT".center(width - 2), BOLD + WHITE)
        + c("║", BOLD + CYAN)
    )
    print(
        c("║", BOLD + CYAN)
        + c(
            f"  Skill: pc-system-health  ·  {time.strftime('%H:%M:%S')} on "
            f"{time.strftime('%A, %d %B %Y')}".center(width - 2),
            DIM,
        )
        + c("║", BOLD + CYAN)
    )
    print(c("╚" + "═" * (width - 2) + "╝", BOLD + CYAN))
    print()

    # ── Load skill ───────────────────────────────────────────────────────────
    print(c("  Loading skill …", DIM), end="", flush=True)
    skill = SkillLoader().load_one(SKILL_DIR)
    print(
        c(
            f"\r  ✓ Skill loaded: {skill.name} v{skill.version}  ({len(skill.triggers)} triggers)",
            GREEN,
        )
    )
    print()

    # ── Read sensors ─────────────────────────────────────────────────────────
    print(
        c(
            "── LIVE SENSOR READINGS ─────────────────────────────────────────",
            BOLD + BLUE,
        )
    )
    print()

    tasks = {
        sensor_id: asyncio.create_task(read_sensor(sensor_id, sensor_type))
        for sensor_id, sensor_type, _ in SENSORS
    }

    readings: dict[str, SensorReading | None] = {}
    for sensor_id, sensor_type, unit_label in SENSORS:
        reading = await tasks[sensor_id]
        readings[sensor_id] = reading
        print(_reading_row(sensor_type, reading, unit_label))

    print()

    # ── Hooks — compute derived values (write rate) ──────────────────────────
    # We can't fully run pre_trigger_eval without a StateStore (needs history),
    # but we can show what the hook would compute with a fresh boot baseline.
    disk_reading = readings.get("disk_write_mb")
    if disk_reading and disk_reading.quality > 0:
        print(
            c("  💡 write_rate_mb_per_min", DIM)
            + c(
                "  — needs history (StateStore) to compute delta. Trigger will be skipped.",
                DIM,
            )
        )
    print()

    # ── Trigger evaluation ───────────────────────────────────────────────────
    print(
        c(
            "── TRIGGER EVALUATION ───────────────────────────────────────────",
            BOLD + BLUE,
        )
    )
    print()

    hits = await evaluate_triggers(readings, skill)

    if not hits:
        print(c("  ✅  All clear — no triggers fired.", GREEN, BOLD))
        print(c("      Your machine is within normal operating parameters.", DIM))
    else:
        print(c(f"  ⚠️  {len(hits)} trigger(s) fired:\n", YELLOW, BOLD))
        for trigger, reading, result in hits:
            tier = trigger.action_tier
            print(f"  {TIER_LABEL.get(tier, tier)}  {c(trigger.name, BOLD)}")
            print(
                f"       Sensor  : {c(reading.sensor_type, CYAN)} = "
                f"{c(str(round(reading.value, 2)), WHITE)}"
            )
            print(f"       Condition: {c(trigger.condition, DIM)}")
            if tier == "D":
                print(
                    f"       {c('⚡ Ori would immediately execute emergency cutoff (no LLM, no approval)', RED, BOLD)}"
                )
            elif tier == "C":
                print(
                    f"       Ori would send WhatsApp: "
                    f"{c('PROPOSED ACTION — reply YES/NO within 300s', YELLOW)}"
                )
            elif tier == "A":
                print(
                    f"       Ori would {c('send WhatsApp alert / log to dashboard', GREEN)}"
                )
            escalate = trigger.escalate_to
            if not trigger.bypass_llm:
                print(f"       Reasoning: {c(f'would escalate to → {escalate}', DIM)}")
            print()

    # ── Summary box ──────────────────────────────────────────────────────────
    tier_d_hits = [h for h in hits if h[0].action_tier == "D"]
    tier_c_hits = [h for h in hits if h[0].action_tier == "C"]
    tier_b_hits = [h for h in hits if h[0].action_tier == "B"]
    tier_a_hits = [h for h in hits if h[0].action_tier == "A"]

    print(
        c(
            "── ORI ASSESSMENT ───────────────────────────────────────────────",
            BOLD + BLUE,
        )
    )
    print()

    if tier_d_hits:
        print(c("  🔴 CRITICAL — Safety-critical condition(s) detected.", RED, BOLD))
        print(
            c(
                "     Ori would have fired an emergency cutoff before this report finished.",
                RED,
            )
        )
    elif tier_c_hits:
        print(
            c(
                "  🟠 ACTION REQUIRED — Hard physical action(s) need your approval.",
                YELLOW,
                BOLD,
            )
        )
        print(
            c("     Ori would have sent a WhatsApp proposal. Reply YES or NO.", YELLOW)
        )
    elif tier_a_hits:
        print(c("  🟡 ATTENTION — Informational alert(s) fired.", YELLOW))
        print(
            c(
                "     Ori has reasoned about this and is notifying you. No action required.",
                DIM,
            )
        )
    else:
        print(c("  🟢 HEALTHY — No issues detected.", GREEN, BOLD))
        print(c("     Ori would remain in passive observation mode.", DIM))

    print()
    print(c("  Triggers fired  : ", DIM) + c(str(len(hits)), BOLD))
    print(
        c("  By tier         : ", DIM)
        + c(f"D={len(tier_d_hits)}", RED)
        + "  "
        + c(f"C={len(tier_c_hits)}", YELLOW)
        + "  "
        + c(f"B={len(tier_b_hits)}", BLUE)
        + "  "
        + c(f"A={len(tier_a_hits)}", GREEN)
    )
    print()
    print(c("  This is what Ori sees on your machine right now.", DIM))
    print(
        c(
            "  In a live runtime, each trigger would kick off the Intelligence Elevator.",
            DIM,
        )
    )
    print()


if __name__ == "__main__":
    asyncio.run(main())
