# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The target a host-state executor acts on, read from its skill context.

`terminate_process` and `reset_kernel_subsystem` each resolve one target
from the event that raised them; the dispatcher's resource resolvers use the
same functions, so the act that is admitted is the act that runs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ori.reasoning.elevator import SkillContext


def process_target_from_context(ctx: SkillContext) -> tuple[int | None, str]:
    """Resolve a single process target for `terminate_process`.

    Resolution order:
    1. Explicit event context override: `event.context["terminate_process"]`
       with `{pid, name}`.
    2. Exactly one process in `event.reading.metadata["processes"]`.
    """
    if not ctx or not ctx.event:
        return None, ""

    terminate_ctx = ctx.event.context.get("terminate_process", {})
    if isinstance(terminate_ctx, dict):
        pid = terminate_ctx.get("pid")
        name = terminate_ctx.get("name")
        if isinstance(pid, int) and isinstance(name, str) and name.strip():
            return pid, name.strip()
        if (
            isinstance(pid, str)
            and pid.isdigit()
            and isinstance(name, str)
            and name.strip()
        ):
            return int(pid), name.strip()

    reading = ctx.event.reading
    if reading is None:
        return None, ""

    processes = reading.metadata.get("processes", [])
    if not isinstance(processes, list):
        processes = []

    recommended = reading.metadata.get("recommended_process")
    if isinstance(recommended, dict):
        pid = recommended.get("pid")
        name = recommended.get("name")
        if isinstance(pid, int) and isinstance(name, str) and name.strip():
            return pid, name.strip()
        if (
            isinstance(pid, str)
            and pid.isdigit()
            and isinstance(name, str)
            and name.strip()
        ):
            return int(pid), name.strip()

    valid: list[tuple[int, str]] = []
    for proc in processes:
        if not isinstance(proc, dict):
            continue
        pid = proc.get("pid")
        name = proc.get("name")
        if isinstance(pid, int) and isinstance(name, str) and name.strip():
            valid.append((pid, name.strip()))
        elif (
            isinstance(pid, str)
            and pid.isdigit()
            and isinstance(name, str)
            and name.strip()
        ):
            valid.append((int(pid), name.strip()))

    if len(valid) == 1:
        return valid[0]

    return None, ""


def kernel_subsystem_from_context(ctx: SkillContext) -> str:
    """Resolve subsystem target for `reset_kernel_subsystem`.

    Resolution order:
    1. Explicit event context override:
       `event.context["reset_kernel_subsystem"]` as either
       `{"subsystem": "<name>"}` or `"<name>"`.
    2. Reading metadata keys: `kernel_subsystem` then `subsystem`.
    """
    if not ctx or not ctx.event:
        return ""

    raw = ctx.event.context.get("reset_kernel_subsystem", "")
    if isinstance(raw, dict):
        subsystem = raw.get("subsystem")
        if isinstance(subsystem, str) and subsystem.strip():
            return subsystem.strip()
    elif isinstance(raw, str) and raw.strip():
        return raw.strip()

    reading = ctx.event.reading
    if reading is None:
        return ""

    for key in ("kernel_subsystem", "subsystem"):
        value = reading.metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""
