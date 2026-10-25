# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hold every action-log row the suite writes to the action_taken vocabulary.

A row that did not execute says why with the empty string or a reserved name
(`ori/reasoning/action_taken.py`). A row that did names the action taken, or,
where a Tier C decision could not be recorded, the decision lost beside the
safe default that ran: never another reserved name. The store's writer is
wrapped once per process, so every path the suite drives is held, however the
value was spelled on its way to the row. The wrapper only records: it never
changes what the store writes. It is installed when pytest configures, before
any fixture. `tests/conftest.py` fails, on the finished report so `xfail` cannot
absorb it, the phase that wrote the row, the next test's setup for a row
written outside one, and the run for a row written after the last test's
check, an xdist worker's included.
"""

from __future__ import annotations

import functools
from typing import Any

from ori.reasoning.action_taken import UNRECORDED_SUFFIX, is_reserved
from ori.state._actions import ActionLogStore

#: Stated in every failure, because the message is what the next reader meets.
LIMIT = (
    "only rows written through a real StateStore are held: a row a test writes "
    "to a fake store, or a path no test drives, is not seen"
)

_violations: list[str] = []


def violation(executed: bool, action_taken: str) -> str | None:
    """Why a row with these fields breaks the vocabulary, or None."""
    if not executed and action_taken and not is_reserved(action_taken):
        return f"a row that did not execute names unreserved {action_taken!r}"
    if executed and is_reserved(action_taken):
        if not action_taken.endswith(UNRECORDED_SUFFIX):
            return f"an executed row names reserved {action_taken!r}"
    return None


def install() -> None:
    original = ActionLogStore._log_action_sync
    if getattr(original, "_action_taken_guard", False):
        return

    @functools.wraps(original)
    def guarded(self: Any, result: Any, *args: Any, **kwargs: Any) -> int:
        row_id = original(self, result, *args, **kwargs)
        # After the write: a row the store refused was never written.
        problem = violation(bool(result.executed), str(result.action_taken))
        if problem is not None:
            _violations.append(f"{result.action_name}: {problem}")
        return row_id

    guarded._action_taken_guard = True  # type: ignore[attr-defined]
    ActionLogStore._log_action_sync = guarded  # type: ignore[method-assign]


def drain() -> list[str]:
    found = list(_violations)
    _violations.clear()
    return found
