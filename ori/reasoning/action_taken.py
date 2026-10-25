# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What the runtime writes in ``action_log.action_taken`` other than an action.

The column names the action an executor carried out, and otherwise says why
none was: a marker below, a Tier C decision state, a ``refused_`` reason, or
the empty string for an executor that ran and failed. A Tier C decision that
could not be recorded is named with an ``_unrecorded`` suffix, beside a safe
default that may have run. A skill action carrying one of those names would
make its row read as something the runtime decided, so the loader refuses it,
and the test suite holds every row the store writes to this vocabulary
(``tests/conftest.py``).
"""

from typing import Final

from ori.reasoning.tier_c_admission import DECISION_STATES

#: A request that joined an act another request holds, instead of acting.
COALESCED: Final = "coalesced"
#: An executor may return this instead of a bool to say it deliberately did not
#: act. A plain `False` means the action was attempted and did not happen, which
#: an operator reading `action_log` must be able to tell from a notice a
#: customer switched off.
SUPPRESSED: Final = "suppressed"
#: Recorded when a dispatched action has no registered executor. `executed` is
#: false for it, like any other non-execution, but the cause is a configuration
#: fault rather than a runtime one: nothing was attempted because there was
#: nothing to attempt. An operator reading `action_log` fixes a missing executor
#: differently from an executor that ran and failed, so the two must not
#: collapse into one indistinguishable row.
NO_EXECUTOR: Final = "no_executor"
#: An executor's affirmation that the commanded physical outcome did not
#: occur: the driver refused before anything was driven. Only this makes an
#: approved dispatch `dispatch_failed`; a bare False or a raise is unknown.
NOT_PERFORMED: Final = "not_performed"
#: A Tier C proposal the store did not commit, so no decision exists for it.
PROPOSAL_NOT_COMMITTED: Final = "proposal_not_committed"

REFUSED_PREFIX: Final = "refused_"
UNRECORDED_SUFFIX: Final = "_unrecorded"

_MARKERS: Final = frozenset(
    {COALESCED, SUPPRESSED, NO_EXECUTOR, NOT_PERFORMED, PROPOSAL_NOT_COMMITTED}
    | DECISION_STATES
)


def is_reserved(name: str) -> bool:
    """Whether *name* is one the runtime writes to say no action was taken."""
    folded = name.strip().lower()
    return (
        folded in _MARKERS
        or folded.startswith(REFUSED_PREFIX)
        or folded.endswith(UNRECORDED_SUFFIX)
    )
