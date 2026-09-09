# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime's map from an alert trigger to a customer-disableable class.

A class is disableable because a customer turned it off in a signed policy, so
what belongs to it is a decision about which notices a customer may silence --
never something derived from a trigger's name, its display text, its action
tier or the channel it would use.

**The map is empty, and stays empty until the contract names its entries.**
Binding a bare trigger name would be doubly wrong: it is the inference the
contract forbids, and the name is not an identity. Trigger names come from
`skill.yaml`, which is untrusted input, so any skill declaring a trigger of the
same name would inherit the customer's toggle. An entry therefore needs a
first-party skill and trigger together, and the product has to state which pair
each of its customer-facing classes names. Tracked as
ori-platform/ori-energy#92.

Absence of an entry is always enablement. That is the direction a gap has to
fail in: an unmapped trigger keeps notifying, whereas a wrong guess silences
something the customer never chose to silence.
"""

from __future__ import annotations

from typing import Final

GENERATOR_RUNNING_TOO_LONG: Final = "generator_running_too_long"
UNUSUAL_CONSUMPTION_SPIKE: Final = "unusual_consumption_spike"
BATTERY_UNDERPERFORMING: Final = "battery_underperforming"
GRID_POWER_RESTORED: Final = "grid_power_restored"

#: Every class the signed policy may carry a toggle for.
ALERT_CLASSES: Final[frozenset[str]] = frozenset(
    {
        GENERATOR_RUNNING_TOO_LONG,
        UNUSUAL_CONSUMPTION_SPIKE,
        BATTERY_UNDERPERFORMING,
        GRID_POWER_RESTORED,
    }
)

#: (first-party skill name, trigger name) -> class.
#:
#: Keyed on the pair rather than the trigger alone because a bare name is not
#: an identity. Populated only from the cross-repo contract, never from this
#: repository's skills.
TRIGGER_ALERT_CLASS: Final[dict[tuple[str, str], str]] = {}

#: Classes no entry resolves to. Every one of them, today.
UNBOUND_ALERT_CLASSES: Final[frozenset[str]] = ALERT_CLASSES - frozenset(
    TRIGGER_ALERT_CLASS.values()
)


def alert_class_for_trigger(
    skill_name: str, trigger_name: str, *, first_party: bool
) -> str | None:
    """The disableable class this trigger belongs to, or None if it has none.

    A community skill never resolves to a class. Its `skill.yaml` is untrusted
    input and its trigger names are its own to choose, so honouring one here
    would let any loaded skill take over a customer's toggle by naming a
    trigger after a first-party one.
    """
    if not first_party:
        return None
    key = (str(skill_name or "").strip(), str(trigger_name or "").strip())
    if not key[0] or not key[1]:
        return None
    return TRIGGER_ALERT_CLASS.get(key)
