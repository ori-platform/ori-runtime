# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The shape of action-log records, shared by the writer and the migrations."""

import sqlite3
from typing import Any, Mapping

_INPUT_ATTESTATION_GRADES = frozenset({"attested", "attested_dev", "unattested"})


_INPUT_POSTURES = frozenset({"development", "sealed_flash", "hardware_key"})


def _normalise_input_attestation_grade(value: Any) -> str:
    grade = str(value or "").strip().lower()
    return grade if grade in _INPUT_ATTESTATION_GRADES else "unattested"


def _normalise_input_evidence(grade_value: Any, posture_value: Any) -> tuple[str, str]:
    grade = _normalise_input_attestation_grade(grade_value)
    posture = str(posture_value or "").strip().lower()
    if grade == "unattested":
        return "unattested", ""
    if grade == "attested_dev":
        if posture == "development":
            return "attested_dev", "development"
        return "unattested", ""
    if posture in _INPUT_POSTURES - {"development"}:
        return "attested", posture
    return "unattested", ""


RECORD_DISPATCH = "dispatch"


RECORD_CONTRIBUTOR = "contributor"


RECORD_CONTRIBUTOR_LEGACY = "contributor_legacy"


RECORD_KINDS = frozenset(
    {RECORD_DISPATCH, RECORD_CONTRIBUTOR, RECORD_CONTRIBUTOR_LEGACY}
)


def _action_record_members(row: Mapping[str, Any] | sqlite3.Row) -> dict[str, Any]:
    """What a stored action row records, as gateway-api/v2's export row checks require.

    A table the columns were added to has no CHECK, and a rolled-back release
    writes joined rows as dispatches until the next open reclassifies them, so
    the kind is read again here by the runtime's own test: a joined row is a
    contributor only with a valid link and no execution, otherwise a legacy
    contributor with none, and every other row is a dispatch.
    """
    key = row["record_key"]
    record_key = key if isinstance(key, str) and key else None
    link = row["contributed_to"]
    if row["action_taken"] != "coalesced":
        return {
            "record_kind": RECORD_DISPATCH,
            "record_key": record_key,
            "contributed_to": None,
        }
    if (
        row["record_kind"] == RECORD_CONTRIBUTOR
        and type(row["executed"]) is int
        and row["executed"] == 0
        and isinstance(link, str)
        and link
        and link != record_key
    ):
        return {
            "record_kind": RECORD_CONTRIBUTOR,
            "record_key": record_key,
            "contributed_to": link,
        }
    return {
        "record_kind": RECORD_CONTRIBUTOR_LEGACY,
        "record_key": record_key,
        "contributed_to": None,
    }


def _check_action_record_shape(
    record_kind: str,
    *,
    executed: bool,
    approved: Any,
    action_taken: str,
    authority_json: Any,
    attestation_status: str,
    contributed_to: Any,
) -> None:
    """Refuse an action row whose fields disagree with what it says it records.

    The table's CHECK holds this on a database created with the columns; this
    holds it on one they were added to, and gives the refusal a reason.
    """
    if record_kind not in RECORD_KINDS:
        raise ValueError(f"unknown action record kind {record_kind!r}")
    if record_kind == RECORD_DISPATCH:
        if contributed_to is not None:
            raise ValueError("a dispatch record names no holder it contributed to")
        if action_taken == "coalesced":
            raise ValueError("a dispatch that joined another's act is a contributor")
        return
    if record_kind == RECORD_CONTRIBUTOR_LEGACY:
        raise ValueError(
            "contributor_legacy rows are only ever migrated, never written"
        )
    if (
        executed
        or approved is not None
        or action_taken != "coalesced"
        or authority_json is not None
        or attestation_status != ""
        or not isinstance(contributed_to, str)
        or not contributed_to
    ):
        raise ValueError(
            "a contributor record performs nothing, holds no licence, is never "
            "attested and names the holder it joined"
        )
