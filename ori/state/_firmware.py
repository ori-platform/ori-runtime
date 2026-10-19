# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Firmware device anchors, confirmations, sequences and provisioning."""

import base64
import binascii
import json
import sqlite3
from typing import Any

from ori.state._core import StoreCore
from ori.state._migrations import (
    _MIGRATION_ACTIVATION_START_UNKNOWN,
    _MIGRATION_ACTIVATION_UNPROVABLE,
    _MIGRATION_ACTIVATION_UNRECONSTRUCTABLE,
    _require_attribution,
)
from ori.utils.time_utils import now_ms

# The registry columns a firmware message is verified against. A freshness
# advance commits only while each still holds the value verification read.
FIRMWARE_ANCHOR_COLUMNS = (
    "public_key_b64",
    "posture",
    "capability_hash",
    "channel_map_json",
    "anchor_epoch_id",
    "key_epoch_id",
)


# In service, and its epoch confirmed by the evidence store: what a grant, a
# command or a liveness assertion needs (ori-specs device-provisioning/v1.md).
_FIRMWARE_AUTHORITY_SQL = """
    AND revoked = 0 AND approved = 1
    AND EXISTS (
        SELECT 1 FROM firmware_confirmation_outbox c
         WHERE c.device_id = firmware_device_registry.device_id
           AND c.anchor_epoch_id = firmware_device_registry.anchor_epoch_id
           AND c.status = 'confirmed'
    )
"""


# The fault row's epoch is the one the advance's WHERE binds.
_ANCHOR_KEY_EPOCH = FIRMWARE_ANCHOR_COLUMNS.index("key_epoch_id")


def _firmware_anchor_values(verified_against: Any) -> tuple[str, ...]:
    """The anchor a decision was made under, refused unless complete."""
    anchor = tuple(verified_against[column] for column in FIRMWARE_ANCHOR_COLUMNS)
    if any(not isinstance(value, str) for value in anchor):
        raise ValueError("verified_against must carry every anchor column")
    return anchor


_FIRMWARE_FAULT_COLUMNS = (
    "grade",
    "posture",
    "capability_hash",
    "code",
    "subject",
    "detail",
    "device_uptime_ms",
    "received_at_ms",
    "fault_json",
)


def _firmware_fault_values(fault_event: dict[str, Any]) -> tuple[Any, ...]:
    """The fault row's columns past its (device_id, boot_id, seq) key."""
    return tuple(fault_event[column] for column in _FIRMWARE_FAULT_COLUMNS)


# The device's latest promotion: it changes on every promotion, including a
# reinstated anchor promoted again with byte-identical columns.
_FIRMWARE_ACTIVATION_SQL = """
    AND (SELECT MAX(t.id) FROM firmware_anchor_transitions t
          WHERE t.device_id = firmware_device_registry.device_id
            AND t.transition = 'promoted') IS ?
"""


def _firmware_activation(verified_against: Any) -> int | None:
    """The activation a decision was made under, refused unless it was read."""
    if "activation_id" not in verified_against:
        raise ValueError("verified_against must carry activation_id")
    activation = verified_against["activation_id"]
    if activation is not None and (
        isinstance(activation, bool) or not isinstance(activation, int)
    ):
        raise ValueError("verified_against activation_id must be an int or None")
    return activation


def _firmware_anchor_sql() -> str:
    return "".join(f" AND {column} = ?" for column in FIRMWARE_ANCHOR_COLUMNS)


def _firmware_key_identity(public_key_b64: str) -> bytes | None:
    """A stored device key's identity, or None for one that does not decode."""
    from ori.security.ed25519_keys import key_identity

    try:
        raw = base64.b64decode(public_key_b64, validate=True)
        return key_identity(raw)
    except (binascii.Error, ValueError):
        return None


def _uptime_mark(key_epoch_id: Any, boot_id: int, seq: int) -> str:
    """The freshness mark an uptime is stored against, as the store writes it."""
    return f"{key_epoch_id or ''}:{boot_id}:{seq}"


class FirmwareStore(StoreCore):
    """Firmware device anchors, confirmations, sequences and provisioning."""

    # ─── firmware_device_registry ────────────────────────────────────────────

    async def upsert_firmware_device_anchor(
        self,
        *,
        device_id: str,
        public_key_b64: str,
        posture: str,
        capability_hash: str,
        manifest_json: str,
        channel_map_json: str,
        board_profile: str = "",
        provisioned_at_ms: int | None = None,
    ) -> str:
        """Register a provisioning anchor, per the lifecycle in
        ori-specs/device-provisioning/v1.md.

        Returns an outcome code rather than silently overwriting:

        ``registered``
            No prior anchor; stored unapproved.
        ``unchanged``
            The anchor already matches exactly. Idempotent no-op — nothing
            is touched, including approval and freshness.
        ``pending_manifest_epoch``
            Same key, new capability hash. Stored as a PENDING candidate
            beside the still-active anchor, which is untouched. Nothing is
            accepted against it until it is promoted.
        ``refused_revoked``
            The identity is revoked. Revocation belongs to the identity
            and is never cleared by registration.
        ``refused_key_change``
            The device key differs. A changed key through ordinary
            registration is indistinguishable from a takeover attempt and
            requires an explicit re-provisioning transaction.

        The decision is made inside the write transaction so a concurrent
        revocation cannot be raced.
        """
        return await self._run_write(
            self._immediate,
            self._upsert_firmware_device_anchor_sync,
            device_id,
            public_key_b64,
            posture,
            capability_hash,
            manifest_json,
            channel_map_json,
            board_profile,
            provisioned_at_ms if provisioned_at_ms is not None else now_ms(),
        )

    def _upsert_firmware_device_anchor_sync(  # noqa: PLR0913
        self,
        device_id: str,
        public_key_b64: str,
        posture: str,
        capability_hash: str,
        manifest_json: str,
        channel_map_json: str,
        board_profile: str,
        provisioned_at_ms: int,
    ) -> str:
        assert self._conn is not None
        from ori.security.firmware.telemetry import (
            anchor_epoch_id as _anchor_epoch_id,
        )
        from ori.security.firmware.telemetry import (
            key_epoch_id as _key_epoch_id,
        )

        kid = _key_epoch_id(device_id=device_id, public_key_b64=public_key_b64)
        aid = _anchor_epoch_id(
            device_id=device_id,
            public_key_b64=public_key_b64,
            posture=posture,
            capability_hash=capability_hash,
        )

        # Decide inside the transaction: a read-then-write in the caller
        # could be raced by a concurrent revocation.
        row = self._conn.execute(
            """
            SELECT public_key_b64, posture, capability_hash, revoked,
                   anchor_epoch_id, key_epoch_id
              FROM firmware_device_registry
             WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()

        def _record_anchor(state: str) -> None:
            self._conn.execute(  # type: ignore[union-attr]
                """
                INSERT OR REPLACE INTO firmware_device_anchors
                    (anchor_epoch_id, device_id, key_epoch_id, public_key_b64,
                     posture, capability_hash, manifest_json, channel_map_json,
                     board_profile, state, created_at_ms, state_changed_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    aid,
                    device_id,
                    kid,
                    public_key_b64,
                    posture,
                    capability_hash,
                    manifest_json,
                    channel_map_json,
                    board_profile,
                    state,
                    provisioned_at_ms,
                    provisioned_at_ms,
                ),
            )

        def _record_transition(
            transition: str, from_epoch: str | None, to_epoch: str | None
        ) -> None:
            self._conn.execute(  # type: ignore[union-attr]
                """
                INSERT INTO firmware_anchor_transitions
                    (device_id, transition, from_epoch_id, to_epoch_id,
                     key_epoch_id, actor, reason, occurred_at_ms)
                VALUES (?, ?, ?, ?, ?, '', '', ?)
                """,
                (device_id, transition, from_epoch, to_epoch, kid, provisioned_at_ms),
            )

        if row is None:
            self._conn.execute(
                """
                INSERT INTO firmware_device_registry
                    (device_id, public_key_b64, posture, capability_hash,
                     manifest_json, channel_map_json, board_profile,
                     approved, provisioned_at_ms, last_boot_id, last_seq,
                     revoked, revoked_at_ms, anchor_epoch_id, key_epoch_id)
                -- anchor_epoch_id stays empty until promotion: it names the
                -- ACTIVE anchor, and nothing is active yet.
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0, 0, 0, NULL, '', ?)
                """,
                (
                    device_id,
                    public_key_b64,
                    posture,
                    capability_hash,
                    manifest_json,
                    channel_map_json,
                    board_profile,
                    provisioned_at_ms,
                    kid,
                ),
            )
            _record_anchor("pending")
            _record_transition("registered", None, aid)
            self._conn.commit()
            return "registered"

        # Revocation belongs to the identity. It is never cleared as a
        # side effect of a device re-publishing its manifest.
        if row["revoked"]:
            return "refused_revoked"

        # A changed key through ordinary registration is indistinguishable
        # from an attacker presenting a key they control for an identity
        # they do not own: the manifest is self-signed, so verifying it
        # against the key inside it proves consistency, never provenance.
        if row["public_key_b64"] != public_key_b64:
            return "refused_key_change"

        # Authoritative: the anchors table, not the registry pointer. For
        # an identity with no active anchor the registry tracks the pending
        # candidate, so consulting it alone would call a superseded or
        # discarded anchor "unchanged".
        existing_anchor = self._conn.execute(
            "SELECT state FROM firmware_device_anchors WHERE anchor_epoch_id = ?",
            (aid,),
        ).fetchone()
        if existing_anchor is not None and existing_anchor["state"] in (
            "active",
            "pending",
        ):
            # Exact match against the live anchor: idempotent. Touch
            # nothing — not approval, not freshness, not
            # provisioned_at_ms. Re-publishing a manifest is not an event.
            return "unchanged"

        # Same key, new manifest or posture: a PENDING candidate beside
        # the still-active anchor. The active anchor is deliberately
        # untouched — overwriting it would let a device replace its own
        # accepted capability surface by publishing, and would reset a
        # replay window that never left its key epoch.
        existing_pending = self._conn.execute(
            """
            SELECT anchor_epoch_id FROM firmware_device_anchors
             WHERE device_id = ? AND state = 'pending'
            """,
            (device_id,),
        ).fetchone()
        if existing_pending is not None:
            if existing_pending["anchor_epoch_id"] == aid:
                return "unchanged"
            # A pending anchor grants nothing, so replacing one loses no
            # authority; refusing would strand a device whose earlier
            # manifest nobody promoted.
            self._conn.execute(
                """
                UPDATE firmware_device_anchors
                   SET state = 'discarded', state_changed_at_ms = ?
                 WHERE anchor_epoch_id = ?
                """,
                (provisioned_at_ms, existing_pending["anchor_epoch_id"]),
            )
            _record_transition("discarded", existing_pending["anchor_epoch_id"], aid)

        _record_anchor("pending")
        _record_transition("registered", row["anchor_epoch_id"] or None, aid)

        has_active = self._conn.execute(
            "SELECT 1 FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'active'",
            (device_id,),
        ).fetchone()
        if has_active is None:
            # Nothing is active, so the registry row is the identity's
            # description of its only candidate. Point it at the new one —
            # otherwise it would still describe the anchor just discarded,
            # and promotion would activate the wrong manifest.
            self._conn.execute(
                """
                UPDATE firmware_device_registry
                   SET posture = ?, capability_hash = ?, manifest_json = ?,
                       channel_map_json = ?, board_profile = ?,
                       provisioned_at_ms = ?
                 WHERE device_id = ?
                """,
                (
                    posture,
                    capability_hash,
                    manifest_json,
                    channel_map_json,
                    board_profile,
                    provisioned_at_ms,
                    device_id,
                ),
            )
        self._conn.commit()
        return "pending_manifest_epoch"

    async def get_pending_firmware_anchor(self, device_id: str) -> dict | None:
        """The pending candidate for a device, if one is awaiting
        promotion. A pending anchor grants nothing."""
        return await self._run_read(self._get_pending_firmware_anchor_sync, device_id)

    def _get_pending_firmware_anchor_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT * FROM firmware_device_anchors
             WHERE device_id = ? AND state = 'pending'
            """,
            (device_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    async def list_firmware_anchor_history(self, device_id: str) -> list[dict]:
        """Every anchor this identity has held, newest first.

        Append-only: evidence outlives the anchor that authorised it, so
        superseded and discarded anchors are retained rather than
        overwritten.
        """
        return await self._run_read(self._list_firmware_anchor_history_sync, device_id)

    def _list_firmware_anchor_history_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT * FROM firmware_device_anchors
             WHERE device_id = ?
             ORDER BY state_changed_at_ms DESC, rowid DESC
            """,
            (device_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── cross-store confirmation outbox ──────────────────────────────

    async def get_firmware_confirmation_status(
        self, device_id: str, anchor_epoch_id: str
    ) -> str | None:
        """The confirmation status of one approved epoch, or ``None`` if no
        obligation was recorded for it.

        The publish gate reads this: a grant may reach firmware only when
        its active anchor's epoch is ``confirmed``.
        """
        return await self._run_read(
            self._get_firmware_confirmation_status_sync, device_id, anchor_epoch_id
        )

    def _get_firmware_confirmation_status_sync(
        self, conn: sqlite3.Connection, device_id: str, anchor_epoch_id: str
    ) -> str | None:
        row = conn.execute(
            "SELECT status FROM firmware_confirmation_outbox "
            "WHERE device_id = ? AND anchor_epoch_id = ?",
            (device_id, anchor_epoch_id),
        ).fetchone()
        return str(row[0]) if row is not None else None

    async def list_pending_firmware_confirmations(self, limit: int = 100) -> list[dict]:
        """Obligations still awaiting the evidence store's confirmation, oldest first.

        The reconciliation worker drains this. `quarantined` and `confirmed`
        rows are terminal and never returned — a quarantine is resolved by
        an operator, not a retry.
        """
        return await self._run_read(
            self._list_pending_firmware_confirmations_sync, limit
        )

    def _list_pending_firmware_confirmations_sync(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT device_id, anchor_epoch_id, attempt_count, created_at_ms,
                   last_attempt_ms
              FROM firmware_confirmation_outbox
             WHERE status = 'confirmation_pending'
             ORDER BY created_at_ms ASC, device_id ASC
             LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
        return [dict(r) for r in rows]

    async def record_firmware_confirmation_attempt(
        self, device_id: str, anchor_epoch_id: str, at_ms: int
    ) -> None:
        """Bump the attempt counter for a still-pending obligation.

        Recorded even when the attempt did not resolve (evidence store unreachable),
        so a stuck grant is visibly being worked rather than silently idle.
        """
        await self._run_write(
            self._record_firmware_confirmation_attempt_sync,
            device_id,
            anchor_epoch_id,
            at_ms,
        )

    def _record_firmware_confirmation_attempt_sync(
        self, device_id: str, anchor_epoch_id: str, at_ms: int
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE firmware_confirmation_outbox
               SET attempt_count = attempt_count + 1, last_attempt_ms = ?
             WHERE device_id = ? AND anchor_epoch_id = ?
               AND status = 'confirmation_pending'
            """,
            (at_ms, device_id, anchor_epoch_id),
        )
        self._conn.commit()

    async def resolve_firmware_confirmation(
        self, device_id: str, anchor_epoch_id: str, *, status: str, at_ms: int
    ) -> None:
        """Move an obligation to a terminal state: ``confirmed`` or
        ``quarantined``.

        Only a `confirmation_pending` row is resolved, so a late or
        duplicate attempt cannot move a `quarantined` grant to `confirmed`
        or re-resolve one — the reconciliation is idempotent.
        """
        if status not in ("confirmed", "quarantined"):
            raise ValueError(f"invalid confirmation resolution: {status!r}")
        await self._run_write(
            self._resolve_firmware_confirmation_sync,
            device_id,
            anchor_epoch_id,
            status,
            at_ms,
        )

    def _resolve_firmware_confirmation_sync(
        self, device_id: str, anchor_epoch_id: str, status: str, at_ms: int
    ) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            UPDATE firmware_confirmation_outbox
               SET status = ?, resolved_at_ms = ?,
                   attempt_count = attempt_count + 1, last_attempt_ms = ?
             WHERE device_id = ? AND anchor_epoch_id = ?
               AND status = 'confirmation_pending'
            """,
            (status, at_ms, at_ms, device_id, anchor_epoch_id),
        )
        self._conn.commit()

    async def get_firmware_confirmation_summary(self, now_ms_value: int) -> dict:
        """Counts and oldest-pending age for the health snapshot.

        `oldest_pending_age_ms` is derived from the receiver-recorded
        `created_at_ms`, so a stuck grant's age is measured from when this
        store recorded the obligation, not any device-reported time.
        """
        return await self._run_read(
            self._get_firmware_confirmation_summary_sync, now_ms_value
        )

    def _get_firmware_confirmation_summary_sync(
        self, conn: sqlite3.Connection, now_ms_value: int
    ) -> dict:
        row = conn.execute(
            """
            SELECT
              SUM(CASE WHEN status = 'confirmation_pending' THEN 1 ELSE 0 END),
              SUM(CASE WHEN status = 'quarantined' THEN 1 ELSE 0 END),
              MIN(CASE WHEN status = 'confirmation_pending'
                       THEN created_at_ms END)
            FROM firmware_confirmation_outbox
            """,
        ).fetchone()
        pending = int(row[0] or 0)
        quarantined = int(row[1] or 0)
        oldest_created = row[2]
        return {
            "confirmation_pending_count": pending,
            "quarantined_count": quarantined,
            "oldest_pending_age_ms": (
                max(0, now_ms_value - int(oldest_created))
                if oldest_created is not None
                else None
            ),
        }

    async def list_firmware_anchor_transitions(self, device_id: str) -> list[dict]:
        """The audited trust transitions for an identity, oldest first."""
        return await self._run_read(
            self._list_firmware_anchor_transitions_sync, device_id
        )

    async def firmware_active_promotion_attribution(
        self, device_id: str
    ) -> dict | None:
        """The actor and reason of the promotion that made the CURRENT
        active anchor active.

        This is the provenance the coordinating evidence store must
        record when it mirrors the approval: the same operator decision,
        not a fresh or generic one. It is resolved precisely -- the latest
        ``promoted`` transition whose ``to_epoch_id`` is the registry's
        currently active ``anchor_epoch_id`` -- so a later re-provisioning
        or an unrelated promotion cannot be mistaken for it.

        ``None`` if the device is unknown, not approved, or has no such
        promotion (e.g. a legacy row whose activation was inferred by the
        migration -- that attribution is ``migration``, which is returned
        as recorded rather than hidden).
        """
        return await self._run_read(
            self._firmware_active_promotion_attribution_sync, device_id
        )

    def _firmware_active_promotion_attribution_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT t.actor, t.reason, t.occurred_at_ms, t.to_epoch_id
              FROM firmware_anchor_transitions t
              JOIN firmware_device_registry r
                ON r.device_id = t.device_id
               AND r.anchor_epoch_id = t.to_epoch_id
             WHERE t.device_id = ?
               AND t.transition = 'promoted'
               AND r.approved = 1
               AND r.revoked = 0
             -- The transition id is this store's append order: the
             -- receiver-anchored ordering. occurred_at_ms is a recorded
             -- wall-clock that can regress or collide, so it must not
             -- decide which promotion is latest.
             ORDER BY t.id DESC
             LIMIT 1
            """,
            (device_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    def _list_firmware_anchor_transitions_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT * FROM firmware_anchor_transitions
             WHERE device_id = ?
             ORDER BY occurred_at_ms ASC, id ASC
            """,
            (device_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    async def firmware_anchor_activation_intervals(
        self, device_id: str, anchor_epoch_id: str
    ) -> list[dict]:
        """Every interval during which an anchor epoch was active.

        ori-specs/device-provisioning/v1.md requires implementations to be
        able to determine, for any anchor epoch, whether it was ever
        active and over which intervals.

        The anchor's ``state`` column cannot answer this. An anchor that
        was active, was superseded, and has since been re-registered
        reads ``pending`` today, because an anchor epoch has exactly one
        record whose state is its *current* state. Evidence produced
        while it was active is still legitimately attributed to it, so a
        consumer reading only the current state would treat correctly
        signed history as never having been authorised.

        The transition log is the append-only record, and this derives
        the intervals from it rather than storing them, so there is one
        source of truth.

        Ordering is receiver-anchored: ``seq`` is the log's own append
        order and ``at_ms`` is assigned by this store when the transition
        is recorded. Device wall-clock time is never consulted — a device
        supplying its own timestamps could otherwise place its evidence
        inside an interval when its anchor was active, which is the very
        question being decided.

        An interval with ``deactivated_seq`` of ``None`` is still open:
        the anchor is active now.
        """
        return await self._run_read(
            self._firmware_anchor_activation_intervals_sync,
            device_id,
            anchor_epoch_id,
        )

    def _firmware_anchor_activation_intervals_sync(
        self, conn: sqlite3.Connection, device_id: str, anchor_epoch_id: str
    ) -> list[dict]:
        rows = conn.execute(
            """
            SELECT id, transition, from_epoch_id, to_epoch_id, occurred_at_ms
              FROM firmware_anchor_transitions
             WHERE device_id = ?
             ORDER BY id ASC
            """,
            (device_id,),
        ).fetchall()

        intervals: list[dict] = []
        open_interval: dict | None = None

        for r in rows:
            # Promotion is the only thing that makes an anchor active, so
            # it is the only thing that opens an interval.
            if r["transition"] == "promoted" and r["to_epoch_id"] == anchor_epoch_id:
                if open_interval is None:
                    open_interval = {
                        "activated_seq": int(r["id"]),
                        "activated_at_ms": int(r["occurred_at_ms"]),
                        "deactivated_seq": None,
                        "deactivated_at_ms": None,
                    }
                    intervals.append(open_interval)
                continue

            # Two things end an interval: another anchor being promoted
            # over this one, and the identity being revoked.
            #
            # `reprovisioned` deliberately does NOT, even though it also
            # carries this anchor in from_epoch_id: re-provisioning stores
            # the new key as PENDING and leaves the current anchor active
            # until it is promoted. Treating it as a deactivation would
            # report a gap in which the device was in fact still trusted.
            ends = r["transition"] in ("promoted", "revoked")
            if ends and r["from_epoch_id"] == anchor_epoch_id:
                if open_interval is not None:
                    open_interval["deactivated_seq"] = int(r["id"])
                    open_interval["deactivated_at_ms"] = int(r["occurred_at_ms"])
                    open_interval = None

        return intervals

    async def firmware_anchor_was_active_at(
        self, device_id: str, anchor_epoch_id: str, *, at_ms: int
    ) -> bool:
        """Whether this anchor was *known* active at a receiver-anchored
        instant.

        ``at_ms`` MUST be a time this receiver assigned — its record of
        when evidence arrived, or a position derived from the evidence
        store's chain. It must never be a device-reported timestamp: a device
        choosing its own would place its evidence inside an interval when
        its anchor was active, which is the question being decided.

        Returns ``False`` outside every known interval. For a migrated
        identity that means anything before the migration boundary is
        refused, because when its approval originally happened was never
        recorded — see ``firmware_activation_history_is_provable``.
        """
        intervals = await self.firmware_anchor_activation_intervals(
            device_id, anchor_epoch_id
        )
        for iv in intervals:
            if at_ms < iv["activated_at_ms"]:
                continue
            if iv["deactivated_at_ms"] is None or at_ms < iv["deactivated_at_ms"]:
                return True
        return False

    async def firmware_activation_history_is_provable(self, device_id: str) -> bool:
        """Whether this identity's activation history can be trusted as
        complete.

        ``False`` for an identity migrated from a pre-lifecycle database
        while revoked. Revocation sets ``approved = 0``, so such a row is
        identical whether it was revoked after being promoted or before
        ever being promoted, and the migration refuses to guess.

        Also ``False`` for an identity this store has never heard of.
        Absence of a marker is not evidence of a complete history when
        there is no history at all, and a caller asking about an unknown
        device must not be told its records are trustworthy.

        Callers deciding historical authorisation MUST treat ``False`` as
        "unknown", not as "never active", and fail closed. An empty
        interval list means *provably never promoted* only when this
        returns ``True``.
        """
        return await self._run_read(
            self._firmware_activation_history_is_provable_sync, device_id
        )

    def _firmware_activation_history_is_provable_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> bool:
        known = conn.execute(
            "SELECT 1 FROM firmware_device_registry WHERE device_id = ? LIMIT 1",
            (device_id,),
        ).fetchone()
        if known is None:
            return False

        row = conn.execute(
            """
            SELECT 1 FROM firmware_anchor_transitions
             WHERE device_id = ? AND actor = 'migration' AND reason IN (?, ?, ?)
             LIMIT 1
            """,
            (
                device_id,
                _MIGRATION_ACTIVATION_UNPROVABLE,
                _MIGRATION_ACTIVATION_UNRECONSTRUCTABLE,
                _MIGRATION_ACTIVATION_START_UNKNOWN,
            ),
        ).fetchone()
        return row is None

    async def firmware_anchor_was_ever_active(
        self, device_id: str, anchor_epoch_id: str
    ) -> bool:
        """Whether this anchor epoch is *known* to have been active.

        Distinct from ``state == 'active'``, which is only true right
        now, and from ``state == 'superseded'``, which a re-registration
        clears. Evidence resolution needs this question, not that one.

        ``False`` means "no recorded activation", which is not the same
        as "never active" for an identity migrated while revoked — see
        ``firmware_activation_history_is_provable``.
        """
        intervals = await self.firmware_anchor_activation_intervals(
            device_id, anchor_epoch_id
        )
        return bool(intervals)

    async def get_firmware_device(self, device_id: str) -> dict | None:
        return await self._run_read(self._get_firmware_device_sync, device_id)

    async def list_firmware_device_manifests(self) -> list[tuple[str, Any]]:
        """Each unrevoked registered device with its accepted manifest, by device_id."""
        return await self._run_read(self._list_firmware_device_manifests_sync)

    def _list_firmware_device_manifests_sync(
        self, conn: sqlite3.Connection
    ) -> list[tuple[str, Any]]:
        rows = conn.execute(
            "SELECT device_id, manifest_json FROM firmware_device_registry "
            "WHERE revoked = 0 ORDER BY device_id"
        ).fetchall()
        return [(str(row[0]), json.loads(row[1])) for row in rows]

    def _get_firmware_device_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT device_id, public_key_b64, alg, posture, capability_hash,
                   manifest_json, channel_map_json, board_profile, approved,
                   provisioned_at_ms, last_boot_id, last_seq, last_provision_seq,
                   revoked, revoked_at_ms, anchor_epoch_id, key_epoch_id,
                   last_uptime_ms, last_uptime_mark,
                   (SELECT MAX(t.id) FROM firmware_anchor_transitions t
                     WHERE t.device_id = firmware_device_registry.device_id
                       AND t.transition = 'promoted')
            FROM firmware_device_registry WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "device_id": row[0],
            "public_key_b64": row[1],
            "alg": row[2],
            "posture": row[3],
            "capability_hash": row[4],
            "manifest": json.loads(row[5]),
            "channel_map": json.loads(row[6]),
            "channel_map_json": row[6],
            "board_profile": row[7],
            "approved": bool(row[8]),
            "provisioned_at_ms": int(row[9]),
            "last_boot_id": int(row[10]),
            "last_seq": int(row[11]),
            "last_provision_seq": int(row[12]),
            "revoked": bool(row[13]),
            "revoked_at_ms": int(row[14]) if row[14] is not None else None,
            "anchor_epoch_id": row[15],
            "key_epoch_id": row[16],
            # Only an uptime stored with the mark now recorded is comparable.
            "last_uptime_ms": (
                int(row[17])
                if row[17] is not None
                and row[18] == _uptime_mark(row[16], int(row[10]), int(row[11]))
                else None
            ),
            # Every promotion writes a new transition, including the promotion
            # of a reinstated anchor that is byte-for-byte the one revoked, so
            # this tells two activations of one anchor apart.
            "activation_id": int(row[19]) if row[19] is not None else None,
        }

    async def approve_firmware_device(
        self,
        device_id: str,
        *,
        actor: str,
        reason: str,
        occurred_at_ms: int | None = None,
        expected_anchor_epoch_id: str | None = None,
    ) -> bool:
        """Promote the pending anchor to active (ori-specs
        device-provisioning/v1.md). Promotion is the only path to active.

        `actor` and `reason` are REQUIRED and recorded in the transition
        log. Promotion is a trust transition; an unattributed one is
        indistinguishable from a compromise after the fact. With
        `expected_anchor_epoch_id`, only that pending candidate is promoted.
        """
        return await self._run_write(
            self._immediate,
            self._approve_firmware_device_sync,
            device_id,
            actor,
            reason,
            occurred_at_ms if occurred_at_ms is not None else now_ms(),
            expected_anchor_epoch_id,
        )

    def _approve_firmware_device_sync(
        self,
        device_id: str,
        actor: str,
        reason: str,
        occurred_at_ms: int,
        expected_anchor_epoch_id: str | None = None,
    ) -> bool:
        """Promotion: the ONLY path an anchor becomes active.

        Moves the pending candidate to `active`, the previously active
        anchor to `superseded`, and points the registry at the promoted
        anchor — all in one transaction, so the registry and the anchor
        history cannot disagree about which anchor is trusted.
        """
        assert self._conn is not None
        _require_attribution("promotion", actor, reason)
        registry = self._conn.execute(
            "SELECT revoked, anchor_epoch_id, key_epoch_id "
            "FROM firmware_device_registry "
            "WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if registry is None or registry["revoked"]:
            return False

        pending = self._conn.execute(
            "SELECT * FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'pending'",
            (device_id,),
        ).fetchone()
        if pending is None:
            # Nothing to promote. An already-active anchor is not
            # re-promoted, and inventing one here would be the implicit
            # transition this model exists to remove.
            return False
        if (
            expected_anchor_epoch_id is not None
            and pending["anchor_epoch_id"] != expected_anchor_epoch_id
        ):
            # The candidate the caller checked was replaced before this
            # transaction; promoting its successor would skip that check.
            return False

        # A quarantined epoch is a cross-store disagreement awaiting
        # explicit operator resolution. Re-approving it must NOT silently
        # clear the quarantine, so the promotion is refused here rather
        # than proceeding and re-opening the obligation below. Returning
        # nothing changes state: the operator must resolve the quarantine
        # first (ori-specs/device-provisioning/v1.md).
        quarantined = self._conn.execute(
            "SELECT 1 FROM firmware_confirmation_outbox "
            "WHERE device_id = ? AND anchor_epoch_id = ? AND status = 'quarantined'",
            (device_id, pending["anchor_epoch_id"]),
        ).fetchone()
        if quarantined is not None:
            return False

        previous = self._conn.execute(
            "SELECT anchor_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'active'",
            (device_id,),
        ).fetchone()
        if previous is not None:
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'superseded', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (occurred_at_ms, previous["anchor_epoch_id"]),
            )

        self._conn.execute(
            "UPDATE firmware_device_anchors SET state = 'active', "
            "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
            (occurred_at_ms, pending["anchor_epoch_id"]),
        )

        # Telemetry replay state is scoped to the KEY epoch. Promoting
        # within one key epoch must not re-open a closed replay window, so
        # freshness is preserved. Promoting a NEW key epoch — only
        # reachable through re-provisioning — starts a fresh window,
        # because a re-keyed device restarts its counters and would
        # otherwise be refused as a replay against its predecessor's
        # high-water mark. The old epoch's counters remain historical and
        # unusable, since they belong to a key no longer active.
        #
        # last_cmd_seq is deliberately NOT reset: the command mark is per
        # device, not per key, and must continue across rotation
        # (ori-specs/firmware-commands/v1.md).
        key_epoch_changed = pending["key_epoch_id"] != registry["key_epoch_id"]
        self._conn.execute(
            """
            UPDATE firmware_device_registry
               SET approved = 1,
                   public_key_b64 = ?,
                   posture = ?,
                   capability_hash = ?,
                   manifest_json = ?,
                   channel_map_json = ?,
                   board_profile = ?,
                   anchor_epoch_id = ?,
                   key_epoch_id = ?,
                   last_boot_id = CASE WHEN ? THEN 0 ELSE last_boot_id END,
                   last_seq = CASE WHEN ? THEN 0 ELSE last_seq END,
                   last_uptime_ms = CASE WHEN ? THEN NULL ELSE last_uptime_ms END,
                   last_uptime_mark =
                       CASE WHEN ? THEN NULL ELSE last_uptime_mark END
             WHERE device_id = ? AND revoked = 0
            """,
            (
                pending["public_key_b64"],
                pending["posture"],
                pending["capability_hash"],
                pending["manifest_json"],
                pending["channel_map_json"],
                pending["board_profile"],
                pending["anchor_epoch_id"],
                pending["key_epoch_id"],
                1 if key_epoch_changed else 0,
                1 if key_epoch_changed else 0,
                1 if key_epoch_changed else 0,
                1 if key_epoch_changed else 0,
                device_id,
            ),
        )
        self._conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'promoted', ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                previous["anchor_epoch_id"] if previous is not None else None,
                pending["anchor_epoch_id"],
                pending["key_epoch_id"],
                actor,
                reason,
                occurred_at_ms,
            ),
        )
        # Record the cross-store confirmation obligation in the SAME
        # transaction as the promotion, so a crash cannot leave an anchor
        # active locally with no record that the evidence store must still confirm it.
        #
        # A promotion always re-opens confirmation, even for an epoch this
        # identity held before. The only way the same epoch is promoted
        # twice is revoke -> reinstate -> approve, and by then the earlier
        # revocation may have propagated to the evidence store, so the grant genuinely
        # needs re-confirming. The row is reused (the transition log, not
        # this outbox, is the history), with a fresh age and attempt count.
        self._conn.execute(
            """
            INSERT INTO firmware_confirmation_outbox
                (device_id, anchor_epoch_id, status, created_at_ms)
            VALUES (?, ?, 'confirmation_pending', ?)
            ON CONFLICT(device_id, anchor_epoch_id) DO UPDATE SET
                status = 'confirmation_pending',
                attempt_count = 0,
                created_at_ms = excluded.created_at_ms,
                last_attempt_ms = NULL,
                resolved_at_ms = NULL
              WHERE firmware_confirmation_outbox.status != 'quarantined'
            """,
            (device_id, pending["anchor_epoch_id"], occurred_at_ms),
        )
        self._conn.commit()
        return True

    async def revoke_firmware_device(
        self,
        device_id: str,
        *,
        revoked_at_ms: int | None = None,
        actor: str,
        reason: str,
    ) -> bool:
        """Take an identity out of service: the active anchor is retained
        as `revoked`, any pending candidate is discarded, and the
        transition is recorded."""
        return await self._run_write(
            self._immediate,
            self._revoke_firmware_device_sync,
            device_id,
            revoked_at_ms if revoked_at_ms is not None else now_ms(),
            actor,
            reason,
        )

    def _revoke_firmware_device_sync(
        self, device_id: str, revoked_at_ms: int, actor: str, reason: str
    ) -> bool:
        """Takes an identity out of service, in one transaction.

        The active anchor is retained as `revoked` so reinstatement has
        something to return to, and any pending candidate is discarded —
        an unpromoted candidate must not survive a revocation and become
        promotable later.
        """
        assert self._conn is not None
        _require_attribution("revocation", actor, reason)
        cur = self._conn.execute(
            """
            UPDATE firmware_device_registry
            SET revoked = 1, approved = 0, revoked_at_ms = ?
            WHERE device_id = ?
            """,
            (revoked_at_ms, device_id),
        )
        if cur.rowcount == 0:
            return False

        active = self._conn.execute(
            "SELECT anchor_epoch_id, key_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'active'",
            (device_id,),
        ).fetchone()
        if active is not None:
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'revoked', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (revoked_at_ms, active["anchor_epoch_id"]),
            )
        pending = self._conn.execute(
            "SELECT anchor_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'pending'",
            (device_id,),
        ).fetchone()
        if pending is not None:
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'discarded', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (revoked_at_ms, pending["anchor_epoch_id"]),
            )
        self._conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'revoked', ?, NULL, ?, ?, ?, ?)
            """,
            (
                device_id,
                active["anchor_epoch_id"] if active is not None else None,
                active["key_epoch_id"] if active is not None else "",
                actor,
                reason,
                revoked_at_ms,
            ),
        )
        self._conn.commit()
        return True

    async def reinstate_firmware_device(
        self,
        device_id: str,
        *,
        actor: str,
        reason: str,
        occurred_at_ms: int | None = None,
    ) -> bool:
        """Return a revoked identity to service.

        Clears the identity's revoked flag and moves the retained
        ``revoked`` anchor back to **pending** — never to active.
        Promotion remains the only path to active, so the operator's next
        act is an explicit, separately audited promotion.
        """
        return await self._run_write(
            self._immediate,
            self._reinstate_firmware_device_sync,
            device_id,
            actor,
            reason,
            occurred_at_ms if occurred_at_ms is not None else now_ms(),
        )

    def _reinstate_firmware_device_sync(
        self, device_id: str, actor: str, reason: str, occurred_at_ms: int
    ) -> bool:
        assert self._conn is not None
        _require_attribution("reinstatement", actor, reason)
        row = self._conn.execute(
            "SELECT revoked FROM firmware_device_registry WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if row is None or not row["revoked"]:
            # Nothing to reinstate. Clearing a flag that is not set would
            # write an audit row describing an event that did not happen.
            return False

        retained = self._conn.execute(
            "SELECT anchor_epoch_id, key_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'revoked'",
            (device_id,),
        ).fetchone()

        self._conn.execute(
            """
            UPDATE firmware_device_registry
               SET revoked = 0, revoked_at_ms = NULL, approved = 0
             WHERE device_id = ?
            """,
            (device_id,),
        )
        to_epoch = None
        key_epoch = ""
        if retained is not None:
            # Back to pending, not active: promotion is a separate act.
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'pending', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (occurred_at_ms, retained["anchor_epoch_id"]),
            )
            to_epoch = retained["anchor_epoch_id"]
            key_epoch = retained["key_epoch_id"]
        self._conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'reinstated', ?, ?, ?, ?, ?, ?)
            """,
            (device_id, to_epoch, to_epoch, key_epoch, actor, reason, occurred_at_ms),
        )
        self._conn.commit()
        return True

    async def reprovision_firmware_device(
        self,
        *,
        device_id: str,
        public_key_b64: str,
        posture: str,
        capability_hash: str,
        manifest_json: str,
        channel_map_json: str,
        board_profile: str = "",
        actor: str,
        reason: str,
        occurred_at_ms: int | None = None,
    ) -> str:
        """Replace an identity's key: an explicit, audited transaction.

        Ordinary registration refuses a changed key, because a self-signed
        manifest proves consistency and never provenance. This is the path
        that accepts one, and it exists so that acceptance is a deliberate
        operator act with independent identity confirmation behind it.

        The new-key anchor is stored **pending**; the previously active
        anchor stays active until promotion. Historical anchors are
        retained, and the command sequence is untouched — it is per device,
        not per key, so rotation must not reset it.

        Returns ``reprovisioned``, or a refusal: ``unknown_device``,
        ``revoked``, ``refused_same_key`` (the submitted key is the
        current one, so nothing is being replaced), or
        ``refused_key_reuse`` (this identity has used that key before).
        """
        return await self._run_write(
            self._immediate,
            self._reprovision_firmware_device_sync,
            device_id,
            public_key_b64,
            posture,
            capability_hash,
            manifest_json,
            channel_map_json,
            board_profile,
            actor,
            reason,
            occurred_at_ms if occurred_at_ms is not None else now_ms(),
        )

    def _reprovision_firmware_device_sync(  # noqa: PLR0913
        self,
        device_id: str,
        public_key_b64: str,
        posture: str,
        capability_hash: str,
        manifest_json: str,
        channel_map_json: str,
        board_profile: str,
        actor: str,
        reason: str,
        occurred_at_ms: int,
    ) -> str:
        assert self._conn is not None
        _require_attribution("re-provisioning", actor, reason)
        from ori.security.firmware.telemetry import (
            anchor_epoch_id as _anchor_epoch_id,
        )
        from ori.security.firmware.telemetry import (
            key_epoch_id as _key_epoch_id,
        )

        row = self._conn.execute(
            "SELECT revoked, anchor_epoch_id FROM firmware_device_registry "
            "WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if row is None:
            return "unknown_device"
        if row["revoked"]:
            # Reinstate first: re-provisioning a revoked identity would
            # return it to service without ever saying so.
            return "revoked"

        kid = _key_epoch_id(device_id=device_id, public_key_b64=public_key_b64)
        aid = _anchor_epoch_id(
            device_id=device_id,
            public_key_b64=public_key_b64,
            posture=posture,
            capability_hash=capability_hash,
        )

        # Re-provisioning means REPLACING the key. Submitting the current
        # key is not a key change: with INSERT OR REPLACE it would have
        # overwritten the active anchor row with a pending one while the
        # registry still said approved — a split-brain, and a violation of
        # append-only history.
        # Keys are compared by identity, not encoding: a key's negation is
        # signed by the same scalar's holder, so it is the same key here.
        submitted = _firmware_key_identity(public_key_b64)
        if submitted is None:
            raise ValueError("re-provisioning needs a decoded 32-byte public key")
        current_key = self._conn.execute(
            "SELECT key_epoch_id, public_key_b64 FROM firmware_device_registry "
            "WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if current_key is not None and (
            current_key["key_epoch_id"] == kid
            or _firmware_key_identity(current_key["public_key_b64"]) == submitted
        ):
            return "refused_same_key"

        # Nor may a key this identity has used before come back. An old key
        # may be exactly the one that was rotated away from because it was
        # compromised; allowing its return would make rotation reversible
        # by whoever holds it.
        used = self._conn.execute(
            "SELECT key_epoch_id, public_key_b64 FROM firmware_device_anchors "
            "WHERE device_id = ?",
            (device_id,),
        ).fetchall()
        if any(
            row["key_epoch_id"] == kid
            or _firmware_key_identity(row["public_key_b64"]) == submitted
            for row in used
        ):
            return "refused_key_reuse"

        # Any existing candidate is superseded by this one.
        existing = self._conn.execute(
            "SELECT anchor_epoch_id FROM firmware_device_anchors "
            "WHERE device_id = ? AND state = 'pending'",
            (device_id,),
        ).fetchone()
        if existing is not None and existing["anchor_epoch_id"] != aid:
            self._conn.execute(
                "UPDATE firmware_device_anchors SET state = 'discarded', "
                "state_changed_at_ms = ? WHERE anchor_epoch_id = ?",
                (occurred_at_ms, existing["anchor_epoch_id"]),
            )

        self._conn.execute(
            """
            INSERT INTO firmware_device_anchors
                (anchor_epoch_id, device_id, key_epoch_id, public_key_b64,
                 posture, capability_hash, manifest_json, channel_map_json,
                 board_profile, state, created_at_ms, state_changed_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                aid,
                device_id,
                kid,
                public_key_b64,
                posture,
                capability_hash,
                manifest_json,
                channel_map_json,
                board_profile,
                occurred_at_ms,
                occurred_at_ms,
            ),
        )
        self._conn.execute(
            """
            INSERT INTO firmware_anchor_transitions
                (device_id, transition, from_epoch_id, to_epoch_id,
                 key_epoch_id, actor, reason, occurred_at_ms)
            VALUES (?, 'reprovisioned', ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                row["anchor_epoch_id"] or None,
                aid,
                kid,
                actor,
                reason,
                occurred_at_ms,
            ),
        )
        self._conn.commit()
        return "reprovisioned"

    async def allocate_firmware_runtime_seq(
        self, device_id: str, *, capability_hash: str
    ) -> int:
        """Allocate the next strictly increasing runtime-liveness sequence
        for a device (firmware-commands/v1 runtime liveness).

        Durability here is load-bearing, and for a different reason than
        ``cmd_seq``. A device holds the last accepted value for its CURRENT
        boot, so a runtime that restarted with an in-memory counter would
        have every subsequent message rejected and could not recover while
        that device stayed booted — the device would report a healthy
        runtime unreachable and keep doing so. Recovery would need a device
        reboot, which is not something a runtime restart may require.

        The allocation lands only while the identity is unrevoked, approved
        and confirmed at the `capability_hash` the liveness message names. A
        confirmed epoch stays confirmed through an evidence-store outage; a
        re-promoted or quarantined one is a grant awaiting confirmation.

        Raises KeyError for unknown devices, ValueError when the counter is
        exhausted, and PermissionError when that authority no longer holds.
        """
        if not isinstance(capability_hash, str) or not capability_hash:
            raise ValueError("capability_hash must name the supervised manifest")
        return await self._run_write(
            self._allocate_firmware_runtime_seq_sync, device_id, capability_hash
        )

    def _allocate_firmware_runtime_seq_sync(
        self, device_id: str, capability_hash: str
    ) -> int:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            UPDATE firmware_device_registry
               SET last_runtime_seq = last_runtime_seq + 1
             WHERE device_id = ?
               AND last_runtime_seq < 9007199254740991
               AND capability_hash = ?
            """
            + _FIRMWARE_AUTHORITY_SQL,
            (device_id, capability_hash),
        )
        if cur.rowcount != 1:
            # The UPDATE misses for three reasons and they are not the same
            # failure: an unknown device is a caller error, an exhausted
            # counter is the end of the sequence space, and anything else is
            # authority this runtime no longer holds.
            current = self._conn.execute(
                "SELECT last_runtime_seq FROM firmware_device_registry "
                "WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            self._conn.rollback()
            if current is None:
                raise KeyError(f"unknown firmware device: {device_id!r}")
            if int(current[0]) >= 9007199254740991:
                raise ValueError(
                    f"runtime_seq exhausted for {device_id!r}; "
                    "the device cannot accept a higher value in this boot"
                )
            raise PermissionError(
                "firmware liveness authority changed before allocation"
            )
        row = self._conn.execute(
            "SELECT last_runtime_seq FROM firmware_device_registry WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        assert row is not None
        # Commit before returning. _run_write provides locking and thread
        # dispatch, not a transaction boundary. Without this the allocation
        # is only in the connection's open transaction: a process restart
        # rolls it back, the device then rejects every message from the
        # restarted runtime for the rest of its current boot, and whether
        # it survives at all depends on some unrelated later write
        # happening to commit it.
        self._conn.commit()
        return int(row[0])

    async def allocate_firmware_command_seq(
        self, device_id: str, *, verified_against: dict[str, Any]
    ) -> int:
        """Allocate the next strictly increasing command sequence for a
        provisioned device (firmware-commands contract: one strictly
        increasing cmd_seq per device, continuing across command-key
        rotation and never reused; under firmware-commands/v2 a command
        is never reissued automatically).

        The allocation is the command's authority commit: it lands only
        while the identity is unrevoked, approved and confirmed at the
        anchor, `verified_against`, the command was built from. Raises
        KeyError for unknown devices, OverflowError when the counter is
        exhausted, and PermissionError when that
        authority no longer holds."""
        return await self._run_write(
            self._allocate_firmware_command_seq_sync,
            device_id,
            _firmware_anchor_values(verified_against),
        )

    def _allocate_firmware_command_seq_sync(
        self, device_id: str, anchor: tuple[str, ...]
    ) -> int:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            UPDATE firmware_device_registry
            SET last_cmd_seq = last_cmd_seq + 1
            WHERE device_id = ?
              AND last_cmd_seq < 9007199254740991
            """
            + _firmware_anchor_sql()
            + _FIRMWARE_AUTHORITY_SQL,
            (device_id, *anchor),
        )
        if cur.rowcount != 1:
            known = self._conn.execute(
                "SELECT last_cmd_seq FROM firmware_device_registry WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            self._conn.rollback()
            if known is None:
                raise KeyError(f"unknown firmware device: {device_id!r}")
            if int(known[0]) >= 9007199254740991:
                raise OverflowError(f"cmd_seq exhausted for {device_id!r}")
            raise PermissionError(
                "firmware command authority changed before allocation"
            )
        row = self._conn.execute(
            "SELECT last_cmd_seq FROM firmware_device_registry WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        self._conn.commit()
        return int(row[0])

    async def firmware_command_authority_holds(
        self, device_id: str, *, verified_against: dict[str, Any]
    ) -> bool:
        """Whether the identity is still unrevoked, approved and confirmed
        at the anchor `verified_against`, in one read."""
        return await self._run_read(
            self._firmware_command_authority_holds_sync,
            device_id,
            _firmware_anchor_values(verified_against),
        )

    def _firmware_command_authority_holds_sync(
        self, conn: sqlite3.Connection, device_id: str, anchor: tuple[str, ...]
    ) -> bool:
        row = conn.execute(
            "SELECT 1 FROM firmware_device_registry WHERE device_id = ?"
            + _firmware_anchor_sql()
            + _FIRMWARE_AUTHORITY_SQL,
            (device_id, *anchor),
        ).fetchone()
        return row is not None

    async def allocate_firmware_provision_seq(
        self,
        device_id: str,
        *,
        expected_anchor_epoch_id: str,
        allow_revoked: bool,
    ) -> int:
        """Allocate the independent firmware transport-provisioning sequence.

        The counter belongs to the stable device identity and is never reset by
        anchor, command-key, certificate, or revocation transitions.
        """
        return await self._run_write(
            self._allocate_firmware_provision_seq_sync,
            device_id,
            expected_anchor_epoch_id,
            allow_revoked,
        )

    def _allocate_firmware_provision_seq_sync(
        self,
        device_id: str,
        expected_anchor_epoch_id: str,
        allow_revoked: bool,
    ) -> int:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            UPDATE firmware_device_registry
               SET last_provision_seq = last_provision_seq + 1
             WHERE device_id = ?
               AND anchor_epoch_id = ?
               AND last_provision_seq < 9007199254740991
               AND (
                    (? = 1 AND revoked = 1)
                    OR
                    (revoked = 0 AND approved = 1 AND EXISTS (
                        SELECT 1 FROM firmware_confirmation_outbox c
                         WHERE c.device_id = firmware_device_registry.device_id
                           AND c.anchor_epoch_id =
                               firmware_device_registry.anchor_epoch_id
                           AND c.status = 'confirmed'
                    ))
               )
            """,
            (device_id, expected_anchor_epoch_id, int(allow_revoked)),
        )
        if cur.rowcount != 1:
            row = self._conn.execute(
                "SELECT last_provision_seq FROM firmware_device_registry "
                "WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            self._conn.rollback()
            if row is None:
                raise KeyError(f"unknown firmware device: {device_id!r}")
            if int(row[0]) < 9007199254740991:
                raise PermissionError(
                    "firmware provisioning authority changed before allocation"
                )
            raise OverflowError("firmware provision_seq exhausted")
        row = self._conn.execute(
            "SELECT last_provision_seq FROM firmware_device_registry "
            "WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        self._conn.commit()
        return int(row[0])

    async def append_firmware_mqtt_provisioning_audit(
        self,
        *,
        device_id: str,
        event_kind: str,
        operation_kind: str,
        provision_seq: int | None,
        request_id: str,
        anchor_epoch_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        verdict: str,
        certificate_sha256: str,
        broker_uri: str,
        payload_sha256: str,
        occurred_at_ms: int,
    ) -> int:
        """Append one immutable provisioning request or verified response."""
        return await self._run_write(
            self._append_firmware_mqtt_provisioning_audit_sync,
            device_id,
            event_kind,
            operation_kind,
            provision_seq,
            request_id,
            anchor_epoch_id,
            actor,
            reason,
            request_sha256,
            verdict,
            certificate_sha256,
            broker_uri,
            payload_sha256,
            occurred_at_ms,
        )

    def _append_firmware_mqtt_provisioning_audit_sync(
        self,
        device_id: str,
        event_kind: str,
        operation_kind: str,
        provision_seq: int | None,
        request_id: str,
        anchor_epoch_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        verdict: str,
        certificate_sha256: str,
        broker_uri: str,
        payload_sha256: str,
        occurred_at_ms: int,
    ) -> int:
        assert self._conn is not None
        cur = self._conn.execute(
            """
            INSERT INTO firmware_mqtt_provisioning_audit
                (device_id, event_kind, operation_kind, provision_seq,
                 request_id, anchor_epoch_id, actor, reason, request_sha256,
                 verdict, certificate_sha256, broker_uri, payload_sha256,
                 occurred_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                event_kind,
                operation_kind,
                provision_seq,
                request_id,
                anchor_epoch_id,
                actor,
                reason,
                request_sha256,
                verdict,
                certificate_sha256,
                broker_uri,
                payload_sha256,
                occurred_at_ms,
            ),
        )
        self._conn.commit()
        if cur.lastrowid is None:
            raise RuntimeError("firmware MQTT provisioning audit insert returned no id")
        return cur.lastrowid

    async def list_firmware_mqtt_provisioning_audit(self, device_id: str) -> list[dict]:
        """Return provisioning audit facts in receiver append order."""
        return await self._run_read(
            self._list_firmware_mqtt_provisioning_audit_sync, device_id
        )

    def _list_firmware_mqtt_provisioning_audit_sync(
        self, conn: sqlite3.Connection, device_id: str
    ) -> list[dict]:
        rows = conn.execute(
            "SELECT * FROM firmware_mqtt_provisioning_audit "
            "WHERE device_id = ? ORDER BY id ASC",
            (device_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    async def save_firmware_mqtt_operator_request(
        self,
        *,
        correlation_id: str,
        parent_correlation_id: str,
        operation_kind: str,
        message: bytes,
        request: bytes,
        device_id: str,
        anchor_epoch_id: str,
        provision_seq: int | None,
        request_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        certificate_sha256: str,
        broker_uri: str,
        audit_id: int,
        certificate_serial: str,
        not_valid_before: str,
        not_valid_after: str,
        created_at_ms: int,
        completed_parent_correlation_id: str = "",
        parent_response_verdict: str = "",
        parent_response_payload_sha256: str = "",
        parent_completed_at_ms: int = 0,
    ) -> None:
        """Persist one immutable, public operator correlation record."""
        if completed_parent_correlation_id:
            if completed_parent_correlation_id != parent_correlation_id:
                raise ValueError(
                    "completed parent must match the request parent correlation"
                )
            if (
                not parent_response_verdict
                or not parent_response_payload_sha256
                or parent_completed_at_ms <= 0
            ):
                raise ValueError("completed parent response facts are required")
        await self._run_write(
            self._save_firmware_mqtt_operator_request_sync,
            correlation_id,
            parent_correlation_id,
            operation_kind,
            message,
            request,
            device_id,
            anchor_epoch_id,
            provision_seq,
            request_id,
            actor,
            reason,
            request_sha256,
            certificate_sha256,
            broker_uri,
            audit_id,
            certificate_serial,
            not_valid_before,
            not_valid_after,
            created_at_ms,
            completed_parent_correlation_id,
            parent_response_verdict,
            parent_response_payload_sha256,
            parent_completed_at_ms,
        )

    def _save_firmware_mqtt_operator_request_sync(
        self,
        correlation_id: str,
        parent_correlation_id: str,
        operation_kind: str,
        message: bytes,
        request: bytes,
        device_id: str,
        anchor_epoch_id: str,
        provision_seq: int | None,
        request_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        certificate_sha256: str,
        broker_uri: str,
        audit_id: int,
        certificate_serial: str,
        not_valid_before: str,
        not_valid_after: str,
        created_at_ms: int,
        completed_parent_correlation_id: str,
        parent_response_verdict: str,
        parent_response_payload_sha256: str,
        parent_completed_at_ms: int,
    ) -> None:
        assert self._conn is not None
        try:
            self._insert_firmware_mqtt_operator_request_on_conn(
                self._conn,
                correlation_id=correlation_id,
                parent_correlation_id=parent_correlation_id,
                operation_kind=operation_kind,
                message=message,
                request=request,
                device_id=device_id,
                anchor_epoch_id=anchor_epoch_id,
                provision_seq=provision_seq,
                request_id=request_id,
                actor=actor,
                reason=reason,
                request_sha256=request_sha256,
                certificate_sha256=certificate_sha256,
                broker_uri=broker_uri,
                audit_id=audit_id,
                certificate_serial=certificate_serial,
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                created_at_ms=created_at_ms,
            )
            if completed_parent_correlation_id:
                self._conn.execute(
                    """
                    INSERT INTO firmware_mqtt_operator_responses
                        (correlation_id, verdict, payload_sha256, completed_at_ms)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        completed_parent_correlation_id,
                        parent_response_verdict,
                        parent_response_payload_sha256,
                        parent_completed_at_ms,
                    ),
                )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def _insert_firmware_mqtt_operator_request_on_conn(
        self,
        conn: sqlite3.Connection,
        *,
        correlation_id: str,
        parent_correlation_id: str,
        operation_kind: str,
        message: bytes,
        request: bytes,
        device_id: str,
        anchor_epoch_id: str,
        provision_seq: int | None,
        request_id: str,
        actor: str,
        reason: str,
        request_sha256: str,
        certificate_sha256: str,
        broker_uri: str,
        audit_id: int,
        certificate_serial: str,
        not_valid_before: str,
        not_valid_after: str,
        created_at_ms: int,
    ) -> None:
        conn.execute(
            """
            INSERT INTO firmware_mqtt_operator_requests
                (correlation_id, parent_correlation_id, operation_kind,
                 message, request, device_id, anchor_epoch_id, provision_seq,
                 request_id, actor, reason, request_sha256,
                 certificate_sha256, broker_uri, audit_id,
                 certificate_serial, not_valid_before, not_valid_after,
                 created_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                correlation_id,
                parent_correlation_id,
                operation_kind,
                sqlite3.Binary(message),
                sqlite3.Binary(request),
                device_id,
                anchor_epoch_id,
                provision_seq,
                request_id,
                actor,
                reason,
                request_sha256,
                certificate_sha256,
                broker_uri,
                audit_id,
                certificate_serial,
                not_valid_before,
                not_valid_after,
                created_at_ms,
            ),
        )

    async def get_firmware_mqtt_operator_request(
        self, correlation_id: str
    ) -> dict | None:
        """Load a public request and its completion state."""
        return await self._run_read(
            self._get_firmware_mqtt_operator_request_sync,
            correlation_id,
        )

    def _get_firmware_mqtt_operator_request_sync(
        self,
        conn: sqlite3.Connection,
        correlation_id: str,
    ) -> dict | None:
        row = conn.execute(
            """
            SELECT r.*, p.verdict AS response_verdict,
                   p.payload_sha256 AS response_payload_sha256,
                   p.completed_at_ms
              FROM firmware_mqtt_operator_requests r
              LEFT JOIN firmware_mqtt_operator_responses p
                ON p.correlation_id = r.correlation_id
             WHERE r.correlation_id = ?
            """,
            (correlation_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    async def complete_firmware_mqtt_operator_request(
        self,
        *,
        correlation_id: str,
        verdict: str,
        payload_sha256: str,
        completed_at_ms: int,
    ) -> None:
        """Append the one terminal response fact for a correlation."""
        await self._run_write(
            self._complete_firmware_mqtt_operator_request_sync,
            correlation_id,
            verdict,
            payload_sha256,
            completed_at_ms,
        )

    def _complete_firmware_mqtt_operator_request_sync(
        self,
        correlation_id: str,
        verdict: str,
        payload_sha256: str,
        completed_at_ms: int,
    ) -> None:
        assert self._conn is not None
        try:
            self._conn.execute(
                """
                INSERT INTO firmware_mqtt_operator_responses
                    (correlation_id, verdict, payload_sha256, completed_at_ms)
                VALUES (?, ?, ?, ?)
                """,
                (correlation_id, verdict, payload_sha256, completed_at_ms),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    async def advance_firmware_freshness(
        self,
        device_id: str,
        *,
        boot_id: int,
        seq: int,
        uptime_ms: int,
        verified_against: dict[str, Any],
        fault_event: dict[str, Any] | None = None,
    ) -> bool:
        """Advance the replay high-water mark, strictly monotonically.

        The WHERE clause is the atomicity guarantee: a concurrent or
        replayed writer whose (boot_id, seq) does not strictly advance
        the stored mark, or whose uptime goes back within one boot,
        updates zero rows, and the caller must treat that as a replay.
        So does one whose anchor, `verified_against`, is no longer the
        registry's, including a byte-identical anchor promoted again since
        (its `activation_id`): the message must be verified again.

        A `fault_event` is recorded in the same transaction as the advance:
        the mark never moves past a fault that was not recorded, and a
        failure raises with neither written."""
        return await self._run_write(
            self._advance_firmware_freshness_sync,
            device_id,
            boot_id,
            seq,
            uptime_ms,
            _firmware_anchor_values(verified_against),
            _firmware_activation(verified_against),
            None if fault_event is None else _firmware_fault_values(fault_event),
        )

    def _advance_firmware_freshness_sync(
        self,
        device_id: str,
        boot_id: int,
        seq: int,
        uptime_ms: int,
        anchor: tuple[Any, ...],
        activation: int | None,
        fault: tuple[Any, ...] | None,
    ) -> bool:
        conn = self._conn
        if conn is None:
            raise sqlite3.ProgrammingError("the state store is not open")
        bound = _firmware_anchor_sql() + _FIRMWARE_ACTIVATION_SQL
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                """
                UPDATE firmware_device_registry
                SET last_boot_id = ?, last_seq = ?, last_uptime_ms = ?,
                    last_uptime_mark =
                        COALESCE(key_epoch_id, '') || ':' || ? || ':' || ?
                WHERE device_id = ? AND revoked = 0 AND approved = 1
                  AND ? >= last_boot_id AND ? > last_seq
                  AND (? > last_boot_id OR last_uptime_ms IS NULL
                       OR last_uptime_mark IS NOT
                          COALESCE(key_epoch_id, '') || ':' || last_boot_id
                          || ':' || last_seq
                       OR ? >= last_uptime_ms)
                """
                + bound,
                (
                    boot_id,
                    seq,
                    uptime_ms,
                    int(boot_id),
                    int(seq),
                    device_id,
                    boot_id,
                    seq,
                    boot_id,
                    uptime_ms,
                    *anchor,
                    activation,
                ),
            )
            if cur.rowcount == 0:
                conn.rollback()
                return False
            if fault is not None:
                # Plain INSERT: the mark is strictly monotonic within an epoch,
                # so a collision is a defect and must refuse the advance.
                conn.execute(
                    """
                    INSERT INTO firmware_fault_events
                        (device_id, key_epoch_id, boot_id, seq, grade, posture,
                         capability_hash, code, subject, detail, device_uptime_ms,
                         received_at_ms, fault_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (device_id, anchor[_ANCHOR_KEY_EPOCH], boot_id, seq, *fault),
                )
            conn.commit()
            return True
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
