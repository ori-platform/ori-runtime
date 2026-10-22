# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The Tier C approver registry, on the store's one writer connection."""

from typing import Any

from ori.security.approvers.registry import ApproverRegistry, Outcome
from ori.state._core import StoreCore

#: The registry's operations a caller may run, by name.
APPROVER_OPERATIONS = frozenset(
    {"issue", "recover", "local_seed", "enrol", "revoke", "binding", "phone_text"}
)


class ApproverStore(StoreCore):
    """Approver registry operations, serialised with every other store write."""

    async def run_approver_operation(
        self, registry: ApproverRegistry, operation: str, *args: Any
    ) -> Outcome:
        """Run one registry operation in one transaction on the writer."""
        if operation not in APPROVER_OPERATIONS:
            raise ValueError(f"no approver registry operation {operation!r}")
        return await self._run_write(self._run_approver_sync, registry, operation, args)

    def _run_approver_sync(
        self, registry: ApproverRegistry, operation: str, args: tuple[Any, ...]
    ) -> Outcome:
        assert self._conn is not None
        return registry.run(self._conn, getattr(registry, operation), *args)

    async def retire_approver_runs(self, run_id: str) -> None:
        """Delete every other run's challenges and phone state.

        Housekeeping only: every query is scoped to its run, so another run's
        rows are never read, retired or not.
        """
        await self._run_write(self._retire_approver_runs_sync, run_id)

    def _retire_approver_runs_sync(self, run_id: str) -> None:
        assert self._conn is not None
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            for table in (
                "approver_challenges",
                "approver_phone_authorizations",
                "approver_pending_phone",
                "approver_invalidated_phone",
            ):
                conn.execute(
                    f"DELETE FROM {table} WHERE run_id <> ?",  # noqa: S608 - fixed names
                    (run_id,),
                )
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
