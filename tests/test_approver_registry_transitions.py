# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""tier-c-approvers/v1 `vectors/transitions.json`, through the real registry.

The corpus is a state model: its IDs, keys and codes are symbolic. This module
translates each step into what the runtime receives -- a challenge request, a
presented challenge with real Ed25519 signatures, a revocation's wire bytes, a
text on the SMS ingress -- and runs it through `ApproverRegistry` against a
real state store. The translation owns no rule: every verdict is the engine's,
except two the runtime decides before the engine, at the socket.

- `local_request: false` is a caller the socket does not admit. The corpus
  calls it `local_auth_required`; the socket answers `unauthenticated` and
  the engine is never reached, so nothing changes.
- `contacts` is a recovery that names provisioning contacts. The socket's
  recover request has no member for them, so it is `invalid_arguments`.

Two places differ in where a check runs, not in what it decides:

- operator-socket/v3 refuses a candidate whose state conflicts (a duplicate or
  tombstoned value, a revoked approver, an initialized registry for recovery)
  when the challenge is requested; the model issues the challenge and refuses
  at presentation. A challenge the socket refused is answered, at the step
  that presents it, with a refusal from `DECIDED_AT_ISSUE`, and that step's
  model verdict must be a refusal from the same set.
- A runtime cannot attempt a phone commit with no reply. The model's
  `possession_required` is the pending operation's window lapsing, the one
  way a runtime's pending operation ends with no reply.
- A reply on a channel with no authenticated ingress never reaches the
  registry (`ingress_unauthenticated`, nothing changes): it cannot consume a
  pending operation, which would let anyone end an enrolment. The model,
  whose steps there are two-fault by construction, refuses it
  `possession_invalid`; for the runtime that pending operation, too, ends
  only when its window lapses.

This runtime accepts a provisioning document only at start, so a restart
step carrying `device_id` or `site_id` starts it under that identity. An
`apply_provisioning` step is what an in-run apply would be: the identity
changes and the run's state survives, and the registry is compared against
the identity now accepted. A restart removes every pending phone operation,
so a commit after one is `pending_unavailable` at the runtime where the
model, which keeps the operation, refuses it `device_binding_mismatch`,
`site_binding_mismatch` or `epoch_changed`. Either way no credential is added.
A recovery within a run is told exactly: `epoch_changed`.

A revocation's wire bytes reach the socket on one line, so the LFs in the
model's whitespace variants are sent as spaces, which JSON reads the same.

Scenarios that open or admit a Tier C proposal need the Tier C admission path
and are listed in `NEEDS_TIER_C_ADMISSION`; the list is held equal to exactly
those scenarios, so it can neither hide one nor go stale.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.security.approvers.forms import (
    ENROL_DOMAIN,
    PHONE_CHANNELS,
    POSSESSION_DOMAIN,
    b64,
    sha256_hex,
    signed_preimage,
)
from ori.security.approvers.registry import (
    Anchors,
    ApproverRegistry,
    RegistryRefusedError,
    RunContext,
    read_header,
)
from ori.security.approvers.requests import (
    SocketRequestError,
    frame,
    parse,
    validate_registry_request,
)
from ori.state.store import StateStore

CORPUS = json.loads(
    (
        Path(__file__).parent / "vectors" / "tier_c_approvers" / "transitions.json"
    ).read_text(encoding="utf-8")
)
SCENARIOS = {s["name"]: s for s in CORPUS["scenarios"]}
DEVICE = "edge-1"
SITE = "site-1"

NEEDS_TIER_C_ADMISSION = frozenset(
    {
        "empty_registry_admits_nobody",
        "local_console_requires_registered_human",
        "empty_registry_local_seed_requires_site_proofs",
        "recovery_can_seed_but_closes_old_proposals",
        "phone_candidate_late_reply_refused",
        "phone_authorizer_revoked_before_commit",
        "phone_recovery_before_commit",
        "one_pending_phone_per_candidate_value",
        "sms_ingress_unavailable",
        "whatsapp_candidate_refused_at_issue",
        "phone_registry_change_before_commit",
        "phone_site_change_before_commit",
        "phone_pending_expiry_releases_value",
        "enrol_and_admit",
        "enrolled_after_proposal_refused",
        "replacement_does_not_inherit_cutoff",
        "unknown_target_makes_revocation_atomic",
        "approver_revocation_removes_all_credentials",
        "signed_site_change_locks_admission",
        "revocation_before_admission",
        "admission_before_revocation_stands",
        "device_change_decides_over_site_change",
        "device_identity_change_locks_admission",
        "inrun_device_and_site_change_device_decides",
        "inrun_device_change_locks_admission",
        "inrun_site_change_locks_admission",
        "phone_device_change_before_commit",
        "recovery_binds_the_runtime_device",
        "recovery_binds_the_runtime_site",
    }
)


#: The Challenge-table refusals that concern the candidate's state.
DECIDED_AT_ISSUE = frozenset(
    {
        "recovery_not_available",
        "registry_unavailable",
        "active_authorizer_exists",
        "approver_revoked",
        "value_tombstoned",
        "duplicate_value",
        "credential_reused",
        "phone_pending_for_value",
    }
)
#: (the model's verdict at presentation, the socket's at issue): the same
#: refusal. One pair differs in name only: the model's symbolic candidate
#: reuses an existing credential's ID and value together, and the socket,
#: which never takes a credential ID from a request, refuses the value.
SAME_REFUSAL = frozenset(
    {(code, code) for code in DECIDED_AT_ISSUE}
    | {("credential_reused", "duplicate_value")}
)
#: The model's verdicts on a commit whose pending operation a restart had
#: already removed.
REMOVED_PENDING = frozenset(
    {"device_binding_mismatch", "site_binding_mismatch", "epoch_changed"}
)
NO_CODE = "Tm8gY29kZSB3YXMgc2VudA=="


def test_the_tier_c_list_is_exactly_the_scenarios_that_admit() -> None:
    admitting = {
        name
        for name, scenario in SCENARIOS.items()
        if any(step["op"] in ("open", "admit") for step in scenario["steps"])
    }
    assert admitting == NEEDS_TIER_C_ADMISSION
    assert CORPUS["contract"] == "tier-c-approvers/v1"


def _seed(name: str) -> bytes:
    return hashlib.sha256(f"transitions {name}".encode()).digest()


def _public(name: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(_seed(name)).public_key()
    return b64(key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def _sign(name: str, domain: bytes, unsigned: dict[str, Any]) -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(_seed(name))
    signature = key.sign(signed_preimage(domain, {**unsigned, "signature": ""}))
    return {**unsigned, "signature": b64(signature)}


def _value(channel: str, symbolic: str) -> str:
    return symbolic if channel in PHONE_CHANNELS else "ed25519:" + _public(symbolic)


class _Minter:
    def __init__(self) -> None:
        self.next: dict[str, str] = {}

    def challenge_id(self) -> str:
        return self.next["challenge_id"]

    def approver_id(self) -> str:
        return self.next["approver_id"]

    def credential_id(self) -> str:
        return self.next["credential_id"]

    def identity_epoch(self) -> str:
        return self.next["identity_epoch"]

    def possession_code(self) -> str:
        return self.next.get("code", NO_CODE)


class Site:
    """One scenario's runtime: its store, its run, its clock."""

    def __init__(self, store: StateStore, scenario: dict[str, Any]) -> None:
        self.store = store
        self.scenario = scenario
        self.now = 1_000_000
        self.run = 0
        self.sms = True
        self.site = SITE
        self.device = DEVICE
        self.signed = True
        self.minter = _Minter()
        self.issued_at: dict[str, int] = {}
        self.sent: list[tuple[str, str, str]] = []
        self.refused_at_issue: dict[str, str] = {}
        self.pending_removed: set[str] = set()
        self.key_names: dict[str, str] = {}
        self.registry = self._registry()

    def _registry(self) -> ApproverRegistry:
        return ApproverRegistry(
            RunContext(
                device_id=self.device,
                verified_site_id=self.site,
                authenticated_phone_channels=frozenset({"sms"} if self.sms else ()),
                anchors=Anchors(
                    current=base64.b64decode(
                        CORPUS["provisioning_test_public_key_b64"]
                    ),
                    previous=base64.b64decode(CORPUS["previous_test_public_key_b64"]),
                    other_class=(
                        base64.b64decode(CORPUS["commercial_test_public_key_b64"]),
                    ),
                    verified_config=self.signed,
                ),
                run_id=f"run-{self.run}",
            ),
            clock=lambda: self.now,
            minter=self.minter,
        )

    async def engine(self, operation: str, *args: Any) -> Any:
        return await self.store.run_approver_operation(self.registry, operation, *args)

    async def refused_or(self, operation: str, request: dict[str, Any]) -> str:
        try:
            outcome = await self.engine(operation, request)
        except RegistryRefusedError as refused:
            return refused.code
        self.outcome = outcome
        return outcome.result.get("status", "issued")

    async def challenge(self, challenge_id: str) -> dict[str, Any]:
        held = await self.store._run_read(
            lambda conn: conn.execute(
                "SELECT canonical FROM approver_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        )
        assert held is not None, f"no challenge {challenge_id}"
        return json.loads(held[0])

    def _code_for(self, challenge_id: str, digest: str | None) -> str | None:
        for step in self.scenario["steps"]:
            reply = step.get("phone_reply")
            if reply is None:
                continue
            tokens = reply["text"].split(" ")
            if len(tokens) == 3 and tokens[1] == challenge_id:
                if digest is None or sha256_hex(tokens[2].encode()) == digest:
                    return tokens[2]
        return None

    async def active(self) -> dict[str, dict[str, Any]]:
        rows = await self.store._run_read(
            lambda conn: conn.execute(
                "SELECT credential_id, approver_id, channel, value"
                " FROM approver_credentials"
            ).fetchall()
        )
        return {
            r[0]: {"approver_id": r[1], "channel": r[2], "value": r[3]} for r in rows
        }

    # ─── steps ──────────────────────────────────────────────────────────────

    async def issue(self, step: dict[str, Any]) -> str:
        kind, cid = step["kind"], step["challenge_id"]
        candidate = step["candidate"] or None
        self.minter.next = {"challenge_id": cid}
        if kind == "recover":
            self.minter.next["identity_epoch"] = step["proposed_epoch"]
            request: dict[str, Any] = {"challenge_operation": kind, "candidate": None}
        else:
            assert candidate is not None
            channel = candidate["channel"]
            value = _value(channel, candidate["value"])
            self.key_names[value] = candidate["value"]
            self.minter.next |= {
                "approver_id": candidate["approver_id"],
                "credential_id": candidate["credential"],
            }
            code = self._code_for(cid, step.get("phone_code_sha256"))
            if code is not None:
                assert sha256_hex(code.encode()) == step["phone_code_sha256"]
                self.minter.next["code"] = code
            presented: dict[str, Any] = {"channel": channel, "value": value}
            if kind == "enrol":
                owners = {c["approver_id"] for c in (await self.active()).values()}
                named = candidate["approver_id"] in owners
                presented["approver_id"] = candidate["approver_id"] if named else None
            request = {"challenge_operation": kind, "candidate": presented}
        verdict = await self.refused_or("issue", request)
        if verdict in DECIDED_AT_ISSUE and step["expect"] == "issued":
            self.refused_at_issue[cid] = verdict
            return "issued"
        if verdict == "issued":
            self.issued_at[cid] = self.now
            if self.outcome.possession_message is not None:
                self.sent.append(self.outcome.possession_message)
        return verdict

    async def recover(self, step: dict[str, Any]) -> str:
        if not step["local_request"]:
            return "local_auth_required"
        if step.get("contacts"):
            # The socket's recover request has no member that could carry them.
            request = {
                "operation": "approver_registry_recover",
                "challenge_id": "AAAAAAAAAAAAAAAAAAAAAA==",
                "contacts": step["contacts"],
            }
            with pytest.raises(SocketRequestError) as refused:
                validate_registry_request(request)
            assert refused.value.code == "invalid_arguments"
            return "contacts_forbidden"
        if self._deferred(step):
            return step["expect"]
        verdict = await self.refused_or(
            "recover", {"challenge_id": step["challenge_id"]}
        )
        if verdict == "recovered":
            header = await self.store._run_read(read_header)
            assert header is not None and header.identity_epoch == step["epoch"]
        return verdict

    async def _presented(self, step: dict[str, Any]) -> tuple[dict[str, Any], dict]:
        cid = step["challenge_id"]
        try:
            challenge = await self.challenge(cid)
        except AssertionError:
            return {}, {"challenge_id": cid, "candidate": None}
        (candidate,) = challenge["candidates"]
        presented = dict(candidate)
        if "value" in step and step["op"] != "phone_authorize":
            presented["value"] = _value(candidate["channel"], step["value"])
        return challenge, {"challenge_id": cid, "candidate": presented}

    def _deferred(self, step: dict[str, Any]) -> bool:
        refused = self.refused_at_issue.pop(step["challenge_id"], None)
        if refused is None:
            return False
        assert (step["expect"], refused) in SAME_REFUSAL, (refused, step)
        return True

    def _possession(self, challenge: dict[str, Any], good: bool) -> dict[str, Any]:
        (candidate,) = challenge["candidates"]
        digest = sha256_hex(
            json.dumps(challenge, sort_keys=True, separators=(",", ":")).encode()
        )
        unsigned = {
            "v": 1,
            "challenge_id": challenge["challenge_id"],
            "challenge_sha256": digest if good else "0" * 64,
            "candidate_credential_id": candidate["credential_id"],
        }
        return _sign(self.key_names[candidate["value"]], POSSESSION_DOMAIN, unsigned)

    async def local_seed(self, step: dict[str, Any]) -> str:
        if not step["local_request"]:
            return "local_auth_required"
        if self._deferred(step):
            return step["expect"]
        challenge, request = await self._presented(step)
        if not challenge:
            return await self.refused_or("local_seed", {**request, "possession": None})
        request["possession"] = self._possession(challenge, step["possession"])
        return await self.refused_or("local_seed", request)

    async def _authorization(
        self, challenge: dict[str, Any], authorizer: str
    ) -> dict[str, Any] | None:
        active = await self.active()
        credential = active.get(authorizer)
        digest = sha256_hex(
            json.dumps(challenge, sort_keys=True, separators=(",", ":")).encode()
        )
        if credential is not None and credential["channel"] in PHONE_CHANNELS:
            text = f"ORI-ENROL-V1 {challenge['challenge_id']} {digest}"
            await self.engine(
                "phone_text", credential["channel"], credential["value"], text, True
            )
            return None
        unsigned = {
            "v": 1,
            "challenge_id": challenge["challenge_id"],
            "challenge_sha256": digest,
            "authorizer_credential_id": authorizer,
        }
        # An authorizer the registry does not hold signs with a key of its own.
        name = authorizer if credential is None else self.key_names[credential["value"]]
        return _sign(name, ENROL_DOMAIN, unsigned)

    async def enrol(self, step: dict[str, Any]) -> str:
        if not step["local_request"]:
            return "local_auth_required"
        if self._deferred(step):
            return step["expect"]
        challenge, request = await self._presented(step)
        if not challenge:
            request |= {"authorization": None, "possession": None}
            return await self.refused_or("enrol", request)
        request["authorization"] = await self._authorization(
            challenge, step["authorizer"]
        )
        phone = request["candidate"]["channel"] in PHONE_CHANNELS
        request["possession"] = (
            None if phone else self._possession(challenge, step.get("possession", True))
        )
        return await self.refused_or("enrol", request)

    async def phone_commit(self, step: dict[str, Any]) -> str:
        reply = step.get("phone_reply")
        if reply is None:
            # No reply: the window lapses, and the value is free again.
            self.now = self.issued_at[step["challenge_id"]] + 600_001
            return "possession_required"
        self.now = self.issued_at[step["challenge_id"]] + step["phone_elapsed_ms"]
        outcome = await self.engine(
            "phone_text",
            reply["channel"],
            reply["sender"],
            reply["text"],
            reply["authenticated"],
        )
        verdict = outcome.result["outcome"]
        if verdict == "pending_unavailable" and step["expect"] in REMOVED_PENDING:
            assert step["challenge_id"] in self.pending_removed, step
            return str(step["expect"])
        if verdict == "ingress_unauthenticated":
            assert step["expect"] == "possession_invalid", step
            self.now = self.issued_at[step["challenge_id"]] + 600_001
            return "possession_invalid"
        return verdict

    async def revoke(self, step: dict[str, Any]) -> str:
        self.signed = step.get("config_signed", True)
        self.registry = self._registry()
        wire = step.get("document_wire")
        document = (wire if wire is not None else json.dumps(step["document"])).replace(
            "\n", " "
        )
        raw = (
            '{"operation":"approver_registry_revoke","document":' + document + "}"
        ).encode()
        try:
            request = validate_registry_request(parse(frame(raw + b"\n")))
        except SocketRequestError as refused:
            return refused.code
        verdict = await self.refused_or("revoke", request)
        self.signed = True
        self.registry = self._registry()
        return verdict

    async def lose(self, _step: dict[str, Any]) -> str:
        def drop(conn: Any) -> None:
            conn.execute("DELETE FROM approver_registry")
            conn.commit()

        await self.store._run_write(lambda: drop(self.store._conn))
        assert await self.store._run_read(read_header) is None
        return "locked"

    def _accept(self, step: dict[str, Any]) -> None:
        """The provisioning document the step makes the accepted one."""
        self.device = step.get("device_id", self.device)
        self.site = step.get("site_id", self.site)

    async def restart(self, step: dict[str, Any]) -> str:
        self.pending_removed |= set(self.issued_at)
        self.run += 1
        if "sms_ingress" in step:
            self.sms = bool(step["sms_ingress"])
        self._accept(step)
        self.registry = self._registry()
        return "restarted"

    async def apply_provisioning(self, step: dict[str, Any]) -> str:
        """An accepted document changed within the run.

        This runtime applies a provisioning document only at start, so it has
        no such step; the step is what an in-run apply would be. The run's
        challenges, phone state and challenge-state lock all survive it.
        """
        locked = self.registry._challenge_state_locked
        self._accept(step)
        self.registry = self._registry()
        self.registry._challenge_state_locked = locked
        return "applied"

    async def expire(self, step: dict[str, Any]) -> str:
        self.now = self.issued_at[step["challenge_id"]] + 60_001
        return "expired"

    async def expire_phone(self, step: dict[str, Any]) -> str:
        """Observed as the runtime shows it: whether the number is still held."""
        self.now = self.issued_at[step["challenge_id"]] + step["phone_elapsed_ms"]
        held = await self.store._run_read(
            lambda conn: conn.execute(
                "SELECT value FROM approver_pending_phone WHERE challenge_id = ?",
                (step["challenge_id"],),
            ).fetchone()
        )
        assert held is not None
        self.minter.next = {
            "challenge_id": f"probe-{step['challenge_id']}-{step['phone_elapsed_ms']}",
            "approver_id": "probe",
            "credential_id": "probe",
        }
        probe = {
            "challenge_operation": "enrol",
            "candidate": {"approver_id": None, "channel": "sms", "value": held[0]},
        }
        verdict = await self.refused_or("issue", probe)
        if verdict == "phone_pending_for_value":
            return "not_expired"
        # Expired means the number is free again: the probe is issued, and the
        # timed-out pending operation is gone. Any other verdict is a fault.
        assert verdict == "issued", verdict
        gone = await self.store._run_read(
            lambda conn: conn.execute(
                "SELECT 1 FROM approver_pending_phone WHERE challenge_id = ?",
                (step["challenge_id"],),
            ).fetchone()
        )
        assert gone is None
        return "expired"


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


@pytest.mark.parametrize("name", sorted(SCENARIOS))
async def test_every_scenario(store: StateStore, name: str) -> None:
    """A scenario that opens or admits a proposal runs up to that step."""
    scenario = SCENARIOS[name]
    assert scenario["initial_mode"] == "locked"
    site = Site(store, scenario)
    operations = {
        "issue": site.issue,
        "recover": site.recover,
        "local_seed": site.local_seed,
        "enrol": site.enrol,
        "phone_authorize": site.enrol,
        "phone_commit": site.phone_commit,
        "revoke": site.revoke,
        "lose": site.lose,
        "restart": site.restart,
        "apply_provisioning": site.apply_provisioning,
        "expire": site.expire,
        "expire_phone": site.expire_phone,
    }
    for index, step in enumerate(scenario["steps"]):
        if step["op"] in ("open", "admit"):
            assert name in NEEDS_TIER_C_ADMISSION
            break
        verdict = await operations[step["op"]](step)
        assert verdict == step["expect"], (index, step["op"], step)
