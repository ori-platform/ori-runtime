# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Operator CLI for the firmware provisioning transaction.

Supports the bench proof in ori-edge-firmware#14. It **orchestrates the
runtime's existing provisioning path** — it is not a second authority.
Approvals are signed by :class:`FirmwareCommandService` from the stored
registry row, so registration, explicit operator approval, and
revocation are all honoured. A tool that signed approvals from a
presented manifest would let firmware accept a device the runtime still
regards as unknown, unapproved, or revoked; that split-brain is the
thing this command exists to prevent.

The transaction, in the order the subcommands run:

``keygen``
    Create the provisioning-authority and runtime-command keys. Emits
    the authority public key as the C array the firmware compiles in as
    ``BENCH_PROVISIONER_PUBKEY`` (its all-zero default refuses every
    approval), and both seeds in the canonical base64 the runtime's
    ``load_raw_ed25519_seed_from_env`` expects.

``register``
    Verify the manifest the device published on ``ori/fw/<id>/manifest``
    and store its anchor **unapproved** via
    ``FirmwareTelemetryGate.register_device``. Prints the device public
    key for the operator to confirm out of band.

``approve``
    Promote the pending anchor to active. Requires ``--reason``:
    promotion is a trust transition and every one is audited. The actor
    is the authenticated OS principal, derived from the real UID rather
    than supplied on the command line, because a typed name is an
    assertion rather than attribution. Records explicit operator approval, but only after the
    operator
    supplies the device public key they observed independently — read
    from the device's serial console, which prints
    ``ori: device public key (b64) <KEY>`` at boot, not from the
    manifest. Verifying a manifest against the key inside that same
    manifest proves internal consistency, never that the bytes came
    from the board in front of you.

``publish``
    Sign from the stored, approved, unrevoked row and publish retained
    on ``ori/fw/<id>/provision``.

``selfcheck``
    Contract diagnostic: reproduce the shared golden vectors, which is
    what ties these bytes to the firmware's C verifier. No hardware, no
    network, no store.

The authority private key grants command authority over a fleet. It is
written owner-only, never printed, and never overwritten.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

from ori.security.firmware_commands import build_provisioning_approval_bytes
from ori.security.firmware_telemetry import FirmwareVerificationError

# The shared corpus that ties these bytes to the C verifier in
# ori-edge-firmware; the same bytes its test_provisioning.c accepts.
_VECTORS = (
    Path(__file__).resolve().parent.parent
    / "tests"
    / "fixtures"
    / "firmware_provisioning_approval_vectors.json"
)


class ProvisionerError(Exception):
    """An operator-facing failure with a message worth reading."""


# ── key material ─────────────────────────────────────────────────────


def _public_key_b64(seed: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return base64.b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(
        "ascii"
    )


def _c_array(seed: bytes, name: str) -> str:
    """The authority public key in the form app_main.c declares it."""
    raw = base64.b64decode(_public_key_b64(seed))
    rows = [
        "    " + " ".join(f"0x{b:02X}," for b in raw[i : i + 8])
        for i in range(0, len(raw), 8)
    ]
    body = "\n".join(rows)
    return f"static const uint8_t {name}[ORI_ED25519_PUBLIC_KEY_LEN] = {{\n{body}\n}};"


def _write_secret(path: Path, seed: bytes) -> None:
    # Owner-only and created exclusively: a second keygen must not
    # silently invalidate a fleet's authority.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ProvisionerError(
            f"{path} already exists; refusing to overwrite an authority key"
        ) from exc
    except OSError as exc:
        raise ProvisionerError(f"cannot write {path}: {exc}") from exc
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        # Canonical base64: the form load_raw_ed25519_seed_from_env
        # reads. Writing hex here would generate keys the runtime cannot
        # load, so the approval would install a key it never uses.
        fh.write(base64.b64encode(seed).decode("ascii") + "\n")


def read_seed(path: Path, label: str) -> bytes:
    try:
        raw = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise ProvisionerError(f"cannot read {label} at {path}: {exc}") from exc
    try:
        seed = base64.b64decode(raw.encode("ascii"), validate=True)
    except Exception as exc:
        raise ProvisionerError(
            f"{label} at {path} must be canonical base64 (the form the runtime loads)"
        ) from exc
    if len(seed) != 32:
        raise ProvisionerError(f"{label} must be 32 bytes ({len(seed)} found)")
    return seed


def authenticated_actor(label: str = "") -> str:
    """The OS principal running this command, for the audit log.

    The contract requires the *authenticated* operator. A caller-supplied
    name is an assertion, not attribution: anyone can type any name. So
    the recorded actor is derived from the real UID via the passwd
    database — deliberately not ``getpass.getuser()``, which trusts the
    LOGNAME/USER environment variables and is therefore caller-controlled.

    An optional display label is appended for human context but never
    replaces the principal. Raises :class:`ProvisionerError` where no real
    UID is available, rather than recording a placeholder that would look
    like attribution.
    """
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        # No real UID to authenticate against. Recording a placeholder
        # would put an unattributable row in the audit log while looking
        # like attribution, so fail closed instead.
        raise ProvisionerError(
            "cannot determine an authenticated OS principal on this platform; "
            "trust transitions must be attributable, so this operation is "
            "refused rather than audited to a placeholder"
        )
    uid = getuid()
    try:
        import pwd

        principal = f"uid={uid}:{pwd.getpwuid(uid).pw_name}"
    except (ImportError, KeyError):
        # The UID itself is still authenticated even without a name.
        principal = f"uid={uid}"
    clean = str(label).strip()
    return f"{principal} ({clean})" if clean else principal


def cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    seed_auth = os.urandom(32)
    seed_rt = os.urandom(32)
    _write_secret(out / "provisioner_seed.b64", seed_auth)
    _write_secret(out / "runtime_command_seed.b64", seed_rt)

    print(f"authority seed      : {out / 'provisioner_seed.b64'}  (0600, keep offline)")
    print(f"runtime command seed: {out / 'runtime_command_seed.b64'}  (0600)")
    print()
    print("Load into the runtime environment (canonical base64):")
    print(
        f"  export ORI_FIRMWARE_PROVISIONER_SEED=$(cat {out / 'provisioner_seed.b64'})"
    )
    print(
        f"  export ORI_FIRMWARE_COMMAND_SEED=$(cat {out / 'runtime_command_seed.b64'})"
    )
    print()
    print("Compile into device/main/app_main.c, replacing the all-zero")
    print("BENCH_PROVISIONER_PUBKEY — until you do, the device refuses every")
    print("approval and stays telemetry-only:")
    print()
    print(_c_array(seed_auth, "BENCH_PROVISIONER_PUBKEY"))
    return 0


# ── store-backed transaction ─────────────────────────────────────────


async def _open_store(db_path: str) -> Any:
    """Open the runtime's own state store. `open()` applies the DDL
    migrations, so the registry this CLI reads is the same table the
    runtime uses — not a private copy."""
    from ori.state.store import StateStore

    store = StateStore(db_path=db_path)
    await store.open()
    return store


def _load_manifest_message(path: str) -> dict[str, Any]:
    try:
        message = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvisionerError(f"cannot read manifest message {path}: {exc}") from exc
    if not isinstance(message, dict) or not isinstance(message.get("manifest"), dict):
        raise ProvisionerError("message has no manifest object")
    return message


async def _register(db_path: str, manifest_path: str) -> tuple[str, str]:
    from ori.security.firmware_ingest import FirmwareTelemetryGate

    message = _load_manifest_message(manifest_path)
    manifest = message["manifest"]
    device_id = manifest.get("device_id")
    device_pub = manifest.get("public_key_b64")
    posture = manifest.get("posture")
    if not all(isinstance(v, str) for v in (device_id, device_pub, posture)):
        raise ProvisionerError(
            "manifest is missing device_id, public_key_b64, or posture"
        )

    store = await _open_store(db_path)
    try:
        # The store refuses a revoked identity and a changed key outright
        # (ori-specs/device-provisioning/v1.md), so no flag here could
        # override it. Returning a revoked identity to service is
        # reinstatement: an explicit, audited operation.
        gate = FirmwareTelemetryGate(store)
        capability_hash = await gate.register_device(
            device_id=device_id,
            public_key_b64=device_pub,
            posture=posture,
            manifest_message=message,
            board_profile=str(manifest.get("board_profile", "")),
        )
    except FirmwareVerificationError as exc:
        raise ProvisionerError(f"manifest rejected: {exc}") from exc
    finally:
        await store.close()
    return str(device_pub), capability_hash


def cmd_register(args: argparse.Namespace) -> int:
    device_pub, capability_hash = asyncio.run(_register(args.db, args.manifest))
    print("registered UNAPPROVED — telemetry is not accepted until approval")
    print(f"  capability hash : {capability_hash}")
    print(f"  device key (b64): {device_pub}")
    print()
    print("Before approving, read the key off the device itself. Its serial")
    print("console prints, at boot:")
    print()
    print("    ori: device public key (b64) <KEY>")
    print()
    print("Confirm that string matches the one above, then pass it to")
    print("`approve --confirm-device-key`. A manifest verified against the key")
    print("carried inside it proves the message is self-consistent, not that it")
    print("came from the board in front of you.")
    return 0


async def _approve(
    db_path: str, device_id: str, confirmed_key: str, actor: str, reason: str
) -> None:
    from ori.security.firmware_ingest import FirmwareTelemetryGate

    store = await _open_store(db_path)
    try:
        row = await store.get_firmware_device(device_id)
        if row is None:
            raise ProvisionerError(
                f"unknown device {device_id!r}; run `register` first"
            )
        if row.get("revoked"):
            raise ProvisionerError(
                f"device {device_id!r} is revoked; approving it here would contradict "
                "the registry — re-provision deliberately instead"
            )
        # Confirm the key of the anchor about to be ACTIVATED, not the one
        # currently active. After re-provisioning they differ, and checking
        # the active key would make a re-keyed device impossible to promote.
        pending = await store.get_pending_firmware_anchor(device_id)
        if pending is None:
            raise ProvisionerError(
                f"device {device_id!r} has no pending anchor to promote"
            )
        stored_key = str(pending.get("public_key_b64", ""))
        if confirmed_key != stored_key:
            raise ProvisionerError(
                "the confirmed device key does not match the anchor awaiting "
                "promotion.\n"
                f"  awaiting promotion: {stored_key}\n"
                f"  confirmed         : {confirmed_key}\n"
                "Approving would bind authority to a device you did not verify."
            )
        gate = FirmwareTelemetryGate(store)
        if not await gate.approve_device(device_id, actor=actor, reason=reason):
            raise ProvisionerError(
                f"registry refused to promote {device_id!r}: there is no pending "
                "anchor to promote, or the identity is revoked"
            )
    finally:
        await store.close()


def cmd_approve(args: argparse.Namespace) -> int:
    asyncio.run(
        _approve(
            args.db,
            args.device_id,
            args.confirm_device_key,
            authenticated_actor(args.actor_label),
            args.reason,
        )
    )
    print(f"{args.device_id} approved in the runtime registry")
    print("Run `publish` to sign and publish the retained approval.")
    return 0


async def _publish(
    db_path: str,
    device_id: str,
    provisioner_seed: bytes,
    runtime_seed: bytes,
    dry_run: bool,
) -> bytes:
    from ori.gateway.firmware_commands import (
        FirmwareCommandError,
        FirmwareCommandService,
    )
    from ori.security.firmware_liveness import FirmwareLivenessSupervisor

    store = await _open_store(db_path)

    class _CapturingPublisher:
        """Dry-run publisher: exercises every store-backed control and
        returns the bytes without touching a broker."""

        def __init__(self) -> None:
            self.published: bytes | None = None

        async def publish_provisioning_approval(
            self, device_id: str, message: bytes
        ) -> None:
            del device_id
            self.published = message

    if dry_run:
        publisher: Any = _CapturingPublisher()
    else:
        raise ProvisionerError(
            "live publishing runs inside the runtime's gateway; use --dry-run here "
            "and publish through the runtime, or hand the emitted bytes to your "
            "bench MQTT client"
        )

    try:
        service = FirmwareCommandService(
            store=store,
            publisher=publisher,
            runtime_command_key_bytes=runtime_seed,
            provisioner_key_bytes=provisioner_seed,
            # A private, permanently empty supervisor, on purpose. This
            # tool signs provisioning approvals offline and receives no
            # telemetry, so it must never be able to publish liveness —
            # asserting supervision from a CLI that is about to exit is
            # precisely the claim a device must not be given.
            liveness_supervisor=FirmwareLivenessSupervisor(),
        )
        return await service.publish_provisioning_approval(device_id)
    except FirmwareCommandError as exc:
        # Unknown / unapproved / revoked all land here — the controls a
        # parallel signer would have skipped.
        raise ProvisionerError(f"registry refused: {exc}") from exc
    finally:
        await store.close()


def cmd_publish(args: argparse.Namespace) -> int:
    message = asyncio.run(
        _publish(
            args.db,
            args.device_id,
            read_seed(Path(args.provisioner_seed), "provisioner seed"),
            read_seed(Path(args.runtime_command_seed), "runtime command seed"),
            dry_run=True,
        )
    )
    if args.out:
        Path(args.out).write_bytes(message)
        print(f"approval written to {args.out}")
    else:
        sys.stdout.write(message.decode("utf-8") + "\n")
    print(
        f"publish RETAINED on ori/fw/{args.device_id}/provision (QoS 1)",
        file=sys.stderr,
    )
    return 0


async def _reinstate(db_path: str, device_id: str, actor: str, reason: str) -> None:
    from ori.security.firmware_ingest import FirmwareTelemetryGate

    store = await _open_store(db_path)
    try:
        if not await FirmwareTelemetryGate(store).reinstate_device(
            device_id, actor=actor, reason=reason
        ):
            raise ProvisionerError(
                f"cannot reinstate {device_id!r}: it is unknown, or it is not revoked"
            )
    finally:
        await store.close()


def cmd_reinstate(args: argparse.Namespace) -> int:
    asyncio.run(
        _reinstate(
            args.db,
            args.device_id,
            authenticated_actor(args.actor_label),
            args.reason,
        )
    )
    print(f"{args.device_id} reinstated; its retained anchor is PENDING")
    print("Reinstatement activates nothing. Run `approve` to promote it.")
    return 0


async def _reprovision(
    db_path: str,
    manifest_path: str,
    confirmed_key: str,
    actor: str,
    reason: str,
) -> str:
    from ori.security.firmware_ingest import FirmwareTelemetryGate

    message = _load_manifest_message(manifest_path)
    manifest = message["manifest"]
    device_id = manifest.get("device_id")
    device_pub = manifest.get("public_key_b64")
    posture = manifest.get("posture")
    if not all(isinstance(v, str) for v in (device_id, device_pub, posture)):
        raise ProvisionerError(
            "manifest is missing device_id, public_key_b64, or posture"
        )

    # The whole reason re-provisioning is a separate operation: the new key
    # must be confirmed against the device itself, not against the manifest
    # that asserts it.
    if confirmed_key != device_pub:
        raise ProvisionerError(
            "the confirmed device key does not match the key in the manifest.\n"
            f"  manifest : {device_pub}\n"
            f"  confirmed: {confirmed_key}\n"
            "Re-provisioning binds authority to a NEW key; confirm it from the "
            "device's own console before proceeding."
        )

    store = await _open_store(db_path)
    try:
        return await FirmwareTelemetryGate(store).reprovision_device(
            device_id=str(device_id),
            public_key_b64=str(device_pub),
            posture=str(posture),
            manifest_message=message,
            actor=actor,
            reason=reason,
        )
    except FirmwareVerificationError as exc:
        raise ProvisionerError(f"re-provisioning refused: {exc}") from exc
    finally:
        await store.close()


def cmd_reprovision(args: argparse.Namespace) -> int:
    capability_hash = asyncio.run(
        _reprovision(
            args.db,
            args.manifest,
            args.confirm_device_key,
            authenticated_actor(args.actor_label),
            args.reason,
        )
    )
    print("new key accepted as a PENDING anchor; the previous anchor stays active")
    print(f"  capability hash: {capability_hash}")
    print("Run `approve` to promote it.")
    return 0


# ── contract diagnostic ──────────────────────────────────────────────


def golden_selfcheck() -> list[str]:
    """Reproduce the shared vectors. A mismatch means this runtime and
    the firmware's C verifier no longer agree on the wire bytes."""
    problems: list[str] = []
    vectors = json.loads(_VECTORS.read_text(encoding="utf-8"))
    seed = bytes.fromhex(vectors["provisioner_test_seed_hex"])
    for case in vectors["cases"]:
        i = case["input"]
        produced = build_provisioning_approval_bytes(
            capability_hash=i["capability_hash"],
            device_id=i["device_id"],
            posture=i["posture"],
            public_key_b64=i["public_key_b64"],
            runtime_public_key_b64=i["runtime_public_key_b64"],
            provisioner_private_key_bytes=seed,
        )
        if produced.hex() != case["message_hex"]:
            problems.append(f"{case['name']}: wire message does not match the vector")
    return problems


def cmd_selfcheck(args: argparse.Namespace) -> int:
    del args
    problems = golden_selfcheck()
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    if problems:
        return 1
    count = len(json.loads(_VECTORS.read_text(encoding="utf-8"))["cases"])
    print(f"golden vectors reproduced byte-for-byte ({count} cases)")
    print("runtime and firmware agree on the approval wire format")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ori-firmware-provisioner",
        description="Operator CLI for the firmware provisioning transaction.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create authority + runtime keys")
    p.add_argument("--out-dir", required=True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("register", help="store a device anchor, unapproved")
    p.add_argument("--db", required=True)
    p.add_argument("--manifest", required=True)
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("approve", help="record explicit operator approval")
    p.add_argument("--db", required=True)
    p.add_argument("--device-id", required=True)
    p.add_argument(
        "--confirm-device-key",
        required=True,
        metavar="B64",
        help="device public key as observed on the device itself, not from the manifest",
    )
    p.add_argument(
        "--actor-label",
        default="",
        help="optional display name; the audit log always records the "
        "authenticated OS principal regardless",
    )
    p.add_argument(
        "--reason",
        required=True,
        help="why this device is being approved; recorded in the audit log",
    )
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser(
        "publish", help="sign from the approved row and emit the approval"
    )
    p.add_argument("--db", required=True)
    p.add_argument("--device-id", required=True)
    p.add_argument("--provisioner-seed", required=True)
    p.add_argument("--runtime-command-seed", required=True)
    p.add_argument("--out")
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser(
        "reinstate", help="return a revoked identity to service (anchor -> pending)"
    )
    p.add_argument("--db", required=True)
    p.add_argument("--device-id", required=True)
    p.add_argument("--reason", required=True, help="recorded in the audit log")
    p.add_argument("--actor-label", default="", help="optional display name")
    p.set_defaults(func=cmd_reinstate)

    p = sub.add_parser(
        "reprovision", help="accept a NEW device key (explicit, audited)"
    )
    p.add_argument("--db", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument(
        "--confirm-device-key",
        required=True,
        metavar="B64",
        help="the NEW device public key as observed on the device itself",
    )
    p.add_argument("--reason", required=True, help="recorded in the audit log")
    p.add_argument("--actor-label", default="", help="optional display name")
    p.set_defaults(func=cmd_reprovision)

    p = sub.add_parser("selfcheck", help="reproduce the shared golden vectors")
    p.set_defaults(func=cmd_selfcheck)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ProvisionerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
