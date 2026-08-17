# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Upgrade through the incoming release, never through the installed one.

An installed release must not install its successor with its own transaction
logic. That logic is versioned like everything else: the bundle being installed
was built, tested, and signed together with the installer that knows how to
install it, and running last release's installer against new content discards
that pairing.

So the flow is: authenticate the requested bundle against the pinned key
registry, build a throwaway environment from the wheelhouse *inside* that
verified bundle, and hand the installation to the ``ori-install-linux`` it
ships. The installed ``ori`` orchestrates; the new bundle supplies the
implementation.

Python dependencies come only from the bundle's authenticated, hash-locked
wheelhouse — ``--no-index`` and ``--require-hashes`` are not optional here.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any

from ori.installer.cli import detected_release_target
from ori.security.release_bundles import (
    ReleaseBundleError,
    extract_verified_bundle,
    load_release_key_registry,
    verify_release_bundle,
)


class UpgradeError(Exception):
    """The upgrade could not be carried out. The host is left untouched."""


def install_from_bundle(args: argparse.Namespace) -> dict[str, Any]:
    """Verify ``args.bundle`` and let its own installer install it."""
    bundle = Path(args.bundle).expanduser()
    signature = Path(args.signature).expanduser()
    for label, path in (("bundle", bundle), ("signature", signature)):
        if not path.is_file():
            raise UpgradeError(f"{label} not found: {path}")

    registry_resource = resources.files("ori.installer").joinpath("release-keys.json")
    try:
        with resources.as_file(registry_resource) as registry_path:
            registry = load_release_key_registry(registry_path)
        verified = verify_release_bundle(
            artifact_path=bundle,
            envelope_path=signature,
            key_registry=registry,
            expected_version=args.expected_version,
            expected_target=detected_release_target(),
        )
    except ReleaseBundleError as exc:
        raise UpgradeError(f"bundle is not authentic: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix="ori-upgrade-") as workspace:
        root = Path(workspace)
        try:
            extracted = extract_verified_bundle(verified, destination=root / "verified")
        except (ReleaseBundleError, OSError) as exc:
            raise UpgradeError(f"verified bundle could not be opened: {exc}") from exc
        installer = _build_installer(extracted.root, root / "installer-venv")
        return _run_installer(installer, bundle, signature, verified, args)


def _build_installer(bundle_root: Path, environment: Path) -> Path:
    """Create a throwaway environment holding the incoming bundle's installer."""
    wheelhouse = bundle_root / "wheelhouse"
    requirements = wheelhouse / "requirements.txt"
    runtime_wheels = sorted(wheelhouse.glob("ori_runtime-*.whl"))
    if not requirements.is_file() or len(runtime_wheels) != 1:
        raise UpgradeError("verified wheelhouse is incomplete")

    python = environment / "bin" / "python"
    steps = (
        [sys.executable, "-m", "venv", str(environment)],
        # --no-index and --require-hashes keep resolution inside the bundle:
        # nothing here may be fetched from the network.
        [
            str(python), "-m", "pip", "install",
            "--disable-pip-version-check", "--no-index",
            "--find-links", str(wheelhouse),
            "--require-hashes", "-r", str(requirements),
        ],
        [
            str(python), "-m", "pip", "install",
            "--disable-pip-version-check", "--no-index", "--no-deps",
            str(runtime_wheels[0]),
        ],
    )  # fmt: skip
    for step in steps:
        try:
            subprocess.run(step, check=True, stdin=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, OSError) as exc:
            raise UpgradeError(
                "could not prepare the incoming release's installer"
            ) from exc

    installer = environment / "bin" / "ori-install-linux"
    if not installer.is_file():
        raise UpgradeError("verified bundle does not ship an installer")
    return installer


def _run_installer(
    installer: Path,
    bundle: Path,
    signature: Path,
    verified: Any,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Hand over to the incoming installer and return what it reports.

    The bundle is passed through by path and verified a second time by that
    installer against its own pinned registry. Re-verification is the point:
    this process never asks the new installer to trust a decision made here.
    """
    command = [
        str(installer),
        "install",
        # The handoff always uses machine output. What the operator asked to
        # see is a presentation choice made here, in the outer command; it is
        # not the contract this process parses.
        "--json",
        "--bundle",
        str(bundle),
        "--signature",
        str(signature),
        "--expected-version",
        verified.runtime_version,
    ]
    # Forward the whole operator surface. Anything accepted by `ori install`
    # and silently dropped here would be a flag that appears to work.
    for option, flag in (
        ("--scope", "scope"),
        ("--service-user", "service_user"),
        ("--device-id", "device_id"),
        ("--name", "name"),
        ("--location", "location"),
        ("--deployment-type", "deployment_type"),
        ("--operator-contact", "operator_contact"),
        ("--root", "root"),
    ):
        value = getattr(args, flag, None)
        if value:
            command += [option, str(value)]
    for option, flag in (
        ("--unattended", "unattended"),
        ("--generate-device-id", "generate_device_id"),
        ("--allow-downgrade", "allow_downgrade"),
    ):
        if getattr(args, flag, False):
            command.append(option)

    try:
        completed = subprocess.run(
            command,
            # Only stdout is captured, because only stdout carries the result.
            # Capturing stderr as well would swallow the child's prompts and
            # progress, leaving an operator staring at a silent process that is
            # in fact waiting for them to answer something.
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            check=False,
            # Unattended runs get no input source at all, so a child that tries
            # to prompt fails immediately instead of blocking forever.
            stdin=subprocess.DEVNULL if args.unattended else None,
        )
    except OSError as exc:
        raise UpgradeError(f"could not run the incoming installer: {exc}") from exc

    payload = _payload(completed.stdout)
    if completed.returncode != 0:
        error = payload.get("error", {}) if payload else {}
        code, detail = error.get("code"), error.get("detail")
        # Carry the installer's own stable code through rather than flattening
        # a precise diagnosis into "installation failed".
        if code and detail:
            raise UpgradeError(f"{code}: {detail}")
        raise UpgradeError(detail or code or "installation failed; see above")
    if payload is None:
        raise UpgradeError("the incoming installer returned an unreadable result")
    # Validate the envelope rather than accepting any dictionary: an installer
    # that returned something unexpected has not told us the install succeeded.
    if payload.get("schema_version") != 1:
        raise UpgradeError(
            f"incoming installer returned schema {payload.get('schema_version')!r}, "
            "expected 1"
        )
    if payload.get("ok") is not True:
        raise UpgradeError("incoming installer did not report success")
    if payload.get("status") != "healthy":
        raise UpgradeError(
            f"incoming installer reported status {payload.get('status')!r}"
        )
    payload.setdefault("summary", "Installation completed.")
    return payload


def _payload(stdout: str) -> dict[str, Any] | None:
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    return document if isinstance(document, dict) else None
