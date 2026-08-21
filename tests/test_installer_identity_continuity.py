# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""An upgrade must not re-identify the device it is upgrading.

Install and upgrade are the same code path: `ori install` authenticates the
new bundle and runs *that bundle's* installer against the same root. That
function only ever knew how to author an identity, so a run that did not
repeat `--device-id` invented a new one.

On a host whose name is distinctive the invented value happened to match, and
the bug stayed hidden. On a stock image it does not: `raspberrypi` is in
GENERIC_HOSTNAMES, so `suggest()` appends `secrets.token_hex`, and every run
produces a different device. That is the default hostname of the hardware this
runtime targets.

The data directory survives the upgrade while the identity does not, which
strands the runtime's `ori/{device_id}/...` topics, the client identifiers
per-device broker ACLs are written against, and every stored reasoning, action
and Tier C decision row indexed by `(device_id, timestamp)`.

Identity continuity holds regardless of who authored the identity. A config
generated and signed by a provisioning backend is preserved by the same rule
that preserves a locally derived one, because the installer stops authoring
identity on upgrade and starts reading it.
"""

from __future__ import annotations

import pytest
import yaml

from ori.installer import identity
from ori.installer.linux import (
    InstallerInputOptions,
    InstallLayout,
    LinuxInstallError,
    collect_installer_config,
)


def _layout(tmp_path) -> InstallLayout:
    """A managed root with its directories present but nothing in them."""
    layout = InstallLayout.resolve(tmp_path)
    layout.releases.mkdir(parents=True, exist_ok=True)
    layout.data.mkdir(parents=True, exist_ok=True)
    return layout


def _write_config(layout, device_id, name="Deployed", location="Ikeja"):
    config = layout.data / "ori.yaml"
    config.write_text(
        yaml.safe_dump(
            {"device": {"id": device_id, "name": name, "location": location}}
        )
    )
    return config


# --- reading an existing installation --------------------------------------


def test_unused_root_reads_as_no_installation(tmp_path):
    """Only a genuinely unused managed root may derive an identity."""
    assert identity.read_installed(_layout(tmp_path)) is None


def test_occupied_root_without_config_refuses_by_activated_release(tmp_path):
    """An activated release with no config is an installation, not a fresh root.

    A device's identity is not recoverable from a release tree, so deleting
    the config must stop the run rather than license a new identity.
    """
    layout = _layout(tmp_path)
    release = layout.releases / "2.4.0"
    release.mkdir(parents=True)
    layout.current.symlink_to(release)
    with pytest.raises(identity.InstalledConfigUnreadableError) as excinfo:
        identity.read_installed(layout)
    assert "activated release" in str(excinfo.value)


def test_occupied_root_without_config_refuses_by_managed_release(tmp_path):
    """A staged release with no `current` pointer still occupies the root."""
    layout = _layout(tmp_path)
    (layout.releases / "2.4.0").mkdir(parents=True)
    with pytest.raises(identity.InstalledConfigUnreadableError) as excinfo:
        identity.read_installed(layout)
    assert "managed releases" in str(excinfo.value)


def test_unexpected_root_entry_refuses(tmp_path):
    """An unused managed root is unused, not merely free of known artifacts."""
    layout = _layout(tmp_path)
    (layout.root / "leftover.db").write_bytes(b"")
    with pytest.raises(identity.InstalledConfigUnreadableError) as excinfo:
        identity.read_installed(layout)
    assert "leftover.db" in str(excinfo.value)


@pytest.mark.parametrize("directory", ["data", "releases", "root"])
def test_uninspectable_directory_fails_closed(tmp_path, directory):
    """A directory that cannot be read is not an empty one.

    Collapsing a permissions or I/O failure into "no entries" would answer
    "is this root in use?" with the one value that licenses deriving a new
    identity. That question must fail closed.
    """
    layout = _layout(tmp_path)
    target = {
        "data": layout.data,
        "releases": layout.releases,
        "root": layout.root,
    }[directory]
    original = target.stat().st_mode
    target.chmod(0o000)
    try:
        with pytest.raises(identity.InstalledConfigUnreadableError) as excinfo:
            identity.read_installed(layout)
        assert "could not be inspected" in str(excinfo.value)
    finally:
        target.chmod(original)


@pytest.mark.parametrize(
    "artifact",
    [
        "ori_state.db",
        "ori_evidence.db",
        "ori_evidence.key",
        # Not a name this code knows. Occupancy is decided by the directory
        # holding anything, so a state path configured away from its default,
        # or an artifact added later, is covered without being enumerated.
        "some-future-artifact.db",
    ],
)
def test_occupied_root_without_config_refuses_by_any_data_entry(tmp_path, artifact):
    layout = _layout(tmp_path)
    (layout.data / artifact).write_bytes(b"")
    with pytest.raises(identity.InstalledConfigUnreadableError) as excinfo:
        identity.read_installed(layout)
    assert artifact in str(excinfo.value)


def test_existing_config_yields_its_identity(tmp_path):
    layout = _layout(tmp_path)
    _write_config(layout, "energy-monitor-ikeja-01")
    installed = identity.read_installed(layout)
    assert installed is not None
    assert installed.device_id == "energy-monitor-ikeja-01"
    assert installed.name == "Deployed"
    assert installed.location == "Ikeja"


@pytest.mark.parametrize(
    "contents",
    [
        "device: [not, a, mapping]",
        "device:\n  name: no id here\n",
        "device:\n  id: '   '\n",
        ": : not yaml : :",
    ],
)
def test_unreadable_installation_refuses_rather_than_inventing(tmp_path, contents):
    """A config that exists but cannot be read is not a fresh install.

    Returning None here would let an upgrade invent an identity for a device
    whose real one is merely unreadable — the exact failure this prevents.
    """
    layout = _layout(tmp_path)
    (layout.data / "ori.yaml").write_text(contents)
    with pytest.raises(identity.InstalledConfigUnreadableError):
        identity.read_installed(layout)


# --- collection preserves what is deployed ---------------------------------


def _installed(device_id="energy-monitor-ikeja-01"):
    return identity.InstalledIdentity(
        device_id=device_id, name="Deployed", location="Ikeja"
    )


def test_unattended_upgrade_without_device_id_keeps_the_deployed_identity():
    values = collect_installer_config(
        InstallerInputOptions(
            unattended=True,
            location="Ikeja",
            installed=_installed(),
        )
    )
    assert values.device_id == "energy-monitor-ikeja-01"


def test_generate_device_id_on_an_installation_is_refused_as_contradictory():
    """That flag derives an identity from the host; the root already has one."""
    with pytest.raises(LinuxInstallError) as excinfo:
        collect_installer_config(
            InstallerInputOptions(
                unattended=True,
                location="Ikeja",
                generate_device_id=True,
                installed=_installed(),
            )
        )
    assert "--generate-device-id" in str(excinfo.value)


def test_conflicting_device_id_is_refused():
    """No install or upgrade input may mutate an established identity."""
    with pytest.raises(LinuxInstallError) as excinfo:
        collect_installer_config(
            InstallerInputOptions(
                unattended=True,
                device_id="something-else",
                name="N",
                location="L",
                installed=_installed(),
            )
        )
    message = str(excinfo.value)
    assert "energy-monitor-ikeja-01" in message
    assert "evidence idempotency" in message


def test_no_installer_option_can_mutate_an_established_identity():
    """Asserted over the option surface rather than one flag at a time.

    A future option that reached identity would otherwise pass every other
    test in this file.
    """
    installed = _installed()
    for overrides in (
        {"device_id": "other-id"},
        {"generate_device_id": True},
        {"device_id": "other-id", "generate_device_id": True},
    ):
        with pytest.raises(LinuxInstallError):
            collect_installer_config(
                InstallerInputOptions(
                    unattended=True,
                    name="N",
                    location="L",
                    installed=installed,
                    **overrides,
                )
            )

    kept = collect_installer_config(
        InstallerInputOptions(unattended=True, installed=installed)
    )
    assert kept.device_id == installed.device_id


def test_fresh_install_still_derives_identity_from_the_host():
    """Nothing installed means the question is genuinely open."""
    values = collect_installer_config(
        InstallerInputOptions(
            unattended=True,
            name="Fresh",
            location="Lab",
            generate_device_id=True,
            installed=None,
        )
    )
    assert values.device_id


def test_generic_hostname_upgrade_does_not_drift():
    """The case that made this demo-fatal.

    `raspberrypi` is the default hostname of stock Raspberry Pi OS and is in
    GENERIC_HOSTNAMES, so a host-derived suggestion carries a random suffix
    and differs on every run. Two upgrades of the same installation must still
    produce the same device.
    """
    assert identity.needs_suffix(identity.normalise("raspberrypi"))
    first = identity.suggest("raspberrypi")
    second = identity.suggest("raspberrypi")
    assert first is not None and second is not None
    assert first.device_id != second.device_id, "precondition: suggestion drifts"

    installed = _installed("pi-ikeja-01")
    runs = [
        collect_installer_config(
            InstallerInputOptions(
                unattended=True, location="Ikeja", installed=installed
            )
        ).device_id
        for _ in range(2)
    ]
    assert runs == ["pi-ikeja-01", "pi-ikeja-01"]


def test_backend_authored_identity_is_preserved_the_same_way(tmp_path):
    """Identity continuity does not depend on who authored the identity.

    A configuration generated and signed by a provisioning backend is read
    back by the same path as a locally derived one, so the rule survives the
    move to backend-issued identity rather than being replaced by it.
    """
    layout = _layout(tmp_path)
    _write_config(layout, "tenant-site-0042")
    installed = identity.read_installed(layout)
    values = collect_installer_config(
        InstallerInputOptions(unattended=True, location="Site", installed=installed)
    )
    assert values.device_id == "tenant-site-0042"
