# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The host evidence bindings, exercised rather than read.

These tests call the functions in `scripts/evidence_host.py` directly. That is
the point of them: a binding between a verified value and the value actually
used must fail here because behaviour changed, not because a string moved.

Asserting on the text of the harness script instead would be weaker than it
looks. A search for a flag's name is satisfied by any occurrence of that name,
including one inside a comment, so such an assertion keeps passing after the
flag it was meant to police is gone.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from evidence_host import (  # noqa: E402
    EvidenceError,
    InstallRecord,
    Target,
    envelope_target,
    interpreter_for,
    require_reboot_since,
    verify_artifact,
    write_record,
)

# --- the target tuple ---------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "architecture", "python"),
    [
        ("linux-x86_64-python3.12", "x86_64", "3.12"),
        ("linux-aarch64-python3.11", "aarch64", "3.11"),
    ],
)
def test_a_supported_tuple_parses(value: str, architecture: str, python: str) -> None:
    target = Target.parse(value)

    assert target.architecture == architecture
    assert target.python == python
    assert str(target) == value


@pytest.mark.parametrize(
    "value",
    [
        "linux-x86_64-python3.10",  # unsupported interpreter
        "linux-riscv64-python3.12",  # unsupported architecture
        "darwin-x86_64-python3.12",
        "linux-x86_64",
        "",
    ],
)
def test_an_unsupported_tuple_is_refused(value: str) -> None:
    with pytest.raises(EvidenceError):
        Target.parse(value)


@pytest.mark.parametrize("machine", ["x86_64", "amd64"])
def test_a_matching_architecture_is_accepted(machine: str) -> None:
    Target.parse("linux-x86_64-python3.12").require_host_architecture(machine)


@pytest.mark.parametrize("machine", ["aarch64", "arm64", "riscv64"])
def test_a_mismatched_architecture_is_refused(machine: str) -> None:
    """A tuple is a claim about this machine, not a filename."""
    with pytest.raises(EvidenceError, match="this host is"):
        Target.parse("linux-x86_64-python3.12").require_host_architecture(machine)


# --- selecting the interpreter ------------------------------------------------


def _fake_interpreter(directory: Path, name: str, reports: str) -> Path:
    path = directory / name
    path.write_text(
        f'#!/bin/sh\nif [ "$1" = "-c" ]; then echo {reports}; fi\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def test_the_selected_interpreter_is_asked_its_own_version(tmp_path: Path) -> None:
    """A name on PATH is not evidence: it may be a wrapper or a shim."""
    honest = _fake_interpreter(tmp_path, "python3.12", "3.12")

    chosen = interpreter_for(
        Target.parse("linux-x86_64-python3.12"), which=lambda _name: str(honest)
    )

    assert chosen == honest


def test_an_interpreter_that_reports_another_version_is_refused(tmp_path: Path) -> None:
    """The exact case a 3.10 host produces when 3.12 is only named."""
    liar = _fake_interpreter(tmp_path, "python3.12", "3.10")

    with pytest.raises(EvidenceError, match="reports 3.10"):
        interpreter_for(
            Target.parse("linux-x86_64-python3.12"), which=lambda _name: str(liar)
        )


def test_a_missing_interpreter_is_refused() -> None:
    with pytest.raises(EvidenceError, match="not on PATH"):
        interpreter_for(
            Target.parse("linux-x86_64-python3.12"), which=lambda _name: None
        )


# --- the target comes from the signed envelope --------------------------------


def _envelope(path: Path, **overrides: object) -> Path:
    document = {
        "artifact": "ori-runtime-2.4.0-rc.5-linux-x86_64-python3.12.tar.gz",
        "artifact_sha256": "sha256:" + "0" * 64,
        "artifact_size": 1,
        "key_id": "ori-runtime-release-2026-01",
        "runtime_version": "2.4.0-rc.5",
        "schema": "ori.runtime_release_bundle_signature.v1",
        "signature": "ed25519:",
        "target": "linux-x86_64-python3.12",
    }
    document.update(overrides)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_the_target_is_read_from_the_envelope(tmp_path: Path) -> None:
    """Taking it from anywhere else lets a 3.12 artifact be driven by 3.10."""
    signature = _envelope(tmp_path / "sig.json")

    assert str(envelope_target(signature)) == "linux-x86_64-python3.12"


def test_an_envelope_without_a_target_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "sig.json"
    path.write_text(json.dumps({"runtime_version": "2.4.0-rc.5"}), encoding="utf-8")

    with pytest.raises(EvidenceError, match="declares no target"):
        envelope_target(path)


# --- verification, before anything is extracted -------------------------------


def _signed(tmp_path: Path, payload: bytes = b"bundle") -> dict[str, Path]:
    """A real Ed25519-signed artifact, so verification is genuinely exercised."""
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    bundle = tmp_path / "ori-runtime-2.4.0-rc.5-linux-x86_64-python3.12.tar.gz"
    bundle.write_bytes(payload)

    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    registry = tmp_path / "keys.json"
    registry.write_text(
        json.dumps(
            {
                "schema": "ori.runtime_release_keys.v1",
                "keys": [
                    {
                        "key_id": "ori-runtime-release-2026-01",
                        "public_key_b64": base64.b64encode(public).decode(),
                        "purpose": "runtime_release_bundle",
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    unsigned = {
        "artifact": bundle.name,
        "artifact_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "artifact_size": len(payload),
        "key_id": "ori-runtime-release-2026-01",
        "runtime_version": "2.4.0-rc.5",
        "schema": "ori.runtime_release_bundle_signature.v1",
        "target": "linux-x86_64-python3.12",
    }
    message = (
        b"ori.runtime_release_bundle_signature.v1\0"
        + json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    )
    envelope = dict(unsigned)
    envelope["signature"] = "ed25519:" + base64.b64encode(key.sign(message)).decode()
    signature = tmp_path / "sig.json"
    signature.write_text(json.dumps(envelope), encoding="utf-8")
    return {"bundle": bundle, "signature": signature, "registry": registry}


def _openssl_available() -> bool:
    try:
        return (
            subprocess.run(
                ["openssl", "version"], capture_output=True, check=False
            ).returncode
            == 0
        )
    except OSError:
        return False


requires_openssl = pytest.mark.skipif(
    not _openssl_available(), reason="openssl is required to verify Ed25519"
)


@requires_openssl
def test_a_correctly_signed_artifact_verifies(tmp_path: Path) -> None:
    paths = _signed(tmp_path)

    message = verify_artifact(
        bundle=paths["bundle"],
        signature=paths["signature"],
        registry=paths["registry"],
        expected_sha256=hashlib.sha256(b"bundle").hexdigest(),
        expected_version="2.4.0-rc.5",
        workspace=tmp_path / "work",
    )

    assert "verified" in message


@requires_openssl
def test_a_tampered_artifact_is_refused(tmp_path: Path) -> None:
    paths = _signed(tmp_path)
    # Same length as the original, so the digest check is what refuses it
    # rather than the size check firing first.
    paths["bundle"].write_bytes(b"tamper")

    with pytest.raises(EvidenceError, match="digest"):
        verify_artifact(
            bundle=paths["bundle"],
            signature=paths["signature"],
            registry=paths["registry"],
            expected_sha256=hashlib.sha256(b"tamper").hexdigest(),
            expected_version="2.4.0-rc.5",
            workspace=tmp_path / "work",
        )


@requires_openssl
def test_an_artifact_signed_by_another_key_is_refused(tmp_path: Path) -> None:
    """The registry is the trust anchor; a valid signature by a stranger fails."""
    paths = _signed(tmp_path)
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    other = _signed(elsewhere)
    paths["signature"].write_text(
        other["signature"].read_text(encoding="utf-8"), encoding="utf-8"
    )

    # The reason, not merely a refusal: every other field is identical, so a
    # bare `raises` would also pass if the signature check were removed and
    # some earlier field check happened to fire.
    with pytest.raises(EvidenceError, match="did not verify"):
        verify_artifact(
            bundle=paths["bundle"],
            signature=paths["signature"],
            registry=paths["registry"],
            expected_sha256=hashlib.sha256(b"bundle").hexdigest(),
            expected_version="2.4.0-rc.5",
            workspace=tmp_path / "work",
        )


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("status", "revoked", "not trusted"),
        ("purpose", "something_else", "not a release-bundle key"),
    ],
)
@requires_openssl
def test_a_key_production_would_refuse_is_refused_here(
    tmp_path: Path, field: str, value: str, expected: str
) -> None:
    """`release_bundles.py` refuses both, and this runs before it.

    Verifying more loosely than the installer would record a PASS for an
    artifact the installer then refuses with `untrusted_release_key`.
    """
    paths = _signed(tmp_path)
    registry = json.loads(paths["registry"].read_text(encoding="utf-8"))
    registry["keys"][0][field] = value
    paths["registry"].write_text(json.dumps(registry), encoding="utf-8")

    with pytest.raises(EvidenceError, match=expected):
        verify_artifact(
            bundle=paths["bundle"],
            signature=paths["signature"],
            registry=paths["registry"],
            expected_sha256=hashlib.sha256(b"bundle").hexdigest(),
            expected_version="2.4.0-rc.5",
            workspace=tmp_path / "work",
        )


def test_a_digest_that_disagrees_with_the_record_is_refused(tmp_path: Path) -> None:
    """Checked before the signature: the record is what the operator was given."""
    paths = _signed(tmp_path)

    with pytest.raises(EvidenceError, match="the record says"):
        verify_artifact(
            bundle=paths["bundle"],
            signature=paths["signature"],
            registry=paths["registry"],
            expected_sha256="0" * 64,
            expected_version="2.4.0-rc.5",
            workspace=tmp_path / "work",
        )


def test_an_envelope_for_another_version_is_refused(tmp_path: Path) -> None:
    paths = _signed(tmp_path)

    with pytest.raises(EvidenceError, match="expected 2.4.0-rc.4"):
        verify_artifact(
            bundle=paths["bundle"],
            signature=paths["signature"],
            registry=paths["registry"],
            expected_sha256=hashlib.sha256(b"bundle").hexdigest(),
            expected_version="2.4.0-rc.4",
            workspace=tmp_path / "work",
        )


# --- the install record -------------------------------------------------------


def test_a_record_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "state"
    write_record(path, InstallRecord(boot_id="boot-a", version="2.4.0-rc.5"))

    assert InstallRecord.parse(path.read_text(encoding="utf-8")) == InstallRecord(
        boot_id="boot-a", version="2.4.0-rc.5"
    )


def test_a_record_is_private_to_root(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "state"
    write_record(path, InstallRecord(boot_id="boot-a", version="2.4.0-rc.5"))

    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert not list(path.parent.glob(".record-*")), "a staging file was left behind"


def test_a_failed_write_leaves_the_previous_record_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What atomicity means here, asserted by interrupting a write.

    Asserting the mode and the absence of a staging file does not test this: a
    plain in-place `write_text` satisfies both, and truncates the destination
    the moment it fails.
    """
    import evidence_host

    path = tmp_path / "state"
    write_record(path, InstallRecord(boot_id="boot-a", version="2.4.0-rc.5"))

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise OSError("interrupted")

    monkeypatch.setattr(evidence_host.os, "replace", refuse)
    with pytest.raises(OSError):
        write_record(path, InstallRecord(boot_id="boot-b", version="2.4.0-rc.6"))

    survivor = InstallRecord.parse(path.read_text(encoding="utf-8"))
    assert survivor == InstallRecord(boot_id="boot-a", version="2.4.0-rc.5")
    assert not list(path.parent.glob(".record-*")), "a staging file was left behind"


def test_writing_a_record_does_not_reassign_its_directory(tmp_path: Path) -> None:
    """The real path is /var/lib/ori-evidence-state, and this runs as root.

    Tightening the parent to 0700 there would make /var/lib unreadable to every
    non-root account on the operator's host — breaking the machine to protect a
    file that is already 0600.
    """
    parent = tmp_path / "lib"
    parent.mkdir()
    parent.chmod(0o755)

    write_record(parent / "ori-evidence-state", InstallRecord(boot_id="b", version="v"))

    assert oct(parent.stat().st_mode & 0o777) == "0o755"


def test_persistence_requires_a_different_boot(tmp_path: Path) -> None:
    """Installing just after a boot and checking at once restarts nothing."""
    path = tmp_path / "state"
    write_record(path, InstallRecord(boot_id="boot-a", version="2.4.0-rc.5"))

    with pytest.raises(EvidenceError, match="reboot before"):
        require_reboot_since(path, expected_version="2.4.0-rc.5", current_boot="boot-a")

    found = require_reboot_since(
        path, expected_version="2.4.0-rc.5", current_boot="boot-b"
    )
    assert found.boot_id == "boot-a"


def test_persistence_refuses_a_record_for_another_release(tmp_path: Path) -> None:
    """A stale record plus a later reboot would vouch for whatever is active."""
    path = tmp_path / "state"
    write_record(path, InstallRecord(boot_id="boot-a", version="2.4.0-rc.4"))

    with pytest.raises(EvidenceError, match="asked about 2.4.0-rc.5"):
        require_reboot_since(path, expected_version="2.4.0-rc.5", current_boot="boot-b")


def test_persistence_refuses_a_missing_record(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match="no install record"):
        require_reboot_since(
            tmp_path / "absent", expected_version="2.4.0-rc.5", current_boot="boot-b"
        )


# --- the command line the shell calls -----------------------------------------


def _run(*arguments: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
    module = Path(__file__).resolve().parents[1] / "scripts" / "evidence_host.py"
    return subprocess.run(
        [sys.executable, str(module), *arguments],
        capture_output=True,
        text=True,
        check=False,
        **kwargs,  # type: ignore[arg-type]
    )


def test_the_cli_reports_failures_as_a_message_and_an_exit_code(tmp_path: Path) -> None:
    """The shell branches on the status; a traceback is not a contract."""
    result = _run(
        "require-reboot", "--path", str(tmp_path / "absent"), "--version", "2.4.0-rc.5"
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "no install record" in result.stderr


def test_no_operator_mistake_reaches_the_shell_as_a_traceback(tmp_path: Path) -> None:
    """A mistyped path and a truncated download are the likely host mistakes.

    The contract was asserted on one path and violated on the rest: a malformed
    envelope and an absent bundle both raised through `main`.
    """
    malformed = tmp_path / "bad.json"
    malformed.write_text("not json", encoding="utf-8")
    present = tmp_path / "bundle.tar.gz"
    present.write_bytes(b"x")
    registry = tmp_path / "keys.json"
    registry.write_text(json.dumps({"keys": []}), encoding="utf-8")
    digest = hashlib.sha256(b"x").hexdigest()

    invocations = {
        "malformed envelope, selecting an interpreter": (
            "select-python",
            "--signature",
            str(malformed),
        ),
        "malformed envelope, verifying": (
            "verify",
            "--bundle",
            str(present),
            "--signature",
            str(malformed),
            "--registry",
            str(registry),
            "--sha256",
            digest,
            "--version",
            "2.4.0-rc.5",
            "--workspace",
            str(tmp_path / "w"),
        ),
        "absent artifact": (
            "verify",
            "--bundle",
            str(tmp_path / "absent.tar.gz"),
            "--signature",
            str(malformed),
            "--registry",
            str(registry),
            "--sha256",
            digest,
            "--version",
            "2.4.0-rc.5",
            "--workspace",
            str(tmp_path / "w"),
        ),
    }
    for description, arguments in invocations.items():
        result = _run(*arguments)

        assert result.returncode == 1, f"{description}: exit {result.returncode}"
        assert "Traceback" not in result.stderr, f"{description} raised"
        assert result.stderr.strip(), f"{description} explained nothing"


def _corrupt(tmp_path: Path, **edits: object) -> dict[str, Path]:
    """A correctly signed set, then one field broken."""
    paths = _signed(tmp_path)
    for target, (field, value) in edits.items():  # type: ignore[misc]
        document = json.loads(paths[target].read_text(encoding="utf-8"))
        if target == "registry":
            if value is None:
                del document["keys"][0][field]
            else:
                document["keys"][0][field] = value
        else:
            document[field] = value
        paths[target].write_text(json.dumps(document), encoding="utf-8")
    return paths


@requires_openssl
@pytest.mark.parametrize(
    ("description", "edits", "expected"),
    [
        (
            "a key entry with no public key",
            {"registry": ("public_key_b64", None)},
            "declares no public_key_b64",
        ),
        (
            "a public key that is not base64",
            {"registry": ("public_key_b64", "not!b64")},
            "not valid base64",
        ),
        (
            "a signature that is not base64",
            {"signature": ("signature", "ed25519:@@@")},
            "not valid base64",
        ),
    ],
)
def test_malformed_cryptographic_input_is_an_operator_message(
    tmp_path: Path, description: str, edits: dict[str, object], expected: str
) -> None:
    """Indexing a registry field and strict base64 both raise on bad input.

    `KeyError` and `binascii.Error` are not `EvidenceError`, so they escaped
    `main` as tracebacks. The earlier no-traceback test covered malformed JSON
    and absent files, which is a different failure entirely.
    """
    paths = _corrupt(tmp_path, **edits)

    result = _run(
        "verify",
        "--bundle",
        str(paths["bundle"]),
        "--signature",
        str(paths["signature"]),
        "--registry",
        str(paths["registry"]),
        "--sha256",
        hashlib.sha256(b"bundle").hexdigest(),
        "--version",
        "2.4.0-rc.5",
        "--workspace",
        str(tmp_path / "work"),
    )

    assert result.returncode == 1, description
    assert "Traceback" not in result.stderr, f"{description} raised"
    assert expected in result.stderr, f"{description}: {result.stderr.strip()}"


@requires_openssl
def test_an_unusable_workspace_is_an_operator_message(tmp_path: Path) -> None:
    """The workspace is a caller-supplied path; a file where a directory is
    expected raised `NotADirectoryError` out of `main`."""
    paths = _signed(tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    result = _run(
        "verify",
        "--bundle",
        str(paths["bundle"]),
        "--signature",
        str(paths["signature"]),
        "--registry",
        str(paths["registry"]),
        "--sha256",
        hashlib.sha256(b"bundle").hexdigest(),
        "--version",
        "2.4.0-rc.5",
        "--workspace",
        str(blocker / "work"),
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "workspace is unusable" in result.stderr


def test_a_host_without_openssl_is_told_so(tmp_path: Path) -> None:
    """openssl is the tooling that predates the artifact. A host without it
    cannot verify at all, and needs to be told that rather than shown a
    traceback from inside subprocess."""
    paths = _signed(tmp_path)

    result = _run(
        "verify",
        "--bundle",
        str(paths["bundle"]),
        "--signature",
        str(paths["signature"]),
        "--registry",
        str(paths["registry"]),
        "--sha256",
        hashlib.sha256(b"bundle").hexdigest(),
        "--version",
        "2.4.0-rc.5",
        "--workspace",
        str(tmp_path / "work"),
        env={**os.environ, "PATH": str(tmp_path / "no-tools")},
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "openssl could not be run" in result.stderr


def test_the_cli_records_and_then_requires_a_reboot(tmp_path: Path) -> None:
    """End to end, through the same entry point the harness uses."""
    if not Path("/proc/sys/kernel/random/boot_id").exists():
        pytest.skip("boot id is a Linux interface")
    path = tmp_path / "state"

    assert (
        _run("record", "--path", str(path), "--version", "2.4.0-rc.5").returncode == 0
    )
    same_boot = _run("require-reboot", "--path", str(path), "--version", "2.4.0-rc.5")

    assert same_boot.returncode == 1
    assert "reboot before" in same_boot.stderr
    assert os.stat(path).st_mode & 0o777 == 0o600
