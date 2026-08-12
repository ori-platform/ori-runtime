# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import hashlib
import json
import runpy
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@pytest.fixture
def bootstrap() -> dict[str, Any]:
    return runpy.run_path("scripts/install-linux.sh")


def _envelope(
    bootstrap: dict[str, Any], artifact: Path, private: Ed25519PrivateKey
) -> dict[str, Any]:
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    envelope: dict[str, Any] = {
        "artifact": artifact.name,
        "artifact_sha256": f"sha256:{digest}",
        "artifact_size": artifact.stat().st_size,
        "key_id": bootstrap["KEY_ID"],
        "runtime_version": "2.3.0",
        "schema": bootstrap["SIGNATURE_SCHEMA"],
        "signature": "ed25519:" + base64.b64encode(bytes(64)).decode(),
        "target": "linux-x86_64-python3.12",
    }
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    message = bootstrap["SIGNATURE_DOMAIN"] + json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    envelope["signature"] = "ed25519:" + base64.b64encode(
        private.sign(message)
    ).decode()
    return envelope


def test_bootstrap_pins_normative_release_key(bootstrap: dict[str, Any]) -> None:
    public = base64.b64decode(bootstrap["PUBLIC_KEY_B64"], validate=True)
    assert bootstrap["KEY_ID"] == "ori-runtime-release-2026-01"
    assert hashlib.sha256(public).hexdigest() == bootstrap["PUBLIC_KEY_SHA256"]
    assert bootstrap["PUBLIC_KEY_SHA256"] == (
        "d4f44308d60fb78a33f709eebc85271f2b8c0d4e59e50bb77bf08f5864918c90"
    )


def test_shell_polyglot_help_runs_without_importing_runtime() -> None:
    completed = subprocess.run(
        ["bash", "scripts/install-linux.sh", "--help"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert "--version" in completed.stdout
    assert "Traceback" not in completed.stderr
    piped = subprocess.run(
        ["bash", "-s", "--", "--help"],
        input=Path("scripts/install-linux.sh").read_text(encoding="utf-8"),
        text=True,
        capture_output=True,
        check=False,
    )
    assert piped.returncode == 0
    assert "--version" in piped.stdout
    if Path("/bin/dash").is_file():
        dash = subprocess.run(
            ["/bin/dash", "-s", "--", "--help"],
            input=Path("scripts/install-linux.sh").read_text(encoding="utf-8"),
            text=True,
            capture_output=True,
            check=False,
        )
        assert dash.returncode == 2
        assert "must be run with bash" in dash.stderr
        assert "Traceback" not in dash.stderr


def test_load_envelope_rejects_duplicate_fields(
    bootstrap: dict[str, Any], tmp_path: Path
) -> None:
    path = tmp_path / "signature.json"
    path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
    with pytest.raises(bootstrap["BootstrapError"], match="duplicate fields"):
        bootstrap["load_envelope"](
            path, "2.3.0", "linux-x86_64-python3.12"
        )


def test_openssl_verifies_exact_canonical_signature(
    bootstrap: dict[str, Any], tmp_path: Path
) -> None:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    artifact = tmp_path / "ori-runtime-2.3.0-linux-x86_64-python3.12.tar.gz"
    artifact.write_bytes(b"authenticated release")
    envelope = _envelope(bootstrap, artifact, private)
    globals_ = bootstrap["verify_signature"].__globals__
    globals_["PUBLIC_KEY_B64"] = base64.b64encode(public).decode()
    globals_["PUBLIC_KEY_SHA256"] = hashlib.sha256(public).hexdigest()

    bootstrap["verify_signature"](envelope, artifact, tmp_path)

    artifact.write_bytes(b"tampered release")
    with pytest.raises(
        bootstrap["BootstrapError"], match="artifact size or SHA-256 mismatch"
    ):
        bootstrap["verify_signature"](envelope, artifact, tmp_path)


def test_invalid_signature_fails_closed(
    bootstrap: dict[str, Any], tmp_path: Path
) -> None:
    private = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    public = other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    artifact = tmp_path / "ori-runtime-2.3.0-linux-x86_64-python3.12.tar.gz"
    artifact.write_bytes(b"release")
    envelope = _envelope(bootstrap, artifact, private)
    globals_ = bootstrap["verify_signature"].__globals__
    globals_["PUBLIC_KEY_B64"] = base64.b64encode(public).decode()
    globals_["PUBLIC_KEY_SHA256"] = hashlib.sha256(public).hexdigest()
    with pytest.raises(bootstrap["BootstrapError"], match="signature verification"):
        bootstrap["verify_signature"](envelope, artifact, tmp_path)


def test_openssl_before_version_three_is_reported_as_crypto_unavailable(
    bootstrap: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    artifact = tmp_path / "ori-runtime-2.3.0-linux-x86_64-python3.12.tar.gz"
    artifact.write_bytes(b"release")
    envelope = _envelope(bootstrap, artifact, private)
    globals_ = bootstrap["verify_signature"].__globals__
    globals_["PUBLIC_KEY_B64"] = base64.b64encode(public).decode()
    globals_["PUBLIC_KEY_SHA256"] = hashlib.sha256(public).hexdigest()
    monkeypatch.setattr(
        globals_["subprocess"],
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout="OpenSSL 1.1.1w  11 Sep 2023"
        ),
    )
    with pytest.raises(bootstrap["BootstrapError"], match="OpenSSL 3 or newer") as error:
        bootstrap["verify_signature"](envelope, artifact, tmp_path)
    assert error.value.code == "crypto_unavailable"


def test_download_rejects_non_approved_origin(
    bootstrap: dict[str, Any], tmp_path: Path
) -> None:
    with pytest.raises(bootstrap["BootstrapError"], match="approved HTTPS origin"):
        bootstrap["download"](
            "http://example.com/release", tmp_path / "release", 100
        )


@pytest.mark.parametrize(
    "argument",
    [
        "--bundle",
        "--bund",
        "--signature=other.json",
        "--signat",
        "--expected-version",
        "--expected-vers",
    ],
)
def test_bootstrap_owned_identity_arguments_cannot_be_overridden(
    bootstrap: dict[str, Any], argument: str
) -> None:
    with pytest.raises(bootstrap["BootstrapError"], match="controlled"):
        bootstrap["validate_forwarded"]([argument])


def test_archive_rejects_traversal_after_authentication(
    bootstrap: dict[str, Any], tmp_path: Path
) -> None:
    artifact = tmp_path / "release.tar.gz"
    source = tmp_path / "payload"
    source.write_text("bad", encoding="utf-8")
    with tarfile.open(artifact, "w:gz") as archive:
        archive.add(source, arcname="ori-runtime-2.3.0-linux-x86_64-python3.12/../bad")
    with pytest.raises(bootstrap["BootstrapError"], match="unsafe member"):
        bootstrap["extract_verified_bundle"](
            artifact,
            tmp_path / "extract",
            "ori-runtime-2.3.0-linux-x86_64-python3.12",
        )


def test_main_verifies_before_extracting_or_executing(
    bootstrap: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setitem(bootstrap["main"].__globals__, "detected_target", lambda: "linux-x86_64-python3.12")
    monkeypatch.setitem(bootstrap["main"].__globals__, "download", lambda *_args: calls.append("download"))
    monkeypatch.setitem(
        bootstrap["main"].__globals__,
        "load_envelope",
        lambda *_args: {"artifact_size": 1},
    )

    def reject(*_args: object) -> None:
        calls.append("verify")
        raise bootstrap["BootstrapError"]("signature_verification_failed", "bad")

    monkeypatch.setitem(bootstrap["main"].__globals__, "verify_signature", reject)
    monkeypatch.setitem(
        bootstrap["main"].__globals__,
        "extract_verified_bundle",
        lambda *_args: calls.append("extract"),
    )
    monkeypatch.setitem(
        bootstrap["main"].__globals__,
        "verify_manifest",
        lambda *_args: calls.append("manifest"),
    )
    monkeypatch.setitem(
        bootstrap["main"].__globals__,
        "bootstrap_install",
        lambda *_args: calls.append("execute"),
    )
    assert bootstrap["main"](["--version", "2.3.0"]) == 2
    assert calls == ["download", "download", "verify"]


def test_bootstrap_install_uses_only_verified_wheelhouse(
    bootstrap: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "verified"
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    (wheelhouse / "requirements.txt").write_text("locked", encoding="utf-8")
    (wheelhouse / "ori_runtime-2.3.0-py3-none-any.whl").write_bytes(b"wheel")
    calls: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setitem(
        bootstrap["bootstrap_install"].__globals__,
        "subprocess",
        SimpleNamespace(
            run=run,
            DEVNULL=subprocess.DEVNULL,
            SubprocessError=subprocess.SubprocessError,
        ),
    )
    result = bootstrap["bootstrap_install"](
        root,
        tmp_path / "bundle",
        tmp_path / "signature",
        "2.3.0",
        ["--unattended", "--scope", "user"],
    )
    assert result == 0
    assert "--no-index" in calls[1]
    assert "--require-hashes" in calls[1]
    assert "--no-deps" in calls[2]
    assert calls[3][-5:] == [
        "--expected-version",
        "2.3.0",
        "--unattended",
        "--scope",
        "user",
    ]


def test_manifest_requires_exact_file_set_and_digest(
    bootstrap: dict[str, Any], tmp_path: Path
) -> None:
    root = tmp_path / "bundle"
    root.mkdir()
    payload = root / "wheelhouse" / "dependency.whl"
    payload.parent.mkdir()
    payload.write_bytes(b"wheel")
    manifest = {
        "files": {
            "wheelhouse/dependency.whl": "sha256:"
            + hashlib.sha256(b"wheel").hexdigest()
        },
        "python": "3.12",
        "runtime_version": "2.3.0",
        "schema": bootstrap["MANIFEST_SCHEMA"],
        "target": "linux-x86_64-python3.12",
    }
    (root / "BUNDLE-MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    bootstrap["verify_manifest"](
        root, "2.3.0", "linux-x86_64-python3.12"
    )
    payload.write_bytes(b"tampered")
    with pytest.raises(bootstrap["BootstrapError"], match="digest mismatch"):
        bootstrap["verify_manifest"](
            root, "2.3.0", "linux-x86_64-python3.12"
        )
