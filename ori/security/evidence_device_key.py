# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The device's Ed25519 evidence key, sealed at rest.

The key is what makes a chain row attributable to this device. It is generated
once, at first start, and sealed with a per-install secret so that reading the
key file alone does not yield a signing key — an attacker needs the file and
the environment secret, which live in different places.

The public half is this device's verification anchor. It is the device's own
property and is reported in health; the private half never leaves this module.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_SEAL_SALT = b"ori.evidence.device_key.seal.v2"
_SEAL_INFO = b"ori.evidence.device_key.aes256gcm.v2"
_MAGIC = b"ORIEVK2\x00"
_NONCE_BYTES = 12
_SEED_BYTES = 32


class DeviceKeyError(RuntimeError):
    """The device key could not be provisioned, opened, or trusted."""


def _derive_seal_key(device_secret: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SEAL_SALT,
        info=_SEAL_INFO,
    ).derive(device_secret.encode("utf-8"))


class EvidenceDeviceKey:
    """An Ed25519 signing key sealed on disk under a per-install secret."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key
        self._public: Ed25519PublicKey = private_key.public_key()

    @property
    def public_key_hex(self) -> str:
        """This device's verification anchor."""
        return self._public.public_bytes_raw().hex()

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)

    def verify(self, signature: bytes, message: bytes) -> None:
        """Raises on mismatch. Used to prove a row this device wrote is its own."""
        self._public.verify(signature, message)

    @classmethod
    def load_or_create(
        cls, key_path: str | Path, device_secret: str
    ) -> "EvidenceDeviceKey":
        """Open the sealed key, provisioning one on first start.

        A configured-but-empty secret fails loudly rather than sealing under a
        predictable key: a seal whose secret is the empty string protects
        nothing, and doing it silently would leave a device reporting healthy
        evidence with an unsealed key.
        """
        if not device_secret:
            raise DeviceKeyError(
                "the evidence device secret is empty; a key sealed under an "
                "empty secret is not sealed"
            )
        path = Path(key_path)
        if path.exists():
            cls._assert_key_file_is_protected(path)
            return cls(cls._unseal(path.read_bytes(), device_secret))

        private = Ed25519PrivateKey.generate()
        sealed = cls._seal(private.private_bytes_raw(), device_secret)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Written 0600 before any content reaches the filesystem, and via a
        # temporary file so a crash mid-write cannot leave a truncated key that
        # would look openable and produce garbage signatures.
        temporary = path.with_suffix(path.suffix + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(sealed)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            # fsync the directory as well as the file. Without this the rename
            # itself can be lost to a power cut while the chain that key signs
            # survives, stranding a chain whose signing key no longer exists —
            # every row in it unverifiable and unextendable.
            cls._fsync_directory(path.parent)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return cls(private)

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        """Make the rename durable, and fail loudly when it cannot be.

        An earlier version swallowed both the open and the fsync. That left the
        original risk in place — a power cut losing the rename and stranding a
        chain whose signing key no longer exists — while reporting provisioning
        as successful, which is worse than not trying: the comment claimed a
        guarantee the code did not provide.

        Failing here is recoverable. The sealed key is already written and
        renamed, so a restart finds it; what is not established is that the
        rename survives a power loss, and a caller told provisioning succeeded
        would never know to check.
        """
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(directory, flags)
        except OSError as exc:
            raise DeviceKeyError(
                f"could not open {directory} to make the evidence key durable"
            ) from exc
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise DeviceKeyError(
                f"could not flush {directory}; the evidence key rename is not "
                "known to have reached disk"
            ) from exc
        finally:
            os.close(descriptor)

    @staticmethod
    def _assert_key_file_is_protected(path: Path) -> None:
        """A key readable by other accounts is not sealed in any useful sense.

        The seal defends against someone holding the file without the secret.
        It does not defend against a local account that can read both, so a
        permissive key file is refused rather than used — quietly widening
        access is how a device ends up signing evidence with a key several
        accounts can copy.
        """
        info = path.stat()
        if info.st_mode & 0o077:
            raise DeviceKeyError(
                f"the evidence key at {path} is readable or writable by other "
                f"accounts (mode {info.st_mode & 0o777:04o}); it must be 0600"
            )
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise DeviceKeyError(
                f"the evidence key at {path} is owned by another account; the "
                "runtime must own the key it signs with"
            )

    @staticmethod
    def _seal(seed: bytes, device_secret: str) -> bytes:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = AESGCM(_derive_seal_key(device_secret)).encrypt(
            nonce, seed, _MAGIC
        )
        return _MAGIC + nonce + ciphertext

    @staticmethod
    def _unseal(blob: bytes, device_secret: str) -> Ed25519PrivateKey:
        if not blob.startswith(_MAGIC):
            raise DeviceKeyError("the evidence key file is not in the expected format")
        body = blob[len(_MAGIC) :]
        if len(body) <= _NONCE_BYTES:
            raise DeviceKeyError("the evidence key file is truncated")
        nonce, ciphertext = body[:_NONCE_BYTES], body[_NONCE_BYTES:]
        try:
            seed = AESGCM(_derive_seal_key(device_secret)).decrypt(
                nonce, ciphertext, _MAGIC
            )
        except Exception as exc:
            # Wrong secret and tampered file are indistinguishable here, and
            # deliberately so: AES-GCM authenticates, and reporting which one
            # failed would tell an attacker whether their secret was close.
            raise DeviceKeyError(
                "the evidence key could not be unsealed; the device secret is "
                "wrong or the file has been altered"
            ) from exc
        if len(seed) != _SEED_BYTES:
            raise DeviceKeyError("the unsealed evidence key is the wrong length")
        return Ed25519PrivateKey.from_private_bytes(seed)
