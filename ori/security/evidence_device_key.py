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
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return cls(private)

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
