# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import time
from typing import TYPE_CHECKING

import pytest

from ori.security.offline_tokens import OfflineTierCTokenVerifier
from ori.skills.signing import canonical_signed_payload
from ori.state.store import StateStore

if TYPE_CHECKING:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
else:  # pragma: no cover - environment without cryptography support
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception:
        Ed25519PrivateKey = None
        serialization = None


@pytest.mark.skipif(
    Ed25519PrivateKey is None or serialization is None,
    reason="cryptography Ed25519 unavailable",
)
class TestOfflineTierCTokenVerifier:
    @staticmethod
    def _mint_token(
        *,
        private_key,
        token_id: str,
        device_id: str,
        action_scope: str,
        issued_at: int,
        expires_at: int,
        nonce: str = "n1",
    ) -> str:
        payload = {
            "token_id": token_id,
            "device_id": device_id,
            "action_scope": action_scope,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "nonce": nonce,
        }
        signature = private_key.sign(canonical_signed_payload(payload))
        payload["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    async def test_valid_token_approves_and_claims_single_use(self, tmp_path):
        private_key = Ed25519PrivateKey.generate()
        pub = base64.b64encode(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")
        now_s = int(time.time())
        token = self._mint_token(
            private_key=private_key,
            token_id="tok-01",
            device_id="dev-01",
            action_scope="open_safety_circuit",
            issued_at=now_s - 5,
            expires_at=now_s + 120,
        )
        verifier = OfflineTierCTokenVerifier(public_key_b64=pub, max_clock_skew_s=300)
        store = StateStore(str(tmp_path / "offline-token.db"))
        await store.open()
        try:
            first = await verifier.verify_token(
                token,
                expected_device_id="dev-01",
                expected_action="open_safety_circuit",
                state_store=store,
            )
            assert first.approved is True

            second = await verifier.verify_token(
                token,
                expected_device_id="dev-01",
                expected_action="open_safety_circuit",
                state_store=store,
            )
            assert second.approved is False
            assert second.reason == "replay_detected"
        finally:
            await store.close()

    async def test_a_lone_surrogate_is_refused_not_raised(self, tmp_path):
        private_key = Ed25519PrivateKey.generate()
        pub = base64.b64encode(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")
        now_s = int(time.time())
        # Raw JSON text, so the escape decodes to an unpaired surrogate.
        token = (
            '{"token_id":"tok-\\ud800","device_id":"dev-01",'
            '"action_scope":"open_safety_circuit",'
            f'"issued_at":{now_s - 5},"expires_at":{now_s + 120},'
            '"nonce":"n1","signature":"ed25519:'
            + base64.b64encode(b"\x00" * 64).decode("ascii")
            + '"}'
        )
        verifier = OfflineTierCTokenVerifier(public_key_b64=pub, max_clock_skew_s=300)
        store = StateStore(str(tmp_path / "offline-token.db"))
        await store.open()
        try:
            result = await verifier.verify_token(
                token,
                expected_device_id="dev-01",
                expected_action="open_safety_circuit",
                state_store=store,
            )
            assert result.approved is False
            assert result.reason == "decode_failed"
        finally:
            await store.close()

    async def test_wrong_device_rejected(self, tmp_path):
        private_key = Ed25519PrivateKey.generate()
        pub = base64.b64encode(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")
        now_s = int(time.time())
        token = self._mint_token(
            private_key=private_key,
            token_id="tok-02",
            device_id="dev-a",
            action_scope="open_safety_circuit",
            issued_at=now_s - 5,
            expires_at=now_s + 120,
        )
        verifier = OfflineTierCTokenVerifier(public_key_b64=pub, max_clock_skew_s=300)
        store = StateStore(str(tmp_path / "offline-token-device.db"))
        await store.open()
        try:
            result = await verifier.verify_token(
                token,
                expected_device_id="dev-b",
                expected_action="open_safety_circuit",
                state_store=store,
            )
            assert result.approved is False
            assert result.reason == "device_mismatch"
        finally:
            await store.close()


_SIGNATURE = '"signature":"ed25519:' + base64.b64encode(b"\x00" * 64).decode() + '"'
_BASE = (
    '"token_id":"t","device_id":"d","action_scope":"a",'
    '"issued_at":0,"expires_at":9999999999,' + _SIGNATURE
)
_HOSTILE_TOKENS = {
    "empty": "",
    "not json": "{{{",
    "json list": "[1,2]",
    "deep list": "[" * 100_000 + "]" * 100_000,
    "deep object": '{"a":' * 50_000 + "1" + "}" * 50_000,
    "lone surrogate value": "{" + _BASE.replace('"t"', '"t\\ud800"') + "}",
    "lone surrogate key": '{"k\\udc00":1,' + _BASE + "}",
    "token_id object": "{"
    + _BASE.replace('"token_id":"t"', '"token_id":{"a":1}')
    + "}",
    "issued_at 1e999": "{" + _BASE.replace('"issued_at":0', '"issued_at":1e999') + "}",
    "issued_at NaN": "{" + _BASE.replace('"issued_at":0', '"issued_at":NaN') + "}",
    "issued_at 5000 digits": "{"
    + _BASE.replace('"issued_at":0', '"issued_at":' + "9" * 5000)
    + "}",
    "signature not a string": "{" + _BASE.replace(_SIGNATURE, '"signature":5') + "}",
    "NUL in token_id": "{"
    + _BASE.replace('"token_id":"t"', '"token_id":"t\\u0000x"')
    + "}",
    "base64 of invalid UTF-8": base64.urlsafe_b64encode(b"\xff\xfe{").decode(),
    "base64 of a lone surrogate": base64.urlsafe_b64encode(
        ("{" + _BASE.replace('"t"', '"t\\ud800"') + "}").encode()
    ).decode(),
    "duplicate keys": "{" + _BASE + ',"token_id":"u"}',
}


@pytest.mark.skipif(
    Ed25519PrivateKey is None, reason="cryptography Ed25519 unavailable"
)
@pytest.mark.parametrize("name", sorted(_HOSTILE_TOKENS))
async def test_a_hostile_token_is_refused_never_raised(name: str, tmp_path) -> None:
    """Whatever an operator types, the verifier answers; it approves nothing."""
    public_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    verifier = OfflineTierCTokenVerifier(
        public_key_b64=base64.b64encode(public_key).decode("ascii")
    )
    store = StateStore(str(tmp_path / "offline-token.db"))
    await store.open()
    try:
        result = await verifier.verify_token(
            _HOSTILE_TOKENS[name],
            expected_device_id="d",
            expected_action="a",
            state_store=store,
        )
    finally:
        await store.close()
    assert result.approved is False
