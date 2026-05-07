# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import time

import pytest

from ori.security.offline_tokens import OfflineTierCTokenVerifier
from ori.skills.signing import canonical_signed_payload
from ori.state.store import StateStore

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover
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
            action_scope="trip_main_breaker",
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
                expected_action="trip_main_breaker",
                state_store=store,
            )
            assert first.approved is True

            second = await verifier.verify_token(
                token,
                expected_device_id="dev-01",
                expected_action="trip_main_breaker",
                state_store=store,
            )
            assert second.approved is False
            assert second.reason == "replay_detected"
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
            action_scope="trip_main_breaker",
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
                expected_action="trip_main_breaker",
                state_store=store,
            )
            assert result.approved is False
            assert result.reason == "device_mismatch"
        finally:
            await store.close()
