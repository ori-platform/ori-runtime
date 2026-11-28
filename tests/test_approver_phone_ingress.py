# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The SMS webhook hands registry texts to the Tier C approver registry.

`sms` is an authenticated phone channel only when the webhook signs every
request with a mandatory nonce (tier-c-approvers/v1, maintainer ruling D1-a).
The channel is the webhook's own; nothing in the payload selects it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import quote

import pytest

from ori.network.sms_webhook import SMSWebhookServer, _HttpRequest
from ori.security.approvers.registry import Outcome
from ori.security.approvers.service import RegistryService
from ori.security.webhook_signatures import (
    WebhookSignatureConfig,
    WebhookSignatureVerifier,
    sign_webhook_body,
)
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms
from tests.test_approver_registry_engine import Site, _count_credentials, b64
from tests.test_sms_webhook import _fakewriter

SECRET = "hmac-secret"
SENDER = "+2348012345678"


def _verifier(mode: str = "hmac_required", *, require_nonce: bool = True) -> Any:
    return WebhookSignatureVerifier(
        WebhookSignatureConfig(
            mode=mode,
            shared_secret="" if mode == "token_only" else SECRET,
            max_skew_ms=10_000_000_000,
            require_nonce=require_nonce,
        )
    )


@pytest.mark.parametrize(
    ("mode", "require_nonce", "expected"),
    [
        ("token_only", True, False),
        ("hmac_required", True, True),
        ("token_and_hmac", True, True),
        ("hmac_required", False, False),
        ("token_and_hmac", False, False),
    ],
)
def test_only_a_signed_mandatory_nonce_ingress_authenticates_each_request(
    mode: str, require_nonce: bool, expected: bool
) -> None:
    verifier = _verifier(mode, require_nonce=require_nonce)
    assert verifier.authenticates_each_request is expected
    server = SMSWebhookServer(
        sms_action=AsyncMock(), token="t", signature_verifier=verifier
    )
    assert server.authenticates_each_request is expected
    assert (
        SMSWebhookServer(sms_action=AsyncMock(), token="t").authenticates_each_request
        is False
    )


def _request(text: str, *, nonce: str = "nonce-1", sign: bool = True) -> _HttpRequest:
    body = f"from={quote(SENDER)}&text={quote(text)}".encode()
    headers = {
        "x-ori-webhook-token": "t",
        "content-type": "application/x-www-form-urlencoded",
    }
    if sign:
        at = now_ms()
        headers |= {
            "x-ori-webhook-signature": sign_webhook_body(
                body, shared_secret=SECRET, signed_at_ms=at, nonce=nonce
            ),
            "x-ori-webhook-timestamp": str(at),
            "x-ori-webhook-nonce": nonce,
        }
    return _HttpRequest("POST", "/webhooks/sms/africastalking", headers, body)


async def _deliver(server: SMSWebhookServer, request: _HttpRequest) -> str:
    server._read_request = AsyncMock(return_value=request)  # type: ignore[method-assign]
    writer = _fakewriter()
    await server._handle_client(asyncio.StreamReader(), writer)
    return writer.buffer.decode("utf-8", errors="replace")


def _server(verifier: Any = None) -> tuple[SMSWebhookServer, AsyncMock, AsyncMock]:
    sms_action, registry_text = AsyncMock(), AsyncMock()
    sms_action.ingest_incoming_webhook.return_value = True
    server = SMSWebhookServer(
        sms_action=sms_action,
        token="t",
        signature_verifier=verifier,
        registry_text=registry_text,
    )
    return server, sms_action, registry_text


@pytest.mark.parametrize("token", ["ORI-POSSESS-V1", "ORI-ENROL-V1"])
async def test_a_signed_registry_text_reaches_the_registry_authenticated(
    token: str,
) -> None:
    server, sms_action, registry_text = _server(_verifier())
    text = f"{token} abc def"
    assert "200 OK" in await _deliver(server, _request(text))
    registry_text.assert_awaited_once_with(SENDER, text, True)
    sms_action.ingest_incoming_webhook.assert_not_awaited()


async def test_a_replayed_registry_text_reaches_nothing_twice() -> None:
    server, _sms, registry_text = _server(_verifier())
    request = _request("ORI-POSSESS-V1 abc def")
    assert "200 OK" in await _deliver(server, request)
    assert "401" in await _deliver(server, request)
    assert registry_text.await_count == 1


@pytest.mark.parametrize(
    "verifier",
    [None, "token_only", "no_nonce"],
    ids=["no-verifier", "token-only", "nonce-optional"],
)
async def test_a_registry_text_from_a_weaker_ingress_is_unauthenticated(
    verifier: str | None,
) -> None:
    built = {
        None: None,
        "token_only": _verifier("token_only"),
        "no_nonce": _verifier(require_nonce=False),
    }[verifier]
    server, sms_action, registry_text = _server(built)
    request = _request("ORI-POSSESS-V1 abc def", sign=verifier == "no_nonce")
    assert "200 OK" in await _deliver(server, request)
    registry_text.assert_awaited_once_with(SENDER, "ORI-POSSESS-V1 abc def", False)
    sms_action.ingest_incoming_webhook.assert_not_awaited()


@pytest.mark.parametrize(
    "text", ["YES-AB12CD34", "ORI-POSSESS-V1x a b", "ori-possess-v1 a b"]
)
async def test_any_other_text_takes_the_approval_path(text: str) -> None:
    server, sms_action, registry_text = _server(_verifier())
    assert "200 OK" in await _deliver(server, _request(text))
    registry_text.assert_not_awaited()
    sms_action.ingest_incoming_webhook.assert_awaited_once()


async def test_phone_text_delivers_a_possession_message_after_its_commit() -> None:
    store, send = AsyncMock(), AsyncMock()
    message = ("sms", SENDER, "ORI-POSSESS-V1 x y")
    store.run_approver_operation.return_value = Outcome({}, possession_message=message)
    service = RegistryService(store, AsyncMock(), send_possession=send)
    await service.phone_text("sms", SENDER, "ORI-ENROL-V1 a b", authenticated=True)
    store.run_approver_operation.assert_awaited_once()
    send.assert_awaited_once_with(*message)


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def test_a_phone_candidate_enrols_through_the_signed_webhook(
    store: StateStore,
) -> None:
    """Issue, authorize, then the candidate's own signed possession text commits."""
    site = Site(store)
    owner = await site.seeded()
    challenge = await site.issue(
        "enrol", {"approver_id": None, "channel": "sms", "value": SENDER}
    )
    (candidate,) = challenge["candidates"]
    await site.op(
        "enrol",
        {
            "challenge_id": challenge["challenge_id"],
            "candidate": candidate,
            "authorization": site.authorization(challenge, owner, "owner"),
            "possession": None,
        },
    )
    service = RegistryService(store, site.registry)

    async def to_registry(sender: str, text: str, authenticated: bool) -> None:
        await service.phone_text("sms", sender, text, authenticated=authenticated)

    server = SMSWebhookServer(
        sms_action=AsyncMock(),
        token="t",
        signature_verifier=_verifier(),
        registry_text=to_registry,
    )
    code = b64(b"\x01" * 16)
    text = f"ORI-POSSESS-V1 {challenge['challenge_id']} {code}"
    before = await _count_credentials(store)
    assert "200 OK" in await _deliver(server, _request(text))
    assert await _count_credentials(store) == before + 1


@pytest.mark.parametrize(
    ("verifier", "channels"),
    [(None, frozenset()), ("token_only", frozenset()), ("signed", frozenset({"sms"}))],
)
async def test_the_registry_takes_sms_only_from_a_webhook_that_signs_every_request(
    verifier: str | None, channels: frozenset[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.runtime import OriRuntime, _services

    captured: dict[str, Any] = {}

    async def prepare(store: Any, config: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return None

    monkeypatch.setattr(_services, "prepare_registry_service", prepare)
    runtime = OriRuntime(config_path="ori.yaml")
    if verifier is not None:
        built = _verifier("token_only") if verifier == "token_only" else _verifier()
        runtime._sms_webhook_server = SMSWebhookServer(
            sms_action=AsyncMock(), token="t", signature_verifier=built
        )
    await runtime._prepare_approver_registry()
    assert captured["authenticated_phone_channels"] == channels


async def test_the_runtime_hands_a_registry_text_to_the_registry_as_sms() -> None:
    from ori.runtime import OriRuntime

    runtime = OriRuntime(config_path="ori.yaml")
    await runtime._registry_phone_text(SENDER, "ORI-ENROL-V1 a b", True)  # no registry
    runtime._approver_registry = AsyncMock()
    await runtime._registry_phone_text(SENDER, "ORI-ENROL-V1 a b", False)
    runtime._approver_registry.phone_text.assert_not_awaited()  # dropped unread
    await runtime._registry_phone_text(SENDER, "ORI-ENROL-V1 a b", True)
    runtime._approver_registry.phone_text.assert_awaited_once_with(
        "sms", SENDER, "ORI-ENROL-V1 a b", authenticated=True
    )


async def test_a_registry_text_that_fails_to_apply_is_logged_without_the_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from ori.runtime import OriRuntime

    runtime = OriRuntime(config_path="ori.yaml")
    runtime._approver_registry = AsyncMock()
    runtime._approver_registry.phone_text.side_effect = RuntimeError("SECRET-CODE")
    text = "ORI-POSSESS-V1 challenge SECRET-CODE"
    with caplog.at_level("DEBUG"):
        await runtime._registry_phone_text(SENDER, text, True)
    assert "could not be applied" in caplog.text
    assert "SECRET-CODE" not in caplog.text


async def test_a_possession_code_goes_only_by_sms_and_a_refused_send_raises() -> None:
    from ori.runtime import OriRuntime

    runtime = OriRuntime(config_path="ori.yaml")
    runtime._sms_action = AsyncMock()
    runtime._sms_action.send.return_value = True
    await runtime._send_possession_code("sms", SENDER, "ORI-POSSESS-V1 a b")
    runtime._sms_action.send.assert_awaited_once_with("ORI-POSSESS-V1 a b", SENDER)
    with pytest.raises(RuntimeError, match="whatsapp"):
        await runtime._send_possession_code("whatsapp", SENDER, "ORI-POSSESS-V1 a b")
    runtime._sms_action.send.return_value = False
    with pytest.raises(RuntimeError) as refused:
        await runtime._send_possession_code("sms", SENDER, "ORI-POSSESS-V1 a SECRET")
    assert "SECRET" not in str(refused.value)


async def test_the_real_preparation_forwards_channels_and_sender(
    store: StateStore,
) -> None:
    from types import SimpleNamespace

    from ori.security.approvers.wiring import prepare_registry_service

    config: Any = SimpleNamespace(
        device=SimpleNamespace(
            id="edge-1", site_id="site-1", deployment_profile="development"
        ),
        security={"config_signature": {"verified": True}},
        device_policy={},
    )
    send = AsyncMock()
    service = await prepare_registry_service(
        store,
        config,
        authenticated_phone_channels=frozenset({"sms"}),
        send_possession=send,
    )
    assert service is not None
    assert service.registry.context.authenticated_phone_channels == frozenset({"sms"})
    assert service._send_possession is send


async def test_the_started_webhook_carries_the_registry_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from ori.runtime import OriRuntime
    from tests.package_layout import patch_runtime

    built: dict[str, Any] = {}

    class _Server:
        def __init__(self, **kwargs: Any) -> None:
            built.update(kwargs)

        async def start(self) -> None:
            return None

        async def serve_until(self, event: Any) -> None:
            return None

    patch_runtime(monkeypatch, "SMSWebhookServer", _Server)
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._sms_action = AsyncMock()
    config: Any = SimpleNamespace(
        actions=SimpleNamespace(
            sms={"incoming_webhook": {"enabled": True, "token": "t"}}
        )
    )
    task = await runtime._start_sms_webhook_if_enabled(config)
    assert task is not None
    await task
    assert built["registry_text"] == runtime._registry_phone_text


async def test_a_webhook_that_cannot_bind_leaves_no_authenticated_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from ori.runtime import OriRuntime
    from tests.package_layout import patch_runtime

    class _Unbindable:
        def __init__(self, **kwargs: Any) -> None:
            self.authenticates_each_request = True

        async def start(self) -> None:
            raise OSError("address in use")

    patch_runtime(monkeypatch, "SMSWebhookServer", _Unbindable)
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._sms_action = AsyncMock()
    config: Any = SimpleNamespace(
        actions=SimpleNamespace(
            sms={"incoming_webhook": {"enabled": True, "token": "t"}}
        )
    )
    assert await runtime._start_sms_webhook_if_enabled(config) is None
    assert runtime._sms_webhook_server is None


@pytest.mark.parametrize(
    "sender", ["whatsapp:+2348012345678", "tel:+2348012345678", "2348012345678"]
)
async def test_a_sender_that_is_not_canonical_reaches_the_registry_unchanged(
    sender: str,
) -> None:
    server, _sms, registry_text = _server(_verifier())
    body = f"from={quote(sender)}&text={quote('ORI-POSSESS-V1 a b')}".encode()
    at = now_ms()
    request = _HttpRequest(
        "POST",
        "/webhooks/sms/africastalking",
        {
            "x-ori-webhook-token": "t",
            "content-type": "application/x-www-form-urlencoded",
            "x-ori-webhook-signature": sign_webhook_body(
                body, shared_secret=SECRET, signed_at_ms=at, nonce="n-raw"
            ),
            "x-ori-webhook-timestamp": str(at),
            "x-ori-webhook-nonce": "n-raw",
        },
        body,
    )
    await _deliver(server, request)
    registry_text.assert_awaited_once_with(sender, "ORI-POSSESS-V1 a b", True)


async def test_a_padded_registry_text_never_takes_the_approval_path() -> None:
    server, sms_action, registry_text = _server(_verifier())
    await _deliver(server, _request(" ORI-POSSESS-V1 a b\n"))
    registry_text.assert_awaited_once_with(SENDER, " ORI-POSSESS-V1 a b\n", True)
    sms_action.ingest_incoming_webhook.assert_not_awaited()


async def test_a_message_field_registry_text_is_routed_too() -> None:
    server, sms_action, registry_text = _server(_verifier())
    body = f"from={quote(SENDER)}&message={quote('ORI-ENROL-V1 a b')}".encode()
    at = now_ms()
    request = _HttpRequest(
        "POST",
        "/webhooks/sms/africastalking",
        {
            "x-ori-webhook-token": "t",
            "content-type": "application/x-www-form-urlencoded",
            "x-ori-webhook-signature": sign_webhook_body(
                body, shared_secret=SECRET, signed_at_ms=at, nonce="n-msg"
            ),
            "x-ori-webhook-timestamp": str(at),
            "x-ori-webhook-nonce": "n-msg",
        },
        body,
    )
    await _deliver(server, request)
    registry_text.assert_awaited_once_with(SENDER, "ORI-ENROL-V1 a b", True)
    sms_action.ingest_incoming_webhook.assert_not_awaited()


@pytest.mark.parametrize(("require_nonce", "expected"), [(None, True), (False, False)])
def test_the_configured_verifier_decides_the_channel(
    require_nonce: bool | None, expected: bool
) -> None:
    """config -> verifier -> authenticates_each_request, nonce mandatory by default."""
    from ori.runtime import OriRuntime

    signature: dict[str, Any] = {"mode": "hmac_required", "shared_secret": SECRET}
    if require_nonce is not None:
        signature["require_nonce"] = require_nonce
    verifier = OriRuntime(config_path="ori.yaml")._build_sms_webhook_signature_verifier(
        {"signature": signature}
    )
    assert verifier is not None and verifier.authenticates_each_request is expected


@pytest.mark.parametrize("sms_enabled", ["true", "'on'", "false", None])
@pytest.mark.parametrize("enabled", ["on", "yes", "1", "true", True])
def test_a_webhook_enabled_in_any_spelling_has_its_secret_checked(
    enabled: Any,
    sms_enabled: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whatever `actions.sms.enabled` says: the runtime never reads it to start
    the webhook, so it cannot gate the webhook's checks."""
    from ori.config import Config, ConfigValidationError

    monkeypatch.delenv("ORI_SMS_WEBHOOK_HMAC_SECRET", raising=False)
    config = tmp_path / "ori.yaml"
    config.write_text(
        "device:\n  id: edge-1\n  name: Edge\n  location: Bench\n"
        'actions:\n  operator_contact: "+2348012345678"\n'
        "  sms:\n"
        + (f"    enabled: {sms_enabled}\n" if sms_enabled is not None else "")
        + "    AT_USERNAME: sandbox\n    AT_API_KEY: k\n"
        f"    incoming_webhook:\n      enabled: {enabled!r}\n      token: t\n"
        "      signature:\n        mode: hmac_required\n"
        "        shared_secret: ${ORI_SMS_WEBHOOK_HMAC_SECRET}\n"
    )
    with pytest.raises(ConfigValidationError, match="ORI_SMS_WEBHOOK_HMAC_SECRET"):
        Config.load(str(config))


async def test_stop_closes_a_webhook_whose_serve_task_never_ran() -> None:
    from ori.runtime import OriRuntime

    runtime = OriRuntime(config_path="ori.yaml")
    server = SMSWebhookServer(sms_action=AsyncMock(), token="t", port=0)
    await server.start()
    runtime._sms_webhook_server = server
    task = asyncio.create_task(server.serve_until(runtime._shutdown_event))
    task.cancel()  # before its first step: its `finally` never runs
    runtime._background_tasks.append(task)
    assert server._server is not None
    await runtime.stop()
    assert server._server is None
