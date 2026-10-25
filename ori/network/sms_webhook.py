# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Minimal async HTTP ingress for Africa's Talking SMS webhooks."""

import asyncio
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

from ori.security.webhook_signatures import WebhookSignatureVerifier
from ori.utils.path_utils import shown
from ori.utils.strict_json import unique_members

logger = logging.getLogger(__name__)

_MAX_HEADER_BYTES = 64 * 1024
_MAX_BODY_BYTES = 64 * 1024
_CHUNK_BYTES = 4096
_CONTENT_LENGTH = re.compile(r"[0-9]{1,10}")
#: Headers whose value decides framing or authentication: one of them repeated
#: would let two readers take different values, so the request is refused.
_SINGLE_HEADERS = frozenset(
    {"content-length", "content-type", "authorization", "x-ori-webhook-token"}
)
_RATE_WINDOW_SECONDS: float = 60.0
# Per peer address, before anything is read: a CPU backstop, not an approval
# budget. Every message arrives from the bridge's one address, so a limit here
# cannot tell an operator from a stranger; SMSAction limits each allowlisted
# sender after its allowlist, and the bridge limits senders (ori-gateway#138).
_RATE_MAX_REQUESTS: int = 600


@dataclass
class _HttpRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class SMSWebhookServer:
    """Token-protected HTTP server that forwards inbound SMS to SMSAction."""

    def __init__(
        self,
        sms_action: Any,
        host: str = "127.0.0.1",
        port: int = 8080,
        path: str = "/webhooks/sms/africastalking",
        token: str = "",
        signature_verifier: WebhookSignatureVerifier | None = None,
        state_store: Any = None,
        allowed_source_cidrs: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        self._sms_action = sms_action
        self._host = host
        self._port = int(port)
        self._path = path
        self._token = token
        self._signature_verifier = signature_verifier
        self._single_headers = _SINGLE_HEADERS | (
            signature_verifier.header_names
            if signature_verifier is not None
            else frozenset()
        )
        self._state_store = state_store
        self._server: asyncio.AbstractServer | None = None
        self._ip_request_log: dict[str, list[float]] = {}
        self._allowed_source_networks = tuple(
            ip_network(str(cidr).strip(), strict=False)
            for cidr in (allowed_source_cidrs or [])
            if str(cidr).strip()
        )

    @property
    def port(self) -> int:
        server = self._server
        sockets = getattr(server, "sockets", None) if server is not None else None
        if sockets:
            return int(sockets[0].getsockname()[1])
        return self._port

    async def serve_until(self, shutdown_event: asyncio.Event) -> None:
        await self.start()
        try:
            await shutdown_event.wait()
        finally:
            await self.stop()

    async def start(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._handle_client, self._host, self._port
        )
        logger.info(
            "SMSWebhookServer: listening on host=%s port=%d path=%s",
            shown(self._host),
            self.port,
            shown(self._path),
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    def _rate_check(self, peer_ip: str) -> bool:
        """Return True when the request is within rate limits, False to reject."""
        now = time.monotonic()
        cutoff = now - _RATE_WINDOW_SECONDS
        history = self._ip_request_log.get(peer_ip) or []
        history = [t for t in history if t > cutoff]
        if len(history) >= _RATE_MAX_REQUESTS:
            self._ip_request_log[peer_ip] = history
            return False
        history.append(now)
        self._ip_request_log[peer_ip] = history
        return True

    def _source_allowed(self, peer_ip: str) -> bool:
        """Return True when peer_ip is allowed by configured source CIDRs."""
        if not self._allowed_source_networks:
            return True
        try:
            address = ip_address(peer_ip)
        except ValueError:
            return False
        return any(address in network for network in self._allowed_source_networks)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        get_extra = getattr(writer, "get_extra_info", None)
        peer = cast(
            "tuple[Any, ...] | None",
            get_extra("peername") if callable(get_extra) else None,
        )
        peer_ip = str(peer[0]) if peer else "unknown"
        try:
            if not self._source_allowed(peer_ip):
                logger.warning(
                    "SMSWebhookServer: rejected request from disallowed source %s",
                    peer_ip,
                )
                await self._respond(writer, 403, "forbidden")
                return

            if not self._rate_check(peer_ip):
                logger.warning("SMSWebhookServer: rate limit exceeded for %s", peer_ip)
                await self._respond(writer, 429, "too many requests")
                return

            request = await self._read_request(reader)
            if request is None:
                await self._respond(writer, 400, "bad request")
                return

            url = urlsplit(request.path)
            if request.method != "POST":
                await self._respond(writer, 405, "method not allowed")
                return
            if url.path != self._path:
                await self._respond(writer, 404, "not found")
                return
            if self._token and not self._authorized(request.headers):
                await self._respond(writer, 401, "unauthorized")
                return
            if self._signature_verifier is not None:
                verification = await self._signature_verifier.verify(
                    headers=request.headers,
                    body=request.body,
                    state_store=self._state_store,
                    source="sms_webhook",
                )
                if not verification.accepted:
                    logger.warning(
                        "SMSWebhookServer: rejected unsigned or replayed webhook reason=%s",
                        verification.reason,
                    )
                    await self._respond(writer, 401, "unauthorized")
                    return

            payload = self._decode_payload(request.headers, request.body)
            ok = await self._sms_action.ingest_incoming_webhook(payload)
            if ok:
                await self._respond(writer, 200, "ok")
                return
            await self._respond(writer, 400, "invalid payload")
        except Exception:
            logger.exception("SMSWebhookServer: unexpected error handling request")
            await self._respond(writer, 500, "internal error")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _read_request(self, reader: asyncio.StreamReader) -> _HttpRequest | None:
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = await reader.read(_CHUNK_BYTES)
            if not chunk:
                return None
            raw += chunk
            if len(raw) > _MAX_HEADER_BYTES:
                return None

        head, body = raw.split(b"\r\n\r\n", 1)
        try:
            # Strict: a replaced byte could make two header values compare equal.
            lines = head.decode("utf-8").split("\r\n")
        except UnicodeDecodeError:
            return None
        if not lines:
            return None

        request_line = lines[0].split(" ")
        if len(request_line) < 3:
            return None
        method = request_line[0]  # case-sensitive (RFC 9110)
        path = request_line[1]

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if line[:1] in (" ", "\t"):
                return None  # an obsolete folded line (RFC 9112 5.2)
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            # No whitespace around a name (RFC 9112 5.1), and ASCII only: a
            # Unicode case mapping could turn it into a header read here.
            if not name or name != name.strip(" \t") or not name.isascii():
                return None
            name = name.lower()
            if name in headers and name in self._single_headers:
                return None
            headers[name] = value.strip(" \t")

        length_text = headers.get("content-length", "0")
        if not _CONTENT_LENGTH.fullmatch(length_text) or "transfer-encoding" in headers:
            # A chunked body is not read here, so one is refused, not misread.
            return None
        content_length = int(length_text)
        if content_length > _MAX_BODY_BYTES:
            return None
        if len(body) > _MAX_BODY_BYTES:
            return None
        if len(body) > content_length:
            # Bytes past the declared length would be read and signed as body.
            return None
        while len(body) < content_length:
            chunk = await reader.read(content_length - len(body))
            if not chunk:
                return None
            body += chunk
            if len(body) > _MAX_BODY_BYTES:
                return None

        return _HttpRequest(method=method, path=path, headers=headers, body=body)

    def _authorized(self, headers: dict[str, str]) -> bool:
        """Whether a header carries the token, compared as bytes in constant time."""
        token = self._token.encode("utf-8")
        presented = headers.get("x-ori-webhook-token", "")
        if hmac.compare_digest(presented.encode("utf-8"), token):
            return True
        auth = headers.get("authorization", "")
        if auth[:7].lower() != "bearer ":
            return False
        return hmac.compare_digest(auth[7:].strip(" \t").encode("utf-8"), token)

    def _decode_payload(self, headers: dict[str, str], body: bytes) -> dict[str, Any]:
        ctype = headers.get("content-type", "").lower()
        text = body.decode("utf-8", errors="replace")
        if "application/json" in ctype:
            try:
                parsed = json.loads(
                    text or "{}",
                    object_pairs_hook=unique_members(),
                )
            except (ValueError, RecursionError):
                return {}
            if isinstance(parsed, dict):
                return parsed
            return {}
        parsed_qs = parse_qs(text, keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in parsed_qs.items()}

    async def _respond(
        self, writer: asyncio.StreamWriter, status: int, message: str
    ) -> None:
        reason = {
            200: "OK",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            429: "Too Many Requests",
            500: "Internal Server Error",
        }.get(status, "OK")
        body = message.encode("utf-8")
        response = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8") + body
        writer.write(response)
        await writer.drain()
