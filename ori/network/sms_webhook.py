# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Minimal async HTTP ingress for Africa's Talking SMS webhooks."""

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

logger = logging.getLogger(__name__)

_MAX_HEADER_BYTES = 64 * 1024
_CHUNK_BYTES = 4096


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
        host: str = "0.0.0.0",
        port: int = 8080,
        path: str = "/webhooks/sms/africastalking",
        token: str = "",
    ) -> None:
        self._sms_action = sms_action
        self._host = host
        self._port = int(port)
        self._path = path
        self._token = token
        self._server: asyncio.AbstractServer | None = None

    @property
    def port(self) -> int:
        if self._server and self._server.sockets:
            return int(self._server.sockets[0].getsockname()[1])
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
            "SMSWebhookServer: listening on %s:%d%s",
            self._host,
            self.port,
            self._path,
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
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
            query = parse_qs(url.query, keep_blank_values=True)
            if self._token and not self._authorized(request.headers, query):
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
        lines = head.decode("utf-8", errors="replace").split("\r\n")
        if not lines:
            return None

        request_line = lines[0].split(" ")
        if len(request_line) < 3:
            return None
        method = request_line[0].upper()
        path = request_line[1]

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        content_length = int(headers.get("content-length", "0") or "0")
        if content_length < 0:
            return None
        while len(body) < content_length:
            chunk = await reader.read(content_length - len(body))
            if not chunk:
                return None
            body += chunk

        return _HttpRequest(method=method, path=path, headers=headers, body=body)

    def _authorized(
        self, headers: dict[str, str], query: dict[str, list[str]] | None = None
    ) -> bool:
        token_header = headers.get("x-ori-webhook-token", "")
        if token_header == self._token:
            return True
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip() == self._token
        if query:
            token_values = query.get("token") or []
            if token_values and token_values[0] == self._token:
                logger.warning(
                    "SMSWebhookServer: authenticated inbound webhook via query token fallback"
                )
                return True
        return False

    def _decode_payload(self, headers: dict[str, str], body: bytes) -> dict[str, Any]:
        ctype = headers.get("content-type", "").lower()
        text = body.decode("utf-8", errors="replace")
        if "application/json" in ctype:
            parsed = json.loads(text or "{}")
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
            404: "Not Found",
            405: "Method Not Allowed",
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
