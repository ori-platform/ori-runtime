# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Read-only runtime health/status RPC over Unix domain socket."""

import asyncio
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

_HEALTH_SOCKET_MAX_REQUEST_BYTES = 1024
_HEALTH_SOCKET_DEFAULT_DEV_FALLBACK_PATH = "/tmp/ori-health.sock"
_HEALTH_SOCKET_ALLOWED_REQUESTS = {"", "GET_HEALTH"}


class RuntimeHealthSocketServer:
    """Serve read-only runtime health snapshots over AF_UNIX socket."""

    def __init__(
        self,
        *,
        socket_path: str,
        mode: int,
        snapshot_provider: Callable[[], dict[str, Any] | Awaitable[dict[str, Any]]],
    ) -> None:
        self._socket_path = str(socket_path)
        self._mode = int(mode)
        self._snapshot_provider = snapshot_provider
        self._server: asyncio.AbstractServer | None = None
        self._bound_path: str = self._socket_path

    @property
    def bound_path(self) -> str:
        return self._bound_path

    async def start(self) -> str:
        """Start serving health requests and return bound socket path."""
        if os.name == "nt":
            raise RuntimeError("Unix domain sockets are unsupported on Windows.")

        try:
            self._bound_path = await asyncio.to_thread(
                self._prepare_socket_path,
                self._socket_path,
            )
            self._server = await asyncio.start_unix_server(
                self._handle_client,
                path=self._bound_path,
            )
            await asyncio.to_thread(os.chmod, self._bound_path, self._mode)
            return self._bound_path
        except PermissionError as exc:
            # Developer-safe fallback for non-root local environments.
            if self._socket_path == "/run/ori/health.sock":
                logger.warning(
                    "[runtime] health socket path %s not writable (%s); falling back to %s",
                    self._socket_path,
                    exc,
                    _HEALTH_SOCKET_DEFAULT_DEV_FALLBACK_PATH,
                )
                self._bound_path = await asyncio.to_thread(
                    self._prepare_socket_path,
                    _HEALTH_SOCKET_DEFAULT_DEV_FALLBACK_PATH,
                )
                self._server = await asyncio.start_unix_server(
                    self._handle_client,
                    path=self._bound_path,
                )
                await asyncio.to_thread(os.chmod, self._bound_path, self._mode)
                return self._bound_path
            raise

    async def close(self) -> None:
        """Stop serving and cleanup socket file."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        await asyncio.to_thread(self._cleanup_bound_socket)

    def _prepare_socket_path(self, socket_path: str) -> str:
        path = Path(socket_path)
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            st = path.lstat()
            if stat.S_ISSOCK(st.st_mode):
                path.unlink()
            else:
                raise RuntimeError(
                    f"health socket path {socket_path!r} exists and is not a socket"
                )
        return str(path)

    def _cleanup_bound_socket(self) -> None:
        path = Path(self._bound_path)
        if not path.exists():
            return
        try:
            st = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(st.st_mode):
            path.unlink()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        response: dict[str, Any]
        try:
            raw = await reader.read(_HEALTH_SOCKET_MAX_REQUEST_BYTES + 1)
            if len(raw) > _HEALTH_SOCKET_MAX_REQUEST_BYTES:
                response = self._error_response(
                    code="request_too_large",
                    detail="request exceeded maximum size",
                )
            else:
                request = raw.decode("utf-8", errors="ignore").strip()
                if request not in _HEALTH_SOCKET_ALLOWED_REQUESTS:
                    response = self._error_response(
                        code="unsupported_request",
                        detail="send GET_HEALTH or empty request",
                    )
                else:
                    snapshot = self._snapshot_provider()
                    if asyncio.iscoroutine(snapshot):
                        snapshot = await snapshot
                    response = {
                        "schema_version": 1,
                        "ok": True,
                        "health": snapshot,
                    }
        except Exception as exc:
            response = self._error_response(
                code="internal_error",
                detail=str(exc),
            )

        try:
            payload = json.dumps(response, separators=(",", ":")).encode("utf-8")
            writer.write(payload + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    def _error_response(self, *, code: str, detail: str) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "ok": False,
            "error": {"code": code, "detail": detail},
        }
