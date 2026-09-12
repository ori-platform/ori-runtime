# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Read-only runtime health/status RPC over Unix domain socket."""

import asyncio
import errno
import json
import logging
import os
import socket
import stat
from pathlib import Path
from typing import Any, Awaitable, Callable

from ori.utils.path_utils import shown

# The ways "the packaged default socket path is not usable on this host"
# presents. Anything else is a real failure of this socket rather than of the
# path, and is raised: an address already in use is another runtime holding it.
# Bounded so a peer that accepts the connection and then says nothing cannot
# hold up startup. Long enough that a busy device answers, short enough that a
# runtime is not waiting on it.
_LISTENER_PROBE_TIMEOUT_S = 1.0

_FALLBACK_ERRNOS: frozenset[int] = frozenset(
    {
        errno.EACCES,  # no permission to create or bind under /run/ori
        errno.EPERM,
        errno.ENOENT,  # /run does not exist, as on macOS
        errno.EROFS,  # /run exists on a read-only filesystem
        errno.ENOTDIR,  # a component of the path is not a directory
    }
)

logger = logging.getLogger(__name__)

_HEALTH_SOCKET_MAX_REQUEST_BYTES = 1024
_HEALTH_SOCKET_DEFAULT_DEV_FALLBACK_PATH = "/tmp/ori-health.sock"
_HEALTH_SOCKET_ALLOWED_REQUESTS = {"", "GET_HEALTH"}


def _socket_identity(socket_path: str) -> tuple[int, int, int] | None:
    """Device, inode and creation time of the socket at *socket_path*, or None.

    A pathname is not an identity. Two runtimes can hold the same one in
    succession, and the file at it after a restart is a different object that
    happens to have the same name.

    Nor is device and inode alone: Linux reuses an inode number immediately
    after the file holding it is unlinked, so a replacement binding the same
    pathname was measured taking the departing socket's exact inode. macOS did
    not, which is why the host suite agreed with a rule the hosted runner
    refuted on all three interpreters.

    The creation time narrows it and does not close it. A handover fast enough
    to finish inside the filesystem's timestamp granularity was measured
    producing a byte-identical triple for two different sockets, so this is a
    best-effort discriminator rather than a proof of ownership. What actually
    protects a running replacement is the listener check in
    :func:`_remove_socket_file`, which does not depend on identity at all.
    """
    try:
        st = Path(socket_path).lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    if not stat.S_ISSOCK(st.st_mode):
        return None
    return (st.st_dev, st.st_ino, st.st_ctime_ns)


def _remove_socket_file(
    socket_path: str, identity: tuple[int, int, int] | None
) -> None:
    """Remove *socket_path* only while it is still the file *identity* named.

    Checking that the pathname holds *a* socket is not enough. A runtime that
    stops listening and then cleans up has a window in which a replacement can
    detect the stale file, bind its own, and start answering — and the departing
    runtime's cleanup then deletes the newcomer's live socket, leaving a
    running device with no health surface and no error anywhere. Identity is
    device and inode, so a pathname that now resolves to a different file is
    left alone.
    """
    if identity is None:
        return
    if _socket_identity(socket_path) != identity:
        return
    # This, not the comparison above, is the guarantee. A stat identity was
    # measured tying on Linux for a handover fast enough to reuse the inode
    # inside the filesystem's timestamp granularity, so it narrows the case and
    # cannot settle it. The property actually worth protecting is simpler than
    # ownership and needs no identity: never remove a socket some process is
    # answering on, whoever created it. Our own listener is closed before
    # cleanup runs, so this does not refuse our own file.
    if _socket_has_a_listener(Path(socket_path)):
        return
    Path(socket_path).unlink(missing_ok=True)


def _socket_has_a_listener(path: Path) -> bool:
    """Whether something is accepting connections on *path* right now.

    A refused connection is the one answer that proves the file is stale: the
    socket exists and no process is bound to it. Every other outcome —
    a successful connect, a timeout, a permission error, anything unexpected —
    is treated as a live listener, because the consequence of guessing wrong in
    that direction is unlinking a socket a running device is serving on, and
    the consequence of guessing wrong the other way is a refusal an operator
    can see and clear.
    """
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(_LISTENER_PROBE_TIMEOUT_S)
    try:
        probe.connect(str(path))
        return True
    except ConnectionRefusedError:
        return False
    except FileNotFoundError:
        return False
    except OSError:
        return True
    finally:
        probe.close()


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
        # Device and inode of the socket file this server actually bound.
        self._bound_identity: tuple[int, int, int] | None = None

    @property
    def bound_path(self) -> str:
        return self._bound_path

    async def start(self) -> str:
        """Start serving health requests and return bound socket path."""
        if os.name == "nt":
            raise RuntimeError("Unix domain sockets are unsupported on Windows.")

        try:
            return await self._bind(self._socket_path)
        except OSError as exc:
            # Developer-safe fallback for non-root local environments.
            #
            # `PermissionError` alone was the wrong set. The same condition —
            # the packaged default path is not usable on this host — arrives as
            # `FileNotFoundError` where `/run` does not exist, and as
            # `OSError(EROFS)` where it exists on a read-only filesystem, so on
            # a developer machine the fallback written for exactly this case
            # never fired and the health surface was lost for the life of the
            # process.
            #
            # Filtered by errno rather than widened to every `OSError`: a socket
            # already in use is another runtime on this path, and falling back
            # from that would hide it behind a working health surface on a
            # different one.
            if (
                exc.errno in _FALLBACK_ERRNOS
                and self._socket_path == "/run/ori/health.sock"
            ):
                logger.warning(
                    "[runtime] health socket path %s is not usable here (%s); "
                    "falling back to %s",
                    shown(self._socket_path),
                    exc,
                    shown(_HEALTH_SOCKET_DEFAULT_DEV_FALLBACK_PATH),
                )
                return await self._bind(_HEALTH_SOCKET_DEFAULT_DEV_FALLBACK_PATH)
            raise

    async def _bind(self, socket_path: str) -> str:
        """Bind *socket_path*, or leave nothing behind.

        Startup is transactional past the bind. `_server` used to be assigned
        the moment the listener existed and `chmod` applied afterwards, so a
        `chmod` that failed raised out of `start()` with a live listener nobody
        held: the caller discards the object on the exception, `close()` is
        never reached, and the socket keeps serving on permissions that were
        never applied. A partial start must not be reachable, whether this is
        the configured path or the fallback.
        """
        bound = await asyncio.to_thread(self._prepare_socket_path, socket_path)
        server = await asyncio.start_unix_server(self._handle_client, path=bound)
        # Taken the moment the file exists, so a failure applying the mode
        # removes the file this server bound rather than whatever holds the name.
        provisional = await asyncio.to_thread(_socket_identity, bound)
        try:
            await asyncio.to_thread(os.chmod, bound, self._mode)
        except BaseException:
            server.close()
            await server.wait_closed()
            await asyncio.to_thread(_remove_socket_file, bound, provisional)
            raise
        self._server = server
        self._bound_path = bound
        # Re-read after the mode is applied: `chmod` is a metadata change, so it
        # moves the inode's ctime. Holding the earlier reading meant the
        # identity never matched again and a runtime stopped removing its own
        # socket on shutdown, leaving a stale file for every clean stop.
        self._bound_identity = await asyncio.to_thread(_socket_identity, bound)
        return bound

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
            if not stat.S_ISSOCK(st.st_mode):
                raise RuntimeError(
                    f"health socket path {socket_path!r} exists and is not a socket"
                )
            # An existing socket file says nothing about whether anything is
            # listening on it. Unlinking unconditionally meant a second runtime
            # took the pathname from a live first one, which stayed running and
            # unreachable while the fleet read the newcomer — so `EADDRINUSE`,
            # the case this module refuses to fall back from, could never occur.
            if _socket_has_a_listener(path):
                raise OSError(
                    errno.EADDRINUSE,
                    "another process is already serving this health socket",
                    str(path),
                )
            path.unlink()
        return str(path)

    def _cleanup_bound_socket(self) -> None:
        _remove_socket_file(self._bound_path, self._bound_identity)
        self._bound_identity = None

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
