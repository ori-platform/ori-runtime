# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The authenticated local operator socket (operator-socket/v1).

A person at the device reaches the running runtime here, and only here, to
record what they observed of an uncertain Tier C dispatch. The caller is
established from the kernel's peer credentials and nothing else; the request
is one JSON object whose members are closed; the answer is the runtime's.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import json
import logging
import os
import pwd
import re
import socket
import sqlite3
import stat
import struct
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from ori.reasoning.tier_c_admission import RECONCILE_REASONS
from ori.runtime_health_socket import (
    _remove_socket_file,
    _socket_has_a_listener,
    _socket_identity,
)
from ori.utils.path_utils import shown

logger = logging.getLogger(__name__)

SOCKET_NAME: Final = "operator.sock"
SYSTEM_RUNTIME_DIRECTORY: Final = Path("/run/ori")
OPERATOR_UID_FILE: Final = "operator-uid"
RECONCILE_OPERATION: Final = "reconcile_tier_c"
COMMISSION_OPERATION: Final = "evidence_commission"
RECONCILE_MEMBERS: Final = frozenset(
    {"operation", "proposal_id", "device_id", "zone_id", "outcome", "reason", "note"}
)
RECONCILE_OUTCOMES: Final = ("executed", "not-executed")
NOTE_MAX_BYTES: Final = 280
ENTRY_POINT: Final = "local_operator_socket"
#: Far above the largest valid request (the note is 280 bytes), finite so a
#: peer cannot stream forever.
MAX_REQUEST_BYTES: Final = 8192
REQUEST_TIMEOUT_S: Final = 5.0
#: The kernel's value for an audit login user ID that was never set.
UNSET_LOGIN_UID: Final = 4294967295
MAX_UID: Final = 4294967294

#: Every `error.code` the socket answers as a refusal or an operational outcome,
#: closed by the contract (exit 2 at the bridge). `internal_error` is not one of
#: them: it is the contract's unexpected runtime fault, exit 1 at the bridge.
RECONCILE_ERRORS: Final = frozenset(
    {
        "invalid_arguments",
        "unauthenticated",
        "device_mismatch",
        "unknown_proposal",
        "zone_mismatch",
        "already_reconciled",
        "not_uncertain",
        "runtime_store_unavailable",
        "state_store_locked",
        "cancelled",
    }
)

_UID_TEXT = re.compile(rb"[1-9][0-9]{0,9}\n?")
# Linux's SO_PEERPIDFD (6.5 and later); Python names it only on recent builds.
_SO_PEERPIDFD: Final = getattr(socket, "SO_PEERPIDFD", 77)


class OperatorRequestError(Exception):
    """A refusal with its contract code; the detail never carries state."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ReconcileRequest:
    proposal_id: str
    device_id: str
    zone_id: str
    outcome: str
    reason: str
    note: str | None

    def as_request(self) -> dict[str, Any]:
        return {
            "operation": RECONCILE_OPERATION,
            "proposal_id": self.proposal_id,
            "device_id": self.device_id,
            "zone_id": self.zone_id,
            "outcome": self.outcome,
            "reason": self.reason,
            "note": self.note,
        }


@dataclass(frozen=True)
class PeerCredentials:
    """What the kernel reports for the connection's peer."""

    uid: int
    pid: int | None
    login_uid: int | None


def parse_request(raw: bytes) -> dict[str, Any]:
    """One JSON object, with no member named twice."""

    def refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise OperatorRequestError(
                    "invalid_arguments", "a request member is named twice"
                )
            value[key] = item
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=refuse_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OperatorRequestError(
            "invalid_arguments", "the request must be one JSON object"
        ) from exc
    if not isinstance(value, dict):
        raise OperatorRequestError(
            "invalid_arguments", "the request must be one JSON object"
        )
    return value


def validate_note(note: str) -> None:
    if len(note.encode("utf-8", errors="surrogatepass")) > NOTE_MAX_BYTES:
        raise OperatorRequestError(
            "invalid_arguments", f"the note exceeds {NOTE_MAX_BYTES} bytes of UTF-8"
        )
    if any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in note):
        raise OperatorRequestError(
            "invalid_arguments", "the note carries a control character"
        )
    try:
        note.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise OperatorRequestError(
            "invalid_arguments", "the note is not valid UTF-8"
        ) from exc


def validate_reconcile_request(request: Mapping[str, Any]) -> ReconcileRequest:
    """The request's closed members and sets, decided before any state is read."""
    operation = request.get("operation")
    if operation == COMMISSION_OPERATION:
        raise OperatorRequestError(
            "invalid_arguments", "this runtime does not serve evidence_commission here"
        )
    if operation != RECONCILE_OPERATION:
        raise OperatorRequestError(
            "invalid_arguments", "the request names no operation this socket serves"
        )
    members = set(request)
    if members != RECONCILE_MEMBERS:
        missing = sorted(RECONCILE_MEMBERS - members)
        if missing:
            raise OperatorRequestError(
                "invalid_arguments", "missing request member: " + ", ".join(missing)
            )
        raise OperatorRequestError(
            "invalid_arguments",
            f"{len(members - RECONCILE_MEMBERS)} request member(s) this operation "
            "does not accept",
        )
    for name in ("proposal_id", "device_id", "zone_id"):
        value = request[name]
        if not isinstance(value, str) or not value:
            raise OperatorRequestError(
                "invalid_arguments", f"{name} must be a non-empty string"
            )
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise OperatorRequestError(
                "invalid_arguments", f"{name} is not valid UTF-8"
            ) from exc
    if request["outcome"] not in RECONCILE_OUTCOMES:
        raise OperatorRequestError(
            "invalid_arguments", "outcome must be executed or not-executed"
        )
    if request["reason"] not in RECONCILE_REASONS:
        raise OperatorRequestError(
            "invalid_arguments",
            "reason must be one of " + ", ".join(sorted(RECONCILE_REASONS)),
        )
    note = request["note"]
    if note is not None:
        if not isinstance(note, str):
            raise OperatorRequestError(
                "invalid_arguments", "note must be a string or null"
            )
        validate_note(note)
    return ReconcileRequest(
        proposal_id=request["proposal_id"],
        device_id=request["device_id"],
        zone_id=request["zone_id"],
        outcome=request["outcome"],
        reason=request["reason"],
        note=note,
    )


# ─── peer credentials ─────────────────────────────────────────────────────────


def peer_credentials(sock: Any) -> PeerCredentials | None:
    """The peer's effective user ID and, where it can be pinned, its login UID.

    None when the kernel reports nothing usable; the caller is then
    unauthenticated. The audit login user ID is read for the process pinned
    by `SO_PEERPIDFD` and kept only if that process is still the one the pid
    names after the read, so a pid reused in between is never recorded.
    """
    if sock is None:
        return None
    if sys.platform.startswith("linux"):
        try:
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            pid, uid, _gid = struct.unpack("=iII", raw)
        except (OSError, struct.error):
            return None
        return PeerCredentials(
            uid=int(uid),
            pid=int(pid) if pid > 0 else None,
            login_uid=_pinned_login_uid(sock, pid),
        )
    if sys.platform == "darwin" and hasattr(socket, "LOCAL_PEERCRED"):
        try:
            # xucred begins with cr_version (u32), then cr_uid (uid_t).
            raw = sock.getsockopt(0, socket.LOCAL_PEERCRED, 8)
            _version, uid = struct.unpack("=II", raw)
        except (OSError, struct.error):
            return None
        return PeerCredentials(uid=int(uid), pid=None, login_uid=None)
    return None


def _pinned_login_uid(sock: Any, pid: int) -> int | None:
    if not sys.platform.startswith("linux") or pid <= 0:
        return None
    try:
        pidfd = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERPIDFD)
    except OSError:
        return None
    try:
        if _pidfd_pid(pidfd) != pid:
            return None
        try:
            text = _read_login_uid(pid)
        except (OSError, UnicodeDecodeError):
            return None
        # The pidfd still names that pid after the read, so the process was
        # alive throughout and its pid was not reused in between. Read from our
        # own fdinfo: a service may not signal another user's process.
        if _pidfd_pid(pidfd) != pid:
            return None
    except (OSError, ValueError):
        return None
    finally:
        os.close(pidfd)
    value = text.strip()
    if not value.isascii() or not value.isdigit():
        return None
    login_uid = int(value)
    return None if login_uid == UNSET_LOGIN_UID else login_uid


def _read_login_uid(pid: int) -> str:
    return Path(f"/proc/{pid}/loginuid").read_text(encoding="ascii")


def _pidfd_pid(pidfd: int) -> int | None:
    for line in Path(f"/proc/self/fdinfo/{pidfd}").read_text().splitlines():
        if line.startswith("Pid:"):
            return int(line.split(":", 1)[1])
    return None


def account_name(uid: int) -> str | None:
    """Diagnostic only: recorded, never compared."""
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError):
        return None


# ─── the installed operator identity ──────────────────────────────────────────


@dataclass(frozen=True)
class FilesystemView:
    """The two reads the operator identity rests on, replaceable only in tests."""

    lstat: Callable[[str], os.stat_result]
    read_nofollow: Callable[[str], tuple[os.stat_result, bytes]]


def _read_nofollow(path: str) -> tuple[os.stat_result, bytes]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return info, b""
        return info, os.read(fd, 64)
    finally:
        os.close(fd)


REAL_FILESYSTEM: Final = FilesystemView(lstat=os.lstat, read_nofollow=_read_nofollow)


def _trusted(info: os.stat_result) -> bool:
    return info.st_uid == 0 and not info.st_mode & 0o022


def read_operator_uid(
    install_root: Path | None,
    *,
    service_uid: int,
    fs: FilesystemView = REAL_FILESYSTEM,
) -> int | None:
    """The installed operator identity, or None when none is validly installed.

    Read only when the file, the install root and every ancestor are owned by
    user ID 0 and writable by no one else, the file is not a symbolic link,
    and it holds one decimal user ID without leading zeros, other than 0 and
    the service account's, optionally followed by one LF.
    """
    if install_root is None or not install_root.is_absolute():
        return None
    directories = [install_root, *install_root.parents]
    try:
        for directory in directories:
            info = fs.lstat(str(directory))
            if not stat.S_ISDIR(info.st_mode) or not _trusted(info):
                return None
        info, content = fs.read_nofollow(str(install_root / OPERATOR_UID_FILE))
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or not _trusted(info):
        return None
    if not _UID_TEXT.fullmatch(content):
        return None
    uid = int(content.rstrip(b"\n"))
    if uid > MAX_UID or uid == service_uid:
        return None
    return uid


def install_root_for_prefix(prefix: str) -> Path | None:
    """The install root whose release this interpreter runs, or None.

    An installed runtime runs `<root>/current/venv/bin/python`, which Python
    may report through `current` or through the release it points at.
    """
    venv = Path(prefix)
    if not venv.is_absolute() or venv.name != "venv":
        return None
    release = venv.parent
    if release.name == "current":
        return release.parent
    if release.parent.name == "releases":
        return release.parent.parent
    return None


def runtime_directory(environ: Mapping[str, str] | None = None) -> Path | None:
    """The directory systemd created for this service, when it created one."""
    value = (os.environ if environ is None else environ).get("RUNTIME_DIRECTORY", "")
    if not value or ":" in value or "\x00" in value:
        return None
    path = Path(value)
    return path if path.is_absolute() else None


# ─── access-control entries ───────────────────────────────────────────────────

_ACL_XATTR: Final = "system.posix_acl_access"
_ACL_VERSION: Final = 2
_ACL_USER_OBJ: Final = 0x01
_ACL_USER: Final = 0x02
_ACL_GROUP_OBJ: Final = 0x04
_ACL_GROUP: Final = 0x08
_ACL_MASK: Final = 0x10
_ACL_OTHER: Final = 0x20
_ACL_UNDEFINED_ID: Final = 0xFFFFFFFF


class AccessGrantError(Exception):
    """The operator identity could not be granted what connecting needs."""


def _encode_acl(entries: list[tuple[int, int, int]]) -> bytes:
    body = b"".join(
        struct.pack("<HHI", tag, perm, ident) for tag, perm, ident in sorted(entries)
    )
    return struct.pack("<I", _ACL_VERSION) + body


def _decode_acl(raw: bytes) -> list[tuple[int, int, int]]:
    if len(raw) < 4 or (len(raw) - 4) % 8:
        raise AccessGrantError("unreadable access-control list")
    (version,) = struct.unpack_from("<I", raw)
    if version != _ACL_VERSION:
        raise AccessGrantError("unsupported access-control list version")
    return [
        struct.unpack_from("<HHI", raw, 4 + 8 * i) for i in range((len(raw) - 4) // 8)
    ]


def _exact_acl(owner_perm: int, operator_uid: int, operator_perm: int) -> bytes:
    """Owner, the operator identity, and no one else."""
    return _encode_acl(
        [
            (_ACL_USER_OBJ, owner_perm, _ACL_UNDEFINED_ID),
            (_ACL_USER, operator_perm, operator_uid),
            (_ACL_GROUP_OBJ, 0, _ACL_UNDEFINED_ID),
            (_ACL_MASK, operator_perm, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, 0, _ACL_UNDEFINED_ID),
        ]
    )


def _set_exact_access(
    path: Path, mode: int, operator_uid: int | None, operator_perm: int
) -> None:
    """Mode *mode* for the owner, and *operator_perm* for the operator alone."""
    os.chmod(path, mode)
    if operator_uid is None:
        _remove_acl(path)
        return
    if not sys.platform.startswith("linux"):
        raise AccessGrantError("this platform has no access-control lists")
    try:
        os.setxattr(
            path, _ACL_XATTR, _exact_acl((mode >> 6) & 0o7, operator_uid, operator_perm)
        )
    except OSError as exc:
        raise AccessGrantError(f"{shown(str(path))}: {exc.strerror or exc}") from exc


def _remove_acl(path: Path) -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        os.removexattr(path, _ACL_XATTR)
    except OSError as exc:
        if exc.errno not in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
            raise


def _can_search(info: os.stat_result, uid: int, gids: set[int]) -> bool:
    if info.st_uid == uid:
        return bool(info.st_mode & 0o100)
    if info.st_gid in gids:
        return bool(info.st_mode & 0o010)
    return bool(info.st_mode & 0o001)


def _operator_gids(uid: int) -> set[int]:
    try:
        entry = pwd.getpwuid(uid)
    except (KeyError, OverflowError):
        return set()
    try:
        return set(os.getgrouplist(entry.pw_name, entry.pw_gid))
    except (OSError, OverflowError):
        return {entry.pw_gid}


def _grant_search(path: Path, operator_uid: int) -> None:
    """Add search for the operator to *path*'s entries, keeping every other."""
    if not sys.platform.startswith("linux"):
        raise AccessGrantError("this platform has no access-control lists")
    info = os.lstat(path)
    try:
        entries = _decode_acl(os.getxattr(path, _ACL_XATTR))
    except OSError as exc:
        if exc.errno not in (errno.ENODATA,):
            raise AccessGrantError(
                f"{shown(str(path))}: {exc.strerror or exc}"
            ) from exc
        mode = info.st_mode
        entries = [
            (_ACL_USER_OBJ, (mode >> 6) & 0o7, _ACL_UNDEFINED_ID),
            (_ACL_GROUP_OBJ, (mode >> 3) & 0o7, _ACL_UNDEFINED_ID),
            (_ACL_OTHER, mode & 0o7, _ACL_UNDEFINED_ID),
        ]
    kept = [e for e in entries if not (e[0] == _ACL_USER and e[2] == operator_uid)]
    current = next(
        (e[1] for e in entries if e[0] == _ACL_USER and e[2] == operator_uid), 0
    )
    mask = next((e[1] for e in entries if e[0] == _ACL_MASK), None)
    if mask is None:
        group_obj = next(e[1] for e in entries if e[0] == _ACL_GROUP_OBJ)
        mask = group_obj
    # Widening the mask widens every group-class entry it masks. Search for
    # the operator alone cannot be granted that way, so it is not granted.
    widened = [
        e
        for e in kept
        if e[0] in (_ACL_GROUP_OBJ, _ACL_GROUP, _ACL_USER) and e[1] & 0o1
    ]
    if not mask & 0o1 and widened:
        raise AccessGrantError(
            f"{shown(str(path))}: granting the operator search would also grant it "
            "to an entry the mask now withholds it from"
        )
    kept = [e for e in kept if e[0] != _ACL_MASK]
    kept.append((_ACL_USER, current | 0o1, operator_uid))
    kept.append((_ACL_MASK, mask | 0o1, _ACL_UNDEFINED_ID))
    try:
        os.setxattr(path, _ACL_XATTR, _encode_acl(kept))
    except OSError as exc:
        raise AccessGrantError(f"{shown(str(path))}: {exc.strerror or exc}") from exc


def grant_access(directory: Path, socket_path: Path, operator_uid: int | None) -> None:
    """No group or world access; connect and search for the operator alone.

    The socket is the owner's and the operator's. The runtime directory is the
    owner's, with search for the operator; every ancestor the operator cannot
    otherwise search gains an entry naming it. Any of these that cannot be
    applied is an `AccessGrantError`.
    """
    _set_exact_access(socket_path, 0o600, operator_uid, 0o6)
    _set_exact_access(directory, 0o700, operator_uid, 0o1)
    if operator_uid is None:
        return
    gids = _operator_gids(operator_uid)
    for ancestor in directory.parents:
        if not _can_search(os.lstat(ancestor), operator_uid, gids):
            _grant_search(ancestor, operator_uid)


# ─── the server ───────────────────────────────────────────────────────────────

Reconciler = Callable[
    [ReconcileRequest, PeerCredentials, str | None], Awaitable[Mapping[str, Any]]
]


class OperatorSocketServer:
    """Serve `reconcile_tier_c` to root and the installed operator identity."""

    def __init__(
        self,
        *,
        directory: Path,
        reconcile: Reconciler,
        operator_uid: Callable[[], int | None],
        peer_credentials: Callable[[Any], PeerCredentials | None] = peer_credentials,
        grant: Callable[[Path, Path, int | None], None] = grant_access,
        account: Callable[[int], str | None] = account_name,
    ) -> None:
        self._directory = directory
        self._path = directory / SOCKET_NAME
        self._reconcile = reconcile
        self._operator_uid = operator_uid
        self._peer_credentials = peer_credentials
        self._grant = grant
        self._account = account
        self._server: asyncio.AbstractServer | None = None
        self._identity: tuple[int, int, int] | None = None
        self._closing = False
        self._appends: set[asyncio.Task[Any]] = set()

    @property
    def path(self) -> Path:
        return self._path

    async def start(self) -> Path:
        """Bind, or raise leaving no socket behind."""
        if os.name == "nt":
            raise RuntimeError("the operator socket requires AF_UNIX")
        await asyncio.to_thread(self._prepare)
        operator_uid = await asyncio.to_thread(self._operator_uid)
        server = await asyncio.start_unix_server(
            self._handle, path=str(self._path), limit=MAX_REQUEST_BYTES + 1
        )
        provisional = await asyncio.to_thread(_socket_identity, str(self._path))
        try:
            await asyncio.to_thread(
                self._grant, self._directory, self._path, operator_uid
            )
        except BaseException:
            server.close()
            await server.wait_closed()
            await asyncio.to_thread(_remove_own_socket, self._path, provisional)
            raise
        self._server = server
        self._identity = await asyncio.to_thread(_socket_identity, str(self._path))
        return self._path

    def _prepare(self) -> None:
        self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(self._directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise RuntimeError(
                f"runtime directory {shown(str(self._directory))} is not a directory "
                "this runtime owns"
            )
        if os.path.lexists(self._path):
            current = os.lstat(self._path)
            if not stat.S_ISSOCK(current.st_mode):
                raise RuntimeError(
                    f"operator socket path {shown(str(self._path))} is not a socket"
                )
            if _socket_has_a_listener(self._path):
                raise OSError(
                    errno.EADDRINUSE,
                    "another process is already serving this operator socket",
                    str(self._path),
                )
            self._path.unlink()

    async def close(self) -> None:
        """Stop accepting, and return only once every begun append has ended.

        Not bounded here: the append is one store transaction, bounded by the
        store, and the runtime closes the store after this returns, so a
        timeout would let it close underneath an append the contract says
        completes or fails as one transaction.
        """
        self._closing = True
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._appends:
            await asyncio.wait(self._appends)
        await asyncio.to_thread(_remove_socket_file, str(self._path), self._identity)
        self._identity = None

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            response = await self._answer(reader, writer)
        except Exception:
            logger.exception("[operator-socket] request failed")
            response = _error(
                "internal_error", "the runtime could not complete the request"
            )
        # A caller that left before its answer is not answered; the answer
        # records nothing, and a begun append completes regardless.
        try:
            with contextlib.suppress(OSError):
                await self._write(writer, response)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _write(
        self, writer: asyncio.StreamWriter, response: dict[str, Any]
    ) -> None:
        writer.write(
            json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n"
        )
        await writer.drain()

    async def _answer(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> dict[str, Any]:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=REQUEST_TIMEOUT_S)
        except (TimeoutError, asyncio.IncompleteReadError):
            return _error("invalid_arguments", "the request was not completed in time")
        except ValueError:
            return _error("invalid_arguments", "the request exceeds its bound")
        if len(raw) > MAX_REQUEST_BYTES:
            return _error("invalid_arguments", "the request exceeds its bound")
        try:
            request = validate_reconcile_request(parse_request(raw))
        except OperatorRequestError as exc:
            return _error(exc.code, exc.detail)

        # /proc, the identity file and the account database are read off the loop.
        peer = await asyncio.to_thread(
            self._peer_credentials, writer.get_extra_info("socket")
        )
        operator_uid = await asyncio.to_thread(self._operator_uid)
        if peer is None or not (peer.uid == 0 or peer.uid == operator_uid):
            logger.warning(
                "[operator-socket] refused an unauthenticated caller (uid %s)",
                "unknown" if peer is None else peer.uid,
            )
            return _error("unauthenticated", "the caller is not admitted")

        account = await asyncio.to_thread(self._account, peer.uid)
        # Nothing awaits between this check and the append beginning, so an
        # append never begins after close() has stopped waiting for them.
        if self._closing:
            return _error("cancelled", "the runtime is stopping; nothing was recorded")
        append = asyncio.ensure_future(self._reconcile(request, peer, account))
        self._appends.add(append)
        append.add_done_callback(self._appends.discard)
        try:
            answer = await asyncio.shield(append)
        except sqlite3.OperationalError as exc:
            if _locked(exc):
                return _error(
                    "state_store_locked",
                    "the state store is held; nothing was recorded",
                )
            return _store_unavailable(exc)
        except (sqlite3.Error, OSError) as exc:
            return _store_unavailable(exc)
        return self._reconciled(request, peer, answer)

    def _reconciled(
        self,
        request: ReconcileRequest,
        peer: PeerCredentials,
        answer: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not answer.get("ok"):
            code = str(answer.get("error", ""))
            if code not in RECONCILE_ERRORS:
                raise RuntimeError(f"the store answered an unknown refusal {code!r}")
            logger.info(
                "[operator-socket] reconcile of %s by uid %s refused: %s",
                request.proposal_id,
                peer.uid,
                code,
            )
            return _error(code, "nothing was recorded")
        record = answer["record"]
        already = bool(answer.get("already_recorded"))
        logger.warning(
            "[operator-socket] proposal %s reconciled %s by uid %s (login %s)%s",
            request.proposal_id,
            record["decision_state"],
            peer.uid,
            peer.login_uid,
            " (already recorded)" if already else "",
        )
        return {
            "schema_version": 1,
            "ok": True,
            "result": {
                "proposal_id": record["proposal_id"],
                "device_id": record["device_id"],
                "zone_id": record["zone_id"],
                "decision_state": record["decision_state"],
                "reason": record["reason"],
                "note": record["note"],
                "operator": {
                    "uid": record["principal_uid"],
                    "account": record["principal_account"],
                    "login_uid": record["principal_login_uid"],
                },
                "entry_point": record["entry_point"],
                "recorded_at_ms": record["recorded_at_ms"],
                "already_recorded": already,
            },
        }


def _remove_own_socket(path: Path, provisional: tuple[int, int, int] | None) -> None:
    """Remove the socket a failed start bound, found by device and inode.

    Applying its mode moves its ctime, so the identity taken at bind no longer
    matches in full; the file is still this server's when device and inode do,
    and `_remove_socket_file` still refuses one some process is answering on.
    """
    current = _socket_identity(str(path))
    if provisional is None or current is None or current[:2] != provisional[:2]:
        return
    _remove_socket_file(str(path), current)


def _locked(exc: sqlite3.OperationalError) -> bool:
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def _store_unavailable(exc: BaseException) -> dict[str, Any]:
    logger.error("[operator-socket] the state store cannot serve a reconcile: %s", exc)
    return _error(
        "runtime_store_unavailable", "the state store cannot serve this request"
    )


def _error(code: str, detail: str) -> dict[str, Any]:
    return {"schema_version": 1, "ok": False, "error": {"code": code, "detail": detail}}
