# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Community skill hook execution with optional OS-level sandboxing.

This module provides a two-way JSON-RPC bridge between parent runtime and a
child hook subprocess. The child can execute untrusted hook code while
requesting history/state reads/writes from the parent process via RPC.
"""

from __future__ import annotations

import asyncio
import ctypes
import errno
import json
import logging
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from ori.skills.sandbox import SkillSecurityError, load_hooks_restricted

logger = logging.getLogger(__name__)


_OS_SANDBOX_DEFAULTS = {
    "enabled": True,
    "require_for_community": False,
    "exec_timeout_ms": 2000,
    "max_output_bytes": 65536,
}

_RPC_REQ = "rpc_request"
_RPC_RESP = "rpc_response"
_RESULT = "result"
_INIT = "init"

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_SET_MODE_FILTER = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_K = 0x00
_BPF_RET = 0x06

_SECCOMP_ARCH = {
    "x86_64": 0xC000003E,
    "aarch64": 0xC00000B7,
}
_SECCOMP_DENY_SYSCALLS = {
    "x86_64": {
        "socket": 41,
        "connect": 42,
        "accept": 43,
        "accept4": 288,
        "bind": 49,
        "listen": 50,
        "sendto": 44,
        "recvfrom": 45,
        "sendmsg": 46,
        "recvmsg": 47,
        "sendmmsg": 307,
        "recvmmsg": 299,
    },
    "aarch64": {
        "socket": 198,
        "connect": 203,
        "accept": 202,
        "accept4": 242,
        "bind": 200,
        "listen": 201,
        "sendto": 206,
        "recvfrom": 207,
        "sendmsg": 211,
        "recvmsg": 212,
        "sendmmsg": 269,
        "recvmmsg": 243,
    },
}

_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_RULE_PATH_BENEATH = 1
_LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
_LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
_LANDLOCK_ACCESS_FS_REFER = 1 << 13
_LANDLOCK_RULESET_ALL = (
    _LANDLOCK_ACCESS_FS_EXECUTE
    | _LANDLOCK_ACCESS_FS_WRITE_FILE
    | _LANDLOCK_ACCESS_FS_READ_FILE
    | _LANDLOCK_ACCESS_FS_READ_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_FILE
    | _LANDLOCK_ACCESS_FS_MAKE_CHAR
    | _LANDLOCK_ACCESS_FS_MAKE_DIR
    | _LANDLOCK_ACCESS_FS_MAKE_REG
    | _LANDLOCK_ACCESS_FS_MAKE_SOCK
    | _LANDLOCK_ACCESS_FS_MAKE_FIFO
    | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | _LANDLOCK_ACCESS_FS_MAKE_SYM
    | _LANDLOCK_ACCESS_FS_REFER
)
_LANDLOCK_READ_EXEC = (
    _LANDLOCK_ACCESS_FS_READ_FILE
    | _LANDLOCK_ACCESS_FS_READ_DIR
    | _LANDLOCK_ACCESS_FS_EXECUTE
)


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


@dataclass
class OSSandboxSupport:
    supported: bool
    reason: str


def _normalize_os_sandbox_config(raw: dict[str, Any] | None) -> dict[str, Any]:
    cfg = dict(_OS_SANDBOX_DEFAULTS)
    if isinstance(raw, dict):
        cfg.update(raw)
    cfg["enabled"] = bool(cfg.get("enabled", True))
    cfg["require_for_community"] = bool(cfg.get("require_for_community", False))
    cfg["exec_timeout_ms"] = max(100, int(cfg.get("exec_timeout_ms", 2000)))
    cfg["max_output_bytes"] = max(4096, int(cfg.get("max_output_bytes", 65536)))
    return cfg


def probe_os_sandbox_support() -> OSSandboxSupport:
    if os.name != "posix":
        return OSSandboxSupport(False, "os_not_posix")
    if sys.platform != "linux":
        return OSSandboxSupport(False, "kernel_not_linux")
    machine = os.uname().machine
    if machine not in _SECCOMP_ARCH:
        return OSSandboxSupport(False, f"unsupported_arch:{machine}")
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "syscall") or not hasattr(libc, "prctl"):
        return OSSandboxSupport(False, "missing_libc_syscall_prctl")

    # Landlock probe: ENOSYS/EOPNOTSUPP/EINVAL means unsupported or too old.
    ruleset = _LandlockRulesetAttr(handled_access_fs=_LANDLOCK_RULESET_ALL)
    fd = libc.syscall(
        _LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset),
        ctypes.sizeof(ruleset),
        0,
    )
    if fd < 0:
        err = ctypes.get_errno()
        if err in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL, errno.EPERM}:
            return OSSandboxSupport(False, f"landlock_unavailable:{err}")
        return OSSandboxSupport(False, f"landlock_probe_failed:{err}")
    try:
        os.close(fd)
    except OSError:
        pass

    return OSSandboxSupport(True, "ok")


def load_community_hooks(
    *,
    hooks_path: Path,
    state_store: Any,
    skill_name: str,
    os_sandbox_config: dict[str, Any] | None,
) -> Any:
    cfg = _normalize_os_sandbox_config(os_sandbox_config)
    if not cfg["enabled"]:
        return load_hooks_restricted(str(hooks_path))

    support = probe_os_sandbox_support()
    if not support.supported:
        logger.warning(
            "SkillLoader: OS sandbox unavailable for %s (%s); using python sandbox fallback",
            hooks_path.parent.name,
            support.reason,
        )
        if cfg["require_for_community"]:
            raise SkillSecurityError(
                f"os sandbox required for community skill but unavailable: {support.reason}"
            )
        return load_hooks_restricted(str(hooks_path))

    return OSSandboxHookRunner(
        hooks_path=hooks_path,
        state_store=state_store,
        skill_name=skill_name,
        os_sandbox_config=cfg,
    )


class OSSandboxHookRunner:
    """Async hook runner for community hooks in child subprocess."""

    def __init__(
        self,
        *,
        hooks_path: Path,
        state_store: Any,
        skill_name: str,
        os_sandbox_config: dict[str, Any],
    ) -> None:
        self._hooks_path = str(hooks_path)
        self._state_store = state_store
        self._skill_name = skill_name
        self._cfg = _normalize_os_sandbox_config(os_sandbox_config)

    async def pre_trigger_eval(self, hook_ctx: Any) -> None:
        payload = _serialize_hook_context(hook_ctx, include_result=False)
        result = await self._invoke_child("pre_trigger_eval", payload)
        if not result.get("ok", False):
            raise SkillSecurityError(result.get("error", "pre_trigger_eval failed"))
        _apply_hook_updates(hook_ctx, result.get("hook_ctx", {}))

    async def post_reasoning(self, reasoning_result: Any, hook_ctx: Any) -> None:
        payload = _serialize_hook_context(
            hook_ctx,
            include_result=True,
            reasoning_result=reasoning_result,
        )
        result = await self._invoke_child("post_reasoning", payload)
        if not result.get("ok", False):
            raise SkillSecurityError(result.get("error", "post_reasoning failed"))
        _apply_hook_updates(hook_ctx, result.get("hook_ctx", {}))
        _apply_reasoning_updates(reasoning_result, result.get("reasoning_result", {}))

    async def _invoke_child(
        self, method: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ori.skills.os_sandbox",
            "--child",
            self._hooks_path,
            method,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None
        assert proc.stderr is not None

        req_id = 0
        init_msg = {
            "type": _INIT,
            "payload": payload,
            "skill_name": self._skill_name,
        }
        proc.stdin.write((json.dumps(init_msg, separators=(",", ":")) + "\n").encode())
        await proc.stdin.drain()

        max_bytes = int(self._cfg["max_output_bytes"])
        stderr_bytes = b""
        result_msg: dict[str, Any] | None = None

        async def _read_stderr() -> None:
            nonlocal stderr_bytes
            while True:
                chunk = await proc.stderr.read(1024)
                if not chunk:
                    return
                if len(stderr_bytes) < max_bytes:
                    stderr_bytes += chunk

        stderr_task = asyncio.create_task(_read_stderr())

        try:
            timeout_s = float(self._cfg["exec_timeout_ms"]) / 1000.0
            with asyncio.timeout(timeout_s):
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    msg = json.loads(line.decode("utf-8"))
                    msg_type = str(msg.get("type", ""))
                    if msg_type == _RPC_REQ:
                        req_id = int(msg.get("id", req_id + 1))
                        response = self._handle_rpc_request(msg)
                        response["id"] = req_id
                        proc.stdin.write(
                            (
                                json.dumps(response, separators=(",", ":")) + "\n"
                            ).encode()
                        )
                        await proc.stdin.drain()
                    elif msg_type == _RESULT:
                        result_msg = msg
                        break
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise SkillSecurityError("os_sandbox_timeout")
        finally:
            if proc.returncode is None:
                proc.stdin.close()
                await proc.wait()
            await stderr_task

        if result_msg is None:
            err = stderr_bytes.decode("utf-8", errors="ignore").strip()
            raise SkillSecurityError(f"os_sandbox_ipc_protocol_error:{err}")
        return dict(result_msg)

    def _handle_rpc_request(self, msg: dict[str, Any]) -> dict[str, Any]:
        method = str(msg.get("method", "")).strip()
        params = msg.get("params", {}) or {}
        try:
            if method == "state.get":
                key = str(params.get("key", ""))
                fn = getattr(self._state_store, "hooks_get_skill_state", None)
                val = fn(self._skill_name, key) if callable(fn) else None
                return {"type": _RPC_RESP, "ok": True, "result": val}

            if method == "state.set":
                key = str(params.get("key", ""))
                value = str(params.get("value", ""))
                fn = getattr(self._state_store, "hooks_set_skill_state", None)
                if callable(fn):
                    fn(self._skill_name, key, value)
                return {"type": _RPC_RESP, "ok": True, "result": True}

            if method == "history.avg_hours":
                sensor_id = str(params.get("sensor_id", ""))
                hours = int(params.get("hours", 0))
                return self._history_read_response(
                    "hooks_avg_last_hours", sensor_id, hours
                )

            if method == "history.avg_last_n":
                sensor_id = str(params.get("sensor_id", ""))
                n = int(params.get("n", 0))
                return self._history_read_response("hooks_avg_last_n", sensor_id, n)

            if method == "history.same_weekday_hour_baseline":
                sensor_id = str(params.get("sensor_id", ""))
                reference_timestamp_ms = int(params.get("reference_timestamp_ms", 0))
                timezone = str(params.get("timezone", "UTC") or "UTC")
                lookback_weeks = int(params.get("lookback_weeks", 8))
                min_weeks = int(params.get("min_weeks", 3))
                return self._history_read_response(
                    "hooks_time_of_week_baseline",
                    sensor_id,
                    reference_timestamp_ms,
                    timezone,
                    lookback_weeks,
                    min_weeks,
                )

            if method in {
                "history.last_value",
                "history.last_timestamp",
                "history.fetch_history",
            }:
                sensor_id = str(params.get("sensor_id", ""))
                limit = int(params.get("limit", 1))
                history = (
                    self._history_read_response("hooks_get_history", sensor_id, limit)[
                        "result"
                    ]
                    or []
                )
                if method == "history.fetch_history":
                    serial = [
                        {
                            "sensor_id": r.sensor_id,
                            "sensor_type": r.sensor_type,
                            "value": r.value,
                            "unit": r.unit,
                            "timestamp": r.timestamp,
                            "quality": r.quality,
                            "metadata": r.metadata,
                        }
                        for r in history
                    ]
                    return {"type": _RPC_RESP, "ok": True, "result": serial}
                if not history:
                    return {"type": _RPC_RESP, "ok": True, "result": None}
                if method == "history.last_value":
                    return {"type": _RPC_RESP, "ok": True, "result": history[0].value}
                return {"type": _RPC_RESP, "ok": True, "result": history[0].timestamp}

            return {
                "type": _RPC_RESP,
                "ok": False,
                "error": f"unsupported_rpc_method:{method}",
            }
        except Exception as exc:
            return {"type": _RPC_RESP, "ok": False, "error": str(exc)}

    def _history_read_response(self, method_name: str, *args: Any) -> dict[str, Any]:
        fn = getattr(self._state_store, method_name, None)
        val = fn(*args) if callable(fn) else None
        return {"type": _RPC_RESP, "ok": True, "result": val}


def _serialize_hook_context(
    hook_ctx: Any,
    *,
    include_result: bool,
    reasoning_result: Any | None = None,
) -> dict[str, Any]:
    event = getattr(hook_ctx, "event", None)
    reading = getattr(event, "reading", None) if event is not None else None
    event_ctx = (
        event.context if event is not None and isinstance(event.context, dict) else {}
    )
    payload: dict[str, Any] = {
        "hook_ctx": {
            "trigger_name": str(getattr(hook_ctx, "trigger_name", "") or ""),
            "readings": dict(getattr(hook_ctx, "readings", {}) or {}),
            "timestamp": int(getattr(hook_ctx, "timestamp", 0) or 0),
            "config": dict(getattr(hook_ctx, "config", {}) or {}),
            "derived": dict(getattr(hook_ctx, "derived", {}) or {}),
            "event": {
                "event_id": str(getattr(event, "event_id", "") or ""),
                "event_type": str(getattr(event, "event_type", "") or ""),
                "device_id": str(getattr(event, "device_id", "") or ""),
                "sensor_id": str(getattr(event, "sensor_id", "") or ""),
                "timestamp": int(getattr(event, "timestamp", 0) or 0),
                "context": dict(event_ctx),
            }
            if event is not None
            else None,
            "reading": {
                "sensor_id": str(getattr(reading, "sensor_id", "") or ""),
                "sensor_type": str(getattr(reading, "sensor_type", "") or ""),
                "value": getattr(reading, "value", None),
                "unit": str(getattr(reading, "unit", "") or ""),
                "timestamp": int(getattr(reading, "timestamp", 0) or 0),
                "quality": float(getattr(reading, "quality", 0.0) or 0.0),
                "metadata": dict(getattr(reading, "metadata", {}) or {}),
            }
            if reading is not None
            else None,
        }
    }
    if include_result and reasoning_result is not None:
        payload["reasoning_result"] = {
            "text": str(getattr(reasoning_result, "text", "") or ""),
            "tier": str(getattr(reasoning_result, "tier", "") or ""),
            "model": str(getattr(reasoning_result, "model", "") or ""),
            "tokens_used": int(getattr(reasoning_result, "tokens_used", 0) or 0),
            "latency_ms": int(getattr(reasoning_result, "latency_ms", 0) or 0),
            "confidence": float(getattr(reasoning_result, "confidence", 0.0) or 0.0),
            "action_tier": str(getattr(reasoning_result, "action_tier", "") or ""),
            "proposed_action": str(
                getattr(reasoning_result, "proposed_action", "") or ""
            ),
        }
    return payload


def _apply_hook_updates(hook_ctx: Any, updated: dict[str, Any]) -> None:
    if not isinstance(updated, dict):
        return
    derived = updated.get("derived")
    if isinstance(derived, dict):
        hook_ctx.derived.clear()
        hook_ctx.derived.update(derived)


def _apply_reasoning_updates(reasoning_result: Any, updated: dict[str, Any]) -> None:
    if not isinstance(updated, dict):
        return
    if "text" in updated:
        reasoning_result.text = str(updated.get("text") or "")
    if "proposed_action" in updated:
        reasoning_result.proposed_action = str(updated.get("proposed_action") or "")
    if "action_tier" in updated:
        reasoning_result.action_tier = str(updated.get("action_tier") or "")


class _RPCStateProxy:
    def __init__(self, rpc: Callable[[str, dict[str, Any]], Any]):
        self._rpc = rpc

    def get(self, key: str) -> Any:
        return self._rpc("state.get", {"key": str(key)})

    def set(self, key: str, value: Any) -> None:
        self._rpc("state.set", {"key": str(key), "value": str(value)})


class _RPCHistoryProxy:
    def __init__(
        self,
        rpc: Callable[[str, dict[str, Any]], Any],
        *,
        reference_timestamp_ms: int = 0,
        timezone: str = "UTC",
    ):
        self._rpc = rpc
        self._reference_timestamp_ms = int(reference_timestamp_ms)
        self._timezone = str(timezone or "UTC")

    def avg_hours(self, sensor_id: str, hours: int) -> Any:
        return self._rpc(
            "history.avg_hours", {"sensor_id": sensor_id, "hours": int(hours)}
        )

    def avg_last_n(self, sensor_id: str, n: int) -> Any:
        return self._rpc("history.avg_last_n", {"sensor_id": sensor_id, "n": int(n)})

    def last_value(self, sensor_id: str) -> Any:
        return self._rpc("history.last_value", {"sensor_id": sensor_id})

    def last_timestamp(self, sensor_id: str) -> Any:
        return self._rpc("history.last_timestamp", {"sensor_id": sensor_id})

    def fetch_history(self, sensor_id: str, limit: int = 1) -> Any:
        return self._rpc(
            "history.fetch_history", {"sensor_id": sensor_id, "limit": int(limit)}
        )

    def same_weekday_hour_baseline(
        self,
        sensor_id: str,
        lookback_weeks: int = 8,
        min_weeks: int = 3,
    ) -> Any:
        return self._rpc(
            "history.same_weekday_hour_baseline",
            {
                "sensor_id": sensor_id,
                "reference_timestamp_ms": self._reference_timestamp_ms,
                "timezone": self._timezone,
                "lookback_weeks": int(lookback_weeks),
                "min_weeks": int(min_weeks),
            },
        )


class _ChildHookContext:
    def __init__(self, raw: dict[str, Any], rpc: Callable[[str, dict[str, Any]], Any]):
        self.trigger_name = str(raw.get("trigger_name", "") or "")
        self.readings = dict(raw.get("readings") or {})
        self.timestamp = int(raw.get("timestamp", 0) or 0)
        self.config = dict(raw.get("config") or {})
        self.derived = dict(raw.get("derived") or {})
        event_raw = raw.get("event")
        event_context = (
            dict(event_raw.get("context") or {}) if isinstance(event_raw, dict) else {}
        )
        self.history = _RPCHistoryProxy(
            rpc,
            reference_timestamp_ms=self.timestamp,
            timezone=str(event_context.get("device_timezone") or "UTC"),
        )
        self.state = _RPCStateProxy(rpc)

        reading_raw = raw.get("reading")
        reading = None
        if isinstance(reading_raw, dict):
            reading = SimpleNamespace(
                sensor_id=str(reading_raw.get("sensor_id", "") or ""),
                sensor_type=str(reading_raw.get("sensor_type", "") or ""),
                value=reading_raw.get("value"),
                unit=str(reading_raw.get("unit", "") or ""),
                timestamp=int(reading_raw.get("timestamp", 0) or 0),
                quality=float(reading_raw.get("quality", 0.0) or 0.0),
                metadata=dict(reading_raw.get("metadata") or {}),
            )
        if isinstance(event_raw, dict):
            self.event = SimpleNamespace(
                event_id=str(event_raw.get("event_id", "") or ""),
                event_type=str(event_raw.get("event_type", "") or ""),
                device_id=str(event_raw.get("device_id", "") or ""),
                sensor_id=str(event_raw.get("sensor_id", "") or ""),
                timestamp=int(event_raw.get("timestamp", 0) or 0),
                context=dict(event_raw.get("context") or {}),
                reading=reading,
            )
        else:
            self.event = None

    @property
    def reading(self) -> Any:
        return self.event.reading if self.event is not None else None


def _child_rpc_call(
    *,
    stdin: Any,
    stdout: Any,
    next_id: list[int],
    method: str,
    params: dict[str, Any],
) -> Any:
    req_id = next_id[0]
    next_id[0] += 1
    req = {"type": _RPC_REQ, "id": req_id, "method": method, "params": params}
    stdout.write(json.dumps(req, separators=(",", ":")) + "\n")
    stdout.flush()
    line = stdin.readline()
    if not line:
        raise RuntimeError("rpc_response_eof")
    resp = json.loads(line)
    if resp.get("type") != _RPC_RESP or int(resp.get("id", -1)) != req_id:
        raise RuntimeError("rpc_response_mismatch")
    if not resp.get("ok", False):
        raise RuntimeError(str(resp.get("error", "rpc_error")))
    return resp.get("result")


def _install_seccomp_network_deny() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    machine = os.uname().machine
    arch = _SECCOMP_ARCH[machine]
    deny_syscalls = list(_SECCOMP_DENY_SYSCALLS[machine].values())

    def stmt(code: int, k: int) -> _SockFilter:
        return _SockFilter(code=code, jt=0, jf=0, k=k)

    def jump(code: int, k: int, jt: int, jf: int) -> _SockFilter:
        return _SockFilter(code=code, jt=jt, jf=jf, k=k)

    filters: list[_SockFilter] = [
        # A = arch
        stmt(_BPF_LD | _BPF_W | _BPF_ABS, 4),
        # if arch == expected continue; else allow (avoid false-positive kill)
        jump(_BPF_JMP | _BPF_JEQ | _BPF_K, arch, 1, 0),
        stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_ALLOW),
        # A = nr
        stmt(_BPF_LD | _BPF_W | _BPF_ABS, 0),
    ]
    for nr in deny_syscalls:
        filters.append(jump(_BPF_JMP | _BPF_JEQ | _BPF_K, nr, 0, 1))
        filters.append(stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_ERRNO | errno.EPERM))
    filters.append(stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_ALLOW))

    arr_t = _SockFilter * len(filters)
    arr = arr_t(*filters)
    prog = _SockFprog(
        len=len(filters), filter=ctypes.cast(arr, ctypes.POINTER(_SockFilter))
    )

    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, "prctl(PR_SET_NO_NEW_PRIVS) failed")

    res = libc.syscall(
        317 if machine == "x86_64" else 277,
        _SECCOMP_SET_MODE_FILTER,
        0,
        ctypes.byref(prog),
    )
    if res != 0:
        # Fallback older kernels may not expose SYS_seccomp; try PR_SET_SECCOMP
        if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(prog)) != 0:
            err = ctypes.get_errno()
            raise OSError(err, "seccomp filter install failed")


def _install_landlock_readonly(paths: list[str]) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    ruleset = _LandlockRulesetAttr(handled_access_fs=_LANDLOCK_RULESET_ALL)
    ruleset_fd = libc.syscall(
        _LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset),
        ctypes.sizeof(ruleset),
        0,
    )
    if ruleset_fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, "landlock_create_ruleset failed")
    try:
        for path in paths:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = _LandlockPathBeneathAttr(
                    allowed_access=_LANDLOCK_READ_EXEC,
                    parent_fd=fd,
                )
                rc = libc.syscall(
                    _LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    _LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(rule),
                    0,
                )
                if rc != 0:
                    err = ctypes.get_errno()
                    raise OSError(err, f"landlock_add_rule failed for {path}")
            finally:
                os.close(fd)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            err = ctypes.get_errno()
            raise OSError(err, "prctl(PR_SET_NO_NEW_PRIVS) failed")
        rc = libc.syscall(_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
        if rc != 0:
            err = ctypes.get_errno()
            raise OSError(err, "landlock_restrict_self failed")
    finally:
        os.close(ruleset_fd)


def _build_readonly_allow_paths(hooks_path: str) -> list[str]:
    paths = {
        str(Path(hooks_path).resolve().parent),
        str(Path(tempfile.gettempdir()).resolve()),
        str(Path(sys.prefix).resolve()),
        "/usr",
        "/lib",
        "/lib64",
        "/etc",
    }
    return sorted(p for p in paths if Path(p).exists())


def _run_child(hooks_path: str, method: str) -> int:
    init_line = sys.stdin.readline()
    if not init_line:
        sys.stdout.write(
            json.dumps({"type": _RESULT, "ok": False, "error": "missing_init"}) + "\n"
        )
        sys.stdout.flush()
        return 2
    init = json.loads(init_line)
    payload = init.get("payload", {})
    hook_raw = payload.get("hook_ctx", {}) if isinstance(payload, dict) else {}

    support = probe_os_sandbox_support()
    if support.supported:
        try:
            _install_landlock_readonly(_build_readonly_allow_paths(hooks_path))
            _install_seccomp_network_deny()
        except Exception as exc:
            sys.stdout.write(
                json.dumps(
                    {
                        "type": _RESULT,
                        "ok": False,
                        "error": f"os_sandbox_init_failed:{exc}",
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
            sys.stdout.flush()
            return 3

    module = load_hooks_restricted(hooks_path)
    if module is None:
        sys.stdout.write(
            json.dumps({"type": _RESULT, "ok": False, "error": "hooks_not_found"})
            + "\n"
        )
        sys.stdout.flush()
        return 4

    next_id = [1]

    def rpc(method_name: str, params: dict[str, Any]) -> Any:
        return _child_rpc_call(
            stdin=sys.stdin,
            stdout=sys.stdout,
            next_id=next_id,
            method=method_name,
            params=params,
        )

    hook_ctx = _ChildHookContext(hook_raw, rpc)

    try:
        if method == "pre_trigger_eval":
            fn = getattr(module, "pre_trigger_eval", None)
            if callable(fn):
                fn(hook_ctx)
            out = {"hook_ctx": {"derived": dict(hook_ctx.derived)}}
        elif method == "post_reasoning":
            fn = getattr(module, "post_reasoning", None)
            rr = SimpleNamespace(**dict(payload.get("reasoning_result") or {}))
            if callable(fn):
                returned = fn(rr, hook_ctx)
                if returned is not None:
                    rr = returned
            out = {
                "hook_ctx": {"derived": dict(hook_ctx.derived)},
                "reasoning_result": {
                    "text": str(getattr(rr, "text", "") or ""),
                    "action_tier": str(getattr(rr, "action_tier", "") or ""),
                    "proposed_action": str(getattr(rr, "proposed_action", "") or ""),
                },
            }
        else:
            raise RuntimeError(f"unknown_hook_method:{method}")
        msg = {"type": _RESULT, "ok": True}
        msg.update(out)
        sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        return 0
    except Exception as exc:
        sys.stdout.write(
            json.dumps(
                {"type": _RESULT, "ok": False, "error": f"hook_execution_failed:{exc}"},
                separators=(",", ":"),
            )
            + "\n"
        )
        sys.stdout.flush()
        return 5


def _main() -> int:
    if len(sys.argv) >= 4 and sys.argv[1] == "--child":
        hooks_path = sys.argv[2]
        method = sys.argv[3]
        return _run_child(hooks_path, method)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
