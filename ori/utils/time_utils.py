# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
import ctypes
import ctypes.util
import functools
import sys
import time
from typing import Any

# adjtimex() returns TIME_ERROR while the kernel's STA_UNSYNC flag is set, which
# is what timedatectl reports as NTPSynchronized=no.
_TIME_ERROR = 5
# Larger than struct timex on every Linux ABI; zeroed, so modes is 0 and the
# call reads the clock state without adjusting anything.
_TIMEX_BUFFER_BYTES = 512


def now_ms() -> int:
    """Return current Unix time in milliseconds."""
    return int(time.time() * 1000)


@functools.cache
def _libc() -> Any:
    """The C library, loaded once: finding it can spawn `ldconfig`."""
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _on_android() -> bool:
    return sys.platform == "android" or hasattr(sys, "getandroidapilevel")


def host_clock_synchronized() -> bool | None:
    """Whether the kernel reports the host clock synchronized, or None if unknown.

    Never asked on Android: its seccomp filter traps `adjtimex` in app
    processes with a signal Python cannot catch, which would end the runtime.
    """
    if not sys.platform.startswith("linux") or _on_android():
        return None
    try:
        libc = _libc()
        libc.adjtimex.argtypes = [ctypes.c_void_p]
        libc.adjtimex.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(_TIMEX_BUFFER_BYTES)
        state = int(libc.adjtimex(buffer))
    except (OSError, AttributeError):
        return None
    if state < 0:
        return None
    return state != _TIME_ERROR
