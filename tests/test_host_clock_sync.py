# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Whether the host clock is synchronized, as the kernel reports it."""

from __future__ import annotations

import sys

import pytest

from ori.utils import time_utils


class _Adjtimex:
    """A foreign function: callable, and taking argtypes and restype."""

    def __init__(self, result: int | Exception) -> None:
        self._result = result
        self.buffers: list[bytes] = []
        self.argtypes: list | None = None
        self.restype: object = None

    def __call__(self, buffer) -> int:
        self.buffers.append(bytes(buffer))
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class _Libc:
    def __init__(self, result: int | Exception) -> None:
        self.adjtimex = _Adjtimex(result)

    @property
    def buffers(self) -> list[bytes]:
        return self.adjtimex.buffers


@pytest.fixture(autouse=True)
def _fresh_libc():
    """The loader caches the C library; each case supplies its own."""
    time_utils._libc.cache_clear()
    yield
    time_utils._libc.cache_clear()


def _on_linux(monkeypatch, libc: _Libc) -> None:
    monkeypatch.setattr(time_utils.sys, "platform", "linux")
    monkeypatch.delattr(time_utils.sys, "getandroidapilevel", raising=False)
    monkeypatch.setattr(time_utils.ctypes, "CDLL", lambda *_a, **_k: libc)


@pytest.mark.parametrize(
    ("state", "expected"),
    [(0, True), (1, True), (4, True), (5, False), (-1, None)],
)
def test_the_clock_state_decides_synchronization(monkeypatch, state, expected):
    """TIME_ERROR is the kernel's unsynchronized state; a failed call is unknown."""
    libc = _Libc(state)
    _on_linux(monkeypatch, libc)
    assert time_utils.host_clock_synchronized() is expected


def test_the_call_reads_and_never_adjusts(monkeypatch):
    """A zeroed struct has modes 0, which only reads the clock state."""
    libc = _Libc(0)
    _on_linux(monkeypatch, libc)
    time_utils.host_clock_synchronized()
    assert libc.buffers and set(libc.buffers[0]) == {0}
    assert libc.adjtimex.argtypes == [time_utils.ctypes.c_void_p]
    assert libc.adjtimex.restype is time_utils.ctypes.c_int


def test_an_unloadable_libc_is_unknown(monkeypatch):
    _on_linux(monkeypatch, _Libc(OSError("no libc")))
    assert time_utils.host_clock_synchronized() is None


def test_another_platform_is_unknown(monkeypatch):
    monkeypatch.setattr(time_utils.sys, "platform", "darwin")
    assert time_utils.host_clock_synchronized() is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs Linux")
def test_the_real_kernel_answers():
    assert time_utils.host_clock_synchronized() in (True, False)


@pytest.mark.parametrize("marker", ["platform", "api_level"])
def test_android_is_never_asked(monkeypatch, marker):
    """Its seccomp filter traps adjtimex with a signal Python cannot catch."""
    libc = _Libc(0)
    _on_linux(monkeypatch, libc)
    if marker == "platform":
        monkeypatch.setattr(time_utils.sys, "platform", "android")
    else:
        monkeypatch.setattr(
            time_utils.sys, "getandroidapilevel", lambda: 24, raising=False
        )
    assert time_utils.host_clock_synchronized() is None
    assert libc.buffers == []


def test_the_library_is_loaded_once(monkeypatch):
    """Finding it can spawn ldconfig, and the probe runs every compaction cycle."""
    loads = []
    libc = _Libc(0)
    monkeypatch.setattr(time_utils.sys, "platform", "linux")
    monkeypatch.delattr(time_utils.sys, "getandroidapilevel", raising=False)
    monkeypatch.setattr(
        time_utils.ctypes, "CDLL", lambda *_a, **_k: loads.append(1) or libc
    )
    time_utils.host_clock_synchronized()
    time_utils.host_clock_synchronized()
    assert len(loads) == 1
