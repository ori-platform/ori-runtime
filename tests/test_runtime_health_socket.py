# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import errno
import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ori.runtime import OriRuntime
from ori.runtime_health_socket import RuntimeHealthSocketServer
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms


def _short_socket_path(suffix: str) -> str:
    return f"/tmp/ori-{suffix}-{os.getpid()}.sock"


def _require_unix_socket_bindable() -> None:
    probe_path = _short_socket_path("probe")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(probe_path)
    except PermissionError as exc:
        pytest.skip(f"Unix socket bind not permitted in this environment: {exc}")
    finally:
        sock.close()
        if os.path.exists(probe_path):
            os.remove(probe_path)


async def _read_json_line(path: str, request: bytes) -> dict:
    reader, writer = await asyncio.open_unix_connection(path=path)
    writer.write(request)
    await writer.drain()
    raw = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return json.loads(raw.decode("utf-8"))


@pytest.mark.asyncio
async def test_health_socket_serves_snapshot_and_rejects_unsupported_request():
    _require_unix_socket_bindable()
    socket_path = _short_socket_path("health")
    server = RuntimeHealthSocketServer(
        socket_path=socket_path,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "dev-01", "uptime_s": 12.3},
    )
    bound = await server.start()
    try:
        ok_resp = await _read_json_line(bound, b"GET_HEALTH\n")
        assert ok_resp["ok"] is True
        assert ok_resp["schema_version"] == 1
        assert ok_resp["health"]["device_id"] == "dev-01"

        bad_resp = await _read_json_line(bound, b"PING\n")
        assert bad_resp["ok"] is False
        assert bad_resp["error"]["code"] == "unsupported_request"
    finally:
        await server.close()

    assert not os.path.exists(socket_path)


@pytest.mark.asyncio
async def test_health_socket_removes_stale_socket_before_bind():
    _require_unix_socket_bindable()
    socket_path = _short_socket_path("stale")
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(socket_path)
    stale.close()
    assert os.path.exists(socket_path)

    server = RuntimeHealthSocketServer(
        socket_path=socket_path,
        mode=0o660,
        snapshot_provider=lambda: {"ok": True},
    )
    try:
        await server.start()
    finally:
        await server.close()

    assert not os.path.exists(socket_path)


@pytest.mark.asyncio
async def test_health_socket_refuses_non_socket_existing_path(tmp_path):
    _require_unix_socket_bindable()
    socket_path = tmp_path / "not-a-socket"
    socket_path.write_text("not a socket", encoding="utf-8")

    server = RuntimeHealthSocketServer(
        socket_path=str(socket_path),
        mode=0o660,
        snapshot_provider=lambda: {"ok": True},
    )
    with pytest.raises(RuntimeError, match="is not a socket"):
        await server.start()


@pytest.mark.asyncio
async def test_runtime_health_snapshot_shape():
    runtime: Any = OriRuntime(config_path="ori.yaml")
    now = now_ms()
    runtime._device_id = "dev-01"
    runtime._runtime_started_at_ms = now - 5_000
    runtime._health_socket_path = "/tmp/ori-health.sock"
    runtime._device_policy_enabled = True
    runtime._configured_sensors = [
        SimpleNamespace(
            id="sensor-1",
            type="ads1115_voltage",
            protocol="i2c",
            poll_interval_ms=1000,
        )
    ]
    runtime._connected_sensor_ids = {"sensor-1"}
    runtime._sensor_last_seen_ms = {"sensor-1": now - 200}
    runtime._last_alert_timestamps_by_channel = {"sms": now - 100}
    runtime._last_alert_timestamps_by_trigger = {"battery_cycle_stress": now - 50}
    runtime._remote_command_lockout_states = {
        "sms:+2348012345678": {
            "channel": "sms",
            "from_number": "+2348012345678",
            "risk_level": "critical",
            "locked_out": False,
            "enforcement_enabled": False,
            "incident_count": 3,
            "rejection_count": 18,
            "window_ms": 3_600_000,
            "checked_at_ms": now,
            "reason": "critical_incident_volume",
        },
        "whatsapp:whatsapp:+2348099999999": {
            "channel": "whatsapp",
            "from_number": "whatsapp:+2348099999999",
            "risk_level": "elevated",
            "locked_out": False,
            "enforcement_enabled": False,
            "incident_count": 1,
            "rejection_count": 6,
            "window_ms": 3_600_000,
            "checked_at_ms": now - 7_200_000,
            "reason": "recent_security_incident",
        },
    }

    class _Dispatcher:
        def get_policy_state_snapshot(self):
            return {
                "available": True,
                "policy_version": 3,
                "tier": "cloud",
                "relay_b_enabled": True,
                "relay_c_enabled": True,
                "cloud_llm_enabled": True,
                "valid_until": 999_999_999,
                "issued_at": 123_456_789,
                "is_expired": False,
            }

    runtime._dispatcher = _Dispatcher()
    snapshot = await runtime._build_health_snapshot()

    assert snapshot["device_id"] == "dev-01"
    assert snapshot["uptime_s"] >= 5.0
    assert snapshot["health_socket_path"] == "/tmp/ori-health.sock"
    assert "capability_posture" in snapshot
    assert isinstance(snapshot["sensors"], list)
    assert snapshot["sensors"][0]["id"] == "sensor-1"
    assert snapshot["last_alert_timestamps"]["by_channel"]["sms"] > 0
    assert snapshot["alert_outbox"] == {
        "backlog_count": 0,
        "oldest_queued_original_ts": None,
        "oldest_queued_age_ms": None,
        "retry_interval_minutes": 0.5,
        "max_non_tier_d_attempts": 10,
        "tier_d_critical_warning_threshold": 3,
        "batch_size": 50,
    }
    assert snapshot["device_policy"]["enabled"] is True
    assert snapshot["device_policy"]["policy_version"] == 3
    assert snapshot["remote_command_lockout"]["enforcement_enabled"] is False
    assert snapshot["remote_command_lockout"]["risk_window_ms"] == 3_600_000
    assert snapshot["remote_command_lockout"]["stale_after_ms"] == 3_600_000
    assert snapshot["remote_command_lockout"]["incident_sender_limit"] == 50
    senders = {
        item["from_number"]: item
        for item in snapshot["remote_command_lockout"]["senders"]
    }
    assert senders["+2348012345678"]["risk_level"] == "critical"
    assert senders["+2348012345678"]["stale"] is False
    assert senders["whatsapp:+2348099999999"]["risk_level"] == "elevated"
    assert senders["whatsapp:+2348099999999"]["stale"] is True


@pytest.mark.asyncio
async def test_runtime_health_snapshot_uses_configured_lockout_staleness():
    runtime = OriRuntime(config_path="ori.yaml")
    now = now_ms()
    runtime._remote_command_lockout_config = {
        "risk_window_ms": 120_000,
        "state_stale_after_ms": 1_000,
        "incident_sender_limit": 7,
        "elevated_incident_threshold": 1,
        "critical_incident_threshold": 3,
        "elevated_rejection_threshold": 5,
        "critical_rejection_threshold": 15,
        "enforcement_enabled": False,
    }
    runtime._remote_command_lockout_states = {
        "sms:+2348012345678": {
            "channel": "sms",
            "from_number": "+2348012345678",
            "risk_level": "elevated",
            "locked_out": False,
            "enforcement_enabled": False,
            "incident_count": 1,
            "rejection_count": 0,
            "window_ms": 120_000,
            "checked_at_ms": now - 1_500,
            "reason": "recent_security_incident",
        }
    }

    snapshot = await runtime._build_health_snapshot()

    assert snapshot["remote_command_lockout"]["enforcement_enabled"] is False
    assert snapshot["remote_command_lockout"]["risk_window_ms"] == 120_000
    assert snapshot["remote_command_lockout"]["stale_after_ms"] == 1_000
    assert snapshot["remote_command_lockout"]["incident_sender_limit"] == 7
    assert snapshot["remote_command_lockout"]["senders"][0]["stale"] is True


@pytest.mark.asyncio
async def test_health_snapshot_includes_alert_outbox_empty(tmp_path):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = StateStore(str(tmp_path / "health-empty.db"))
    await runtime._state_store.open()

    try:
        snapshot = await runtime._build_health_snapshot()

        assert snapshot["alert_outbox"]["backlog_count"] == 0
        assert snapshot["alert_outbox"]["oldest_queued_original_ts"] is None
        assert snapshot["alert_outbox"]["oldest_queued_age_ms"] is None
    finally:
        await runtime._state_store.close()


@pytest.mark.asyncio
async def test_health_snapshot_includes_alert_outbox_backlog(tmp_path):
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._state_store = StateStore(str(tmp_path / "health-backlog.db"))
    await runtime._state_store.open()
    original_ts = now_ms() - 12_000

    try:
        await runtime._state_store.enqueue_alert(
            alert_id="health-backlog-1",
            channel="sms",
            recipient="+2340000000000",
            message="queued",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=original_ts,
        )

        snapshot = await runtime._build_health_snapshot()

        assert snapshot["alert_outbox"]["backlog_count"] == 1
        assert snapshot["alert_outbox"]["oldest_queued_original_ts"] == original_ts
        assert snapshot["alert_outbox"]["oldest_queued_age_ms"] >= 0
    finally:
        await runtime._state_store.close()


# ── the developer fallback ───────────────────────────────────────────────────


_PACKAGED_DEFAULT = "/run/ori/health.sock"


def _raising(exc: BaseException):
    """A `_prepare_socket_path` that fails the way a given host fails."""

    def _prepare(socket_path: str) -> str:
        if socket_path == _PACKAGED_DEFAULT:
            raise exc
        return socket_path

    return _prepare


@pytest.mark.parametrize(
    "failure",
    [
        PermissionError(13, "Permission denied", "/run/ori"),
        FileNotFoundError(2, "No such file or directory", "/run/ori"),
        OSError(30, "Read-only file system", "/run"),
        NotADirectoryError(20, "Not a directory", "/run/ori"),
    ],
    ids=["permission", "run-absent", "read-only", "not-a-directory"],
)
@pytest.mark.asyncio
async def test_the_fallback_fires_however_an_unusable_path_presents(
    failure, monkeypatch
):
    """One condition, four errnos.

    The packaged default path being unusable on this host arrives as
    `PermissionError` under a non-root account, `FileNotFoundError` where
    `/run` does not exist, and `OSError(EROFS)` where it exists read-only.
    Catching only the first meant the fallback written for exactly this case
    never fired on a developer machine, and the health surface was lost for the
    life of the process.
    """
    _require_unix_socket_bindable()
    server = RuntimeHealthSocketServer(
        socket_path=_PACKAGED_DEFAULT,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "dev-01"},
    )
    fallback = _short_socket_path("fallback")
    monkeypatch.setattr(
        "ori.runtime_health_socket._HEALTH_SOCKET_DEFAULT_DEV_FALLBACK_PATH",
        fallback,
    )
    monkeypatch.setattr(server, "_prepare_socket_path", _raising(failure))

    bound = await server.start()
    try:
        assert bound == fallback
        assert (await _read_json_line(bound, b"GET_HEALTH\n"))["ok"] is True
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_a_second_runtime_cannot_take_a_path_the_first_is_serving():
    """Driven with two real servers, because the injected version proved nothing.

    An earlier form of this test raised `EADDRINUSE` from a patched
    `_prepare_socket_path` and asserted it propagated. That method unlinked any
    existing socket before binding, so the error it injected could not occur:
    a second runtime took the pathname from a live first one, which stayed
    running and unreachable while anything reading health got the newcomer.
    The refusal has to be observed against a real listener or it is a claim
    about a mock.
    """
    _require_unix_socket_bindable()
    path = _short_socket_path("collision")
    first = RuntimeHealthSocketServer(
        socket_path=path,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "first"},
    )
    await first.start()
    try:
        second = RuntimeHealthSocketServer(
            socket_path=path,
            mode=0o660,
            snapshot_provider=lambda: {"device_id": "second"},
        )
        with pytest.raises(OSError) as raised:
            await second.start()
        assert raised.value.errno == errno.EADDRINUSE

        # The point of refusing: the first runtime is still the one answering.
        served = await _read_json_line(path, b"GET_HEALTH\n")
        assert served["health"]["device_id"] == "first"
    finally:
        await first.close()


@pytest.mark.asyncio
async def test_a_busy_packaged_default_does_not_fall_back_to_another_path():
    """The errno filter, on the one path the fallback applies to.

    The refusal is injected here because `/run/ori/health.sock` cannot be bound
    on a developer machine — that the implementation really produces this errno
    against a live listener is proven separately, on a real pathname, by
    `test_a_second_runtime_cannot_take_a_path_the_first_is_serving`. What this
    covers is what the fallback does with it: answering a second runtime by
    quietly serving health somewhere else would leave the first holding the
    socket a fleet reads while the second reports itself healthy elsewhere.
    """
    server = RuntimeHealthSocketServer(
        socket_path=_PACKAGED_DEFAULT,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "dev-01"},
    )
    server._prepare_socket_path = _raising(  # type: ignore[method-assign]
        OSError(errno.EADDRINUSE, "already serving", _PACKAGED_DEFAULT)
    )

    with pytest.raises(OSError) as raised:
        await server.start()
    assert raised.value.errno == errno.EADDRINUSE


@pytest.mark.parametrize(
    "outcome,expected_live",
    [
        (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), False),
        (FileNotFoundError(errno.ENOENT, "gone"), False),
        (TimeoutError("peer accepted and said nothing"), True),
        (PermissionError(errno.EACCES, "denied"), True),
        (OSError(errno.EPROTOTYPE, "something unexpected"), True),
    ],
    ids=["refused", "vanished", "timeout", "denied", "unexpected"],
)
def test_only_a_refused_connection_proves_a_socket_is_stale(
    outcome, expected_live, monkeypatch
):
    """Guessing wrong in one direction unlinks a socket a device is serving on.

    Guessing wrong in the other produces a refusal an operator can see and
    clear, so every outcome that is not a refusal is read as a live listener.
    """
    from ori.runtime_health_socket import _socket_has_a_listener

    class _Probe:
        def settimeout(self, _seconds):
            return None

        def connect(self, _path):
            raise outcome

        def close(self):
            return None

    monkeypatch.setattr(socket, "socket", lambda *a, **k: _Probe())
    assert _socket_has_a_listener(Path("/tmp/whatever.sock")) is expected_live


@pytest.mark.asyncio
async def test_a_stale_socket_file_with_no_listener_is_replaced():
    """The control. Refusing every existing socket file would strand a device.

    A socket left by a runtime that was killed has no listener, and a device
    that cannot rebind after an unclean stop has lost its health surface until
    someone deletes a file by hand.
    """
    _require_unix_socket_bindable()
    path = _short_socket_path("stale")
    abandoned = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    abandoned.bind(path)
    abandoned.close()  # the file remains; nothing is listening
    assert os.path.exists(path)

    server = RuntimeHealthSocketServer(
        socket_path=path,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "restarted"},
    )
    bound = await server.start()
    try:
        served = await _read_json_line(bound, b"GET_HEALTH\n")
        assert served["health"]["device_id"] == "restarted"
    finally:
        await server.close()


@pytest.mark.parametrize("path_kind", ["configured", "fallback"])
@pytest.mark.asyncio
async def test_a_failure_after_binding_leaves_nothing_running(path_kind, monkeypatch):
    """Startup is transactional past the bind, on both attempts.

    `_server` used to be assigned the moment the listener existed and `chmod`
    applied afterwards, so a `chmod` that failed raised out of `start()` with a
    live listener nobody held: the caller discards the object on the exception,
    `close()` is never reached, and the socket kept serving on permissions that
    were never applied.
    """
    _require_unix_socket_bindable()
    target = _short_socket_path(f"partial-{path_kind}")
    if path_kind == "configured":
        server = RuntimeHealthSocketServer(
            socket_path=target,
            mode=0o660,
            snapshot_provider=lambda: {"device_id": "dev-01"},
        )
    else:
        server = RuntimeHealthSocketServer(
            socket_path=_PACKAGED_DEFAULT,
            mode=0o660,
            snapshot_provider=lambda: {"device_id": "dev-01"},
        )
        monkeypatch.setattr(
            "ori.runtime_health_socket._HEALTH_SOCKET_DEFAULT_DEV_FALLBACK_PATH",
            target,
        )
        monkeypatch.setattr(
            server,
            "_prepare_socket_path",
            _raising(FileNotFoundError(errno.ENOENT, "absent", "/run/ori")),
        )

    real_chmod = os.chmod

    def refuse_chmod(path, mode, *args, **kwargs):
        if str(path) == target:
            raise PermissionError(errno.EPERM, "Operation not permitted", str(path))
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", refuse_chmod)

    with pytest.raises(PermissionError):
        await server.start()

    assert not os.path.exists(target), "the socket file outlived the failed start"
    with pytest.raises(OSError):
        await asyncio.open_unix_connection(path=target)


@pytest.mark.asyncio
async def test_a_path_that_is_not_the_packaged_default_never_falls_back(
    monkeypatch,
):
    """The guard's scope is unchanged: a configured path is the operator's.

    The fallback path here is deliberately usable, so a runtime that ignored
    the guard would bind it and return successfully. The refusal is therefore
    evidence about the guard rather than about a second failure.
    """
    _require_unix_socket_bindable()
    configured = "/some/configured/health.sock"
    server = RuntimeHealthSocketServer(
        socket_path=configured,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "dev-01"},
    )
    monkeypatch.setattr(
        "ori.runtime_health_socket._HEALTH_SOCKET_DEFAULT_DEV_FALLBACK_PATH",
        _short_socket_path("unused-fallback"),
    )

    def _fail_configured(socket_path: str) -> str:
        if socket_path == configured:
            raise FileNotFoundError(2, "No such file or directory", socket_path)
        return socket_path

    monkeypatch.setattr(server, "_prepare_socket_path", _fail_configured)

    with pytest.raises(FileNotFoundError):
        await server.start()


@pytest.mark.asyncio
async def test_a_runtime_that_cannot_start_the_socket_says_so_and_keeps_going(
    caplog, monkeypatch
):
    """A lost health surface must not look like a device that is not answering.

    The runtime cannot report itself degraded through the surface that failed,
    and the snapshot is the only reporter of several conditions — a sensor that
    stopped measuring, a trust anchor that verifies nothing, a signed field an
    unsigned source supplied. So the log line is the only thing distinguishing
    such a device from one that is simply unreachable, and a traceback at
    default severity is not that line.
    """
    runtime = OriRuntime.__new__(OriRuntime)
    runtime._health_socket_server = None
    runtime._health_socket_path = ""

    config = cast(
        "Any",
        SimpleNamespace(
            health_socket={
                "enabled": True,
                "path": "/run/ori/health.sock",
                "mode": 0o660,
            }
        ),
    )

    async def refuse(self):
        raise PermissionError(errno.EPERM, "Operation not permitted", "/run/ori")

    monkeypatch.setattr(RuntimeHealthSocketServer, "start", refuse)

    with caplog.at_level("DEBUG"):
        # Returns rather than raising: every other surface is unaffected, so a
        # failed health socket must not take the runtime down with it.
        await OriRuntime._start_health_socket_if_enabled(runtime, config)

    assert runtime._health_socket_server is None
    critical = [r for r in caplog.records if r.levelname == "CRITICAL"]
    assert critical, [(r.levelname, r.message) for r in caplog.records]
    assert "no health surface" in critical[-1].getMessage()


@pytest.mark.asyncio
async def test_a_departing_runtime_does_not_delete_a_replacement_s_socket():
    """The overlapping restart, driven with two real servers.

    A runtime that has stopped listening but has not yet cleaned up leaves a
    window in which a replacement detects the stale file, binds its own and
    starts answering. Cleanup that removes whatever socket holds the pathname
    then deletes the newcomer's live socket, leaving a running device with no
    health surface and nothing anywhere reporting why.
    """
    _require_unix_socket_bindable()
    path = _short_socket_path("handover")

    departing = RuntimeHealthSocketServer(
        socket_path=path,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "departing"},
    )
    await departing.start()

    # Stop serving without cleaning up: the pathname is now stale, and the
    # departing runtime's `close()` is still to come.
    assert departing._server is not None
    departing._server.close()
    await departing._server.wait_closed()
    departing._server = None

    replacement = RuntimeHealthSocketServer(
        socket_path=path,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "replacement"},
    )
    bound = await replacement.start()
    try:
        served = await _read_json_line(bound, b"GET_HEALTH\n")
        assert served["health"]["device_id"] == "replacement"

        await departing.close()

        assert os.path.exists(path), "the departing runtime removed a live socket"
        still = await _read_json_line(bound, b"GET_HEALTH\n")
        assert still["health"]["device_id"] == "replacement"
    finally:
        await replacement.close()


@pytest.mark.asyncio
async def test_a_runtime_still_removes_its_own_socket_on_close():
    """The control. Ownership must not become a licence to leave files behind.

    A socket left by every clean shutdown is the stale file the next start has
    to reason about, and the reasoning is a connection probe — cheap, but not
    something to require on every restart because cleanup stopped working.
    """
    _require_unix_socket_bindable()
    path = _short_socket_path("own-cleanup")
    server = RuntimeHealthSocketServer(
        socket_path=path,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "dev-01"},
    )
    bound = await server.start()
    assert os.path.exists(bound)
    await server.close()
    assert not os.path.exists(bound)


@pytest.mark.parametrize("occupant", ["regular-file", "nothing", "another-socket"])
def test_cleanup_with_no_bound_identity_removes_nothing(occupant):
    """A server that never bound owns nothing, and must delete nothing.

    Without the explicit no-identity guard, a `None` identity compares equal to
    what a **non-socket** path reports, so cleanup fell through and unlinked an
    ordinary file that happened to sit at the pathname — a file this module has
    no business touching, deleted by a server that never started.
    """
    from ori.runtime_health_socket import _remove_socket_file

    # A short pathname: AF_UNIX has a length limit a pytest tmp_path exceeds.
    target = Path(_short_socket_path(f"unowned-{occupant}"))
    target.unlink(missing_ok=True)
    try:
        if occupant == "regular-file":
            target.write_text("not a socket")
        elif occupant == "another-socket":
            held = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            held.bind(str(target))
            held.close()

        _remove_socket_file(str(target), None)

        assert target.exists() is (occupant != "nothing")
    finally:
        target.unlink(missing_ok=True)
