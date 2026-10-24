# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import functools
import inspect
import json
import logging
import math
import random
import socket
import ssl
import threading
import time
from typing import Any, ClassVar, Iterable

from ori.hal.base import (
    DEFAULT_POLL_INTERVAL_MS,
    AdapterConnectionError,
    AdapterReadError,
    BaseAdapter,
    HardwareCircuitBreaker,
    cache_arrival,
    poll_interval_from,
    refuse_stale_cache,
)
from ori.utils.mqtt_suback import subscription_refusal
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

# Reconnect back-off after the broker drops: full jitter over a doubling ceiling.
RECONNECT_BASE_S = 1.0
RECONNECT_CAP_S = 60.0
# A connection that lasted less than this before dropping does not reset the
# back-off: a broker accepting and dropping (two clients sharing one client id)
# would otherwise be redialled at the base delay forever.
RECONNECT_STABLE_S = 30.0

# How long a close waits for connect threads it abandoned to settle; paho's
# connect timeout defaults to 5 s. It bounds that wait only: a close issued
# during the adapter's first connect() first waits for that connect to return.
ABANDONED_CONNECT_WAIT_S = 6.0
# An abandoned socket is closed only where no registration its attempt queued
# can still run: on the event loop, after them, or off it once the loop is
# closed. Once the loop has accepted the attempt's `_settle`, the reaper thread
# owns the socket: it closes it when the loop closes, checking every
# REAPER_POLL_S, and ends the connection, keeping the descriptor, if the loop
# has neither run nor closed ABANDONED_SOCKET_OWNER_WAIT_S after the handover.
# The loop closes it if it resumes. Only an owner that does neither, for the
# life of the process, holds the descriptor.
ABANDONED_SOCKET_OWNER_WAIT_S = 60.0
REAPER_POLL_S = 0.5

# The characters MQTT reserves for subscription filters; no published message
# carries one in its topic.
MQTT_TOPIC_WILDCARDS = ("+", "#")


def topic_wildcards(topic: str) -> tuple[str, ...]:
    """The wildcard characters *topic* carries; empty for a concrete topic."""
    return tuple(char for char in MQTT_TOPIC_WILDCARDS if char in topic)


def reconnect_delay(attempt: int, rng: random.Random | None = None) -> float:
    """Seconds before reconnect *attempt* (0-based): uniform in [0, ceiling]."""
    ceiling = min(RECONNECT_CAP_S, RECONNECT_BASE_S * (2 ** min(attempt, 16)))
    return (rng or random).uniform(0.0, ceiling)


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


def _finite_float(text: str) -> float:
    number = float(text)
    if not math.isfinite(number):
        raise ValueError(f"{text} does not fit a float")
    return number


def load_json_payload(text: str, adapter_name: str) -> Any:
    """Parse one message's JSON, refusing anything that is not JSON.

    `json.loads` raises more than `JSONDecodeError`: `ValueError` for an
    integer past the digit limit and `RecursionError` for deep nesting. It also
    accepts `NaN` and `Infinity`, and reads `1e400` as infinity; none is a JSON
    number, and each would reach a cached reading as a value or timestamp.
    """
    try:
        return json.loads(
            text, parse_constant=_refuse_constant, parse_float=_finite_float
        )
    except (ValueError, RecursionError) as exc:
        raise AdapterReadError(
            f"{adapter_name}: payload is not valid JSON: {exc}"
        ) from exc


try:
    import aiomqtt as _aiomqtt  # type: ignore[import-untyped]

    _AIOMQTT_AVAILABLE = True
except ImportError:
    _aiomqtt = None
    _AIOMQTT_AVAILABLE = False


class SubscriptionRefusedError(AdapterConnectionError):
    """The broker answered a SUBSCRIBE with a refusal and kept the link up."""


# What a connect at start retries. aiomqtt raises MqttError for a broker not
# reached (refused, DNS, TLS handshake, socket timeout), for no CONNACK or
# SUBACK within the timeout, and for a CONNACK refusal, bad credentials
# included; a raw OSError is only a guard. A refused subscription is the
# adapter's own SubscriptionRefusedError. Anything else, such as paho's
# ValueError for a filter it cannot send, can never succeed and fails the
# connect.
_RETRIED_AT_START: tuple[type[BaseException], ...] = (
    OSError,
    SubscriptionRefusedError,
    *((_aiomqtt.MqttError,) if _aiomqtt is not None else ()),
)


# Deprecated spellings of each `mqtt.tls.*` setting, kept for migration.
_TLS_ALIASES: dict[str, tuple[str, ...]] = {
    "enabled": ("mqtt_tls_enabled",),
    "ca_certfile": ("mqtt_tls_ca_certfile", "tls_ca_certfile"),
    "certfile": ("mqtt_tls_certfile", "tls_certfile"),
    "keyfile": ("mqtt_tls_keyfile", "tls_keyfile"),
    "keyfile_password": ("mqtt_tls_keyfile_password", "tls_keyfile_password"),
    "insecure": ("mqtt_tls_insecure", "tls_insecure"),
}

# Shared by MQTT-family adapter declarations.  The adapter modules expose their
# own CONFIG_SCHEMA values by composing this mapping with protocol-specific
# fields; keeping the common connection grammar beside the shared consumer
# avoids MQTT aliases drifting between five adapters.
MQTT_CONNECTION_SCHEMA: dict[str, dict[str, Any]] = {
    "broker_host": {"type": "string", "required": True},
    "port": {"type": "integer", "default": 1883, "minimum": 1, "maximum": 65535},
    "mqtt": {
        "type": "object",
        "properties": {
            "username": {"type": "string"},
            "mqtt_username": {
                "type": "string",
                "deprecated": True,
                "supersedes": "username",
            },
            "password": {"type": "string"},
            "mqtt_password": {
                "type": "string",
                "deprecated": True,
                "supersedes": "password",
            },
            "client_id": {"type": "string"},
            "identifier": {
                "type": "string",
                "deprecated": True,
                "supersedes": "client_id",
            },
            "mqtt_client_id": {
                "type": "string",
                "deprecated": True,
                "supersedes": "client_id",
            },
            "keepalive": {"type": "integer", "minimum": 1},
            "mqtt_keepalive_s": {
                "type": "integer",
                "deprecated": True,
                "supersedes": "keepalive",
            },
            "clean_session": {"type": "boolean"},
            "mqtt_clean_session": {
                "type": "boolean",
                "deprecated": True,
                "supersedes": "clean_session",
            },
            "transport": {"type": "string", "enum": ["tcp", "websockets"]},
            "mqtt_transport": {
                "type": "string",
                "deprecated": True,
                "supersedes": "transport",
            },
            "timeout": {"type": "number", "minimum": 0},
            "mqtt_timeout_s": {
                "type": "number",
                "deprecated": True,
                "supersedes": "timeout",
            },
            "tls": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean", "default": False},
                    "ca_certfile": {"type": "string"},
                    "certfile": {"type": "string"},
                    "keyfile": {"type": "string"},
                    "keyfile_password": {"type": "string"},
                    "insecure": {"type": "boolean", "default": False},
                },
            },
        },
    },
    "mqtt_username": {
        "type": "string",
        "deprecated": True,
        "supersedes": "mqtt.username",
    },
    "username": {"type": "string", "deprecated": True, "supersedes": "mqtt.username"},
    "mqtt_password": {
        "type": "string",
        "deprecated": True,
        "supersedes": "mqtt.password",
    },
    "password": {"type": "string", "deprecated": True, "supersedes": "mqtt.password"},
    "mqtt_client_id": {
        "type": "string",
        "deprecated": True,
        "supersedes": "mqtt.client_id",
    },
    "client_id": {
        "type": "string",
        "deprecated": True,
        "supersedes": "mqtt.client_id",
    },
    "identifier": {
        "type": "string",
        "deprecated": True,
        "supersedes": "mqtt.client_id",
    },
    "mqtt_keepalive_s": {
        "type": "integer",
        "deprecated": True,
        "supersedes": "mqtt.keepalive",
    },
    "keepalive": {
        "type": "integer",
        "deprecated": True,
        "supersedes": "mqtt.keepalive",
    },
    "mqtt_clean_session": {
        "type": "boolean",
        "deprecated": True,
        "supersedes": "mqtt.clean_session",
    },
    "clean_session": {
        "type": "boolean",
        "deprecated": True,
        "supersedes": "mqtt.clean_session",
    },
    "mqtt_transport": {
        "type": "string",
        "deprecated": True,
        "supersedes": "mqtt.transport",
    },
    "transport": {"type": "string", "deprecated": True, "supersedes": "mqtt.transport"},
    "mqtt_timeout_s": {
        "type": "number",
        "deprecated": True,
        "supersedes": "mqtt.timeout",
    },
    "timeout": {"type": "number", "deprecated": True, "supersedes": "mqtt.timeout"},
}
for _canonical, _aliases in _TLS_ALIASES.items():
    for _alias in _aliases:
        MQTT_CONNECTION_SCHEMA[_alias] = {
            "type": MQTT_CONNECTION_SCHEMA["mqtt"]["properties"]["tls"]["properties"][
                _canonical
            ]["type"],
            "deprecated": True,
            "supersedes": f"mqtt.tls.{_canonical}",
        }
        MQTT_CONNECTION_SCHEMA["mqtt"]["properties"][_alias] = {
            "type": MQTT_CONNECTION_SCHEMA["mqtt"]["properties"]["tls"]["properties"][
                _canonical
            ]["type"],
            "deprecated": True,
            "supersedes": f"tls.{_canonical}",
        }


def _abandon_half_open(client: Any) -> None:
    """Give back what a connect that never completed left open.

    aiomqtt leaves paho's socket and its misc task running when the connect
    handshake times out or is cancelled, and the adapter never held the client,
    so nothing else would close them before paho's own keepalive. Private
    attributes of aiomqtt 2.5.x, read defensively; tested against a broker
    that accepts and never answers.
    """
    paho = getattr(client, "_client", None)
    # No DISCONNECT first: queueing one makes aiomqtt schedule a writer for a
    # socket closed before it runs, and the loop logs EBADF on every attempt.
    close = getattr(paho, "_sock_close", None)
    if callable(close):
        try:
            close()
        except Exception:
            # Best effort on an abandoned client: the socket may already be
            # closed, and the misc task below is cancelled regardless.
            pass
    task = getattr(client, "_misc_task", None)
    if isinstance(task, asyncio.Task) and not task.done():
        task.cancel()


@functools.cache
def _warn_connect_watch_unavailable() -> None:
    """Once per process: the guard against a leaked connect socket is off."""
    logger.warning(
        "aiomqtt %s has no _client_connect hook; a close during a connect may "
        "leave that attempt's socket open",
        getattr(_aiomqtt, "__version__", "?"),
    )


class _AbandonedSocketReaper:
    """The one owner of every abandoned socket whose `_settle` post was accepted.

    A daemon thread, started when a watch is handed over and gone when none is
    left, so no thread is held while idle and none delays interpreter exit. It
    never touches a loop: it reads only whether the loop has closed.
    """

    def __init__(self) -> None:
        # Reentrant: garbage collection can finalize an abandoned connect,
        # which hands over, on a thread already holding this lock.
        self._lock = threading.RLock()
        self._watches: list[_ConnectWatch] = []
        self._thread: threading.Thread | None = None
        # Completed polling passes, so a test can wait for one.
        self.passes = 0

    def hand_over(self, watch: "_ConnectWatch") -> None:
        watch._deadline = time.monotonic() + ABANDONED_SOCKET_OWNER_WAIT_S
        with self._lock:
            self._watches.append(watch)
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name="mqtt-abandoned-socket-reaper", daemon=True
                )
                self._thread.start()

    def _run(self) -> None:
        while True:
            time.sleep(REAPER_POLL_S)
            now = time.monotonic()
            with self._lock:
                remaining = [watch for watch in self._watches if watch._reap(now)]
                self._watches = remaining
                self.passes += 1
                if not remaining:
                    self._thread = None
                    return


_REAPER = _AbandonedSocketReaper()


class _ConnectWatch:
    """Owns the socket of a connect abandoned while aiomqtt's thread runs it.

    aiomqtt runs paho's blocking connect with `run_in_executor`, and cancelling
    the await does not stop the thread: a socket it opens after the abandon
    would stay open. The thread is wrapped so that, once abandoned, it either
    never connects or has its socket closed.

    The socket is closed only where no registration its attempt queued can
    still run. aiomqtt queues `add_reader` and `add_writer` with the integer
    descriptor, so a socket closed before they run would hand them a
    descriptor the OS may already have given another socket. So it is closed
    on the event loop by `_settle`, which runs after them and unregisters
    first, or off the loop only once the loop is closed and its queue
    discarded. `abandon()` tells the abandoning side whether it may close now.
    Once the loop has accepted `_settle` for an abandoned attempt, the reaper
    owns the socket: past `ABANDONED_SOCKET_OWNER_WAIT_S` it ends the
    connection, keeping the descriptor, which is closed when the loop resumes
    or closes. Only an owner that does neither, for the life of the process,
    holds it. `settled` resolves when the loop has run `_settle`. Wraps
    aiomqtt 2.5.x's private `_client_connect`, read defensively.
    """

    # What `abandon()` leaves the abandoning side to do.
    NOTHING = "nothing"
    CLOSE_NOW = "close_now"
    AWAIT_SETTLED = "await_settled"

    def __init__(
        self, client: Any, loop: asyncio.AbstractEventLoop, label: str
    ) -> None:
        self._client = client
        self._loop = loop
        self._label = label
        # Reentrant for the same reason as the reaper's.
        self._lock = threading.RLock()
        self._running = False
        self._abandoned = False
        self._posted = False
        # Under the lock: whichever side closes second does nothing.
        self._closed = False
        # Set by the reaper on handover, and once the cap has passed.
        self._deadline = math.inf
        self._past_cap = False
        self._disposed = threading.Event()
        # Set once the loop has accepted the `_settle` post; observable.
        self.post_accepted = threading.Event()
        self.settled: asyncio.Future[None] = loop.create_future()

    @classmethod
    def install(cls, client: Any, label: str) -> "_ConnectWatch | None":
        original = getattr(client, "_client_connect", None)
        if not callable(original):
            _warn_connect_watch_unavailable()
            return None
        watch = cls(client, asyncio.get_running_loop(), label)

        def connect() -> None:
            with watch._lock:
                if watch._abandoned:
                    return
                watch._running = True
            try:
                original()
            finally:
                watch._dispose_after_connect()

        client._client_connect = connect
        return watch

    def _dispose_after_connect(self) -> None:
        """On the executor thread: hand the socket to the loop and return.

        A refused post means the loop is closed, so nothing queued can run and
        the thread closes the socket. An accepted post for an abandoned attempt
        goes to the reaper, since a stopped loop discards it when closed. The
        thread never waits, so it holds no executor slot and no exit.
        """
        try:
            self._loop.call_soon_threadsafe(self._settle)
        except RuntimeError:
            self._close_from_thread()
            return
        with self._lock:
            self._posted = True
            abandoned = self._abandoned
        self.post_accepted.set()
        if abandoned:
            # Otherwise an abandon from here on finds the post and hands over.
            _REAPER.hand_over(self)

    def _reap(self, now: float) -> bool:
        """One reaper pass, off the loop; whether the reaper keeps the watch."""
        if self._disposed.is_set() or self._closed:
            return False
        if self._loop.is_closed():
            self._close_from_thread()
            return False
        if now >= self._deadline and not self._past_cap:
            self._past_cap = True
            if self._shut_down_from_thread():
                logger.warning(
                    "%s: an abandoned connect's event loop has neither run nor "
                    "closed in %.0fs; its broker connection is ended now, and its "
                    "descriptor is closed when the loop resumes or closes",
                    self._label,
                    ABANDONED_SOCKET_OWNER_WAIT_S,
                )
        return True

    def _shut_down_from_thread(self) -> bool:
        """End the connection but keep the descriptor, so it cannot be reused.

        The attempt's queued registrations can then only touch this dead
        socket, and `_settle` still unregisters and closes it if the loop
        resumes. Returns whether there was a socket to end.
        """
        with self._lock:
            if not self._abandoned or self._closed:
                return False
            sock = getattr(getattr(self._client, "_client", None), "_sock", None)
            if sock is None:
                return False
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                # Already disconnected; the descriptor is kept either way.
                pass
            return True

    def _close_from_thread(self) -> None:
        """Close an abandoned socket once the loop is closed; never touches it."""
        with self._lock:
            if not self._abandoned or self._closed:
                return
            self._closed = True
            paho = getattr(self._client, "_client", None)
            sock = getattr(paho, "_sock", None)
            if paho is None or sock is None:
                return
            paho._sock = None
            try:
                sock.close()
            except OSError:
                # Already closed by the peer side or the OS; nothing is left
                # to release, and paho no longer holds it.
                pass

    def _settle(self) -> None:
        # Queued after the reader and writer aiomqtt registered from the same
        # thread, so they are removed rather than left on a closed socket.
        with self._lock:
            if self._abandoned and not self._closed:
                self._closed = True
                _abandon_half_open(self._client)
        self._disposed.set()
        if not self.settled.done():
            self.settled.set_result(None)

    def abandon(self) -> str:
        """Mark the attempt abandoned, on the loop, and say what is left to do.

        Never started: it never will, so there is no socket. Settled: the
        registrations have run, so the caller closes now. Otherwise the watch
        owns disposal and the caller awaits `settled`; a post already accepted
        goes to the reaper, on the same path the thread uses.
        """
        with self._lock:
            self._abandoned = True
            if not self._running:
                return self.NOTHING
            if self._disposed.is_set():
                return self.CLOSE_NOW
            posted = self._posted
        if posted:
            _REAPER.hand_over(self)
        return self.AWAIT_SETTLED


class MqttCachedAdapter(BaseAdapter):
    """Reusable base for MQTT adapters that subscribe and cache latest values."""

    # Reads past the silence bound are refused. Retained replays are ignored
    # by every adapter, bounded or not.
    # False for a publish-on-change or duty-cycled producer, where silence is
    # not staleness, until a keepalive or reporting guarantee bounds it.
    SILENCE_BOUNDED: ClassVar[bool] = True

    def __init__(self) -> None:
        self._connected = False
        self._broker_host: str = ""
        self._port: int = 1883

        self._breaker: HardwareCircuitBreaker | None = None
        self._client: Any = None
        self._listener_task: asyncio.Task[None] | None = None
        self._topics: tuple[str, ...] = ()
        self._client_kwargs: dict[str, Any] = {}
        # Connect threads abandoned mid-connect, awaited by close().
        self._abandoned_connects: set[asyncio.Future[None]] = set()
        # False while the broker connection is down and being retried.
        self._link_up = False

        # topic -> (value, timestamp_ms, raw_payload)
        self._cache: dict[str, tuple[float, int, Any]] = {}
        # topic -> why its last payload was refused; cleared by an accepted one
        self._refused: dict[str, str] = {}
        # topic -> receiver monotonic arrival time of the cached value
        self._arrived_at: dict[str, float] = {}
        self._poll_interval_ms: int = DEFAULT_POLL_INTERVAL_MS

    @property
    def is_connected(self) -> bool:
        return self._connected and _AIOMQTT_AVAILABLE

    def _ensure_aiomqtt_available(self) -> None:
        if not _AIOMQTT_AVAILABLE or _aiomqtt is None:
            raise AdapterConnectionError(
                f"{self.adapter_name}: 'aiomqtt' is not installed. Run: pip install aiomqtt"
            )

    @staticmethod
    def _as_bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        return default

    def _build_mqtt_client_kwargs(self, config: dict) -> dict[str, Any]:
        """Build aiomqtt.Client kwargs from raw or loader-resolved MQTT config.

        Production configuration reaches this method only after the loader has
        canonicalised aliases. The compatibility branches remain for direct HAL
        callers and older embedding integrations; their duplicate detection is
        retained rather than making direct use silently choose a TLS setting.
        """
        mqtt_cfg = config.get("mqtt")
        if not isinstance(mqtt_cfg, dict):
            mqtt_cfg = {}

        def _first(*keys: str) -> Any:
            for key in keys:
                if key in config and config.get(key) is not None:
                    return config.get(key)
                if key in mqtt_cfg and mqtt_cfg.get(key) is not None:
                    return mqtt_cfg.get(key)
            return None

        kwargs: dict[str, Any] = {}

        username = _first("mqtt_username", "username")
        password = _first("mqtt_password", "password")
        identifier = _first("mqtt_client_id", "client_id", "identifier")
        keepalive = _first("mqtt_keepalive_s", "keepalive")
        clean_session = _first("mqtt_clean_session", "clean_session")
        transport = _first("mqtt_transport", "transport")
        timeout = _first("mqtt_timeout_s", "timeout")

        if username not in (None, ""):
            kwargs["username"] = str(username)
        if password not in (None, ""):
            kwargs["password"] = str(password)
        if identifier not in (None, ""):
            kwargs["identifier"] = str(identifier)
        if keepalive not in (None, ""):
            kwargs["keepalive"] = int(keepalive)
        if clean_session is not None and not self._as_bool(clean_session, True):
            raise AdapterConnectionError(
                f"{self.adapter_name}: a persistent MQTT session is refused for a "
                "sensor. A broker queues messages for it while the runtime is "
                "away and delivers them on reconnect, and the freshness bound "
                "would time each one from its delivery, not its publication."
            )
        # Always clean, so nothing queued for this client is delivered on
        # (re)connect. A retained message still is, and every adapter ignores it.
        kwargs["clean_session"] = True
        if transport not in (None, ""):
            kwargs["transport"] = str(transport)
        if timeout not in (None, ""):
            seconds = float(timeout)
            # aiomqtt times out at once on zero, and the connect would be
            # retried forever as an unreachable broker.
            if not math.isfinite(seconds) or seconds <= 0:
                raise AdapterConnectionError(
                    f"{self.adapter_name}: the MQTT timeout must be a finite "
                    f"number of seconds above zero, got {timeout!r}"
                )
            kwargs["timeout"] = seconds

        tls_cfg = mqtt_cfg.get("tls")
        if not isinstance(tls_cfg, dict):
            tls_cfg = {}

        def _tls_setting(canonical: str) -> Any:
            """Resolve one raw compatibility spelling, refusing duplicates."""
            supplied: list[tuple[str, Any]] = []
            if canonical in tls_cfg:
                supplied.append((f"mqtt.tls.{canonical}", tls_cfg[canonical]))
            for alias in _TLS_ALIASES[canonical]:
                if alias in config:
                    supplied.append((alias, config[alias]))
                if alias in mqtt_cfg:
                    supplied.append((f"mqtt.{alias}", mqtt_cfg[alias]))
            if len(supplied) > 1:
                names = ", ".join(repr(name) for name, _ in supplied)
                raise AdapterConnectionError(
                    f"{self.adapter_name}: {names} all supply the TLS setting "
                    f"'mqtt.tls.{canonical}'. Refused rather than resolved by "
                    f"precedence, even where the values agree. Keep "
                    f"'mqtt.tls.{canonical}' and remove the others."
                )
            return supplied[0][1] if supplied else None

        tls_enabled = self._as_bool(_tls_setting("enabled"), default=False)
        tls_ca_certfile = _tls_setting("ca_certfile")
        tls_certfile = _tls_setting("certfile")
        tls_keyfile = _tls_setting("keyfile")
        tls_keyfile_password = _tls_setting("keyfile_password")
        tls_insecure = _tls_setting("insecure")

        needs_tls_context = tls_enabled or any(
            v not in (None, "")
            for v in (tls_ca_certfile, tls_certfile, tls_keyfile, tls_keyfile_password)
        )

        if needs_tls_context:
            try:
                context = ssl.create_default_context(
                    cafile=str(tls_ca_certfile) if tls_ca_certfile else None
                )
                if tls_certfile:
                    context.load_cert_chain(
                        certfile=str(tls_certfile),
                        keyfile=str(tls_keyfile) if tls_keyfile else None,
                        password=(
                            str(tls_keyfile_password)
                            if tls_keyfile_password not in (None, "")
                            else None
                        ),
                    )
                if self._as_bool(tls_insecure, default=False):
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                kwargs["tls_context"] = context
            except Exception as exc:
                raise AdapterConnectionError(
                    f"{self.adapter_name}: invalid MQTT TLS configuration: {exc}"
                ) from exc

        # Keep compatibility across aiomqtt versions by filtering unknown kwargs.
        if _aiomqtt is None:
            return kwargs
        try:
            sig = inspect.signature(_aiomqtt.Client)
        except (TypeError, ValueError):
            return kwargs

        params = sig.parameters
        accepts_kwargs = any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
        )
        if accepts_kwargs:
            return kwargs

        supported = set(params)
        filtered = {k: v for k, v in kwargs.items() if k in supported}
        dropped = sorted(set(kwargs) - set(filtered))
        if dropped:
            logger.warning(
                "%s: ignoring unsupported aiomqtt.Client options: %s",
                self.adapter_name,
                ", ".join(dropped),
            )
        return filtered

    async def _connect_mqtt(
        self,
        *,
        config: dict,
        topics: Iterable[str],
        default_port: int = 1883,
        broker_host_key: str = "broker_host",
        port_key: str = "port",
        listener_name: str | None = None,
    ) -> None:
        self._ensure_aiomqtt_available()

        self._broker_host = str(config.get(broker_host_key, "")).strip()
        self._port = int(config.get(port_key, default_port))
        self._poll_interval_ms = poll_interval_from(
            config, DEFAULT_POLL_INTERVAL_MS, self.adapter_name
        )
        self._breaker = HardwareCircuitBreaker(self.adapter_name, config)

        if not self._broker_host:
            raise AdapterConnectionError(
                f"{self.adapter_name}: '{broker_host_key}' is required in sensor config."
            )
        if self._port <= 0:
            raise AdapterConnectionError(
                f"{self.adapter_name}: '{port_key}' must be > 0."
            )
        # A value is cached under the topic of the message that carried it and
        # read back under the subscribed one, so a filter would never read.
        topics = tuple(topics)
        for topic in topics:
            if topic_wildcards(topic):
                raise AdapterConnectionError(
                    f"{self.adapter_name}: topic {topic!r} is a wildcard "
                    "subscription, and a sensor reads one concrete topic."
                )

        try:
            self._client_kwargs = self._build_mqtt_client_kwargs(config)
            self._topics = topics
            reached = await self._open_client(at_start=True)
        except Exception as exc:
            await self._close_mqtt_quietly()
            raise AdapterConnectionError(
                f"{self.adapter_name}: failed to connect/subscribe to "
                f"{self._broker_host}:{self._port}: {exc}"
            ) from exc
        self._link_up = reached
        self._listener_task = asyncio.create_task(
            self._supervise(),
            name=listener_name or f"mqtt-listener:{self._broker_host}:{self._port}",
        )

    async def _open_client(self, *, at_start: bool = False) -> bool:
        """Connect and subscribe to every topic, or leave no client behind.

        At start, a broker that cannot be reached, or that refuses the
        connection or a subscription, returns False instead of raising, and the
        supervisor retries it under the reconnect back-off, as after a drop.
        Anything else fails the connect.
        """
        if _aiomqtt is None:
            raise AdapterConnectionError(
                "MQTT adapter: 'aiomqtt' is not installed. Run: pip install aiomqtt"
            )
        client = _aiomqtt.Client(
            hostname=self._broker_host,
            port=self._port,
            **self._client_kwargs,
        )
        try:
            label = f"{self.adapter_name} {self._broker_host}:{self._port}"
            await self._connect_and_subscribe(
                client, _ConnectWatch.install(client, label)
            )
        except _RETRIED_AT_START as exc:
            if not at_start:
                raise
            logger.warning(
                "%s: connect at start to %s:%s failed: %s; retrying under the "
                "reconnect back-off, reads refuse until a value arrives",
                self.adapter_name,
                self._broker_host,
                self._port,
                exc,
            )
            return False
        return True

    async def _connect_and_subscribe(
        self, client: Any, watch: _ConnectWatch | None
    ) -> None:
        # Captured now: a close may come from a finalizer on another thread.
        own_loop = asyncio.get_running_loop()
        try:
            self._client = await client.__aenter__()
        except BaseException:
            # The watch decides: closing here, ahead of registrations the
            # connect thread has queued, would hand them a reusable descriptor.
            if watch is None:
                _abandon_half_open(client)
            else:
                left = watch.abandon()
                if left == _ConnectWatch.CLOSE_NOW:
                    # The thread's registrations have run. aiomqtt can still
                    # queue an `add_writer` through `call_soon_threadsafe` from
                    # the loop thread itself; no path was found that queues one
                    # before a CONNACK refusal or timeout, which is what lands
                    # here, so this closes at once.
                    _abandon_half_open(client)
                elif left == _ConnectWatch.AWAIT_SETTLED:
                    self._abandoned_connects.add(watch.settled)
                    watch.settled.add_done_callback(self._abandoned_connects.discard)
            raise
        try:
            for topic in self._topics:
                # Sending SUBSCRIBE is not being subscribed: a broker can answer
                # with a refusal and keep the link up.
                refusal = subscription_refusal(await self._client.subscribe(topic))
                if refusal is not None:
                    raise SubscriptionRefusedError(
                        f"the broker refused the subscription to topic={topic!r} "
                        f"({refusal}); check the broker's ACL for this client"
                    )
        except GeneratorExit:
            # Closed, not cancelled: nothing may be awaited. The connect
            # thread's registrations have run, but SUBSCRIBE queues its own
            # `add_writer` through `call_soon_threadsafe`, so the close is
            # queued behind it while the loop can still run it.
            held, self._client = self._client, None
            try:
                own_loop.call_soon_threadsafe(_abandon_half_open, held)
            except RuntimeError:
                # The loop is closed: nothing queued on it can run.
                _abandon_half_open(held)
            raise
        except BaseException:
            await self._close_mqtt_quietly()
            raise

    async def health_check(self) -> bool:
        """Operational health: the broker link is up with every subscription
        granted, and the listener is alive.

        Not `is_connected`, which says only that connect() returned: an adapter
        retrying its broker is connected and unhealthy. Whether values are
        fresh is the runtime's staleness watch, not this.
        """
        task = self._listener_task
        return (
            self._connected and self._link_up and task is not None and not task.done()
        )

    @property
    def connection_retrying(self) -> bool:
        return (
            self._listener_task is not None
            and not self._listener_task.done()
            and not self._link_up
        )

    async def _supervise(self) -> None:
        """The adapter's one listener: consume, and reconnect when the broker drops.

        Only this task ever holds the client after connect, so a reconnect
        cannot leave two listeners. Cancelling it (close) ends a pending
        back-off or reconnect as well. A broker not reached at start enters
        the same back-off before any connection has been held.
        """
        loop = asyncio.get_running_loop()
        attempt = 0
        while True:
            if self._link_up:
                connected_at = loop.time()
                await self._listen_loop()
                self._mark_link_down()
                await self._close_mqtt_quietly()
                if loop.time() - connected_at >= RECONNECT_STABLE_S:
                    attempt = 0
            while True:
                await asyncio.sleep(reconnect_delay(attempt))
                attempt += 1
                try:
                    await self._open_client()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(
                        "%s: reconnect %d to %s:%s failed: %s",
                        self.adapter_name,
                        attempt,
                        self._broker_host,
                        self._port,
                        exc,
                    )
                    continue
                break
            self._link_up = True
            logger.info(
                "%s: connected to %s:%s after %d attempt(s) and subscribed to "
                "%d topic(s)",
                self.adapter_name,
                self._broker_host,
                self._port,
                attempt,
                len(self._topics),
            )

    def _mark_link_down(self) -> None:
        """No cached value survives the connection it arrived on."""
        self._link_up = False
        self._cache.clear()
        self._arrived_at.clear()
        self._refused.clear()
        logger.warning(
            "%s: lost the broker at %s:%s; reads refuse until a value arrives "
            "after reconnecting",
            self.adapter_name,
            self._broker_host,
            self._port,
        )

    async def close(self) -> None:
        """Close for the whole MQTT family, under the lifecycle contract.

        Every subclass had the same two-line `close()`; it lives here once so
        that the guarantee cannot be adopted by some of them and not others.
        """
        async with self._closing():
            await self._close_mqtt()

    async def _close_mqtt(self) -> None:
        """Give back the listener and the client, finished or not.

        Called from `close()` and as the `release` of an abandoned connect, so
        it must be idempotent and safe on a partial connect.
        """
        task = self._listener_task
        self._listener_task = None
        self._link_up = False
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        await self._close_mqtt_quietly()
        if self._abandoned_connects:
            _, unsettled = await asyncio.wait(
                set(self._abandoned_connects), timeout=ABANDONED_CONNECT_WAIT_S
            )
            if unsettled:
                logger.warning(
                    "%s: %d connect thread(s) to %s:%s still running after %.0fs; "
                    "when each finishes, its socket is closed on this event loop, "
                    "or off it once the loop is closed",
                    self.adapter_name,
                    len(unsettled),
                    self._broker_host,
                    self._port,
                    ABANDONED_CONNECT_WAIT_S,
                )

    async def _close_mqtt_quietly(self) -> None:
        client = self._client
        self._client = None
        if client is None:
            return
        try:
            await client.__aexit__(None, None, None)
        except Exception:
            logger.warning("%s: exception while closing MQTT client", self.adapter_name)

    async def _listen_loop(self) -> None:
        """Consume until the connection ends; cancellation propagates."""
        if self._client is None:
            return

        try:
            async for message in self._client.messages:
                topic = str(message.topic)
                if getattr(message, "retain", False):
                    # A retained message is replayed on subscribe with no age
                    # the receiver can know; only a live delivery is a reading.
                    # This holds for an on-change source too: its cache clears
                    # on a link drop, and a replay given a fresh arrival would
                    # be served as current with no silence bound to expire it.
                    logger.info(
                        "%s: ignoring retained message on topic=%s",
                        self.adapter_name,
                        topic,
                    )
                    continue
                try:
                    await self._handle_message(topic, message.payload)
                except AdapterReadError as exc:
                    self._refuse_topic(topic, str(exc))
                    logger.warning(
                        "%s: refused payload on topic=%s: %s",
                        self.adapter_name,
                        topic,
                        exc,
                    )
                except Exception as exc:
                    # No single message ends the listener: a payload a parser
                    # did not anticipate is refused like any other, and the
                    # next one is still consumed.
                    self._refuse_topic(topic, f"{type(exc).__name__}: {exc}")
                    logger.exception(
                        "%s: refused a payload that could not be handled on topic=%s",
                        self.adapter_name,
                        topic,
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "%s: listener lost the broker %s:%s: %s",
                self.adapter_name,
                self._broker_host,
                self._port,
                exc,
            )

    def _refuse_topic(self, topic: str, reason: str) -> None:
        """A refused payload withdraws the value it would have replaced.

        Serving the earlier value would present it as current while the source
        reports something the runtime could not accept.
        """
        self._cache.pop(topic, None)
        self._arrived_at.pop(topic, None)
        self._refused[topic] = reason

    def _require_listener(self) -> None:
        """Refuse a read once the listener has stopped.

        The cache holds the last value the listener delivered. Served after the
        listener ends, it reads as a live measurement: the runtime records the
        sensor as seen, the staleness watch stays quiet, and a Tier D condition
        evaluates a frozen value. A stopped listener is a silent sensor.
        """
        task = self._listener_task
        if task is None or task.done():
            raise AdapterReadError(
                f"{self.adapter_name}: the MQTT listener is not running; "
                "the cached value is no longer a live reading"
            )
        if not self._link_up:
            raise AdapterReadError(
                f"{self.adapter_name}: the broker connection is down and being "
                "retried; no value is current"
            )

    def _cached_value(
        self, topic: str, missing: str = "no MQTT data cached yet"
    ) -> tuple[float, int, Any]:
        """The cached value for *topic*, or a refusal naming why there is none.

        Called outside the breaker: a source that has not published, or whose
        last payload was refused, is not a fault to back off from, and counted
        there it would keep the next real value refused for the recovery window.
        """
        cached = self._cache.get(topic)
        if cached is not None:
            return cached
        reason = self._refused.get(topic)
        if reason is not None:
            raise AdapterReadError(
                f"{self.adapter_name}: the last payload on topic={topic} was "
                f"refused ({reason}); no current value"
            )
        raise AdapterReadError(f"{self.adapter_name}: {missing}")

    async def _handle_message(self, topic: str, payload: Any) -> None:
        """Override in concrete adapters to parse and cache message values."""
        raise NotImplementedError

    def _cache_value(self, topic: str, value: float, raw_payload: Any) -> None:
        self._cache[topic] = (float(value), now_ms(), raw_payload)
        self._arrived_at[topic] = cache_arrival()
        self._refused.pop(topic, None)
        if self._breaker is not None:
            self._breaker.record_fresh_value()

    def _require_fresh(self, topic: str) -> None:
        """Refuse the cached value for *topic* once it is past the silence bound.

        Called outside the breaker. A silent source is not a fault the breaker
        should back off from: counted there, a gap would keep reads refused for
        the recovery timeout after the source resumed, and Tier D blind with it.
        """
        if not self.SILENCE_BOUNDED:
            return
        refuse_stale_cache(
            self._arrived_at.get(topic), self._poll_interval_ms, self.adapter_name
        )

    @staticmethod
    def parse_numeric_payload(payload: Any) -> tuple[float, Any]:
        """Parse common MQTT payload formats into a float.

        Supports:
        - plain numeric strings/bytes, e.g. b"42.5"
        - JSON object payload with a `value` field, e.g. {"value": 42.5}
        """
        raw_payload: Any = payload
        if isinstance(payload, (bytes, bytearray)):
            text = bytes(payload).decode("utf-8", errors="replace").strip()
            raw_payload = text
        else:
            text = str(payload).strip()
            raw_payload = text

        if not text:
            raise AdapterReadError("MQTT payload is empty")

        parsed: Any = text
        if text.startswith("{") or text.startswith("["):
            parsed = load_json_payload(text, "MQTT")

        if isinstance(parsed, dict):
            if "value" not in parsed:
                raise AdapterReadError("JSON payload missing required 'value' field")
            value_candidate = parsed["value"]
            raw_payload = parsed
        else:
            value_candidate = parsed

        try:
            value = float(value_candidate)
        except (TypeError, ValueError, OverflowError) as exc:
            raise AdapterReadError(
                f"MQTT payload value is not numeric: {value_candidate!r}"
            ) from exc
        if not math.isfinite(value):
            raise AdapterReadError(f"MQTT payload value is not finite: {value!r}")
        return value, raw_payload
