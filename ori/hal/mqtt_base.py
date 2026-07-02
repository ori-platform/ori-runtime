# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import inspect
import json
import logging
import ssl
from typing import Any, Iterable

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    BaseAdapter,
    HardwareCircuitBreaker,
)
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    import aiomqtt as _aiomqtt  # type: ignore[import-untyped]

    _AIOMQTT_AVAILABLE = True
except ImportError:
    _aiomqtt = None
    _AIOMQTT_AVAILABLE = False


class MqttCachedAdapter(BaseAdapter):
    """Reusable base for MQTT adapters that subscribe and cache latest values."""

    def __init__(self) -> None:
        self._connected = False
        self._broker_host: str = ""
        self._port: int = 1883

        self._breaker: HardwareCircuitBreaker | None = None
        self._client: Any = None
        self._listener_task: asyncio.Task[None] | None = None

        # topic -> (value, timestamp_ms, raw_payload)
        self._cache: dict[str, tuple[float, int, Any]] = {}

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
        """Build aiomqtt.Client kwargs from flat and nested mqtt config."""
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
        if clean_session is not None:
            kwargs["clean_session"] = self._as_bool(clean_session)
        if transport not in (None, ""):
            kwargs["transport"] = str(transport)
        if timeout not in (None, ""):
            kwargs["timeout"] = float(timeout)

        tls_cfg = mqtt_cfg.get("tls")
        if not isinstance(tls_cfg, dict):
            tls_cfg = {}

        tls_enabled = self._as_bool(
            _first("mqtt_tls_enabled")
            if _first("mqtt_tls_enabled") is not None
            else tls_cfg.get("enabled"),
            default=False,
        )

        tls_ca_certfile = _first("mqtt_tls_ca_certfile", "tls_ca_certfile")
        tls_certfile = _first("mqtt_tls_certfile", "tls_certfile")
        tls_keyfile = _first("mqtt_tls_keyfile", "tls_keyfile")
        tls_keyfile_password = _first(
            "mqtt_tls_keyfile_password", "tls_keyfile_password"
        )
        tls_insecure = _first("mqtt_tls_insecure", "tls_insecure")
        if tls_insecure is None:
            tls_insecure = tls_cfg.get("insecure")

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
        self._breaker = HardwareCircuitBreaker(self.adapter_name, config)

        if not self._broker_host:
            raise AdapterConnectionError(
                f"{self.adapter_name}: '{broker_host_key}' is required in sensor config."
            )
        if self._port <= 0:
            raise AdapterConnectionError(
                f"{self.adapter_name}: '{port_key}' must be > 0."
            )

        try:
            client_kwargs = self._build_mqtt_client_kwargs(config)
            client = _aiomqtt.Client(
                hostname=self._broker_host,
                port=self._port,
                **client_kwargs,
            )
            self._client = await client.__aenter__()
            for topic in topics:
                await self._client.subscribe(topic)
            self._connected = True
            self._listener_task = asyncio.create_task(
                self._listen_loop(),
                name=listener_name or f"mqtt-listener:{self._broker_host}:{self._port}",
            )
        except Exception as exc:
            await self._close_mqtt_quietly()
            raise AdapterConnectionError(
                f"{self.adapter_name}: failed to connect/subscribe to "
                f"{self._broker_host}:{self._port}: {exc}"
            ) from exc

    async def _close_mqtt(self) -> None:
        self._connected = False

        task = self._listener_task
        self._listener_task = None
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        await self._close_mqtt_quietly()

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
        if self._client is None:
            return

        try:
            async for message in self._client.messages:
                topic = str(message.topic)
                try:
                    await self._handle_message(topic, message.payload)
                except AdapterReadError as exc:
                    logger.warning(
                        "%s: skipping invalid payload on topic=%s: %s",
                        self.adapter_name,
                        topic,
                        exc,
                    )
        except asyncio.CancelledError:
            return
        except Exception:
            logger.exception(
                "%s: listener loop crashed for broker %s:%s",
                self.adapter_name,
                self._broker_host,
                self._port,
            )

    async def _handle_message(self, topic: str, payload: Any) -> None:
        """Override in concrete adapters to parse and cache message values."""
        raise NotImplementedError

    def _cache_value(self, topic: str, value: float, raw_payload: Any) -> None:
        self._cache[topic] = (float(value), now_ms(), raw_payload)

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
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise AdapterReadError(f"Invalid JSON payload: {exc}") from exc

        if isinstance(parsed, dict):
            if "value" not in parsed:
                raise AdapterReadError("JSON payload missing required 'value' field")
            value_candidate = parsed["value"]
            raw_payload = parsed
        else:
            value_candidate = parsed

        try:
            return float(value_candidate), raw_payload
        except (TypeError, ValueError) as exc:
            raise AdapterReadError(
                f"MQTT payload value is not numeric: {value_candidate!r}"
            ) from exc
