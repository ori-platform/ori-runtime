# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ori Runtime — main entry point.

Wires every component built into a running system:

    runtime = OriRuntime(config_path="ori.yaml")
    asyncio.run(runtime.start())

Or via the CLI entry point::

    ori-runtime --config /path/to/ori.yaml
"""

import asyncio
import logging
import os
import signal
import uuid
from pathlib import Path
from typing import Any

from ori.actions.alert_failover import AlertFailoverSender
from ori.actions.coap import CoAPAction
from ori.actions.logger import LoggerAction
from ori.actions.process_manager import ProcessManagerAction
from ori.actions.relay import RelayAction
from ori.actions.sms import SMSAction
from ori.actions.system_control import SystemControlAction
from ori.actions.whatsapp import TwilioProvider, WhatsAppAction
from ori.config import Config, ConfigValidationError
from ori.hal.base import AdapterReadError, BaseAdapter
from ori.hal.protocol_registry import UnknownProtocolError, make_adapter
from ori.network.event_bus import EventBus
from ori.network.events import OriEvent
from ori.network.sms_webhook import SMSWebhookServer
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import IntelligenceElevator, SkillContext
from ori.reasoning.local_llm import LocalLLM
from ori.skills.loader import SkillLoader
from ori.state.store import StateStore

logger = logging.getLogger(__name__)

WATCHDOG_DEVICE = "/dev/watchdog"
WATCHDOG_PING_INTERVAL = 10  # seconds — kernel expects a ping at least this often
WATCHDOG_TIMEOUT = 60  # seconds — kernel reboots if no ping within this window
EXTERNAL_WATCHDOG_GPIO = 17  # BCM pin for optional external watchdog heartbeat
EXTERNAL_WATCHDOG_PING_S = 30  # heartbeat interval for external watchdog devices
TIER_D_DRAIN_TIMEOUT = 5.0  # seconds — wait for in-flight Tier D tasks on shutdown


class OriRuntime:
    """Main runtime class. Wires all Ori components and manages the event loop.

    Args:
        config_path: Path to ``ori.yaml``. Defaults to ``"ori.yaml"`` in the
            current working directory.
    """

    def __init__(self, config_path: str = "ori.yaml") -> None:
        self._config_path = config_path
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._adapters: list[BaseAdapter] = []
        self._state_store: StateStore | None = None
        self._background_tasks: list[asyncio.Task] = []
        self._sms_action: SMSAction | None = None
        self._sms_webhook_server: SMSWebhookServer | None = None
        self._dispatcher: ActionDispatcher | None = None
        self._event_bus: EventBus | None = None
        self._skill_loader: SkillLoader | None = None
        self._skills_dir: str | None = None
        self._loaded_skills: list[Any] = []
        self._skill_subscriptions: list[tuple[str, Any]] = []
        self._skill_reload_lock: asyncio.Lock | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    async def reload_skills(self) -> bool:
        """Reload skills from ``skills_dir`` without restarting the runtime.

        This method preserves the same validation and sandbox rules as startup:
        it reuses :class:`ori.skills.loader.SkillLoader` and only swaps handlers
        after the new skill set has been loaded successfully.
        """
        if self._skill_reload_lock is None:
            self._skill_reload_lock = asyncio.Lock()

        async with self._skill_reload_lock:
            if self._event_bus is None or self._skill_loader is None:
                logger.warning(
                    "[runtime] skill reload requested before startup completed"
                )
                return False

            skills_dir = self._skills_dir or str(
                Path(self._config_path).parent / "skills"
            )
            loaded = self._skill_loader.load_all(skills_dir)

            # Safety-first fallback: do not replace a working handler graph
            # with an empty one due to a transient load issue.
            if not loaded and self._loaded_skills:
                logger.warning(
                    "[runtime] skill reload found 0 valid skills in %s — keeping existing handlers",
                    skills_dir,
                )
                return False

            self._unregister_skill_handlers()
            for skill in loaded:
                subscriptions = self._skill_loader.register(skill, self._event_bus)
                self._skill_subscriptions.extend(subscriptions)

            self._loaded_skills = loaded
            logger.info(
                "[runtime] skills reloaded — skills=%d triggers=%d source=%s",
                len(self._loaded_skills),
                sum(len(s.triggers) for s in self._loaded_skills),
                skills_dir,
            )
            return True

    async def start(self) -> None:
        """Full startup sequence. Blocks until a shutdown signal is received."""

        # ── Step A: Load and validate config ─────────────────────────────────
        try:
            config = Config.load(self._config_path)
        except ConfigValidationError:
            logger.exception("[runtime] config validation failed — aborting")
            raise

        from logging.handlers import RotatingFileHandler

        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, config.logging.level, logging.INFO))

        # Prevent duplicate file handlers when start() is called multiple times.
        target_log_file = os.path.abspath(config.logging.file)
        for handler in list(root_logger.handlers):
            if (
                isinstance(handler, RotatingFileHandler)
                and os.path.abspath(getattr(handler, "baseFilename", ""))
                == target_log_file
            ):
                root_logger.removeHandler(handler)
                try:
                    handler.close()
                except Exception:
                    logger.debug(
                        "[runtime] failed to close stale rotating handler: %r",
                        handler,
                    )

        file_handler = RotatingFileHandler(
            config.logging.file,
            maxBytes=config.logging.max_bytes,
            backupCount=config.logging.backup_count,
        )
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        root_logger.addHandler(file_handler)

        logger.info(
            "[runtime] config loaded — device=%s location=%s deployment=%s",
            config.device.id,
            config.device.location,
            config.device.deployment_type,
        )

        # ── Step B: Open StateStore ───────────────────────────────────────────
        db_path: str = config.raw.get("database", {}).get("path", "ori_state.db")
        self._state_store = StateStore(db_path=db_path)
        await self._state_store.open()

        # ── Step C: Instantiate action executors and ActionDispatcher ─────────
        whatsapp_action = WhatsAppAction(provider=TwilioProvider())
        sms_action = SMSAction(state_store=self._state_store)
        coap_action = CoAPAction(config=config.actions.coap)
        self._sms_action = sms_action
        logger_action = LoggerAction()
        process_manager_action = ProcessManagerAction()
        system_control_action = SystemControlAction()

        relay_action: RelayAction | None = None
        relay_requested = bool(config.actions.relay.get("enabled", False))
        if config.device.deployment_type == "phone" and relay_requested:
            logger.warning(
                "[runtime] deployment_type=phone with relay enabled; skipping relay initialization "
                "(phone gateway supports Tier A/B software actions only)."
            )
            relay_requested = False

        if relay_requested:
            relay_action = RelayAction()
            gpio_pin: int = config.actions.relay["gpio_pin"]
            try:
                await relay_action.connect(gpio_pin=gpio_pin)
                logger.info("[runtime] relay connected on GPIO pin %d", gpio_pin)
            except Exception:
                logger.exception(
                    "[runtime] relay connect failed on pin %d — relay disabled",
                    gpio_pin,
                )
                relay_action = None

        # operator_contact is a first-class config field, not assembled from sub-dicts
        _operator_contact: str = config.actions.operator_contact or ""
        if not _operator_contact:
            logger.warning(
                "[runtime] operator_contact is not configured — "
                "Tier C approval requests and emergency SMS will not reach the operator. "
                "Set actions.operator_contact in ori.yaml."
            )
        _secondary_contact: str = config.actions.secondary_contact or ""

        # Use first skill's approval_timeout_seconds if set; otherwise default
        _approval_timeout: int = 300
        for sc in config.skills:
            t = sc.config.get("approval_timeout_seconds")
            if t is not None:
                _approval_timeout = int(t)
                break

        primary_alert_channel = config.actions.primary_alert_channel
        alert_sender = AlertFailoverSender(
            primary_channel=primary_alert_channel,
            sms_sender=sms_action,
            whatsapp_sender=whatsapp_action,
        )
        causal_cfg = (
            config.reasoning.causal_memory
            if isinstance(config.reasoning.causal_memory, dict)
            else {}
        )
        rejection_expiry_days = int(causal_cfg.get("rejection_expiry_days", 30))

        dispatcher = ActionDispatcher(
            state_store=self._state_store,
            alert_sender=alert_sender,
            config={
                "operator_contact": _operator_contact,
                "secondary_contact": _secondary_contact,
                "approval_timeout_seconds": _approval_timeout,
                "primary_alert_channel": primary_alert_channel,
                "device_timezone": config.device.timezone,
                "log_action_decisions": config.logging.log_action_decisions,
                "log_approval_workflow": config.logging.log_approval_workflow,
                "rejection_expiry_days": rejection_expiry_days,
            },
        )
        self._dispatcher = dispatcher

        # alert_whatsapp executor
        async def _exec_alert_whatsapp(action: str, ctx: SkillContext) -> None:
            msg = _message_from_context(ctx, action)
            await whatsapp_action.send(message=msg, to_number=_operator_contact)

        dispatcher.register_executor("alert_whatsapp", _exec_alert_whatsapp)

        # alert_sms executor
        async def _exec_alert_sms(action: str, ctx: SkillContext) -> None:
            msg = _message_from_context(ctx, action)
            await sms_action.send(message=msg, to_number=_operator_contact)

        dispatcher.register_executor("alert_sms", _exec_alert_sms)

        async def _exec_terminate_process(action: str, ctx: SkillContext) -> bool:
            pid, name = _process_target_from_context(ctx)
            if pid is None or not name:
                logger.warning(
                    "[runtime] terminate_process requested but no unambiguous process target is available"
                )
                return False
            ok = await process_manager_action.terminate_process(pid=pid, name=name)
            if not ok:
                logger.warning(
                    "[runtime] terminate_process failed for pid=%s name=%r",
                    pid,
                    name,
                )
            return ok

        dispatcher.register_executor("terminate_process", _exec_terminate_process)

        async def _exec_reset_kernel_subsystem(action: str, ctx: SkillContext) -> bool:
            subsystem = _kernel_subsystem_from_context(ctx)
            if not subsystem:
                logger.warning(
                    "[runtime] reset_kernel_subsystem requested but no target subsystem was provided"
                )
                return False
            ok = await system_control_action.reset_kernel_subsystem(subsystem=subsystem)
            if not ok:
                logger.warning(
                    "[runtime] reset_kernel_subsystem failed for subsystem=%r",
                    subsystem,
                )
            return ok

        dispatcher.register_executor(
            "reset_kernel_subsystem", _exec_reset_kernel_subsystem
        )

        async def _exec_coap_command(action: str, ctx: SkillContext) -> bool:
            command_name, payload_override = _coap_command_from_context(ctx)
            if not command_name:
                logger.warning(
                    "[runtime] coap_command requested but no command was resolved from trigger=%r "
                    "(expected skill.config.coap.trigger_commands or event metadata coap_command)",
                    getattr(ctx, "trigger_name", ""),
                )
                return False
            ok = await coap_action.execute_command(
                command_name=command_name,
                payload_override=payload_override,
            )
            if not ok:
                logger.warning(
                    "[runtime] coap_command execution failed for command=%r",
                    command_name,
                )
            return ok

        dispatcher.register_executor("coap_command", _exec_coap_command)

        # log_to_dashboard — override built-in with device_id from config
        async def _exec_log_to_dashboard(action: str, *_: Any) -> None:
            logger_action.log_override(
                action=action,
                override_type="safe_default",
                device_id=config.device.id,
            )

        dispatcher.register_executor("log_to_dashboard", _exec_log_to_dashboard)

        # Relay executors — only if relay successfully connected
        if relay_action is not None:

            async def _exec_trip_relay(*_: Any) -> None:
                await relay_action.trigger(duration_seconds=None)  # type: ignore[union-attr]

            async def _exec_release_relay(*_: Any) -> None:
                await relay_action.release()  # type: ignore[union-attr]

            dispatcher.register_executor("trip_relay", _exec_trip_relay)
            dispatcher.register_executor("release_relay", _exec_release_relay)

        # ── Step D: IntelligenceElevator ──────────────────────────────────────
        local_llm = _build_local_llm(config.reasoning, self._config_path)
        elevator = IntelligenceElevator(local_llm=local_llm, config=config.reasoning)

        # ── Step E: EventBus ──────────────────────────────────────────────────
        event_bus = EventBus()
        elevator.attach_event_bus(event_bus)
        self._event_bus = event_bus
        self._skill_reload_lock = asyncio.Lock()

        # ── Step F: Load skills and register handlers ─────────────────────────
        skills_dir: str = config.raw.get(
            "skills_dir",
            str(Path(self._config_path).parent / "skills"),
        )
        self._skills_dir = skills_dir
        loader = SkillLoader(
            elevator=elevator,
            state_store=self._state_store,
            dispatcher=dispatcher,
        )
        self._skill_loader = loader
        await self.reload_skills()

        # ── Step G: Log startup tier configuration ────────────────────────────
        for skill in self._loaded_skills:
            logger.info("[skill] %s v%s loaded", skill.name, skill.version)
            for trigger in skill.triggers:
                escalation = "bypass_llm" if trigger.bypass_llm else trigger.escalate_to
                logger.info(
                    "  trigger: %s → Tier %s → %s",
                    trigger.name,
                    trigger.action_tier,
                    escalation,
                )

        logger.info(
            "[runtime] event loop ready — device=%s skills=%d triggers=%d",
            config.device.id,
            len(self._loaded_skills),
            sum(len(s.triggers) for s in self._loaded_skills),
        )

        # ── Register signal handlers ──────────────────────────────────────────
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(
            signal.SIGTERM, lambda: asyncio.create_task(self.stop())
        )
        loop.add_signal_handler(signal.SIGINT, lambda: asyncio.create_task(self.stop()))
        if hasattr(signal, "SIGHUP"):
            loop.add_signal_handler(
                signal.SIGHUP, lambda: asyncio.create_task(self.reload_skills())
            )
            logger.info("[runtime] SIGHUP handler active — send HUP to reload skills")

        # ── Start background tasks ────────────────────────────────────────────
        for sensor_cfg in config.sensors:
            try:
                adapter = make_adapter(sensor_cfg.protocol)
            except UnknownProtocolError as exc:
                raise ConfigValidationError(str(exc)) from exc
            connect_cfg = {
                "sensor_id": sensor_cfg.id,
                "sensor_type": sensor_cfg.type,
                "circuit_breaker": config.hal.circuit_breaker,
                **sensor_cfg.metadata,
            }
            try:
                await adapter.connect(connect_cfg)
                self._adapters.append(adapter)
                logger.info(
                    "[runtime] adapter=%s sensor_id=%s connected",
                    adapter.adapter_name,
                    sensor_cfg.id,
                )
            except Exception:
                logger.exception(
                    "[runtime] failed to connect adapter for sensor_id=%s — skipping",
                    sensor_cfg.id,
                )
                continue

            task = asyncio.create_task(
                self._poll_sensor(adapter, sensor_cfg, event_bus, config.device.id),
                name=f"poll:{sensor_cfg.id}",
            )
            self._background_tasks.append(task)

        self._background_tasks.append(
            asyncio.create_task(self._watchdog_loop(), name="watchdog")
        )
        external_wd = (
            config.hal.external_watchdog
            if isinstance(config.hal.external_watchdog, dict)
            else {}
        )
        if bool(external_wd.get("enabled", False)):
            if config.device.deployment_type == "phone":
                logger.warning(
                    "[runtime] external watchdog requested on phone deployment; skipping "
                    "(requires Raspberry Pi GPIO)."
                )
            else:
                gpio_pin = int(external_wd.get("gpio_pin", EXTERNAL_WATCHDOG_GPIO))
                ping_interval_s = float(
                    external_wd.get("ping_interval_s", EXTERNAL_WATCHDOG_PING_S)
                )
                self._background_tasks.append(
                    asyncio.create_task(
                        self._external_watchdog_loop(gpio_pin, ping_interval_s),
                        name="external-watchdog",
                    )
                )
        self._background_tasks.append(
            asyncio.create_task(
                self._heartbeat_loop(config.device.id), name="heartbeat"
            )
        )
        self._background_tasks.append(
            asyncio.create_task(self._compaction_loop(), name="compaction")
        )
        webhook_task = await self._start_sms_webhook_if_enabled(config)
        if webhook_task is not None:
            self._background_tasks.append(webhook_task)

        # Block here until stop() sets the shutdown event
        await self._shutdown_event.wait()

    async def stop(self) -> None:
        """Graceful shutdown. Called by SIGTERM/SIGINT signal handlers."""
        if self._shutdown_event.is_set():
            return
        logger.info("[runtime] shutdown initiated")
        self._shutdown_event.set()

        # 1. Drain in-flight Tier D tasks before cancelling anything else.
        tier_d_tasks: list[asyncio.Task] = []
        if self._dispatcher is not None and hasattr(
            self._dispatcher, "get_inflight_tier_d_tasks"
        ):
            tier_d_tasks.extend(self._dispatcher.get_inflight_tier_d_tasks())

        # Backward-compatible fallback: if any legacy Tier D task tags exist,
        # still honour them during shutdown drain.
        for task in asyncio.all_tasks():
            if task.done():
                continue
            if getattr(task, "_is_tier_d", False) and task not in tier_d_tasks:
                tier_d_tasks.append(task)

        if tier_d_tasks:
            logger.warning(
                "[shutdown] waiting up to %.1fs for %d Tier D task(s)",
                TIER_D_DRAIN_TIMEOUT,
                len(tier_d_tasks),
            )
            await asyncio.wait(tier_d_tasks, timeout=TIER_D_DRAIN_TIMEOUT)

        # 2. Cancel tracked background tasks only — never cancel the task
        #    running start() itself, which returns naturally once the shutdown
        #    event is set.
        tasks = [t for t in self._background_tasks if not t.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # 3. Close HAL adapters
        for adapter in self._adapters:
            try:
                await adapter.close()
            except Exception:
                logger.exception("[shutdown] error closing adapter")

        # 4. Close StateStore
        if self._state_store is not None:
            await self._state_store.close()

        self._unregister_skill_handlers()
        self._loaded_skills = []

        logger.info("[runtime] shutdown complete")

    async def ingest_sms_webhook(self, payload: dict[str, Any]) -> bool:
        """Store one inbound SMS webhook payload for approval workflows."""
        if self._sms_action is None:
            logger.warning("[runtime] SMSAction is not initialised")
            return False
        return await self._sms_action.ingest_incoming_webhook(payload)

    async def _start_sms_webhook_if_enabled(
        self, config: Config
    ) -> asyncio.Task | None:
        sms_cfg = config.actions.sms if isinstance(config.actions.sms, dict) else {}
        webhook_cfg = sms_cfg.get("incoming_webhook", {})
        if not isinstance(webhook_cfg, dict):
            return None

        enabled = _is_truthy(webhook_cfg.get("enabled", False))
        if not enabled:
            return None

        if self._sms_action is None:
            logger.warning("[runtime] SMS webhook enabled but SMSAction is unavailable")
            return None

        token = str(webhook_cfg.get("token", "") or "").strip()
        if not token:
            logger.warning(
                "[runtime] SMS webhook enabled but incoming_webhook.token is empty; "
                "refusing to start unauthenticated public ingress"
            )
            return None

        host = str(webhook_cfg.get("host", "0.0.0.0"))
        port = int(webhook_cfg.get("port", 8080))
        path = str(webhook_cfg.get("path", "/webhooks/sms/africastalking"))

        self._sms_webhook_server = SMSWebhookServer(
            sms_action=self._sms_action,
            host=host,
            port=port,
            path=path,
            token=token,
        )
        return asyncio.create_task(
            self._sms_webhook_server.serve_until(self._shutdown_event),
            name="sms-webhook",
        )

    def _unregister_skill_handlers(self) -> None:
        if self._event_bus is None:
            self._skill_subscriptions.clear()
            return
        for sensor_type, handler in self._skill_subscriptions:
            self._event_bus.unsubscribe(sensor_type, handler)
        self._skill_subscriptions.clear()

    # ── Background tasks ──────────────────────────────────────────────────────

    async def _poll_sensor(
        self,
        adapter: BaseAdapter,
        sensor_cfg: Any,
        event_bus: EventBus,
        device_id: str,
    ) -> None:
        """Read *adapter* at the configured poll interval and publish to *event_bus*."""
        assert self._state_store is not None
        while not self._shutdown_event.is_set():
            try:
                reading = await adapter.read(sensor_cfg.id)
                event = OriEvent(
                    event_id=str(uuid.uuid4()),
                    event_type=f"sensor.{reading.sensor_type}",
                    device_id=device_id,
                    sensor_id=reading.sensor_id,
                    timestamp=reading.timestamp,
                    reading=reading,
                )
                await event_bus.publish(event)
                await self._state_store.append_history(event)
            except AdapterReadError as exc:
                logger.warning("[sensor] %s read failed: %s", sensor_cfg.id, exc)
            except Exception:
                logger.exception("[sensor] unexpected error polling %s", sensor_cfg.id)
            await asyncio.sleep(sensor_cfg.poll_interval_ms / 1000)

    async def _watchdog_loop(self) -> None:
        """Ping /dev/watchdog every WATCHDOG_PING_INTERVAL seconds."""
        if not os.path.exists(WATCHDOG_DEVICE):
            logger.warning(
                "Watchdog: %s not found. "
                "Run: echo bcm2835_wdt | sudo tee -a /etc/modules",
                WATCHDOG_DEVICE,
            )
            return
        try:
            with open(WATCHDOG_DEVICE, "wb", buffering=0) as wd:
                logger.info(
                    "Watchdog: active on %s — timeout %ds",
                    WATCHDOG_DEVICE,
                    WATCHDOG_TIMEOUT,
                )
                try:
                    while not self._shutdown_event.is_set():
                        wd.write(b"1")
                        wd.flush()
                        try:
                            # Immediate wake on shutdown instead of sleeping blindly
                            await asyncio.wait_for(
                                self._shutdown_event.wait(),
                                timeout=WATCHDOG_PING_INTERVAL,
                            )
                        except asyncio.TimeoutError:
                            pass
                finally:
                    # Clean shutdown — magic V tells the kernel this was intentional
                    # Runs even if the task is cancelled (CancelledError)
                    wd.write(b"V")
                    wd.flush()
                    logger.info("Watchdog: closed cleanly (magic V written)")
        except PermissionError:
            logger.warning(
                "Watchdog: cannot open %s — permission denied. "
                "Run Ori with sudo or add user to watchdog group.",
                WATCHDOG_DEVICE,
            )
        except Exception:
            logger.exception("Watchdog loop failed — reboot may follow")

    async def _external_watchdog_loop(
        self,
        gpio_pin: int = EXTERNAL_WATCHDOG_GPIO,
        ping_interval_s: float = EXTERNAL_WATCHDOG_PING_S,
    ) -> None:
        """Pulse a GPIO pin for optional external watchdog hardware."""
        try:
            import importlib

            gpiozero = importlib.import_module("gpiozero")
        except ImportError:
            # Optional hardware feature; silently skip on non-Pi systems.
            return

        pin = None
        try:
            pin = gpiozero.DigitalOutputDevice(gpio_pin)
            logger.info("External GPIO watchdog active on BCM%d", gpio_pin)
            while not self._shutdown_event.is_set():
                pin.on()
                await asyncio.sleep(0.1)
                pin.off()
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=ping_interval_s,
                    )
                except asyncio.TimeoutError:
                    pass
        except Exception:
            logger.exception("[runtime] external watchdog loop failed")
        finally:
            if pin is not None:
                try:
                    pin.off()
                except Exception:
                    pass
                if hasattr(pin, "close"):
                    try:
                        pin.close()
                    except Exception:
                        pass

    async def _heartbeat_loop(self, device_id: str) -> None:
        """Log a heartbeat every 5 minutes to confirm the runtime is alive.

        The heartbeat reports:
        - managed runtime background tasks (pollers/watchdog/compaction/etc.)
        - pending reasoning tasks
        - pending approval-wait tasks
        - total active asyncio tasks
        """
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=300.0,
                )
                break  # shutdown was signalled during the wait — exit cleanly
            except asyncio.TimeoutError:
                pass  # 5 minutes elapsed normally — log heartbeat
            active = [t for t in asyncio.all_tasks() if not t.done()]
            managed = [t for t in self._background_tasks if not t.done()]
            reasoning_pending = 0
            approval_pending = 0
            for task in active:
                name = task.get_name()
                if name.startswith("reason:"):
                    reasoning_pending += 1
                elif name.startswith("approval:"):
                    approval_pending += 1
            logger.info(
                "[heartbeat] device=%s managed_tasks=%d reasoning_pending=%d "
                "approval_pending=%d active_tasks=%d",
                device_id,
                len(managed),
                reasoning_pending,
                approval_pending,
                len(active),
            )
        logger.debug("[heartbeat] loop exited cleanly")

    async def _compaction_loop(self) -> None:
        """Run the SQLite Compaction Pyramid every 5 minutes."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=300.0,
                )
                break  # shutdown was signalled
            except asyncio.TimeoutError:
                pass

            if self._state_store is not None:
                try:
                    await self._state_store.compact_history()
                    logger.debug("[compaction] history compaction complete")
                except Exception:
                    logger.exception(
                        "[compaction] history compaction failed — will retry"
                    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _message_from_context(ctx: SkillContext, fallback: str) -> str:
    """Build an alert message string from a SkillContext."""
    if ctx.event and ctx.event.reading:
        r = ctx.event.reading
        return (
            f"[{ctx.event.device_id}] {r.sensor_id} ({r.sensor_type}): "
            f"{r.value} {r.unit}"
        )
    return fallback


def _is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _maybe_autoload_dotenv(config_path: str) -> None:
    """Load .env when explicitly enabled via ORI_AUTOLOAD_DOTENV=true.

    This is a development convenience toggle. Production remains explicit-env
    by default (no implicit .env loading).
    """
    if not _is_truthy(os.environ.get("ORI_AUTOLOAD_DOTENV", "")):
        return

    try:
        from dotenv import load_dotenv  # type: ignore[import-not-found]
    except ImportError:
        logger.warning(
            "[runtime] ORI_AUTOLOAD_DOTENV is enabled but python-dotenv is not installed"
        )
        return

    config_dir = Path(config_path).resolve().parent
    candidates = [config_dir / ".env", Path.cwd() / ".env"]
    loaded_any = False
    seen: set[str] = set()

    for candidate in candidates:
        key = str(candidate.resolve())
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            load_dotenv(dotenv_path=candidate, override=False)
            loaded_any = True
            logger.info("[runtime] loaded environment from %s", candidate)

    if not loaded_any:
        logger.info(
            "[runtime] ORI_AUTOLOAD_DOTENV enabled but no .env file found near config/cwd"
        )


def _resolve_local_model_file(
    local_model: str,
    model_path: str,
    config_path: str,
) -> str | None:
    """Resolve local model config to an existing GGUF file path.

    Resolution supports:
    - `local_model` as an absolute/relative file path (with or without `.gguf`)
    - `model_path` as a directory containing `local_model` (with optional `.gguf`)
    - `model_path` itself as a direct model file path
    """
    config_dir = Path(config_path).resolve().parent
    local_model = (local_model or "").strip()
    model_path = (model_path or "").strip()

    candidates: list[Path] = []

    def _to_abs(path_text: str) -> Path:
        p = Path(path_text)
        return p if p.is_absolute() else (config_dir / p)

    if local_model:
        local_model_path = _to_abs(local_model)
        candidates.append(local_model_path)
        if local_model_path.suffix.lower() != ".gguf":
            candidates.append(local_model_path.with_suffix(".gguf"))

        if model_path:
            model_base = _to_abs(model_path)
            local_name = Path(local_model).name
            candidates.append(model_base / local_name)
            if not local_name.endswith(".gguf"):
                candidates.append(model_base / f"{local_name}.gguf")
    elif model_path:
        candidates.append(_to_abs(model_path))

    deduped: list[Path] = []
    seen: set[str] = set()
    for c in candidates:
        key = str(c.resolve(strict=False))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)

    for candidate in deduped:
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def _build_local_llm(reasoning_cfg: Any, config_path: str) -> LocalLLM | None:
    """Instantiate LocalLLM from config when a valid local model is available."""
    local_model = str(getattr(reasoning_cfg, "local_model", "") or "")
    model_path = str(getattr(reasoning_cfg, "model_path", "") or "")
    context_window = int(getattr(reasoning_cfg, "local_context_window", 2048) or 2048)

    model_file = _resolve_local_model_file(local_model, model_path, config_path)
    if model_file is None:
        logger.warning(
            "[runtime] local SLM disabled — could not resolve a model file from "
            "reasoning.local_model=%r and reasoning.model_path=%r",
            local_model,
            model_path,
        )
        return None

    local_llm = LocalLLM(model_path=model_file, context_window=context_window)
    if not local_llm.is_available:
        logger.warning(
            "[runtime] local SLM unavailable for model=%s. Ensure llama-cpp-python "
            "is installed and model file is accessible.",
            model_file,
        )
        return None

    logger.info(
        "[runtime] local SLM enabled — model=%s n_ctx=%d",
        model_file,
        context_window,
    )
    return local_llm


def _process_target_from_context(ctx: SkillContext) -> tuple[int | None, str]:
    """Resolve a single process target for `terminate_process`.

    Resolution order:
    1. Explicit event context override: `event.context["terminate_process"]`
       with `{pid, name}`.
    2. Exactly one process in `event.reading.metadata["processes"]`.
    """
    if not ctx or not ctx.event:
        return None, ""

    terminate_ctx = ctx.event.context.get("terminate_process", {})
    if isinstance(terminate_ctx, dict):
        pid = terminate_ctx.get("pid")
        name = terminate_ctx.get("name")
        if isinstance(pid, int) and isinstance(name, str) and name.strip():
            return pid, name.strip()
        if (
            isinstance(pid, str)
            and pid.isdigit()
            and isinstance(name, str)
            and name.strip()
        ):
            return int(pid), name.strip()

    reading = ctx.event.reading
    if reading is None:
        return None, ""

    processes = reading.metadata.get("processes", [])
    if not isinstance(processes, list):
        processes = []

    recommended = reading.metadata.get("recommended_process")
    if isinstance(recommended, dict):
        pid = recommended.get("pid")
        name = recommended.get("name")
        if isinstance(pid, int) and isinstance(name, str) and name.strip():
            return pid, name.strip()
        if (
            isinstance(pid, str)
            and pid.isdigit()
            and isinstance(name, str)
            and name.strip()
        ):
            return int(pid), name.strip()

    valid: list[tuple[int, str]] = []
    for proc in processes:
        if not isinstance(proc, dict):
            continue
        pid = proc.get("pid")
        name = proc.get("name")
        if isinstance(pid, int) and isinstance(name, str) and name.strip():
            valid.append((pid, name.strip()))
        elif (
            isinstance(pid, str)
            and pid.isdigit()
            and isinstance(name, str)
            and name.strip()
        ):
            valid.append((int(pid), name.strip()))

    if len(valid) == 1:
        return valid[0]

    return None, ""


def _kernel_subsystem_from_context(ctx: SkillContext) -> str:
    """Resolve subsystem target for `reset_kernel_subsystem`.

    Resolution order:
    1. Explicit event context override:
       `event.context["reset_kernel_subsystem"]` as either
       `{"subsystem": "<name>"}` or `"<name>"`.
    2. Reading metadata keys: `kernel_subsystem` then `subsystem`.
    """
    if not ctx or not ctx.event:
        return ""

    raw = ctx.event.context.get("reset_kernel_subsystem", "")
    if isinstance(raw, dict):
        subsystem = raw.get("subsystem")
        if isinstance(subsystem, str) and subsystem.strip():
            return subsystem.strip()
    elif isinstance(raw, str) and raw.strip():
        return raw.strip()

    reading = ctx.event.reading
    if reading is None:
        return ""

    for key in ("kernel_subsystem", "subsystem"):
        value = reading.metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _coap_command_from_context(ctx: SkillContext) -> tuple[str, str | None]:
    """Resolve CoAP command from event metadata and skill config.

    Resolution order:
    1. event.context["coap_command"] / ["coap_payload"]
    2. reading.metadata["coap_command"] / ["coap_payload"]
    3. skill.config.coap.trigger_commands[trigger_name]
    4. skill.config.coap.default_command
    """
    if not ctx or not ctx.event:
        return "", None

    command_name = ""
    payload_override: str | None = None

    event_ctx = ctx.event.context if isinstance(ctx.event.context, dict) else {}
    if isinstance(event_ctx.get("coap_command"), str):
        command_name = str(event_ctx["coap_command"]).strip()
    if event_ctx.get("coap_payload") is not None:
        payload_override = str(event_ctx.get("coap_payload"))

    reading = ctx.event.reading
    metadata = reading.metadata if reading is not None else {}
    if not command_name and isinstance(metadata.get("coap_command"), str):
        command_name = str(metadata["coap_command"]).strip()
    if payload_override is None and metadata.get("coap_payload") is not None:
        payload_override = str(metadata.get("coap_payload"))

    skill_cfg = getattr(getattr(ctx, "skill", None), "config", {}) or {}
    if isinstance(skill_cfg, dict):
        coap_cfg = skill_cfg.get("coap") or {}
        if isinstance(coap_cfg, dict):
            trigger_commands = coap_cfg.get("trigger_commands") or {}
            if (
                not command_name
                and isinstance(trigger_commands, dict)
                and isinstance(getattr(ctx, "trigger_name", ""), str)
            ):
                trigger_name = ctx.trigger_name.strip()
                mapped = trigger_commands.get(trigger_name)
                if isinstance(mapped, str) and mapped.strip():
                    command_name = mapped.strip()
            if not command_name:
                default_command = coap_cfg.get("default_command")
                if isinstance(default_command, str) and default_command.strip():
                    command_name = default_command.strip()

    return command_name, payload_override


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Ori Runtime")
    parser.add_argument(
        "--config",
        default="ori.yaml",
        help="Path to ori.yaml config file",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    _maybe_autoload_dotenv(args.config)

    runtime = OriRuntime(config_path=args.config)
    asyncio.run(runtime.start())


if __name__ == "__main__":
    main()
