# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Backend availability: the capabilities a hardened start requires, and local
inference, built only when it is requested and its model can be read."""

import logging
from pathlib import Path
from typing import Any

from ori.actions.coap import coap_backend_available
from ori.actions.relay import (
    gpio_backend_arbitrated,
    gpio_backend_importable,
    resolved_pin_factory_name,
)
from ori.config import Config, ConfigValidationError, requires_production_posture
from ori.reasoning.local_llm import LocalLLM, local_llm_backend_available
from ori.utils.bool_utils import is_truthy
from ori.utils.path_utils import shown

logger = logging.getLogger("ori.runtime")


def is_local_slm_available(local_llm: Any) -> bool:
    """Safely resolve local SLM availability from any LocalLLM-like object."""
    if local_llm is None:
        return False
    return bool(getattr(local_llm, "is_available", False))


def local_llm_requested(reasoning_cfg: Any) -> bool:
    """Return whether configuration asks this runtime to provide local inference."""
    return (
        str(getattr(reasoning_cfg, "default_tier", "") or "").strip().lower() == "local"
    )


def validate_required_runtime_capabilities(
    config: Config,
    config_path: str,
) -> None:
    """Fail before host mutation when hardened configuration cannot be served.

    Development deliberately retains simulation and graceful degradation for
    laptops and CI. Staging, production, and explicit posture enforcement must
    never report a healthy runtime while a requested physical/protocol/reasoning
    backend is absent.
    """
    if not requires_production_posture(
        device=config.device,
        security=config.security,
    ):
        return

    missing: list[str] = []
    status_cfg = (
        config.hal.status_signaling
        if isinstance(config.hal.status_signaling, dict)
        else {}
    )
    relay_requested = bool(
        config.device.deployment_type != "phone" and "gpio_pin" in config.actions.relay
    )
    status_signaling_requested = is_truthy(status_cfg.get("enabled", False))
    if relay_requested or status_signaling_requested:
        requested_by = (
            "relay control and status signaling"
            if relay_requested and status_signaling_requested
            else "relay control"
            if relay_requested
            else "status signaling"
        )
        if not gpio_backend_importable():
            missing.append(f"gpiozero is unavailable but {requested_by} is configured")
        elif not gpio_backend_arbitrated():
            # The dependency is present and pins would move, so the import check
            # passes. gpiozero fell back to a factory that drives /dev/gpiomem
            # without claiming the line, so the kernel refuses no second writer.
            # A hardened runtime must not report a physical capability it cannot
            # hold exclusively.
            factory = resolved_pin_factory_name() or "none"
            missing.append(
                f"{requested_by} is configured but the resolved GPIO backend "
                f"({factory}) does not claim its lines through the kernel"
            )

    coap_requested = is_truthy(config.actions.coap.get("enabled", False)) or any(
        sensor.protocol == "coap" for sensor in config.sensors
    )
    if coap_requested and not coap_backend_available():
        missing.append(
            "aiocoap is unavailable but a CoAP action or sensor is configured"
        )

    if local_llm_requested(config.reasoning):
        if not local_llm_backend_available():
            missing.append(
                "llama-cpp-python is unavailable but local reasoning is configured"
            )
        if (
            _resolve_local_model_file(
                str(config.reasoning.local_model or ""),
                str(config.reasoning.model_path or ""),
                config_path,
            )
            is None
        ):
            missing.append(
                "a readable GGUF model file could not be resolved for local reasoning"
            )

    if missing:
        raise ConfigValidationError(
            "production posture requires every configured host capability to be "
            "available; "
            + "; ".join(missing)
            + ". Install the required signed runtime target/dependencies or disable "
            "the capability explicitly before startup."
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


def build_local_llm(
    reasoning_cfg: Any,
    config_path: str,
    *,
    required: bool = False,
) -> LocalLLM | None:
    """Instantiate LocalLLM from config when a valid local model is available."""
    local_model = str(getattr(reasoning_cfg, "local_model", "") or "")
    model_path = str(getattr(reasoning_cfg, "model_path", "") or "")
    context_window = int(getattr(reasoning_cfg, "local_context_window", 2048) or 2048)

    model_file = _resolve_local_model_file(local_model, model_path, config_path)
    if model_file is None:
        if required:
            raise ConfigValidationError(
                "production posture requires a readable GGUF model file when "
                "local reasoning is configured"
            )
        logger.warning(
            "[runtime] local SLM disabled — could not resolve a model file from "
            "reasoning.local_model=%r and reasoning.model_path=%r",
            local_model,
            model_path,
        )
        return None

    local_llm = LocalLLM(model_path=model_file, context_window=context_window)
    if not local_llm.is_available:
        if required:
            raise ConfigValidationError(
                "production posture requires llama-cpp-python and an accessible "
                f"local model file; local reasoning is unavailable for {model_file}"
            )
        logger.warning(
            "[runtime] local SLM unavailable for model=%s. Ensure llama-cpp-python "
            "is installed and model file is accessible.",
            shown(model_file),
        )
        return None

    logger.info(
        "[runtime] local SLM enabled — model=%s n_ctx=%d",
        shown(model_file),
        context_window,
    )
    return local_llm
