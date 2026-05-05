# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import os
import re
from functools import partial

from ori.network.events import ReasoningResult
from ori.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    from llama_cpp import Llama  # type: ignore[import-untyped]

    _LLAMA_AVAILABLE = True
except ImportError:
    _LLAMA_AVAILABLE = False


class ModelNotAvailableError(Exception):
    """Raised when the model file is missing or llama-cpp-python is not installed."""


_OUTPUT_CONTRACT = (
    "You are Ori, an offline device reasoning agent.\n"
    "Respond in plain English, exactly 2-3 short sentences.\n"
    "Provide direct operator guidance only.\n"
    "Do NOT ask questions.\n"
    "Do NOT produce quizzes, multiple-choice options, or A/B/C/D answers.\n"
    "Do NOT include markdown, bullet points, or numbered lists.\n"
    "Do NOT prefix steps with numbers like '1.' or '2.'."
)


class LocalLLM:
    """Thin asyncio wrapper around a llama-cpp-python ``Llama`` instance.

    The model is loaded lazily on the first :meth:`reason` call so that startup
    time is not penalised when the model is ultimately not needed (e.g. when a
    rule engine match bypasses the LLM entirely).

    **Action tier authority:** :meth:`reason` always returns
    ``action_tier='A'``.  The Intelligence Elevator overwrites this with the
    tier declared in the skill YAML trigger.  The LLM never has authority over
    what physical action is taken — it only provides reasoning text and a
    confidence estimate.

    Args:
        model_path: Absolute path to a GGUF model file.
        context_window: Token context window passed to ``Llama(n_ctx=...)``.
    """

    def __init__(self, model_path: str, context_window: int = 2048) -> None:
        self._model_path = model_path
        self._context_window = context_window
        self._llm: object | None = None  # Llama instance, populated on first call

    # ── Public interface ──────────────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        """``True`` if llama-cpp-python is installed and the model file exists."""
        if not _LLAMA_AVAILABLE:
            return False
        return os.path.isfile(self._model_path)

    async def reason(self, prompt: str, max_tokens: int = 200) -> ReasoningResult:
        """Run inference and return a :class:`~ori.network.events.ReasoningResult`.

        Loads the model on the first call.  Subsequent calls reuse the loaded
        instance.

        The returned ``action_tier`` is always ``'A'`` — the elevator is
        responsible for setting the real tier from the skill configuration.

        Args:
            prompt: The formatted prompt string (built by the elevator).
            max_tokens: Maximum tokens to generate.

        Returns:
            :class:`~ori.network.events.ReasoningResult` with ``tier='local_slm'``
            and ``action_tier='A'``.

        Raises:
            :exc:`ModelNotAvailableError`: llama-cpp-python is not installed or
                the model file does not exist.
        """
        if not _LLAMA_AVAILABLE:
            raise ModelNotAvailableError(
                "LocalLLM: llama-cpp-python is not installed. "
                "Run: pip install llama-cpp-python"
            )
        if not os.path.isfile(self._model_path):
            raise ModelNotAvailableError(
                f"LocalLLM: model file not found: '{self._model_path}'"
            )

        await self._ensure_loaded()

        loop = asyncio.get_running_loop()
        start_ms = now_ms()

        output = await loop.run_in_executor(
            None,
            partial(
                self._infer,
                prompt=self._build_inference_prompt(prompt),
                max_tokens=max_tokens,
            ),
        )

        latency_ms = now_ms() - start_ms
        raw_text = output["choices"][0]["text"].strip()
        text = self._normalize_output(raw_text)
        tokens_used = output["usage"]["completion_tokens"]

        # Confidence is not reliably extractable from a base LLM completion.
        # Default to 0.0; the elevator may override via post-processing.
        return ReasoningResult(
            text=text,
            tier="local_slm",
            model=os.path.basename(self._model_path),
            tokens_used=tokens_used,
            latency_ms=latency_ms,
            confidence=0.0,
            action_tier="A",  # always — see class docstring
            proposed_action=None,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _ensure_loaded(self) -> None:
        """Load the model in a thread-pool executor if not already loaded."""
        if self._llm is not None:
            return
        loop = asyncio.get_running_loop()
        logger.info(
            "LocalLLM: loading model '%s' (n_ctx=%d) …",
            self._model_path,
            self._context_window,
        )
        self._llm = await loop.run_in_executor(None, self._load_model)
        logger.info("LocalLLM: model loaded")

    def _load_model(self) -> object:
        return Llama(
            model_path=self._model_path,
            n_ctx=self._context_window,
            n_threads=4,
            n_gpu_layers=0,
            verbose=False,
        )

    def _infer(self, prompt: str, max_tokens: int) -> dict:
        return self._llm(  # type: ignore[operator]
            prompt,
            max_tokens=max_tokens,
            temperature=0.0,
            top_p=0.9,
            repeat_penalty=1.1,
            stop=[
                "\n\n",
                "Which of the following",
                "\nA)",
                "\nB)",
                "\nC)",
                "\nD)",
            ],
            echo=False,
        )

    @staticmethod
    def _build_inference_prompt(prompt: str) -> str:
        return f"{_OUTPUT_CONTRACT}\n\nOperator context:\n{prompt}\n\nResponse:"

    @staticmethod
    def _normalize_output(text: str) -> str:
        """Enforce plain operator-style output and strip MCQ drift."""
        cleaned = " ".join((text or "").strip().split())

        # Remove common quiz/multiple-choice tails if they still appear.
        for marker in (
            "Which of the following",
            "A)",
            "B)",
            "C)",
            "D)",
            "Option A",
            "Option B",
            "Option C",
            "Option D",
        ):
            idx = cleaned.find(marker)
            if idx > 0:
                cleaned = cleaned[:idx].strip()
                break

        # Remove leading numbering/bullet clutter.
        cleaned = re.sub(r"^(?:[-*]\s+|\d+[.)]\s+)+", "", cleaned)
        # Remove inline numbering/list markers that can still appear mid-output.
        cleaned = re.sub(r"(?:^|\s)\d+[.)]\s+", " ", cleaned).strip()
        cleaned = " ".join(cleaned.split())

        # Keep at most 3 sentences to match the skills contract.
        sentence_parts = re.split(r"(?<=[.!?])\s+", cleaned)
        sentence_parts = [s.strip() for s in sentence_parts if s.strip()]
        if sentence_parts:
            cleaned = " ".join(sentence_parts[:3]).strip()

        if not cleaned:
            cleaned = (
                "An anomaly was detected. Check the device state and reduce load "
                "if the issue persists."
            )
        return cleaned
