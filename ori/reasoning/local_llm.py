# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import os
import re
import threading
from typing import Any

from ori.network.events import ReasoningResult
from ori.utils.path_utils import shown
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

try:
    from llama_cpp import Llama  # pyright: ignore[reportMissingImports]

    _LLAMA_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised without llama-cpp-python
    # A sentinel, not a type. mypy reads the imported name as `type[Llama]`;
    # binding it here is what lets the call site check availability directly
    # rather than relying on a module flag no checker can correlate.
    Llama = None  # type: ignore[assignment,misc]
    _LLAMA_AVAILABLE = False


def local_llm_backend_available() -> bool:
    """Return whether llama-cpp-python is importable in this interpreter."""
    return bool(_LLAMA_AVAILABLE)


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


def _retrieve(future: asyncio.Future[Any]) -> None:
    """Mark an abandoned worker's failure as seen; its caller was cancelled."""
    if not future.cancelled():
        future.exception()


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
        self._load_lock = asyncio.Lock()
        # One load, shared: a caller cancelled mid-load must not abandon it.
        # llama.cpp silences stdout and stderr process-wide while loading, and
        # two overlapping loads restore them out of order, leaving the
        # process's output at /dev/null for good.
        self._load_task: asyncio.Task[object] | None = None
        # One inference at a time on the loaded model: a llama.cpp context
        # decoded from two threads at once crashes the process. Callers queue
        # in the event loop, never in pool threads. A cancelled caller's decode
        # cannot be stopped, so it keeps the model until its thread returns and
        # the next caller waits for it here; the thread lock is the last line.
        self._infer_lock = asyncio.Lock()
        self._decode_task: asyncio.Future[dict] | None = None
        self._decode_lock = threading.Lock()

    # ── Public interface ──────────────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        """``True`` if llama-cpp-python is installed and the model file exists."""
        if not local_llm_backend_available():
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
        if not local_llm_backend_available():
            raise ModelNotAvailableError(
                "LocalLLM: llama-cpp-python is not installed. "
                "Run: pip install llama-cpp-python"
            )
        if not os.path.isfile(self._model_path):
            raise ModelNotAvailableError(
                f"LocalLLM: model file not found: '{self._model_path}'"
            )

        await self._ensure_loaded()

        start_ms = now_ms()

        async with self._infer_lock:
            abandoned = self._decode_task
            if abandoned is not None and not abandoned.done():
                await asyncio.wait({abandoned})
            decode = asyncio.ensure_future(
                asyncio.to_thread(
                    self._infer,
                    prompt=self._build_inference_prompt(prompt),
                    max_tokens=max_tokens,
                )
            )
            decode.add_done_callback(_retrieve)
            self._decode_task = decode
            output = await asyncio.shield(decode)

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
        """Load the model once, in a worker thread, whichever caller asks first."""
        if self._llm is not None:
            return
        async with self._load_lock:
            if self._llm is None and self._load_task is None:
                logger.info(
                    "LocalLLM: loading model %s (n_ctx=%d) …",
                    shown(self._model_path),
                    self._context_window,
                )
                self._load_task = asyncio.create_task(
                    asyncio.to_thread(self._load_model)
                )
                self._load_task.add_done_callback(self._forget_failed_load)
            task = self._load_task
        if task is None:
            return
        llm = await asyncio.shield(task)
        if self._llm is None:
            self._llm = llm
            logger.info("LocalLLM: model loaded")

    def _forget_failed_load(self, task: asyncio.Task[object]) -> None:
        # Here rather than in an awaiter, so a load that fails after every
        # caller was cancelled is still retried by the next one.
        if (task.cancelled() or task.exception() is not None) and (
            self._load_task is task
        ):
            self._load_task = None

    def _load_model(self) -> object:
        if Llama is None:
            raise RuntimeError("LocalLLM: llama-cpp-python is not installed")
        return Llama(
            model_path=self._model_path,
            n_ctx=self._context_window,
            n_threads=4,
            n_gpu_layers=0,
            verbose=False,
        )

    def _infer(self, prompt: str, max_tokens: int) -> dict:
        # _llm is populated by load(); _infer is unreachable before that.
        with self._decode_lock:
            return self._infer_unlocked(prompt, max_tokens)

    def _infer_unlocked(self, prompt: str, max_tokens: int) -> dict:
        return self._llm(  # type: ignore[operator, misc, no-any-return]
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
