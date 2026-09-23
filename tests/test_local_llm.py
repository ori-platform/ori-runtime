# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from ori.network.events import ReasoningResult
from ori.reasoning.local_llm import LocalLLM, ModelNotAvailableError

# ─── Helpers ──────────────────────────────────────────────────────────────────

_FAKE_MODEL = "/models/qwen2.5-0.5b.gguf"

_LLAMA_OUTPUT = {
    "choices": [{"text": "  Load is 40% above baseline. Likely cause: AC unit.  "}],
    "usage": {"completion_tokens": 22, "prompt_tokens": 80, "total_tokens": 102},
}


def _llm_with_mock(model_path: str = _FAKE_MODEL) -> tuple[LocalLLM, MagicMock]:
    """Return a LocalLLM and an already-loaded mock Llama instance."""
    llm = LocalLLM(model_path=model_path)
    mock_llama = MagicMock(return_value=_LLAMA_OUTPUT)
    llm._llm = mock_llama
    return llm, mock_llama


# ─── is_available ─────────────────────────────────────────────────────────────


class TestIsAvailable:
    def test_false_when_llama_not_installed(self):
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", False):
            llm = LocalLLM(model_path=_FAKE_MODEL)
            assert llm.is_available is False

    def test_false_when_model_file_missing(self):
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            llm = LocalLLM(model_path="/does/not/exist.gguf")
            assert llm.is_available is False

    def test_true_when_installed_and_file_exists(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            llm = LocalLLM(model_path=str(model_file))
            assert llm.is_available is True


# ─── reason — guard checks ────────────────────────────────────────────────────


class TestReasonGuards:
    async def test_raises_if_llama_not_installed(self):
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", False):
            llm = LocalLLM(model_path=_FAKE_MODEL)
            with pytest.raises(ModelNotAvailableError, match="llama-cpp-python"):
                await llm.reason("test prompt")

    async def test_raises_if_model_file_missing(self):
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            llm = LocalLLM(model_path="/does/not/exist.gguf")
            with pytest.raises(ModelNotAvailableError, match="not found"):
                await llm.reason("test prompt")


# ─── reason — result shape ────────────────────────────────────────────────────


class TestReasonResult:
    async def test_returns_reasoning_result(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, _ = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("Is this anomalous?")
        assert isinstance(result, ReasoningResult)

    async def test_tier_is_local_slm(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, _ = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("prompt")
        assert result.tier == "local_slm"

    async def test_action_tier_always_a(self, tmp_path):
        """action_tier must always be 'A' — the elevator sets the real tier."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, _ = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("overcurrent detected — open safety circuit?")
        assert result.action_tier == "A"

    async def test_text_stripped(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, _ = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("prompt")
        # Leading/trailing whitespace stripped from LLM output
        assert result.text == "Load is 40% above baseline. Likely cause: AC unit."

    async def test_tokens_used_from_llm_output(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, _ = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("prompt")
        assert result.tokens_used == 22

    async def test_latency_ms_positive(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, _ = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("prompt")
        assert result.latency_ms >= 0

    async def test_model_name_from_basename(self, tmp_path):
        model_file = tmp_path / "qwen2.5-0.5b-instruct.gguf"
        model_file.write_bytes(b"fake")
        llm, _ = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("prompt")
        assert result.model == "qwen2.5-0.5b-instruct.gguf"

    async def test_confidence_defaults_to_zero(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, _ = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("prompt")
        assert result.confidence == 0.0

    async def test_proposed_action_is_none(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, _ = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("prompt")
        assert result.proposed_action is None


# ─── reason — inference call ──────────────────────────────────────────────────


class TestReasonInference:
    async def test_llm_called_with_prompt(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, mock_llama = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            await llm.reason("my prompt text")
        call_kwargs = mock_llama.call_args
        sent_prompt = call_kwargs[0][0]
        assert "my prompt text" in sent_prompt
        assert "Do NOT produce quizzes" in sent_prompt

    async def test_max_tokens_passed_to_llm(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, mock_llama = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            await llm.reason("prompt", max_tokens=50)
        assert mock_llama.call_args[1]["max_tokens"] == 50

    async def test_temperature_is_0_1(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, mock_llama = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            await llm.reason("prompt")
        assert mock_llama.call_args[1]["temperature"] == 0.0

    async def test_stop_tokens(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm, mock_llama = _llm_with_mock(str(model_file))
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            await llm.reason("prompt")
        assert mock_llama.call_args[1]["stop"] == [
            "\n\n",
            "Which of the following",
            "\nA)",
            "\nB)",
            "\nC)",
            "\nD)",
        ]


class TestOutputNormalization:
    async def test_mcq_tail_is_removed(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm = LocalLLM(model_path=str(model_file))
        llm._llm = MagicMock(
            return_value={
                "choices": [
                    {
                        "text": "Check the compressor and clean the filter. "
                        "Reduce load for now. Which of the following is true? "
                        "A) this B) that"
                    }
                ],
                "usage": {
                    "completion_tokens": 30,
                    "prompt_tokens": 50,
                    "total_tokens": 80,
                },
            }
        )
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("prompt")
        assert "Which of the following" not in result.text
        assert "A)" not in result.text

    async def test_inline_numbered_list_markers_are_removed(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm = LocalLLM(model_path=str(model_file))
        llm._llm = MagicMock(
            return_value={
                "choices": [
                    {
                        "text": (
                            "Ensure the fan is running. "
                            "2. Close heavy apps and monitor CPU for 5 minutes."
                        )
                    }
                ],
                "usage": {
                    "completion_tokens": 24,
                    "prompt_tokens": 40,
                    "total_tokens": 64,
                },
            }
        )
        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            result = await llm.reason("prompt")
        assert "2." not in result.text


# ─── lazy loading ─────────────────────────────────────────────────────────────


class TestLazyLoading:
    def test_model_not_loaded_on_init(self):
        llm = LocalLLM(model_path=_FAKE_MODEL)
        assert llm._llm is None

    async def test_model_loaded_on_first_reason(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm = LocalLLM(model_path=str(model_file))

        mock_llama_instance = MagicMock(return_value=_LLAMA_OUTPUT)
        mock_llama_cls = MagicMock(return_value=mock_llama_instance)

        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("ori.reasoning.local_llm.Llama", mock_llama_cls, create=True),
        ):
            await llm.reason("prompt")

        mock_llama_cls.assert_called_once()
        call_kwargs = mock_llama_cls.call_args[1]
        assert call_kwargs["model_path"] == str(model_file)
        assert call_kwargs["n_ctx"] == 2048
        assert call_kwargs["n_threads"] == 4
        assert call_kwargs["n_gpu_layers"] == 0

    async def test_model_loaded_only_once(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm = LocalLLM(model_path=str(model_file))

        mock_llama_instance = MagicMock(return_value=_LLAMA_OUTPUT)
        mock_llama_cls = MagicMock(return_value=mock_llama_instance)

        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("ori.reasoning.local_llm.Llama", mock_llama_cls, create=True),
        ):
            await llm.reason("first call")
            await llm.reason("second call")

        # Llama() constructor called exactly once despite two reason() calls
        mock_llama_cls.assert_called_once()

    async def test_custom_context_window_passed_to_llama(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm = LocalLLM(model_path=str(model_file), context_window=4096)

        mock_llama_cls = MagicMock(return_value=MagicMock(return_value=_LLAMA_OUTPUT))

        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("ori.reasoning.local_llm.Llama", mock_llama_cls, create=True),
        ):
            await llm.reason("prompt")

        assert mock_llama_cls.call_args[1]["n_ctx"] == 4096

    async def test_concurrent_reason_calls_load_model_once(self, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        llm = LocalLLM(model_path=str(model_file))

        mock_llama_instance = MagicMock(return_value=_LLAMA_OUTPUT)
        load_calls = 0

        def _slow_load():
            nonlocal load_calls
            load_calls += 1
            time.sleep(0.05)
            return mock_llama_instance

        with patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True):
            with patch.object(llm, "_load_model", side_effect=_slow_load):
                await asyncio.gather(
                    llm.reason("first concurrent call"),
                    llm.reason("second concurrent call"),
                )

        assert load_calls == 1


# ─── one inference at a time ──────────────────────────────────────────────────


async def _was_cancelled(task: asyncio.Task) -> bool:
    [outcome] = await asyncio.gather(task, return_exceptions=True)
    return isinstance(outcome, asyncio.CancelledError)


class _OverlapDetectingLlama:
    """A model whose decode records how many callers are inside it at once."""

    def __init__(self, release: "threading.Event | None" = None) -> None:
        self._guard = threading.Lock()
        self.inside = 0
        self.most_inside = 0
        self.entered = threading.Event()
        self._release = release

    def __call__(self, *_args, **_kwargs) -> dict:
        with self._guard:
            self.inside += 1
            self.most_inside = max(self.most_inside, self.inside)
        self.entered.set()
        if self._release is not None:
            self._release.wait(5)
        else:
            time.sleep(0.05)
        with self._guard:
            self.inside -= 1
        return _LLAMA_OUTPUT


class TestOneInferenceAtATime:
    """A llama.cpp context decoded from two threads at once crashes the process."""

    async def test_concurrent_callers_never_decode_together(self):
        llm = LocalLLM(model_path=_FAKE_MODEL)
        model = _OverlapDetectingLlama()
        llm._llm = model
        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("os.path.isfile", return_value=True),
        ):
            results = await asyncio.gather(*(llm.reason(f"p{i}") for i in range(4)))

        assert len(results) == 4
        assert model.most_inside == 1

    async def test_a_cancelled_caller_does_not_let_the_next_decode_alongside_it(self):
        """The cancelled caller's thread keeps decoding; the next must still wait."""
        release = threading.Event()
        llm = LocalLLM(model_path=_FAKE_MODEL)
        model = _OverlapDetectingLlama(release)
        llm._llm = model
        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("os.path.isfile", return_value=True),
        ):
            first = asyncio.create_task(llm.reason("first"))
            await asyncio.to_thread(model.entered.wait, 5)
            first.cancel()
            assert await _was_cancelled(first)
            second = asyncio.create_task(llm.reason("second"))
            await asyncio.sleep(0.2)
            assert model.inside == 1, "the second decode started beside the first"
            release.set()
            result = await second

        assert result.tier == "local_slm"
        assert model.most_inside == 1

    async def test_queued_callers_wait_in_the_loop_not_in_pool_threads(self):
        """Each waiting caller parked in a worker thread would starve other to_thread work."""
        llm = LocalLLM(model_path=_FAKE_MODEL)
        llm._llm = _OverlapDetectingLlama()
        real_to_thread = asyncio.to_thread
        in_flight = 0
        most_in_flight = 0

        async def counting_to_thread(func, *args, **kwargs):
            nonlocal in_flight, most_in_flight
            in_flight += 1
            most_in_flight = max(most_in_flight, in_flight)
            try:
                return await real_to_thread(func, *args, **kwargs)
            finally:
                in_flight -= 1

        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("os.path.isfile", return_value=True),
            patch("ori.reasoning.local_llm.asyncio.to_thread", counting_to_thread),
        ):
            await asyncio.gather(*(llm.reason(f"p{i}") for i in range(4)))

        assert most_in_flight == 1

    async def test_a_cancellation_storm_never_parks_callers_in_pool_threads(self):
        """Callers cancelled one after another behind a running decode each
        leave their work queued; none may take a worker thread to wait in."""
        release = threading.Event()
        llm = LocalLLM(model_path=_FAKE_MODEL)
        model = _OverlapDetectingLlama(release)
        llm._llm = model
        real_to_thread = asyncio.to_thread
        in_flight = 0
        most_in_flight = 0

        async def counting_to_thread(func, *args, **kwargs):
            nonlocal in_flight, most_in_flight
            in_flight += 1
            most_in_flight = max(most_in_flight, in_flight)
            try:
                return await real_to_thread(func, *args, **kwargs)
            finally:
                in_flight -= 1

        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("os.path.isfile", return_value=True),
            patch("ori.reasoning.local_llm.asyncio.to_thread", counting_to_thread),
        ):
            first = asyncio.create_task(llm.reason("first"))
            await real_to_thread(model.entered.wait, 5)
            first.cancel()
            for i in range(6):
                caller = asyncio.create_task(llm.reason(f"storm{i}"))
                await asyncio.sleep(0.02)
                caller.cancel()
                assert await _was_cancelled(caller)
            assert await _was_cancelled(first)
            release.set()
            result = await llm.reason("after")

        assert result.tier == "local_slm"
        assert most_in_flight == 1
        assert model.most_inside == 1


class TestOneLoad:
    """llama.cpp silences stdout and stderr process-wide while it loads; two
    overlapping loads restore them out of order and leave them silenced."""

    @staticmethod
    def _slow_llama(loads: list, release: threading.Event):
        class _Llama:
            def __init__(self, *_args, **_kwargs):
                loads.append(threading.get_ident())
                release.wait(5)

            def __call__(self, *_args, **_kwargs):
                return _LLAMA_OUTPUT

        return _Llama

    async def test_a_caller_cancelled_mid_load_does_not_start_a_second_load(self):
        loads: list = []
        release = threading.Event()
        llm = LocalLLM(model_path=_FAKE_MODEL)
        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("ori.reasoning.local_llm.Llama", self._slow_llama(loads, release)),
            patch("os.path.isfile", return_value=True),
        ):
            first = asyncio.create_task(llm.reason("first"))
            await asyncio.sleep(0.1)
            first.cancel()
            assert await _was_cancelled(first)
            second = asyncio.create_task(llm.reason("second"))
            await asyncio.sleep(0.1)
            assert len(loads) == 1, "a second load started beside the first"
            release.set()
            result = await second

        assert result.tier == "local_slm"
        assert len(loads) == 1

    async def test_a_failed_load_is_retried_by_the_next_caller(self):
        attempts = []

        class _FailingOnce:
            def __init__(self, *_args, **_kwargs):
                attempts.append(1)
                if len(attempts) == 1:
                    raise RuntimeError("model file unreadable")

            def __call__(self, *_args, **_kwargs):
                return _LLAMA_OUTPUT

        llm = LocalLLM(model_path=_FAKE_MODEL)
        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("ori.reasoning.local_llm.Llama", _FailingOnce),
            patch("os.path.isfile", return_value=True),
        ):
            with pytest.raises(RuntimeError):
                await llm.reason("first")
            result = await llm.reason("second")

        assert result.tier == "local_slm"
        assert len(attempts) == 2

    async def test_a_load_failing_after_every_caller_left_is_retried(self):
        release = threading.Event()
        attempts = []

        class _FailingOnceSlowly:
            def __init__(self, *_args, **_kwargs):
                attempts.append(1)
                if len(attempts) == 1:
                    release.wait(5)
                    raise RuntimeError("model file unreadable")

            def __call__(self, *_args, **_kwargs):
                return _LLAMA_OUTPUT

        llm = LocalLLM(model_path=_FAKE_MODEL)
        with (
            patch("ori.reasoning.local_llm._LLAMA_AVAILABLE", True),
            patch("ori.reasoning.local_llm.Llama", _FailingOnceSlowly),
            patch("os.path.isfile", return_value=True),
        ):
            first = asyncio.create_task(llm.reason("first"))
            await asyncio.sleep(0.1)
            first.cancel()
            assert await _was_cancelled(first)
            release.set()
            while llm._load_task is not None and not llm._load_task.done():
                await asyncio.sleep(0.01)
            await asyncio.sleep(0)
            result = await llm.reason("second")

        assert result.tier == "local_slm"
        assert len(attempts) == 2
