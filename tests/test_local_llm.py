# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

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
            result = await llm.reason("overcurrent detected — trip breaker?")
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
                "usage": {"completion_tokens": 30, "prompt_tokens": 50, "total_tokens": 80},
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
                "usage": {"completion_tokens": 24, "prompt_tokens": 40, "total_tokens": 64},
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
