import json
import sys
import types
import unittest
from pathlib import Path
from typing import ClassVar

import openai
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

root = Path(__file__).resolve().parents[1]
src_pkg = types.ModuleType("src")
src_pkg.__path__ = [str(root / "src")]
sys.modules.setdefault("src", src_pkg)
react_pkg = types.ModuleType("src.react")
react_pkg.__path__ = [str(root / "src" / "react")]
sys.modules.setdefault("src.react", react_pkg)

from src.react.llm_node import (
    _LENGTH_RECOVERY_DIRECTIVE,
    _build_structured_chain,
    call_llm_analysis,
)
from src.react.logging_callback import GraphLoggingCallback
import src.react.llm_runtime as llm_runtime_mod
from src.react.llm_runtime import (
    ContextBudgetError,
    INITIAL_CHARS_PER_TOKEN,
    LLMBudgetConfig,
    OutputBudget,
    ainvoke_with_retry,
    calibrate_chars_per_token,
    compress_messages_for_llm,
    plan_output_budget,
    prepare_messages_for_llm,
)
from src.react.schema import ToolCall, VMCoreLLMAnalysisStep
from src.llm.model import ChatDeepSeekReasoner


def _config(**overrides) -> LLMBudgetConfig:
    values = {
        "context_window": 524_288,
        "max_output_tokens": 48_000,
        "min_thinking_output_tokens": 32_768,
        "thinking_enabled": True,
        "reasoning_effort": "max",
        "safety_margin_tokens": 8_192,
        "min_output_tokens": 4_096,
        "max_text_output_tokens": 16_384,
        "reasoning_history_keep": 2,
        "chars_per_token": 2.0,
    }
    values.update(overrides)
    return LLMBudgetConfig(**values)


class CompressionTests(unittest.TestCase):
    def test_ai_gate_evidence_is_stripped_but_status_is_kept(self) -> None:
        content = json.dumps(
            {
                "step_id": 1,
                "reasoning": "r",
                "gates": {
                    "register_provenance": {
                        "status": "open",
                        "closure_basis": None,
                        "evidence": "E" * 20_000,
                    }
                },
            }
        )

        compressed = compress_messages_for_llm([AIMessage(content=content)])

        payload = json.loads(compressed[0].content)
        gate = payload["gates"]["register_provenance"]
        self.assertIsNone(gate["evidence"])
        self.assertEqual(gate["status"], "open")

    def test_prepare_keeps_latest_tool_and_strips_repeated_evidence(self) -> None:
        system = SystemMessage(content="s" * 1_000)
        messages = [HumanMessage(content="analyze")]
        messages.append(
            AIMessage(
                content=json.dumps(
                    {
                        "step_id": 1,
                        "reasoning": "r",
                        "gates": {
                            "register_provenance": {
                                "status": "open",
                                "evidence": "E" * 200_000,
                            }
                        },
                    }
                )
            )
        )
        for index in range(4):
            messages.append(
                ToolMessage(
                    content="O" * 30_000,
                    name="bt",
                    tool_call_id=f"old-{index}",
                )
            )
        latest = "L" * 10_000
        messages.append(
            ToolMessage(content=latest, name="bt", tool_call_id="latest")
        )

        compressed, budget = prepare_messages_for_llm(system, messages, _config())

        self.assertFalse(budget.must_compress)
        self.assertTrue(budget.thinking)
        self.assertEqual(compressed[-1].content, latest)
        payload = json.loads(compressed[1].content)
        self.assertIsNone(payload["gates"]["register_provenance"]["evidence"])
        self.assertIn("[SYSTEM LOG:", compressed[2].content)

    def test_prepare_raises_for_oversized_system_prompt(self) -> None:
        system = SystemMessage(content="s" * 1_100_000)
        with self.assertRaises(ContextBudgetError):
            prepare_messages_for_llm(system, [HumanMessage(content="x")], _config())


class BudgetPlanningTests(unittest.TestCase):
    def test_thinking_budget_uses_full_available_window(self) -> None:
        budget = plan_output_budget(100_000, 200_000, _config())

        self.assertFalse(budget.must_compress)
        self.assertTrue(budget.thinking)
        self.assertEqual(budget.max_tokens, 48_000)

    def test_thinking_is_disabled_when_window_is_tight(self) -> None:
        budget = plan_output_budget(500_000, 1_000_000, _config())

        self.assertFalse(budget.must_compress)
        self.assertFalse(budget.thinking)
        self.assertEqual(budget.max_tokens, 16_096)

    def test_insufficient_window_requires_compression(self) -> None:
        budget = plan_output_budget(520_000, 1_040_000, _config())

        self.assertTrue(budget.must_compress)
        self.assertIsNone(budget.max_tokens)


class _ProbeLLM(ChatDeepSeekReasoner):
    captured_kwargs: ClassVar[dict] = {}
    captured_payload: ClassVar[dict] = {}

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        type(self).captured_kwargs = kwargs
        payload = self._get_request_payload(messages, stop=stop, **kwargs)
        type(self).captured_payload = payload
        return ChatResult(
            generations=[
                ChatGeneration(
                    message=AIMessage(
                        content='{"step_id": 1, "reasoning": "ok", "action": null}'
                    )
                )
            ]
        )


class BindingTests(unittest.TestCase):
    def test_structured_chain_passes_budget_to_model(self) -> None:
        llm = _ProbeLLM(
            api_key="test",
            api_base="https://example.invalid/v1",
            model="test",
            max_tokens=48_000,
        )
        budget = OutputBudget(
            max_tokens=123,
            thinking=False,
            reasoning_effort="low",
            prompt_tokens=1,
            prompt_chars=2,
        )
        chain = _build_structured_chain(llm, budget)

        chain.invoke([AIMessage(content="x")])

        self.assertEqual(llm.captured_kwargs["max_tokens"], 123)
        self.assertEqual(llm.captured_kwargs["reasoning_effort"], "low")
        self.assertEqual(
            llm.captured_kwargs["extra_body"],
            {"thinking": {"type": "disabled"}},
        )
        self.assertEqual(llm.captured_payload["max_tokens"], 123)
        self.assertEqual(llm.captured_payload["reasoning_effort"], "low")
        self.assertEqual(
            llm.captured_payload["extra_body"],
            {"thinking": {"type": "disabled"}},
        )

    def test_structured_chain_omits_thinking_field_when_disabled_by_profile(
        self,
    ) -> None:
        llm = _ProbeLLM(
            api_key="test",
            api_base="https://example.invalid/v1",
            model="test",
            max_tokens=48_000,
        )
        budget = OutputBudget(
            max_tokens=123,
            thinking=True,
            reasoning_effort="high",
            prompt_tokens=1,
            prompt_chars=2,
        )
        chain = _build_structured_chain(
            llm,
            budget,
            send_thinking_field=False,
        )

        chain.invoke([AIMessage(content="x")])

        self.assertEqual(llm.captured_kwargs["max_tokens"], 123)
        self.assertEqual(llm.captured_kwargs["reasoning_effort"], "high")
        self.assertNotIn("extra_body", llm.captured_kwargs)
        self.assertNotIn("extra_body", llm.captured_payload)


class _LengthErrorChain:
    def __init__(self) -> None:
        self.calls = 0

    async def ainvoke(self, messages):
        self.calls += 1
        exc = openai.LengthFinishReasonError.__new__(openai.LengthFinishReasonError)
        Exception.__init__(exc, "length")
        raise exc


class RetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_length_error_is_not_retried(self) -> None:
        chain = _LengthErrorChain()

        with self.assertRaises(openai.LengthFinishReasonError):
            await ainvoke_with_retry(chain, [], max_retries=3, base_delay=0)

        self.assertEqual(chain.calls, 1)

    def test_calibrate_chars_per_token_accepts_english_hex_ratio_above_three(
        self,
    ) -> None:
        original = llm_runtime_mod._CHARS_PER_TOKEN
        try:
            llm_runtime_mod._CHARS_PER_TOKEN = INITIAL_CHARS_PER_TOKEN
            calibrate_chars_per_token(665_547, 203_311)  # ~3.2735 chars/token
            self.assertGreater(llm_runtime_mod._CHARS_PER_TOKEN, 2.0)

            calibrated = llm_runtime_mod._CHARS_PER_TOKEN
            calibrate_chars_per_token(600_000, 100_000)  # 6.0 -> out of range
            self.assertEqual(llm_runtime_mod._CHARS_PER_TOKEN, calibrated)
        finally:
            llm_runtime_mod._CHARS_PER_TOKEN = original

    def test_logging_callback_treats_length_finish_reason_as_recoverable(self) -> None:
        exc = openai.LengthFinishReasonError.__new__(openai.LengthFinishReasonError)
        Exception.__init__(
            exc,
            "Could not parse response content as the length limit was reached",
        )
        self.assertTrue(
            GraphLoggingCallback._is_recoverable_output_parsing_error(exc)
        )
        self.assertTrue(
            GraphLoggingCallback._is_recoverable_output_parsing_error(
                RuntimeError(
                    "Could not parse response content as the length limit was reached"
                )
            )
        )

    async def test_call_llm_analysis_length_fallback_injects_directive_and_calibrates(
        self,
    ) -> None:
        sent_batches: list[list] = []

        class _FallbackChain:
            async def ainvoke(self, messages, config=None):
                sent_batches.append(list(messages))
                if len(sent_batches) == 1:
                    exc = openai.LengthFinishReasonError.__new__(
                        openai.LengthFinishReasonError
                    )
                    Exception.__init__(
                        exc,
                        "Could not parse response content as the length limit was reached",
                    )
                    exc.completion = types.SimpleNamespace(
                        usage=types.SimpleNamespace(prompt_tokens=39_000)
                    )
                    raise exc
                parsed = VMCoreLLMAnalysisStep(
                    step_id=1,
                    reasoning="concise reasoning",
                    action=ToolCall(command_name="bt", arguments=["-a"]),
                    is_conclusive=False,
                )
                raw = AIMessage(
                    content=parsed.model_dump_json(),
                    usage_metadata={
                        "input_tokens": 39_000,
                        "output_tokens": 200,
                        "total_tokens": 39_200,
                    },
                )
                return {"parsed": parsed, "raw": raw}

        class _DummyLLM:
            def with_structured_output(self, *args, **kwargs):
                return _FallbackChain()

        state = {
            "step_count": 1,
            "messages": [
                HumanMessage(content="init"),
                AIMessage(
                    content='{"step_id": 0, "reasoning": "start"}',
                    tool_calls=[{"id": "tc1", "name": "sys", "args": {}}],
                ),
                ToolMessage(
                    content="X" * 6_000,
                    name="sys",
                    tool_call_id="tc1",
                ),
                ToolMessage(
                    content="Y" * 1_000,
                    name="bt",
                    tool_call_id="tc2",
                ),
                ToolMessage(
                    content="Z" * 1_000,
                    name="bt",
                    tool_call_id="tc3",
                ),
            ],
        }

        original = llm_runtime_mod._CHARS_PER_TOKEN
        try:
            llm_runtime_mod._CHARS_PER_TOKEN = INITIAL_CHARS_PER_TOKEN
            result = await call_llm_analysis(state, _DummyLLM())
            self.assertIsNone(result["error"])
            self.assertEqual(len(sent_batches), 2)
            first_sys = sent_batches[0][0].content
            second_sys = sent_batches[1][0].content
            self.assertNotIn(_LENGTH_RECOVERY_DIRECTIVE, first_sys)
            self.assertIn(_LENGTH_RECOVERY_DIRECTIVE, second_sys)
            # Older ToolMessage is truncated once on both calls, never double-truncated
            self.assertEqual(sent_batches[0][3].content, sent_batches[1][3].content)
            self.assertEqual(
                sent_batches[1][3].content.count("[SYSTEM LOG:"), 1
            )
            self.assertGreater(
                llm_runtime_mod._CHARS_PER_TOKEN, INITIAL_CHARS_PER_TOKEN
            )
        finally:
            llm_runtime_mod._CHARS_PER_TOKEN = original


if __name__ == "__main__":
    unittest.main()