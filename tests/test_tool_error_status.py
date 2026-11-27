"""工具整轮报错必须记为 tool_error，而不是 executed。

背景（rcu_stall run 2026-11-27）：read_source 因参数是列表被 MCP 拒绝，
报错被当成普通 ToolMessage 记为 executed，replan 菜单随即给出"立即收尾"，
模型没有任何纠错机会。
"""

import asyncio
import sys
import types
from pathlib import Path
from unittest import mock

root = Path(__file__).resolve().parents[1]
src_pkg = types.ModuleType("src")
src_pkg.__path__ = [str(root / "src")]
sys.modules.setdefault("src", src_pkg)
react_pkg = types.ModuleType("src.react")
react_pkg.__path__ = [str(root / "src" / "react")]
sys.modules.setdefault("src.react", react_pkg)

from langchain_core.messages import AIMessage

from src.react.nodes import call_crash_tool

SOURCE_OK = (
    "SOURCE_STATUS configured=true\n"
    "file=kernel/rcu/tree_plugin.h lines=298-338/1200\n"
    "SOURCE_REF: kernel/rcu/tree_plugin.h:318\n"
    "   318| \tWARN_ON_ONCE(!preempt && rcu_preempt_depth() > 0);\n"
)


def _state(*tool_calls) -> dict:
    return {
        "step_count": 8,
        "messages": [AIMessage(content="", tool_calls=list(tool_calls))],
        "executed_fingerprints": [],
        "tool_output_cache": {},
        "replayed_fingerprints": [],
        "last_action_fingerprint": "",
        "no_progress_streak": 0,
        "duplicate_streak": 0,
        "evidence_facts": [],
        "current_action_intent": {},
        "vmcore_path": "/tmp/vmcore",
        "vmlinux_path": "/tmp/vmlinux",
    }


def _read_source(call_id: str, file: str, line: int) -> dict:
    return {
        "name": "read_source",
        "args": {"file": file, "line": line, "kver": "5.14.0-362.24.1.el9_3.x86_64"},
        "id": call_id,
    }


def _run(state, outputs):
    """outputs: list of per-request outputs (str or Exception), or None for "no match"."""

    async def fake_dispatch(requests, _state):
        if outputs is None:
            return []
        return [(req["display"], out) for req, out in zip(requests, outputs)]

    with mock.patch("src.react.nodes.dispatch_mcp_requests", side_effect=fake_dispatch):
        return asyncio.run(call_crash_tool(state))


def test_all_errors_are_recorded_as_tool_error():
    update = _run(
        _state(_read_source("call-1", "kernel/rcu/tree_plugin.h", 318)),
        [ValueError("read_source parameter 'line' must be a single integer, not list.")],
    )
    assert update["last_action_status"] == "tool_error"
    assert update["replan_required"] is True
    assert update["evidence_delta"] == []
    assert update["no_progress_streak"] == 1
    assert update["messages"][0].content.startswith("[error]")


def test_partial_success_stays_executed():
    update = _run(
        _state(
            _read_source("call-1", "kernel/rcu/tree_plugin.h", 318),
            _read_source("call-2", "kernel/rcu/tree_stall.h", 345),
        ),
        [SOURCE_OK, ValueError("boom")],
    )
    assert update["last_action_status"] == "executed"
    assert "source_ref:kernel/rcu/tree_plugin.h:318" in update["evidence_delta"]


def test_timeout_is_not_tool_error():
    update = _run(
        _state(_read_source("call-1", "kernel/rcu/tree_plugin.h", 318)),
        ["[TIMEOUT] command exceeded 180s"],
    )
    assert update["last_action_status"] != "tool_error"


def test_unmatched_tool_counts_as_tool_error():
    update = _run(_state(_read_source("call-1", "kernel/rcu/tree_plugin.h", 318)), None)
    assert update["messages"][0].content.startswith("[error] No matching crash tool found")
    assert update["last_action_status"] == "tool_error"


def test_only_source_ref_tools_consume_the_citation_retry():
    update = _run(
        _state(_read_source("call-1", "kernel/rcu/tree_plugin.h", 318)), [ValueError("x")]
    )
    assert update["source_citation_retry_used"] is True

    grep = {"name": "grep_source", "args": {"pattern": "rcu_read_lock"}, "id": "call-9"}
    update = _run(_state(grep), ["SOURCE_GREP pattern=rcu_read_lock hits=0\n"])
    assert update["source_citation_retry_used"] is False


def test_exemption_flags_are_consumed_when_issued():
    from src.react.llm_node import _exemption_flag_updates

    assert _exemption_flag_updates({}, "tool_error_retry") == {
        "tool_error_retry_used": True,
        "source_citation_retry_used": False,
    }
    assert _exemption_flag_updates({}, "missing_source_ref")["source_citation_retry_used"] is True
    # 已置位的标记不会被后续轮次清掉
    assert _exemption_flag_updates({"tool_error_retry_used": True}, None)["tool_error_retry_used"] is True


def test_provider_error_texts_are_recorded_as_tool_error():
    # 回归：lock_hang 返回 "Failed to analyze ..."、kernel_source 返回 "SOURCE_ERROR ..."，
    # 都不以 "[error]" 开头，v2 会把它们记成 executed。
    lockup = {
        "name": "analyze_cpu_lockup_rcu",
        "args": {"command": "--rcu-pids 309547,309548"},
        "id": "call-1",
    }
    cases = (
        (
            lockup,
            "Failed to analyze CPU lockup / RCU state: Unsupported option for "
            "analyze_cpu_lockup_rcu: --top",
        ),
        (
            _read_source("call-2", "kernel/rcu/tree_plugin.h", 99999),
            "SOURCE_ERROR line 99999 is outside kernel/rcu/tree_plugin.h (1..1302); "
            "dis -s may have been resolved against a different build",
        ),
    )
    for call, output in cases:
        update = _run(_state(call), [output])
        assert update["last_action_status"] == "tool_error", output
        assert update["replan_required"] is True
        assert update["no_progress_streak"] == 1


def test_error_text_mid_output_is_not_a_tool_error():
    # 只按前缀判断：正常输出中间出现 "SOURCE_ERROR" 字样不算失败
    update = _run(
        _state(_read_source("call-1", "kernel/rcu/tree_plugin.h", 318)),
        [SOURCE_OK + "   319| /* SOURCE_ERROR is just a comment here */\n"],
    )
    assert update["last_action_status"] == "executed"


def test_bracket_error_prefix_from_provider_is_tool_error():
    # server 现在返回 "[error] Failed to analyze ..."；与旧写法一样必须记为 tool_error
    lockup = {
        "name": "analyze_cpu_lockup_rcu",
        "args": {"command": "--rcu-pids 309547,309548"},
        "id": "call-1",
    }
    update = _run(
        _state(lockup),
        ["[error] Failed to analyze CPU lockup / RCU state: crash session exited with code 1"],
    )
    assert update["last_action_status"] == "tool_error"
    assert update["replan_required"] is True
    assert update["no_progress_streak"] == 1
