#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic gate closure tests for rcu_stall (rcu_stall_trace + lock_holder)."""

from __future__ import annotations

import json
import unittest

from langchain_core.messages import AIMessage

from src.react.evidence import (
    evaluate_gate_closures,
    extract_evidence_facts,
    gate_completion_criteria,
    has_executor_closure_rule,
)
from src.react.report_generator import generate_markdown_report
from src.react.schema import (
    FinalDiagnosis,
    GateEntry,
    SuspectCode,
    VMCoreLLMAnalysisStep,
)
from src.react.state_manager import project_managed_analysis_step


class TestRcuStallGateClosure(unittest.TestCase):
    """验证 rcu_stall 的确定性门控事实抽取、闭合与端到端报告输出。"""

    def test_closure_rule_registration_and_signature_isolation(self) -> None:
        self.assertTrue(has_executor_closure_rule("rcu_stall_trace", ["rcu_stall"]))
        self.assertTrue(has_executor_closure_rule("lock_holder", ["rcu_stall"]))
        # lock_holder 的确定性规则同时覆盖 rcu_stall 与 soft_lockup
        self.assertTrue(has_executor_closure_rule("lock_holder", ["soft_lockup"]))

        # 未指定签名时 lock_holder 不得闭合；不属于锁等待类签名的场景仍为 telemetry only
        self.assertFalse(has_executor_closure_rule("lock_holder", []))
        self.assertFalse(has_executor_closure_rule("lock_holder", ["hung_task"]))
        self.assertIn(
            "telemetry only",
            " ".join(gate_completion_criteria("lock_holder", ["hung_task"])),
        )
        self.assertNotIn(
            "telemetry only",
            " ".join(gate_completion_criteria("lock_holder", ["rcu_stall"])),
        )
        self.assertNotIn(
            "telemetry only",
            " ".join(gate_completion_criteria("lock_holder", ["soft_lockup"])),
        )

    def test_real_rcu_stall_vmcore_replay_closes_gates_and_renders_conclusion(self) -> None:
        """重放真实 rcu_stall_mod.ko vmcore 分析输出，验证门控闭合且正式结论不被清空。"""
        # 步骤 3: dis -l rcu_stall_thread
        dis_out = """\
/home/calmwu/Program/vmcore-analysis-agent/simulate-crash/rcu_stall/rcu_stall_mod.c: 240
0xffffffffc0fd791d <rcu_stall_thread+221>:	call   0xffffffffaa5a71d0 <__rcu_read_lock>
0xffffffffc0fd7928 <rcu_stall_thread+232>:	call   0xffffffffab06c500 <schedule_timeout_interruptible>
"""
        # 步骤 5: bt 309547
        bt_out = """\
PID: 309547   TASK: ffff9b29cc4a3980  CPU: 6    COMMAND: "rcu_blocked_rea"
 #0 [ffffb09bc052fd90] __schedule at ffffffffab06658a
 #1 [ffffb09bc052fdf8] schedule at ffffffffab066a2d
 #2 [ffffb09bc052fe08] schedule_timeout at ffffffffab06c418
 #3 [ffffb09bc052fe70] rcu_stall_thread at ffffffffc0fd79c4 [rcu_stall_mod]
"""
        # 步骤 9: struct task_struct RCU 字段
        task_struct_out = """\
  pid = 309547,
  comm = "rcu_blocked_rea",
  __state = 1,
  rcu_read_lock_nesting = 1,
  rcu_blocked_node = 0xffffffffac3e9800 <rcu_state+640>,
  rcu_node_entry = {
    next = 0xffffffffac3e9888 <rcu_state+776>,
    prev = 0xffffffffac3e9888 <rcu_state+776>
  },
"""
        # 步骤 11: struct rcu_node + p sysctl_panic_on_rcu_stall
        rcu_node_out = """\
sysctl_panic_on_rcu_stall = $2 = 1
  gp_tasks = 0xffff9b29cc4a42c0,
  exp_tasks = 0x0,
  blkd_tasks = {
    next = 0xffff9b29cc4a42c0,
    prev = 0xffff9b29cc4a42c0
  },
  qsmask = 0,
  gp_seq = 7398185,
"""
        facts: set[str] = set()
        facts.update(
            extract_evidence_facts(
                "run_script",
                {"script": "mod -s rcu_stall_mod /tmp/rcu_stall_mod.ko\ndis -l rcu_stall_thread"},
                dis_out,
            )
        )
        facts.update(extract_evidence_facts("bt", {"command": "bt 309547"}, bt_out))
        facts.update(
            extract_evidence_facts(
                "struct",
                {"command": "struct task_struct.pid,rcu_read_lock_nesting,rcu_blocked_node ffff9b29cc4a3980"},
                task_struct_out,
            )
        )
        facts.update(
            extract_evidence_facts(
                "run_script",
                {
                    "script": (
                        "p sysctl_panic_on_rcu_stall\n"
                        "struct rcu_node.gp_tasks,blkd_tasks,qsmask,gp_seq 0xffffffffac3e9800"
                    )
                },
                rcu_node_out,
            )
        )

        # 验证关键事实已准确抽取
        self.assertIn("bt_task:pid=309547:task=0xffff9b29cc4a3980:cpu=6:comm=rcu_blocked_rea", facts)
        self.assertIn("rcu_reader_nesting:pid=309547=1", facts)
        self.assertIn("rcu_blocked_node:0xffffffffac3e9800", facts)
        self.assertIn("rcu_node_gp_tasks:0xffff9b29cc4a42c0", facts)
        self.assertIn("rcu_gp_seq:7398185", facts)
        self.assertIn("rcu_sysctl:sysctl_panic_on_rcu_stall=1", facts)

        # 构造步骤 14 的 LLM 结论请求，验证 project_managed_analysis_step 保留正式结论
        # 模拟生产路径：LLM 输出的是 VMCoreLLMAnalysisStep（无 conclusive 合同
        # 的强制降级），门控闭合由 executor 的确定性评估负责。
        llm_step = VMCoreLLMAnalysisStep(
            step_id=14,
            reasoning="PID 309547 holds __rcu_read_lock across schedule_timeout_interruptible for 70s.",
            action=None,
            is_conclusive=True,
            signature_class="rcu_stall",
            root_cause_class="rcu_misuse",
            partial_dump="partial",
            gates={
                "lock_holder": GateEntry(required_for=["rcu_stall"], status="open"),
                "rcu_stall_trace": GateEntry(required_for=["rcu_stall"], status="open"),
            },
            final_diagnosis=FinalDiagnosis(
                crash_type="RCU stall (rcu_sched self-detected stall on CPU)",
                panic_string="rcu: INFO: rcu_sched self-detected stall on CPU",
                faulting_instruction="schedule_timeout_interruptible at ffffffffab06658a (rcu_stall_mod)",
                root_cause="第三方模块 rcu_stall_mod 在 RCU 读临界区内循环睡眠 70 秒，阻塞宽限期完成，触发 RCU Stall panic。",
                detailed_analysis=(
                    "PID 309547 (rcu_blocked_rea) 持有 rcu_read_lock_nesting=1 并在 "
                    "rcu_read_lock() 区间内调用 schedule_timeout_interruptible 睡眠 70 秒；"
                    "rcu_node.gp_tasks/blkd_tasks 均指向该任务，宽限期 gp_seq=7398185 无法完成。"
                ),
                suspect_code=SuspectCode(
                    file="rcu_stall_mod.c",
                    function="rcu_stall_thread",
                    line="unknown",
                ),
                evidence=[
                    "rcu_reader_nesting:pid=309547=1",
                    "rcu_blocked_node:0xffffffffac3e9800",
                    "rcu_node_gp_tasks:0xffff9b29cc4a42c0",
                    "rcu_gp_seq:7398185",
                    "bt_task:pid=309547:task=0xffff9b29cc4a3980:cpu=6:comm=rcu_blocked_rea",
                ],
            ),
            fix_suggestion="将 schedule_timeout_interruptible 移出 rcu_read_lock()/rcu_read_unlock() 区间。",
            confidence="high",
        )
        state = {
            "current_signature_class": "rcu_stall",
            "current_root_cause_class": "rcu_misuse",
            "evidence_facts": sorted(facts),
            "managed_gates": {
                "lock_holder": GateEntry(required_for=["rcu_stall"], status="open"),
                "rcu_stall_trace": GateEntry(required_for=["rcu_stall"], status="open"),
            },
        }
        projected, updates = project_managed_analysis_step(
            llm_step, state, original_reasoning=llm_step.reasoning
        )

        self.assertTrue(projected.is_conclusive)
        self.assertIsNotNone(projected.final_diagnosis)
        self.assertEqual(projected.gates["lock_holder"].status, "closed")
        self.assertEqual(projected.gates["lock_holder"].closure_basis, "executor_evidence")
        self.assertEqual(projected.gates["rcu_stall_trace"].status, "closed")
        self.assertEqual(projected.gates["rcu_stall_trace"].closure_basis, "executor_evidence")

        # 端到端验证报告渲染出正式结论且无规则覆盖告警
        report_state = {
            "vmcore_path": "/var/crash/vmcore",
            "vmlinux_path": "/usr/lib/debug/vmlinux",
            "vmcore_dmesg_path": "/var/crash/vmcore-dmesg.txt",
            "debug_symbol_paths": [],
            "step_count": 14,
            "token_usage": 12345,
            "current_signature_class": "rcu_stall",
            "managed_gates": updates["managed_gates"],
            "messages": [AIMessage(content=projected.model_dump_json())],
        }
        md = generate_markdown_report(report_state)
        self.assertIn("第三方模块 rcu_stall_mod", md)
        self.assertNotIn("Rule coverage limitation", md)
        self.assertNotIn("规则能力限制", md)
        self.assertNotIn("分析未得出正式的最终结论", md)

    def test_negative_cases_never_false_close_rcu_gates(self) -> None:
        """只有 bt/dis 或 RCU 字段为 0/NULL 时，绝不能误关门控。"""
        # 1) 仅有 bt + dis，没有 RCU 结构体/状态事实
        only_exec_facts = extract_evidence_facts(
            "bt",
            {"command": "bt 309547"},
            'PID: 309547   TASK: ffff9b29cc4a3980  CPU: 6    COMMAND: "rcu_blocked_rea"\n'
            " #0 [ffffb09bc052fd90] __schedule at ffffffffab06658a\n",
        )
        # 2) rcu_read_lock_nesting=0, rcu_blocked_node=0x0, gp_tasks=0x0 不产生阳性持锁事实
        zero_struct_facts = extract_evidence_facts(
            "struct",
            {"command": "struct task_struct ffff9b29cc4a3980"},
            "  pid = 309547,\n  rcu_read_lock_nesting = 0,\n  rcu_blocked_node = 0x0,\n  gp_tasks = 0x0,\n",
        )
        facts = only_exec_facts | zero_struct_facts

        gates = {
            "lock_holder": GateEntry(required_for=["rcu_stall"], status="closed", evidence="LLM guess"),
            "rcu_stall_trace": GateEntry(required_for=["rcu_stall"], status="closed", evidence="LLM guess"),
        }
        evaluated, transitions = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["lock_holder"].status, "open")
        self.assertEqual(evaluated["rcu_stall_trace"].status, "open")
        rejected = {t["gate_name"] for t in transitions if t["event"] == "llm_close_rejected"}
        self.assertEqual(rejected, {"lock_holder", "rcu_stall_trace"})

    def test_lock_hang_json_tools_can_close_rcu_gates(self) -> None:
        """使用 lock_hang MCP 工具 JSON 输出 + bt 同样能闭合 rcu_stall 门控。"""
        cpu_json = json.dumps(
            {
                "rcu_stall_detected": True,
                "active_or_suspected_cpus": [{"cpu": 6, "wait_category": "irq_softirq"}],
                "spinlock_contenders": [],
            }
        )
        wait_json = json.dumps(
            {
                "root_blockers": [{"pid": 309547, "comm": "rcu_blocked_rea"}],
                "wait_edges": [],
            }
        )
        bt_out = 'PID: 309547   TASK: ffff9b29cc4a3980  CPU: 6    COMMAND: "rcu_blocked_rea"\n'

        facts = (
            extract_evidence_facts("analyze_cpu_lockup_rcu", {"command": ""}, cpu_json)
            | extract_evidence_facts("analyze_lock_wait_graph", {"command": ""}, wait_json)
            | extract_evidence_facts("bt", {"command": "bt 309547"}, bt_out)
        )
        gates = {
            "lock_holder": GateEntry(required_for=["rcu_stall"], status="open"),
            "rcu_stall_trace": GateEntry(required_for=["rcu_stall"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["lock_holder"].status, "closed")
        self.assertEqual(evaluated["rcu_stall_trace"].status, "closed")

    def test_source_ref_does_not_pollute_soft_lockup_lock_holder(self) -> None:
        """source_ref 事实不触发 soft_lockup 下 lock_holder 的 weak_gate_closure 遥测。"""
        facts = extract_evidence_facts("read_source", {}, "SOURCE_REF: kernel/rcu/tree.c:1200\n")
        gates = {"lock_holder": GateEntry(required_for=["soft_lockup"], status="open")}
        evaluated, transitions = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["lock_holder"].status, "open")
        self.assertEqual(transitions, [])

    def test_analyze_cpu_lockup_rcu_with_blocked_task_frames_closes_rcu_gates(self) -> None:
        """真实 analyze_cpu_lockup_rcu 输出已包含 pid 栈帧时，可直接闭合 lock_holder 与 rcu_stall_trace。"""
        analyzer_json = json.dumps(
            {
                "total_cpus_parsed": 8,
                "idle_cpu_count": 0,
                "spinlock_contender_count": 0,
                "spinlock_contenders": [],
                "irq_or_softirq_cpus": [],
                "active_or_suspected_cpus": [],
                "rcu_state_summary": {
                    "gp_seq": "7398185",
                    "gp_state": "5",
                    "gp_start": "4660044008",
                    "jiffies_stall": "9223372041514879817",
                    "n_force_qs": "2279386",
                },
                "rcu_stall_controls": {
                    "rcu_cpu_stall_timeout": 60,
                    "sysctl_panic_on_rcu_stall": 1,
                    "jiffies": 4660104011,
                    "gp_age_jiffies": 60003,
                },
                "rcu_blocked_tasks": [
                    {
                        "pid": 309547,
                        "comm": "[rcu_blocked_rea]",
                        "task_addr": "0xffff9b29cc4a3980",
                        "role": "blocked_reader",
                        "__state": 1,
                        "rcu_read_lock_nesting": 1,
                        "rcu_blocked_node": "0xffffffffac3e9800",
                        "bt_top_frames": [
                            "__schedule",
                            "schedule",
                            "schedule_timeout",
                            "rcu_stall_thread",
                            "kthread",
                            "ret_from_fork",
                        ],
                        "bt_truncated": False,
                        "blocked_node_info": {
                            "level": "1",
                            "grplo": "0",
                            "grphi": "15",
                            "qsmask": "0",
                            "gp_seq": "7398185",
                            "gp_tasks": "0xffff9b29cc4a42c0",
                            "exp_tasks": "0x0",
                            "blkd_tasks_next": "0xffff9b29cc4a42c0",
                        },
                    }
                ],
            }
        )
        facts = extract_evidence_facts(
            "analyze_cpu_lockup_rcu", {"command": "--rcu-pids 309547"}, analyzer_json
        )
        self.assertIn(
            "bt_task:pid=309547:task=0xffff9b29cc4a3980:comm=rcu_blocked_rea",
            facts,
        )
        self.assertIn("bt_frame:rcu_stall_thread", facts)

        gates = {
            "lock_holder": GateEntry(required_for=["rcu_stall"], status="open"),
            "rcu_stall_trace": GateEntry(required_for=["rcu_stall"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["lock_holder"].status, "closed")
        self.assertEqual(evaluated["rcu_stall_trace"].status, "closed")

    def test_analyze_cpu_lockup_rcu_empty_frames_does_not_emit_bt_facts(self) -> None:
        """bt_top_frames 为空时不得伪造 bt_task/bt_frame 事实。"""
        analyzer_json = json.dumps(
            {
                "rcu_state_summary": {"gp_seq": "7398185"},
                "rcu_blocked_tasks": [
                    {
                        "pid": 309547,
                        "comm": "[rcu_blocked_rea]",
                        "task_addr": "0xffff9b29cc4a3980",
                        "rcu_read_lock_nesting": 1,
                        "rcu_blocked_node": "0xffffffffac3e9800",
                        "bt_top_frames": [],
                        "blocked_node_info": {
                            "gp_tasks": "0xffff9b29cc4a42c0",
                            "blkd_tasks_next": "0xffff9b29cc4a42c0",
                            "qsmask": "0",
                            "gp_seq": "7398185",
                        },
                    }
                ],
            }
        )
        facts = extract_evidence_facts("analyze_cpu_lockup_rcu", {}, analyzer_json)
        self.assertFalse(any(f.startswith(("bt_task:", "bt_frame:")) for f in facts))
        gates = {
            "lock_holder": GateEntry(required_for=["rcu_stall"], status="open"),
            "rcu_stall_trace": GateEntry(required_for=["rcu_stall"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["lock_holder"].status, "open")
        self.assertEqual(evaluated["rcu_stall_trace"].status, "open")


if __name__ == "__main__":
    unittest.main()
