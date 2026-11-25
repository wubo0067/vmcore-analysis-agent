#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic gate closure tests for all 4 lock/hang signatures:
rcu_stall, hung_task, soft_lockup, and hard_lockup.
"""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import dataclass, field

from src.react.evidence import (
    evaluate_gate_closures,
    extract_evidence_facts,
    gate_completion_criteria,
    has_executor_closure_rule,
)

try:
    from langchain_core.messages import AIMessage
    from src.react.report_generator import generate_markdown_report
    from src.react.schema import (
        FinalDiagnosis,
        GateEntry,
        SuspectCode,
        VMCoreLLMAnalysisStep,
    )
    from src.react.state_manager import project_managed_analysis_step

    _HAS_FULL_STACK = True
except ImportError:
    _HAS_FULL_STACK = False


@dataclass
class _LiteGate:
    required_for: list[str] = field(default_factory=list)
    status: str = "open"
    prerequisite: str | None = None
    evidence: str | None = None
    closure_basis: str | None = None
    completion_criteria: list[str] = field(default_factory=list)

    def model_copy(self, deep: bool = False) -> "_LiteGate":
        return copy.deepcopy(self) if deep else copy.copy(self)


def _make_gate(**kwargs):
    if _HAS_FULL_STACK:
        return GateEntry(**kwargs)
    return _LiteGate(**kwargs)


class TestLockHangGateClosure(unittest.TestCase):
    """覆盖 rcu_stall / hung_task / soft_lockup / hard_lockup 的确定性门控闭合与零回归。"""

    def test_rule_registration_and_scope_isolation(self) -> None:
        self.assertTrue(has_executor_closure_rule("rcu_stall_trace", ["rcu_stall"]))
        self.assertTrue(has_executor_closure_rule("lock_holder", ["rcu_stall"]))
        self.assertTrue(has_executor_closure_rule("lock_holder", ["soft_lockup"]))
        self.assertTrue(has_executor_closure_rule("stack_integrity", ["soft_lockup"]))
        self.assertTrue(has_executor_closure_rule("blocked_task_context", ["hung_task"]))
        self.assertTrue(has_executor_closure_rule("wait_chain", ["hung_task"]))
        self.assertTrue(has_executor_closure_rule("nmi_watchdog_evidence", ["hard_lockup"]))
        self.assertTrue(has_executor_closure_rule("cpu_progress_state", ["hard_lockup"]))

        # 作用域隔离（零回归）：非锁/挂死签名下的共享门控保持原样
        self.assertFalse(has_executor_closure_rule("lock_holder", []))
        self.assertFalse(has_executor_closure_rule("stack_integrity", ["bug_on"]))
        self.assertFalse(has_executor_closure_rule("stack_integrity", ["atomic_sleep"]))
        self.assertIn(
            "telemetry only",
            " ".join(gate_completion_criteria("stack_integrity", ["bug_on"])),
        )

    # ------------------------------------------------------------------
    # 1. rcu_stall
    # ------------------------------------------------------------------
    def _collect_real_rcu_stall_facts(self) -> set[str]:
        dis_out = (
            "/home/calmwu/Program/vmcore-analysis-agent/simulate-crash/rcu_stall/rcu_stall_mod.c: 240\n"
            "0xffffffffc0fd791d <rcu_stall_thread+221>:\tcall   0xffffffffaa5a71d0 <__rcu_read_lock>\n"
            "0xffffffffc0fd7928 <rcu_stall_thread+232>:\tcall   0xffffffffab06c500 <schedule_timeout_interruptible>\n"
        )
        bt_out = (
            'PID: 309547   TASK: ffff9b29cc4a3980  CPU: 6    COMMAND: "rcu_blocked_rea"\n'
            " #0 [ffffb09bc052fd90] __schedule at ffffffffab06658a\n"
            " #1 [ffffb09bc052fdf8] schedule at ffffffffab066a2d\n"
            " #2 [ffffb09bc052fe08] schedule_timeout at ffffffffab06c418\n"
            " #3 [ffffb09bc052fe70] rcu_stall_thread at ffffffffc0fd79c4 [rcu_stall_mod]\n"
        )
        task_struct_out = (
            "  pid = 309547,\n"
            '  comm = "rcu_blocked_rea",\n'
            "  __state = 1,\n"
            "  rcu_read_lock_nesting = 1,\n"
            "  rcu_blocked_node = 0xffffffffac3e9800 <rcu_state+640>,\n"
        )
        rcu_node_out = (
            "sysctl_panic_on_rcu_stall = $2 = 1\n"
            "  gp_tasks = 0xffff9b29cc4a42c0,\n"
            "  blkd_tasks = {\n"
            "    next = 0xffff9b29cc4a42c0,\n"
            "    prev = 0xffff9b29cc4a42c0\n"
            "  },\n"
            "  qsmask = 0,\n"
            "  gp_seq = 7398185,\n"
        )
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
        return facts

    def test_rcu_stall_real_replay_closes_gates(self) -> None:
        facts = self._collect_real_rcu_stall_facts()
        gates = {
            "lock_holder": _make_gate(required_for=["rcu_stall"], status="open"),
            "rcu_stall_trace": _make_gate(required_for=["rcu_stall"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["lock_holder"].status, "closed")
        self.assertEqual(evaluated["rcu_stall_trace"].status, "closed")

    def test_rcu_stall_negative_zero_fields_do_not_close(self) -> None:
        facts = (
            extract_evidence_facts(
                "bt",
                {"command": "bt 309547"},
                'PID: 309547   TASK: ffff9b29cc4a3980  CPU: 6    COMMAND: "rcu_blocked_rea"\n'
                " #0 [ffffb09bc052fd90] __schedule at ffffffffab06658a\n",
            )
            | extract_evidence_facts(
                "struct",
                {"command": "struct task_struct ffff9b29cc4a3980"},
                "  pid = 309547,\n  rcu_read_lock_nesting = 0,\n  rcu_blocked_node = 0x0,\n  gp_tasks = 0x0,\n",
            )
        )
        gates = {
            "lock_holder": _make_gate(required_for=["rcu_stall"], status="closed"),
            "rcu_stall_trace": _make_gate(required_for=["rcu_stall"], status="closed"),
        }
        evaluated, transitions = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["lock_holder"].status, "open")
        self.assertEqual(evaluated["rcu_stall_trace"].status, "open")
        rejected = {t["gate_name"] for t in transitions if t["event"] == "llm_close_rejected"}
        self.assertEqual(rejected, {"lock_holder", "rcu_stall_trace"})

    # ------------------------------------------------------------------
    # 2. hung_task (blocked_task_context + wait_chain)
    # ------------------------------------------------------------------
    def test_hung_task_lock_hang_wait_graph_and_bt_closes_gates(self) -> None:
        wait_graph_json = json.dumps(
            {
                "status": "deadlock_detected",
                "tasks_analyzed": 2,
                "deadlock_cycles": [[1001, 1002, 1001]],
                "root_blockers": [{"pid": 1002, "comm": "worker_b"}],
                "wait_edges": [
                    {
                        "waiter_pid": 1001,
                        "owner_pid": 1002,
                        "lock_type": "mutex",
                        "lock_addr": "0xffff888100001000",
                    }
                ],
                "non_sleep_lock_or_unresolved_tasks": [],
            }
        )
        bt_out = (
            'PID: 1001   TASK: ffff888100100000  CPU: 1    COMMAND: "worker_a"\n'
            " #0 [ffffc9000010fd00] __schedule at ffffffff81a00100\n"
            " #1 [ffffc9000010fd60] __mutex_lock at ffffffff81a02300\n"
        )
        facts = (
            extract_evidence_facts("analyze_lock_wait_graph", {"command": ""}, wait_graph_json)
            | extract_evidence_facts("bt", {"command": "bt 1001"}, bt_out)
        )
        self.assertIn("wait_graph_cycle:1001->1002->1001", facts)
        self.assertIn("wait_graph_blocker:pid=1002", facts)

        gates = {
            "blocked_task_context": _make_gate(required_for=["hung_task"], status="open"),
            "wait_chain": _make_gate(required_for=["hung_task"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["blocked_task_context"].status, "closed")
        self.assertEqual(evaluated["blocked_task_context"].closure_basis, "executor_evidence")
        self.assertEqual(evaluated["wait_chain"].status, "closed")
        self.assertEqual(evaluated["wait_chain"].closure_basis, "executor_evidence")

    def test_hung_task_native_bt_ps_and_mutex_owner_closes_gates(self) -> None:
        ps_out = "  1001      2   1  ffff888100100000  UN   0.0       0      0  [worker_a]\n"
        bt_out = (
            'PID: 1001   TASK: ffff888100100000  CPU: 1    COMMAND: "worker_a"\n'
            " #0 [ffffc9000010fd00] __schedule at ffffffff81a00100\n"
        )
        mutex_out = "  owner = { counter = 0xffff888100200001 }\n"
        facts = (
            extract_evidence_facts("ps", {"command": "ps -m"}, ps_out)
            | extract_evidence_facts("bt", {"command": "bt 1001"}, bt_out)
            | extract_evidence_facts("struct", {"command": "struct mutex.owner ffff888100001000"}, mutex_out)
        )
        gates = {
            "blocked_task_context": _make_gate(required_for=["hung_task"], status="open"),
            "wait_chain": _make_gate(required_for=["hung_task"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["blocked_task_context"].status, "closed")
        self.assertEqual(evaluated["wait_chain"].status, "closed")

    def test_hung_task_negative_only_bt_does_not_close(self) -> None:
        bt_only = extract_evidence_facts(
            "bt",
            {"command": "bt 1001"},
            'PID: 1001   TASK: ffff888100100000  CPU: 1    COMMAND: "worker_a"\n'
            " #0 [ffffc9000010fd00] __schedule at ffffffff81a00100\n",
        )
        gates = {
            "blocked_task_context": _make_gate(required_for=["hung_task"], status="open"),
            "wait_chain": _make_gate(required_for=["hung_task"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, bt_only)
        self.assertEqual(evaluated["blocked_task_context"].status, "open")
        self.assertEqual(evaluated["wait_chain"].status, "open")

    # ------------------------------------------------------------------
    # 3. soft_lockup (stack_integrity + lock_holder)
    # ------------------------------------------------------------------
    def test_soft_lockup_spinlock_contention_closes_gates(self) -> None:
        cpu_json = json.dumps(
            {
                "total_cpus_parsed": 8,
                "idle_cpu_count": 6,
                "spinlock_contender_count": 2,
                "spinlock_contenders": [{"cpu": 2, "pid": 4400, "comm": "net_rx"}],
                "irq_or_softirq_cpus": [],
                "active_or_suspected_cpus": [{"cpu": 2, "pid": 4400, "wait_category": "spinlock"}],
                "rcu_state_summary": {},
            }
        )
        bt_out = (
            'PID: 4400   TASK: ffff888100440000  CPU: 2    COMMAND: "net_rx"\n'
            " #0 [ffffc9000020fd00] native_queued_spin_lock_slowpath at ffffffff81a05000\n"
        )
        dis_out = "0xffffffff81a05000 <native_queued_spin_lock_slowpath+0>:\tpause\n"
        facts = (
            extract_evidence_facts("analyze_cpu_lockup_rcu", {"command": ""}, cpu_json)
            | extract_evidence_facts("bt", {"command": "bt -c 2"}, bt_out)
            | extract_evidence_facts("dis", {"command": "dis native_queued_spin_lock_slowpath"}, dis_out)
        )
        gates = {
            "stack_integrity": _make_gate(required_for=["soft_lockup"], status="open"),
            "lock_holder": _make_gate(required_for=["soft_lockup"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["stack_integrity"].status, "closed")
        self.assertEqual(evaluated["lock_holder"].status, "closed")

    def test_soft_lockup_lock_free_busy_loop_closes_gates(self) -> None:
        """无外部锁争抢的纯 CPU/softirq 死循环：有无锁停滞诊断 + bt + dis 也能合法闭合。"""
        cpu_json = json.dumps(
            {
                "total_cpus_parsed": 8,
                "idle_cpu_count": 7,
                "spinlock_contender_count": 0,
                "spinlock_contenders": [],
                "irq_or_softirq_cpus": [{"cpu": 3, "pid": 0}],
                "active_or_suspected_cpus": [{"cpu": 3, "pid": 0, "wait_category": "irq_softirq"}],
                "rcu_state_summary": {},
            }
        )
        bt_out = (
            'PID: 0   TASK: ffff888100003000  CPU: 3    COMMAND: "swapper/3"\n'
            " #0 [ffffc9000030fd00] bad_softirq_loop at ffffffffc0100100 [badmod]\n"
        )
        dis_out = "0xffffffffc0100100 <bad_softirq_loop+0>:\tjmp 0xffffffffc0100100\n"
        facts = (
            extract_evidence_facts("analyze_cpu_lockup_rcu", {"command": ""}, cpu_json)
            | extract_evidence_facts("bt", {"command": "bt -c 3"}, bt_out)
            | extract_evidence_facts("dis", {"command": "dis bad_softirq_loop"}, dis_out)
        )
        self.assertIn("cpu_lockup_no_spinlock:true", facts)
        gates = {
            "stack_integrity": _make_gate(required_for=["soft_lockup"], status="open"),
            "lock_holder": _make_gate(required_for=["soft_lockup"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["stack_integrity"].status, "closed")
        self.assertEqual(evaluated["lock_holder"].status, "closed")

    def test_soft_lockup_negative_bt_dis_without_lock_or_cpu_diag_does_not_close_holder(self) -> None:
        """仅有 bt + dis 而未排查锁或 CPU 停滞诊断时，lock_holder 不得误关。"""
        facts = (
            extract_evidence_facts(
                "bt",
                {"command": "bt -c 3"},
                'PID: 0   TASK: ffff888100003000  CPU: 3    COMMAND: "swapper/3"\n'
                " #0 [ffffc9000030fd00] some_func at ffffffffc0100100\n",
            )
            | extract_evidence_facts(
                "dis",
                {"command": "dis some_func"},
                "0xffffffffc0100100 <some_func+0>:\tnop\n",
            )
        )
        gates = {
            "stack_integrity": _make_gate(required_for=["soft_lockup"], status="open"),
            "lock_holder": _make_gate(required_for=["soft_lockup"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["stack_integrity"].status, "closed")
        self.assertEqual(evaluated["lock_holder"].status, "open")

    # ------------------------------------------------------------------
    # 4. hard_lockup (nmi_watchdog_evidence + cpu_progress_state)
    # ------------------------------------------------------------------
    def test_hard_lockup_nmi_bt_and_runq_closes_gates(self) -> None:
        bt_out = (
            'PID: 5500   TASK: ffff888100550000  CPU: 4    COMMAND: "irq_hog"\n'
            " #0 [fffffe00000c0e00] watchdog_overflow_callback at ffffffff811a2000\n"
            " #1 [fffffe00000c0e40] nmi_handle at ffffffff81023400\n"
            " #2 [fffffe00000c0ec0] exc_nmi at ffffffff81a10000\n"
        )
        runq_out = (
            "CPU 4 RUNQUEUE: ffff88842ed2aa00\n"
            '  CURRENT: PID: 5500  TASK: ffff888100550000  COMMAND: "irq_hog"\n'
        )
        facts = (
            extract_evidence_facts("bt", {"command": "bt -c 4"}, bt_out)
            | extract_evidence_facts("runq", {"command": "runq"}, runq_out)
        )
        self.assertIn("nmi_watchdog_frame:watchdog_overflow_callback", facts)
        self.assertIn("runq_cpu:cpu=4:pid=5500", facts)

        gates = {
            "nmi_watchdog_evidence": _make_gate(required_for=["hard_lockup"], status="open"),
            "cpu_progress_state": _make_gate(required_for=["hard_lockup"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["nmi_watchdog_evidence"].status, "closed")
        self.assertEqual(evaluated["cpu_progress_state"].status, "closed")

    def test_hard_lockup_negative_normal_bt_without_nmi_or_runq_does_not_close(self) -> None:
        bt_out = (
            'PID: 5500   TASK: ffff888100550000  CPU: 4    COMMAND: "irq_hog"\n'
            " #0 [fffffe00000c0e00] __schedule at ffffffff81a00100\n"
        )
        facts = extract_evidence_facts("bt", {"command": "bt -c 4"}, bt_out)
        gates = {
            "nmi_watchdog_evidence": _make_gate(required_for=["hard_lockup"], status="open"),
            "cpu_progress_state": _make_gate(required_for=["hard_lockup"], status="open"),
        }
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["nmi_watchdog_evidence"].status, "open")
        self.assertEqual(evaluated["cpu_progress_state"].status, "open")

    # ------------------------------------------------------------------
    # 5. Full-stack end-to-end projection & report rendering (project venv)
    # ------------------------------------------------------------------
    @unittest.skipUnless(_HAS_FULL_STACK, "Requires project venv (langchain_core/pydantic)")
    def test_end_to_end_rcu_stall_projection_and_markdown_report(self) -> None:
        facts = self._collect_real_rcu_stall_facts()
        # 生产路径的 LLM 输出是 VMCoreLLMAnalysisStep：它不做构造期门控降级，
        # 门控闭合由 executor 的 project_managed_analysis_step 负责。
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
                crash_type="rcu_stall",
                panic_string="rcu: INFO: rcu_preempt detected stalls on CPUs/tasks",
                faulting_instruction="schedule_timeout_interruptible",
                root_cause=(
                    "第三方模块 rcu_stall_mod 在 RCU 读临界区内循环睡眠 70 秒触发 RCU Stall panic。"
                ),
                detailed_analysis=(
                    "PID 309547 在 __rcu_read_lock 与 __rcu_read_unlock 之间调用 "
                    "schedule_timeout_interruptible，持有 RCU 读锁进入睡眠。"
                ),
                suspect_code=SuspectCode(
                    module="rcu_stall_mod",
                    function="rcu_stall_thread",
                    file="rcu_stall_mod.c",
                    line="240",
                    description="rcu_read_lock() 区间内调用可睡眠函数",
                ),
                evidence=["dis_instruction:0xffffffffc0fd791d=call"],
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
        self.assertNotIn("分析未得出正式的最终结论", md)


if __name__ == "__main__":
    unittest.main()
