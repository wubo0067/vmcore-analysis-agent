#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for P1 + P2 + P3 review fixes:
- P1-1: lock_hang/stack_canary stdio env forwarding via crash_stdio_env()
- P1-2: ps -m parsing in evidence._parse_ps
- P2-3: CrashDaemonClient dynamic HTTP timeout & TimeoutError vs unreachable distinction
- P2-4: _parse_bt per-task frame cap under multi-CPU bt -a
- P2-5: state_manager._build_evidence_goal coverage for all 7 lock/hang gates
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from src.mcp_tools.crash import daemon as daemon_mod
from src.mcp_tools.crash import executor as executor_mod
from src.react.evidence import evaluate_gate_closures, extract_evidence_facts


class _LiteGate:
    def __init__(self, required_for, status="open"):
        self.required_for = list(required_for)
        self.status = status
        self.prerequisite = None
        self.evidence = None
        self.closure_basis = None
        self.completion_criteria = []

    def model_copy(self, deep=False):
        g = _LiteGate(self.required_for, self.status)
        g.evidence = self.evidence
        g.closure_basis = self.closure_basis
        g.completion_criteria = list(self.completion_criteria)
        return g


class TestReviewFixes(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_env = {
            k: os.environ.get(k)
            for k in (
                "CRASH_EXECUTION_MODE",
                "CRASH_DAEMON_ENDPOINT",
                "CRASH_COMMAND_TIMEOUT_SEC",
                "CRASH_POOL_ACQUIRE_TIMEOUT_SEC",
                "CRASH_SKIP_DISTRO_CHECK",
            )
        }

    def tearDown(self) -> None:
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_p1_1_lock_hang_and_stack_canary_forward_crash_stdio_env(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "mcp_tools"
        for sub in ("lock_hang", "stack_canary"):
            src = (root / sub / "client.py").read_text(encoding="utf-8")
            self.assertIn("crash_stdio_env", src)
            self.assertIn('"env": crash_stdio_env()', src)

    def test_p1_2_ps_m_format_extracts_un_state_and_closes_hung_task(self) -> None:
        ps_m_out = (
            '[0 00:05:12.100] [UN]  PID: 2048   TASK: ffff888100204800  CPU: 2  COMMAND: "xfs_io"\n'
            '[0 00:00:01.000] [IN]  PID: 2049   TASK: ffff888100204900  CPU: 3  COMMAND: "sshd"\n'
        )
        bt_out = (
            'PID: 2048   TASK: ffff888100204800  CPU: 2    COMMAND: "xfs_io"\n'
            " #0 [ffffc9000010fd00] __schedule at ffffffff81a00100\n"
            " #1 [ffffc9000010fd60] rwsem_down_write_slowpath at ffffffff81a03300\n"
        )
        facts = (
            extract_evidence_facts("ps", {"command": "ps -m"}, ps_m_out)
            | extract_evidence_facts("bt", {"command": "bt 2048"}, bt_out)
        )
        self.assertIn("ps_task_state:pid=2048=UN", facts)
        self.assertNotIn("ps_task_state:pid=2049=IN", facts)

        gates = {"blocked_task_context": _LiteGate(["hung_task"], "open")}
        evaluated, _ = evaluate_gate_closures(gates, facts)
        self.assertEqual(evaluated["blocked_task_context"].status, "closed")

    def test_p2_3_daemon_client_dynamic_timeout_and_timeout_error_message(self) -> None:
        os.environ["CRASH_COMMAND_TIMEOUT_SEC"] = "180"
        os.environ["CRASH_POOL_ACQUIRE_TIMEOUT_SEC"] = "120"
        client = daemon_mod.CrashDaemonClient("http://127.0.0.1:8765")

        captured = {}

        def fake_request_json(method, path, body=None, *, timeout=190.0):
            captured["timeout"] = timeout
            return {"ok": True, "output": "ok"}

        with mock.patch.object(client, "_request_json", side_effect=fake_request_json):
            self.assertEqual(client.execute("bt", "/tmp/v", "/tmp/l"), "ok")
        # 180 + 120 + 30 = 330s，覆盖排队 + 冷启动 + 执行
        self.assertEqual(captured["timeout"], 330.0)

        # TimeoutError 不得被误报为 daemon unreachable
        os.environ["CRASH_EXECUTION_MODE"] = "daemon"
        os.environ["CRASH_SKIP_DISTRO_CHECK"] = "1"
        os.environ["CRASH_DAEMON_ENDPOINT"] = "http://127.0.0.1:8765"
        with mock.patch.object(
            daemon_mod.CrashDaemonClient,
            "execute",
            side_effect=TimeoutError("timed out"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                executor_mod.run_crash_command("bt", "/tmp/v", "/tmp/l")
        msg = str(ctx.exception)
        self.assertIn("timed out", msg)
        self.assertNotIn("is unreachable", msg)

    def test_p2_4_parse_bt_per_task_limit_preserves_later_cpu_frames(self) -> None:
        # 构造 4 个 idle CPU（各 10 帧）+ 第 5 个卡死 CPU，验证第 5 个 CPU 栈帧不被前 16 帧吃光
        blocks = []
        for cpu in range(4):
            lines = [f'PID: 0   TASK: ffff88810000{cpu}000  CPU: {cpu}    COMMAND: "swapper/{cpu}"']
            for i in range(10):
                lines.append(f" #{i} [ffffc90000{cpu}0fd{i:02x}] idle_frame_{cpu}_{i} at ffffffff81000{cpu}{i:02x}")
            blocks.append("\n".join(lines))
        blocks.append(
            'PID: 7777   TASK: ffff888100777700  CPU: 4    COMMAND: "stalled_worker"\n'
            " #0 [ffffc9000040fd00] real_stalled_spin_func at ffffffffc0990100\n"
        )
        facts = extract_evidence_facts("bt", {"command": "bt -a"}, "\n".join(blocks))
        self.assertIn("bt_frame:real_stalled_spin_func", facts)

    def test_p2_5_state_manager_evidence_goal_covers_lock_hang_gates(self) -> None:
        sm_py = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "react"
            / "state_manager.py"
        ).read_text(encoding="utf-8")
        for gate_name in (
            "rcu_stall_trace",
            "lock_holder",
            "blocked_task_context",
            "wait_chain",
            "stack_integrity",
            "nmi_watchdog_evidence",
            "cpu_progress_state",
        ):
            self.assertIn(f'"{gate_name}":', sm_py)


if __name__ == "__main__":
    unittest.main()
