#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# test_lock_hang_analyzer.py - Lock Hang 分析器单元测试
# Author: CalmWU
# Created: 2026-11-22

"""Unit tests for src.mcp_tools.lock_hang.analyzer."""

import json
import unittest

from src.mcp_tools.lock_hang.analyzer import (
    analyze_cpu_lockup_rcu,
    analyze_lock_wait_graph,
    decode_lock_owner_word,
    detect_wait_cycles,
    find_root_blockers,
    parse_multi_bt,
    parse_ps_tasks,
    parse_runq_summary,
    parse_struct_lock_owner,
    WaitEdge,
)


MOCK_PS_M = """\
[0 00:05:12.100] [UN]  PID: 1001   TASK: ffff888100001000  CPU: 1   COMMAND: "kworker/1:1"
[0 00:05:11.900] [UN]  PID: 1002   TASK: ffff888100002000  CPU: 2   COMMAND: "xfsaild/sda1"
[0 00:00:00.010] [RU]  PID: 1003   TASK: ffff888100003000  CPU: 3   COMMAND: "app_worker"
"""

MOCK_BT_DEADLOCK = """\
PID: 1001   TASK: ffff888100001000  CPU: 1   COMMAND: "kworker/1:1"
 #0 [ffffc90000103d00] __schedule at ffffffff81a01234
 #1 [ffffc90000103d80] schedule at ffffffff81a01800
 #2 [ffffc90000103da0] __mutex_lock_slowpath at ffffffff81a04400
    ffffc90000103da8: ffff88820000a000 0000000000000000
 #3 [ffffc90000103e00] ext4_sync_file at ffffffffc0123456

PID: 1002   TASK: ffff888100002000  CPU: 2   COMMAND: "xfsaild/sda1"
 #0 [ffffc90000203d00] __schedule at ffffffff81a01234
 #1 [ffffc90000203d80] schedule at ffffffff81a01800
 #2 [ffffc90000203da0] __mutex_lock_slowpath at ffffffff81a04400
    ffffc90000203da8: ffff88820000b000 0000000000000000
 #3 [ffffc90000203e00] xfs_fs_sync_fs at ffffffffc0223456
"""

MOCK_CPU_LOCKUP_OUTPUT = """\
PID: 0      TASK: ffffffff82614840  CPU: 0   COMMAND: "swapper/0"
 #0 [fffffe0000003f00] default_idle at ffffffff81a0f000

PID: 2048   TASK: ffff888100008000  CPU: 1   COMMAND: "ksoftirqd/1"
 #0 [fffffe0000013e00] watchdog_timer_fn at ffffffff81123456
 #1 [fffffe0000013e40] native_queued_spin_lock_slowpath at ffffffff81a09900
 #2 [fffffe0000013e80] __do_softirq at ffffffff81c00010
===LOCK_HANG_RUNQ===
CPU 0: RUNQUEUE: ffff8881fbc2a000
  CURRENT: PID: 0      TASK: ffffffff82614840  COMMAND: "swapper/0"
  RT PRIO_ARRAY: ffff8881fbc2a180
     [no tasks queued]
CPU 1: RUNQUEUE: ffff8881fbc6a000
  CURRENT: PID: 2048   TASK: ffff888100008000  COMMAND: "ksoftirqd/1"
  CFS RB_ROOT: ffff8881fbc6a0a0
     [120] PID: 3001   TASK: ffff888100009000  COMMAND: "nginx"
     [120] PID: 3002   TASK: ffff888100009100  COMMAND: "nginx"
===LOCK_HANG_RCU===
rcu_state = $1 = {
  gp_seq = 0x1045,
  gp_state = 2,
  gp_kthread = 0xffff888100004000,
  jiffies_stall = 4295001234
}
"""


class LockHangAnalyzerTests(unittest.TestCase):
    def test_decode_lock_owner_word_masks_low_bits(self):
        # 0xffff888100002003 -> task=0xffff888100002000, flags=0x3
        addr, flags, reader = decode_lock_owner_word(0xFFFF888100002003, "mutex")
        self.assertEqual(addr, 0xFFFF888100002000)
        self.assertEqual(flags, 0x3)
        self.assertFalse(reader)

        addr_rw, flags_rw, reader_rw = decode_lock_owner_word(0xFFFF888100002001, "rwsem")
        self.assertEqual(addr_rw, 0xFFFF888100002000)
        self.assertEqual(flags_rw, 0x1)
        self.assertTrue(reader_rw)

    def test_parse_struct_lock_owner_handles_signed_negative_counter(self):
        # 0xffff888100002001 as signed 64-bit integer
        signed_val = 0xFFFF888100002001 - (1 << 64)
        output = f"  owner = {{\n    counter = {signed_val}\n  }}"
        addr, flags, _ = parse_struct_lock_owner(output, "mutex")
        self.assertEqual(addr, 0xFFFF888100002000)
        self.assertEqual(flags, 0x1)

    def test_ab_ba_deadlock_detection_end_to_end(self):
        def fake_crash(cmd, vmcore, vmlinux, verbose):
            if cmd == "ps -m":
                return MOCK_PS_M
            raise AssertionError(f"Unexpected crash cmd: {cmd}")

        def fake_script(script, vmcore, vmlinux, verbose):
            if "bt -f" in script:
                return MOCK_BT_DEADLOCK
            if "ffff88820000a000" in script:
                return "===LOCK_CAND:ffff88820000a000===\n  owner = {\n    counter = 0xffff888100002001\n  }\n"
            if "ffff88820000b000" in script:
                return "===LOCK_CAND:ffff88820000b000===\n  owner = {\n    counter = 0xffff888100001001\n  }\n"
            return ""

        res = json.loads(
            analyze_lock_wait_graph(
                "/tmp/vmcore",
                "/tmp/vmlinux",
                "--top 5",
                crash_runner=fake_crash,
                script_runner=fake_script,
            )
        )
        self.assertEqual(res["status"], "deadlock_detected")
        self.assertEqual(res["deadlock_cycles"], [[1001, 1002, 1001]])
        self.assertEqual(len(res["wait_edges"]), 2)

    def test_cpu_lockup_rcu_aggregation(self):
        def fake_script(script, vmcore, vmlinux, verbose):
            return MOCK_CPU_LOCKUP_OUTPUT

        res = json.loads(
            analyze_cpu_lockup_rcu(
                "/tmp/vmcore",
                "/tmp/vmlinux",
                "",
                script_runner=fake_script,
            )
        )
        self.assertEqual(res["total_cpus_parsed"], 2)
        self.assertEqual(res["idle_cpu_count"], 1)
        # CPU 1 的调用栈包含 watchdog_timer_fn (#0) 和 native_queued_spin_lock_slowpath (#1)。
        # 经优先级全栈扫描后，核心自旋锁原语被优先捕获为 spinlock，同时 IRQ 状态也正常记录。
        self.assertEqual(res["spinlock_contender_count"], 1)
        self.assertEqual(res["spinlock_contenders"][0]["cpu"], 1)
        self.assertEqual(len(res["irq_or_softirq_cpus"]), 1)
        self.assertEqual(res["irq_or_softirq_cpus"][0]["cpu"], 1)
        self.assertEqual(res["rcu_state_summary"]["gp_seq"], "0x1045")

    # ------------------------------------------------------------------ #
    # #11 补充：detect_wait_cycles 多场景覆盖
    # ------------------------------------------------------------------ #

    def test_detect_wait_cycles_no_cycle(self):
        """线性等待链 A->B->C，不应检测到环。"""
        edges = [
            WaitEdge(waiter_pid=1, waiter_comm="a", waiter_task="0x1",
                     lock_type="mutex", lock_addr="0xa", owner_pid=2,
                     owner_comm="b", owner_task="0x2", owner_flags=0),
            WaitEdge(waiter_pid=2, waiter_comm="b", waiter_task="0x2",
                     lock_type="mutex", lock_addr="0xb", owner_pid=3,
                     owner_comm="c", owner_task="0x3", owner_flags=0),
        ]
        self.assertEqual(detect_wait_cycles(edges), [])

    def test_detect_wait_cycles_single_cycle(self):
        """A->B->A 两节点环。"""
        edges = [
            WaitEdge(waiter_pid=10, waiter_comm="a", waiter_task="0x1",
                     lock_type="mutex", lock_addr="0xa", owner_pid=20,
                     owner_comm="b", owner_task="0x2", owner_flags=0),
            WaitEdge(waiter_pid=20, waiter_comm="b", waiter_task="0x2",
                     lock_type="mutex", lock_addr="0xb", owner_pid=10,
                     owner_comm="a", owner_task="0x1", owner_flags=0),
        ]
        cycles = detect_wait_cycles(edges)
        self.assertEqual(len(cycles), 1)
        # 归一化后以最小 PID 10 开头
        self.assertEqual(cycles[0], [10, 20, 10])

    def test_detect_wait_cycles_multiple_cycles(self):
        """A->B->A 和 C->D->C 两个独立环。"""
        edges = [
            WaitEdge(waiter_pid=1, waiter_comm="a", waiter_task="0x1",
                     lock_type="mutex", lock_addr="0xa", owner_pid=2,
                     owner_comm="b", owner_task="0x2", owner_flags=0),
            WaitEdge(waiter_pid=2, waiter_comm="b", waiter_task="0x2",
                     lock_type="mutex", lock_addr="0xb", owner_pid=1,
                     owner_comm="a", owner_task="0x1", owner_flags=0),
            WaitEdge(waiter_pid=3, waiter_comm="c", waiter_task="0x3",
                     lock_type="mutex", lock_addr="0xc", owner_pid=4,
                     owner_comm="d", owner_task="0x4", owner_flags=0),
            WaitEdge(waiter_pid=4, waiter_comm="d", waiter_task="0x4",
                     lock_type="mutex", lock_addr="0xd", owner_pid=3,
                     owner_comm="c", owner_task="0x3", owner_flags=0),
        ]
        cycles = detect_wait_cycles(edges)
        self.assertEqual(len(cycles), 2)

    def test_detect_wait_cycles_three_node_ring(self):
        """A->B->C->A 三节点环。"""
        edges = [
            WaitEdge(waiter_pid=5, waiter_comm="a", waiter_task="0x1",
                     lock_type="mutex", lock_addr="0xa", owner_pid=10,
                     owner_comm="b", owner_task="0x2", owner_flags=0),
            WaitEdge(waiter_pid=10, waiter_comm="b", waiter_task="0x2",
                     lock_type="mutex", lock_addr="0xb", owner_pid=15,
                     owner_comm="c", owner_task="0x3", owner_flags=0),
            WaitEdge(waiter_pid=15, waiter_comm="c", waiter_task="0x3",
                     lock_type="mutex", lock_addr="0xc", owner_pid=5,
                     owner_comm="a", owner_task="0x1", owner_flags=0),
        ]
        cycles = detect_wait_cycles(edges)
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0], [5, 10, 15, 5])

    # ------------------------------------------------------------------ #
    # #11 补充：find_root_blockers
    # ------------------------------------------------------------------ #

    def test_find_root_blockers_identifies_non_waiting_owner(self):
        """PID 1 -> PID 2 -> PID 3（PID 3 不在 waiters 中），PID 3 是根阻塞者。"""
        edges = [
            WaitEdge(waiter_pid=1, waiter_comm="a", waiter_task="0x1",
                     lock_type="mutex", lock_addr="0xa", owner_pid=2,
                     owner_comm="b", owner_task="0x2", owner_flags=0),
            WaitEdge(waiter_pid=2, waiter_comm="b", waiter_task="0x2",
                     lock_type="mutex", lock_addr="0xb", owner_pid=3,
                     owner_comm="c", owner_task="0x3", owner_flags=0),
        ]
        blockers = find_root_blockers(edges)
        self.assertEqual(len(blockers), 1)
        self.assertEqual(blockers[0]["pid"], 3)
        # find_root_blockers 仅记录直接等待该 owner 的 waiter（PID 2），
        # 不做传递闭包（PID 1 间接被阻塞但不直接列出）。
        self.assertIn(2, blockers[0]["blocked_waiter_pids"])

    def test_find_root_blockers_sorted_by_blocked_count(self):
        """多个根阻塞者按被阻塞的 waiter 数量降序排列。"""
        edges = [
            WaitEdge(waiter_pid=1, waiter_comm="a", waiter_task="0x1",
                     lock_type="mutex", lock_addr="0xa", owner_pid=100,
                     owner_comm="blocker1", owner_task="0x100", owner_flags=0),
            WaitEdge(waiter_pid=2, waiter_comm="b", waiter_task="0x2",
                     lock_type="mutex", lock_addr="0xa", owner_pid=100,
                     owner_comm="blocker1", owner_task="0x100", owner_flags=0),
            WaitEdge(waiter_pid=3, waiter_comm="c", waiter_task="0x3",
                     lock_type="mutex", lock_addr="0xb", owner_pid=200,
                     owner_comm="blocker2", owner_task="0x200", owner_flags=0),
        ]
        blockers = find_root_blockers(edges)
        self.assertEqual(len(blockers), 2)
        # PID 100 阻塞了 2 个 waiter，排在前面
        self.assertEqual(blockers[0]["pid"], 100)
        self.assertEqual(blockers[1]["pid"], 200)

    # ------------------------------------------------------------------ #
    # #11 补充：parse_ps_tasks
    # ------------------------------------------------------------------ #

    def test_parse_ps_tasks_standard_format(self):
        ps_output = """\
>     1234      1   3  ffff888100abc000  UN   0  120  120  my_daemon
      5678      1   0  ffff888100def000  RU   0  120  120  kworker/0:1
"""
        tasks = parse_ps_tasks(ps_output)
        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0].pid, 1234)
        self.assertEqual(tasks[0].state, "UN")
        self.assertEqual(tasks[0].comm, "my_daemon")
        self.assertEqual(tasks[1].pid, 5678)
        self.assertEqual(tasks[1].state, "RU")

    def test_parse_ps_tasks_ps_m_format(self):
        tasks = parse_ps_tasks(MOCK_PS_M)
        self.assertEqual(len(tasks), 3)
        self.assertEqual(tasks[0].pid, 1001)
        self.assertEqual(tasks[0].age, "0 00:05:12.100")
        self.assertEqual(tasks[2].state, "RU")

    # ------------------------------------------------------------------ #
    # #11 补充：parse_multi_bt 分类覆盖
    # ------------------------------------------------------------------ #

    def test_parse_multi_bt_classifies_spinlock(self):
        bt_text = """\
PID: 99   TASK: ffff888100099000  CPU: 0   COMMAND: "spin_holder"
 #0 [ffffc90000099d00] native_queued_spin_lock_slowpath at ffffffff81a09900
 #1 [ffffc90000099d40] some_driver_func at ffffffffc0999999
"""
        bts = parse_multi_bt(bt_text)
        self.assertEqual(len(bts), 1)
        self.assertEqual(bts[0].wait_category, "spinlock")
        self.assertEqual(bts[0].wait_function, "native_queued_spin_lock_slowpath")

    def test_parse_multi_bt_classifies_io_wait(self):
        bt_text = """\
PID: 50   TASK: ffff888100050000  CPU: 2   COMMAND: "io_worker"
 #0 [ffffc90000050d00] io_schedule at ffffffff81a0ab00
 #1 [ffffc90000050d40] wait_on_page_bit at ffffffff81234567
"""
        bts = parse_multi_bt(bt_text)
        self.assertEqual(len(bts), 1)
        self.assertEqual(bts[0].wait_category, "io_wait")

    def test_parse_multi_bt_classifies_irq_softirq(self):
        bt_text = """\
PID: 60   TASK: ffff888100060000  CPU: 4   COMMAND: "irq_handler"
 #0 [ffffc90000060d00] watchdog_timer_fn at ffffffff81b00000
 #1 [ffffc90000060d40] __do_softirq at ffffffff81c00010
"""
        bts = parse_multi_bt(bt_text)
        self.assertEqual(len(bts), 1)
        self.assertEqual(bts[0].wait_category, "irq_softirq")

    # ------------------------------------------------------------------ #
    # #11 补充：parse_runq_summary
    # ------------------------------------------------------------------ #

    def test_parse_runq_summary_counts_queued_tasks(self):
        runq_text = """\
CPU 0: RUNQUEUE: ffff8881fbc2a000
  CURRENT: PID: 100   TASK: ffff888100100000  COMMAND: "worker"
  CFS RB_ROOT: ffff8881fbc2a0a0
     [120] PID: 200   TASK: ffff888100200000  COMMAND: "task_a"
     [120] PID: 201   TASK: ffff888100201000  COMMAND: "task_b"
     [120] PID: 202   TASK: ffff888100202000  COMMAND: "task_c"
CPU 1: RUNQUEUE: ffff8881fbc6a000
  CURRENT: PID: 0      TASK: ffffffff82614840  COMMAND: "swapper/1"
"""
        result = parse_runq_summary(runq_text)
        self.assertEqual(result[0]["current_pid"], 100)
        self.assertEqual(result[0]["queued_tasks"], 3)
        self.assertEqual(result[1]["current_pid"], 0)
        self.assertEqual(result[1]["queued_tasks"], 0)

    # ------------------------------------------------------------------ #
    # #11 补充：decode_lock_owner_word 边界值
    # ------------------------------------------------------------------ #

    def test_decode_lock_owner_word_zero_returns_none(self):
        addr, flags, reader = decode_lock_owner_word(0, "mutex")
        self.assertIsNone(addr)
        self.assertEqual(flags, 0)
        self.assertFalse(reader)

    def test_decode_lock_owner_word_negative_returns_none(self):
        addr, flags, reader = decode_lock_owner_word(-1, "mutex")
        self.assertIsNone(addr)
        self.assertFalse(reader)

    def test_decode_lock_owner_word_text_segment_addr_returns_none(self):
        """内核文本段地址 (>= 0xFFFFFFFF80000000) 不是合法的 task_struct。"""
        addr, flags, reader = decode_lock_owner_word(0xFFFFFFFF81000000, "mutex")
        self.assertIsNone(addr)

    def test_decode_lock_owner_word_rwsem_non_reader(self):
        """rwsem owner 未设 RWSEM_READER_OWNED_BIT 时 reader_owned=False。"""
        addr, flags, reader = decode_lock_owner_word(0xFFFF888100002004, "rwsem")
        self.assertEqual(addr, 0xFFFF888100002000)
        self.assertEqual(flags, 0x4)
        self.assertFalse(reader)

    # ------------------------------------------------------------------ #
    # 优先级全栈分类测试
    # ------------------------------------------------------------------ #

    def test_classify_backtrace_prioritizes_spinlock_over_watchdog_frame(self):
        """当看门狗或中断打断自旋锁时，应优先分类为 spinlock。"""
        bt_text = """\
PID: 88   TASK: ffff888100088000  CPU: 3   COMMAND: "kworker/3:1"
 #0 [ffffc90000088d00] watchdog_timer_fn at ffffffff81b00000
 #1 [ffffc90000088d40] native_queued_spin_lock_slowpath at ffffffff81a09900
 #2 [ffffc90000088d80] _raw_spin_lock at ffffffff81a09800
"""
        bts = parse_multi_bt(bt_text)
        self.assertEqual(len(bts), 1)
        self.assertEqual(bts[0].wait_category, "spinlock")
        self.assertEqual(bts[0].wait_function, "native_queued_spin_lock_slowpath")

    def test_classify_backtrace_prioritizes_mutex_over_irq_exit(self):
        """当调用栈深处有 mutex 等待时，应优先分类为 mutex。"""
        bt_text = """\
PID: 89   TASK: ffff888100089000  CPU: 2   COMMAND: "worker"
 #0 [ffffc90000089d00] irq_exit at ffffffff81060000
 #1 [ffffc90000089d40] __mutex_lock_slowpath at ffffffff81a04400
"""
        bts = parse_multi_bt(bt_text)
        self.assertEqual(len(bts), 1)
        self.assertEqual(bts[0].wait_category, "mutex")
        self.assertEqual(bts[0].wait_function, "__mutex_lock_slowpath")

    def test_idle_cpu_with_hardware_interrupt_remains_idle(self):
        """空闲 CPU 栈中包含底层硬件中断跳板（asm_common_interrupt）时，仍应被判定为 idle。"""
        bt_idle_with_irq = """\
PID: 0   TASK: ffffffff82614840  CPU: 9   COMMAND: "swapper/9"
 #0 [ffffc9000a0c3d40] intel_idle at ffffffff81c0f10
 #1 [ffffc9000a0c3d78] cpuidle_enter_state at ffffffff81d0a9a0
 #2 [ffffc9000a0c3ea0] cpuidle_enter at ffffffff81d0acd0
 #3 [ffffc9000a0c3ec8] do_idle at ffffffff81a1d000
 #4 [ffffc9000a0c3f10] asm_common_interrupt at ffffffff81c0100e
"""
        def fake_script(script, vmcore, vmlinux, verbose):
            return bt_idle_with_irq

        # include-idle=False 时，空闲 CPU 9 应被计入 idle_cpu_count 并被过滤
        res_default = json.loads(
            analyze_cpu_lockup_rcu(
                "/tmp/vmcore", "/tmp/vmlinux", "", script_runner=fake_script
            )
        )
        self.assertEqual(res_default["idle_cpu_count"], 1)
        self.assertEqual(len(res_default["irq_or_softirq_cpus"]), 0)
        self.assertEqual(len(res_default["active_or_suspected_cpus"]), 0)
        self.assertEqual(len(res_default["recommended_next_commands"]), 0)

        # include-idle=True 时，虽输出该核信息，但其不能被放入 irq_or_softirq 或 suspected 列表中
        res_include = json.loads(
            analyze_cpu_lockup_rcu(
                "/tmp/vmcore", "/tmp/vmlinux", "--include-idle", script_runner=fake_script
            )
        )
        self.assertEqual(res_include["idle_cpu_count"], 1)
        self.assertEqual(len(res_include["irq_or_softirq_cpus"]), 0)
        self.assertEqual(len(res_include["active_or_suspected_cpus"]), 0)

    def test_hardirq_active_cpu_fallback_recommendation(self):
        """当无自旋锁或看门狗触发，但存在非 idle 硬件中断活跃核时，应触发兜底建议。"""
        bt_hardirq = """\
PID: 1234   TASK: ffff888100123000  CPU: 5   COMMAND: "app_worker"
 #0 [ffffc900050c3d00] broken_nic_isr at ffffffffc0012345
 #1 [ffffc900050c3d40] handle_irq_event_percpu at ffffffff81123456
 #2 [ffffc900050c3d80] handle_irq_event at ffffffff81123789
 #3 [ffffc900050c3dc0] common_interrupt at ffffffff81c01000
"""
        def fake_script(script, vmcore, vmlinux, verbose):
            return bt_hardirq

        res = json.loads(
            analyze_cpu_lockup_rcu(
                "/tmp/vmcore", "/tmp/vmlinux", "", script_runner=fake_script
            )
        )
        self.assertEqual(res["idle_cpu_count"], 0)
        self.assertEqual(res["spinlock_contender_count"], 0)
        self.assertEqual(len(res["active_or_suspected_cpus"]), 0)
        # 应触发兜底建议：输出 bt -c 5 以及反汇编顶帧 dis -rl broken_nic_isr
        self.assertIn("bt -c 5", res["recommended_next_commands"])
        self.assertIn("dis -rl broken_nic_isr", res["recommended_next_commands"])


if __name__ == "__main__":
    unittest.main()
