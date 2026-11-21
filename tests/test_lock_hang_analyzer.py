#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for src.mcp_tools.lock_hang.analyzer."""

import json
import unittest

from src.mcp_tools.lock_hang.analyzer import (
    analyze_cpu_lockup_rcu,
    analyze_lock_wait_graph,
    decode_lock_owner_word,
    detect_wait_cycles,
    parse_multi_bt,
    parse_ps_tasks,
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
        self.assertEqual(res["spinlock_contender_count"], 1)
        self.assertEqual(res["spinlock_contenders"][0]["cpu"], 1)
        self.assertEqual(res["rcu_state_summary"]["gp_seq"], "0x1045")


if __name__ == "__main__":
    unittest.main()
