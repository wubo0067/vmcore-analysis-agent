#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# test_lock_hang_client.py - Lock Hang MCP 客户端单元测试
# Author: CalmWU
# Created: 2026-11-22

"""Unit tests for src.mcp_tools.lock_hang.client and server registration."""

import asyncio
import unittest

from src.mcp_tools.lock_hang.client import build_tool_payload


class LockHangClientTests(unittest.TestCase):
    def test_build_tool_payload_success_dict_args(self):
        state = {"vmcore_path": "/var/crash/vmcore", "vmlinux_path": "/boot/vmlinux"}
        payload = build_tool_payload("analyze_lock_wait_graph", {"command": "--top 5"}, state)
        self.assertEqual(payload["command"], "--top 5")
        self.assertEqual(payload["vmcore_path"], "/var/crash/vmcore")
        self.assertEqual(payload["vmlinux_path"], "/boot/vmlinux")

    def test_build_tool_payload_success_list_args(self):
        state = {"vmcore_path": "/tmp/vmcore", "vmlinux_path": "/tmp/vmlinux"}
        payload = build_tool_payload("analyze_cpu_lockup_rcu", ["--cpus", "0,1"], state)
        self.assertEqual(payload["command"], "--cpus 0,1")

    def test_build_tool_payload_success_none_args(self):
        state = {"vmcore_path": "/tmp/vmcore", "vmlinux_path": "/tmp/vmlinux"}
        payload = build_tool_payload("analyze_cpu_lockup_rcu", None, state)
        self.assertEqual(payload["command"], "")

    def test_build_tool_payload_missing_state_keys(self):
        with self.assertRaises(ValueError) as ctx:
            build_tool_payload("analyze_lock_wait_graph", "", {"vmcore_path": "/tmp/vmcore"})
        self.assertIn("vmlinux_path", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            build_tool_payload("analyze_lock_wait_graph", "", {})
        self.assertIn("requires vmcore_path and vmlinux_path", str(ctx.exception))

    def test_build_tool_payload_unsupported_tool(self):
        state = {"vmcore_path": "/tmp/vmcore", "vmlinux_path": "/tmp/vmlinux"}
        with self.assertRaises(ValueError) as ctx:
            build_tool_payload("non_existent_tool", "", state)
        self.assertIn("Unsupported lock_hang tool", str(ctx.exception))


class LockHangServerSchemaTests(unittest.TestCase):
    """Guards the FastMCP tool schema that merely importing older versions broke.

    FastMCP rebuilds a pydantic model from each tool signature, so a parameter
    declared with ``Field(default=...)`` before a required one raises
    ``SchemaError: Non-default argument ... follows default argument``. The
    process then serves zero tools while every analyzer test still passes.
    """

    EXPECTED = {"analyze_lock_wait_graph", "analyze_cpu_lockup_rcu"}

    @classmethod
    def setUpClass(cls):
        from src.mcp_tools.lock_hang import server as server_module

        cls.server = server_module.lock_hang_server

    def test_server_registers_both_tools(self):
        tools = asyncio.run(self.server.get_tools())
        self.assertEqual(set(tools), self.EXPECTED)

    def test_tools_expose_vmcore_and_vmlinux_paths(self):
        tools = asyncio.run(self.server.get_tools())
        for name in sorted(self.EXPECTED):
            params = tools[name].parameters.get("properties", {})
            self.assertIn("command", params, name)
            self.assertIn("vmcore_path", params, name)
            self.assertIn("vmlinux_path", params, name)



class LockHangStructuredParameterTests(unittest.TestCase):
    """action.parameters（dict）必须完整转换为 CLI 参数，且不能静默丢弃。"""

    STATE = {"vmcore_path": "/tmp/vmcore", "vmlinux_path": "/tmp/vmlinux"}

    def _cmd(self, tool, params):
        return build_tool_payload(tool, params, self.STATE)["command"]

    def test_rcu_pids_parameter_reaches_the_analyzer(self):
        # 回归：本次事故中 {"rcu_pids": "309547,309548"} 被转换成了空 command
        from src.mcp_tools.lock_hang.analyzer import parse_cpu_lockup_command

        cmd = self._cmd("analyze_cpu_lockup_rcu", {"rcu_pids": "309547,309548"})
        self.assertEqual(cmd, "--rcu-pids 309547,309548")
        self.assertEqual(parse_cpu_lockup_command(cmd).rcu_pids, [309547, 309548])

    def test_list_values_and_spaced_strings_are_normalized(self):
        from src.mcp_tools.lock_hang.analyzer import parse_cpu_lockup_command

        for value in ([309547, 309548], "309547, 309548", "309547 309548"):
            with self.subTest(value=value):
                cmd = self._cmd("analyze_cpu_lockup_rcu", {"rcu_pids": value, "cpus": "6, 7"})
                opts = parse_cpu_lockup_command(cmd)
                self.assertEqual(opts.rcu_pids, [309547, 309548])
                self.assertEqual(opts.cpus, [6, 7])

    def test_hyphenated_key_and_bool_flag(self):
        from src.mcp_tools.lock_hang.analyzer import parse_cpu_lockup_command

        cmd = self._cmd("analyze_cpu_lockup_rcu", {"rcu-pids": "1", "include_idle": True})
        self.assertTrue(parse_cpu_lockup_command(cmd).include_idle)
        cmd = self._cmd("analyze_cpu_lockup_rcu", {"include_idle": "false"})
        self.assertEqual(cmd, "")

    def test_wait_graph_parameters_and_command_merge(self):
        from src.mcp_tools.lock_hang.analyzer import parse_lock_wait_graph_command

        cmd = self._cmd(
            "analyze_lock_wait_graph",
            {
                "command": "--top 5",
                "pids": [11, 22],
                "max_depth": 3,
                "lock_addr": "0xffff9b29cc4a42c0",
                "lock_type": "rwsem",
            },
        )
        opts = parse_lock_wait_graph_command(cmd)
        self.assertTrue(cmd.startswith("--top 5 "))
        self.assertEqual(opts.top, 5)
        self.assertEqual(opts.pids, [11, 22])
        self.assertEqual(opts.max_depth, 3)
        self.assertEqual(opts.lock_type, "rwsem")

    def test_unknown_or_cross_tool_keys_are_rejected(self):
        cases = (
            ("analyze_lock_wait_graph", {"rcu_pids": "1"}),
            ("analyze_cpu_lockup_rcu", {"top": 5}),
            ("analyze_cpu_lockup_rcu", {"pid": "1"}),
        )
        for tool, params in cases:
            with self.subTest(tool=tool, params=params):
                with self.assertRaises(ValueError) as ctx:
                    build_tool_payload(tool, params, self.STATE)
                self.assertIn("allowed", str(ctx.exception))

    def test_scalar_parameter_rejects_list(self):
        with self.assertRaises(ValueError):
            build_tool_payload("analyze_lock_wait_graph", {"top": [1, 2]}, self.STATE)


class LockHangCommandPrecheckTests(unittest.TestCase):
    """非法选项无论来自 arguments、command 还是 parameters，都要在派发前被拦下。"""

    STATE = {"vmcore_path": "/tmp/vmcore", "vmlinux_path": "/tmp/vmlinux"}

    def test_arguments_list_with_foreign_option_is_rejected(self):
        # 回归：2026-11-27 21:25 的运行里模型写了
        # arguments=["--rcu-pids", "309547,309548", "--top", "12"]，--top 一直传到了分析器
        with self.assertRaises(ValueError) as ctx:
            build_tool_payload(
                "analyze_cpu_lockup_rcu",
                ["--rcu-pids", "309547,309548", "--top", "12"],
                self.STATE,
            )
        message = str(ctx.exception)
        self.assertIn("--top", message)
        self.assertIn("--rcu-pids", message)
        self.assertIn("Accepted options are exactly", message)

    def test_command_string_with_foreign_option_is_rejected(self):
        with self.assertRaises(ValueError):
            build_tool_payload(
                "analyze_cpu_lockup_rcu", {"command": "--rcu-pids 1 --top 12"}, self.STATE
            )
        with self.assertRaises(ValueError):
            build_tool_payload("analyze_lock_wait_graph", "--rcu-pids 1", self.STATE)

    def test_malformed_values_are_rejected(self):
        for tool, cmd in (
            ("analyze_lock_wait_graph", "--top"),
            ("analyze_lock_wait_graph", "--top many"),
            ("analyze_lock_wait_graph", "--lock-addr 0x1 --lock-type spin"),
            ("analyze_cpu_lockup_rcu", "--rcu-pids 'unterminated"),
        ):
            with self.subTest(tool=tool, cmd=cmd):
                with self.assertRaises(ValueError):
                    build_tool_payload(tool, cmd, self.STATE)

    def test_valid_commands_still_pass(self):
        payload = build_tool_payload(
            "analyze_cpu_lockup_rcu", ["--rcu-pids", "309547,309548"], self.STATE
        )
        self.assertEqual(payload["command"], "--rcu-pids 309547,309548")
        payload = build_tool_payload(
            "analyze_lock_wait_graph", {"command": "--top 12 --max-depth 6"}, self.STATE
        )
        self.assertEqual(payload["command"], "--top 12 --max-depth 6")



class LockHangServerErrorPrefixTests(unittest.TestCase):
    """analyzer 内部异常转成文本返回时，必须带 [error] 前缀，与执行器的统一约定一致。"""

    CASES = (
        ("analyze_lock_wait_graph", "_analyze_lock_wait_graph_impl", "[error] Failed to analyze lock wait graph: "),
        ("analyze_cpu_lockup_rcu", "_analyze_cpu_lockup_rcu_impl", "[error] Failed to analyze CPU lockup / RCU state: "),
    )

    def test_failures_are_reported_with_error_prefix(self):
        from unittest import mock

        from src.mcp_tools.lock_hang import server as server_module

        tools = asyncio.run(server_module.lock_hang_server.get_tools())
        for tool_name, impl_name, prefix in self.CASES:
            with self.subTest(tool=tool_name):
                with mock.patch.object(server_module, impl_name, side_effect=RuntimeError("boom")):
                    result = tools[tool_name].fn(command="", vmcore_path="/v", vmlinux_path="/l")
                self.assertEqual(result, prefix + "boom")


if __name__ == "__main__":
    unittest.main()
