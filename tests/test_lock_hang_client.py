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


if __name__ == "__main__":
    unittest.main()
