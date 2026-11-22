#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# client.py - Lock Hang MCP 客户端实现
# Author: CalmWU
# Created: 2026-11-22

"""MCP client for the lock_hang provider.

遵循 src/mcp_tools/registry.py 的自动发现约定，暴露标准接口：
MCP_CLIENT、MCP_SERVER_NAME、initialize_tools、build_tool_payload。
"""

import sys
from typing import Any, List, Optional

from langchain_mcp_adapters.client import MultiServerMCPClient

from src.utils.logging import logger

MCP_SERVER_NAME = "lock_hang"

lock_hang_client = MultiServerMCPClient(
    {
        MCP_SERVER_NAME: {
            "command": sys.executable,
            "args": ["-m", "src.mcp_tools.lock_hang.server"],
            "transport": "stdio",
        }
    }
)
MCP_CLIENT = lock_hang_client

_lock_hang_tools: Optional[List] = None

_SUPPORTED_TOOLS = frozenset(
    {
        "analyze_lock_wait_graph",
        "analyze_cpu_lockup_rcu",
    }
)


async def _initialize_tools() -> List:
    global _lock_hang_tools
    if _lock_hang_tools is not None:
        return _lock_hang_tools

    try:
        logger.info("Initializing lock_hang MCP tools...")
        _lock_hang_tools = await lock_hang_client.get_tools()

        logger.info(
            "Successfully initialized %d lock_hang tools.\n\t%s",
            len(_lock_hang_tools),
            "\n\t".join(
                f"{tool.name}: {tool.description}" for tool in _lock_hang_tools
            ),
        )
        return _lock_hang_tools
    except Exception as exc:
        logger.error("Failed to initialize lock_hang tools: %s", exc)
        return []  # 不缓存空列表，_lock_hang_tools 保持 None 以允许下次重试


async def initialize_tools() -> List:
    return await _initialize_tools()


def build_tool_payload(
    tool_name: str, raw_args: Any, state: dict[str, Any]
) -> dict[str, Any]:
    if tool_name not in _SUPPORTED_TOOLS:
        raise ValueError(f"Unsupported lock_hang tool: {tool_name}")

    vmcore = state.get("vmcore_path")
    vmlinux = state.get("vmlinux_path")
    if not vmcore or not vmlinux:
        raise ValueError(
            f"lock_hang tool requires vmcore_path and vmlinux_path in state, "
            f"got vmcore_path={vmcore!r}, vmlinux_path={vmlinux!r}"
        )

    if isinstance(raw_args, dict):
        command = str(raw_args.get("command", "")).strip()
    elif isinstance(raw_args, (list, tuple)):
        command = " ".join(str(item).strip() for item in raw_args if str(item).strip())
    elif raw_args is None:
        command = ""
    else:
        command = str(raw_args).strip()

    return {
        "command": command,
        "vmcore_path": vmcore,
        "vmlinux_path": vmlinux,
    }
