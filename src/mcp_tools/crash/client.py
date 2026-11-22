#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# client.py - Crash MCP 客户端实现（支持 stdio 与 streamable_http 远程常驻连接）
# Author: CalmWU
# Created: 2026-01-09

import os
import sys
from typing import Any, List, Optional
from langchain_mcp_adapters.client import MultiServerMCPClient
from src.utils.logging import logger
from src.utils.crash_command import with_tool_prefix

MCP_SERVER_NAME = "crash"


def _build_mcp_server_config() -> dict[str, Any]:
    """根据环境变量构建 MCP 连接配置。

    - 未配置 CRASH_MCP_URL 时保持默认 stdio 模式；
    - 配置 CRASH_MCP_URL（如 http://127.0.0.1:8766/mcp）时连接常驻 HTTP MCP 服务，
      使多个并发客户端 / Agent Worker 共享同一个常驻 CrashSessionPool。
    """
    mcp_url = os.environ.get("CRASH_MCP_URL", "").strip()
    if mcp_url:
        transport = (
            os.environ.get("CRASH_MCP_CLIENT_TRANSPORT", "streamable_http").strip()
            or "streamable_http"
        )
        return {
            "url": mcp_url,
            "transport": transport,
        }

    return {
        "command": sys.executable,
        "args": ["-m", "src.mcp_tools.crash.server"],
        "transport": "stdio",
    }


# 初始化 MCP 客户端
crash_client = MultiServerMCPClient({MCP_SERVER_NAME: _build_mcp_server_config()})
MCP_CLIENT = crash_client

# 全局工具列表（延迟初始化）
_crash_tools: Optional[List] = None


async def _initialize_tools():
    """异步初始化工具列表"""
    global _crash_tools
    if _crash_tools is not None:
        return _crash_tools

    try:
        logger.info("Initializing crash MCP tools...")
        _crash_tools = await crash_client.get_tools()
        logger.info(
            f"Successfully initialized {len(_crash_tools)} crash tools.\n\t%s",
            "\n\t".join(f"{tool.name}: {tool.description}" for tool in _crash_tools),
        )
        return _crash_tools
    except Exception as e:
        logger.error(f"Failed to get tools from MCP client: {e}")
        _crash_tools = []
        return []


def get_crash_tools() -> List:
    """获取 crash 工具列表（同步接口）。"""
    global _crash_tools

    if _crash_tools is not None:
        return _crash_tools

    try:
        import asyncio

        asyncio.get_running_loop()
        logger.warning(
            "Cannot initialize tools synchronously in a running event loop. "
            "Please call 'await initialize_crash_tools()' explicitly in async context."
        )
        return []
    except RuntimeError:
        import asyncio

        try:
            return asyncio.run(_initialize_tools())
        except Exception as e:
            logger.error(f"Failed to run async tool initialization: {e}")
            return []


async def initialize_crash_tools() -> List:
    """异步初始化 crash 工具（推荐在 async 上下文中使用）。"""
    return await _initialize_tools()


async def initialize_tools() -> List:
    return await initialize_crash_tools()


def _build_full_crash_command(tool_name: str, raw_args: Any) -> str:
    if isinstance(raw_args, dict):
        if "command" in raw_args:
            command = str(raw_args.get("command", "")).strip()
        elif "arguments" in raw_args:
            command = " ".join(
                str(part).strip()
                for part in raw_args.get("arguments", [])
                if str(part).strip()
            )
        else:
            command = ""
    elif isinstance(raw_args, (list, tuple)):
        command = " ".join(str(part).strip() for part in raw_args if str(part).strip())
    else:
        command = str(raw_args).strip()

    if not command:
        return tool_name

    return with_tool_prefix(tool_name, command)


def build_tool_payload(
    tool_name: str, raw_args, state: dict[str, object]
) -> dict[str, object]:
    payload: dict[str, object] = {
        "vmcore_path": state["vmcore_path"],
        "vmlinux_path": state["vmlinux_path"],
    }

    if tool_name == "run_script":
        script = (
            raw_args.get("script", "") if isinstance(raw_args, dict) else str(raw_args)
        )
        payload["script"] = script
        return payload

    payload["command"] = _build_full_crash_command(tool_name, raw_args)
    return payload


crash_tools = []

logger.info(
    "Crash MCP client initialized. Call 'await initialize_crash_tools()' to load tools."
)
