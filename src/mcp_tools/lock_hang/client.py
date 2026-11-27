#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# client.py - Lock Hang MCP 客户端实现
# Author: CalmWU
# Created: 2026-11-22

"""MCP client for the lock_hang provider.

遵循 src/mcp_tools/registry.py 的自动发现约定，暴露标准接口：
MCP_CLIENT、MCP_SERVER_NAME、initialize_tools、build_tool_payload。
"""

import re
import sys
from typing import Any, List, Optional

from langchain_mcp_adapters.client import MultiServerMCPClient

from src.mcp_tools.crash.client import crash_stdio_env
from src.utils.logging import logger

MCP_SERVER_NAME = "lock_hang"

lock_hang_client = MultiServerMCPClient(
    {
        MCP_SERVER_NAME: {
            "command": sys.executable,
            "args": ["-m", "src.mcp_tools.lock_hang.server"],
            "transport": "stdio",
            "env": crash_stdio_env(),
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


# 按工具拆分的合法结构化参数映射：(flag_name, is_bool_flag)
_TOOL_PARAM_SPECS: dict[str, dict[str, tuple[str, bool]]] = {
    "analyze_lock_wait_graph": {
        "pids": ("--pids", False),
        "top": ("--top", False),
        "max_depth": ("--max-depth", False),
        "lock_addr": ("--lock-addr", False),
        "lock_type": ("--lock-type", False),
    },
    "analyze_cpu_lockup_rcu": {
        "cpus": ("--cpus", False),
        "rcu_pids": ("--rcu-pids", False),
        "include_idle": ("--include-idle", True),
    },
}
_RUNTIME_OWNED_KEYS = frozenset({"vmcore_path", "vmlinux_path", "command"})
# 取值为逗号分隔列表的参数（analyzer 侧按 "," 切分并转 int）。
_LIST_VALUED_KEYS = frozenset({"pids", "cpus", "rcu_pids"})


def _format_cli_value(key: str, val: Any) -> str:
    """把结构化取值压成单个 CLI token，保证 shlex.split 后仍是一个参数。

    列表参数统一规范成无空格的逗号串：模型常写 "309547, 309548"，若原样拼接，
    shlex 会把 "309548" 拆成多余的位置参数，analyzer 直接报 Unsupported option。
    """
    if key in _LIST_VALUED_KEYS:
        items = val if isinstance(val, (list, tuple, set)) else re.split(r"[,\s]+", str(val))
        return ",".join(str(item).strip() for item in items if str(item).strip())
    if isinstance(val, (list, tuple, set, dict)):
        raise ValueError(
            f"lock_hang parameter '{key}' takes a single value, got {type(val).__name__}"
        )
    return str(val).strip()


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
        parts: list[str] = []
        base_cmd = str(raw_args.get("command", "") or "").strip()
        if base_cmd:
            parts.append(base_cmd)

        param_specs = _TOOL_PARAM_SPECS.get(tool_name, {})
        unknown_keys: list[str] = []
        for raw_key, val in raw_args.items():
            if val is None:
                continue
            norm_key = str(raw_key).strip().lower().lstrip("-").replace("-", "_")
            if norm_key in _RUNTIME_OWNED_KEYS:
                continue
            spec = param_specs.get(norm_key)
            if spec is None:
                unknown_keys.append(str(raw_key))
                continue
            flag, is_bool = spec
            if is_bool:
                if isinstance(val, bool):
                    enabled = val
                elif isinstance(val, str):
                    enabled = val.strip().lower() in {"1", "true", "yes", "on"}
                else:
                    enabled = bool(val)
                if enabled:
                    parts.append(flag)
            else:
                formatted = _format_cli_value(norm_key, val)
                if formatted:
                    parts.append(f"{flag} {formatted}")

        if unknown_keys:
            # 不能静默丢弃：本次事故正是 rcu_pids 被丢掉后分析器跑了默认范围，
            # 模型却以为过滤已生效。抛错后 nodes 会包装成 "[error] ..." 并记为
            # tool_error，由豁免 A 给一次纠错重试。
            raise ValueError(
                f"Unknown parameter(s) {unknown_keys} for lock_hang tool '{tool_name}'; "
                f"allowed: {sorted(param_specs)}"
            )
        command = " ".join(parts).strip()
    elif isinstance(raw_args, (list, tuple)):
        command = " ".join(str(item).strip() for item in raw_args if str(item).strip())
    elif raw_args is None:
        command = ""
    else:
        command = str(raw_args).strip()

    _validate_command(tool_name, command)

    return {
        "command": command,
        "vmcore_path": vmcore,
        "vmlinux_path": vmlinux,
    }


def _validate_command(tool_name: str, command: str) -> None:
    """派发前用 analyzer 自己的解析器预检最终命令串。

    结构化 parameters 的键名校验只覆盖 dict 入参；模型照着语法示例写 `arguments`
    （或直接给 `command` 字符串）时，非法选项会一路传到 MCP server，被包装成
    "Failed to analyze ..." 文本返回。这里统一拦截：无论哪种入参形态，非法选项
    都在派发前抛 ValueError，由 nodes 记为 tool_error 并给出可用选项。
    """
    from src.mcp_tools.lock_hang.analyzer import (
        parse_cpu_lockup_command,
        parse_lock_wait_graph_command,
    )

    parser = (
        parse_lock_wait_graph_command
        if tool_name == "analyze_lock_wait_graph"
        else parse_cpu_lockup_command
    )
    try:
        parser(command)
    except ValueError as exc:
        allowed = ", ".join(flag for flag, _ in _TOOL_PARAM_SPECS[tool_name].values())
        raise ValueError(
            f"{tool_name} rejected command {command!r}: {exc}. "
            f"Accepted options are exactly: {allowed}."
        ) from exc
