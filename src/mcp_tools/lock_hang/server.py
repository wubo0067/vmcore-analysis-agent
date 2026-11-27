#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# server.py - Lock Hang MCP 服务器实现
# Author: CalmWU
# Created: 2026-11-22

"""FastMCP server exposing deterministic lock-wait-graph and CPU lockup/RCU analyzers.

Entry points:
- client.py launches this server via: `python -m src.mcp_tools.lock_hang.server`
- __main__.py provides the package-level CLI entry point: `python -m src.mcp_tools.lock_hang`
"""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from .analyzer import (
    analyze_cpu_lockup_rcu as _analyze_cpu_lockup_rcu_impl,
    analyze_lock_wait_graph as _analyze_lock_wait_graph_impl,
)

lock_hang_server = FastMCP(
    "lock_hang",
    instructions=(
        "Deterministic analyzer for Linux kernel hung tasks, AB-BA deadlocks, "
        "soft/hard lockups, and RCU stalls. Extracts mutex/rwsem wait-for graphs "
        "and per-CPU stall summaries without flooding context with raw bt -a output."
    ),
)


@lock_hang_server.tool()
def analyze_lock_wait_graph(
    command: Annotated[
        str,
        Field(
            description=(
                "Build a deterministic lock wait-for graph and detect deadlock cycles or root blockers.\n"
                "Syntax: [--pids <pid1,pid2,...>] [--top <int>] [--max-depth <int>] "
                "[--lock-addr <hex> --lock-type <mutex|rwsem>]\n"
                "Examples:\n"
                "  --top 12 --max-depth 6\n"
                "  --pids 1234,5678\n"
                "  --lock-addr ffff88810234a010 --lock-type mutex"
            ),
            default="",
        ),
    ],
    vmcore_path: Annotated[
        str, Field(description="The absolute path to the vmcore file.", default="")
    ],
    vmlinux_path: Annotated[
        str, Field(description="The absolute path to the vmlinux file.", default="")
    ],
) -> str:
    """Extract UN-state task backtraces, resolve mutex/rwsem owners, and detect deadlock cycles."""
    try:
        return _analyze_lock_wait_graph_impl(vmcore_path, vmlinux_path, command)
    except Exception as exc:
        return f"[error] Failed to analyze lock wait graph: {exc}"


@lock_hang_server.tool()
def analyze_cpu_lockup_rcu(
    command: Annotated[
        str,
        Field(
            description=(
                "Aggregate per-CPU backtraces, runq pressure, spinlock contention, RCU grace-period/sysctl state, full rcu_node tree blkd_tasks traversal, gp_kthread health, and blocked-task inspection.\n"
                "Syntax: [--cpus <cpu1,cpu2,...>] [--rcu-pids <pid1,pid2,...>] [--include-idle]\n"
                "Examples:\n"
                "  (empty string analyzes all non-idle CPUs)\n"
                "  --cpus 0,3,7\n"
                "  --rcu-pids 309547,309548"
            ),
            default="",
        ),
    ],
    vmcore_path: Annotated[
        str, Field(description="The absolute path to the vmcore file.", default="")
    ],
    vmlinux_path: Annotated[
        str, Field(description="The absolute path to the vmlinux file.", default="")
    ],
) -> str:
    """Summarize multi-CPU lockup/spinlock/IRQ/softirq states and RCU stall indicators."""
    try:
        return _analyze_cpu_lockup_rcu_impl(vmcore_path, vmlinux_path, command)
    except Exception as exc:
        return f"[error] Failed to analyze CPU lockup / RCU state: {exc}"


if __name__ == "__main__":
    lock_hang_server.run(transport="stdio", show_banner=False)
