#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# analyzer.py - Lock Hang 分析核心实现
# Author: CalmWU
# Created: 2026-11-22

"""Deterministic Linux kernel lock-wait-graph, deadlock, lockup, and RCU stall analyzer.

设计原则：
1. 尽量使用 run_crash_script 批量合并多条 crash 命令，减少冷启动开销；
2. 在 Python 侧完成内核锁结构（mutex/rw_semaphore）的位掩码解码、owner 链追踪、
   Wait-For Graph 构建与 DFS 死锁环检测；
3. 输出紧凑、结构化的 JSON，避免百核机器的 bt -a / ps 原始文本撑爆 LLM 上下文窗口。
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterator, Optional, TypedDict

from src.mcp_tools.crash.executor import run_crash_command, run_crash_script

# Linux 内核 mutex.owner / rw_semaphore.owner 低 3 位为标志位：
#   mutex:  MUTEX_FLAG_WAITERS(0x01), MUTEX_FLAG_HANDOFF(0x02), MUTEX_FLAG_PICKUP(0x04)
#   rwsem:  RWSEM_READER_OWNED(0x01), RWSEM_RD_NONSPINNABLE(0x02), RWSEM_WR_NONSPINNABLE(0x04)
LOCK_OWNER_FLAG_MASK = 0x7
LOCK_OWNER_TASK_MASK = ~LOCK_OWNER_FLAG_MASK
RWSEM_READER_OWNED_BIT = 0x1

# 正则模式
_PS_LINE_RE = re.compile(r"""
    ^\s*(?P<active>>)?          # 可选的 ">" 活跃任务标记
    \s*(?P<pid>\d+)             # PID
    \s+(?P<ppid>\d+)            # 父进程 PID
    \s+(?P<cpu>\d+)             # CPU 编号
    \s+(?P<task>[0-9a-fA-F]+)   # task_struct 地址（十六进制）
    \s+(?P<state>[A-Z]{2})      # 任务状态（UN / IN / RU 等）
    \s+\S+\s+\d+\s+\d+          # 优先级、nice 值等（跳过）
    \s+(?P<comm>.+?)\s*$        # 命令名
""", re.VERBOSE)
_PS_M_LINE_RE = re.compile(r"""
    ^\s*\[(?P<age>[^\]]+)\]     # [阻塞时长]，如 "0 00:05:12.100"
    \s+\[(?P<state>[A-Z]{2})\]  # [任务状态]
    \s+PID:\s+(?P<pid>\d+)      # PID
    \s+TASK:\s+(?P<task>[0-9a-fA-F]+)   # task_struct 地址
    \s+CPU:\s+(?P<cpu>\d+)      # CPU 编号
    \s+COMMAND:\s+\"(?P<comm>[^\"]+)\"  # 命令名（双引号包裹）
""", re.VERBOSE)
_BT_HEADER_RE = re.compile(r"""
    ^PID:\s+(?P<pid>\d+)        # PID
    \s+TASK:\s+(?P<task>[0-9a-fA-F]+)   # task_struct 地址
    \s+CPU:\s+(?P<cpu>\d+)      # CPU 编号
    \s+COMMAND:\s+\"(?P<comm>[^\"]+)\"  # 命令名
""", re.VERBOSE)
_BT_FRAME_RE = re.compile(r"""
    ^\s*\#(?P<num>\d+)          # 帧序号
    \s+\[(?P<frame>[0-9a-fA-F]+)\]  # 帧地址
    \s+(?P<func>\S+)            # 函数名
    \s+at\s+(?P<rip>[0-9a-fA-F]+)   # 指令指针地址
""", re.VERBOSE)
_BT_EXCEPTION_RE = re.compile(r"^\s*\[exception RIP:\s+(?P<func>[^,\]]+)")
_STACK_WORD_RE = re.compile(r"\b(ffff[0-9a-fA-F]{12})\b")
_OWNER_COUNTER_RE = re.compile(r"counter\s*=\s*(?P<val>-?(?:0x)?[0-9a-fA-F]+)")
_OWNER_DIRECT_RE = re.compile(r"owner\s*=\s*(?P<val>(?:0x)?[0-9a-fA-F]+)")
_STRUCT_PID_RE = re.compile(r"\bpid\s*=\s*(?P<pid>\d+)")
_STRUCT_COMM_RE = re.compile(r'\bcomm\s*=\s*"(?P<comm>[^"]+)"')
_STRUCT_STATE_RE = re.compile(r"\b(?:__)?state\s*=\s*(?P<state>\d+)")
_WAIT_LIST_ADDR_RE = re.compile(r"wait_list\s*=\s*\{[^}]*next\s*=\s*(?P<next>0x[0-9a-fA-F]+)")
_RUNQ_CPU_RE = re.compile(r"^CPU\s+(?P<cpu>\d+):\s+RUNQUEUE:\s+(?P<rq>[0-9a-fA-F]+)")
_RUNQ_CURR_RE = re.compile(
    r"CURRENT:\s+PID:\s+(?P<pid>\d+)\s+TASK:\s+(?P<task>[0-9a-fA-F]+)\s+COMMAND:\s+\"(?P<comm>[^\"]+)\""
)
_RCU_FIELD_RE = re.compile(
    r"\b(?P<name>gp_seq|completed|gpnum|gp_state|gp_kthread|jiffies_stall|n_force_qs)\s*=\s*(?P<val>(?:0x)?-?[0-9a-fA-F]+)"
)
_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")

# 等待原语分类关键字
_MUTEX_FUNCS = (
    "__mutex_lock",
    "__mutex_lock_slowpath",
    "mutex_lock",
    "mutex_lock_interruptible",
    "mutex_lock_killable",
    "mutex_lock_nested",
)
_RWSEM_FUNCS = (
    "rwsem_down_write_slowpath",
    "rwsem_down_read_slowpath",
    "__down_write",
    "__down_read",
    "down_write",
    "down_read",
    "down_write_killable",
    "down_read_killable",
)
_SPINLOCK_FUNCS = (
    "native_queued_spin_lock_slowpath",
    "queued_spin_lock_slowpath",
    "osq_lock",
    "_raw_spin_lock",
    "_raw_spin_lock_irqsave",
    "_raw_spin_lock_irq",
    "_raw_spin_lock_bh",
    "queued_write_lock_slowpath",
    "queued_read_lock_slowpath",
)
_IO_WAIT_FUNCS = (
    "io_schedule",
    "io_schedule_timeout",
    "wait_on_page_bit",
    "folio_wait_bit",
    "blk_mq_get_tag",
    "submit_bio_wait",
    "rq_qos_throttle",
)
# 真正代表软中断执行或看门狗/RCU停顿检测的原语
_SOFTIRQ_OR_STALL_FUNCS = (
    "__do_softirq",
    "do_softirq",
    "watchdog_timer_fn",
    "watchdog_overflow_callback",
    "rcu_dump_cpu_stacks",
)
# 底层硬件中断与 NMI 入口/出口跳板（不作为等待原语参与 wait_category 分类）
_HARDIRQ_ENTRY_FUNCS = (
    "asm_common_interrupt",
    "common_interrupt",
    "irq_exit",
    "nmi_handle",
)
_IDLE_FUNCS = (
    "cpu_idle",
    "do_idle",
    "default_idle",
    "intel_idle",
    "acpi_idle_enter",
    "cpuidle_enter_state",
    "arch_cpu_idle",
)

# 复合常量与单一事实来源
_LOCK_FUNC_PREFIXES = (*_MUTEX_FUNCS, *_RWSEM_FUNCS)

_CLASSIFY_PRIORITY = (
    ("mutex", _MUTEX_FUNCS),
    ("rwsem", _RWSEM_FUNCS),
    ("spinlock", _SPINLOCK_FUNCS),
    ("io_wait", _IO_WAIT_FUNCS),
    ("irq_softirq", _SOFTIRQ_OR_STALL_FUNCS),
)


@dataclass
class TaskSummary:
    pid: int
    task_addr: int
    cpu: int
    state: str
    comm: str
    age: Optional[str] = None


@dataclass
class BtFrame:
    num: int
    frame_addr: int
    function: str
    rip: int


@dataclass
class ParsedBacktrace:
    pid: int
    task_addr: int
    cpu: int
    comm: str
    frames: list[BtFrame] = field(default_factory=list)
    wait_category: str = "other"
    wait_function: Optional[str] = None
    candidate_lock_addrs: list[int] = field(default_factory=list)
    exception_rips: list[str] = field(default_factory=list)


@dataclass
class WaitEdge:
    waiter_pid: int
    waiter_comm: str
    waiter_task: str
    lock_type: str
    lock_addr: str
    owner_pid: Optional[int]
    owner_comm: Optional[str]
    owner_task: Optional[str]
    owner_flags: int
    reader_owned: bool = False
    resolution_note: str = ""


@dataclass
class LockWaitGraphOptions:
    pids: list[int] = field(default_factory=list)
    top: int = 12
    max_depth: int = 6
    lock_addr: Optional[int] = None
    lock_type: Optional[str] = None


@dataclass
class CpuLockupOptions:
    cpus: list[int] = field(default_factory=list)
    include_idle: bool = False


def parse_lock_wait_graph_command(command: str) -> LockWaitGraphOptions:
    """解析 analyze_lock_wait_graph 的命令行参数。"""
    opts = LockWaitGraphOptions()
    tokens = shlex.split(command or "")
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--pids":
            idx += 1
            raw = _require_arg(tokens, idx, tok)
            opts.pids = [int(p.strip()) for p in raw.split(",") if p.strip()]
        elif tok == "--top":
            idx += 1
            opts.top = max(1, min(64, int(_require_arg(tokens, idx, tok))))
        elif tok == "--max-depth":
            idx += 1
            opts.max_depth = max(1, min(16, int(_require_arg(tokens, idx, tok))))
        elif tok == "--lock-addr":
            idx += 1
            opts.lock_addr = _parse_hex(_require_arg(tokens, idx, tok))
        elif tok == "--lock-type":
            idx += 1
            ltype = _require_arg(tokens, idx, tok).lower()
            if ltype not in {"mutex", "rwsem"}:
                raise ValueError("--lock-type must be 'mutex' or 'rwsem'")
            opts.lock_type = ltype
        else:
            raise ValueError(f"Unsupported option for analyze_lock_wait_graph: {tok}")
        idx += 1

    if opts.lock_addr is not None and opts.lock_type is None:
        opts.lock_type = "mutex"
    return opts


def parse_cpu_lockup_command(command: str) -> CpuLockupOptions:
    """解析 analyze_cpu_lockup_rcu 的命令行参数。"""
    opts = CpuLockupOptions()
    tokens = shlex.split(command or "")
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--cpus":
            idx += 1
            raw = _require_arg(tokens, idx, tok)
            opts.cpus = [int(c.strip()) for c in raw.split(",") if c.strip()]
        elif tok == "--include-idle":
            opts.include_idle = True
        else:
            raise ValueError(f"Unsupported option for analyze_cpu_lockup_rcu: {tok}")
        idx += 1
    return opts


def parse_ps_tasks(ps_output: str) -> list[TaskSummary]:
    """解析 `ps -m` 或 `ps` 输出为任务摘要列表。"""
    tasks: list[TaskSummary] = []
    for line in ps_output.splitlines():
        m_age = _PS_M_LINE_RE.match(line)
        if m_age:
            tasks.append(
                TaskSummary(
                    pid=int(m_age.group("pid")),
                    task_addr=int(m_age.group("task"), 16),
                    cpu=int(m_age.group("cpu")),
                    state=m_age.group("state"),
                    comm=m_age.group("comm"),
                    age=m_age.group("age").strip(),
                )
            )
            continue
        m_std = _PS_LINE_RE.match(line)
        if m_std:
            tasks.append(
                TaskSummary(
                    pid=int(m_std.group("pid")),
                    task_addr=int(m_std.group("task"), 16),
                    cpu=int(m_std.group("cpu")),
                    state=m_std.group("state"),
                    comm=m_std.group("comm").strip(),
                )
            )
    return tasks


def parse_multi_bt(bt_output: str) -> list[ParsedBacktrace]:
    """解析单个或多个连续 `bt` / `bt -f` / `bt -a` 输出块。"""
    results: list[ParsedBacktrace] = []
    current: Optional[ParsedBacktrace] = None
    in_lock_frame_zone = False

    for line in bt_output.splitlines():
        header_match = _BT_HEADER_RE.match(line.strip())
        if header_match:
            if current is not None:
                _classify_backtrace(current)
                results.append(current)
            current = ParsedBacktrace(
                pid=int(header_match.group("pid")),
                task_addr=int(header_match.group("task"), 16),
                cpu=int(header_match.group("cpu")),
                comm=header_match.group("comm"),
            )
            in_lock_frame_zone = False
            continue

        if current is None:
            continue

        exc_match = _BT_EXCEPTION_RE.match(line)
        if exc_match:
            current.exception_rips.append(exc_match.group("func").strip())
            continue

        frame_match = _BT_FRAME_RE.match(line)
        if frame_match:
            func = frame_match.group("func")
            frame = BtFrame(
                num=int(frame_match.group("num")),
                frame_addr=int(frame_match.group("frame"), 16),
                function=func,
                rip=int(frame_match.group("rip"), 16),
            )
            current.frames.append(frame)
            in_lock_frame_zone = _is_lock_frame(func)
            continue

        # 在 `bt -f` 的锁帧栈槽中提取可能的内核对象指针（高半区 canonical 地址）
        if in_lock_frame_zone:
            for hex_word in _STACK_WORD_RE.findall(line):
                addr = int(hex_word, 16)
                # 排除明显的文本段地址（通常 >= 0xffffffff80000000）以及当前栈帧附近地址
                if addr >= 0xFFFFFFFF80000000:
                    continue
                if current.frames and abs(addr - current.frames[0].frame_addr) < 0x4000:
                    continue
                if addr not in current.candidate_lock_addrs:
                    current.candidate_lock_addrs.append(addr)

    if current is not None:
        _classify_backtrace(current)
        results.append(current)
    return results


def decode_lock_owner_word(raw_owner: int, lock_type: str) -> tuple[Optional[int], int, bool]:
    """解码 Linux mutex.owner / rw_semaphore.owner 原子字。

    Returns:
        (owner_task_addr_or_None, flags, reader_owned)
    """
    if raw_owner <= 0:
        return None, 0, False

    flags = raw_owner & LOCK_OWNER_FLAG_MASK
    reader_owned = bool(lock_type == "rwsem" and (flags & RWSEM_READER_OWNED_BIT))
    task_addr = raw_owner & LOCK_OWNER_TASK_MASK
    # 校验是否为合法的 64 位内核直接映射/vmalloc 地址
    if task_addr < 0xFFFF800000000000 or task_addr >= 0xFFFFFFFF80000000:
        return None, flags, reader_owned
    return task_addr, flags, reader_owned


def parse_struct_lock_owner(struct_output: str, lock_type: str) -> tuple[Optional[int], int, bool]:
    """从 `struct mutex.owner <addr>` 或 `struct rw_semaphore.owner <addr>` 输出解析 owner。"""
    m = _OWNER_COUNTER_RE.search(struct_output)
    if not m:
        m = _OWNER_DIRECT_RE.search(struct_output)
    if not m:
        return None, 0, False

    val_str = m.group("val")
    try:
        raw_val = int(val_str, 0)
    except ValueError:
        raw_val = int(val_str, 16)

    # 兼容有符号 64 位负整数输出（某些 crash 版本对 atomic_long_t 打印十进制负数）
    if raw_val < 0:
        raw_val &= (1 << 64) - 1

    return decode_lock_owner_word(raw_val, lock_type)


def parse_task_struct_brief(struct_output: str, task_addr: int) -> Optional[TaskSummary]:
    """从 `struct task_struct.pid,comm,__state <addr>` 输出解析任务摘要。"""
    pid_m = _STRUCT_PID_RE.search(struct_output)
    comm_m = _STRUCT_COMM_RE.search(struct_output)
    if not pid_m or not comm_m:
        return None
    state_m = _STRUCT_STATE_RE.search(struct_output)
    state_num = int(state_m.group("state")) if state_m else -1
    state_str = {0: "RU", 1: "IN", 2: "UN"}.get(state_num, f"S{state_num}")
    return TaskSummary(
        pid=int(pid_m.group("pid")),
        task_addr=task_addr,
        cpu=-1,
        state=state_str,
        comm=comm_m.group("comm"),
    )


def detect_wait_cycles(edges: list[WaitEdge]) -> list[list[int]]:
    """在 Wait-For Graph（waiter_pid -> owner_pid）上执行确定性迭代 DFS 环检测。

    使用显式调用栈替代递归，避免百核机器上 UN 状态任务数量过多导致
    Python 递归深度超限（默认 1000 层）而抛出 RecursionError。
    """
    adj: dict[int, list[int]] = {}
    for edge in edges:
        if edge.owner_pid is not None:
            adj.setdefault(edge.waiter_pid, []).append(edge.owner_pid)

    visited: set[int] = set()
    # pos_in_stack 同时充当 in_stack 成员检测（O(1)）和环起点位置索引（O(1)），
    # 替代原先 set + list.index() 的组合，将记环查找从 O(V) 降到 O(1)。
    pos_in_stack: dict[int, int] = {}
    stack: list[int] = []
    cycles: list[list[int]] = []
    seen_canonical: set[tuple[int, ...]] = set()

    def _record_cycle(nxt: int) -> None:
        idx = pos_in_stack[nxt]
        cycle = stack[idx:] + [nxt]
        # 归一化去重（以环内最小 PID 为起点）
        core = cycle[:-1]
        min_pos = core.index(min(core))
        canonical = tuple(core[min_pos:] + core[:min_pos])
        if canonical not in seen_canonical:
            seen_canonical.add(canonical)
            cycles.append(list(canonical) + [canonical[0]])

    for start_node in sorted(adj):
        if start_node in visited:
            continue
        # 显式调用栈：每个元素为 (node, neighbor_iterator)
        call_stack: list[tuple[int, Iterator[int]]] = []
        visited.add(start_node)
        pos_in_stack[start_node] = len(stack)
        stack.append(start_node)
        call_stack.append((start_node, iter(adj.get(start_node, []))))

        while call_stack:
            _node, neighbors = call_stack[-1]
            nxt = next(neighbors, None)
            if nxt is None:
                # 当前节点的所有邻居都已处理完毕，回溯
                call_stack.pop()
                stack.pop()
                del pos_in_stack[_node]
                continue
            if nxt in pos_in_stack:
                _record_cycle(nxt)
            elif nxt not in visited:
                visited.add(nxt)
                pos_in_stack[nxt] = len(stack)
                stack.append(nxt)
                call_stack.append((nxt, iter(adj.get(nxt, []))))

    return cycles


def find_root_blockers(edges: list[WaitEdge]) -> list[dict[str, object]]:
    """找出等待链末端（持有锁且本身未等待其他已知锁）的根阻塞任务。"""
    waiters = {edge.waiter_pid for edge in edges}
    blockers: dict[int, dict[str, object]] = {}
    blocker_waiters: dict[int, list[int]] = {}
    blocker_locks: dict[int, list[str]] = {}

    for edge in edges:
        if edge.owner_pid is None or edge.owner_pid in waiters:
            continue

        owner_pid = edge.owner_pid
        if owner_pid not in blockers:
            blocked_waiter_pids: list[int] = []
            held_locks: list[str] = []
            blocker_waiters[owner_pid] = blocked_waiter_pids
            blocker_locks[owner_pid] = held_locks
            blockers[owner_pid] = {
                "pid": owner_pid,
                "comm": edge.owner_comm,
                "task_addr": edge.owner_task,
                "blocked_waiter_pids": blocked_waiter_pids,
                "held_locks": held_locks,
            }

        blocked_waiter_pids = blocker_waiters[owner_pid]
        if edge.waiter_pid not in blocked_waiter_pids:
            blocked_waiter_pids.append(edge.waiter_pid)

        held_locks = blocker_locks[owner_pid]
        lock_desc = f"{edge.lock_type}@{edge.lock_addr}"
        if lock_desc not in held_locks:
            held_locks.append(lock_desc)

    return [
        blockers[owner_pid]
        for owner_pid in sorted(
            blockers,
            key=lambda pid: len(blocker_waiters[pid]),
            reverse=True,
        )
    ]


def analyze_lock_wait_graph(
    vmcore_path: str,
    vmlinux_path: str,
    command: str = "",
    *,
    crash_runner: Callable[[str, str, str, bool], str] = run_crash_command,
    script_runner: Callable[[str, str, str, bool], str] = run_crash_script,
) -> str:
    """构建确定性锁等待依赖图并返回紧凑 JSON 报告。"""
    opts = parse_lock_wait_graph_command(command)

    # 1. 显式指定了单个锁地址时，直接解码该锁 owner 并追踪其调用栈
    if opts.lock_addr is not None:
        return _analyze_single_lock(
            vmcore_path,
            vmlinux_path,
            opts.lock_addr,
            opts.lock_type or "mutex",
            crash_runner=crash_runner,
        )

    # 2. 获取任务列表（优先 ps -m 按阻塞时长排序）
    ps_output = crash_runner("ps -m", vmcore_path, vmlinux_path, False)
    all_tasks = parse_ps_tasks(ps_output)
    task_by_pid = {t.pid: t for t in all_tasks}
    task_by_addr = {t.task_addr: t for t in all_tasks}

    if opts.pids:
        target_pids = [pid for pid in opts.pids if pid in task_by_pid] or opts.pids
    else:
        un_tasks = [t for t in all_tasks if t.state == "UN"]
        # ps -m 默认按等待时间降序排列，取最久阻塞的 top N 个 UN 任务
        target_pids = [t.pid for t in un_tasks[: opts.top]]

    if not target_pids:
        return json.dumps(
            {
                "status": "no_uninterruptible_tasks",
                "total_tasks_scanned": len(all_tasks),
                "message": "No UN-state or matching target tasks found in vmcore.",
            },
            indent=2,
            ensure_ascii=False,
        )

    # 3. 批量采集目标任务的 bt -f，减少 crash 进程启动次数
    bt_script = "\n".join(f"bt -f {pid}" for pid in target_pids)
    bt_output = script_runner(bt_script, vmcore_path, vmlinux_path, False)
    parsed_bts = parse_multi_bt(bt_output)

    edges: list[WaitEdge] = []
    unresolved_waiters: list[dict[str, object]] = []
    category_counts: dict[str, int] = {}
    visited_owner_pids: set[int] = set(target_pids)
    owner_frontier: list[int] = []

    for bt in parsed_bts:
        category_counts[bt.wait_category] = category_counts.get(bt.wait_category, 0) + 1
        if bt.wait_category not in {"mutex", "rwsem"}:
            unresolved_waiters.append(
                {
                    "pid": bt.pid,
                    "comm": bt.comm,
                    "wait_category": bt.wait_category,
                    "wait_function": bt.wait_function,
                    "top_frames": [f.function for f in bt.frames[:6]],
                }
            )
            continue

        edge = _resolve_lock_edge_for_bt(
            bt,
            task_by_addr=task_by_addr,
            vmcore_path=vmcore_path,
            vmlinux_path=vmlinux_path,
            crash_runner=crash_runner,
            script_runner=script_runner,
        )
        if edge is not None:
            edges.append(edge)
            if edge.owner_pid is not None and edge.owner_pid not in visited_owner_pids:
                visited_owner_pids.add(edge.owner_pid)
                owner_frontier.append(edge.owner_pid)
        else:
            unresolved_waiters.append(
                {
                    "pid": bt.pid,
                    "comm": bt.comm,
                    "wait_category": bt.wait_category,
                    "wait_function": bt.wait_function,
                    "candidate_lock_addrs": [hex(a) for a in bt.candidate_lock_addrs[:4]],
                    "note": "Could not mechanically confirm mutex/rwsem owner from stack slots; inspect with dis/bt -f.",
                }
            )

    # 4. 沿 owner 链递归向下追踪，直到命中环或根阻塞任务
    depth = 1
    while owner_frontier and depth < opts.max_depth:
        next_script = "\n".join(f"bt -f {pid}" for pid in owner_frontier)
        next_bt_out = script_runner(next_script, vmcore_path, vmlinux_path, False)
        next_bts = parse_multi_bt(next_bt_out)
        owner_frontier = []
        for bt in next_bts:
            if bt.wait_category not in {"mutex", "rwsem"}:
                continue
            edge = _resolve_lock_edge_for_bt(
                bt,
                task_by_addr=task_by_addr,
                vmcore_path=vmcore_path,
                vmlinux_path=vmlinux_path,
                crash_runner=crash_runner,
                script_runner=script_runner,
            )
            if edge is not None:
                edges.append(edge)
                if edge.owner_pid is not None and edge.owner_pid not in visited_owner_pids:
                    visited_owner_pids.add(edge.owner_pid)
                    owner_frontier.append(edge.owner_pid)
        depth += 1

    cycles = detect_wait_cycles(edges)
    root_blockers = find_root_blockers(edges)

    recommended = []
    for cycle in cycles[:2]:
        recommended.append(f"bt {' '.join(str(p) for p in cycle[:-1])}")
    for blocker in root_blockers[:3]:
        recommended.append(f"bt {blocker['pid']}")

    result = {
        "status": "deadlock_detected" if cycles else "wait_graph_built",
        "tasks_analyzed": len(parsed_bts),
        "wait_category_counts": category_counts,
        "deadlock_cycles": cycles,
        "root_blockers": root_blockers,
        "wait_edges": [asdict(e) for e in edges],
        "non_sleep_lock_or_unresolved_tasks": unresolved_waiters[:10],
        "recommended_next_commands": recommended,
    }
    return json.dumps(result, indent=2, ensure_ascii=False)


class RunqCpuInfo(TypedDict):
    cpu: int
    current_pid: Optional[int]
    current_comm: Optional[str]
    queued_tasks: int


def parse_runq_summary(runq_output: str) -> dict[int, RunqCpuInfo]:
    """解析 `runq` 输出，提取各 CPU 的当前运行任务与就绪队列积压数。"""
    per_cpu: dict[int, RunqCpuInfo] = {}
    current_cpu: Optional[int] = None
    for line in runq_output.splitlines():
        m_cpu = _RUNQ_CPU_RE.match(line.strip())
        if m_cpu:
            current_cpu = int(m_cpu.group("cpu"))
            per_cpu[current_cpu] = {
                "cpu": current_cpu,
                "current_pid": None,
                "current_comm": None,
                "queued_tasks": 0,
            }
            continue
        if current_cpu is None:
            continue
        m_curr = _RUNQ_CURR_RE.search(line)
        if m_curr:
            per_cpu[current_cpu]["current_pid"] = int(m_curr.group("pid"))
            per_cpu[current_cpu]["current_comm"] = m_curr.group("comm")
            continue
        if re.match(r"^\s*\[\d+\]\s+PID:\s+\d+", line):
            per_cpu[current_cpu]["queued_tasks"] += 1
    return per_cpu


def parse_rcu_state(rcu_output: str) -> dict[str, str]:
    """解析 `p rcu_state` 输出中的关键宽限期（grace period）字段。"""
    fields: dict[str, str] = {}
    for m in _RCU_FIELD_RE.finditer(rcu_output):
        fields[m.group("name")] = m.group("val")
    return fields


def analyze_cpu_lockup_rcu(
    vmcore_path: str,
    vmlinux_path: str,
    command: str = "",
    *,
    crash_runner: Callable[[str, str, str, bool], str] = run_crash_command,
    script_runner: Callable[[str, str, str, bool], str] = run_crash_script,
) -> str:
    """聚合分析多核 Soft/Hard Lockup、Spinlock 争抢与 RCU Stall 状态。"""
    opts = parse_cpu_lockup_command(command)

    # 使用单次 run_crash_script 合并 bt -a / runq / p rcu_state，避免三次启动 crash
    bt_cmd = (
        f"bt -c {','.join(str(c) for c in opts.cpus)}"
        if opts.cpus
        else "bt -a"
    )
    marker_runq = "===LOCK_HANG_RUNQ==="
    marker_rcu = "===LOCK_HANG_RCU==="
    combined_script = "\n".join(
        [
            bt_cmd,
            f"!echo {marker_runq}",
            "runq",
            f"!echo {marker_rcu}",
            "p rcu_state",
        ]
    )
    raw = script_runner(combined_script, vmcore_path, vmlinux_path, False)

    bt_part = raw
    runq_part = ""
    rcu_part = ""
    if marker_runq in raw:
        bt_part, rest = raw.split(marker_runq, 1)
        if marker_rcu in rest:
            runq_part, rcu_part = rest.split(marker_rcu, 1)
        else:
            runq_part = rest
    elif marker_rcu in raw:
        bt_part, rcu_part = raw.split(marker_rcu, 1)

    cpu_bts = parse_multi_bt(bt_part)
    runq_info = parse_runq_summary(runq_part)
    rcu_fields = parse_rcu_state(rcu_part)

    suspected_lockup_cpus: list[dict[str, object]] = []
    spinlock_contenders: list[dict[str, object]] = []
    irq_or_softirq_cpus: list[dict[str, object]] = []
    hardirq_active_cpus: list[dict[str, object]] = []
    idle_cpu_count = 0

    for bt in cpu_bts:
        frame_funcs = [f.function for f in bt.frames]
        is_idle = any(fn in _IDLE_FUNCS for fn in frame_funcs[:6]) and not any(
            fn in _SPINLOCK_FUNCS or fn in _SOFTIRQ_OR_STALL_FUNCS for fn in frame_funcs[:8]
        )
        if is_idle:
            idle_cpu_count += 1
            if not opts.include_idle:
                continue

        rq_entry = runq_info.get(bt.cpu)
        queued_tasks = rq_entry["queued_tasks"] if rq_entry is not None else 0
        summary = {
            "cpu": bt.cpu,
            "pid": bt.pid,
            "comm": bt.comm,
            "wait_category": bt.wait_category,
            "wait_function": bt.wait_function,
            "queued_tasks": queued_tasks,
            "top_frames": frame_funcs[:8],
            "exception_rips": bt.exception_rips,
        }

        if bt.wait_category == "spinlock":
            spinlock_contenders.append(summary)
        if any(fn in _SOFTIRQ_OR_STALL_FUNCS for fn in frame_funcs[:10]):
            irq_or_softirq_cpus.append(summary)
        if not is_idle and any(fn in _HARDIRQ_ENTRY_FUNCS for fn in frame_funcs[:10]):
            hardirq_active_cpus.append(summary)
        # 仅将真正存在异常指标的 CPU 标记为 suspected lockup：
        #   - spinlock 自旋等待
        #   - watchdog / RCU stall dump 触发
        #   - 运行队列严重积压（>= 4 个就绪任务）
        #   - 非 idle 且处于 softirq/spinlock 上下文（禁用抢占或软中断执行）
        is_in_locked_context = not is_idle and any(
            fn in _SPINLOCK_FUNCS or fn in _SOFTIRQ_OR_STALL_FUNCS
            for fn in frame_funcs[:10]
        )
        if (
            bt.wait_category == "spinlock"
            or any(fn in {"watchdog_timer_fn", "watchdog_overflow_callback", "rcu_dump_cpu_stacks"} for fn in frame_funcs)
            or queued_tasks >= 4
            or is_in_locked_context
        ):
            suspected_lockup_cpus.append(summary)

    recommended = []
    if spinlock_contenders:
        recommended.append(
            f"bt -f -c {','.join(str(c['cpu']) for c in spinlock_contenders[:4])}"
        )
    if suspected_lockup_cpus:
        top_cpu = suspected_lockup_cpus[0]
        top_frames = top_cpu.get("top_frames", [])
        if isinstance(top_frames, list) and top_frames:
            recommended.append(f"dis -rl {top_frames[0]}")
        else:
            recommended.append(f"bt -c {top_cpu.get('cpu')}")
    elif not recommended and hardirq_active_cpus:
        # 兜底建议：当未检测到明显的自旋锁争抢或看门狗触发，但存在处于非 idle 硬中断上下文的活跃 CPU 时，
        # 推荐检查其调用栈与反汇编顶帧（防止硬件中断 ISR 内无锁忙等死循环导致系统挂死）
        top_irq_cpu = hardirq_active_cpus[0]
        recommended.append(
            f"bt -c {','.join(str(c['cpu']) for c in hardirq_active_cpus[:4])}"
        )
        top_frames = top_irq_cpu.get("top_frames", [])
        if isinstance(top_frames, list) and top_frames:
            recommended.append(f"dis -rl {top_frames[0]}")

    result = {
        "total_cpus_parsed": len(cpu_bts),
        "idle_cpu_count": idle_cpu_count,
        "spinlock_contender_count": len(spinlock_contenders),
        "spinlock_contenders": spinlock_contenders[:16],
        "irq_or_softirq_cpus": irq_or_softirq_cpus[:16],
        "active_or_suspected_cpus": suspected_lockup_cpus[:20],
        "rcu_state_summary": rcu_fields,
        "recommended_next_commands": recommended,
    }
    return json.dumps(result, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _analyze_single_lock(
    vmcore_path: str,
    vmlinux_path: str,
    lock_addr: int,
    lock_type: str,
    *,
    crash_runner: Callable[[str, str, str, bool], str],
) -> str:
    struct_name = "mutex" if lock_type == "mutex" else "rw_semaphore"
    raw = crash_runner(
        f"struct {struct_name}.owner {lock_addr:x}",
        vmcore_path,
        vmlinux_path,
        False,
    )
    owner_addr, flags, reader_owned = parse_struct_lock_owner(raw, lock_type)
    owner_task = None
    if owner_addr is not None:
        t_out = crash_runner(
            f"struct task_struct.pid,comm,__state {owner_addr:x}",
            vmcore_path,
            vmlinux_path,
            False,
        )
        owner_task = parse_task_struct_brief(t_out, owner_addr)

    payload = {
        "lock_type": lock_type,
        "lock_addr": hex(lock_addr),
        "owner_task_addr": hex(owner_addr) if owner_addr is not None else None,
        "owner_flags": hex(flags),
        "reader_owned": reader_owned,
        "owner_task": asdict(owner_task) if owner_task is not None else None,
        "raw_struct_owner": raw.strip(),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _resolve_lock_edge_for_bt(
    bt: ParsedBacktrace,
    *,
    task_by_addr: dict[int, TaskSummary],
    vmcore_path: str,
    vmlinux_path: str,
    crash_runner: Callable[[str, str, str, bool], str],
    script_runner: Callable[[str, str, str, bool], str],
) -> Optional[WaitEdge]:
    """从候选栈地址中筛选真实的 mutex/rw_semaphore 并解析其 owner。"""
    if not bt.candidate_lock_addrs:
        return None

    lock_type = bt.wait_category  # "mutex" or "rwsem"
    struct_name = "mutex" if lock_type == "mutex" else "rw_semaphore"
    candidates = bt.candidate_lock_addrs[:6]

    # 批量检查候选地址的 owner 字段，减少 crash 启动次数
    probe_lines = []
    for addr in candidates:
        probe_lines.append(f"!echo ===LOCK_CAND:{addr:x}===")
        probe_lines.append(f"struct {struct_name}.owner {addr:x}")
    probe_out = script_runner("\n".join(probe_lines), vmcore_path, vmlinux_path, False)

    sections = probe_out.split("===LOCK_CAND:")
    for sec in sections[1:]:
        header, _, body = sec.partition("===")
        try:
            cand_addr = int(header.strip(), 16)
        except ValueError:
            continue

        owner_addr, flags, reader_owned = parse_struct_lock_owner(body, lock_type)
        if owner_addr is None and not reader_owned:
            continue

        # 强校验：owner_addr 必须在 ps 任务表中存在（或能通过 task_struct 解析出合法 PID/comm），
        # 从而过滤掉栈上的无关指针误判。
        owner_task = task_by_addr.get(owner_addr) if owner_addr is not None else None
        if owner_task is None and owner_addr is not None:
            t_out = crash_runner(
                f"struct task_struct.pid,comm,__state {owner_addr:x}",
                vmcore_path,
                vmlinux_path,
                False,
            )
            owner_task = parse_task_struct_brief(t_out, owner_addr)

        if owner_task is not None:
            return WaitEdge(
                waiter_pid=bt.pid,
                waiter_comm=bt.comm,
                waiter_task=hex(bt.task_addr),
                lock_type=lock_type,
                lock_addr=hex(cand_addr),
                owner_pid=owner_task.pid,
                owner_comm=owner_task.comm,
                owner_task=hex(owner_task.task_addr),
                owner_flags=flags,
                reader_owned=reader_owned,
                resolution_note="verified_task_struct_owner",
            )
        if reader_owned:
            return WaitEdge(
                waiter_pid=bt.pid,
                waiter_comm=bt.comm,
                waiter_task=hex(bt.task_addr),
                lock_type=lock_type,
                lock_addr=hex(cand_addr),
                owner_pid=None,
                owner_comm=None,
                owner_task=None,
                owner_flags=flags,
                reader_owned=True,
                resolution_note="rwsem_held_by_reader_no_single_owner_task",
            )

    return None


def _is_lock_frame(func_name: str) -> bool:
    return any(func_name.startswith(p) for p in _LOCK_FUNC_PREFIXES)


def _classify_backtrace(bt: ParsedBacktrace) -> None:
    """根据栈帧函数名对等待/阻塞原语做确定性优先级分类。

    优先级由 _CLASSIFY_PRIORITY 定义：mutex > rwsem > spinlock > io_wait > irq_softirq。
    按优先级对整条调用栈进行扫描，确保即使栈顶包含看门狗或中断采样入口帧，深层的核心锁原语仍被优先提取。
    底层硬件中断/NMI 跳板（_HARDIRQ_ENTRY_FUNCS）不作为等待原语参与分类。
    """
    for category, prefixes in _CLASSIFY_PRIORITY:
        for frame in bt.frames:
            fn = frame.function
            if any(fn.startswith(p) for p in prefixes):
                bt.wait_category = category
                bt.wait_function = fn
                return


def _require_arg(tokens: list[str], index: int, flag: str) -> str:
    if index >= len(tokens):
        raise ValueError(f"Missing value for option {flag}")
    return tokens[index]


def _parse_hex(raw: str) -> int:
    token = raw.strip()
    if not _HEX_RE.match(token):
        raise ValueError(f"Invalid hexadecimal address: {raw}")
    return int(token, 16)
