#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# server.py - Crash MCP 服务器实现
# Author: CalmWU
# Created: 2026-01-09

"""
Crash MCP 服务器实现

此模块使用 FastMCP 框架创建一个 MCP 服务器，提供 crash 工具的各种子命令。
每个 crash 子命令都被注册为一个独立的 MCP 工具。
"""

from typing import Annotated
import re
from pydantic import Field
from fastmcp import FastMCP
from .executor import run_crash_command, run_crash_script
from .scsishow import run_scsishow
from src.utils.mechanics import (
    format_mechanical_analysis_summary,
    parse_int_literal,
    parse_kmem_slab_outputs,
    parse_memory_reads,
)

crash_server = FastMCP(
    "crash_server",
    instructions="This server provides crash analysis tools for Linux vmcore files.",
)


def _parse_hex_int(token: str) -> int:
    cleaned = token.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    return int(cleaned, 16)


@crash_server.tool()
def inspect_slab_object(
    command: Annotated[
        str,
        Field(
            description=(
                "The full 'inspect_slab_object' command string to execute.\n"
                "Syntax: inspect_slab_object <hex_address> [slot_size_bytes|struct_name] [module] [debug_path]\n"
                "Example: inspect_slab_object 0xff292187ae124a80 mpt3sas_adapter mpt3sas "
                "/usr/lib/debug/lib/modules/4.18.0/mpt3sas.ko.debug\n"
                "Composite helper: resolves real slab geometry from kmem -S first, then dumps the "
                "target slot plus its immediate predecessor and successor slots, optionally decodes "
                "the object with struct -o/struct <type> <addr> (pass the module name, and a "
                "custom debug_path when debuginfo is not in the default search path, to load "
                "module-private debuginfo with mod -s), and appends deterministic slab slot index "
                "& boundary calculations."
            )
        ),
    ],
    vmcore_path: Annotated[
        str, Field(description="The absolute path to the vmcore file.")
    ],
    vmlinux_path: Annotated[
        str, Field(description="The absolute path to the vmlinux file.")
    ],
) -> str:
    """
    Composite slab object & neighbor inspector (kmem -S + vtop + neighbor slot dumps + mechanical slot attribution).
    (Crash Subcommand: inspect_slab_object)
    """
    try:
        parts = [p for p in command.strip().split() if p]
        if parts and parts[0].lower() == "inspect_slab_object":
            parts = parts[1:]
        if not parts:
            return "[error] inspect_slab_object requires at least <hex_address>."
        target_addr = _parse_hex_int(parts[0])
        if len(parts) > 4:
            return (
                "[error] inspect_slab_object accepts at most "
                "<addr> [slot_size|struct_name] [module] [debug_path]."
            )
        slot_size = 128
        struct_name = ""
        module_name = ""
        debug_path = ""
        if len(parts) >= 2:
            second = parts[1]
            parsed_size = parse_int_literal(second)
            if parsed_size is not None:
                if not (16 <= parsed_size <= 4096):
                    return "[error] inspect_slab_object slot_size_bytes must be between 16 and 4096."
                slot_size = parsed_size
            elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", second):
                # Only C identifiers can be passed to `struct`; cache names such as
                # kmalloc-96 are accepted as a label but decoded via kmem instead.
                struct_name = second if re.fullmatch(r"[A-Za-z_]\w*", second) else ""
            else:
                return (
                    "[error] inspect_slab_object second argument must be "
                    "slot_size_bytes, a C struct name, or a slab cache name."
                )
        if len(parts) >= 3:
            if not re.fullmatch(r"[A-Za-z_]\w*", parts[2]):
                return "[error] inspect_slab_object third argument must be a kernel module name."
            module_name = parts[2]
        if len(parts) >= 4:
            if not re.fullmatch(r"[A-Za-z0-9_./@+-]+", parts[3]):
                return "[error] inspect_slab_object fourth argument must be a debuginfo path."
            debug_path = parts[3]

        # Phase 1: metadata only. Never dump neighbor slots before kmem tells us
        # the real object size and slot base (non power-of-two caches such as
        # kmalloc-96/192 would otherwise be read at the wrong stride).
        phase1: list[str] = []
        if module_name:
            # Module-private struct decode needs the module debuginfo in the SAME
            # crash session; every run_script is a fresh process.
            if debug_path:
                phase1.append(f"mod -s {module_name} {debug_path}")
            else:
                phase1.append(f"mod -s {module_name}")
        phase1.extend(
            [
                f"kmem -S 0x{target_addr:x}",
                f"vtop 0x{target_addr:x}",
            ]
        )
        if struct_name:
            phase1.append(f"struct -o {struct_name}")
            phase1.append(f"struct {struct_name} 0x{target_addr:x}")
        raw_output = run_crash_script(
            "\n".join(phase1), vmcore_path, vmlinux_path, True
        )
        if struct_name and "invalid data structure reference" in raw_output.lower():
            raw_output += (
                "\n[hint] struct type is module-private; pass the module name as the "
                "third argument (inspect_slab_object <addr> <type> <module>) so the "
                "tool can run mod -s in the same crash session."
            )

        # Phase 2: dump prev/current/next using the geometry parsed from phase 1.
        slab_infos = parse_kmem_slab_outputs(raw_output)
        if slab_infos:
            info = slab_infos[0]
            slot_size = info.obj_size or slot_size
            qwords = min(512, max(2, slot_size // 8))
            start = (
                info.prev_slot if info.prev_slot is not None else info.slot_address
            )
            count = min(768, qwords * (3 if info.prev_slot is not None else 2))
        else:
            aligned_addr = (
                target_addr & ~(slot_size - 1)
                if (slot_size & (slot_size - 1)) == 0
                else target_addr
            )
            start = max(0, aligned_addr - slot_size)
            qwords = max(2, slot_size // 8)
            count = qwords * 3

        slot_dump = run_crash_command(
            f"rd -x 0x{start:x} {count}", vmcore_path, vmlinux_path, True
        )
        raw_output = f"{raw_output.rstrip()}\n\n{slot_dump}"
        summary = format_mechanical_analysis_summary(
            raw_output,
            parse_memory_reads(raw_output),
            default_stride=max(16, min(slot_size, 4096)),
        )
        if summary:
            return f"{raw_output.rstrip()}\n\n{summary}"
        return raw_output
    except Exception as e:
        return f"Failed to execute inspect_slab_object: {str(e)}"


@crash_server.tool()
def compare_memory_blocks(
    command: Annotated[
        str,
        Field(
            description=(
                "The full 'compare_memory_blocks' command string to execute.\n"
                "Syntax: compare_memory_blocks <src_hex_addr> <dst_hex_addr> [qword_count] [stride_bytes]\n"
                "Example: compare_memory_blocks 0xff292187bbcd3a00 0xff292187ae124a00 32 128\n"
                "Composite helper: reads both virtual address blocks in one crash session and "
                "deterministically computes address delta, exact byte/qword match length, "
                "spanned stride-byte slots, and the exact offset + values of the first divergence."
            )
        ),
    ],
    vmcore_path: Annotated[
        str, Field(description="The absolute path to the vmcore file.")
    ],
    vmlinux_path: Annotated[
        str, Field(description="The absolute path to the vmlinux file.")
    ],
) -> str:
    """
    Read and mechanically compare two memory blocks for byte-for-byte copy correlation, constant address delta, and first divergence offset.
    (Crash Subcommand: compare_memory_blocks)
    """
    try:
        parts = [p for p in command.strip().split() if p]
        if parts and parts[0].lower() == "compare_memory_blocks":
            parts = parts[1:]
        if len(parts) < 2:
            return (
                "[error] compare_memory_blocks requires <src_hex_addr> <dst_hex_addr> [qword_count]."
            )
        src_addr = _parse_hex_int(parts[0])
        dst_addr = _parse_hex_int(parts[1])
        if len(parts) > 4:
            return (
                "[error] compare_memory_blocks accepts at most "
                "<src> <dst> [qword_count] [stride_bytes]."
            )
        qword_count = parse_int_literal(parts[2]) if len(parts) >= 3 else 32
        if qword_count is None:
            return "[error] compare_memory_blocks qword_count must be an integer."
        if not (2 <= qword_count <= 256):
            return "[error] compare_memory_blocks qword_count must be between 2 and 256."
        stride = parse_int_literal(parts[3]) if len(parts) >= 4 else 128
        if stride is None:
            return "[error] compare_memory_blocks stride_bytes must be an integer."
        if not (8 <= stride <= 4096):
            return "[error] compare_memory_blocks stride_bytes must be between 8 and 4096."
        script_lines = [
            f"rd -x 0x{src_addr:x} {qword_count}",
            f"rd -x 0x{dst_addr:x} {qword_count}",
        ]
        raw_output = run_crash_script(
            "\n".join(script_lines), vmcore_path, vmlinux_path, True
        )
        reads = parse_memory_reads(raw_output)
        summary = format_mechanical_analysis_summary(
            raw_output, reads, default_stride=stride
        )
        # Also compute direct aligned word-by-word comparison from src_addr & dst_addr start
        word_map: dict[int, int] = {}
        for r in reads:
            for idx, w in enumerate(r.words):
                word_map[r.address + idx * 8] = w
        direct_lines: list[str] = [
            f"- block_pair: src=0x{src_addr:x} dst=0x{dst_addr:x} "
            f"signed_delta={dst_addr - src_addr:+d} (abs_delta=0x{abs(dst_addr - src_addr):x}, "
            f"window={qword_count * 8}B / {qword_count} qwords)"
        ]
        matched_qwords = 0
        first_diff_byte: int | None = None
        first_diff_detail = ""
        for q in range(qword_count):
            sw = word_map.get(src_addr + q * 8)
            dw = word_map.get(dst_addr + q * 8)
            if sw is None or dw is None:
                break
            if sw == dw:
                matched_qwords += 1
            else:
                sb = (sw & ((1 << 64) - 1)).to_bytes(8, "little")
                db = (dw & ((1 << 64) - 1)).to_bytes(8, "little")
                sub = 0
                for b1, b2 in zip(sb, db):
                    if b1 == b2:
                        sub += 1
                    else:
                        break
                first_diff_byte = q * 8 + sub
                first_diff_detail = (
                    f"first_diff_at=+0x{first_diff_byte:x} ({first_diff_byte}B): "
                    f"src@0x{src_addr + q * 8:x}=0x{sw:016x} vs dst@0x{dst_addr + q * 8:x}=0x{dw:016x}"
                )
                break
        exact_prefix_bytes = (
            first_diff_byte if first_diff_byte is not None else matched_qwords * 8
        )
        direct_lines.append(
            f"- aligned_prefix_match: {exact_prefix_bytes}B (0x{exact_prefix_bytes:x}, "
            f"{matched_qwords} full qwords)"
            + (f"; {first_diff_detail}" if first_diff_detail else "; all compared qwords identical")
        )
        if summary:
            return f"{raw_output.rstrip()}\n\n{summary}\n" + "\n".join(direct_lines)
        return f"{raw_output.rstrip()}\n\n[mechanical-analysis]\n" + "\n".join(direct_lines)
    except Exception as e:
        return f"Failed to execute compare_memory_blocks: {str(e)}"


# @crash_server.tool()
# def scsishow(
#     vmcore_path: Annotated[
#         str, Field(description="The absolute path to the vmcore file.")
#     ],
#     vmlinux_path: Annotated[
#         str, Field(description="The absolute path to the vmlinux file.")
#     ],
#     kver: Annotated[
#         str, Field(description="The target kernel version (e.g., 4.18.0).")
#     ],
# ) -> str:
#     """
#     Run scsishow crash subcommand to extract SCSI subsystem properties across 3.10, 4.18, 5.14.
#     """
#     try:
#         return run_scsishow(vmcore_path, vmlinux_path, kver)
#     except Exception as e:
#         return f"Failed to execute scsishow: {str(e)}"


@crash_server.tool()
def run_script(
    script: Annotated[
        str,
        Field(
            description=(
                "The full crash script content to execute. Commands separated by newlines.\n"
                "Syntax: command1\\ncommand2\\n...\n"
                "Example: mod -s rcu_stall_mod /path/to/module.ko\\ndis -s rcu_stall_thread\\nbt"
            )
        ),
    ],
    vmcore_path: Annotated[
        str, Field(description="The absolute path to the vmcore file.")
    ],
    vmlinux_path: Annotated[
        str, Field(description="The absolute path to the vmlinux file.")
    ],
) -> str:
    """
    Execute multiple crash commands in a single session.
    Useful for executing a sequence of commands where state (like loaded modules) needs to be preserved.
    """
    try:
        return run_crash_script(script, vmcore_path, vmlinux_path, True)
    except Exception as e:
        return f"Failed to execute crash script: {str(e)}"


# 动态注册 crash 子命令工具
def register_crash_tool(name: str, syntax: str, example: str, summary: str):
    """
    动态创建一个 crash 工具并注册到 crash_server
    """

    async def crash_tool_func(
        command: Annotated[
            str,
            Field(
                description=(
                    f"The full '{name}' command string to execute.\n"
                    f"Syntax: {syntax}\n"
                    f"Example: {example}\n"
                    "IMPORTANT: Replace placeholders with actual values and do not include brackets '[]'."
                ),
            ),
        ],
        vmcore_path: Annotated[
            str, Field(description="The absolute path to the vmcore file.")
        ],
        vmlinux_path: Annotated[
            str, Field(description="The absolute path to the vmlinux file.")
        ],
    ) -> str:
        # 统一的执行逻辑
        try:
            output = run_crash_command(command, vmcore_path, vmlinux_path, True)
            return output
        except Exception as e:
            return f"Failed to execute crash command: {str(e)}"

    # 修改文档字符串，FastMCP 会将其作为工具描述
    crash_tool_func.__doc__ = f"{summary} (Crash Subcommand: {name})"
    # 修改函数名以防冲突
    crash_tool_func.__name__ = f"crash_{name}"

    # 手动调用 tool 装饰器进行注册，确保 __doc__ 已经被修改
    crash_server.tool(name=name)(crash_tool_func)
    return crash_tool_func


# 统一格式：(name, syntax, example, summary)
commands = [
    (
        "sys",
        "sys [-c [name|number]] [-t] [-i] config",
        "sys -i",
        "Display system profile and kernel info.",
    ),
    (
        "bt",
        "bt [-a] [-p] [stack_pointer] [pid|task]",
        "bt -a",
        "Display task backtrace.",
    ),
    ("ps", "ps [-k|-u|-G] [-f] [-t] [pid|task]", "ps -ef", "Display process status."),
    (
        "vm",
        "vm [-p|-m|-v|-a|-f] [task|address]",
        "vm -a",
        "Display task virtual memory.",
    ),
    ("files", "files [-d] [task|address]", "files -a", "Display task open files."),
    (
        "kmem",
        "kmem [-f|-F|-c|-C|-i|-s|-S|-v|-V] [address|symbol]",
        "kmem -i",
        "Display kernel memory usage.",
    ),
    (
        "struct",
        "struct struct_name[.member[,member]][-o][-l offset][-rfuxdp] [address | symbol][:cpuspec] [count | -c count]",
        "struct task_struct 0xffff8800",
        "Display kernel structure.",
    ),
    (
        "dis",
        "dis [-rfludxs][-b [num]] [address | symbol] [count]",
        "dis -l jiffies",
        "Disassemble instructions.",
    ),
    (
        "runq",
        "runq [-t] [-T] [-m] [-g] [-c cpu(s)]",
        "runq -t",
        "Display CPU run queues.",
    ),
    ("log", "log [-Ttdmasc]", "log -t", "Display kernel log."),
    (
        "list",
        "list [[-o] offset][-e end][-[s|S] struct[.member[,member] [-l offset]] -[x|d]] [-r|-B] [-h [-O head_offset]|-H] start",
        "list task_struct.p_pptr c169a000",
        "Dump linked list contents.",
    ),
    (
        "ipcs",
        "ipcs [-smMq] [-n pid|task] [id | addr]",
        "ipcs",
        "Display System V IPC info.",
    ),
    (
        "waitq",
        "waitq [ symbol ] | [ struct.member struct_addr ] | [ address ]",
        "waitq task_struct.wait_chldexit c5496000",
        "Display tasks on a wait queue.",
    ),
    (
        "whatis",
        "whatis [[-o] [struct | union | typedef | symbol]] | [[-r [size|range]] [-m member]]",
        "whatis do_fork",
        "Display the definition of structures, unions, typedefs or text/data symbols.",
    ),
    (
        "pte",
        "pte contents ...",
        "pte 13f600",
        "Translate PTE contents to physical address and page bits.",
    ),
    (
        "search",
        "search [-s start] [ -[kKV] | -u | -p | -t | -T ] [-e end | -l length] [-m mask] \
         [-x count] -[cwh] [value | (expression) | symbol | string] ...",
        "search -s _etext -e _edata c2d400eb",
        "This command searches for a given value within a range of user virtual, kernel  virtual, or physical memory space.",
    ),
    (
        "mount",
        "mount [-f][-i] [-n pid|task] [mount|vfsmount|superblock|dev|dir|dentry|inode]",
        "mount -i",
        "Display basic information about the currently-mounted filesystems.",
    ),
    (
        "p",
        "p [-x|-d][-u] [expression | symbol[:cpuspec]]",
        "p jiffies, px jiffies, pd jiffies",
        'This command passes its arguments on to gdb "print" command for evaluation',
    ),
    (
        "dev",
        "dev [-i | -p | -d | -D ] [-V | -v index [file]]",
        "dev -i",
        "If no argument is entered, this command dumps character and block device data",
    ),
    (
        "foreach",
        "foreach [[pid | taskp | name | state | [kernel | user | gleader]] ...] command [flag] [argument]",
        "foreach bt",
        "This command allows for an examination of various kernel data associated with any, or all, tasks in the system, without having to set the context to each targeted task",
    ),
    (
        "timer",
        "timer [-r][-C cpu]",
        "timer -r",
        "This command displays the timer queue entries",
    ),
    (
        "swap",
        "swap",
        "swap",
        "This command displays information for each configured swap device.",
    ),
    (
        "sig",
        "sig [[-l] | [-s sigset]] | [-g] [pid | taskp] ...",
        "sig -g 2578",
        "This command displays signal-handling data of one or more tasks.",
    ),
    (
        "mach",
        "mach [-m | -c -[xd] | -o]",
        "mach",
        "This command displays data specific to a machine type.",
    ),
    (
        "mod",
        "mod -s module [objfile] | -d module | -S [directory] [-D|-t|-r|-R|-o|-g]",
        "mod -s dm_mod",
        "module information and loading of symbols and debugging data",
    ),
    (
        "rd",
        "rd [-adDsSupxmfNR][-8|-16|-32|-64][-o offs][-e addr][-r file][address|symbol] [count]",
        "rd -a linux_banner",
        "This command displays the contents of memory, with the output formatted in several different manners",
    ),
    (
        "vtop",
        "vtop [-c [pid | taskp]] [-u|-k] address ...",
        "vtop c806e000",
        "This command translates a user or kernel virtual address to its physical address.",
    ),
    (
        "set",
        "set [[-a] [pid | taskp] | [-c cpu] | -p] | [crash_variable [setting]] | -v",
        "set -p; set c2fe8000",
        "This command either sets a new context, or gets the current context for display.",
    ),
    (
        "sym",
        "sym [-l] | [-M] | [-m module] | [-p|-n] | [-q string] | [symbol | vaddr]",
        "sym jiffies; sym c0109944",
        "This command translates a symbol to its virtual address, or a static kernel virtual address to its symbol -- or to a symbol-plus-offset value.",
    ),
    (
        "task",
        "task [-R member[,member]] [-dx] [pid | taskp] ...; task -R se.on_rq",
        "task -x; task -R ngroups,groups 2958",
        "This command dumps a formatted display of the contents of a task's task_struct and thread_info structures.",
    ),
    (
        "ptov",
        "ptov [address | offset:cpuspec]",
        "ptov 56e000; ptov b0c0:a",
        "This command translates a hexadecimal physical address into a kernel virtual address.",
    ),
    (
        "ptob",
        "ptob page_number ...",
        "ptob 512a",
        "This command translates a page frame number to its byte value.",
    ),
    (
        "irq",
        "irq [[[index ...] | -u ] | -d | -b | -a | -s [-c cpu]]",
        "irq -d; irq 21",
        "This command collaborates the data in an irq_desc_t, along with its associated hw_interrupt_type and irqaction structure data, into a consolidated per-IRQ display.",
    ),
    (
        "sbitmapq",
        "sbitmapq [-s struct[.member[,member]] -a address [-p] [-v]] -[x|d] address",
        "sbitmapq -s iscsi_cmd -a 0xc0000000671c0000 -v c0000000e118c808",
        "The command dumps the contents of the sbitmap_queue structure and the used bits in the bitmap.",
    ),
    (
        "cifsshow",
        "cifsshow [-h]",
        "cifsshow",
        "Print information about cifs mounts.",
    ),
    (
        "cpuinfo",
        "cpuinfo [-h]",
        "cpuinfo",
        "Print information about the physical CPUs (processors) in a system.",
    ),
    (
        "detailedsearch",
        "detailedsearch [-h] [-m MASK] [-s START] [-l LENGTH] [-k] [-K] [-u] [-c] [-w] [--slab-only] params",
        "detailedsearch ffff8addd2b92700",
        "Search for a value and print matching location details (slab object, task stack, etc.), enhanced version of 'search'.",
    ),
    (
        "dmshow",
        "dmshow [-h]",
        "dmshow",
        "Display information about multipath devices and LVM volumes from vmcore dumps.",
    ),
    # (
    #     "epython",
    #     "epython program.py arg ...",
    #     "epython xportshow.py --help",
    #     "Invoke the embedded Python interpreter to run crash extension scripts.",
    # ),
    (
        "fregs",
        "fregs [-h]",
        "fregs",
        "Decode and print subroutine registers and arguments from stack frames.",
    ),
    (
        "hanginfo",
        "hanginfo [-h]",
        "hanginfo",
        "Print information about UNINTERRUPTIBLE threads and categorize them by mutex/semaphore waits.",
    ),
    (
        "keyringshow",
        "keyringshow [-h] (-k KEYRING | -p PID | -a)",
        "keyringshow -a",
        "Print information about keyrings for a specific task or all tasks.",
    ),
    (
        "lsdentry",
        "lsdentry [-h] [-R] [-l] [--params FIELDS] [-x] [--negative] [--partial] dentry",
        "lsdentry /var/log",
        "Print directory information based on the dentry tree, similar to 'ls -l'.",
    ),
    (
        "mdadm",
        "mdadm [-h] [-m] [-d]",
        "mdadm -d",
        "Print information about MD devices (Linux Software RAID).",
    ),
    (
        "modinfo",
        "modinfo [-h] [--disasm=DISASM_MODULE] [--details=MODULE_DETAIL] [-t] [-g] [-a] [-u]",
        "modinfo -t",
        "Print information about DLKMs (dynamically loaded kernel modules).",
    ),
    (
        "nbdshow",
        "nbdshow [-h]",
        "nbdshow",
        "Display information about NBD (Network Block Device) devices and diagnose common issues.",
    ),
    (
        "nfsshow",
        "nfsshow [-h]",
        "nfsshow",
        "Print information about NFS subsystem (both client and server).",
    ),
    (
        "nvme",
        "nvme [-h] [-l [NS]] [-c [CTRL]] [-n [NS]] [-d [CTRL]] [-q [CTRL]] [-i [QID]] [-s [SUB]] [-k]",
        "nvme -k",
        "Print information about NVMe devices, controllers, queues, and check for common NVMe issues.",
    ),
    (
        "pstree",
        "pstree [-p] [-g] [-s] [-t]",
        "pstree -p",
        "Print process list in tree format.",
    ),
    (
        "rqlist",
        "rqlist [-h] [-q [FIELDS]] [-r [FIELDS]] [--bio [FIELDS]] [--pages [FIELDS]] [-x] [--summary] [--time] [--olderthan OLDERTHAN] [--youngerthan YOUNGERTHAN]",
        "rqlist --summary",
        "Print information about block I/O requests and request queues with state and timing info.",
    ),
    # (
    #     "taskinfo",
    #     "taskinfo [-h]",
    #     "taskinfo",
    #     "Print detailed information about tasks, more detailed than the built-in 'ps' command.",
    # ),
    # (
    #     "tslog",
    #     "tslog [-h]",
    #     "tslog",
    #     "Display kernel log (dmesg) with timestamps converted to real date/time.",
    # ),
    (
        "xportshow",
        "xportshow [-h] [--summary] [-iv] [-a] [-t] [--everything]",
        "xportshow --summary",
        "Display networking information including connections summary, interfaces, and TCP/UDP state.",
    ),
    (
        "scsishow",
        "scsishow [-h]",
        "scsishow",
        "Display information about SCSI adapters, devices, and commands from vmcore dumps. Includes heuristics to detect stuck SCSI error handling and stalled commands.",
    ),
]

# 批量注册
for cmd_info in commands:
    register_crash_tool(*cmd_info)

if __name__ == "__main__":
    # 作为独立进程启动时，通过 stdio 与 MCP 客户端通信。
    crash_server.run(transport="stdio", show_banner=False)
