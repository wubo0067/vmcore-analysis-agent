#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# executor.py - Crash 工具执行器实现（支持跨进程共享 Daemon / 传统 Oneshot）
# Author: CalmWU
# Created: 2026-01-09

from __future__ import annotations

import os
import subprocess


def _get_logger():
    from src.utils.logging import logger

    return logger


def _get_linux_distro_version() -> tuple[str, str]:
    from src.utils.os import get_linux_distro_version

    return get_linux_distro_version()


# crash 命令单次执行的最长等待时间（秒）。
COMMAND_TIMEOUT = 180

# 单次命令返回的最大字符数。超出部分将被截断以防止 LLM token 溢出。
MAX_OUTPUT_CHARS = 40_000

CRASH_IGNORE_MARKERS = [
    "crash ",
    "Copyright",
    "GNU gdb (GDB)",
    "This GDB was configured",
    "Type",
    "For help",
    "please wait...",
    "NOTE: stdin: not a tty",
    "quit",
    "License GPLv3+",
    "This program",
    "show copying",
    "show warranty",
    "free software",
    "no warranty",
    "you are welcome",
    "certain conditions",
    "There is NO WARRANTY",
    "Find the GDB manual",
    "www.gnu.org",
]

_VALID_EXECUTION_MODES = frozenset({"daemon", "oneshot"})


def get_crash_execution_mode() -> str:
    """获取当前 crash 执行模式：daemon（默认，跨进程共享常驻守护进程）或 oneshot（短生命周期子进程）。"""
    mode = os.environ.get("CRASH_EXECUTION_MODE", "daemon").strip().lower() or "daemon"
    if mode not in _VALID_EXECUTION_MODES:
        if mode == "pool":
            _get_logger().warning(
                "CRASH_EXECUTION_MODE='pool' has been removed (stdio MCP subprocesses "
                "cannot persist an in-process pool across batches); falling back to "
                "'daemon'. Set CRASH_EXECUTION_MODE=daemon or oneshot."
            )
        else:
            _get_logger().warning(
                "Invalid CRASH_EXECUTION_MODE=%r; falling back to 'daemon'.", mode
            )
        return "daemon"
    return mode


def _is_supported_distro() -> bool:
    if os.environ.get("CRASH_SKIP_DISTRO_CHECK", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return True
    distro, version = _get_linux_distro_version()
    return distro == "rhel" and version.isdigit() and int(version) == 9


def run_crash_command_rhel9(command, vmcore_path, vmlinux_path, verbose=False):
    """Run a one-shot crash command on RHEL 9 systems (legacy fallback)."""
    logger = _get_logger()
    full_cmd = ["crash", vmlinux_path, vmcore_path]
    process = subprocess.Popen(
        full_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1024 * 1024,
    )
    try:
        stdout, stderr = process.communicate(
            input=command + "\nquit\n", timeout=COMMAND_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, _ = process.communicate()
        logger.warning(
            f"Crash command '{command}' timed out after {COMMAND_TIMEOUT}s. "
            "Partial output will be returned."
        )
        return (
            f"[TIMEOUT] Command '{command}' exceeded {COMMAND_TIMEOUT}s limit "
            "and was terminated. The command generates too much output or takes too long. "
            "Use a more targeted command or filter the output with grep."
        )

    if process.returncode != 0:
        err = "Crash command '{command}' failed with error:\n{error}".format(
            command=command, error=stderr
        )
        logger.error(err)
        raise Exception(err)

    lines = stdout.splitlines()
    filtered_lines = []
    state_found = False
    capture = False

    for line in lines:
        if any(keyword in line for keyword in CRASH_IGNORE_MARKERS):
            continue

        if "STATE:" in line:
            state_found = True
            continue

        if state_found and not line.strip() and not capture:
            capture = True
            continue

        if capture:
            filtered_lines.append(line)

    output = "\n".join(filtered_lines).strip()

    if len(output) > MAX_OUTPUT_CHARS:
        logger.warning(
            f"Command '{command}' output truncated: {len(output)} -> {MAX_OUTPUT_CHARS} chars"
        )
        output = (
            output[:MAX_OUTPUT_CHARS]
            + f"\n\n[OUTPUT TRUNCATED: {len(output)} chars total, showing first {MAX_OUTPUT_CHARS}. "
            "Use a more specific command or grep filter to reduce output.]"
        )

    if verbose:
        logger.info(f"Filtered output for '{command}' (RHEL 9):\n{output}")

    if not output:
        logger.warning(f"Warning: No valid output from command '{command}'")

    return output


def run_crash_script_rhel9(script_content, vmcore_path, vmlinux_path, verbose=False):
    """Run multiple crash commands (one-shot script) on RHEL 9 systems (legacy fallback)."""
    logger = _get_logger()
    full_cmd = ["crash", vmlinux_path, vmcore_path]

    process = subprocess.Popen(
        full_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1024 * 1024,
    )

    input_str = script_content
    if not input_str.endswith("\n"):
        input_str += "\n"
    input_str += "quit\n"

    try:
        stdout, stderr = process.communicate(input=input_str, timeout=COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        logger.warning(
            f"Crash script timed out after {COMMAND_TIMEOUT}s. Script content: {script_content[:200]!r}"
        )
        return (
            f"[TIMEOUT] Script execution exceeded {COMMAND_TIMEOUT}s limit and was terminated. "
            "One or more commands in the script generates too much output or takes too long. "
            "Split the script into smaller steps and avoid large-output commands like 'log' without filters."
        )

    if process.returncode != 0:
        err = f"Crash script failed with error:\n{stderr}"
        logger.error(err)
        raise Exception(err)

    lines = stdout.splitlines()
    filtered_lines = []

    extra_ignore_markers = [
        "KERNEL:",
        "DUMPFILE:",
        "CPUS:",
        "DATE:",
        "UPTIME:",
        "LOAD AVERAGE:",
        "MEMORY:",
        "NODENAME:",
        "SMP:",
        "TASKS:",
        "RELEASE:",
        "VERSION:",
        "MACHINE",
        "PID",
        "PANIC:",
        "COMMAND",
        "TASK:",
        "CPU:",
        "STATE",
    ]
    for line in lines:
        if any(
            marker in line for marker in CRASH_IGNORE_MARKERS + extra_ignore_markers
        ):
            continue

        if line.strip() == "quit":
            continue

        filtered_lines.append(line)

    output = "\n".join(filtered_lines).strip()

    if len(output) > MAX_OUTPUT_CHARS:
        logger.warning(
            f"Script output truncated: {len(output)} -> {MAX_OUTPUT_CHARS} chars"
        )
        output = (
            output[:MAX_OUTPUT_CHARS]
            + f"\n\n[OUTPUT TRUNCATED: {len(output)} chars total, showing first {MAX_OUTPUT_CHARS}. "
            "Use a more specific command or grep filter to reduce output.]"
        )

    if verbose:
        logger.info(f"Filtered output for script:\n{output}")

    return output


def _execute_via_daemon(
    command_or_script: str,
    vmcore_path: str,
    vmlinux_path: str,
    *,
    is_script: bool,
    verbose: bool,
) -> str:
    # 延迟导入，确保非 POSIX 环境下模块导入与 oneshot 模式不受影响
    from .daemon import CrashDaemonClient

    endpoint = (
        os.environ.get("CRASH_DAEMON_ENDPOINT", "unix:///tmp/vmcore_crashd.sock").strip()
        or "unix:///tmp/vmcore_crashd.sock"
    )
    try:
        client = CrashDaemonClient(endpoint)
        return client.execute(
            command_or_script,
            vmcore_path,
            vmlinux_path,
            is_script=is_script,
            verbose=verbose,
        )
    except OSError as exc:
        raise RuntimeError(
            f"CrashDaemon ({endpoint}) is unreachable: {exc}. "
            "Start it via 'tools/crash-daemon.sh start' or set "
            "CRASH_EXECUTION_MODE=oneshot."
        ) from exc


def run_crash_command(full_subcmd, vmcore_path, vmlinux_path, verbose=False):
    """Run a crash subcommand on the given vmcore and vmlinux files."""
    if not _is_supported_distro():
        return "functionality for other distros/versions not yet implemented."

    if get_crash_execution_mode() == "oneshot":
        return run_crash_command_rhel9(full_subcmd, vmcore_path, vmlinux_path, verbose)

    return _execute_via_daemon(
        full_subcmd,
        vmcore_path,
        vmlinux_path,
        is_script=False,
        verbose=verbose,
    )


def run_crash_script(script_content, vmcore_path, vmlinux_path, verbose=False):
    """Run a crash script on the given vmcore and vmlinux files."""
    if not _is_supported_distro():
        return "functionality for other distros/versions not yet implemented."

    if get_crash_execution_mode() == "oneshot":
        return run_crash_script_rhel9(
            script_content, vmcore_path, vmlinux_path, verbose
        )

    return _execute_via_daemon(
        script_content,
        vmcore_path,
        vmlinux_path,
        is_script=True,
        verbose=verbose,
    )
