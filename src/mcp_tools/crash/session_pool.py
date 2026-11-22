#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# session_pool.py - 常驻 PTY Crash 会话池实现
"""Persistent PTY-based crash session pool.

核心能力：
1. 跨平台安全导入：POSIX 依赖（pty/termios）采用条件导入，非 POSIX（如 Windows 开发/CI）
   下模块可正常导入，不破坏 executor 的 oneshot 模式及其他测试；注意 Windows 的 CPython
   虽带 Lib/pty.py，但其中 `import tty` -> `from termios import *` 必然失败，故运行时
   _PTY_AVAILABLE 为 False，类型检查侧则通过 TYPE_CHECKING 提供真实模块类型；
2. 使用伪终端（PTY）常驻运行 `crash --no_scroll <vmlinux> <vmcore>`，避免每次命令冷启动；
3. 采用唯一哨兵（!echo <token>）+ `crash> ` 提示符双校验切分输出，彻底杜绝伪提示符导致的响应错位；
4. 按模块逐行校验 `mod -s` 结果并归一化路径（bare/auto/具体路径），避免失败写脏缓存或重复加载；
5. 超时时在统一 3 秒预算内发送 SIGINT 挽救会话，失败或进程异常退出时自动杀进程组并重建；
6. 支持多 vmcore 真并行、单 vmcore 多槽位全局按 last_used_at 的严格 LRU 淘汰与空闲 TTL 回收。
"""

from __future__ import annotations

import atexit
import os
import re
import select
import signal
import subprocess
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Optional, TYPE_CHECKING, Protocol

# 在 Windows 上运行时 `import pty` 必然失败（pty 内部 `import tty` 会触发
# `from termios import *`，而 Windows 没有 termios）。因此这里先无条件声明该标志，
# 再由分支决定取值，避免把两次赋值都放进静态分析判定为不可达的分支里。
_PTY_AVAILABLE = False

if TYPE_CHECKING:
    # 类型检查视角：typeshed 的 stdlib/pty.pyi 与 termios.pyi 整体包裹在
    # `if sys.platform != "win32":` 之中，于是在 Windows 解释器下这两个模块被解析为
    # 空模块，openpty/tcgetattr/ECHO 等属性一律不可见。这里用局部 Protocol 声明实际
    # 用到的接口，绕开对平台相关存根的依赖；运行时行为完全不变（该分支永不执行）。
    class _PtyModule(Protocol):
        def openpty(self) -> tuple[int, int]: ...

    class _TermiosModule(Protocol):
        ECHO: int
        TCSANOW: int

        def tcgetattr(self, fd: int) -> list[Any]: ...
        def tcsetattr(self, fd: int, when: int, attributes: list[Any]) -> None: ...

    _pty_mod: Optional[_PtyModule]
    _termios_mod: Optional[_TermiosModule]
else:
    try:
        import pty as _pty_mod
        import termios as _termios_mod

        _PTY_AVAILABLE = True
    except ImportError:
        _pty_mod = None
        _termios_mod = None

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_MOD_S_LINE_RE = re.compile(r"^\s*mod\s+-s\s+(?P<mod>\S+)(?:\s+(?P<path>.+?))?\s*$")
_MOD_ERROR_TOKENS = (
    "cannot find",
    "cannot open",
    "no such file",
    "not a valid",
    "invalid",
    "failed",
    "error:",
)

DEFAULT_COMMAND_TIMEOUT = 180.0
DEFAULT_STARTUP_TIMEOUT = 120.0
DEFAULT_MAX_OUTPUT_CHARS = 40_000


def is_pty_available() -> bool:
    """返回当前运行平台是否支持 POSIX PTY 常驻会话。"""
    return _PTY_AVAILABLE


def _get_logger():
    try:
        from src.utils.logging import logger

        return logger
    except Exception:
        import logging

        return logging.getLogger(__name__)


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        return default
    return max(minimum, val)


def _env_float(name: str, default: float, minimum: float = 0.1) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        val = float(raw)
    except ValueError:
        return default
    return max(minimum, val)


def _normalize_mod_path(raw_path: Optional[str]) -> str:
    """归一化 `mod -s <mod> [path]` 路径参数：空串与 'auto' 统一视作自动解析 ''。"""
    cleaned = (raw_path or "").strip()
    if not cleaned or cleaned.lower() == "auto":
        return ""
    return cleaned


def _mod_load_failed(
    output: str,
    mod_name: str,
    mod_path: str,
    *,
    total_pending_mods: int = 1,
) -> bool:
    """按行判断指定模块的 `mod -s` 是否加载失败，避免多模块脚本互相污染或漏判路径错误。"""
    mod_lower = mod_name.lower()
    path_lower = mod_path.lower()
    base_lower = os.path.basename(mod_path).lower() if mod_path else ""

    for line in output.splitlines():
        low = line.strip().lower()
        if not low:
            continue
        if "mod:" not in low:
            continue
        if not any(tok in low for tok in _MOD_ERROR_TOKENS):
            continue
        # 归属判断：命中模块名、完整路径或文件名（如 mod: /path/x.ko.debug: cannot open）
        if mod_lower in low:
            return True
        if path_lower and path_lower in low:
            return True
        if base_lower and base_lower in low:
            return True
        # 单模块场景下，即使错误行未显式带模块名也判失败
        if total_pending_mods == 1:
            return True
    return False


@dataclass(frozen=True)
class CrashSessionConfig:
    """常驻 Crash 会话池运行时配置（独立于 LLM Settings，便于 daemon 独立启动）。"""

    max_total_sessions: int = 4
    slots_per_vmcore: int = 1
    idle_ttl_sec: float = 900.0
    reap_interval_sec: float = 60.0
    command_timeout_sec: float = DEFAULT_COMMAND_TIMEOUT
    startup_timeout_sec: float = DEFAULT_STARTUP_TIMEOUT
    acquire_timeout_sec: float = 30.0
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS
    crash_binary: str = "crash"

    @classmethod
    def from_env(cls) -> "CrashSessionConfig":
        return cls(
            max_total_sessions=_env_int("CRASH_POOL_MAX_SESSIONS", 4, 1),
            slots_per_vmcore=_env_int("CRASH_POOL_SLOTS_PER_VMCORE", 1, 1),
            idle_ttl_sec=_env_float("CRASH_POOL_IDLE_TTL_SEC", 900.0, 1.0),
            reap_interval_sec=_env_float("CRASH_POOL_REAP_INTERVAL_SEC", 60.0, 0.5),
            command_timeout_sec=_env_float(
                "CRASH_COMMAND_TIMEOUT_SEC", DEFAULT_COMMAND_TIMEOUT, 1.0
            ),
            startup_timeout_sec=_env_float(
                "CRASH_STARTUP_TIMEOUT_SEC", DEFAULT_STARTUP_TIMEOUT, 1.0
            ),
            acquire_timeout_sec=_env_float("CRASH_POOL_ACQUIRE_TIMEOUT_SEC", 30.0, 0.5),
            max_output_chars=_env_int(
                "CRASH_MAX_OUTPUT_CHARS", DEFAULT_MAX_OUTPUT_CHARS, 1024
            ),
            crash_binary=os.environ.get("CRASH_BINARY", "crash").strip() or "crash",
        )


CommandBuilder = Callable[[str, str, str], list[str]]


def _default_command_builder(
    crash_binary: str, vmlinux_path: str, vmcore_path: str
) -> list[str]:
    return [crash_binary, "--no_scroll", vmlinux_path, vmcore_path]


class PersistentCrashSession:
    """单个绑定到 (vmcore_path, vmlinux_path) 的常驻 PTY crash 进程。"""

    def __init__(
        self,
        vmcore_path: str,
        vmlinux_path: str,
        config: Optional[CrashSessionConfig] = None,
        *,
        command_builder: Optional[CommandBuilder] = None,
    ) -> None:
        if not _PTY_AVAILABLE:
            raise RuntimeError(
                "Persistent crash sessions require a POSIX platform with pty/termios. "
                "Set CRASH_EXECUTION_MODE=oneshot on non-POSIX hosts."
            )
        self.vmcore_path = vmcore_path
        self.vmlinux_path = vmlinux_path
        self.config = config or CrashSessionConfig.from_env()
        self._command_builder = command_builder or _default_command_builder

        self._io_lock = threading.RLock()
        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._master_fd: Optional[int] = None
        self._loaded_modules: dict[str, str] = {}
        # 原子替换的只读快照，供 stats() 在 _cond 锁下无锁安全读取，避免跨锁竞态
        self._loaded_modules_snapshot: tuple[str, ...] = ()
        self._closed = False
        self.created_at = time.monotonic()
        self.last_used_at = self.created_at
        self.command_count = 0
        self.restart_count = 0

        self._start()

    @property
    def pid(self) -> Optional[int]:
        return self._proc.pid if self._proc is not None else None

    def loaded_modules_snapshot(self) -> list[str]:
        """无锁返回已加载模块名只读快照。"""
        return list(self._loaded_modules_snapshot)

    def _sync_modules_snapshot(self) -> None:
        self._loaded_modules_snapshot = tuple(sorted(self._loaded_modules.keys()))

    def is_alive(self) -> bool:
        return (
            not self._closed
            and self._proc is not None
            and self._master_fd is not None
            and self._proc.poll() is None
        )

    def rss_kb(self) -> int:
        """读取 /proc/<pid>/status 中的 VmRSS（KB），非 Linux 或已退出返回 0。"""
        pid = self.pid
        if pid is None:
            return 0
        try:
            with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1])
        except OSError:
            return 0
        return 0

    def _start(self) -> None:
        if not _PTY_AVAILABLE or _pty_mod is None:
            raise RuntimeError("POSIX pty is not available on this platform")

        logger = _get_logger()
        master_fd, slave_fd = _pty_mod.openpty()
        if _termios_mod is not None:
            try:
                attrs = _termios_mod.tcgetattr(slave_fd)
                attrs[3] &= ~_termios_mod.ECHO
                _termios_mod.tcsetattr(slave_fd, _termios_mod.TCSANOW, attrs)
            except Exception:
                pass

        cmd = self._command_builder(
            self.config.crash_binary, self.vmlinux_path, self.vmcore_path
        )
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                start_new_session=True,
            )
        except Exception:
            os.close(master_fd)
            os.close(slave_fd)
            raise
        finally:
            try:
                os.close(slave_fd)
            except OSError:
                pass

        self._proc = proc
        self._master_fd = master_fd
        self._loaded_modules.clear()
        self._sync_modules_snapshot()
        self._closed = False

        try:
            self._read_until_prompt(timeout=self.config.startup_timeout_sec)
            self._send_and_collect("set scroll off", timeout=15.0)
            self.last_used_at = time.monotonic()
            logger.info(
                "Started persistent crash session pid=%s for vmcore=%s",
                proc.pid,
                self.vmcore_path,
            )
        except Exception as exc:
            rc = proc.poll()
            logger.error(
                "Failed to initialize persistent crash session pid=%s exit_code=%s for %s: %s",
                proc.pid,
                rc,
                self.vmcore_path,
                exc,
            )
            self._force_kill()
            raise

    def restart(self) -> None:
        """强制清理旧进程并重新拉起常驻 crash 会话。"""
        with self._io_lock:
            self._force_kill()
            self.restart_count += 1
            self._start()

    def execute(
        self,
        command_or_script: str,
        *,
        is_script: bool = False,
        timeout: Optional[float] = None,
        verbose: bool = False,
    ) -> str:
        """在当前常驻会话中执行单条命令或多行脚本。"""
        logger = _get_logger()
        effective_timeout = (
            timeout if timeout is not None else self.config.command_timeout_sec
        )

        with self._io_lock:
            if not self.is_alive():
                self.restart()

            prepared_lines, pending_mods = self._prepare_lines(
                command_or_script, is_script=is_script
            )
            if not prepared_lines:
                return ""

            payload_text = "\n".join(prepared_lines)
            try:
                output = self._send_and_collect(payload_text, timeout=effective_timeout)
            except TimeoutError:
                recovered = self._try_interrupt_recover(budget_sec=3.0)
                if not recovered:
                    logger.warning(
                        "Crash session pid=%s did not recover from SIGINT within 3s; killing for respawn.",
                        self.pid,
                    )
                    self._force_kill()
                if is_script:
                    return (
                        f"[TIMEOUT] Script execution exceeded {int(effective_timeout)}s limit "
                        "and was interrupted. Split the script into smaller steps and avoid "
                        "large-output commands like 'log' without filters."
                    )
                return (
                    f"[TIMEOUT] Command '{command_or_script}' exceeded {int(effective_timeout)}s limit "
                    "and was interrupted. Use a more targeted command or filter the output with grep."
                )
            except (EOFError, OSError, RuntimeError) as exc:
                logger.warning(
                    "Crash session pid=%s failed (%s); restarting and retrying once.",
                    self.pid,
                    exc,
                )
                self.restart()
                prepared_lines, pending_mods = self._prepare_lines(
                    command_or_script, is_script=is_script
                )
                output = self._send_and_collect(
                    "\n".join(prepared_lines), timeout=effective_timeout
                )

            # 按模块逐项检查是否失败，只有确认未失败的模块才写入缓存
            total_pending = len(pending_mods)
            mutated = False
            for mod_name, mod_path in pending_mods:
                if not _mod_load_failed(
                    output, mod_name, mod_path, total_pending_mods=total_pending
                ):
                    self._loaded_modules[mod_name] = mod_path
                    mutated = True
            if mutated:
                self._sync_modules_snapshot()

            self.command_count += 1
            self.last_used_at = time.monotonic()

            if len(output) > self.config.max_output_chars:
                total_len = len(output)
                logger.warning(
                    "Crash output truncated: %d -> %d chars",
                    total_len,
                    self.config.max_output_chars,
                )
                output = (
                    output[: self.config.max_output_chars]
                    + f"\n\n[OUTPUT TRUNCATED: {total_len} chars total, showing first "
                    f"{self.config.max_output_chars}. Use a more specific command or grep filter to reduce output.]"
                )

            if verbose:
                logger.info(
                    "Persistent crash output (%d chars):\n%s",
                    len(output),
                    output[:500],
                )

            return output

    def close(self) -> None:
        """优雅退出 crash 进程并释放 PTY 文件描述符。"""
        with self._io_lock:
            if self._closed:
                return
            self._closed = True
            if (
                self._master_fd is not None
                and self._proc is not None
                and self._proc.poll() is None
            ):
                try:
                    os.write(self._master_fd, b"quit\n")
                    self._proc.wait(timeout=3.0)
                except Exception:
                    pass
            self._force_kill(mark_closed=True)

    # ------------------------------------------------------------------
    # Internal PTY I/O helpers
    # ------------------------------------------------------------------

    def _prepare_lines(
        self, command_or_script: str, *, is_script: bool
    ) -> tuple[list[str], list[tuple[str, str]]]:
        """清理 quit 指令，并对已加载的 `mod -s` 做路径归一化与幂等去重。"""
        raw_lines = command_or_script.splitlines() if is_script else [command_or_script]
        cleaned: list[str] = []
        pending_mods: list[tuple[str, str]] = []

        for raw in raw_lines:
            line = raw.strip()
            if not line or line == "quit" or line == "q":
                continue
            m = _MOD_S_LINE_RE.match(line)
            if m:
                mod_name = m.group("mod")
                norm_path = _normalize_mod_path(m.group("path"))
                if mod_name in self._loaded_modules:
                    existing_path = self._loaded_modules[mod_name]
                    # 1) 裸/auto 请求命中任意已加载记录 -> 跳过
                    # 2) 具体路径与已加载记录一致 -> 跳过
                    if norm_path == "" or existing_path == norm_path:
                        continue
                pending_mods.append((mod_name, norm_path))
            cleaned.append(line)

        return cleaned, pending_mods

    def _require_started(self) -> tuple[int, subprocess.Popen[bytes]]:
        if self._master_fd is None or self._proc is None:
            raise RuntimeError("Crash session is not started")
        return self._master_fd, self._proc

    def _send_and_collect(self, payload_text: str, *, timeout: float) -> str:
        self._require_started()
        self._drain_nonblocking()

        token = f"__CRASH_DONE_{uuid.uuid4().hex[:12]}__"
        wire = f"{payload_text}\n!echo {token}\n".encode("utf-8")
        self._write_all(wire)

        raw = self._read_until_sentinel(token, timeout=timeout)
        return self._clean_output(raw, payload_text, token)

    def _write_all(self, data: bytes) -> None:
        master_fd, _ = self._require_started()
        view = memoryview(data)
        total = 0
        while total < len(data):
            written = os.write(master_fd, view[total:])
            if written <= 0:
                raise OSError("Failed to write to crash PTY")
            total += written

    def _read_until_prompt(self, *, timeout: float) -> str:
        master_fd, proc = self._require_started()
        deadline = time.monotonic() + timeout
        buf = bytearray()
        prompt_marker = b"crash> "

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                rc = proc.poll()
                state_desc = (
                    f"exit_code={rc}"
                    if rc is not None
                    else f"process still running (pid={proc.pid})"
                )
                raise TimeoutError(
                    f"Timed out waiting for crash> prompt after {timeout:.1f}s ({state_desc})"
                )
            rlist, _, _ = select.select([master_fd], [], [], min(remaining, 0.25))
            if not rlist:
                rc = proc.poll()
                if rc is not None:
                    raise RuntimeError(
                        f"crash exited with exit_code={rc}: "
                        f"{buf.decode('utf-8', errors='replace')[-500:]}"
                    )
                continue
            try:
                chunk = os.read(master_fd, 65536)
            except OSError as exc:
                raise EOFError(f"crash PTY closed while waiting for prompt: {exc}") from exc
            if not chunk:
                raise EOFError("EOF reading from crash PTY while waiting for prompt")
            buf.extend(chunk)
            if prompt_marker in buf:
                return buf.decode("utf-8", errors="replace")

    def _read_until_sentinel(self, token: str, *, timeout: float) -> str:
        """持续读取直到同时出现独立哨兵行与紧随其后的 crash> 提示符。"""
        master_fd, proc = self._require_started()
        deadline = time.monotonic() + timeout
        buf = bytearray()
        token_bytes = token.encode("utf-8")
        prompt_bytes = b"crash> "

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                rc = proc.poll()
                raise TimeoutError(
                    f"Timed out waiting for sentinel {token} after {timeout:.1f}s (exit_code={rc})"
                )

            rlist, _, _ = select.select([master_fd], [], [], min(remaining, 0.25))
            if not rlist:
                rc = proc.poll()
                if rc is not None:
                    raise RuntimeError(f"crash exited unexpectedly with exit_code={rc}")
                continue

            try:
                chunk = os.read(master_fd, 65536)
            except OSError as exc:
                raise EOFError(f"crash PTY read error: {exc}") from exc
            if not chunk:
                raise EOFError("EOF reading from crash PTY")
            buf.extend(chunk)

            pos = buf.find(token_bytes)
            while pos != -1:
                prefix_start = max(0, pos - 6)
                if buf[prefix_start:pos] == b"!echo ":
                    pos = buf.find(token_bytes, pos + len(token_bytes))
                    continue
                after_token = pos + len(token_bytes)
                if prompt_bytes in buf[after_token:]:
                    return buf[:pos].decode("utf-8", errors="replace")
                break

    def _try_interrupt_recover(self, *, budget_sec: float = 3.0) -> bool:
        """在严格 budget_sec（默认 3s）预算内发 SIGINT 尝试恢复 crash> 提示符并排空残余输出。"""
        if self._master_fd is None or self._proc is None or self._proc.poll() is not None:
            return False
        deadline = time.monotonic() + budget_sec
        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(self._proc.pid), signal.SIGINT)  # type: ignore[attr-defined]
            else:
                os.write(self._master_fd, b"\x03")

            remaining = max(0.1, deadline - time.monotonic())
            self._read_until_prompt(timeout=remaining)

            # 短暂排空因旧哨兵排队而紧随到达的残余字节（严格不超过剩余预算）
            drain_until = min(deadline, time.monotonic() + 0.15)
            while time.monotonic() < drain_until:
                rlist, _, _ = select.select([self._master_fd], [], [], 0.03)
                if not rlist:
                    break
                try:
                    if not os.read(self._master_fd, 65536):
                        break
                except OSError:
                    break
            return self._proc.poll() is None
        except Exception:
            return False

    def _drain_nonblocking(self) -> None:
        if self._master_fd is None:
            return
        while True:
            try:
                rlist, _, _ = select.select([self._master_fd], [], [], 0.0)
            except Exception:
                break
            if not rlist:
                break
            try:
                chunk = os.read(self._master_fd, 65536)
                if not chunk:
                    break
            except OSError:
                break

    def _clean_output(self, raw: str, payload_text: str, token: str) -> str:
        text = raw.replace("\r\n", "\n").replace("\r", "\n")
        text = _ANSI_ESCAPE_RE.sub("", text)
        sent_lines = {ln.strip() for ln in payload_text.splitlines() if ln.strip()}
        out_lines: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped == f"!echo {token}" or stripped == token:
                continue
            if stripped == "crash>":
                continue
            if line.startswith("crash> "):
                remainder = line[len("crash> ") :].strip()
                if not remainder or remainder in sent_lines or remainder == f"!echo {token}":
                    continue
                line = line[len("crash> ") :]
            out_lines.append(line)
        return "\n".join(out_lines).strip()

    def _force_kill(self, *, mark_closed: bool = False) -> None:
        proc = self._proc
        if proc is not None:
            if proc.poll() is None:
                try:
                    if hasattr(os, "killpg") and hasattr(os, "getpgid") and hasattr(signal, "SIGKILL"):
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)  # type: ignore[attr-defined]
                    else:
                        proc.kill()
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                try:
                    proc.wait(timeout=2.0)
                except Exception:
                    pass
            self._proc = None

        fd = self._master_fd
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
            self._master_fd = None

        self._loaded_modules.clear()
        self._sync_modules_snapshot()
        if mark_closed:
            self._closed = True


@dataclass
class _SessionSlot:
    key: tuple[str, str]
    session: PersistentCrashSession
    in_use: bool = False


class CrashSessionPool:
    """线程安全的常驻 Crash 会话池，支持多 vmcore 并行、严格 LRU 淘汰与空闲 TTL 回收。"""

    def __init__(
        self,
        config: Optional[CrashSessionConfig] = None,
        *,
        command_builder: Optional[CommandBuilder] = None,
        start_reaper: bool = True,
    ) -> None:
        self.config = config or CrashSessionConfig.from_env()
        self._command_builder = command_builder
        self._cond = threading.Condition(threading.Lock())
        self._slots: OrderedDict[tuple[str, str], list[_SessionSlot]] = OrderedDict()
        self._creating_count = 0
        self._shutdown = False

        self._hits = 0
        self._misses = 0
        self._evictions = 0

        self._stop_event = threading.Event()
        self._reaper_thread: Optional[threading.Thread] = None
        if start_reaper:
            self._reaper_thread = threading.Thread(
                target=self._reaper_loop,
                name="crash-session-reaper",
                daemon=True,
            )
            self._reaper_thread.start()

    @staticmethod
    def _normalize_key(vmcore_path: str, vmlinux_path: str) -> tuple[str, str]:
        return (os.path.realpath(vmcore_path), os.path.realpath(vmlinux_path))

    def _total_slots_locked(self) -> int:
        return sum(len(s) for s in self._slots.values()) + self._creating_count

    def _acquire_slot(self, vmcore_path: str, vmlinux_path: str) -> _SessionSlot:
        key = self._normalize_key(vmcore_path, vmlinux_path)
        deadline = time.monotonic() + self.config.acquire_timeout_sec
        to_close: list[PersistentCrashSession] = []

        with self._cond:
            while True:
                if self._shutdown:
                    raise RuntimeError("CrashSessionPool has been shut down")

                key_slots = self._slots.get(key, [])
                # 1. 优先复用该 vmcore 最近使用的空闲槽位（热点缓存命中）
                idle_key_slots = [s for s in key_slots if not s.in_use]
                if idle_key_slots:
                    slot = max(idle_key_slots, key=lambda s: s.session.last_used_at)
                    slot.in_use = True
                    self._slots.move_to_end(key)
                    self._hits += 1
                    return slot

                # 2. 若该 vmcore 尚未达到单库槽位上限，尝试新建（必要时先全局 LRU 淘汰）
                can_create_for_key = len(key_slots) < self.config.slots_per_vmcore
                if can_create_for_key:
                    if self._total_slots_locked() >= self.config.max_total_sessions:
                        evicted = self._evict_lru_idle_locked(exclude_key=key)
                        if evicted is not None:
                            to_close.append(evicted)

                    if self._total_slots_locked() < self.config.max_total_sessions:
                        self._creating_count += 1
                        self._misses += 1
                        break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"Timed out after {self.config.acquire_timeout_sec}s waiting for "
                        f"an available crash session slot (max_total_sessions={self.config.max_total_sessions})."
                    )
                self._cond.wait(timeout=min(remaining, 0.5))

        for old_sess in to_close:
            old_sess.close()

        try:
            session = PersistentCrashSession(
                vmcore_path=vmcore_path,
                vmlinux_path=vmlinux_path,
                config=self.config,
                command_builder=self._command_builder,
            )
        except Exception:
            with self._cond:
                self._creating_count -= 1
                self._cond.notify_all()
            raise

        slot = _SessionSlot(key=key, session=session, in_use=True)
        with self._cond:
            self._creating_count -= 1
            self._slots.setdefault(key, []).append(slot)
            self._slots.move_to_end(key)
            self._cond.notify_all()
        return slot

    def _release_slot(self, slot: _SessionSlot) -> None:
        with self._cond:
            slot.in_use = False
            if slot.key in self._slots:
                self._slots.move_to_end(slot.key)
            self._cond.notify_all()

    def _evict_lru_idle_locked(
        self, *, exclude_key: Optional[tuple[str, str]] = None
    ) -> Optional[PersistentCrashSession]:
        """在所有空闲槽位中按 session.last_used_at 最小者淘汰（严格全局 LRU，兼容多槽位）。"""
        best_key: Optional[tuple[str, str]] = None
        best_idx = -1
        best_ts = float("inf")

        for k, slot_list in self._slots.items():
            if k == exclude_key:
                continue
            for idx, slot in enumerate(slot_list):
                if not slot.in_use and slot.session.last_used_at < best_ts:
                    best_ts = slot.session.last_used_at
                    best_key = k
                    best_idx = idx

        if best_key is None:
            return None

        slot_list = self._slots[best_key]
        removed = slot_list.pop(best_idx)
        if not slot_list:
            del self._slots[best_key]
        self._evictions += 1
        return removed.session

    def execute(
        self,
        command_or_script: str,
        vmcore_path: str,
        vmlinux_path: str,
        *,
        is_script: bool = False,
        timeout: Optional[float] = None,
        verbose: bool = False,
    ) -> str:
        """借出对应 vmcore 的常驻会话执行命令并在完成后归还。"""
        slot = self._acquire_slot(vmcore_path, vmlinux_path)
        try:
            return slot.session.execute(
                command_or_script,
                is_script=is_script,
                timeout=timeout,
                verbose=verbose,
            )
        finally:
            self._release_slot(slot)

    def evict(self, vmcore_path: str, vmlinux_path: str) -> int:
        """主动释放指定 (vmcore, vmlinux) 的所有空闲常驻会话。"""
        key = self._normalize_key(vmcore_path, vmlinux_path)
        to_close: list[PersistentCrashSession] = []
        with self._cond:
            slot_list = self._slots.get(key, [])
            remaining: list[_SessionSlot] = []
            for slot in slot_list:
                if not slot.in_use:
                    to_close.append(slot.session)
                else:
                    remaining.append(slot)
            if remaining:
                self._slots[key] = remaining
            elif key in self._slots:
                del self._slots[key]
            self._cond.notify_all()

        for sess in to_close:
            sess.close()
        return len(to_close)

    def evict_all_idle(self) -> int:
        """主动释放池内所有当前空闲的常驻会话（不关闭会话池本身，不影响后续 /execute）。"""
        to_close: list[PersistentCrashSession] = []
        with self._cond:
            for key, slot_list in list(self._slots.items()):
                busy: list[_SessionSlot] = []
                for slot in slot_list:
                    if not slot.in_use:
                        to_close.append(slot.session)
                    else:
                        busy.append(slot)
                if busy:
                    self._slots[key] = busy
                else:
                    del self._slots[key]
            if to_close:
                self._cond.notify_all()

        for sess in to_close:
            sess.close()
        return len(to_close)

    def reap_idle(self) -> int:
        """回收所有超过 idle_ttl_sec 的空闲会话。"""
        now = time.monotonic()
        to_close: list[PersistentCrashSession] = []
        with self._cond:
            for key, slot_list in list(self._slots.items()):
                kept: list[_SessionSlot] = []
                for slot in slot_list:
                    idle_for = now - slot.session.last_used_at
                    if not slot.in_use and (
                        idle_for >= self.config.idle_ttl_sec or not slot.session.is_alive()
                    ):
                        to_close.append(slot.session)
                    else:
                        kept.append(slot)
                if kept:
                    self._slots[key] = kept
                else:
                    del self._slots[key]
            if to_close:
                self._cond.notify_all()

        for sess in to_close:
            sess.close()
        return len(to_close)

    def _reaper_loop(self) -> None:
        while not self._stop_event.wait(self.config.reap_interval_sec):
            try:
                reaped = self.reap_idle()
                if reaped:
                    _get_logger().info("Reaped %d idle crash session(s).", reaped)
            except Exception as exc:
                _get_logger().warning("Error in crash session reaper: %s", exc)

    def stats(self) -> dict[str, Any]:
        """返回会话池实时状态，用于 /health 监控（使用无锁快照，无跨锁竞态）。"""
        now = time.monotonic()
        with self._cond:
            sessions_info = []
            for (vmcore, vmlinux), slot_list in self._slots.items():
                for slot in slot_list:
                    sess = slot.session
                    loaded_mods = (
                        sess.loaded_modules_snapshot()
                        if hasattr(sess, "loaded_modules_snapshot")
                        else sorted(getattr(sess, "_loaded_modules", {}).keys())
                    )
                    sessions_info.append(
                        {
                            "vmcore_path": vmcore,
                            "vmlinux_path": vmlinux,
                            "pid": sess.pid,
                            "alive": sess.is_alive(),
                            "in_use": slot.in_use,
                            "rss_kb": sess.rss_kb(),
                            "command_count": sess.command_count,
                            "restart_count": sess.restart_count,
                            "loaded_modules": loaded_mods,
                            "idle_sec": round(now - sess.last_used_at, 1),
                        }
                    )
            return {
                "active_sessions": len(sessions_info),
                "max_total_sessions": self.config.max_total_sessions,
                "slots_per_vmcore": self.config.slots_per_vmcore,
                "idle_ttl_sec": self.config.idle_ttl_sec,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "sessions": sessions_info,
            }

    def close_all(self) -> None:
        """关闭所有常驻 crash 进程并停止后台回收线程。"""
        self._stop_event.set()
        to_close: list[PersistentCrashSession] = []
        with self._cond:
            self._shutdown = True
            for slot_list in self._slots.values():
                for slot in slot_list:
                    to_close.append(slot.session)
            self._slots.clear()
            self._cond.notify_all()

        for sess in to_close:
            sess.close()


_default_pool_lock = threading.Lock()
_default_pool: Optional[CrashSessionPool] = None


def get_default_pool() -> CrashSessionPool:
    global _default_pool
    with _default_pool_lock:
        if _default_pool is None:
            _default_pool = CrashSessionPool(CrashSessionConfig.from_env())
        return _default_pool


def shutdown_default_pool() -> None:
    global _default_pool
    with _default_pool_lock:
        if _default_pool is not None:
            _default_pool.close_all()
            _default_pool = None


atexit.register(shutdown_default_pool)
