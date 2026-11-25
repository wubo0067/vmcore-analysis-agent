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

from concurrent.futures import Future
import os
import queue
import re
import select
import signal
import subprocess
import traceback
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
    acquire_timeout_sec: float = 120.0
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
            acquire_timeout_sec=_env_float("CRASH_POOL_ACQUIRE_TIMEOUT_SEC", 120.0, 0.5),
            max_output_chars=_env_int(
                "CRASH_MAX_OUTPUT_CHARS", DEFAULT_MAX_OUTPUT_CHARS, 1024
            ),
            crash_binary=os.environ.get("CRASH_BINARY", "crash").strip() or "crash",
        )


CommandBuilder = Callable[[str, str, str], list[str]]


class _CrashProcessSpawner:
    """常驻单线程子进程孵化器，彻底规避 Linux PR_SET_PDEATHSIG 线程退出误杀。

    Linux 内核中 PR_SET_PDEATHSIG 绑定的是创建子进程的那条具体内核线程（real_parent），
    而非整个进程。若由短命 HTTP 处理线程或可收缩的线程池线程直接 Popen crash，
    该线程结束瞬间内核就会向 crash 发送父死亡信号（crash 捕获 SIGHUP 后 clean_exit(1)）。
    把所有 crash 子进程统一交给本常驻守护线程孵化，可确保 real_parent 在 Python
    进程整个生命周期内永不退出；进程退出时 PDEATHSIG 反而能兜底清理孤儿 crash。
    结果通过 Future 回传，异常链保持完整。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queue: Optional[
            queue.Queue[tuple[list[str], dict[str, Any], Future[subprocess.Popen[bytes]]]]
        ] = None
        self._thread: Optional[threading.Thread] = None

    def _ensure_started(
        self,
    ) -> queue.Queue[tuple[list[str], dict[str, Any], Future[subprocess.Popen[bytes]]]]:
        with self._lock:
            if self._thread is not None and self._thread.is_alive() and self._queue is not None:
                return self._queue
            q: queue.Queue[
                tuple[list[str], dict[str, Any], Future[subprocess.Popen[bytes]]]
            ] = queue.Queue()
            t = threading.Thread(
                target=self._run,
                args=(q,),
                name="crash-process-spawner",
                daemon=True,
            )
            t.start()
            self._queue = q
            self._thread = t
            return q

    @staticmethod
    def _run(
        q: queue.Queue[tuple[list[str], dict[str, Any], Future[subprocess.Popen[bytes]]]]
    ) -> None:
        _get_logger().info(
            "[crash spawner] resident spawner thread started (tid=%s)",
            threading.get_ident(),
        )
        while True:
            cmd, kwargs, fut = q.get()
            try:
                proc = subprocess.Popen[bytes](cmd, **kwargs)
            except BaseException as exc:
                fut.set_exception(exc)
            else:
                fut.set_result(proc)

    def spawn(self, cmd: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        q = self._ensure_started()
        fut: Future[subprocess.Popen[bytes]] = Future()
        q.put((cmd, kwargs, fut))
        return fut.result()


_process_spawner = _CrashProcessSpawner()


_CRASH_CHILD_ENV_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "TERM",
        "TZ",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LD_LIBRARY_PATH",
        "TERMINFO",
        "USER",
        "LOGNAME",
    }
)
_CRASH_CHILD_ENV_PREFIXES = ("LC_", "LANG", "CRASH_")


def _crash_child_env() -> dict[str, str]:
    """仅向 crash 子进程透传运行时白名单环境变量，隔离 API Key 等敏感配置。"""
    return {
        k: v
        for k, v in os.environ.items()
        if k in _CRASH_CHILD_ENV_KEYS or k.startswith(_CRASH_CHILD_ENV_PREFIXES)
    }


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

        # 单会话 PTY I/O 互斥锁：保证同一 crash 进程同一时刻只有一个线程在
        # 发命令/收输出（execute 串行、restart 重启期间不暴露半初始化状态）。
        # 池层同 vmcore 并发由 _cond/slots 控制，此锁兜底防止直接共享 session
        # 对象时命令与哨兵输出串台；用 RLock 是因为 execute 持锁后会重入调用
        # restart()/_start() 等同样需要该锁的内部方法。
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

    @property
    def is_unusable(self) -> bool:
        """会话已确认无法继续服务（crash 退出且重启失败），池应摘除而非复用。"""
        return self._closed

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
        t0 = time.monotonic()
        master_fd: Optional[int] = None
        slave_fd: Optional[int] = None
        try:
            master_fd, slave_fd = _pty_mod.openpty()
            if _termios_mod is not None:
                try:
                    attrs = _termios_mod.tcgetattr(slave_fd)
                    attrs[3] &= ~_termios_mod.ECHO
                    _termios_mod.tcsetattr(slave_fd, _termios_mod.TCSANOW, attrs)
                    logger.debug(
                        "[session start] pty opened master=%s slave=%s (ECHO disabled on slave)",
                        master_fd,
                        slave_fd,
                    )
                except Exception as termios_exc:
                    # ECHO 关不掉时哨兵解析仍能工作（_find_unlinked_sentinel 会跳过回显），
                    # 但日志要留下线索：回显模式是许多超时问题的根因
                    logger.warning(
                        "[session start] failed to disable PTY ECHO (termios error: %s); "
                        "sentinel parser will need to skip echoed input",
                        termios_exc,
                    )

            cmd = self._command_builder(
                self.config.crash_binary, self.vmlinux_path, self.vmcore_path
            )
            logger.info(
                "[session start] spawning crash: %s (vmcore=%s vmlinux=%s, "
                "startup_timeout=%.1fs)",
                " ".join(cmd),
                self.vmcore_path,
                self.vmlinux_path,
                self.config.startup_timeout_sec,
            )
            proc = _process_spawner.spawn(
                cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=_crash_child_env(),
                close_fds=True,
                start_new_session=True,
            )
            logger.info(
                "[session start] crash spawned pid=%s (%.2fs since _start began)",
                proc.pid,
                time.monotonic() - t0,
            )
        except Exception:
            for fd in (master_fd, slave_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            raise
        finally:
            if slave_fd is not None:
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
            t_prompt = time.monotonic()
            self._read_until_prompt(timeout=self.config.startup_timeout_sec)
            logger.info(
                "[session start] pid=%s crash> prompt ready after %.2fs",
                proc.pid,
                time.monotonic() - t_prompt,
            )
            t_init = time.monotonic()
            self._send_and_collect(
                "set scroll off", timeout=self.config.startup_timeout_sec
            )
            logger.info(
                "[session start] pid=%s 'set scroll off' confirmed after %.2fs",
                proc.pid,
                time.monotonic() - t_init,
            )
            self.last_used_at = time.monotonic()
            logger.info(
                "Started persistent crash session pid=%s for vmcore=%s (total %.2fs)",
                proc.pid,
                self.vmcore_path,
                time.monotonic() - t0,
            )
        except Exception as exc:
            rc = proc.poll()
            logger.error(
                "Failed to initialize persistent crash session pid=%s exit_code=%s for %s "
                "after %.2fs: %s",
                proc.pid,
                rc,
                self.vmcore_path,
                time.monotonic() - t0,
                exc,
            )
            self._force_kill(reason="startup initialization failed")

    def restart(self) -> None:
        """强制清理旧进程并重新拉起常驻 crash 会话。"""
        _get_logger().warning(
            "[session restart] pid=%s vmcore=%s restarting (restart_count will become "
            "%d, loaded mods will be lost: %s)",
            self.pid,
            self.vmcore_path,
            self.restart_count + 1,
            sorted(self._loaded_modules) or "none",
        )
        with self._io_lock:
            self._force_kill(reason="session restart")
            self.restart_count += 1
            self._start()
            _get_logger().info(
                "[session restart] vmcore=%s restarted as pid=%s",
                self.vmcore_path,
                self.pid,
            )

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
            if self._closed:
                # 已确认坏死的会话不再尝试重启，交由池摘除后新建
                logger.warning(
                    "[execute] pid=%s vmcore=%s rejected command '%.80s': session is closed/unusable",
                    self.pid,
                    self.vmcore_path,
                    command_or_script,
                )
                return (
                    f"[CRASH SESSION ERROR] Crash session for {self.vmcore_path} is no "
                    "longer usable; it must be recreated."
                )
            if not self.is_alive():
                logger.warning(
                    "[execute] pid=%s vmcore=%s is not alive before '%.80s'; restarting "
                    "(restart_count=%s)",
                    self.pid,
                    self.vmcore_path,
                    command_or_script,
                    self.restart_count,
                )
                self.restart()

            prepared_lines, pending_mods = self._prepare_lines(
                command_or_script, is_script=is_script
            )
            if not prepared_lines:
                return ""

            payload_text = "\n".join(prepared_lines)
            t_exec = time.monotonic()
            logger.debug(
                "[execute] pid=%s sending '%.120s' (is_script=%s timeout=%.1fs, "
                "pending_mods=%s)",
                self.pid,
                payload_text,
                is_script,
                effective_timeout,
                [m for m, _ in pending_mods] or "none",
            )
            try:
                output = self._send_and_collect(payload_text, timeout=effective_timeout)
                logger.info(
                    "[execute] pid=%s command '%.40s' done in %.2fs (%d chars output)",
                    self.pid,
                    command_or_script,
                    time.monotonic() - t_exec,
                    len(output),
                )
            except TimeoutError as exc:
                logger.error(
                    "[execute] pid=%s command '%.80s' timed out after %.1fs "
                    "(is_script=%s); attempting SIGINT recovery",
                    self.pid,
                    command_or_script,
                    effective_timeout,
                    is_script,
                )
                recovered = self._try_interrupt_recover(budget_sec=3.0)
                if not recovered:
                    logger.warning(
                        "Crash session pid=%s did not recover from SIGINT within 3s; killing for respawn.",
                        self.pid,
                    )
                    self._force_kill(
                        mark_closed=True, reason="timeout SIGINT recovery failed"
                    )
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
                # 会话本身可能已损坏（如 crash 退出、PTY 关闭），清空 mod 缓存避免
                # 复用已失效的符号状态后重建，并只重试一次。
                logger.error(
                    "[execute] pid=%s command '%.80s' failed after %.2fs with %s: %s; "
                    "will restart session and retry once",
                    self.pid,
                    command_or_script,
                    time.monotonic() - t_exec,
                    type(exc).__name__,
                    exc,
                )
                self._loaded_modules.clear()
                self._sync_modules_snapshot()
                logger.warning(
                    "Crash session pid=%s failed (%s); restarting and retrying once.",
                    self.pid,
                    exc,
                )
                try:
                    self.restart()
                except Exception as restart_exc:
                    logger.error(
                        "Crash session restart failed after error (%s): %s",
                        exc,
                        restart_exc,
                    )
                    self._force_kill(
                        mark_closed=True, reason="restart after I/O error failed"
                    )
                    return (
                        f"[CRASH SESSION ERROR] Crash session for {self.vmcore_path} "
                        f"cannot be restarted: {restart_exc} (previous error: {exc})"
                    )
                prepared_lines, pending_mods = self._prepare_lines(
                    command_or_script, is_script=is_script
                )
                logger.info(
                    "[execute] pid=%s restarted (restart_count=%s); retrying command '%.80s'",
                    self.pid,
                    self.restart_count,
                    command_or_script,
                )
                try:
                    t_retry = time.monotonic()
                    output = self._send_and_collect(
                        "\n".join(prepared_lines), timeout=effective_timeout
                    )
                    logger.info(
                        "[execute] pid=%s retry of '%.40s' done in %.2fs (%d chars output)",
                        self.pid,
                        command_or_script,
                        time.monotonic() - t_retry,
                        len(output),
                    )
                except TimeoutError as retry_timeout:
                    logger.error(
                        "[execute] pid=%s retry of '%.80s' timed out after %.1fs: %s",
                        self.pid,
                        command_or_script,
                        effective_timeout,
                        retry_timeout,
                    )
                    self._try_interrupt_recover(budget_sec=3.0)
                    return (
                        f"[TIMEOUT] Command '{command_or_script}' exceeded "
                        f"{int(effective_timeout)}s limit and was interrupted. Use a more "
                        "targeted command or filter the output with grep."
                    )
                except Exception as retry_exc:
                    # 重启后仍失败：明确置为坏死，由池摘除，绝不让上层拿到空结果
                    logger.error(
                        "[execute] pid=%s failed again after restart (%s: %s); marking "
                        "session closed for pool eviction",
                        self.pid,
                        type(retry_exc).__name__,
                        retry_exc,
                    )
                    logger.error(
                        "Crash session pid=%s failed again after restart: %s",
                        self.pid,
                        retry_exc,
                    )
                    self._force_kill(
                        mark_closed=True, reason="retry failed after restart"
                    )
                    return (
                        f"[CRASH SESSION ERROR] Crash session for {self.vmcore_path} "
                        f"cannot be restarted: {retry_exc}"
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

    def close(self, *, reason: str = "unspecified") -> None:
        """优雅退出 crash 进程并释放 PTY 文件描述符。"""
        with self._io_lock:
            if self._closed:
                _get_logger().debug(
                    "[session close] pid=%s already closed; ignored close reason=%s",
                    self.pid,
                    reason,
                )
                return
            self._closed = True
            _get_logger().warning(
                "[session close] pid=%s vmcore=%s closing (uptime %.1fs, "
                "commands executed=%d, reason=%s, caller=%s)",
                self.pid,
                self.vmcore_path,
                time.monotonic() - self.created_at,
                self.command_count,
                reason,
                _close_caller(),
            )
            if (
                self._master_fd is not None
                and self._proc is not None
                and self._proc.poll() is None
            ):
                close_pid = self._proc.pid
                try:
                    os.write(self._master_fd, b"quit\n")
                    rc = self._proc.wait(timeout=3.0)
                    _get_logger().info(
                        "[session close] pid=%s acknowledged quit, exit_code=%s "
                        "(%s, reason=%s)",
                        close_pid,
                        rc,
                        _describe_returncode(rc),
                        reason,
                    )
                except Exception as exc:
                    _get_logger().warning(
                        "[session close] pid=%s graceful quit failed (%s: %s, "
                        "reason=%s); falling back to force kill",
                        close_pid,
                        type(exc).__name__,
                        exc,
                        reason,
                    )
            else:
                _get_logger().warning(
                    "[session close] pid=%s was already not running before quit "
                    "(exit_code=%s, reason=%s)",
                    self.pid,
                    self._proc.poll() if self._proc is not None else "no-process",
                    reason,
                )
            self._force_kill(mark_closed=True, reason=f"close:{reason}")

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
        t_drain = time.monotonic()
        drained = self._drain_nonblocking()
        if drained:
            logger = _get_logger()
            logger.warning(
                "[pty io] pid=%s drained %d residual bytes before sending '%.60s' "
                "(stale output from a previous command was pending)",
                self.pid,
                drained,
                payload_text,
            )

        token = f"__CRASH_DONE_{uuid.uuid4().hex[:12]}__"
        wire = f"{payload_text}\n!echo {token}\n".encode("utf-8")
        t_write = time.monotonic()
        self._write_all(wire)
        logger = _get_logger()
        logger.debug(
            "[pty io] pid=%s wrote %d bytes (token=%s) in %.3fs",
            self.pid,
            len(wire),
            token,
            time.monotonic() - t_write,
        )

        t_read = time.monotonic()
        raw = self._read_until_sentinel(token, timeout=timeout)
        logger.debug(
            "[pty io] pid=%s collected %d raw bytes in %.3fs for token=%s",
            self.pid,
            len(raw),
            time.monotonic() - t_read,
            token,
        )
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
        logger = _get_logger()
        t0 = time.monotonic()
        last_report = t0
        deadline = t0 + timeout
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
                logger.error(
                    "[pty io] pid=%s timed out waiting for crash> prompt after %.1fs; "
                    "received %d bytes so far, last 300 bytes: %r",
                    proc.pid,
                    len(buf),
                    bytes(buf[-300:]).decode("utf-8", errors="replace"),
                )
                raise TimeoutError(
                    f"Timed out waiting for crash> prompt after {timeout:.1f}s ({state_desc})"
                )
            # 每 10s 打一条等待进度日志，用于区分"crash 加载 dump 慢"与"死等"
            now = time.monotonic()
            if now - last_report >= 10.0:
                last_report = now
                logger.info(
                    "[pty io] pid=%s still waiting for crash> prompt (%.0fs elapsed, "
                    "%d bytes received, last 120 bytes: %r)",
                    proc.pid,
                    now - t0,
                    len(buf),
                    bytes(buf[-120:]).decode("utf-8", errors="replace"),
                )
            rlist, _, _ = select.select([master_fd], [], [], min(remaining, 0.25))
            if not rlist:
                rc = proc.poll()
                if rc is not None:
                    logger.error(
                        "[pty io] pid=%s crash exited with exit_code=%s while waiting for "
                        "prompt after %.1fs; last 500 bytes: %r",
                        proc.pid,
                        rc,
                        time.monotonic() - t0,
                        bytes(buf[-500:]).decode("utf-8", errors="replace"),
                    )
                    raise RuntimeError(
                        f"crash exited with exit_code={rc}: "
                        f"{buf.decode('utf-8', errors='replace')[-500:]}"
                    )
                continue
            try:
                chunk = os.read(master_fd, 65536)
            except OSError as exc:
                logger.error(
                    "[pty io] pid=%s PTY read error while waiting for prompt: %s",
                    proc.pid,
                    exc,
                )
                raise EOFError(f"crash PTY closed while waiting for prompt: {exc}") from exc
            if not chunk:
                logger.error(
                    "[pty io] pid=%s EOF reading PTY while waiting for prompt after "
                    "%.1fs; last 300 bytes: %r",
                    proc.pid,
                    time.monotonic() - t0,
                    bytes(buf[-300:]).decode("utf-8", errors="replace"),
                )
                raise EOFError("EOF reading from crash PTY while waiting for prompt")
            buf.extend(chunk)
            if prompt_marker in buf:
                return buf.decode("utf-8", errors="replace")

    @staticmethod
    def _find_unlinked_sentinel(buf: bytearray, token_bytes: bytes) -> int:
        """返回第一处"真实输出"的哨兵位置，跳过 PTY 回显的 `!echo <token>` 副本。

        回显行形如 `crash> !echo <token>`，其后紧跟的 token 前面就是 `!echo `；
        非回显场景下若 crash 提示符还没刷新，上一行的 `crash> ` 之后也可能直接跟着
        回显。只有前面既不是 `!echo ` 也不是行首 `crash> ` 的 token 才算输出结果。
        """
        start = 0
        while True:
            pos = buf.find(token_bytes, start)
            if pos == -1:
                return -1

            prefix_start = max(0, pos - 6)
            if buf[prefix_start:pos] == b"!echo ":
                start = pos + len(token_bytes)
                continue

            line_start = buf.rfind(b"\n", 0, pos) + 1
            if line_start == pos:
                return pos

            line_prefix = bytes(buf[line_start:pos]).strip()
            if line_prefix in (b"", b"crash>", b"!echo", b"crash> !echo"):
                start = pos + len(token_bytes)
                continue

            return pos

    def _read_until_sentinel(self, token: str, *, timeout: float) -> str:
        """持续读取直到出现真实哨兵，且 PTY 回显已完整到达（或出现下一个提示符）。

        只要求"哨兵 + crash> 提示符"会漏掉时序：PTY 在子进程回显前已把哨兵行刷进
        缓冲区，此时末尾还没有 `crash> `，旧实现会一直等下去直到超时，把已经产出
        结果的 `sys`/`mod` 等命令误判为超时。这里接受三种完成条件：
        非回显哨兵后的提示符、完整的命令回显行，以及哨兵自身的完整行（\n 或 \r\n）。
        最后一种覆盖 ECHO 关闭且 crash 尚未刷新下一个提示符的实际时序。
        """
        master_fd, proc = self._require_started()
        logger = _get_logger()
        t0 = time.monotonic()
        last_report = t0
        deadline = t0 + timeout
        buf = bytearray()
        token_bytes = token.encode("utf-8")
        prompt_bytes = b"crash> "
        echo_marker = b"!echo " + token_bytes

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                rc = proc.poll()
                tail = bytes(buf[-400:]).decode("utf-8", errors="replace")
                logger.error(
                    "[pty io] pid=%s timed out waiting for sentinel %s after %.1fs; "
                    "received %d bytes, exit_code=%s, buffer tail: %r",
                    proc.pid,
                    token,
                    timeout,
                    len(buf),
                    rc,
                    tail,
                )
                raise TimeoutError(
                    f"Timed out waiting for sentinel {token} after {timeout:.1f}s "
                    f"(exit_code={rc}) (buffer tail: {tail!r})"
                )

            # 每 10s 打一条等待进度日志，用于区分"命令还在跑"与"卡死"
            now = time.monotonic()
            if now - last_report >= 10.0:
                last_report = now
                logger.info(
                    "[pty io] pid=%s still waiting for sentinel %s (%.0fs/%.0fs elapsed, "
                    "%d bytes received, last 120 bytes: %r)",
                    proc.pid,
                    token,
                    now - t0,
                    timeout,
                    len(buf),
                    bytes(buf[-120:]).decode("utf-8", errors="replace"),
                )

            pos = self._find_unlinked_sentinel(buf, token_bytes)
            if pos != -1:
                after_token = pos + len(token_bytes)
                # 随机 token 已通过 _find_unlinked_sentinel 排除命令回显；独占一行的
                # 哨兵且行尾换行已到，说明 !echo 已执行完成。不能再等下一个 crash>，
                # 因为 crash 的提示符刷新可能晚于子进程 stdout（本问题日志实锤）。
                if buf[after_token:after_token + 1] == b"\n" or (
                    buf[after_token:after_token + 2] == b"\r\n"
                ):
                    logger.debug(
                        "[pty io] pid=%s sentinel %s seen (complete-line) after %.3fs, "
                        "%d bytes",
                        proc.pid,
                        token,
                        time.monotonic() - t0,
                        len(buf),
                    )
                    return buf[:pos].decode("utf-8", errors="replace")
                if prompt_bytes in buf[after_token:]:
                    logger.debug(
                        "[pty io] pid=%s sentinel %s seen (prompt-after) after %.3fs, "
                        "%d bytes",
                        proc.pid,
                        token,
                        time.monotonic() - t0,
                        len(buf),
                    )
                    return buf[:pos].decode("utf-8", errors="replace")
                echo_pos = buf.find(echo_marker)
                if echo_pos != -1 and buf.find(b"\n", echo_pos + len(echo_marker)) != -1:
                    logger.debug(
                        "[pty io] pid=%s sentinel %s seen (echo-complete) after %.3fs, "
                        "%d bytes",
                        proc.pid,
                        token,
                        time.monotonic() - t0,
                        len(buf),
                    )
                    return buf[:pos].decode("utf-8", errors="replace")

            rlist, _, _ = select.select([master_fd], [], [], min(remaining, 0.25))
            if not rlist:
                rc = proc.poll()
                if rc is not None:
                    logger.error(
                        "[pty io] pid=%s crash exited with exit_code=%s while waiting "
                        "for sentinel %s after %.1fs; last 500 bytes: %r",
                        proc.pid,
                        rc,
                        token,
                        time.monotonic() - t0,
                        bytes(buf[-500:]).decode("utf-8", errors="replace"),
                    )
                    raise RuntimeError(f"crash exited unexpectedly with exit_code={rc}")
                continue

            try:
                chunk = os.read(master_fd, 65536)
            except OSError as exc:
                # Errno 5 = slave 端全部关闭 = crash 已退出。崩溃前的错误信息
                # （crash 把 stderr 也写到 PTY）就在 buf 尾部，必须落日志才能定位
                crash_tail = bytes(buf[-800:]).decode("utf-8", errors="replace")
                logger.error(
                    "[pty io] pid=%s PTY read error while waiting for sentinel %s: %s "
                    "(exit_code=%s, crash last output: %r)",
                    proc.pid,
                    token,
                    exc,
                    proc.poll(),
                    crash_tail,
                )
                raise EOFError(f"crash PTY read error: {exc}") from exc
            if not chunk:
                logger.error(
                    "[pty io] pid=%s EOF reading PTY while waiting for sentinel %s "
                    "after %.1fs; last 300 bytes: %r",
                    proc.pid,
                    token,
                    time.monotonic() - t0,
                    bytes(buf[-300:]).decode("utf-8", errors="replace"),
                )
                raise EOFError("EOF reading from crash PTY")
            buf.extend(chunk)

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

    def _drain_nonblocking(self) -> int:
        if self._master_fd is None:
            return 0
        drained = 0
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
            drained += len(chunk)
        return drained

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

    def _force_kill(
        self, *, mark_closed: bool = False, reason: str = "unspecified"
    ) -> None:
        proc = self._proc
        logger = _get_logger()
        if proc is not None:
            rc = proc.poll()
            if rc is None:
                logger.warning(
                    "[session kill] pid=%s vmcore=%s force killing crash process "
                    "(mark_closed=%s, reason=%s)",
                    proc.pid,
                    self.vmcore_path,
                    mark_closed,
                    reason,
                )
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
                    rc = proc.wait(timeout=2.0)
                    logger.warning(
                        "[session kill] pid=%s terminated exit_code=%s (%s, reason=%s)",
                        proc.pid,
                        rc,
                        _describe_returncode(rc),
                        reason,
                    )
                except Exception as exc:
                    logger.error(
                        "[session kill] pid=%s wait after kill failed (%s: %s, reason=%s)",
                        proc.pid,
                        type(exc).__name__,
                        exc,
                        reason,
                    )
            else:
                logger.error(
                    "[session exit] pid=%s crash exited before force kill: exit_code=%s "
                    "(%s, reason=%s)",
                    proc.pid,
                    rc,
                    _describe_returncode(rc),
                    reason,
                )
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


def _describe_returncode(rc: Optional[int]) -> str:
    """把 waitpid 返回码翻译成可读原因，尤其是致命信号。"""
    if rc is None:
        return "still running"
    if rc < 0:
        signum = -rc
        try:
            signal_name = signal.Signals(signum).name
        except ValueError:
            signal_name = f"signal {signum}"
        return f"terminated by {signal_name}"
    return "normal exit" if rc == 0 else "nonzero exit"


def _close_caller() -> str:
    """返回首个项目内的关闭调用点，定位谁结束了常驻会话。"""
    current_file = os.path.realpath(__file__)
    for frame in reversed(traceback.extract_stack()):
        frame_path = os.path.realpath(frame.filename)
        if frame_path != current_file and "importlib" not in frame_path:
            return f"{frame.filename}:{frame.lineno} {frame.name}"
    return "unknown"


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
        # 按 key 的"创建中"计数：防止同一 vmcore 并发创建多个会话突破 slots_per_vmcore
        self._creating_by_key: dict[tuple[str, str], int] = {}
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
        """借出一个绑定到 (vmcore, vmlinux) 的会话槽位（阻塞，直到拿到槽位或超时）。

        获取优先级：复用空闲槽位 > 新建槽位 > 等待他人归还。
        注意：真正关闭被淘汰会话（close）和新建 crash 进程这两类耗时/可能阻塞的操作
        必须放在 _cond 锁外执行，否则会长时间持锁阻塞其他线程的 acquire/release。
        """
        # key 用 realpath 归一化：符号链接/相对路径指向同一 vmcore 时能命中同一组槽位
        key = self._normalize_key(vmcore_path, vmlinux_path)
        logger = _get_logger()
        t_acquire = time.monotonic()
        # 获取槽位的绝对截止时间（monotonic 时钟，不受系统时间跳变影响）
        deadline = time.monotonic() + self.config.acquire_timeout_sec
        # 锁外待关闭的会话：先在锁内摘除引用，出锁后再统一 close，避免持锁执行阻塞 I/O
        to_close: list[PersistentCrashSession] = []

        with self._cond:
            while True:
                if self._shutdown:
                    raise RuntimeError("CrashSessionPool has been shut down")

                key_slots = self._slots.get(key, [])
                # 1. 优先复用该 vmcore 最近使用的空闲槽位（热点缓存命中）。
                #    选 last_used_at 最大的空闲槽位：保留"最新鲜"的会话（其 mod 缓存
                #    等状态更可能仍有效），同时避免多个等待者集中抢同一个旧槽位。
                idle_key_slots = [s for s in key_slots if not s.in_use]
                if idle_key_slots:
                    slot = max(idle_key_slots, key=lambda s: s.session.last_used_at)
                    slot.in_use = True
                    # move_to_end 维护 OrderedDict 的 LRU 顺序：越活跃的 key 越靠尾部，
                    # 全局淘汰时从头部（最久未用）开始扫
                    self._slots.move_to_end(key)
                    self._hits += 1
                    logger.debug(
                        "[pool acquire] reuse idle slot pid=%s for vmcore=%s "
                        "(waited %.3fs, hits=%d, misses=%d)",
                        slot.session.pid,
                        vmcore_path,
                        time.monotonic() - t_acquire,
                        self._hits,
                        self._misses,
                    )
                    return slot

                # 2. 若该 vmcore 尚未达到单库槽位上限，尝试新建（必要时先全局 LRU 淘汰腾位）。
                #    注意：已计入 key 的"创建中"会话也占用 key 配额（_creating_by_key），
                #    否则第一个线程在锁外耗数分钟创建 crash 期间，后续线程会因
                #    key_slots 尚为空而给同一 vmcore 重复并发新建多个 crash 进程。
                can_create_for_key = len(key_slots) + self._creating_by_key.get(key, 0) < (
                    self.config.slots_per_vmcore
                )
                if can_create_for_key:
                    # 全局总槽位已满时，先淘汰一个"别的 vmcore"的最近未用空闲会话。
                    # exclude_key=self key：不能淘汰目标 vmcore 自己的会话（可能与
                    # 并发等待者互相踢皮球导致活锁）。
                    if self._total_slots_locked() >= self.config.max_total_sessions:
                        evicted = self._evict_lru_idle_locked(exclude_key=key)
                        if evicted is not None:
                            to_close.append(evicted)

                    # 淘汰腾位成功（或原本未满）才真正新建；_creating_count 计入总占用，
                    # 防止并发线程在创建期间把总槽位超额建满。
                    if self._total_slots_locked() < self.config.max_total_sessions:
                        self._creating_count += 1
                        self._creating_by_key[key] = (
                            self._creating_by_key.get(key, 0) + 1
                        )
                        self._misses += 1
                        logger.info(
                            "[pool acquire] creating NEW crash session for vmcore=%s "
                            "vmlinux=%s (waited %.3fs; existing key slots=%d, "
                            "creating-for-key=%d, total occupied=%d/%d)",
                            vmcore_path,
                            vmlinux_path,
                            time.monotonic() - t_acquire,
                            len(key_slots),
                            self._creating_by_key.get(key, 0),
                            self._total_slots_locked(),
                            self.config.max_total_sessions,
                        )
                        # break 跳出锁内循环，转入锁外执行"关闭被淘汰会话 + 新建会话"
                        break

                # 3. 无空闲槽位且无法新建：等待其他线程 release / 创建失败通知。
                #    remaining <= 0 说明整体超时（常见于所有槽位都被长时间占用的命令卡住）。
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    logger.error(
                        "[pool acquire] timed out after %.1fs waiting for a session slot "
                        "for vmcore=%s (key slots=%d, creating-for-key=%d, "
                        "creating-global=%d, total occupied=%d/%d)",
                        self.config.acquire_timeout_sec,
                        vmcore_path,
                        len(key_slots),
                        self._creating_by_key.get(key, 0),
                        self._creating_count,
                        self._total_slots_locked(),
                        self.config.max_total_sessions,
                    )
                    raise TimeoutError(
                        f"Timed out after {self.config.acquire_timeout_sec}s waiting for "
                        f"an available crash session slot (max_total_sessions={self.config.max_total_sessions})."
                    )
                # 用带超时的 wait 而非无限 wait：即使错过某次 notify_all 也能定期
                # 醒来重新评估；同时保证不超过 deadline
                self._cond.wait(timeout=min(remaining, 0.5))

        # ---- 以下均在 _cond 锁外执行 ----

        # 关闭被淘汰的旧会话（crash 进程退出可能耗时，绝不持锁做）
        for old_sess in to_close:
            old_sess.close(reason="pool LRU eviction during acquire")

        # 新建常驻 crash 进程（PTY 启动 + 等待 crash> 提示符，可达 startup_timeout 秒）
        try:
            session = PersistentCrashSession(
                vmcore_path=vmcore_path,
                vmlinux_path=vmlinux_path,
                config=self.config,
                command_builder=self._command_builder,
            )
        except Exception:
            # 创建失败：归还配额（全局 + 按 key）并唤醒所有等待者（它们可重新尝试抢占或新建）
            logger.error(
                "[pool acquire] crash session creation FAILED for vmcore=%s after "
                "%.1fs; releasing quota and waking waiters",
                vmcore_path,
                time.monotonic() - t_acquire,
            )
            with self._cond:
                self._creating_count -= 1
                self._release_creating_for_key_locked(key)
                self._cond.notify_all()
            raise

        slot = _SessionSlot(key=key, session=session, in_use=True)
        with self._cond:
            self._creating_count -= 1
            self._release_creating_for_key_locked(key)
            self._slots.setdefault(key, []).append(slot)
            self._slots.move_to_end(key)
            # 唤醒等待者：总槽位变化（新建完成/失败）可能让它们的状态判断改变
            self._cond.notify_all()
        logger.info(
            "[pool acquire] created crash session pid=%s for vmcore=%s in %.1fs",
            session.pid,
            vmcore_path,
            time.monotonic() - t_acquire,
        )
        return slot

    def _release_creating_for_key_locked(self, key: tuple[str, str]) -> None:
        """归还按 key 的创建配额。前置条件：调用方已持有 self._cond 锁。"""
        remaining = self._creating_by_key.get(key, 0) - 1
        if remaining > 0:
            self._creating_by_key[key] = remaining
        else:
            self._creating_by_key.pop(key, None)

    def _release_slot(self, slot: _SessionSlot) -> None:
        """归还槽位：标记空闲、维持 LRU 顺序，并唤醒正在等待槽位的 acquire 线程。"""
        with self._cond:
            slot.in_use = False
            if slot.key in self._slots:
                self._slots.move_to_end(slot.key)
            # 关键：唤醒所有 _acquire_slot 中 wait 的线程，让它们重新竞争这个空闲槽位
            self._cond.notify_all()

    def _evict_lru_idle_locked(
        self, *, exclude_key: Optional[tuple[str, str]] = None
    ) -> Optional[PersistentCrashSession]:
        """在所有空闲槽位中按 session.last_used_at 最小者淘汰（严格全局 LRU，兼容多槽位）。

        前置条件：调用方必须已持有 self._cond 锁（方法名后缀 _locked 即此约定）。
        只淘汰空闲（in_use=False）会话，绝不碰正在执行命令的会话；
        exclude_key 用于排除目标 vmcore 自身的槽位。
        返回被摘除的 PersistentCrashSession（由调用方在锁外 close），无可淘汰时返回 None。
        """
        best_key: Optional[tuple[str, str]] = None
        best_idx = -1
        best_ts = float("inf")

        # 线性扫描所有 key 的所有槽位找全局最久未用的空闲会话。
        # 槽位总数受 max_total_sessions 约束（默认个位数），扫描成本可忽略。
        for k, slot_list in self._slots.items():
            if k == exclude_key:
                continue
            for idx, slot in enumerate(slot_list):
                if not slot.in_use and slot.session.last_used_at < best_ts:
                    best_ts = slot.session.last_used_at
                    best_key = k
                    best_idx = idx

        if best_key is None:
            # 没有任何可淘汰的空闲会话（例如全部都在执行命令）
            return None

        # 从槽位表中摘除该槽位；若该 vmcore 的槽位列表因此变空则整个 key 移除
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
        logger = _get_logger()
        t_total = time.monotonic()
        slot = self._acquire_slot(vmcore_path, vmlinux_path)
        t_acquired = time.monotonic()
        logger.info(
            "[pool execute] vmcore=%s session pid=%s acquired in %.3fs, executing "
            "'%.80s' (is_script=%s timeout=%s)",
            vmcore_path,
            slot.session.pid,
            t_acquired - t_total,
            command_or_script,
            is_script,
            timeout,
        )
        try:
            session = slot.session
            output = session.execute(
                command_or_script,
                is_script=is_script,
                timeout=timeout,
                verbose=verbose,
            )
        finally:
            self._release_slot(slot)

        # 会话内部已确认坏死（crash 退出且重启失败）时主动摘除，避免后续命令反复复用
        if session.is_unusable:
            logger.warning(
                "[pool execute] vmcore=%s session pid=%s is unusable after '%.80s'; "
                "dropping slot from pool",
                vmcore_path,
                session.pid,
                command_or_script,
            )
            self._drop_slot(slot)
        logger.debug(
            "[pool execute] vmcore=%s session pid=%s command done in %.3fs total "
            "(%d chars output)",
            vmcore_path,
            session.pid,
            time.monotonic() - t_total,
            len(output),
        )
        return output

    def _drop_slot(self, slot: "_SessionSlot") -> None:
        """将已失效的槽位从池中摘除并在锁外关闭其会话。"""
        _get_logger().warning(
            "[pool evict] dropping dead slot pid=%s for vmcore key=%s",
            slot.session.pid,
            slot.key,
        )
        with self._cond:
            slot_list = self._slots.get(slot.key, [])
            if slot in slot_list:
                slot_list.remove(slot)
                if not slot_list:
                    del self._slots[slot.key]
            self._cond.notify_all()
        slot.session.close(reason="unusable session dropped after execution")

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
            sess.close(reason="explicit evict vmcore/vmlinux")
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
            sess.close(reason="explicit evict all idle sessions")
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
            sess.close(reason="idle TTL reaper or dead process reaper")
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
                "command_timeout_sec": self.config.command_timeout_sec,
                "startup_timeout_sec": self.config.startup_timeout_sec,
                "acquire_timeout_sec": self.config.acquire_timeout_sec,
                "max_output_chars": self.config.max_output_chars,
                "crash_binary": self.config.crash_binary,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "sessions": sessions_info,
            }

    def close_all(self) -> None:
        """关闭所有常驻 crash 进程并停止后台回收线程。"""
        _get_logger().warning(
            "[pool shutdown] close_all requested: stopping reaper and closing all "
            "sessions (caller=%s)",
            _close_caller(),
        )
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
            sess.close(reason="pool close_all / process shutdown")
