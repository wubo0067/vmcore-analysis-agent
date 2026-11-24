#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression test for Linux PR_SET_PDEATHSIG survival across short-lived threads
and CrashDaemonServer requests.

Mock crash 进程启动后显式调用 Linux `prctl(PR_SET_PDEATHSIG, SIGHUP)` 并注册
SIGHUP 处理器（收到即 exit(1)），完全复现真实 RHEL 9 `crash` 行为：
1. 在短命线程中通过 CrashSessionPool 首次创建 crash，随后等待该短命线程彻底退出；
2. 验证 crash 进程不会收到 SIGHUP、保持存活且后续复用同一 PID（restart_count == 0）；
3. 通过 CrashDaemonServer (Unix Socket) 连续并发请求，验证 hits 递增、misses == 1、alive == True。
"""

from __future__ import annotations

import concurrent.futures
import os
import sys
import tempfile
import textwrap
import threading
import time
import unittest

from src.mcp_tools.crash.daemon import (
    CrashDaemonClient,
    CrashDaemonServer,
    _UNIX_SOCKET_AVAILABLE,
)
from src.mcp_tools.crash.session_pool import (
    CrashSessionConfig,
    CrashSessionPool,
    is_pty_available,
)

MOCK_PDEATHSIG_CRASH = textwrap.dedent(
    """\
    import ctypes, os, signal, sys

    # 复现真实 crash：注册 Linux PR_SET_PDEATHSIG(SIGHUP)，收到后立即 exit(1)
    PR_SET_PDEATHSIG = 1
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGHUP)
    except Exception:
        pass

    def _on_sighup(signum, frame):
        sys.exit(1)

    signal.signal(signal.SIGHUP, _on_sighup)

    sys.stdout.write("crash 8.0.4\\nSTATE: TASK_RUNNING\\n\\ncrash> ")
    sys.stdout.flush()

    while True:
        line = sys.stdin.readline()
        if not line:
            break
        cmd = line.strip()
        if not cmd:
            sys.stdout.write("crash> ")
            sys.stdout.flush()
            continue
        if cmd in ("quit", "q"):
            sys.exit(0)
        if cmd.startswith("!echo "):
            sys.stdout.write(cmd[6:] + "\\n")
        elif cmd == "set scroll off":
            sys.stdout.write("scroll: off\\n")
        elif cmd == "pid":
            sys.stdout.write(f"PID={os.getpid()}\\n")
        else:
            sys.stdout.write(f"OUT:{cmd}\\n")
        sys.stdout.write("crash> ")
        sys.stdout.flush()
    """
)


@unittest.skipUnless(
    is_pty_available() and sys.platform.startswith("linux"),
    "Requires Linux POSIX PTY and PR_SET_PDEATHSIG",
)
class CrashPdeathsigRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="crash_pdeathsig_test_")
        self._script = os.path.join(self._tmpdir.name, "mock_pdeathsig_crash.py")
        with open(self._script, "w", encoding="utf-8") as f:
            f.write(MOCK_PDEATHSIG_CRASH)
        self.vmcore = os.path.join(self._tmpdir.name, "vmcore")
        self.vmlinux = os.path.join(self._tmpdir.name, "vmlinux")
        for p in (self.vmcore, self.vmlinux):
            with open(p, "w", encoding="utf-8") as f:
                f.write("dummy")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _builder(self, _bin: str, vmlinux: str, vmcore: str) -> list[str]:
        return [sys.executable, "-u", self._script, vmlinux, vmcore]

    def test_crash_survives_short_lived_caller_thread_exit(self) -> None:
        cfg = CrashSessionConfig(command_timeout_sec=5.0, startup_timeout_sec=5.0)
        pool = CrashSessionPool(cfg, command_builder=self._builder, start_reaper=False)
        try:
            first_out: list[str] = []

            def short_lived_worker() -> None:
                first_out.append(pool.execute("pid", self.vmcore, self.vmlinux))

            t = threading.Thread(target=short_lived_worker)
            t.start()
            t.join(timeout=10.0)
            self.assertFalse(t.is_alive())

            # 短命线程已彻底退出；等待 0.3s 确认不会触发 PR_SET_PDEATHSIG
            time.sleep(0.3)
            st = pool.stats()
            self.assertEqual(st["active_sessions"], 1)
            self.assertTrue(st["sessions"][0]["alive"])

            second_out = pool.execute("pid", self.vmcore, self.vmlinux)
            self.assertEqual(first_out[0], second_out)
            self.assertEqual(pool.stats()["sessions"][0]["restart_count"], 0)
            self.assertEqual(pool.stats()["hits"], 1)
            self.assertEqual(pool.stats()["misses"], 1)
        finally:
            pool.close_all()

    @unittest.skipUnless(_UNIX_SOCKET_AVAILABLE, "Requires AF_UNIX")
    def test_daemon_concurrent_requests_reuse_single_pid(self) -> None:
        sock = os.path.join(self._tmpdir.name, "crashd.sock")
        endpoint = f"unix://{sock}"
        cfg = CrashSessionConfig(command_timeout_sec=5.0, startup_timeout_sec=5.0)
        pool = CrashSessionPool(cfg, command_builder=self._builder, start_reaper=False)
        srv = CrashDaemonServer(endpoint=endpoint, pool=pool)
        srv.start_background()
        try:
            client = CrashDaemonClient(endpoint)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                futs = [
                    ex.submit(client.execute, "pid", self.vmcore, self.vmlinux)
                    for _ in range(4)
                ]
                outs = [f.result() for f in futs]

            # 4 次并发请求全部命中同一个常驻 crash PID，零重启
            self.assertEqual(len(set(outs)), 1)
            time.sleep(0.3)
            health = client.health()["pool"]
            self.assertEqual(health["hits"], 3)
            self.assertEqual(health["misses"], 1)
            self.assertTrue(health["sessions"][0]["alive"])
            self.assertEqual(health["sessions"][0]["restart_count"], 0)
        finally:
            srv.shutdown()
            pool.close_all()


if __name__ == "__main__":
    unittest.main()
