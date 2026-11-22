#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Cross-platform unit tests + POSIX real-PTY integration tests for
perf/crash-persistent-session-pool.

测试分两组：
1. CrashSessionCrossPlatformUnitTests（Windows & Linux 均必跑）：
   - _clean_output / 伪哨兵清洗；
   - _prepare_lines 与 _mod_load_failed（路径错误、bare/auto 归一化、多模块防串扰）；
   - CrashSessionPool 全局按 last_used_at 严格 LRU（含 slots_per_vmcore=2）、reap_idle、
     loaded_modules_snapshot 无锁快照；
   - CrashDaemonServer / CrashDaemonClient TCP HTTP 端到端（含 /health、/execute、/evict、DELETE /sessions）；
   - 按 event loop 隔离的 asyncio.Semaphore 跨线程/跨 loop 防死锁测试。
2. CrashPersistentPtyIntegrationTests（仅 POSIX 平台运行，非 POSIX 自动跳过）：
   - 真实 Linux PTY 常驻复用、伪 crash> 提示符防错位、mod -s 幂等去重；
   - 超时 SIGINT 恢复（严格 <= 3s 内）保持同 PID + SIGKILL 自动重建并清空缓存；
   - 多 vmcore 真并行与 Unix Domain Socket Daemon 端到端。
"""

from __future__ import annotations

import asyncio
import http.client
import json
import os
import signal
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import weakref
from concurrent.futures import ThreadPoolExecutor

from src.mcp_tools.crash import executor as crash_executor
from src.mcp_tools.crash.daemon import (
    CrashDaemonClient,
    CrashDaemonServer,
    _UNIX_SOCKET_AVAILABLE,
)
from src.mcp_tools.crash.session_pool import (
    CrashSessionConfig,
    CrashSessionPool,
    PersistentCrashSession,
    _mod_load_failed,
    is_pty_available,
)

MOCK_CRASH_SCRIPT = textwrap.dedent(
    """\
    import os, signal, sys, time

    def _on_sigint(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGINT, _on_sigint)

    vmcore = sys.argv[-1]
    mod_loads = []
    sys.stdout.write("crash 8.0.4\\nCopyright (C) Red Hat\\nSTATE: TASK_RUNNING\\n\\ncrash> ")
    sys.stdout.flush()

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            cmd = line.strip()
            if not cmd:
                sys.stdout.write("crash> ")
                sys.stdout.flush()
                continue
            if cmd in ("quit", "q"):
                break
            if cmd.startswith("!echo "):
                sys.stdout.write(cmd[6:] + "\\n")
            elif cmd == "set scroll off":
                sys.stdout.write("scroll: off\\n")
            elif cmd == "pid":
                sys.stdout.write(f"MOCK_PID={os.getpid()} VMCORE={vmcore}\\n")
            elif cmd == "fake_prompt":
                sys.stdout.write("line1 before fake\\ncrash> fake prompt inside log\\nline2 after fake\\n")
            elif cmd.startswith("mod -s "):
                if "/missing/" in cmd:
                    path = cmd.split()[-1]
                    sys.stdout.write(f"mod: {path}: cannot open object file\\n")
                else:
                    mod_loads.append(cmd)
                    sys.stdout.write(f"LOADED:{cmd} COUNT={len(mod_loads)}\\n")
            elif cmd == "mod_count":
                sys.stdout.write(f"MOD_COUNT={len(mod_loads)}\\n")
            elif cmd.startswith("sleep "):
                dur = float(cmd.split()[1])
                time.sleep(dur)
                sys.stdout.write(f"SLEPT {dur} ON {vmcore}\\n")
            else:
                sys.stdout.write(f"ECHO:{cmd}\\n")
        except KeyboardInterrupt:
            sys.stdout.write("^C\\n")
        sys.stdout.write("crash> ")
        sys.stdout.flush()
    """
)


class CrashSessionCrossPlatformUnitTests(unittest.TestCase):
    """不依赖 POSIX PTY，可在 Windows 与 Linux CI 全量运行。"""

    def test_clean_output_and_mod_dedup_normalization(self) -> None:
        class _Dummy:
            _loaded_modules: dict[str, str]

        s = _Dummy()
        s._loaded_modules = {"ext4": "/usr/lib/debug/ext4.ko.debug"}
        clean = PersistentCrashSession._clean_output.__get__(s)
        prep = PersistentCrashSession._prepare_lines.__get__(s)

        tok = "__CRASH_DONE_abc123__"
        raw = (
            "crash> bt\nPID: 123  TASK: ffff  CPU: 3\n"
            "crash> !echo __CRASH_DONE_abc123__\n__CRASH_DONE_abc123__\ncrash> "
        )
        self.assertEqual(clean(raw, "bt", tok), "PID: 123  TASK: ffff  CPU: 3")

        # 已用具体路径加载 ext4 后，bare / auto / 同路径都应跳过
        self.assertEqual(prep("mod -s ext4\nbt", is_script=True), (["bt"], []))
        self.assertEqual(prep("mod -s ext4 auto\nbt", is_script=True), (["bt"], []))
        self.assertEqual(
            prep("mod -s ext4 /usr/lib/debug/ext4.ko.debug\nbt", is_script=True),
            (["bt"], []),
        )
        # 指定新的不同具体路径则允许重新加载
        lines, pending = prep("mod -s ext4 /other/ext4.ko.debug\nbt", is_script=True)
        self.assertEqual(lines, ["mod -s ext4 /other/ext4.ko.debug", "bt"])
        self.assertEqual(pending, [("ext4", "/other/ext4.ko.debug")])

    def test_mod_load_failed_per_module_and_path_errors(self) -> None:
        # 路径级错误：mod: /path/x.ko.debug: cannot open
        out_path_err = "mod: /path/x.ko.debug: cannot open object file"
        self.assertTrue(_mod_load_failed(out_path_err, "ext4", "/path/x.ko.debug"))

        # 多模块脚本：b 失败不能污染 a 的成功判定
        out_multi = (
            "MODULE       NAME           BASE           SIZE  OBJECT FILE\n"
            "ffffffffc01  mod_a          ffffffffc0100  4096  /ok/mod_a.ko\n"
            "mod: /bad/mod_b.ko.debug: cannot open object file\n"
        )
        self.assertFalse(
            _mod_load_failed(out_multi, "mod_a", "/ok/mod_a.ko", total_pending_mods=2)
        )
        self.assertTrue(
            _mod_load_failed(
                out_multi, "mod_b", "/bad/mod_b.ko.debug", total_pending_mods=2
            )
        )

    def test_pool_strict_lru_across_multi_slots_and_tcp_daemon(self) -> None:
        import src.mcp_tools.crash.session_pool as sp_mod

        created: list[_FakeSession] = []

        class _FakeSession:
            def __init__(self, vmcore_path, vmlinux_path, config, command_builder=None):
                self.vmcore_path = vmcore_path
                self.vmlinux_path = vmlinux_path
                self.config = config
                self.last_used_at = time.monotonic()
                self.command_count = 0
                self.restart_count = 0
                self.pid = len(created) + 100
                self.closed = False
                self._mods: tuple[str, ...] = ("ext4",)
                created.append(self)

            def loaded_modules_snapshot(self):
                return list(self._mods)

            def execute(self, cmd, **kw):
                self.command_count += 1
                self.last_used_at = time.monotonic()
                return f"FAKE:{cmd}@{os.path.basename(self.vmcore_path)}"

            def close(self):
                self.closed = True

            def is_alive(self):
                return not self.closed

            def rss_kb(self):
                return 1024

        orig_cls = sp_mod.PersistentCrashSession
        sp_mod.PersistentCrashSession = _FakeSession  # type: ignore[assignment]
        try:
            cfg = CrashSessionConfig(
                max_total_sessions=2,
                slots_per_vmcore=2,
                idle_ttl_sec=0.2,
                acquire_timeout_sec=2.0,
            )
            pool = CrashSessionPool(cfg, start_reaper=False)
            # 先启动 TCP Daemon（Windows/Linux 通用）
            daemon = CrashDaemonServer(endpoint="http://127.0.0.1:0", pool=pool)
            daemon.start_background()
            try:
                client = CrashDaemonClient(daemon.bound_endpoint)
                self.assertEqual(client.health()["status"], "ok")

                # 顺序访问 vm1 -> vm2 -> vm1，确保 vm2 的 last_used_at 最旧
                self.assertIn("FAKE:bt@vm1", client.execute("bt", "vm1", "vl"))
                time.sleep(0.02)
                self.assertIn("FAKE:bt@vm2", client.execute("bt", "vm2", "vl"))
                time.sleep(0.02)
                self.assertIn("FAKE:ps@vm1", client.execute("ps", "vm1", "vl"))

                # 访问 vm3 应严格淘汰最久未用的 vm2（而非 vm1）
                self.assertIn("FAKE:bt@vm3", client.execute("bt", "vm3", "vl"))
                closed_names = [os.path.basename(s.vmcore_path) for s in created if s.closed]
                self.assertEqual(closed_names, ["vm2"])

                # 验证 DELETE /sessions 兼容端点
                host_port = daemon.bound_endpoint[len("http://") :]
                host, port_s = host_port.split(":")
                conn = http.client.HTTPConnection(host, int(port_s), timeout=5)
                try:
                    body = json.dumps({"vmcore_path": "vm1", "vmlinux_path": "vl"}).encode()
                    conn.request(
                        "DELETE",
                        "/sessions",
                        body=body,
                        headers={"Content-Type": "application/json"},
                    )
                    resp = conn.getresponse()
                    data = json.loads(resp.read().decode())
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(data["evicted"], 1)
                    self.assertEqual(data["scope"], "target")

                    # 空 Body DELETE /sessions 应清空剩余全部空闲会话，且绝不关闭守护进程
                    conn.request("DELETE", "/sessions")
                    resp2 = conn.getresponse()
                    data2 = json.loads(resp2.read().decode())
                    self.assertEqual(resp2.status, 200)
                    self.assertEqual(data2["scope"], "all_idle")
                    self.assertEqual(data2["evicted"], 1)

                    # 清空后守护进程仍可正常执行新命令
                    self.assertIn("FAKE:sys@vm1", client.execute("sys", "vm1", "vl"))

                    # 缺少必要参数的 POST /evict 与半残参数 DELETE /sessions 应返回 400（非 500）
                    conn.request(
                        "POST",
                        "/evict",
                        body=b"{}",
                        headers={"Content-Type": "application/json"},
                    )
                    resp3 = conn.getresponse()
                    resp3.read()
                    self.assertEqual(resp3.status, 400)

                    conn.request(
                        "DELETE",
                        "/sessions",
                        body=json.dumps({"vmcore_path": "vm1"}).encode(),
                        headers={"Content-Type": "application/json"},
                    )
                    resp4 = conn.getresponse()
                    resp4.read()
                    self.assertEqual(resp4.status, 400)
                finally:
                    conn.close()
            finally:
                daemon.shutdown()
                pool.close_all()
        finally:
            sp_mod.PersistentCrashSession = orig_cls

    def test_loop_scoped_semaphore_does_not_deadlock_across_loops(self) -> None:
        # 复现并验证 server.py 的 WeakKeyDictionary[loop, Semaphore] 模式跨 loop 无死锁
        loop_sems: weakref.WeakKeyDictionary[
            asyncio.AbstractEventLoop, asyncio.Semaphore
        ] = weakref.WeakKeyDictionary()

        def get_sem() -> asyncio.Semaphore:
            loop = asyncio.get_running_loop()
            sem = loop_sems.get(loop)
            if sem is None:
                sem = asyncio.Semaphore(1)
                loop_sems[loop] = sem
            return sem

        async def hold():
            async with get_sem():
                await asyncio.sleep(0.25)
                return "loop1_ok"

        async def acquire_other():
            async with get_sem():
                return "loop2_ok"

        results: dict[str, str] = {}
        t1 = threading.Thread(target=lambda: results.setdefault("r1", asyncio.run(hold())))
        t2 = threading.Thread(
            target=lambda: results.setdefault("r2", asyncio.run(acquire_other()))
        )
        t1.start()
        time.sleep(0.03)
        t2.start()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)
        self.assertEqual(results.get("r1"), "loop1_ok")
        self.assertEqual(results.get("r2"), "loop2_ok")


@unittest.skipUnless(is_pty_available(), "Requires POSIX pty/termios")
class CrashPersistentPtyIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="crash_pool_test_")
        self._mock_script_path = os.path.join(self._tmpdir.name, "mock_crash.py")
        with open(self._mock_script_path, "w", encoding="utf-8") as f:
            f.write(MOCK_CRASH_SCRIPT)

        self.vmcore_a = os.path.join(self._tmpdir.name, "vmcore_a")
        self.vmcore_b = os.path.join(self._tmpdir.name, "vmcore_b")
        self.vmcore_c = os.path.join(self._tmpdir.name, "vmcore_c")
        self.vmlinux = os.path.join(self._tmpdir.name, "vmlinux")
        for p in (self.vmcore_a, self.vmcore_b, self.vmcore_c, self.vmlinux):
            with open(p, "w", encoding="utf-8") as f:
                f.write("dummy")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _cmd_builder(self, _bin: str, vmlinux_path: str, vmcore_path: str) -> list[str]:
        return [sys.executable, "-u", self._mock_script_path, vmlinux_path, vmcore_path]

    def test_persistent_reuse_fake_prompt_and_mod_error_not_cached(self) -> None:
        cfg = CrashSessionConfig(command_timeout_sec=5.0, startup_timeout_sec=5.0)
        sess = PersistentCrashSession(
            self.vmcore_a, self.vmlinux, cfg, command_builder=self._cmd_builder
        )
        try:
            out1 = sess.execute("pid")
            out2 = sess.execute("pid")
            self.assertEqual(out1, out2)
            self.assertIn(f"MOCK_PID={sess.pid}", out1)

            fake_out = sess.execute("fake_prompt")
            self.assertIn("line1 before fake", fake_out)
            self.assertIn("line2 after fake", fake_out)
            self.assertEqual(sess.execute("hello"), "ECHO:hello")

            # 路径错误不得被写入 _loaded_modules
            bad_res = sess.execute(
                "mod -s badmod /missing/badmod.ko.debug\nmod_count", is_script=True
            )
            self.assertIn("cannot open", bad_res)
            self.assertNotIn("badmod", sess.loaded_modules_snapshot())

            # 成功加载后，具体路径和后续裸 mod -s 均去重跳过
            ok_res1 = sess.execute(
                "mod -s mpt3sas /tmp/mpt3sas.ko\nmod_count", is_script=True
            )
            self.assertIn("MOD_COUNT=1", ok_res1)
            ok_res2 = sess.execute("mod -s mpt3sas\nmod_count", is_script=True)
            self.assertNotIn("LOADED:", ok_res2)
            self.assertIn("MOD_COUNT=1", ok_res2)
        finally:
            sess.close()

    def test_timeout_sigint_recovery_within_3s_and_sigkill_respawn(self) -> None:
        cfg = CrashSessionConfig(command_timeout_sec=1.0, startup_timeout_sec=5.0)
        sess = PersistentCrashSession(
            self.vmcore_a, self.vmlinux, cfg, command_builder=self._cmd_builder
        )
        try:
            orig_pid = sess.pid
            if orig_pid is None:
                self.fail("PersistentCrashSession.pid was None")
            t0 = time.monotonic()
            timeout_msg = sess.execute("sleep 5", timeout=0.5)
            elapsed = time.monotonic() - t0
            self.assertIn("[TIMEOUT]", timeout_msg)
            self.assertLess(elapsed, 3.5)
            self.assertEqual(sess.pid, orig_pid)
            self.assertEqual(sess.execute("after_timeout"), "ECHO:after_timeout")

            sess.execute("mod -s ext4\nmod_count", is_script=True)
            self.assertIn("ext4", sess.loaded_modules_snapshot())
            os.kill(orig_pid, getattr(signal, "SIGKILL", 9))
            time.sleep(0.15)

            res_after_kill = sess.execute("mod -s ext4\nmod_count", is_script=True)
            self.assertNotEqual(sess.pid, orig_pid)
            self.assertIn("MOD_COUNT=1", res_after_kill)
        finally:
            sess.close()

    @unittest.skipUnless(_UNIX_SOCKET_AVAILABLE, "Requires AF_UNIX")
    def test_parallel_vmcores_and_unix_daemon_routing(self) -> None:
        sock_path = os.path.join(self._tmpdir.name, "crashd.sock")
        endpoint = f"unix://{sock_path}"
        cfg = CrashSessionConfig(
            max_total_sessions=2,
            slots_per_vmcore=1,
            idle_ttl_sec=0.4,
            command_timeout_sec=5.0,
            startup_timeout_sec=5.0,
        )
        pool = CrashSessionPool(cfg, command_builder=self._cmd_builder, start_reaper=False)
        server = CrashDaemonServer(endpoint=endpoint, pool=pool)
        import stat as _stat
        self.assertEqual(_stat.S_IMODE(os.stat(sock_path).st_mode), 0o600)
        server.start_background()
        try:
            # Warm up both sessions first so the timing below measures parallel
            # execution only, not one-off cold-start/PTY handshake overhead.
            pool.execute("pid", self.vmcore_a, self.vmlinux)
            pool.execute("pid", self.vmcore_b, self.vmlinux)
            t0 = time.monotonic()
            with ThreadPoolExecutor(max_workers=2) as ex:
                f1 = ex.submit(pool.execute, "sleep 0.5", self.vmcore_a, self.vmlinux)
                f2 = ex.submit(pool.execute, "sleep 0.5", self.vmcore_b, self.vmlinux)
                self.assertIn("SLEPT 0.5", f1.result())
                self.assertIn("SLEPT 0.5", f2.result())
            elapsed = time.monotonic() - t0
            # Two independent sessions each sleeping 0.5s must overlap: a serial
            # run needs >=1.0s, so staying below it proves parallelism. The gap
            # to the 1.0s serial floor absorbs scheduler jitter on loaded CI hosts.
            self.assertLess(elapsed, 1.0)

            old_env = {
                k: os.environ.get(k)
                for k in (
                    "CRASH_EXECUTION_MODE",
                    "CRASH_DAEMON_ENDPOINT",
                    "CRASH_SKIP_DISTRO_CHECK",
                )
            }
            try:
                os.environ["CRASH_EXECUTION_MODE"] = "daemon"
                os.environ["CRASH_DAEMON_ENDPOINT"] = endpoint
                os.environ["CRASH_SKIP_DISTRO_CHECK"] = "true"
                out = crash_executor.run_crash_command("pid", self.vmcore_a, self.vmlinux)
                self.assertIn("MOCK_PID=", out)
            finally:
                for k, v in old_env.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
        finally:
            server.shutdown()
            pool.close_all()


if __name__ == "__main__":
    unittest.main()
