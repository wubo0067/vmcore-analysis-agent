#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# daemon.py - 跨进程共享的 Crash 会话池守护服务与客户端
"""Shared Crash Session Daemon (Unix Domain Socket or HTTP) and client.

让 crash / stack_canary / lock_hang 多个 MCP Server 子进程以及多客户端并发 Worker
共享同一套 CrashSessionPool，避免重复冷启动与内存翻倍。

跨平台兼容：
  - Unix Domain Socket 仅在 POSIX 平台（支持 AF_UNIX / UnixStreamServer）启用；
  - HTTP TCP 模式在 Windows 与 Linux 均可运行与测试。
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import signal
import socket
import socketserver
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Optional, cast
from urllib.parse import urlparse

from dotenv import load_dotenv

from .session_pool import CrashSessionConfig, CrashSessionPool, _get_logger

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_UNIX_SOCKET_AVAILABLE = hasattr(socket, "AF_UNIX") and hasattr(
    socketserver, "UnixStreamServer"
)


class _UnixHTTPConnection(http.client.HTTPConnection):
    """通过 Unix Domain Socket 发送标准 HTTP 请求。"""

    def __init__(self, socket_path: str, timeout: float = 190.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        if not _UNIX_SOCKET_AVAILABLE:
            raise RuntimeError("Unix domain sockets are not supported on this platform")
        sock = socket.socket(getattr(socket, "AF_UNIX"), socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


class CrashDaemonClient:
    """CrashDaemon 客户端，透明支持 unix:// 与 http:// 两种 endpoint。"""

    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint.strip()
        if not self.endpoint:
            raise ValueError("Crash daemon endpoint must not be empty")

    def _open_connection(self, timeout: float) -> http.client.HTTPConnection:
        if self.endpoint.startswith("unix://"):
            sock_path = self.endpoint[len("unix://") :]
            return _UnixHTTPConnection(sock_path, timeout=timeout)
        parsed = urlparse(self.endpoint)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError(
                f"Unsupported CRASH_DAEMON_ENDPOINT: {self.endpoint!r} "
                "(expected unix:///path/to.sock or http://host:port)"
            )
        port = parsed.port or 80
        return http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)

    def _request_json(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
        *,
        timeout: float = 190.0,
    ) -> dict[str, Any]:
        conn = self._open_connection(timeout=timeout)
        try:
            headers = {"Content-Type": "application/json"}
            payload = json.dumps(body).encode("utf-8") if body is not None else None
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw) if raw else {}
            if resp.status >= 400:
                err_msg = data.get("error") if isinstance(data, dict) else raw
                raise RuntimeError(f"CrashDaemon HTTP {resp.status}: {err_msg}")
            return data
        finally:
            conn.close()

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
        req_timeout = (timeout or 180.0) + 15.0
        data = self._request_json(
            "POST",
            "/execute",
            {
                "command": command_or_script,
                "vmcore_path": vmcore_path,
                "vmlinux_path": vmlinux_path,
                "is_script": is_script,
                "timeout": timeout,
                "verbose": verbose,
            },
            timeout=req_timeout,
        )
        if not data.get("ok"):
            raise RuntimeError(data.get("error", "Unknown CrashDaemon error"))
        return str(data.get("output", ""))

    def health(self, timeout: float = 10.0) -> dict[str, Any]:
        return self._request_json("GET", "/health", timeout=timeout)

    def evict(self, vmcore_path: str, vmlinux_path: str, timeout: float = 15.0) -> int:
        data = self._request_json(
            "POST",
            "/evict",
            {"vmcore_path": vmcore_path, "vmlinux_path": vmlinux_path},
            timeout=timeout,
        )
        return int(data.get("evicted", 0))


def _make_handler(pool: CrashSessionPool) -> type[BaseHTTPRequestHandler]:
    class CrashDaemonRequestHandler(BaseHTTPRequestHandler):
        def address_string(self) -> str:
            if isinstance(self.client_address, tuple) and self.client_address:
                return str(self.client_address[0])
            return "unix-client"

        def log_message(self, format: str, *args: Any) -> None:
            _get_logger().debug("CrashDaemon: " + format, *args)

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            return json.loads(raw.decode("utf-8"))

        def _handle_evict(self, *, allow_empty_evict_all: bool = False) -> None:
            try:
                body = self._read_json()
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": f"Invalid JSON body: {exc}"})
                return

            if not isinstance(body, dict):
                self._send_json(400, {"ok": False, "error": "JSON body must be an object."})
                return

            vmcore_path = str(body.get("vmcore_path") or "").strip()
            vmlinux_path = str(body.get("vmlinux_path") or "").strip()

            if not vmcore_path and not vmlinux_path:
                if allow_empty_evict_all:
                    try:
                        evicted = pool.evict_all_idle()
                        self._send_json(
                            200, {"ok": True, "evicted": evicted, "scope": "all_idle"}
                        )
                    except Exception as exc:
                        self._send_json(500, {"ok": False, "error": str(exc)})
                    return
                self._send_json(
                    400,
                    {
                        "ok": False,
                        "error": "vmcore_path and vmlinux_path are required.",
                    },
                )
                return

            if not vmcore_path or not vmlinux_path:
                self._send_json(
                    400,
                    {
                        "ok": False,
                        "error": "Both vmcore_path and vmlinux_path must be provided together.",
                    },
                )
                return

            try:
                evicted = pool.evict(vmcore_path=vmcore_path, vmlinux_path=vmlinux_path)
                self._send_json(200, {"ok": True, "evicted": evicted, "scope": "target"})
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": str(exc)})

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json(200, {"status": "ok", "pool": pool.stats()})
                return
            self._send_json(404, {"ok": False, "error": f"Unknown path: {self.path}"})

        def do_DELETE(self) -> None:
            if self.path == "/sessions":
                self._handle_evict(allow_empty_evict_all=True)
                return
            self._send_json(404, {"ok": False, "error": f"Unknown path: {self.path}"})

        def do_POST(self) -> None:
            if self.path == "/evict":
                self._handle_evict(allow_empty_evict_all=False)
                return

            if self.path == "/execute":
                command = "<unavailable>"
                vmcore_path = "<unavailable>"
                try:
                    body = self._read_json()
                    command = str(body.get("command", ""))
                    vmcore_path = str(body.get("vmcore_path", ""))
                    _get_logger().info(
                        "[daemon execute] request from %s: vmcore=%s command=%r "
                        "(is_script=%s timeout=%s)",
                        self.address_string(),
                        vmcore_path,
                        command[:120],
                        bool(body.get("is_script", False)),
                        body.get("timeout"),
                    )
                    output = pool.execute(
                        command_or_script=command,
                        vmcore_path=str(body["vmcore_path"]),
                        vmlinux_path=str(body["vmlinux_path"]),
                        is_script=bool(body.get("is_script", False)),
                        timeout=body.get("timeout"),
                        verbose=bool(body.get("verbose", False)),
                    )
                    self._send_json(200, {"ok": True, "output": output})
                except Exception as exc:
                    _get_logger().exception(
                        "[daemon execute] failed for client=%s vmcore=%s "
                        "command=%r: %s",
                        self.address_string(),
                        vmcore_path,
                        command[:120],
                        exc,
                    )
                    self._send_json(500, {"ok": False, "error": str(exc)})
                return

            self._send_json(404, {"ok": False, "error": f"Unknown path: {self.path}"})

    return CrashDaemonRequestHandler


class _ThreadPoolMixIn:
    """固定大小常驻线程池处理 HTTP 请求，避免每请求创建/销毁 OS 线程。

    短命的每请求线程（ThreadingMixIn 默认语义）会成为 crash 子进程的内核
    real_parent，其退出会触发 PR_SET_PDEATHSIG 陷阱；池内工作线程常驻不退出，
    从结构上规避该问题（crash 的 Popen 已另由 _CrashProcessSpawner 常驻线程
    统一孵化，此为第二道防线）。
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=_daemon_worker_count(),
            thread_name_prefix="crash-daemon-worker",
        )
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        try:
            self._executor.submit(self.process_request_thread, request, client_address)
        except RuntimeError:
            # executor 已关闭（进程退出路径）：回退到 ThreadingMixIn 语义，
            # 在独立线程中同步处理，避免阻塞 accept 循环
            thread = threading.Thread(
                target=self.process_request_thread,
                args=(request, client_address),
                daemon=True,
            )
            thread.start()

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            self.finish_request(request, client_address)  # type: ignore[attr-defined]
        except Exception:
            self.handle_error(request, client_address)  # type: ignore[attr-defined]
        finally:
            self.shutdown_request(request)  # type: ignore[attr-defined]

    def server_close(self) -> None:
        super().server_close()  # type: ignore[misc]
        self._executor.shutdown(wait=True)


def _daemon_worker_count() -> int:
    """HTTP 处理线程池大小：至少 8，覆盖并发 worker 的 4 路初始化并发。"""
    try:
        raw = os.environ.get("CRASH_DAEMON_HTTP_WORKERS", "")
        if raw.strip():
            return max(4, int(raw))
    except ValueError:
        pass
    return max(8, (os.cpu_count() or 4))


if _UNIX_SOCKET_AVAILABLE:

    class _ThreadingUnixHTTPServer(
        _ThreadPoolMixIn, socketserver.UnixStreamServer  # type: ignore[misc]
    ):
        pass


class _ThreadingTCPHTTPServer(_ThreadPoolMixIn, socketserver.TCPServer):
    pass


class CrashDaemonServer:
    """可嵌入测试或独立运行的 Crash 会话池守护服务。"""

    def __init__(
        self,
        endpoint: str = "unix:///tmp/vmcore_crashd.sock",
        pool: Optional[CrashSessionPool] = None,
    ) -> None:
        self.endpoint = endpoint.strip()
        self.pool = pool or CrashSessionPool(CrashSessionConfig.from_env())
        self._owns_pool = pool is None
        self._unix_socket_path: Optional[str] = None
        self._shutdown_lock = threading.Lock()
        self._shut_down = False
        self._server = self._create_server()
        self._thread: Optional[threading.Thread] = None

    @property
    def bound_endpoint(self) -> str:
        """返回实际绑定的 endpoint（TCP 传 port=0 时返回真实分配端口）。"""
        if self._unix_socket_path:
            return f"unix://{self._unix_socket_path}"
        address = self._server.server_address
        host, port = address[-2]  # type: ignore[index]
        return f"http://{host}:{port}"

    def _create_server(self) -> socketserver.BaseServer:
        handler_cls = _make_handler(self.pool)
        if self.endpoint.startswith("unix://"):
            if not _UNIX_SOCKET_AVAILABLE:
                raise RuntimeError("Unix domain sockets are not supported on this platform")
            sock_path = self.endpoint[len("unix://") :]
            os.makedirs(os.path.dirname(sock_path) or ".", exist_ok=True)
            if os.path.exists(sock_path):
                os.unlink(sock_path)
            self._unix_socket_path = sock_path
            old_umask = os.umask(0o077)
            try:
                srv = _ThreadingUnixHTTPServer(sock_path, handler_cls)
            finally:
                os.umask(old_umask)
            os.chmod(sock_path, 0o600)
            return srv

        parsed = urlparse(self.endpoint)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError(f"Unsupported endpoint: {self.endpoint!r}")
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else 8765
        return _ThreadingTCPHTTPServer((host, port), handler_cls)

    def start_background(self) -> None:
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="crash-daemon-server",
            daemon=True,
        )
        self._thread.start()

    def serve_forever(self) -> None:
        _get_logger().info("CrashDaemonServer listening on %s", self.bound_endpoint)
        self._server.serve_forever()

    def request_stop(self) -> None:
        """仅触发 serve_forever 退出循环（适合从信号处理回调安全调用）。"""
        threading.Thread(target=self._server.shutdown, daemon=True).start()

    def shutdown(self) -> None:
        with self._shutdown_lock:
            if self._shut_down:
                return
            self._shut_down = True
        self._server.shutdown()
        self._server.server_close()
        if self._unix_socket_path and os.path.exists(self._unix_socket_path):
            try:
                os.unlink(self._unix_socket_path)
            except OSError:
                pass
        if self._owns_pool:
            self.pool.close_all()


def _load_env() -> None:
    """加载 .env 到进程环境（进程环境变量优先），支持 VMCORE_ENV_FILE 覆盖路径。"""
    override_file = os.environ.get("VMCORE_ENV_FILE", "").strip()
    env_path = Path(override_file) if override_file else (_PROJECT_ROOT / ".env")
    load_dotenv(env_path, override=False)


def main() -> None:
    _load_env()
    parser = argparse.ArgumentParser(description="Shared Persistent Crash Session Pool Daemon")
    parser.add_argument(
        "--endpoint",
        default=os.environ.get("CRASH_DAEMON_ENDPOINT", "unix:///tmp/vmcore_crashd.sock"),
        help="Listen endpoint: unix:///path/to.sock or http://127.0.0.1:8765",
    )
    args = parser.parse_args()

    server = CrashDaemonServer(endpoint=args.endpoint)
    cfg = server.pool.config
    _get_logger().info(
        "[daemon config] endpoint=%s max_sessions=%d slots_per_vmcore=%d "
        "idle_ttl=%.1fs command_timeout=%.1fs startup_timeout=%.1fs "
        "acquire_timeout=%.1fs max_output_chars=%d crash_binary=%s",
        server.bound_endpoint,
        cfg.max_total_sessions,
        cfg.slots_per_vmcore,
        cfg.idle_ttl_sec,
        cfg.command_timeout_sec,
        cfg.startup_timeout_sec,
        cfg.acquire_timeout_sec,
        cfg.max_output_chars,
        cfg.crash_binary,
    )

    def _handle_signal(_signum: int, _frame: Any) -> None:
        server.request_stop()

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        server.serve_forever()
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
