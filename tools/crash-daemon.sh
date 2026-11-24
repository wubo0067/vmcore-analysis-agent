#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENDPOINT="${CRASH_DAEMON_ENDPOINT:-unix:///tmp/vmcore_crashd.sock}"
RUN_DIR="${CRASH_DAEMON_RUN_DIR:-${PROJECT_ROOT}/logs}"
PID_FILE="${RUN_DIR}/crash-daemon.pid"
LOG_FILE="${CRASH_DAEMON_LOG_FILE:-${RUN_DIR}/crash-daemon.log}"
STOP_TIMEOUT="${CRASH_DAEMON_STOP_TIMEOUT:-30}"

usage() {
    cat <<EOF
用法: $0 {start|stop|restart|status|health|logs|run}

  start    后台启动常驻 crash 会话池守护进程（重复执行不会重复启动）
  stop     优雅停止守护进程及其持有的 crash 会话
  restart  重启守护进程（会关闭现有 crash 会话）
  status   显示 PID、endpoint 和运行状态
  health   请求 /health，显示会话池状态
  logs     持续跟踪守护进程日志（Ctrl-C 仅退出日志查看）
  run      前台运行，适合 systemd 或直接调试

环境变量:
  CRASH_DAEMON_ENDPOINT   默认 unix:///tmp/vmcore_crashd.sock
  CRASH_DAEMON_RUN_DIR    PID 文件和默认日志目录，默认 ${PROJECT_ROOT}/logs
  CRASH_DAEMON_LOG_FILE   日志文件，默认 <run-dir>/crash-daemon.log
  CRASH_DAEMON_STOP_TIMEOUT  优雅停止等待秒数，默认 30
EOF
}

pid_is_running() {
    local pid="$1"
    [[ "${pid}" =~ ^[1-9][0-9]*$ ]] && kill -0 "${pid}" 2>/dev/null
}

read_pid() {
    local pid=""
    if [[ -r "${PID_FILE}" ]]; then
        IFS= read -r pid < "${PID_FILE}" || true
    fi
    printf '%s' "${pid}"
}

running_pid() {
    local pid
    pid="$(read_pid)"
    if pid_is_running "${pid}"; then
        printf '%s' "${pid}"
        return 0
    fi
    if [[ -n "${pid}" ]]; then
        echo "清理过期 PID 文件: ${PID_FILE}" >&2
        rm -f -- "${PID_FILE}"
    fi
    return 1
}

start_daemon() {
    local pid
    if pid="$(running_pid)"; then
        echo "crash daemon 已运行: PID=${pid}, endpoint=${ENDPOINT}"
        return 0
    fi

    mkdir -p -- "${RUN_DIR}" "$(dirname "${LOG_FILE}")"
    cd "${PROJECT_ROOT}"

    if command -v uv >/dev/null 2>&1; then
        nohup uv run python -m src.mcp_tools.crash.daemon --endpoint "${ENDPOINT}" \
            >> "${LOG_FILE}" 2>&1 < /dev/null &
    else
        nohup python3 -m src.mcp_tools.crash.daemon --endpoint "${ENDPOINT}" \
            >> "${LOG_FILE}" 2>&1 < /dev/null &
    fi
    pid=$!
    printf '%s\n' "${pid}" > "${PID_FILE}"

    local attempt
    for attempt in {1..50}; do
        if ! pid_is_running "${pid}"; then
            wait "${pid}" || true
            rm -f -- "${PID_FILE}"
            echo "crash daemon 启动失败，最近日志：" >&2
            tail -n 50 "${LOG_FILE}" >&2 || true
            return 1
        fi
        if health_check >/dev/null 2>&1; then
            echo "crash daemon 启动成功: PID=${pid}"
            echo "endpoint: ${ENDPOINT}"
            echo "日志: ${LOG_FILE}"
            return 0
        fi
        sleep 0.2
    done

    echo "进程已启动但健康检查超时: PID=${pid}, 请查看 ${LOG_FILE}" >&2
    return 1
}

stop_daemon() {
    local pid
    if ! pid="$(running_pid)"; then
        echo "crash daemon 未运行"
        return 0
    fi

    echo "正在停止 crash daemon: PID=${pid}"
    kill -TERM "${pid}"
    local attempt
    for ((attempt = 0; attempt < STOP_TIMEOUT * 10; attempt++)); do
        if ! pid_is_running "${pid}"; then
            rm -f -- "${PID_FILE}"
            echo "crash daemon 已停止"
            return 0
        fi
        sleep 0.1
    done

    echo "优雅停止超时（${STOP_TIMEOUT}s），保留 PID 文件并强制终止 PID=${pid}" >&2
    kill -KILL "${pid}" 2>/dev/null || true
    rm -f -- "${PID_FILE}"
    return 1
}

status_daemon() {
    local pid
    if pid="$(running_pid)"; then
        echo "运行中: PID=${pid}, endpoint=${ENDPOINT}"
        echo "日志: ${LOG_FILE}"
    else
        echo "未运行: endpoint=${ENDPOINT}"
        return 1
    fi
}

health_check() {
    cd "${PROJECT_ROOT}"
    if command -v uv >/dev/null 2>&1; then
        uv run python - "${ENDPOINT}" <<'PY'
import json
import sys

from src.mcp_tools.crash.daemon import CrashDaemonClient

print(json.dumps(CrashDaemonClient(sys.argv[1]).health(), ensure_ascii=False, indent=2))
PY
    else
        python3 - "${ENDPOINT}" <<'PY'
import json
import sys

from src.mcp_tools.crash.daemon import CrashDaemonClient

print(json.dumps(CrashDaemonClient(sys.argv[1]).health(), ensure_ascii=False, indent=2))
PY
    fi
}

case "${1:-}" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        stop_daemon
        start_daemon
        ;;
    status)
        status_daemon
        ;;
    health)
        health_check
        ;;
    logs)
        mkdir -p -- "$(dirname "${LOG_FILE}")"
        touch "${LOG_FILE}"
        tail -n 100 -f "${LOG_FILE}"
        ;;
    run)
        cd "${PROJECT_ROOT}"
        if command -v uv >/dev/null 2>&1; then
            exec uv run python -m src.mcp_tools.crash.daemon --endpoint "${ENDPOINT}"
        else
            exec python3 -m src.mcp_tools.crash.daemon --endpoint "${ENDPOINT}"
        fi
        ;;
    *)
        usage
        exit 2
        ;;
esac
