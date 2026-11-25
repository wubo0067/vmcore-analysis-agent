#!/usr/bin/env bash
# vmcore_agent.bash - 统一启停控制脚本（根据 CRASH_EXECUTION_MODE 自动联动 crash-daemon 与 agent）
# 放置于项目根目录（需 chmod +x vmcore_agent.bash）

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${VMCORE_ENV_FILE:-${PROJECT_ROOT}/.env}"

# 安全读取 .env 中的单个键（仅在进程环境变量未显式设置时生效，与 src/utils/settings.py 优先级一致）
read_env_var() {
    local key="$1"
    local default_val="$2"
    local val="${!key:-}"
    if [[ -n "${val}" ]]; then
        printf '%s' "${val}"
        return 0
    fi
    if [[ -r "${ENV_FILE}" ]]; then
        local line raw
        while IFS= read -r line || [[ -n "${line}" ]]; do
            # 去除首尾空白
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "${line}" || "${line}" == \#* ]] && continue
            # 兼容 export KEY=VALUE
            line="${line#export }"
            if [[ "${line}" == "${key}="* ]]; then
                raw="${line#*=}"
                # 去除行尾注释（仅当未被引号包裹时）
                if [[ "${raw}" != \"*\" && "${raw}" != \'*\' ]]; then
                    raw="${raw%%#*}"
                fi
                raw="${raw#"${raw%%[![:space:]]*}"}"
                raw="${raw%"${raw##*[![:space:]]}"}"
                # 剥离成对单/双引号
                if [[ "${raw}" == \"*\" && "${raw}" == *\" ]]; then
                    raw="${raw:1:${#raw}-2}"
                elif [[ "${raw}" == \'*\' && "${raw}" == *\' ]]; then
                    raw="${raw:1:${#raw}-2}"
                fi
                val="${raw}"
            fi
        done < "${ENV_FILE}"
    fi
    if [[ -n "${val}" ]]; then
        printf '%s' "${val}"
    else
        printf '%s' "${default_val}"
    fi
}

# 解析并归一化 CRASH_EXECUTION_MODE（与 executor.py / settings.py 保持一致）
resolve_execution_mode() {
    local raw_mode mode
    raw_mode="$(read_env_var "CRASH_EXECUTION_MODE" "daemon")"
    mode="$(printf '%s' "${raw_mode}" | tr '[:upper:]' '[:lower:]')"
    case "${mode}" in
        ""|daemon)
            printf 'daemon'
            ;;
        oneshot)
            printf 'oneshot'
            ;;
        pool)
            echo "[WARN] CRASH_EXECUTION_MODE='pool' 已移除，自动按 'daemon' 模式运行。" >&2
            printf 'daemon'
            ;;
        *)
            echo "[WARN] 无效的 CRASH_EXECUTION_MODE='${raw_mode}'，自动回退为 'daemon' 模式。" >&2
            printf 'daemon'
            ;;
    esac
}

EXECUTION_MODE="$(resolve_execution_mode)"
ENDPOINT="$(read_env_var "CRASH_DAEMON_ENDPOINT" "unix:///tmp/vmcore_crashd.sock")"

RUN_DIR="${VMCORE_RUN_DIR:-${CRASH_DAEMON_RUN_DIR:-${PROJECT_ROOT}/logs}}"
AGENT_PID_FILE="${RUN_DIR}/vmcore-agent.pid"
AGENT_LOG_FILE="${VMCORE_AGENT_LOG_FILE:-${RUN_DIR}/vmcore-agent.log}"
DAEMON_PID_FILE="${RUN_DIR}/crash-daemon.pid"
DAEMON_LOG_FILE="${CRASH_DAEMON_LOG_FILE:-${RUN_DIR}/crash-daemon.log}"

STOP_TIMEOUT="${VMCORE_STOP_TIMEOUT:-${CRASH_DAEMON_STOP_TIMEOUT:-30}}"
AGENT_START_WAIT_SEC="${VMCORE_AGENT_START_WAIT_SEC:-2}"
DAEMON_START_WAIT_SEC="${CRASH_DAEMON_START_WAIT_SEC:-10}"

usage() {
    cat <<EOF
用法: $0 {start|stop|restart|status|health|logs|run} [目标]

当前生效配置:
  CRASH_EXECUTION_MODE = ${EXECUTION_MODE}
  CRASH_DAEMON_ENDPOINT = ${ENDPOINT}
  RUN_DIR               = ${RUN_DIR}

子命令:
  start [all|daemon|agent]    后台启动服务（默认 all）：
                                - daemon 模式：先启动并等待 crash-daemon 就绪，再启动 agent (uv run main.py)
                                - oneshot 模式：仅启动 agent（若显式指定 daemon 则提示跳过）
  stop [all|daemon|agent]     优雅停止服务（默认 all，先停 agent 后停 daemon）
  restart [all|daemon|agent]  先 stop 再 start（修改 .env 切换模式后可直接 restart 生效）
  status                      查看 agent 与 crash-daemon 的 PID、运行状态与日志路径
  health                      查看 crash-daemon /health 会话池状态（oneshot 模式下仅显示 agent 状态）
  logs [agent|daemon|all]     持续跟踪日志（默认 all）
  run [agent|daemon]          前台运行（默认 agent：daemon 模式下自动拉起/复用守护进程；daemon：仅前台运行守护进程）

环境变量（进程环境变量优先于 .env）:
  CRASH_EXECUTION_MODE        daemon（默认）或 oneshot
  CRASH_DAEMON_ENDPOINT       默认 unix:///tmp/vmcore_crashd.sock
  VMCORE_ENV_FILE             指定 .env 路径，默认 ${PROJECT_ROOT}/.env
  VMCORE_RUN_DIR              PID 与日志目录，默认 ${PROJECT_ROOT}/logs
  VMCORE_AGENT_LOG_FILE       agent 日志路径，默认 <run-dir>/vmcore-agent.log
  CRASH_DAEMON_LOG_FILE       daemon 日志路径，默认 <run-dir>/crash-daemon.log
  VMCORE_STOP_TIMEOUT         优雅停止等待秒数，默认 30
  VMCORE_AGENT_START_WAIT_SEC agent 启动存活复核秒数，默认 2
  CRASH_DAEMON_START_WAIT_SEC daemon 健康检查等待秒数，默认 10
EOF
}

pid_is_running() {
    local pid="$1"
    [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
    kill -0 "${pid}" 2>/dev/null || return 1
    # 排除已退出但尚未被容器 PID 1 回收的僵尸进程（State: Z）
    if [[ -r "/proc/${pid}/stat" ]]; then
        local stat_line state
        IFS= read -r stat_line < "/proc/${pid}/stat" 2>/dev/null || return 1
        state="${stat_line##*) }"
        state="${state%% *}"
        [[ "${state}" != "Z" ]] || return 1
    fi
    return 0
}

read_pid_file() {
    local pid_file="$1"
    local pid=""
    if [[ -r "${pid_file}" ]]; then
        IFS= read -r pid < "${pid_file}" || true
    fi
    printf '%s' "${pid}"
}

running_pid_from_file() {
    local pid_file="$1"
    local pid
    pid="$(read_pid_file "${pid_file}")"
    if pid_is_running "${pid}"; then
        printf '%s' "${pid}"
        return 0
    fi
    if [[ -n "${pid}" ]]; then
        echo "清理过期 PID 文件: ${pid_file}" >&2
        rm -f -- "${pid_file}"
    fi
    return 1
}

spawn_detached() {
    local log_file="$1"
    shift
    if command -v setsid >/dev/null 2>&1; then
        setsid "$@" >> "${log_file}" 2>&1 < /dev/null &
    else
        nohup "$@" >> "${log_file}" 2>&1 < /dev/null &
    fi
}

signal_process_or_group() {
    local sig="$1"
    local pid="$2"
    # 若进程是独立会话/进程组领头进程（setsid 启动），向整个进程组发信号，确保 uv 与其 python 子进程一并退出
    kill "-${sig}" -- "-${pid}" 2>/dev/null || kill "-${sig}" "${pid}" 2>/dev/null || true
}

stop_process_by_pid_file() {
    local name="$1"
    local pid_file="$2"
    local pid
    if ! pid="$(running_pid_from_file "${pid_file}")"; then
        echo "${name} 未运行"
        return 0
    fi

    echo "正在停止 ${name}: PID=${pid}"
    signal_process_or_group TERM "${pid}"

    local attempt
    for ((attempt = 0; attempt < STOP_TIMEOUT * 10; attempt++)); do
        if ! pid_is_running "${pid}"; then
            rm -f -- "${pid_file}"
            echo "${name} 已停止"
            return 0
        fi
        sleep 0.1
    done

    echo "${name} 优雅停止超时（${STOP_TIMEOUT}s），强制终止 PID=${pid}" >&2
    signal_process_or_group KILL "${pid}"
    rm -f -- "${pid_file}"
    return 0
}

daemon_health_check() {
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

start_daemon() {
    local pid
    if pid="$(running_pid_from_file "${DAEMON_PID_FILE}")"; then
        echo "crash-daemon 已运行: PID=${pid}, endpoint=${ENDPOINT}"
        return 0
    fi

    mkdir -p -- "${RUN_DIR}" "$(dirname "${DAEMON_LOG_FILE}")"
    cd "${PROJECT_ROOT}"

    if command -v uv >/dev/null 2>&1; then
        spawn_detached "${DAEMON_LOG_FILE}" uv run python -m src.mcp_tools.crash.daemon --endpoint "${ENDPOINT}"
    else
        spawn_detached "${DAEMON_LOG_FILE}" python3 -m src.mcp_tools.crash.daemon --endpoint "${ENDPOINT}"
    fi
    pid=$!
    printf '%s\n' "${pid}" > "${DAEMON_PID_FILE}"

    local attempt
    local daemon_checks=$(( DAEMON_START_WAIT_SEC * 5 ))
    (( daemon_checks < 1 )) && daemon_checks=1
    for ((attempt = 0; attempt < daemon_checks; attempt++)); do
        if ! pid_is_running "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            rm -f -- "${DAEMON_PID_FILE}"
            echo "crash-daemon 启动失败，最近日志：" >&2
            tail -n 50 "${DAEMON_LOG_FILE}" >&2 || true
            return 1
        fi
        if daemon_health_check >/dev/null 2>&1; then
            echo "crash-daemon 启动成功: PID=${pid}, endpoint=${ENDPOINT}"
            echo "  日志: ${DAEMON_LOG_FILE}"
            return 0
        fi
        sleep 0.2
    done

    echo "crash-daemon 进程已启动但健康检查超时（${DAEMON_START_WAIT_SEC}s）: PID=${pid}, 请查看 ${DAEMON_LOG_FILE}" >&2
    return 1
}

start_agent() {
    local pid
    if pid="$(running_pid_from_file "${AGENT_PID_FILE}")"; then
        echo "vmcore-agent 已运行: PID=${pid}"
        return 0
    fi

    mkdir -p -- "${RUN_DIR}" "$(dirname "${AGENT_LOG_FILE}")"
    cd "${PROJECT_ROOT}"

    if command -v uv >/dev/null 2>&1; then
        spawn_detached "${AGENT_LOG_FILE}" uv run main.py
    else
        spawn_detached "${AGENT_LOG_FILE}" python3 main.py
    fi
    pid=$!
    printf '%s\n' "${pid}" > "${AGENT_PID_FILE}"

    # 短暂复核，防止缺少 .env 配置或端口冲突导致进程秒退却被误报成功
    local checks=$(( AGENT_START_WAIT_SEC * 5 ))
    (( checks < 1 )) && checks=1
    local i
    for ((i = 0; i < checks; i++)); do
        if ! pid_is_running "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            rm -f -- "${AGENT_PID_FILE}"
            echo "vmcore-agent 启动失败，最近日志：" >&2
            tail -n 50 "${AGENT_LOG_FILE}" >&2 || true
            return 1
        fi
        sleep 0.2
    done

    echo "vmcore-agent 启动成功: PID=${pid} (mode=${EXECUTION_MODE})"
    echo "  日志: ${AGENT_LOG_FILE}"
    return 0
}

cmd_start() {
    local target="${1:-all}"
    case "${target}" in
        all)
            echo "=== 启动服务 (CRASH_EXECUTION_MODE=${EXECUTION_MODE}) ==="
            if [[ "${EXECUTION_MODE}" == "daemon" ]]; then
                start_daemon
            else
                echo "当前为 oneshot 模式，跳过启动 crash-daemon"
            fi
            start_agent
            ;;
        daemon)
            if [[ "${EXECUTION_MODE}" != "daemon" ]]; then
                echo "当前为 ${EXECUTION_MODE} 模式，跳过启动 crash-daemon"
                return 0
            fi
            start_daemon
            ;;
        agent)
            start_agent
            ;;
        *)
            echo "未知启动目标: ${target}（可选: all | daemon | agent）" >&2
            exit 2
            ;;
    esac
}

cmd_stop() {
    local target="${1:-all}"
    local rc=0
    case "${target}" in
        all)
            echo "=== 停止服务 (CRASH_EXECUTION_MODE=${EXECUTION_MODE}) ==="
            # 反序优雅停止：先停 agent，再停 crash-daemon
            stop_process_by_pid_file "vmcore-agent" "${AGENT_PID_FILE}" || rc=1
            if [[ "${EXECUTION_MODE}" == "daemon" ]] || [[ -r "${DAEMON_PID_FILE}" ]]; then
                stop_process_by_pid_file "crash-daemon" "${DAEMON_PID_FILE}" || rc=1
            fi
            ;;
        daemon)
            if [[ "${EXECUTION_MODE}" == "daemon" ]] || [[ -r "${DAEMON_PID_FILE}" ]]; then
                stop_process_by_pid_file "crash-daemon" "${DAEMON_PID_FILE}" || rc=1
            else
                echo "crash-daemon 未运行"
            fi
            ;;
        agent)
            stop_process_by_pid_file "vmcore-agent" "${AGENT_PID_FILE}" || rc=1
            ;;
        *)
            echo "未知停止目标: ${target}（可选: all | daemon | agent）" >&2
            exit 2
            ;;
    esac
    return "${rc}"
}

cmd_status() {
    local rc=0
    local agent_pid="" daemon_pid=""
    echo "CRASH_EXECUTION_MODE: ${EXECUTION_MODE}"

    if agent_pid="$(running_pid_from_file "${AGENT_PID_FILE}")"; then
        echo "[OK]   vmcore-agent 运行中: PID=${agent_pid}, 日志=${AGENT_LOG_FILE}"
    else
        echo "[STOP] vmcore-agent 未运行"
        rc=1
    fi

    if [[ "${EXECUTION_MODE}" == "daemon" ]]; then
        if daemon_pid="$(running_pid_from_file "${DAEMON_PID_FILE}")"; then
            echo "[OK]   crash-daemon 运行中: PID=${daemon_pid}, endpoint=${ENDPOINT}, 日志=${DAEMON_LOG_FILE}"
        else
            echo "[STOP] crash-daemon 未运行 (endpoint=${ENDPOINT})"
            rc=1
        fi
    else
        if daemon_pid="$(running_pid_from_file "${DAEMON_PID_FILE}")"; then
            echo "[WARN] crash-daemon 仍在运行: PID=${daemon_pid}（当前为 oneshot 模式，可运行 '$0 stop' 清理）"
        else
            echo "[SKIP] crash-daemon 未启用（oneshot 模式）"
        fi
    fi

    return "${rc}"
}

cmd_health() {
    if [[ "${EXECUTION_MODE}" == "daemon" ]]; then
        daemon_health_check
    else
        echo "当前为 oneshot 模式，未使用 crash-daemon。"
        cmd_status
    fi
}

cmd_logs() {
    local target="${1:-all}"
    mkdir -p -- "${RUN_DIR}" "$(dirname "${AGENT_LOG_FILE}")" "$(dirname "${DAEMON_LOG_FILE}")"
    case "${target}" in
        agent)
            touch "${AGENT_LOG_FILE}"
            tail -n 100 -f "${AGENT_LOG_FILE}"
            ;;
        daemon)
            touch "${DAEMON_LOG_FILE}"
            tail -n 100 -f "${DAEMON_LOG_FILE}"
            ;;
        all)
            touch "${AGENT_LOG_FILE}"
            if [[ "${EXECUTION_MODE}" == "daemon" ]]; then
                touch "${DAEMON_LOG_FILE}"
                tail -n 100 -f "${AGENT_LOG_FILE}" "${DAEMON_LOG_FILE}"
            else
                tail -n 100 -f "${AGENT_LOG_FILE}"
            fi
            ;;
        *)
            echo "未知日志目标: ${target}（可选: agent | daemon | all）" >&2
            exit 2
            ;;
    esac
}

cmd_run() {
    local target="${1:-agent}"
    cd "${PROJECT_ROOT}"
    case "${target}" in
        daemon)
            echo "=== 前台运行 crash-daemon (endpoint=${ENDPOINT}) ==="
            if command -v uv >/dev/null 2>&1; then
                exec uv run python -m src.mcp_tools.crash.daemon --endpoint "${ENDPOINT}"
            else
                exec python3 -m src.mcp_tools.crash.daemon --endpoint "${ENDPOINT}"
            fi
            ;;
        agent)
            echo "=== 前台运行 (CRASH_EXECUTION_MODE=${EXECUTION_MODE}) ==="
            local started_daemon_here=0
            if [[ "${EXECUTION_MODE}" == "daemon" ]]; then
                if ! running_pid_from_file "${DAEMON_PID_FILE}" >/dev/null; then
                    start_daemon
                    started_daemon_here=1
                else
                    echo "复用已运行的 crash-daemon (endpoint=${ENDPOINT})"
                fi
            fi

            if (( started_daemon_here == 1 )); then
                cleanup_on_exit() {
                    trap - EXIT
                    echo ""
                    echo "前台 agent 已退出，正在停止本次自动拉起的 crash-daemon..."
                    stop_process_by_pid_file "crash-daemon" "${DAEMON_PID_FILE}" || true
                }
                trap cleanup_on_exit EXIT

                if command -v uv >/dev/null 2>&1; then
                    uv run main.py
                else
                    python3 main.py
                fi
            else
                if command -v uv >/dev/null 2>&1; then
                    exec uv run main.py
                else
                    exec python3 main.py
                fi
            fi
            ;;
        *)
            echo "未知前台运行目标: ${target}（可选: agent | daemon）" >&2
            exit 2
            ;;
    esac
}

case "${1:-}" in
    start)
        cmd_start "${2:-all}"
        ;;
    stop)
        cmd_stop "${2:-all}"
        ;;
    restart)
        cmd_stop "${2:-all}"
        cmd_start "${2:-all}"
        ;;
    status)
        cmd_status
        ;;
    health)
        cmd_health
        ;;
    logs)
        cmd_logs "${2:-all}"
        ;;
    run)
        cmd_run "${2:-agent}"
        ;;
    *)
        usage
        exit 2
        ;;
esac