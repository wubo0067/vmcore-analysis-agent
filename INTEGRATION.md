# `lock_hang` MCP 工具集成指南

## 1. 零配置自动注册

由于 `src/mcp_tools/registry.py` 会自动扫描 `src/mcp_tools/` 下的所有子目录并加载暴露 `MCP_CLIENT`、`MCP_SERVER_NAME`、`initialize_tools`、`build_tool_payload` 的 `client.py`，将 `src/mcp_tools/lock_hang/` 直接复制到项目的 `src/mcp_tools/` 目录后即可被 Agent 自动发现，**无需修改 `registry.py`**。

## 2. 推荐在提示词层（`react/`）追加的触发指引

为了让模型在面对 `soft_lockup` / `hard_lockup` / `hung_task` / `rcu_stall` 时优先调用新工具而不是直接倾倒 `bt -a`，可在 `react/sop_fragments.py` 与 `react/prompt_builder.py` 中补充以下片段：

### 在 `react/sop_fragments.py` 中新增键 `"lock_hang_fast_path"`：

```python
"lock_hang_fast_path": """[SOP: LOCK / HANG / RCU STALL FAST PATH]
1. When investigating hung tasks, AB-BA deadlocks, or multiple UN-state tasks, call
   `analyze_lock_wait_graph` FIRST (e.g. `{"command_name": "analyze_lock_wait_graph", "arguments": ["--top", "12"]}`).
   It mechanically decodes mutex/rwsem owner pointers (masking low flag bits), builds the Wait-For Graph,
   and reports deadlock cycles and root blockers without flooding context.
2. When investigating soft lockup, hard lockup, spinlock storm, or RCU stall, call
   `analyze_cpu_lockup_rcu` FIRST instead of dumping raw `bt -a` across all CPUs.
3. Only after receiving the structured graph/CPU summary, run targeted `bt -f <pid>`, `struct`, or `dis -rl`
   on the identified deadlock cycle members or root blocker CPU/task.""",
```

### 在 `react/prompt_builder.py` 的 `_select_sop_fragments` 中追加注入条件：

```python
if (
    signature_class in {"soft_lockup", "hard_lockup", "hung_task", "rcu_stall"}
    or any(
        token in lowered_recent_text
        for token in (
            "blocked for more than",
            "soft lockup",
            "hard lockup",
            "rcu_sched self-detected stall",
            "rcu_preempt self-detected stall",
            "__mutex_lock",
            "rwsem_down_",
        )
    )
):
    fragments.append(SOP_FRAGMENTS["lock_hang_fast_path"])
```

## 3. 运行单元测试

`tests/` 没有 `__init__.py`，且 analyzer 测试不依赖 `langchain_mcp_adapters`，因此可以任选其一：

```bash
# 方式一：unittest 逐模块枚举（推荐的跨环境写法）
python3 -m unittest tests.test_lock_hang_analyzer tests.test_lock_hang_client

# 方式二：若环境里有 pytest
python3 -m pytest tests/test_lock_hang_analyzer.py tests/test_lock_hang_client.py -q
```

`test_lock_hang_analyzer.py` 通过注入假 `crash_runner` / `script_runner` 覆盖完整分析流程，不需要真实 vmcore；
`test_lock_hang_client.py` 覆盖 `build_tool_payload`（四种入参形态的压平规则），并额外做一次 server 注册断言：
它导入 `lock_hang_server` 并检查两个工具都出现在 `get_tools()` 里。这一步不能省——FastMCP 会按 `Field(default=...)` 重建 pydantic 模型，
若把带默认值的参数排在必需参数之前，进程会在 import 阶段抛 `SchemaError: Non-default argument ... follows default argument`，
结果是 **server 起得来但工具数为 0**，而纯 analyzer 测试全绿也发现不了。

## 4. 两个工具的入参形态

`build_tool_payload` 会把 LLM 传来的参数的四种形态（`dict` / `list` / `None` / 标量）统一压平成单个 `command` 字符串，
再从 state 注入 `vmcore_path` / `vmlinux_path`，所以工具侧只需要处理 `command`：

| 工具 | 参数语法 |
|---|---|
| `analyze_lock_wait_graph` | `[--pids <pid1,pid2,...>] [--top <int>] [--max-depth <int>] [--lock-addr <hex>] [--lock-type <mutex\|rwsem>]` |
| `analyze_cpu_lockup_rcu` | `[--cpus <cpu1,cpu2,...>] [--include-idle]` |

`command` 为空时行为：前者取 `ps -m` 中阻塞最久的 12 个 `UN` 任务（`--top` 默认 12，范围 1..64），
后者分析全部非 idle CPU。`--max-depth` 默认 6，范围 1..16。只传 `--lock-addr` 而省略 `--lock-type` 时按 `mutex` 处理，确认是读写信号量时需显式传 `rwsem`。参数经 `shlex.split` 解析，因此可以带引号。
