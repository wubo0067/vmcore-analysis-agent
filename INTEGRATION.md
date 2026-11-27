# `lock_hang` MCP 工具集成指南

## 1. 零配置自动注册

由于 `src/mcp_tools/registry.py` 会自动扫描 `src/mcp_tools/` 下的所有子目录并加载暴露 `MCP_CLIENT`、`MCP_SERVER_NAME`、`initialize_tools`、`build_tool_payload` 的 `client.py`，将 `src/mcp_tools/lock_hang/` 直接复制到项目的 `src/mcp_tools/` 目录后即可被 Agent 自动发现，**无需修改 `registry.py`**。

## 2. 提示词层（`react/`）的优先调用引导（已实现）

为了让模型在面对 `soft_lockup` / `hard_lockup` / `hung_task` / `rcu_stall` 时优先调用分析器，而不是直接倾倒 `bt -a` / `foreach UN bt`，提示词分三层引导。每层各管一件事，避免同一指令在提示词里多处重复。

### 2.1 layer0：`react/layer0_system.py` 的 3.7a 小节（每轮注入）

在 `3.8 Extended Commands (mpykdump / crash-extensions)` 之前新增 `3.7a Deterministic Lock / Hang Analyzers`：

- 说明这两个是 MCP 工具，不是 crash 内建命令或 mpykdump 扩展；可用时优先于 3.5 的手工命令和 3.8 的扩展命令。
- 列出两个工具的适用场景和完整语法（含 `--rcu-pids`）。
- 规定分析器返回后只做定向跟进：`bt -f <task_addr>`、`bt -c <cpu>`、`struct`、`dis -rl`。
- 分析器不可用、报错或返回 `no_uninterruptible_tasks` / 空结果时，回退到 `hanginfo` / `rqlist` 和手工命令。

同时把 `hanginfo` 从 "Use as the FIRST command" 改为 "first **extension** command（在 `analyze_lock_wait_graph` 之后）"，`bt -a` 禁令和 3.5 中的 `foreach UN bt` 也加了指向 3.7a 的说明，保证全文只有一个 "FIRST"。

layer0 每轮都注入，是第 1 轮（签名尚未分类）唯一可靠的引导。

### 2.2 playbook：`react/playbooks.py`（签名确定后）

| 签名 | 位置 | 要求 |
|---|---|---|
| `hung_task` | 剧本顶部 `Mandatory Fast Path (Step 1)` | 可用时先调 `analyze_lock_wait_graph`（`--top 12` 或 `--pids <pid1,pid2>`），再对 `deadlock_cycles` / `root_blockers` 定向跟进；单锁确认用 `--lock-addr <hex> --lock-type <mutex\|rwsem>`；不可用时回退 `hanginfo` / `rqlist` |
| `soft_lockup` / `hard_lockup` | `_LOCKUP_PLAYBOOK` 顶部 `Mandatory Fast Path (Step 1)` | 可用时先调 `analyze_cpu_lockup_rcu`（`--cpus <cpu1,cpu2>`），只对它报告的 CPU 执行后续步骤；hard lockup 仍要用 `bt -c <cpu>` 确认 NMI 上下文；`bt -a` 降为工具不可用时的回退 |
| `rcu_stall` | 原有 `Mandatory Fast Path` Step 1 | 先调 `analyze_cpu_lockup_rcu --rcu-pids <pid1,pid2>`（本次未改动） |

措辞统一为 "When `analyze_xxx` is available, you MUST invoke it FIRST"，provider 未加载时模型不会因找不到工具而卡住。

### 2.3 SOP 兜底：`react/sop_fragments.py` + `react/prompt_builder.py`（仅第 1 轮初筛）

`sop_fragments.py` 新增键 `"lock_hang_fast_path"`，内容与 layer0 一致（含 `--rcu-pids`、`bt -f <task_addr>`）。

`prompt_builder._select_sop_fragments` 中的注入条件：

```python
if (not signature_class or signature_class == "unknown") and _has_lock_hang_signal(
    state, lowered_recent_text
):
    fragments.append(SOP_FRAGMENTS["lock_hang_fast_path"])
```

- **只在签名未分类时注入**。签名一旦落定就退场：四类锁/挂死签名由各自的 playbook 负责；非锁类签名（如 `pointer_corruption`）不会因为初始 dmesg 里残留一条历史 `soft lockup` 日志而在后续每轮都被注入。
- **关键词检测读完整初始上下文**：`_recent_text_blob` 对每条消息只取前 800 字符，而初始 HumanMessage 中 vmcore-dmesg 位于 `sys` / `sys -t` / `bt` 之后，会被截掉。`_has_lock_hang_signal` 因此额外读取 `_initial_context_text()`（第一条 HumanMessage 全文）。
- **只用强信号**，均为小写字面量（与 `lower()` 后的文本比较）：

```python
_LOCK_HANG_SIGNAL_TOKENS = (
    "blocked for more than",
    "hung_task: blocked tasks",
    "soft lockup",
    "hard lockup",
    "detected stalls on cpus",
    "self-detected stall",
    "rcu stall",
)
```

  刻意不含 `__mutex_lock` / `rwsem_down_` 等会出现在普通栈中的弱信号，避免在指针破坏类案例中误注入。

### 2.4 未分类时的剧本兜底

`prompt_builder._select_playbook` 在签名未分类（`None` / 空 / `unknown`）时，会用关键词判断是否先挂上 `rcu_stall` 剧本。它同样读取完整初始上下文（`recent_text` + `_initial_context_text()`），所以第 1 轮 dmesg 中的 `detected stalls on cpus/tasks`、`self-detected stall on cpu`、`rcu stall` 不会再被 800 字符截断吃掉。签名一旦确定，就按签名选剧本，不再看这些关键词。

## 3. 运行单元测试

`tests/` 没有 `__init__.py`，且 analyzer 测试不依赖 `langchain_mcp_adapters`，因此可以任选其一：

```bash
# 方式一：unittest 逐模块枚举（推荐的跨环境写法）
python3 -m unittest tests.test_lock_hang_analyzer tests.test_lock_hang_client

# 提示词侧的快速通道测试（需要项目 venv，依赖 langchain_core）
.venv/bin/python -m unittest tests.test_prompt_builder

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
