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
| `rcu_stall` | 原有 `Mandatory Fast Path` Step 1 | 先调 `analyze_cpu_lockup_rcu --rcu-pids <pid1,pid2>`，读者与 `synchronize_rcu` 等待者的 PID 都要传；Step 2 批量命令里若分析器报出 `waiter_bt_truncated`，要补 `bt -f <waiter_task_addr>`（若 Step 1 失败导致批量命令先跑完，则在后续分析器成功后、下结论前补） |

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

### 2.5 证据纪律规则（layer0，每轮注入）

下面这组规则在 `layer0_system.py` 的"Configured vs. actual duration discipline"之后，对所有签名生效。它们是对真实报告里出现过的措辞问题的约束：

| 规则 | 内容 |
|---|---|
| Runtime call-chain boundary | 只有 `bt` / `bt -f` 里实际出现的栈帧才构成运行时调用链；`dis -l` 里的 `call` 指令和 dmesg 的打印文字只是佐证。`bt` 被截断时必须披露 |
| `dis -l` line-annotation boundary | `dis -l` 的行号只说明指令来自哪一行；没有 `read_source` / `find_struct` 的 `SOURCE_REF` 文本时，不能断言那一行写了什么语句 |
| Configured vs. actual duration | 配置值（如 `stall_duration_ms=70000`）与实际耗时（`gp_age_jiffies`、dmesg 时间戳差）分开写 |
| Truncated-stack follow-up | 要引用的任务栈被截断（分析器标 `bt_truncated` / `waiter_bt_truncated`，或栈停在 `schedule_timeout` 之类的调度帧）且分析器建议了 `bt -f`，下结论前先执行；做不到就写明栈被截断，任务角色只写成"与 `__state` / dmesg 相符"，不写成观察到的调用链 |
| No placeholder values | 禁止写 `ffffffffaa42xxxx`、`0x...`、`<addr>` 这类遮掩或编造的地址与数值；工具没打印绝对地址时，只引用它实际打印的内容 |
| SOURCE_REF citation scope | 只有落在 `read_source` / `find_struct` 实际打印的 `lines=<start>-<end>` 窗口内的行，才能说成有 SOURCE_REF；只从 `dis -l` 标注得知的行写成反汇编证据 |
| Disassembly vs. backtrace offset radix | `crash dis` 的 `<sym+N>` 是十进制（如 `+221`），`bt` / dmesg 的 `+0xN/0xSIZE` 是十六进制；引用 `dis` 偏移时要么原样写十进制，要么换算后再加 `0x`（`+0xdd`），不能把十进制偏移直接加 `0x` |

另外，3.7a 对每个分析器写明 "Accepts ONLY these N options"，并指出另一个工具的选项属于谁（例如 `--top` 属于 `analyze_lock_wait_graph`，`analyze_cpu_lockup_rcu` 不接受）。`lock_hang_fast_path`（SOP 兜底）要求 `--rcu-pids` 同时包含阻塞的读者和 `synchronize_rcu` / GP 等待者的 PID，并明确不要传 `--top`。

**这些都是提示词约束，执行器不强制**；模型不遵守时不会被拦下。

### 2.6 收尾豁免与工具报错重试

根因已定、门控全关时，执行器会让模型立即收尾。下面两种情况会暂缓，让模型先补救一次：

- **工具整轮报错**（`tool_error`）：纠正参数后重试一次。典型例子：`read_source` 一次传了多个文件和行号，被拒绝后应改成单文件调用。
- **源码可读但 0 条 `SOURCE_REF`**：补一次 `read_source`，再下结论。

两者各自只触发一次，`rejected`（dedup / convergence-guard）不触发。实现与"三处收尾通道必须同时让位"的细节见 `ARCHITECTURE.md` 的"收尾豁免"一节。


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
`test_lock_hang_client.py` 覆盖 `build_tool_payload`（四种入参形态的压平规则、结构化参数映射、未知键与跨工具键的报错、`command` 串预检，以及 server 返回的 `[error]` 前缀），并额外做一次 server 注册断言：
它导入 `lock_hang_server` 并检查两个工具都出现在 `get_tools()` 里。这一步不能省——FastMCP 会按 `Field(default=...)` 重建 pydantic 模型，
若把带默认值的参数排在必需参数之前，进程会在 import 阶段抛 `SchemaError: Non-default argument ... follows default argument`，
结果是 **server 起得来但工具数为 0**，而纯 analyzer 测试全绿也发现不了。

与这些修复相关的其他测试：

```bash
# 工具报错判定、收尾豁免、证据纪律规则、Source Citations 渲染
.venv/bin/python -m unittest tests.test_prompt_builder tests.test_kernel_source tests.test_report_generator
.venv/bin/python -m pytest tests/test_tool_error_status.py -q
```

- `test_tool_error_status.py`：整轮报错记 `tool_error`、部分成功仍是 `executed`、`[TIMEOUT]` 与"输出中间出现 `SOURCE_ERROR`"都不算工具报错、`[error]` / `Failed to analyze` / `SOURCE_ERROR` 三种前缀都被识别；
- `test_prompt_builder.py` 的 `TerminateExemptionTests`、`SourceCitationStatusTests`：豁免只对 `tool_error` 生效、只触发一次、三处收尾通道同步让位；
- `test_kernel_source.py` 的 `PayloadTypeValidationTests`：列表 / 布尔 / 浮点被拒，数字字符串转 `int`；
- `test_report_generator.py` 的 `SourceCitationLineTests`：三种引用状态与审计行位置。

## 4. 两个工具的入参形态

`build_tool_payload` 会把 LLM 传来的参数的四种形态（`dict` / `list` / `None` / 标量）统一压平成单个 `command` 字符串，
再从 state 注入 `vmcore_path` / `vmlinux_path`，所以工具侧只需要处理 `command`：

| 工具 | 参数语法 |
|---|---|
| `analyze_lock_wait_graph` | `[--pids <pid1,pid2,...>] [--top <int>] [--max-depth <int>] [--lock-addr <hex>] [--lock-type <mutex\|rwsem>]` |
| `analyze_cpu_lockup_rcu` | `[--cpus <cpu1,cpu2,...>] [--rcu-pids <pid1,pid2,...>] [--include-idle]` |

`command` 为空时行为：前者取 `ps -m` 中阻塞最久的 12 个 `UN` 任务（`--top` 默认 12，范围 1..64），
后者分析全部非 idle CPU。`--max-depth` 默认 6，范围 1..16。只传 `--lock-addr` 而省略 `--lock-type` 时按 `mutex` 处理，确认是读写信号量时需显式传 `rwsem`。参数经 `shlex.split` 解析，因此可以带引号。

### 4.1 结构化参数与派发前预检

LLM 可以用两种写法传参：`arguments`（选项列表或 `command` 字符串）或 `parameters`（结构化 dict）。`build_tool_payload` 都会转成同一条 `command`，然后**在派发前再用 analyzer 自己的解析器预检一遍**，非法选项直接抛 `ValueError`（报错里列出该工具"只接受"的选项），执行器记为 `tool_error` 并给一次纠错重试。

| 写法 | 例子 | 说明 |
|---|---|---|
| `arguments` 列表 | `["--rcu-pids", "309547,309548"]` | 拼成 `--rcu-pids 309547,309548` |
| `command` 字符串 | `{"command": "--top 12 --max-depth 6"}` | 原样使用 |
| `parameters` dict | `{"rcu_pids": [309547, 309548], "include_idle": true}` | 按工具映射成 `--rcu-pids 309547,309548 --include-idle` |

`parameters` 的键对应关系：

| 工具 | 键 |
|---|---|
| `analyze_lock_wait_graph` | `pids`、`top`、`max_depth`、`lock_addr`、`lock_type` |
| `analyze_cpu_lockup_rcu` | `cpus`、`rcu_pids`、`include_idle` |

注意：

- **两个工具的选项互不通用**。把 `--top` 传给 `analyze_cpu_lockup_rcu`、或把 `--rcu-pids` 传给 `analyze_lock_wait_graph`，都会在派发前被拒绝。
- 列表型取值（`pids` / `cpus` / `rcu_pids`）允许 `[1, 2]`、`"1,2"`、`"1, 2"` 三种写法，最终统一成 `1,2`。
- 同一个动作里 `parameters` 与 `arguments` 都给出时，`arguments` 会被忽略（见 `ARCHITECTURE.md` 的已知语义风险），建议只用其中一种。
