# VMCore Analysis Agent

[English](./README.md) | 简体中文

![VMCore Analysis Agent](./doc/vmcore-analysis-agent-logo.svg)

基于 LangGraph、MCP 和 Linux `crash` 工具的 vmcore 分析服务。项目入口位于 [`vmcore-analysis-agent/`](./vmcore-analysis-agent/)；本 README 介绍该组件的工作流程、部署方式和输出。

## 项目能做什么

服务接收 vmcore、匹配的 `vmlinux`、`vmcore-dmesg.txt` 以及可选的模块调试符号，驱动 Agent 循环执行 `crash` 命令并生成 Markdown 分析报告。分析结果用于辅助定位，仍需结合内核版本、符号文件和现场信息由工程师复核。

主要能力：

- 先收集崩溃基础信息（含已加载模块 `mod`），再根据当前分析状态选择后续诊断动作。
- 通过 MCP 调用 `crash` 等工具，对命令执行进行保护和去重；严格约束 `run_script` 语法（执行纯 crash 命令、拦截 shell 控制流并引导循环展开与单步多命令批量取证）。
- 自动检测并提示模块私有结构体类型所需的会话级 `mod -s <module>` 前导符号加载。
- 结合内核源码树提供结构体定义快速定位（`find_struct`）、反汇编代码行映射与补丁验证。
- 使用假设与验证门控跟踪证据；是否关闭门控由执行器根据工具输出判断，而非直接采信模型给出的状态。
- 针对长时分析提供证据按类别截断、关键目标地址锁定与历史消息 Gate 载荷精简，有效控制 Token 消耗与上下文膨胀。
- 提供同步和 SSE 流式 API；报告正文之外可生成单独的 Gate 审计文件。

## 工作流程

![分析工作流程](./doc/workflow.zh-CN.svg)

一次分析大致经过以下步骤：

1. FastAPI 检查请求中的文件路径，并创建 Agent 初始状态。
2. LangGraph 执行初始 `crash` 命令，收集系统、taint 和堆栈信息。
3. LLM 根据当前上下文选择下一步分析或工具调用；`action_guard` 和执行器负责约束、执行工具动作。
4. 证据评估器从工具输出提取事实并更新 Gate。必需 Gate 尚未达到 `closed` 或 `n/a` 时，分析不能标记为已确定。
5. 服务返回分析结果；客户端默认保存 Markdown 报告，并在存在 Gate 数据时保存配套的 `.audit.md`。

### 核心目录

| 路径 | 职责 |
|---|---|
| [`main.py`](./vmcore-analysis-agent/main.py) | FastAPI 服务、分析 API 与生命周期初始化 |
| [`client/`](./vmcore-analysis-agent/client/) | HTTP/SSE 客户端及命令行入口 |
| [`src/react/`](./vmcore-analysis-agent/src/react/) | LangGraph 节点、路由、状态、Prompt、证据评估和报告生成 |
| [`src/llm/`](./vmcore-analysis-agent/src/llm/) | LLM 客户端创建 |
| [`src/mcp_tools/`](./vmcore-analysis-agent/src/mcp_tools/) | MCP 工具注册及 crash、源码补丁等工具 |
| [`tests/`](./vmcore-analysis-agent/tests/) | 单元和集成测试 |
| [`doc/`](./vmcore-analysis-agent/doc/) | 架构流程图等项目文档 |
| [`reports/`](./vmcore-analysis-agent/reports/) | 本地生成的报告目录 |

## 部署前准备

服务运行在能够访问 vmcore 文件的 Linux 主机上。准备以下环境和输入：

- Python 3.11 或更高版本，以及 [`uv`](https://docs.astral.sh/uv/)。
- Linux `crash` 工具，以及与 vmcore 内核版本匹配的 `vmlinux` 调试符号。
- 与该 vmcore 对应的 `vmcore-dmesg.txt`。
- 可选：需要分析的第三方内核模块调试符号（`.ko`）。
- 可访问的 OpenAI 兼容模型服务及 API Key。

仓库提供的 mpykdump 安装脚本面向 x86_64，并随附 crash 8.0/9.0 对应扩展。其他 crash 版本需自行准备兼容扩展。

## 快速开始

以下命令以 Linux shell 为例。

### 1. 安装依赖

在仓库根目录执行：

```bash
cd vmcore-analysis-agent
uv sync
```

如果需要安装仓库提供的 mpykdump 扩展，在 `vmcore-analysis-agent` 目录执行（脚本会向系统 crash 扩展目录写文件，可能需要 `sudo`）：

```bash
bash tools/install_mpykdump.sh
```

### 2. 配置模型

复制配置模板：

```bash
cp .env.example .env
```

编辑 `vmcore-analysis-agent/.env`，填入模型服务的有效凭据和地址：

```dotenv
REASONING_API_KEY=替换为你的API密钥
REASONING_BASE_URL=https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1
REASONING_MODEL=deepseek-v4.1-flash-1017
REASONING_PARAM_PROFILE=deepseek

REASONING_THINKING=enabled
REASONING_EFFORT=max
REASONING_TEMPERATURE=0.1
REASONING_CONTEXT_WINDOW=524288
REASONING_MAX_OUTPUT_TOKENS=48000
REASONING_MIN_THINKING_OUTPUT_TOKENS=40960
REASONING_HISTORY_KEEP=2
LANGSMITH_TRACING=false

# 长度失败熔断阈值与降级配置
REASONING_LENGTH_FAILURE_THRESHOLD=2
REASONING_DEGRADED_MAX_OUTPUT_TOKENS=16000
REASONING_DEGRADED_REASONING_EFFORT=low
REASONING_DEGRADED_THINKING=false

# 可选：源码级验证使用的内核源码树
# KERNEL_SOURCE_ROOT=/data/kernel-src/4.18.0-305.130.1.el8_4.x86_64
KERNEL_SOURCE_ROOT=
```

| 变量 | 必需 | 说明 |
|---|---:|---|
| `REASONING_API_KEY` | 是 | 模型服务 API Key |
| `REASONING_BASE_URL` | 是 | 模型服务的 OpenAI 兼容 API 地址 |
| `REASONING_MODEL` | 是 | 服务端使用的模型名称 |
| `REASONING_PARAM_PROFILE` | 否 | 网关参数能力档位：`deepseek`（默认，使用 `ChatDeepSeek` 并下发私有 `thinking` 字段）或 `openai`（适用于严格校验 `/v1/chat/completions` 的网关，使用 `ChatOpenAI` 且不发送 `thinking` 字段） |
| `REASONING_THINKING` | 否 | `enabled` 或 `disabled`，默认 `disabled` |
| `REASONING_EFFORT` | 否 | 推理强度（`deepseek` 档位支持 `minimal`、`low`、`medium`、`high`、`max`；`openai` 档位支持 `minimal`、`low`、`medium`、`high`、`xhigh`），默认 `max` |
| `REASONING_TEMPERATURE` | 否 | 采样温度，默认 `0.1` |
| `REASONING_CONTEXT_WINDOW` | 否 | 上下文预算，默认 `524288`；应按模型服务商的实际限制设置 |
| `REASONING_MAX_OUTPUT_TOKENS` | 否 | 最大 completion 预算，默认 `48000` |
| `REASONING_MIN_THINKING_OUTPUT_TOKENS` | 否 | 保持 thinking 模式所需的最低输出预算，默认 `40960` |
| `REASONING_HISTORY_KEEP` | 否 | 压缩时保留的历史 reasoning 数量，默认 `2` |
| `REASONING_LENGTH_FAILURE_THRESHOLD` | 否 | 单次分析中输出长度超限（max_tokens）的熔断阈值，默认 `2`。达到该次数后本次运行的后续调用启用降级配置；设为 `0` 关闭熔断 |
| `REASONING_DEGRADED_MAX_OUTPUT_TOKENS` | 否 | 降级调用的最大 completion 预算，默认 `16000` |
| `REASONING_DEGRADED_REASONING_EFFORT` | 否 | 降级调用的推理强度，默认 `low` |
| `REASONING_DEGRADED_THINKING` | 否 | 降级调用是否启用 thinking，默认 `false` |
| `KERNEL_SOURCE_ROOT` | 否 | 与本次 dump 匹配的内核源码树（也可指向按版本分目录的根目录）；仅在请求未提供 `kernel_source_root` 时生效。启用 `read_source` / `list_writers` / `git_history` / `find_struct`，留空时 agent 会明确说明源码无法核实，而不是凭记忆引用内核代码 |
| `LANGSMITH_TRACING` | 否 | 是否启用 LangSmith 追踪，默认 `false` |

输出长度熔断可配置：`REASONING_LENGTH_FAILURE_THRESHOLD`（默认 `2`，设为 `0` 关闭）、`REASONING_DEGRADED_MAX_OUTPUT_TOKENS`（默认 `16000`）、`REASONING_DEGRADED_REASONING_EFFORT`（默认 `low`）、`REASONING_DEGRADED_THINKING`（默认 `false`）。达到阈值后，同一 run 的后续调用改用降级预算，避免因长度被拒的输出再次按全预算重试。

进程环境变量优先于 `.env`。缺少三个必需模型变量或配置值无效时，服务会在启动阶段报错。不要提交含真实密钥的 `.env` 文件。MCP 工具由代码自动发现，不需要在 `.env` 中填写 MCP 服务路径。

### 3. 启动服务

在 `vmcore-analysis-agent` 目录执行：

```bash
uv run uvicorn main:app --host 0.0.0.0 --port 8000
```

- 健康检查：<http://localhost:8000/health>
- API 文档：<http://localhost:8000/docs>
- 指标：<http://localhost:8000/metrics>

当前 API 未实现内置身份认证。生产部署时请限制网络访问，或在受控的反向代理/API 网关后提供服务。

### 4. 调用分析

客户端应能访问服务端，且请求中的文件路径必须是**服务端可访问的路径**（客户端不会上传 vmcore 文件）。

```bash
cd client
uv run main.py --health --url http://localhost:8000

uv run main.py --url http://localhost:8000 --stream \
  --vmcore-path /data/case/vmcore \
  --vmlinux-path /usr/lib/debug/lib/modules/<kernel-version>/vmlinux \
  --vmcore-dmesg-path /data/case/vmcore-dmesg.txt \
  --debug-symbols /data/case/driver.ko \
  --kernel-source-root /root/kernel-sources/8/4.18.0-553.22.1.el8_10/BUILD/kernel-4.18.0-553.22.1.el8_10/linux-4.18.0-553.22.1.el8_10.x86_64 \
  --output-dir ../reports
```

`--kernel-source-root` 是可选的；第 5 步说明如何准备它所指向的源码目录。

主要参数：

| 参数 | 说明 |
|---|---|
| `--url` | API 服务地址，默认 `http://localhost:8000` |
| `--health` | 只检查服务健康状态 |
| `--stream` | 使用 SSE 流式接口；不指定时使用同步接口 |
| `--vmcore-path` | vmcore 路径 |
| `--vmlinux-path` | 匹配的 `vmlinux` 路径 |
| `--vmcore-dmesg-path` | `vmcore-dmesg.txt` 路径 |
| `--debug-symbols` | 可选的模块调试符号路径，可提供多个 |
| `--kernel-source-root` | 服务端可见的内核源码树路径，通常是 `rpmbuild -bp kernel.spec` 的产物目录（含 `Makefile` 与 `kernel/` 或 `include/linux/`）。优先于 `KERNEL_SOURCE_ROOT`；留空时使用服务端默认配置 |
| `--timeout` | 请求超时秒数，默认 `600` |
| `--output-dir` | 报告输出目录，默认 `../reports`（相对于 `client` 当前目录） |
| `--no-save` | 不保存报告文件 |

### 5. 准备内核源码（可选，用于源码级验证）

有匹配的源码树时，agent 可以读取 `dis -s` 给出的 `file:line` 处真实代码、按类型名快速查找结构体定义及成员声明（`find_struct`，减少交替 grep 与 read 源码的开销）、枚举可能写某个字段的代码路径、并确认这棵树里是否已包含修复。没有源码树时，agent 会明确说明"源码无法核实"，而不是凭记忆引用内核代码。

在**服务端**用 [`tools/get-kernel-source.sh`](tools/get-kernel-source.sh) 准备源码：

```bash
# 1) 使用本地已有的 SRPM
SRC=$(bash tools/get-kernel-source.sh -s /home/user/Downloads/kernel-4.18.0-553.22.1.el8_10.src.rpm)

# 2) 或按内核版本下载 SRPM（需要已启用 source 仓库）
SRC=$(bash tools/get-kernel-source.sh 5.14.0-362.24.1.el9_3)

# 3) 或只定位此前已经准备好的源码树
SRC=$(SKIP_PREPARE=1 bash tools/get-kernel-source.sh 5.14.0-362.24.1.el9_3)
```

脚本会启用匹配的 source 仓库、把 SRPM 安装到独立的 `_topdir`、执行 `rpmbuild -bp`，并且**只在 stdout 输出**准备好的目录（日志全部走 stderr），所以可以直接用 `SRC=$(...)` 取值。支持 RHEL 7/8/9/10。工作区布局：

```text
${SOURCE_ROOT:-/root/kernel-sources}/<RHEL大版本>/<内核版本>/BUILD/kernel-<ver>/linux-<ver>.<arch>/
```

常用参数：`SOURCE_ROOT=/var/lib/kernel-sources` 改变工作区位置，`SKIP_PREPARE=1` 复用已准备的树，`--uninstall` 删除某个工作区。

前置条件与注意事项：

- 脚本需以 root 运行，或使用有权启用仓库、安装 RPM 的账号。
- **服务进程**必须能读该目录。`/root/kernel-sources` 只有 root 可读；若服务以普通账号运行，请把工作区放到共享路径（如 `SOURCE_ROOT=/var/lib/kernel-sources`）并授予读权限。
- `rpmbuild` 用**宿主机的** `%{?dist}` 命名源码树，所以在 el9 机器上准备 el8 的 SRPM 会得到 `linux-...el9...` 目录。只要上游内核版本一致，agent 会接受并在工具输出中写一条 `note` 说明。

然后把打印出的目录传给客户端：

```bash
uv run main.py --url http://localhost:8000 --stream \
  ... \
  --kernel-source-root "$SRC"
```

优先级：请求字段 `kernel_source_root`（`--kernel-source-root`）优先；未提供时使用服务端默认配置 `KERNEL_SOURCE_ROOT`。两者都没有时，源码级验证保持关闭，agent 必须明确说明这一点。

版本匹配：agent 会把源码树版本与 `sys` 报告的内核版本比对。内核版本不同会被拒绝，因此绝不会读错树的代码；只差 `el` 发行标签或架构后缀时会被接受，并附带说明。

## API 与输出

### API

| 方法 | 路径 | 用途 |
|---|---|---|
| `GET` | `/health` | 返回服务、LLM 和工具初始化状态 |
| `POST` | `/analyze` | 同步分析 |
| `POST` | `/analyze/stream` | 通过 Server-Sent Events 返回进度和结果 |

两个分析接口使用相同的 JSON 请求字段：

```json
{
  "vmcore_path": "/data/case/vmcore",
  "vmlinux_path": "/data/case/vmlinux",
  "vmcore_dmesg_path": "/data/case/vmcore-dmesg.txt",
  "debug_symbol_paths": ["/data/case/driver.ko"],
  "kernel_source_root": "/root/kernel-sources/8/4.18.0-553.22.1.el8_10/BUILD/kernel-4.18.0-553.22.1.el8_10/linux-4.18.0-553.22.1.el8_10.x86_64"
}
```

前三个字段必需；`debug_symbol_paths` 可省略或传空数组。`kernel_source_root` 可选，未提供时回落到服务端的 `KERNEL_SOURCE_ROOT`。文件路径由服务端检查。同步响应包含 `success`、`task_id`、`agent_answer`、`token_usage`，以及可选的 `error`、`audit_report`。流式接口以 SSE 事件发送进度，完成事件包含分析结果和审计内容。

### 报告文件

服务当前默认生成英文报告。客户端默认保存分析 Markdown 报告；如果结果中包含 Gate 数据，还会保存同名的 `.audit.md` 文件。`--no-save` 会跳过这两个文件的保存。审计文件记录 Gate 状态、证据和状态转换，适合追溯；常规阅读优先查看主报告中的验证状态摘要。

## 诊断状态与 Gate

`CrashSignatureClass` 表示从崩溃现场初步识别出的签名，用于选择诊断路径；`RootCauseClass` 表示调查后确认的根因类别。两者不是同一层级的分类。

Gate 是分析状态机中的验证检查点。Gate 是否关闭由执行器根据工具输出中的结构化证据评估，模型给出的状态只是建议。当前签名要求的 Gate 尚未全部达到终态时，分析不会被标记为确定。

| 状态 | 含义 |
|---|---|
| `open` | 尚未完成验证 |
| `blocked` | 前置 Gate 未满足，当前检查暂不能完成 |
| `closed` | 已满足相应证据条件 |
| `n/a` | 已确认该检查不适用，需有理由 |

常见检查：

- `register_provenance`：追溯故障寄存器中的值来自哪个指令、对象或字段。
- `object_lifetime`：评估转储中对象/内存槽位的当前状态。比如 `kmem -S` 显示 `[ALLOCATED]` 只能说明转储时槽位已分配，不能据此排除对象曾释放后被复用。
- `local_corruption_exclusion`：结合反汇编和内存观测，检查本地代码是否可能写入异常值。

具体必需 Gate 和完成条件由 [`schema.py`](./vmcore-analysis-agent/src/react/schema.py) 与 [`evidence.py`](./vmcore-analysis-agent/src/react/evidence.py) 定义。

### 长时分析与证据膨胀控制

在长时间复杂 vmcore 分析中，单次 `kmem`、`rd`、`dis` 等命令可能产生数百至上千条结构化事实。为避免上下文超限与历史消息膨胀，系统具备以下机制：

- **门控证据按类别截断与汇总**：门控展示层（`gate.evidence`）按事实前缀分类，每类最多保留 8 条事实，超出部分幂等合并为 `<category>: ... (+N more)` 计数；审计报告中会明确标注为截断视图。
- **关键目标地址锁定与置顶**：通过地址提取自动锁定当前证据目标与动作意图中的关键十六进制地址（含目标对象及生命周期闭合交集地址），确保关键证据不被字典序无关地址挤出。
- **精简历史消息载荷**：写入 `AIMessage` 历史对话的门控状态仅保留 `required_for`、`status` 和 `closure_basis`，剥离冗长的证据文本与完成标准，消除单步 MB 级的消息体积膨胀与重复反序列化开销。
- **完整闭合判定保真**：状态中的 `evidence_facts` 依然保持全量事实，门控闭合判定基于完整事实集执行，不影响判断准确性。

## 项目结构

```text
ai-app-hub/                       # 仓库根目录（包含多个项目）
├── README.md
├── README.zh-CN.md
└── vmcore-analysis-agent/         # 本文档介绍的组件
    ├── main.py                   # FastAPI 入口
    ├── client/                   # CLI 与 HTTP/SSE 客户端
    ├── src/
    │   ├── llm/                  # 模型初始化
    │   ├── react/                # Agent 图、Prompt、状态、证据和报告
    │   ├── mcp_tools/            # MCP 工具
    │   └── utils/                # 设置与日志
    ├── tests/                    # 测试
    ├── tools/                    # 运维和调试辅助脚本
    ├── doc/                      # 流程图等文档
    ├── simulate-crash/           # 崩溃复现场景
    ├── reports/                  # 报告输出目录
    ├── pyproject.toml
    ├── uv.lock
    └── .env.example
```

## 常见问题

- **服务启动提示缺少配置**：检查 `vmcore-analysis-agent/.env` 或进程环境中是否设置了 `REASONING_API_KEY`、`REASONING_BASE_URL`、`REASONING_MODEL`。
- **模型网关报错 `400 unsupported_parameter: 'thinking'`**：部分严格校验 `/v1/chat/completions` 的网关不接受 DeepSeek 私有的 `thinking` 字段，请在 `.env` 中设置 `REASONING_PARAM_PROFILE=openai`，并将 `REASONING_EFFORT` 设为网关支持的值。
- **执行 crash 脚本提示 `shell control flow is not executable by crash` 或语法被拦截**：`run_script` 的每个参数仅执行单条 crash 原生命令，不支持 `for`/`while`/`if` 循环、分号、`&&`、重定向（如 `2>/dev/null`）或 shell 变量。应将循环展开为逐行独立的 crash 命令（支持在同一次 `run_script` 中批量传入多行以减少交互步数）。
- **执行 crash 脚本提示 `gdb request failed` 或结构体无法识别**：若引用的结构体属于第三方或内核模块私有类型，由于每次 `run_script` 都是独立的 crash 进程会话，脚本中需在读取该类型前显式执行 `mod -s <module>` 加载模块符号。
- **文件不存在**：传给 API 的路径在服务端解析，不是运行 CLI 的客户端本地路径。
- **crash 命令或扩展不可用**：确认服务主机已安装 `crash`，符号文件与 vmcore 对应；仓库脚本只适用于 x86_64 的 crash 8.0/9.0。
- **模块缺少源码/符号信息**：为对应内核和模块准备匹配的调试符号；可参考下方附录。
- **API 长时间无响应**：尝试 `--stream` 查看进度，并根据分析耗时调整客户端 `--timeout`。若多次遇到输出长度超限，可确认已启用 `REASONING_LENGTH_FAILURE_THRESHOLD` 熔断降级。

## 附录：第三方驱动调试符号编译指南（以 mlx5_core 为例）

在分析涉及第三方驱动（如 Mellanox 网卡驱动）的 vmcore 时，如果默认驱动缺少调试符号，需要手动安装源码并重新编译。以下是标准操作流程：

### 1. 环境准备

安装驱动源码包和对应的内核开发包：

```bash
# 安装 Mellanox 驱动源码
rpm -ivh mlnx-ofa_kernel-source-5.8-OFED.5.8.3.0.7.1.rhel8u4.x86_64.rpm

# 安装对应版本的内核开发包（需与 vmcore 的内核版本一致）
rpm -ivh --oldpackage kernel-devel-4.18.0-305.130.1.el8.x86_64.rpm
```

### 2. 编译带调试信息的模块

进入源码目录并配置编译选项：

```bash
cd /usr/src/ofa_kernel-5.8/source

# 配置编译选项：开启 debug info，指定内核源码路径
./configure --with-debug-info --with-mlx5-mod \
                 --kernel-sources /usr/src/kernels/4.18.0-305.130.1.el8_4.x86_64 \
                 --cache-file=my_config.cache

# 执行编译
make -j$(nproc)
```

### 3. 验证调试符号

编译完成后，通过以下方式验证模块是否包含调试信息：

```bash
# 1. 检查 debug section 是否存在
readelf -S drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.ko | grep debug

# 2. 尝试反汇编导出源码（验证源码关联）
objdump -S -d drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.ko > mlx5_debug.asm

# 3. 使用工具脚本验证符号解析
# 从仓库根目录执行
cd /path/to/ai-app-hub
bash vmcore-analysis-agent/tools/show_first_global_func.sh /usr/src/ofa_kernel-5.8/source/drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.ko
```

## 贡献与许可

欢迎提交 Issue 和 Pull Request。本项目完全开源，采用 MIT License；发布时请确保发行包包含对应的许可证文本。

## 联系方式

- 邮箱：[wubo0067@hotmail.com](mailto:wubo0067@hotmail.com)
- GitHub：[wubo0067](https://github.com/wubo0067)
