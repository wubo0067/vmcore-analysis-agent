# VMCore Analysis Agent — 架构与核心逻辑

本文是给维护者的"读码地图"：先给一句话核心，再按数据流展开三个子系统，最后回答"想改 X 应该动哪个文件"。

## 一句话核心

**LangGraph 上的 ReAct 循环（LLM 决策 ↔ crash 工具执行），但 LLM 的输出从不直接生效——每一步都要经过执行器侧（executor-owned）的修复、审计、门控三层确定性治理。**

理解本项目的前提：结论字段（`root_cause_class`、`corruption_mechanism`、`is_conclusive`、`confidence`）有**两个写入者**——LLM 和执行器审计器。读代码时最先要分清"这句话/这个值是谁写的"。

```mermaid
flowchart LR
    START --> A[collect_crash_init_data_node]
    A --> B[llm_analysis_node]
    B -->|tool_calls| C[crash_tool_node]
    C -->|事实 / 门控 / 矛盾 更新| B
    B -->|action=null 且收敛| END[__end__]
    B -.->|reasoning 需要结构化时| S[structure_reasoning_node]
    S -.-> B
    END --> R[report_generator]
```

- 图拓扑：`src/react/graph.py`（`create_agent_graph`）
- 路由：`src/react/edges.py`（`should_continue` / `after_crash_tool`）
- 步数上限：`main.py` 的 `AGENT_RECURSION_LIMIT = 121`
- 入口：`main.py` FastAPI `/analyze`、`/analyze/stream`（SSE），最终由 `report_generator.generate_markdown_report` 渲染报告

## 三个子系统（按数据流顺序）

### ① Prompt 组装 —— 发给 LLM 之前

唯一装配点：`prompt_builder.build_analysis_system_prompt(state, is_last_step=...)`。按状态动态拼接以下层：

| 层 | 文件 | 选择方式 |
|---|---|---|
| 总纲（Stage 0-6、S1-S5 anchor、禁止推理模式） | `layer0_system.py` | 恒定注入 |
| 崩溃类型剧本 | `playbooks.py`（`PLAYBOOKS`） | `_select_playbook` 按签名/近期文本选一个 |
| SOP 片段（DMA、stale-data 等专题） | `sop_fragments.py`（`SOP_FRAGMENTS`） | `_select_sop_fragments` 按信号动态追加 |
| 上下文 overlay | `prompt_overlays.py` | `_select_context_overlays` |
| 共享短语（如 `{S1_S5_DMA_GATE_RULE}`） | `prompt_phrases.py` | 占位符替换 |
| 执行器状态回灌 | `prompt_builder.build_executor_state_section` | 门控状态、未决矛盾、假设、下一步目标 |

**执行器状态回灌是 LLM 与执行器之间唯一的反馈通道**：门控没关、矛盾未解，都会以文本形式出现在下一轮 prompt 里。

`llm_runtime.py` 负责发送前的消息压缩（`compress_messages_for_llm`）与基于真实 token 的预算规划（`prepare_messages_for_llm`）：历史 AI 消息中的 `gates[*].evidence` 只保留在状态/报告中，请求副本会清空；thinking 模式下输出预算覆盖 reasoning + 正文，预算不足时关闭 thinking 或快速失败，不再静默回落到 4,096。

### ② LLM 输出强制管线 —— 每轮固定顺序（`llm_node.py`）

```
repair_structured_output            # JSON/枚举修复（output_parser）
→ apply_executor_consistency_audit  # 确定性审计：可改写结论字段、注入 audit note
→ apply_value_conflict_audit        # 未解决数值矛盾 → 压制收敛/改写根因
→ project_managed_analysis_step     # state_manager：投影门控请求；
                                    #   evidence.evaluate_gate_closures 独占终态判定，
                                    #   拒绝未经验证的 LLM closed/n/a 请求
→ build_tool_calls                  # action → tool_calls（含 action_guard 预检）
→ （收口轮：违规请求工具 → 强制重试一次）
→ apply_fallback_conclusion_synthesis # 收口轮兜底：确定性合成有界结论
```

`structure_reasoning_node`（`llm_node.structure_reasoning_content`）走同一条审计+投影链路（`_audit_and_project` 复用）。

### ③ 工具执行侧 —— `nodes.call_crash_tool`

```
validate_tool_call_request      # action_guard：命令合法性、参数校验、指纹去重
→ dispatch_crash_commands       # 经 MCP 执行（mcp_tools/registry.py 发现 provider）
→ extract_evidence_facts        # evidence：工具输出 → 结构化事实（见下方前缀表）
→ detect_value_conflicts        # consistency：struct 布局 vs 实际内存读数的矛盾
→ update_gate_evidence          # 门控证据累积
```

去重与防停滞状态在 `AgentState`：`executed_fingerprints`、`replayed_fingerprints`、`duplicate_streak`、`no_progress_streak`、`replan_required`。

重复命令的处理只有**一次**宽容：缓存输出有实质证据时，第一次重复回放 `[DEDUP]`（省预算），
并把指纹记入 `replayed_fingerprints`；同一指纹第二次被索取时不再回放，改发 `[DEDUP-BLOCKED]`
硬拒（走 `rejected` 分支，`no_progress_streak` 累加并触发 replan advisory）。否则"有证据"的
重复命令可以无限次骗取同一份输出，只能等 streak 触顶才被掐停。

硬拒消息本身只说"这条命令做过了"，不给出口；当 `no_progress_streak` 达
`CONVERGENCE_GUARD_STREAK_THRESHOLD` 且被拒命令全部是只读取值探测（`rd`/`struct`/`dis`/`kmem`
等，见 `_READONLY_VALUE_PROBE_COMMANDS`）时，`[DEDUP-BLOCKED]` 追加 `FORCED_CHOICE_CONVERGENCE_RULE`
强制二选一：(A) 立即提交结论（`root_cause_class` 必须是真实类，不能是 `unknown`），或
(B) 声明一个此前未观测过的新证据目标。该通道**刻意不看根因是否已提交、也不看门控是否关闭**，
因为真实耗尽预算的 run 恰恰是模型从未提交根因、且在 dedup 分支提前 `continue` 而走不到
`_convergence_guard_error`；`prompt_builder._build_replan_probe_menu` 用同一份措辞镜像到转向菜单。

"根因是否已提交"统一由 `graph_state.has_committed_root_cause` 判定：`None`、`""`、`unknown`
都算未提交（`unknown` 是 `RootCauseClass` 的合法成员且为真值，直接真值判断会把"尚未定论"
当成"结论已成立"，让 `TERMINATE ON THIS TURN` 等通道在错误前提上运行）。

## 一次分析的完整生命周期：从现象到根因

前面三个子系统是"静态结构"；这一节按**时间轴**讲一次 `/analyze` 请求里 agent 如何一步步从
现象推到根因。主干不是固定 pipeline，而是"**执行器定骨架、LLM 选动作**"的 ReAct 循环。
每一步"现在在哪、还缺什么、允许做什么"由三个确定性机制算出并回灌进 prompt，LLM 只决定
"这一轮执行哪条 crash 命令、当前假设是什么"：

1. **Stage 0-6 方法论**（`layer0_system.py` PART 0 / 2.2）——固定主干阶段：分类 → 定位故障
   指令 → 寄存器溯源 → 故障地址分类 → 对象验证 → 破坏源区分 → 根因假设；
2. **签名类强制门控**（`schema._REQUIRED_GATES` → `managed_gates`）——还缺哪些证据、什么才
   允许下结论；
3. **步数预算**（`prompt_builder._infer_stage_name` + SOP 触发条件 + layer0 2.4a 里程碑）——
   现在处于哪个阶段、到当前步数必须达成什么。

> `step_count` 按**节点**累加（llm 节点与 crash_tool 节点各 +1，一次往返 +2），下文步数均指
> 该计数器，与人类直觉的"第几轮工具调用"不同。

```mermaid
flowchart TD
  A["step 0 现象采集<br/>collect_crash_init_data:<br/>sys / sys -t / bt + dmesg 上下文窗口"] --> B["step 1 分类轮<br/>signature_class 强制 null"]
  B --> C["step 2 签名落定<br/>门控集合实例化 + playbook 挂载 + 证据目标建立"]
  C --> D["取证循环 Stage 2-5<br/>门控目标驱动，每轮一个动作"]
  D --> E{"未决门控=0 且<br/>root_cause_class 已定?"}
  E -- 否，继续取证 --> D
  E -- 是 --> F["收敛轮 Stage 6<br/>TERMINATE ON THIS TURN"]
  F --> G["final_diagnosis<br/>（LLM 结论或执行器兜底合成）"]
  G --> H["report_generator<br/>分析报告 + Gate 审计"]
  D -. "no_progress≥3 / is_last_step<br/>→ 强制收口（最多一次）" .-> F
```

### 阶段 0：现象采集（step 0，不进 ReAct 循环）

`nodes.collect_crash_init_data`：

- 并发执行 `DEFAULT_CRASH_COMMANDS`：`sys`（系统概况）、`sys -t`（崩溃时间戳）、`bt`（崩溃栈）；
- 从 bt 提取 panic 的 PID/CPU/COMMAND，据此在 vmcore-dmesg 中定位匹配行，取其**前 50 行**作为
  崩溃前上下文窗口；
- 拼成第一条 HumanMessage（`initial_crash_data`）——这就是 LLM 拿到的"现象"全集；
- 初始化失败 → 置 `error` → `should_continue` 直接路由 `__end__`。

### 阶段 1：签名分类（Stage 0-1，step 1-2）

signature_class 决定后续所有分支（playbook、SOP、门控集合），因此被拆成两步并有执行器纠偏：

| 时点 | 约束 | 机制 |
|---|---|---|
| step 1 | `signature_class` 必须为 null，只许基于 panic 串/bt/dmesg 分类 | layer0 2.1，schema 校验拒绝 |
| step 2 | 必须给出具体 signature_class | layer0 2.1 |
| 落定轮 | CR2 实际访问类型与签名类不符 → 执行器直接改写 | `output_parser._normalize_signature_class_from_fault_context`；`_detect_page_fault_access_mismatch` 注入矛盾说明 |

签名类落定的同一轮，`state_manager` 完成三件事，等于给后续循环"铺轨"：

- `_build_managed_gates`：按 `schema._REQUIRED_GATES[signature_class]` 实例化强制门控（如
  pointer_corruption → register_provenance + object_lifetime + local_corruption_exclusion；
  external_corruption_gate 初始 blocked，前置为 local_corruption_exclusion）；
- `_build_evidence_goal`：把第一个 open/blocked 门控映射成"当前证据目标"（需要哪些 evidence
  type；goal_version 递增用于解锁去重缓存）；
- `prompt_builder._select_playbook`：挂载该签名类的取证剧本。

### 阶段 2：取证循环（Stage 2-5）——每轮 6 个环节

```mermaid
sequenceDiagram
  participant PB as prompt_builder
  participant LLM as llm_analysis_node
  participant CT as call_crash_tool
  participant EV as evidence/state_manager
  PB->>LLM: L0 模板 + 状态回灌 + playbook/SOP + 输出契约
  LLM->>CT: 三步推理 + 一个动作(current_action_intent)
  CT->>EV: guard→去重→执行→结构化事实→取值矛盾
  EV->>PB: 门控评估 + 停滞计数 → 下一轮状态回灌
```

1. **Prompt 装配**（`build_analysis_system_prompt`，逐层见"① Prompt 组装"）。关键是执行器状态
   回灌 `build_executor_state_section`：步数/阶段名、签名类与根因类、活跃假设、门控状态、当前
   门控目标、证据目标+版本、取值矛盾、上次动作状态（executed/duplicate/rejected/no_progress +
   streak）、replan 菜单、已执行命令清单。LLM 的"工作记忆"是这一段，而不是完整消息历史
   （历史会被 `compress_messages_for_llm` 压缩）。
2. **LLM 推理契约**：reasoning 必须三段（读最新 ToolMessage → 更新假设 → 为什么这个动作能推进
   当前门控）；action 必须携带 `current_action_intent`（intended_evidence_type / target_field /
   expected_disambiguation），否则被 executor-guard 拒绝——拒绝不是失败，而是以 ToolMessage
   形式反馈给 LLM 驱动 replan。
3. **审计与投影**（`llm_node._audit_and_project`）：consistency audit → value conflict audit →
   `project_managed_analysis_step`。执行器在此改写 LLM 输出：有未决门控却声明
   `is_conclusive=true` → 强制降级并清空 final_diagnosis；假设与门控是受管字段，LLM 的声明只是
   输入。
4. **工具执行**（`call_crash_tool`，逐环节见"③ 工具执行侧"）：guard → 指纹去重 → 执行 → 每份
   输出抽取结构化事实（`evidence_facts` / `struct_layout_cache` / 内存读数 /
   `crash_path_struct_offsets`）→ 取值级矛盾检测（`value_conflicts`，独立于证据事实）。
5. **门控评估**（`evidence.evaluate_gate_closures`）：只有满足 `_GATE_COMPLETION_CRITERIA` 的阳性
   证据组合才关闭门控（如 register_provenance 需要 rd + dis/sym 且地址关联）；LLM 申请关闭但
   证据不足 → 回退并记录 `llm_close_rejected`；全部变迁写入 `gate_transition_history` 供审计。
6. **停滞计数与路由**：`duplicate_streak` / `no_progress_streak` / `replan_required` 更新；结论已
   成立却还在只读探测 → `_convergence_guard_error` 拒绝空转；`edges.py` 决定回 llm 节点还是走向
   收口。DeepSeek-Reasoner 只输出 reasoning 无 content 时，路由到 `structure_reasoning_node` 用
   chat 模型补结构化，再回到主循环。

### 阶段 3：分支覆盖是如何实现的

"覆盖所有分析路径"不是并行探索，而是四层条件挂载 + 一份负面清单：

| 层 | 选择机制 | 触发条件 |
|---|---|---|
| Playbook | `_select_playbook(signature_class)` | 每个签名类一个剧本；stack_protector 命中 panic 串时特判 |
| SOP 片段 | `_select_sop_fragments` | DMA（step≥10 且门控/关键词命中）、per_cpu、address_search、driver_source_correlation（step≥6）、stack_overflow、stack_protector_fast_path、stack_frame_forensics、kasan_ubsan、advanced_techniques（step≥18） |
| Context overlays | `_select_context_overlays` | 栈破坏 / 驱动对象关键词命中时叠加 |
| mpykdump 扩展工具 | layer0 PART 3 | 场景触发（hung_task→hanginfo、块层挂死→rqlist、SCSI→scsishow 等），并标注"优先于手工等价命令" |

- **卡住时的转向菜单**：`_build_replan_probe_menu` 用确定性状态列出未探索的证据维度
  （rd/struct/dis/sym）与未读过的目标对象，要求换假设或换目标，而不是重复"曾经成功"的命令；当
  根因类已定且门控全关时，菜单整体替换为 `TERMINATE ON THIS TURN`（防止收尾轮继续探测）。
- **负面分支覆盖**：layer0 PART 0 的禁止命令/禁止推理模式清单，显式封死错误路径（对象验证前命名
  驱动、无阳性证据跳 DMA/硬件、用 `kmem -S [ALLOCATED]` 排除 UAF 等）。
- **机制区分要求**：Stage 5 / S4 规定 UAF、栈溢出、本地覆盖**各自需要阳性证据**才能被区分或确认
  ——`[ALLOCATED]` 只是快照状态，"没找到证据"不等于"排除"。

### 阶段 4：收敛与根因输出（Stage 6）

收敛准则（layer0 2.4）：`is_conclusive=true` 需要 ≥2 个独立证据源 + 完整因果链 + 显式写出最强
替代假设 + 无强制验证缺口。判定经历三重把关：

1. LLM 自评（prompt 中的准则文本）；
2. 执行器降级（`project_managed_analysis_step`：有未决门控即强制 `is_conclusive=false`）；
3. 一致性审计（可改写 root_cause_class、压制收敛，直到取值矛盾被 LLM 显式核对剔除）。

终止路径（全部通向 `__end__`）：

| 路径 | 触发 | 行为 |
|---|---|---|
| 正常结论 | is_conclusive + final_diagnosis 且门控全关 | `should_continue` 路由 end |
| 步数耗尽 | LangGraph 运行时在接近 `recursion_limit`（`AGENT_RECURSION_LIMIT=121`）时把内置 `is_last_step` 置 True | prompt 注入 CRITICAL WARNING，`build_tool_calls` 剥掉 tool_calls |
| 空转收口 | `no_progress_streak≥3` | `after_crash_tool` 触发一次强制收口（`force_terminal_wrapup` 保证只发生一次） |
| 空转强制二选一 | `no_progress_streak≥CONVERGENCE_GUARD_STREAK_THRESHOLD` 且重复命令均为只读取值探测 | dedup 硬拒与 replan 菜单追加 `FORCED_CHOICE_CONVERGENCE_RULE`（提交结论 / 声明新证据目标），在触顶收口前把模型推向可执行出口 |
| 收口轮违规 | 收口轮仍请求工具 | 追加 terminal-only 硬性指令，重试且仅重试一次 |
| 兜底合成 | 收口轮无结论，但根因类已定 + 强制门控全关 | `apply_fallback_conclusion_synthesis` 把已闭合证据确定性地渲染成 confidence=low 的有界结论 |

输出：`final_diagnosis` → `generate_markdown_report`（逐步过程回放、验证摘要，其中包含
"ALLOCATED 只是快照状态"的解读提醒）+ `generate_gate_audit_report`（门控变迁独立审计）。

### 步数轴速查

`step_count` 是节点级计数器；`_infer_stage_name` 据此（叠加首个未决门控）给出当前阶段名，
layer0 2.4a 则给出各里程碑必须达成的目标：

| step_count | 阶段（`_infer_stage_name`） | 系统侧关键行为 / 里程碑 |
|---|---|---|
| 0 | — | 初始化采集（sys/sys -t/bt + dmesg 窗口） |
| 1 | Stage 0-1 | signature_class 强制 null |
| 2-3 | Stage 0-1 | 签名落定、门控实例化、playbook 挂载、证据目标建立 |
| 4-9 | Stage 2-5 | step≥5：RIP 指令、CR2 分类、坏操作数来源必须已识别；step≥6 起驱动源码关联 SOP |
| 10-17 | Stage 4-5 | step≥10：至少一个具体对象/page/来源已在检视；DMA SOP 按条件注入 |
| ≥18 | Stage 6 | step≥20：至少一类阳性证据（生命周期/page 归属/设备侧）；step≥24 仍无设备侧证据则禁止点名设备/驱动；advanced SOP，prompt 要求每轮只发一条决定性命令 |
| 接近 121 | — | LangGraph 置 `is_last_step`，进入强制收口；到 121 硬停 |

## 门控（gates）—— 收敛的硬门槛

定义：`schema.GateEntry`（status: `open|closed|blocked|n/a`，`required_for` 按 `signature_class` 决定适用门控；定论要求所有适用门控有 executor-owned `closure_basis`。LLM 不能自行设置 `n/a` 或将门控标记为已验证）。

执行器管理的门控评估与完成条件（`evidence._gate_criteria_satisfied`、`gate_completion_criteria`）：

| gate | 关闭准则（executor-owned，LLM 不能口头关闭） |
|---|---|
| `register_provenance` | 当前执行器校验要求内存事实及 dis/sym 事实类别同时出现；地址/来源关系仍需分析和验证 |
| `object_lifetime` | 当前支持同地址 `kmem -S` 状态与内存读取事实；未绑定目标地址的 KASAN 信号仅作 telemetry。`page_not_present` 的地址关联映射拆除/生命周期事实抽取与闭合规则尚未实现，因此该签名下此门控保持未决 |
| `local_corruption_exclusion` | 当前执行器校验要求 dis 与内存事实类别同时出现 |
| `field_type_classification` | 当前执行器校验要求 struct 与 sym 事实类别同时出现 |
| `external_corruption_gate` | 要求前置门控 executor-verified，且有 `external_source:` 执行器事实；该事实抽取尚未接入，因此不会被通用 rd/struct/dis/sym 事实关闭 |

只有 `_REQUIRED_GATES` 中列出的必需门控阻止定论；额外出现的可选门控只作展示/审计，不影响收敛。没有专属执行器闭合规则的必需门控只记录 `weak_gate_closure` telemetry，保持未决；提示词会说明不要仅为关闭这类门控而重复探测，相关分析仍为非定论，直到补上事实抽取和门控规则。未知或未登记门控策略的签名（当前包括 `unknown` 与 `stack_corruption`）也不能定论。`n/a` 目前没有执行器判定规则，因此 LLM 的请求会被拒绝并写入审计记录。

证据事实前缀（`evidence.extract_evidence_facts`）：`rd_word:`、`struct_`、`dis_`、`sym:`、`vtop_`、`kmem_`、`kmem_slab_state:0x<addr>=allocated|free`、`kmem_vmap_range:`、`lifetime_signal:kasan_use_after_free_unbound`（telemetry，不构成生命周期证明）。

## 工具层（`src/mcp_tools/`）

- `registry.py`：按目录名约定发现 provider（`crash`、`kernel_source`、`lock_hang`、`source_patch`、`stack_canary`），统一注入 `vmcore_path`/`vmlinux_path`
- `crash/`：crash 命令执行（server/client/executor），并导出 `run_crash_command` / `run_crash_script` 供其他 provider 复用；`stack_canary/`、`source_patch/`、`kernel_source/` 为专题工具

### `crash/` —— 常驻 PTY 会话池与跨进程共享守护服务

`crash/` 既对外暴露 51 个注册子命令 + `run_script` / `inspect_slab_object` / `compare_memory_blocks`，也是 `stack_canary/`、`lock_hang/`、`scsishow.py` 共享的底层执行入口。为了消除大型 `vmcore` 每步冷启动与多 MCP 进程重复加载的内存开销，执行层采用**透明三模式路由**，保持 `run_crash_command` / `run_crash_script` 签名 100% 不变：

```
executor.py      统一入口；按 CRASH_EXECUTION_MODE 延迟路由至 daemon / pool / oneshot
session_pool.py  PersistentCrashSession（PTY + 哨兵帧 + mod -s 缓存 + 3s SIGINT 自愈）
                 + CrashSessionPool（Condition 细粒度锁 + 严格全局 LRU + ReaperThread）
daemon.py        零外部依赖多线程守护服务（unix:// 0600 或 http://）+ CrashDaemonClient
server.py        FastMCP 外壳；asyncio.to_thread + WeakKeyDictionary 按 loop 隔离 Semaphore；
                 CRASH_MCP_TRANSPORT 透传给 fastmcp.run()，前者为 stdio 时走 stdio 分支，
                 其余值（streamable-http / http / sse）走 HTTP 分支并读取 CRASH_MCP_HOST/PORT
                 （取值合法性由 fastmcp 2.x 的 run_async 校验，未知值抛 ValueError）
client.py        未配置 CRASH_MCP_URL 保持 stdio；配置后切换 streamable_http 连接常驻服务
```

#### 关键工程不变量

| 机制 | 实现细节 | 解决的问题 |
|---|---|---|
| **跨平台延迟导入** | `session_pool.py` 条件导入 `pty`/`termios`（`_PTY_AVAILABLE`）；`daemon.py` 探测 `_UNIX_SOCKET_AVAILABLE`；`executor.py` 在函数内延迟导入两者 | 保证 Windows 开发/CI 机可正常导入全链路并运行 `oneshot` 兜底与跨平台单测 |
| **哨兵帧与 Banner 消费** | 启动关闭 slave `ECHO`、握手一次性消费 Banner 并执行 `set scroll off`；每条命令追加 `!echo __CRASH_DONE_<uuid>__` 并等待哨兵 + 紧随的 `crash> ` | 去除旧版 `extra_ignore_markers` 误删真实 `bt`/`ps` 行的风险，杜绝日志内伪 `crash> ` 导致输出错位 |
| **`mod -s` 幂等与归属校验** | `_normalize_mod_path` 将 `""`/`auto` 归一为 `""`；已加载具体路径时后续裸/`auto` 请求直接跳过；`_mod_load_failed` 按行归属模块名与路径（识别 `cannot find`/`cannot open`/`no such file` 等） | 防止路径级加载失败写脏缓存，也防止多模块脚本中某一模块失败污染另一模块 |
| **3s 统一恢复预算与诊断** | `_try_interrupt_recover(budget_sec=3.0)` 向进程组发 `SIGINT`、读回 `crash> ` 并短暂排空残余；全模块零 `assert`；超时/启动失败异常均携带 `exit_code` | 超时不断链保留已加载符号；120s 启动超时可区分“仍在加载大符号”与“crash 已崩溃退出” |
| **并发、严格 LRU 与无锁快照** | 池锁仅保护槽位表（不锁命令执行），不同 `vmcore` 真并行；`_evict_lru_idle_locked` 在全部空闲槽中取 `min(last_used_at)`；`loaded_modules_snapshot()` 读取原子替换的 `tuple` 快照 | 支持多槽位严格 LRU，消除 `stats()` 与 `_io_lock` 的跨锁读撕裂 |
| **Loop 隔离信号量与 UDS 加固** | `server.py` 用 `WeakKeyDictionary[AbstractEventLoop, asyncio.Semaphore]`；`daemon.py` 绑定 `unix://` 时 `umask(0o077)` + `chmod 0o600`；`request_stop()` / `shutdown()` 幂等退出 | 彻底消除跨 event loop 信号量死锁与同机其他用户借 `!` 逃逸命令越权执行的风险 |

#### 跨进程测试

`tests/test_crash_session_pool.py` 分为两组：`CrashSessionCrossPlatformUnitTests`（Windows 与 Linux CI 必跑，覆盖 `_clean_output`、`_mod_load_failed`、`_prepare_lines`、多槽位严格 LRU、TCP Daemon 及跨 loop 信号量）和 `CrashPersistentPtyIntegrationTests`（仅 POSIX 运行，使用真实 `pty.openpty()` 驱动 mock `crash` REPL，覆盖常驻复用、伪提示符、`SIGINT` 3s 恢复、`SIGKILL` 重建、多 `vmcore` 真并行与 UDS `0600` 权限校验）。

### `lock_hang/` —— 锁 / 挂死确定性分析

`lock_hang` 与其余 provider 一样遵守 registry 契约（`MCP_CLIENT` / `MCP_SERVER_NAME` / `initialize_tools` / `build_tool_payload`），但它的价值全在 `analyzer.py` 这颗**纯函数式内核**上：除 `run_crash_command` / `run_crash_script` 外不依赖任何框架 API，且这两个 runner 都以关键字参数注入，因此单元测试可以用假 runner 驱动完整分析流程而不需要真实 vmcore。

```
server.py   FastMCP 外壳：两个 @tool 只做参数校验 + 异常转字符串
client.py   暴露 registry 契约；build_tool_payload 从 state 补 vmcore/vmlinux
analyzer.py 全部确定性逻辑（解析 → 分类 → 图构建 → 摘要）
```

两个工具的职责边界：

| 工具 | 输入维度 | 核心产物 |
|---|---|---|
| `analyze_lock_wait_graph` | 任务维度（`ps -m` / `--pids`） | Wait-For Graph、死锁环、根阻塞任务 |
| `analyze_cpu_lockup_rcu` | CPU 维度（`bt -a` / `bt -c`） | 每 CPU 的等待类别、自旋锁争抢、软中断/停顿、RCU 状态 |

#### 等待原语分类（`_CLASSIFY_PRIORITY`）

`_classify_backtrace` 不是"取第一个命中的帧"，而是**类别外层、帧内层**地按 `_CLASSIFY_PRIORITY` 顺序扫描：

```
mutex → rwsem → spinlock → io_wait → irq_softirq
```

顺序本身就是正确性的一部分：真实栈里 `asm_common_interrupt` / `common_interrupt` 这类硬件中断入口帧常常出现在自旋锁帧**之上**，若单纯按帧序取首个命中，中断入口会先被匹配成 `irq_softirq`，把真正的 spinlock 等待吞掉。所有函数名集合（`_MUTEX_FUNCS` … `_SOFTIRQ_OR_STALL_FUNCS`）都定义在 `_CLASSIFY_PRIORITY` 之前，`_LOCK_FUNC_PREFIXES` 也从这些集合派生——新增原语只需改集合本身。

必须区分两组容易混淆的常量：

| 常量 | 内容 | 参与 `wait_category` |
|---|---|:---:|
| `_SOFTIRQ_OR_STALL_FUNCS` | `__do_softirq`、`do_softirq`、`watchdog_timer_fn`、`watchdog_overflow_callback`、`rcu_dump_cpu_stacks` | 是（归为 `irq_softirq`） |
| `_HARDIRQ_ENTRY_FUNCS` | `asm_common_interrupt`、`common_interrupt`、`irq_exit`、`nmi_handle` | 否（仅用于兜底建议） |

两组不相交。硬件中断入口不参与分类是刻意的：一个停在 `asm_common_interrupt` 的 idle CPU 只是在等中断，不代表挂死；把它们算进 `irq_softirq` 会让 `idle_cpu_count` 归零并污染 `recommended_next_commands`。

#### idle 判定

```python
is_idle = (
    any(fn in _IDLE_FUNCS for fn in frame_funcs[:6])
    and not any(fn in _SPINLOCK_FUNCS or fn in _SOFTIRQ_OR_STALL_FUNCS for fn in frame_funcs[:8])
)
```

否定条件是核心：栈顶出现 `do_idle` / `cpu_idle` **不足以**判 idle。空闲 CPU 如果正在跑 watchdog timer softirq（`do_idle → irq_exit → __do_softirq → watchdog_timer_fn`），说明 softirq 卡在 idle 任务上下文里，这恰恰是最该被怀疑的现场之一，因此仍要计入 `active_or_suspected_cpus`。

`suspected` 的置位条件是"至少一条实质异常指标"：自旋锁等待、watchdog/RCU-stall dump、`runq` 就绪队列积压 ≥ 4、或非 idle 且处于自旋锁/软中断上下文。纯硬件中断上下文不计入 suspected（硬中断本身不是"等待"），只在 `spinlock_contenders` 与 `suspected` 都为空时触发兜底建议 `bt -c <cpus>` + `dis -rl <top_frame>`。

#### 锁 owner 解码

`decode_lock_owner_word` / `parse_struct_lock_owner` 负责把 `owner` 字还原成 `task_struct` 地址：

- `LOCK_OWNER_FLAG_MASK = 0x7`，`LOCK_OWNER_TASK_MASK = ~0x7`；
- `mutex`：低 3 位为 `MUTEX_FLAG_WAITERS/HANDOFF/PICKUP`；
- `rwsem`：低 3 位为 `RWSEM_READER_OWNED / RD_NONSPINNABLE / WR_NONSPINNABLE`，置了 reader-owned 位时**没有单一 owner task**，只能输出 `reader_owned=True` 并给出 `resolution_note`；
- 0、负数、以及落在内核正文段的地址都被判为"无有效 owner"（`None`）。

`WaitEdge.reader_owned` 与 `WaitEdge.resolution_note` 就是为这类"解析成功但语义受限"的边准备的，`resolution_note` 只放枚举式说明串，不放临时调试数据。

#### 输入 / 输出契约

| 侧 | 位置 | 说明 |
|---|---|---|
| 参数解析 | `parse_lock_wait_graph_command` / `parse_cpu_lockup_command` | 用 `shlex.split`，因此参数可带引号；`--top` 夹到 1..64，`--max-depth` 夹到 1..16 |
| 结果结构 | `WaitEdge`、`RunqCpuInfo(TypedDict)` | `RunqCpuInfo.queued_tasks` 是 `int`，调用方直接下标访问，无需 `isinstance` 兜底 |
| 建议命令 | `recommended_next_commands` | 只给下一轮的**定向**命令，不给全量 `bt -a` |

`build_tool_payload` 是 LLM 参数与工具入参之间的适配层：把 dict / list / `None` / 标量四种形态统一压平成 `command` 字符串，并强制从 state 注入 `vmcore_path` / `vmlinux_path`；缺任一路径直接 `ValueError`，由 `src/react/nodes.py` 的 `call_crash_tool` 捕获成任务结果。

#### 提示词侧状态

截至当前版本，本仓库**未**在 `src/react/sop_fragments.py` 或 `prompt_builder._select_sop_fragments` 中挂载 `lock_hang_fast_path`：分析器只作为工具暴露，模型是否调用由通用工具描述决定。若要启用强制优先调用，按 `INTEGRATION.md` 追加 SOP 片段与签名/关键词触发条件即可，无需改 `registry.py`。

#### 测试

`tests/test_lock_hang_analyzer.py` 通过注入假 runner 覆盖端到端流程（AB-BA 环、CPU 聚合、idle+硬件中断、硬中断兜底建议等），不依赖真实 vmcore；`tests/test_lock_hang_client.py` 覆盖 `build_tool_payload` 与 **FastMCP server 的工具注册**，前者使 analyzer 测试不必导入 `langchain_mcp_adapters`，后者守住"参数先后顺序导致 server 一个工具都注册不上"这类只在建 pydantic 模型时暴露的问题。

## 报告（`report_generator.py`）

- `generate_markdown_report`：面向读者的最终报告（含验证状态摘要、`ALLOCATED` 语义说明）
- `generate_gate_audit_report`：门控关闭/拒绝审计
- gate 中英标签映射在文件头部字典

## "想改 X 动哪里" 速查

| 目标 | 位置 |
|---|---|
| 改分析方法论/措辞（如 UAF 判定口径） | `layer0_system.py`（总纲）、`playbooks.py`（剧本）、`sop_fragments.py`（专题）、`prompt_phrases.py`（共享短语） |
| 改门控关闭条件 | `evidence.py`（`_GATE_COMPLETION_CRITERIA` + `_gate_criteria_satisfied`） |
| 改"LLM 结论如何被强制改写" | `output_parser.py` 对应 `_audit_*` |
| 改命令合法性/去重 | `action_guard.py` |
| 改收敛/路由（何时结束、何时重试） | `edges.py`、`llm_node.py`（收口逻辑）、`nodes._convergence_guard_error` |
| 改报告呈现 | `report_generator.py` |
| 加新崩溃类型剧本 | `playbooks.py` 加条目 + `prompt_builder._select_playbook` 选择信号 |
| 改等待原语分类（增删 mutex/rwsem/spinlock/io_wait/软中断函数） | `lock_hang/analyzer.py` 对应的 `_*_FUNCS` 集合；优先级在 `_CLASSIFY_PRIORITY` |
| 改 idle 判定阈值（栈顶帧数、是否需要无锁/无软中断） | `lock_hang/analyzer.py` 的 `analyze_cpu_lockup_rcu` 内 `is_idle` 表达式 |
| 改锁 owner 位掩码/reader-owned 语义 | `lock_hang/analyzer.py` 的 `LOCK_OWNER_FLAG_MASK` + `decode_lock_owner_word` |
| 改常驻 `crash` PTY 通信、哨兵帧、`mod -s` 缓存或 LRU/TTL | `crash/session_pool.py`（`PersistentCrashSession` / `CrashSessionPool`） |
| 改跨进程 Crash Daemon 端点或 UDS 权限 | `crash/daemon.py`（`CrashDaemonServer` / `CrashDaemonClient`） |
| 改 `crash` 执行模式路由（`pool`/`daemon`/`oneshot`） | `crash/executor.py`（`get_crash_execution_mode` / `_execute_via_pool_or_daemon`） |
| 改 `crash` MCP 并发上限或 HTTP 传输模式 | `crash/server.py`（`_get_concurrency_semaphore`）与 `crash/client.py`（`_build_mcp_server_config`） |
| 改 `lock_hang` 工具参数或描述 | `lock_hang/server.py` 的 `@tool` 签名与 `Annotated[..., Field(description=...)]` |
| 让模型优先调用锁/挂死分析器 | `react/sop_fragments.py` 加 `lock_hang_fast_path` + `prompt_builder._select_sop_fragments` 触发条件（见 `INTEGRATION.md`） |

注意：prompt 文本改动要检查 `tests/test_prompt_builder.py`、`test_convergence.py` 是否断言了相关字符串；门控改动跑 `tests/test_evidence.py`；`lock_hang` 改动跑 `tests/test_lock_hang_analyzer.py` 与 `tests/test_lock_hang_client.py`。

## 验证

```powershell
# 必须用项目 venv（系统 Python 缺依赖）
.\.venv\Scripts\python.exe -m pytest tests -q

# 若 venv 内没有 pytest，tests/ 又没有 __init__.py（discover 不可用），逐个模块枚举：
$mods = Get-ChildItem tests -Filter 'test_*.py' | ForEach-Object { 'tests.' + $_.BaseName }
.\.venv\Scripts\python.exe -m unittest @mods
```

`tests/test_crash_session_pool.py` 同样无外部框架依赖，在 Windows 上自动运行跨平台纯逻辑单测、在 Linux 上全量运行真实 PTY 集成测试：`python -m unittest tests.test_crash_session_pool`。

`tests/test_lock_hang_analyzer.py` 不依赖 `langchain_mcp_adapters`，可直接用系统 Python 运行：
`python -m unittest tests.test_lock_hang_analyzer`。

## 已知语义风险（备忘）

- KASAN 地址绑定尚未实现：KASAN UAF 输出目前只生成未绑定地址的 telemetry，不参与 `object_lifetime` 闭合；因此仅有 KASAN 证据的 UAF 分析可能保持非定论。
- 多个签名的必需门控尚无执行器闭合规则；这类门控会保持未决，相应分析无法由当前规则集得出定论，直到补齐事实抽取与规则。
- `n/a` 是预留状态，目前没有执行器适用性规则会产生该状态；LLM 请求会被拒绝。
- `local_corruption_exclusion` 是代码级门控名，措辞上仍是 exclusion；prompt 侧已统一为 discrimination 语义，重命名标识符需同步 `state_manager`/`schema`/`report_generator` 与测试。
- `lock_hang` 的 `irq_or_softirq_cpus` 只覆盖软中断与停顿检测原语，不含硬件中断（字段名沿用旧称以避免破坏消费方）；纯硬件中断上下文不计入 `active_or_suspected_cpus`，只在无其它线索时触发兜底建议。
- `soft_lockup` / `hard_lockup` / `rcu_stall` / `hung_task` 的签名门控（`lock_holder`、`wait_chain` 等）在 `evidence._GATE_COMPLETION_CRITERIA` 里**没有**对应条款，因此这些签名当前无法由执行器判定定论；`lock_hang` 提供的是取证加速，不是门控闭合规则的替代。
- `crash/daemon.py` 的 `http://` 端点无内置鉴权，仅限可信单租户主机；多用户主机必须使用 `unix://`（已自动收紧为 `0600` 权限），避免本地其他用户借 `crash` 的 `!` shell 逃逸执行任意命令。
- `daemon` 模式下，所有 MCP Server 共享守护进程侧的 `CRASH_POOL_MAX_SESSIONS × CRASH_POOL_SLOTS_PER_VMCORE` 槽位；若各 MCP Server 的 `CRASH_MCP_MAX_CONCURRENCY` 之和远大于池容量，超出请求会在 `CRASH_POOL_ACQUIRE_TIMEOUT_SEC` 处排队超时，生产部署应按池容量同步调优。
