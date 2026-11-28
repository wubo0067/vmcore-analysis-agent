# VMCore 分析 Agent 案例记忆与离线进化系统详细设计（V4）

**基线代码**：`src_latest5`（`vmcore-analysis-agent`）  
**文档版本**：V4（定稿）  
**更新日期**：2026-11-28

## 1. 设计目标与工程边界

随着真实生产环境 vmcore（覆盖 XFS、NVMe、网络栈、第三方 OOT 驱动等）不断积累，单纯依赖手工扩张 `layer0_system.py`、`playbooks.py`、`gates` 与 `evidence` 规则会导致提示词膨胀、规则冲突与维护成本线性上升。本设计引入**案例记忆（Case Memory）与离线进化闭环**，使 Agent 在不破坏现有确定性门控架构的前提下，随历史结案积累持续复用有效排查路径与避坑经验。

### 四条不可突破的工程红线

1. **禁止在线自动写入记忆**：在线运行态对案例库严格只读；新案例只能经离线蒸馏（`distiller`）生成 `draft`，经人工审核置为 `approved` 后才参与在线检索。
2. **零门控与零证据污染**：历史案例标识仅记入独立审计字段 `consulted_case_refs`，绝不写入 `evidence_facts`，绝不参与 `_GATE_COMPLETION_CRITERIA`、`evidence_delta` 或 `replan_required` 判定。
3. **Turn 1 零检索、零注入**：首轮 `current_signature_class` 为 `None` 时完全跳过检索与注入，维持 `layer0` 的运行时冷启动分类纪律，防止历史案例提前锚定。
4. **纯函数与既有测试零破坏**：保留 `src/react/playbooks.py` 现有静态剧本；`build_analysis_system_prompt` 维持纯函数（无 I/O），检索逻辑全部位于 `llm_node.py`，既有单元测试无需改动。

### V3 → V4 修订记录

- 修正 `call_crash_tool` 记录有效命令轨迹的变量引用：使用 `src/react/nodes.py` 实际存在的 `commands_to_run`（第 890 行初始化，第 1111–1113 行写入 `{"display": full_cmd, "tool_name": name, "args": args}`），取 `[str(c["display"]) for c in commands_to_run]`。
- 明确 `effective_step_trace` 与 `consulted_case_refs` 的覆盖合并语义：二者均不带 `Annotated[..., add]`，每次写回前必须先读取 `state` 中的旧列表浅拷贝再追加，防止 LangGraph 局部覆盖导致历史步骤丢失。
- 明确 `generate_gate_audit_report`（`src/react/report_generator.py:678`）的空返回守卫纳入 `consulted_case_refs` 与 `effective_step_trace`，避免早期收口时审计信息被静默丢弃。

## 2. 总体架构与目录布局

```text
src/
├── case_memory/                    # [Phase 1 新增] 案例记忆独立包（零反向依赖 react）
│   ├── __init__.py                 # 导出 CaseFingerprint, CaseRecord, CaseHint, CaseRetriever, NullCaseRetriever, SqliteCaseRetriever, extract_query_fingerprint
│   ├── schema.py                   # Pydantic 数据模型
│   ├── store.py                    # JSON 真相源读写 + SQLite 可重建索引（cases/index.db）
│   ├── retriever.py                # 确定性指纹提取、硬过滤与四维加权打分
│   └── distiller.py                # [Phase 2 新增] 基于 .audit.md 有效步骤轨迹蒸馏 draft 案例
├── react/                          # [Phase 1 轻量接入]
│   ├── graph_state.py              # 新增 kernel_major / case_hints / case_hint_signature / consulted_case_refs / effective_step_trace
│   ├── graph.py                    # create_agent_graph(..., case_retriever=None) 透传至 call_llm_analysis
│   ├── nodes.py                    # Step 0 解析 kernel_major；call_crash_tool 记 evidence_delta 日志并合并累积 effective_step_trace
│   ├── llm_node.py                 # 签名变化时执行单次检索，构造 effective_state，5 处 return 全量透传状态更新
│   ├── prompt_builder.py           # 纯函数 _should_inject_case_hints + _format_case_hints_section
│   └── report_generator.py         # .audit.md 追加"参考历史案例（非证据）"与"有效步骤轨迹"
cases/                              # [Phase 1 新增] Git 托管的案例真相源目录
├── patterns.yaml                   # 跨案例归并模式目录（<signature_class>.<subsystem_or_scope>.<mechanism>）
├── store/
│   └── case_20261127_rcu_stall_oot_reader.json   # 种子案例 #1（脱敏自 232606 黄金报告）
└── index.db                        # 运行时可重建 SQLite 索引（加入 .gitignore）
scripts/
└── distill_case.py                 # [Phase 2 新增] 离线蒸馏与审核辅助 CLI
tests/
└── test_case_memory.py             # [Phase 1 新增] 单元与集成回归测试（T1–T8）
```

## 3. 数据模型与存储设计（`src/case_memory/`）

### 3.1 `schema.py` 核心字段

| 模型 | 字段 | 类型 | 约束与用途 |
| :--- | :--- | :--- | :--- |
| `CaseFingerprint` | `signature_class` | `str` | 精确硬过滤键，对齐 `CrashSignatureClass` |
| `CaseFingerprint` | `kernel_major` | `Optional[str]` | 主次版本号，如 `"5.10"`、`"6.6"` |
| `CaseFingerprint` | `oot_modules` | `list[str]` | 第三方/业务模块名（小写去重） |
| `CaseFingerprint` | `top_bt_frames` | `list[str]` | 崩溃/阻塞栈顶关键符号（去除地址与偏移） |
| `CaseFingerprint` | `dmesg_signals` | `list[str]` | 归一化后的关键告警短语 |
| `CaseFingerprint` | `panic_keywords` | `list[str]` | `PANIC:` 行与 dmesg 关键词 |
| `CaseRecord` | `case_id` | `str` | 全局唯一 ID，格式 `case_YYYYMMDD_<slug>` |
| `CaseRecord` | `pattern_id` | `str` | 模式归并键：`<signature_class>.<subsystem_or_scope>.<mechanism>` |
| `CaseRecord` | `status` | `Literal["draft", "approved", "deprecated"]` | 仅 `approved` 参与在线检索 |
| `CaseRecord` | `fingerprint` | `CaseFingerprint` | 检索指纹 |
| `CaseRecord` | `candidate_checks` | `list[str]` | 过程导向的 3–5 条优先核查步骤/命令模板（脱敏具体地址与 PID） |
| `CaseRecord` | `pitfalls` | `list[str]` | 1–3 条已知坑位（参数格式、偏移陷阱、常见误判） |
| `CaseRecord` | `outcome_summary` | `str` | 仅离线复盘可见，在线转换 `CaseHint` 时强制剥离 |
| `CaseRecord` | `source_refs` | `list[str]` | 关联源码位置（`file:symbol`），非强约束 |
| `CaseRecord` | `reviewed_by` | `Optional[str]` | 审核人标识 |
| `CaseRecord` | `created_at` | `str` | ISO-8601 时间戳 |
| `CaseHint` | `case_id` | `str` | 注入 `AgentState.case_hints` 的在线视图（不含 `outcome_summary`） |
| `CaseHint` | `pattern_id` | `str` | 模式归并键 |
| `CaseHint` | `score` | `float` | 命中分值（保留 3 位小数） |
| `CaseHint` | `match_reasons` | `list[str]` | 命中维度摘要（仅用于日志与调试，不渲染进提示词） |
| `CaseHint` | `candidate_checks` | `list[str]` | 在线展示的候选核查方向 |
| `CaseHint` | `pitfalls` | `list[str]` | 在线展示的避坑提示 |

### 3.2 `store.py` 真相源与 SQLite 索引

- **真相源**：`cases/store/<case_id>.json`（UTF-8 JSON，纳入 Git 版本管理，通过 PR 审核控制质量）。
- **可重建索引**：`cases/index.db` 单表结构：
  ```sql
  CREATE TABLE IF NOT EXISTS cases (
      case_id TEXT PRIMARY KEY,
      signature_class TEXT NOT NULL,
      status TEXT NOT NULL,
      kernel_major TEXT,
      payload_json TEXT NOT NULL,
      mtime REAL NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_cases_sig_status
      ON cases(signature_class, status);
  ```
- **增量同步**：`CaseStore.sync_index()` 扫描 `cases/store/*.json`，对比文件清单与 `mtime` 做增量 upsert / 删除；删除 `index.db` 后下次启动可无损全量重建，零外部向量库与网络依赖。

## 4. 指纹提取与确定性检索算法（`src/case_memory/retriever.py`）

### 4.1 接口协议

```python
class CaseRetriever(Protocol):
    def retrieve(
        self,
        fingerprint: CaseFingerprint,
        *,
        top_k: int = 2,
    ) -> list[CaseHint]: ...


class NullCaseRetriever:
    def retrieve(
        self,
        fingerprint: CaseFingerprint,
        *,
        top_k: int = 2,
    ) -> list[CaseHint]:
        return []
```

`create_agent_graph` 默认 `case_retriever=None`（内部视同 `NullCaseRetriever`），未启用检索时零磁盘与 SQLite 开销。

### 4.2 查询指纹提取 `extract_query_fingerprint(state: Mapping[str, Any]) -> Optional[CaseFingerprint]`

| 字段 | 数据来源与回退规则 |
| :--- | :--- |
| `signature_class` | 读取 `state.get("current_signature_class")`；为空或属于 `{"unknown", "unclassified"}` 时直接返回 `None`（跳过检索） |
| `kernel_major` | 1. 优先读取 `state.get("kernel_major")`（Step 0 写入）；2. 回退正则扫描首条 `HumanMessage` 中的 `RELEASE:\s+(\d+\.\d+)`（兼容历史 checkpoint 与单测最小 state） |
| `oot_modules` | `debug_symbol_paths` 提取的模块名与 `loaded_modules` 中过滤常见上游基础模块白名单后的模块名求并集，全部转小写去重 |
| `top_bt_frames` | 扫描首条 `HumanMessage`（Step 0 `bt`）及近期 `ToolMessage` 中的栈帧行 `#\d+\s+\[[^\]]+\]\s+([A-Za-z_][A-Za-z0-9_.]*)`，过滤 `panic`/`crash_kexec`/`__schedule`/`ret_from_fork` 等通用噪声帧，保留前 12 个符号 |
| `dmesg_signals` / `panic_keywords` | 扫描首条 `HumanMessage` 中的 `PANIC:` 行与 dmesg 段落，提取归一化告警短语与关键词 |

### 4.3 硬过滤与四维加权打分

1. **硬过滤**：仅查询 `status = 'approved'` 且 `signature_class = query.signature_class`。
2. **四维加权分**（总分范围 `[0.0, 1.0]`）：
   - **`oot_modules`（权重 `0.35`）**：双方均有 OOT 模块时计算 Jaccard 系数 `|Q ∩ C| / |Q ∪ C|`；双方均无 OOT 模块（纯上游内核崩溃）时赋予中性基线分 `0.15`（避免纯上游案例因无第三方模块而达不到阈值）；仅一方有 OOT 模块时得 `0.0`。
   - **`top_bt_frames`（权重 `0.30`）**：计算 Jaccard 系数 `|Q_bt ∩ C_bt| / |Q_bt ∪ C_bt|`。
   - **`dmesg_signals` + `panic_keywords`（权重 `0.25`）**：合并去重后的 Dice 系数 `2 * |Q ∩ C| / (|Q| + |C|)`。
   - **`kernel_major`（权重 `0.10`）**：完全一致得 `1.0`，同主版本（如 `5.10` 与 `5.15`）得 `0.5`，否则 `0.0`。
3. **阈值与排序**：仅保留 `score >= 0.45` 的候选，按 `(score DESC, case_id ASC)` 排序并截断为 `Top 2`。

## 5. `src/react/` 精确接入规格（对齐 `src_latest5`）

### 5.1 `src/react/graph_state.py`（`AgentState`，行 38–157）

新增 5 个覆盖语义字段（不改动现有 5 个 `Annotated[..., add]` 字段，不碰 `evidence_facts` / `managed_gates`）：

```python
# Step 0 从 crash `sys` 的 RELEASE 行提取的主次版本号（如 "5.10"）。
kernel_major: Optional[str]
# 当前签名命中的历史案例在线提示（不含 outcome_summary）；0 命中时显式写回 []。
case_hints: list[dict[str, object]]
# 最近一次已执行案例检索的签名类别，用于同签名防抖。
case_hint_signature: Optional[str]
# 本次运行实际渲染进提示词的案例 ID（去重保序），仅用于 .audit.md 审计，绝不进入 evidence_facts。
consulted_case_refs: list[str]
# 有效步骤轨迹（覆盖语义，写回前必须先合并 state 旧值），仅记录 evidence_delta 非空的工具执行步。
effective_step_trace: list[dict[str, object]]
```

### 5.2 `src/react/graph.py`（`create_agent_graph`，行 38–91）

```python
def create_agent_graph(llm, tools_list: List, *, case_retriever=None):
    ...
    builder.add_node(
        llm_analysis_node,
        partial(call_llm_analysis, llm=llm, case_retriever=case_retriever),
    )
```

`structure_reasoning_node`（行 98–101）仅做推理文本结构化改写，不参与检索，保持原样。

### 5.3 `src/react/nodes.py`

1. **`collect_crash_init_data`（行 621–828）**：
   - 新增辅助函数 `_parse_kernel_major(sys_output: str) -> Optional[str]`，匹配 `RELEASE:\s+(\d+\.\d+)`。
   - 在遍历 `DEFAULT_CRASH_COMMANDS`（含 `sys`、`sys -t`、`bt`、`mod`，行 457–464）的循环内（行 665 附近，与 `mod` 解析并列）：
     ```python
     if cmd.strip() == "sys" and kernel_major is None:
         kernel_major = _parse_kernel_major(output)
     ```
   - 在行 822–828 的返回字典增加 `"kernel_major": kernel_major`。

2. **`call_crash_tool`（行 890、899、1111–1113、1295–1375）**：
   - `commands_to_run` 在第 890 行初始化，第 1111–1113 行写入 `{"display": full_cmd, "tool_name": name, "args": args}`；`step_index` 在第 899 行定义为 `int(state.get("step_count", 0))`。
   - 在计算完 `evidence_delta`（行 1307 之后）显式合并历史轨迹并按需追加：
     ```python
     effective_step_trace: list[dict[str, object]] = [
         dict(item) for item in (state.get("effective_step_trace") or [])
     ]
     if evidence_delta:
         logger.info(
             "Step %s evidence_delta (%d): %s",
             step_index,
             len(evidence_delta),
             evidence_delta[:8],
         )
         effective_step_trace.append(
             {
                 "step": step_index,
                 "commands": [str(c["display"]) for c in commands_to_run],
                 "evidence_delta": list(evidence_delta),
             }
         )
     ```
   - 在行 1340–1375 的返回字典中写回 `"effective_step_trace": effective_step_trace`。

### 5.4 `src/react/llm_node.py`（`call_llm_analysis`，行 200–650）

- 签名更新为：`async def call_llm_analysis(state: AgentState, llm, case_retriever=None) -> dict:`
- **单次检索与状态合并**（放在行 244 `build_analysis_system_prompt` 之前）：
  ```python
  case_memory_updates: dict[str, object] = {}
  effective_state = state
  sig = state.get("current_signature_class")
  sig_str = str(sig).strip() if sig else ""
  if (
      case_retriever is not None
      and sig_str
      and sig_str not in {"unknown", "unclassified"}
      and sig_str != state.get("case_hint_signature")
  ):
      fp = extract_query_fingerprint(state)
      hits = case_retriever.retrieve(fp, top_k=2) if fp is not None else []
      hints_payload = [h.model_dump() for h in hits]
      case_memory_updates = {
          "case_hints": hints_payload,        # 0 命中时显式写回 []，清除旧签名残留
          "case_hint_signature": sig_str,
      }
      effective_state = {**state, **case_memory_updates}

  if _should_inject_case_hints(effective_state, is_last_step=effective_last_step):
      existing_refs = list(state.get("consulted_case_refs") or [])
      new_refs = [
          str(item["case_id"])
          for item in (effective_state.get("case_hints") or [])
          if item.get("case_id")
      ]
      merged_refs = list(dict.fromkeys(existing_refs + new_refs))
      if merged_refs != existing_refs:
          case_memory_updates["consulted_case_refs"] = merged_refs
          effective_state = {**effective_state, "consulted_case_refs": merged_refs}
  ```
- 调用 `build_analysis_system_prompt(effective_state, is_last_step=effective_last_step)`，使本轮检索结果当轮生效。
- **全分支透传写回**：定义 `def _with_case_updates(payload: dict) -> dict: return {**case_memory_updates, **payload}` 包裹 `call_llm_analysis` 全部 5 处 `return`（行 295、490、510、625、636），确保即使进入 `reasoning_to_structure` 早退或预算异常路径，新的 `case_hints`（含 `[]`）、`case_hint_signature` 与 `consulted_case_refs` 都能可靠写回图状态。

### 5.5 `src/react/prompt_builder.py`（纯函数注入与收尾互斥）

1. **统一收尾互斥判定**（与 `build_executor_state_section` 行 490、`_build_replan_probe_menu` 行 341 共享同一结论就绪条件）：
   ```python
   def _should_inject_case_hints(state: AgentState, *, is_last_step: bool) -> bool:
       if is_last_step or state.get("force_terminal_wrapup"):
           return False
       if not state.get("case_hints"):
           return False
       if has_committed_root_cause(state) and _gates_exhausted(state):
           return False
       return True
   ```
   当 `has_committed_root_cause(state) and _gates_exhausted(state)` 为真时（包括 `_terminate_exemption` 豁免 A/B 的单次定点重试期），均抑制 Case Hint 注入，避免在收口阶段引入冲突指令。

2. **渲染位置与模板**（`build_analysis_system_prompt`，行 129–135）：
   在 `sop_fragments` 之后、`[STRUCTURED OUTPUT CONTRACT]` 之前追加 `_format_case_hints_section(state)`：
   ```text
   [HISTORICAL CASE REFERENCE — NON-EVIDENCE]
   Priority rule: Active Playbook, SOP fragments, and Executor Directives ALWAYS take precedence over historical cases.
   These entries are candidate investigation directions only — NEVER treat them as runtime evidence, NEVER cite them to close any gate, and NEVER assume the root cause matches.

   - Case `<case_id>` (pattern: `<pattern_id>`):
     Candidate checks:
       1. <candidate_checks[0]>
       ...
     Known pitfalls:
       - <pitfalls[0]>
       ...
   ```
   严禁输出 `outcome_summary`、`root_cause_class` 或 `score`。

### 5.6 `src/react/report_generator.py`（`generate_gate_audit_report`，行 663–752）

- 主分析报告（`.md`）保持不变。
- 空返回守卫（行 678）更新为：
  ```python
  consulted_case_refs = list(state.get("consulted_case_refs") or [])
  effective_step_trace = list(state.get("effective_step_trace") or [])
  if not gates and not history and not consulted_case_refs and not effective_step_trace:
      return ""
  ```
- 在 `.audit.md` 末尾按需追加两节：
  1. `## 参考历史案例（非证据）`：逐条列出 `consulted_case_refs` 中的 `case_id`，注明仅作候选方向参考、未参与门控闭合判定。
  2. `## 有效步骤轨迹`：按 `effective_step_trace` 逐条输出 `Step <step>`、执行命令列表与新增 `evidence_delta`。

## 6. 端到端状态流转表

| 阶段 | `current_signature_class` | `case_hint_signature` | 检索行为 | `case_hints` 写回 | Prompt 注入 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Step 0 (`collect_crash_init_data`) | `None` | `None` | 不触发；写入 `kernel_major` + `loaded_modules` | 未设置 | 无 |
| Turn 1 (`call_llm_analysis`) | `None` | `None` | 跳过（红线 3） | 不写 | 无 |
| Turn 2（分类为 `rcu_stall`） | `"rcu_stall"` | `None` → `"rcu_stall"` | 触发 1 次，命中 1–2 条 | 写 `[hint1, ...]` | 注入（非证据块） |
| Turn 3（仍为 `rcu_stall`） | `"rcu_stall"` | `"rcu_stall"` | 跳过（同签名防抖） | 保留旧值 | 保持注入 |
| Turn 4（转向 `deadlock`，0 命中） | `"deadlock"` | `"rcu_stall"` → `"deadlock"` | 触发 1 次，命中 0 条 | 显式写回 `[]` | 立即停止注入 |
| Turn K（`conclusion_ready` 或 `is_last_step`） | 任意 | 保持 | 跳过 | 保留 | 收尾互斥抑制 |

## 7. Phase 2 离线蒸馏与演进治理规格

### 7.1 确定性最小有效命令序列提取（`src/case_memory/distiller.py`）

1. **主路径（新版 `.audit.md` 含 `## 有效步骤轨迹`）**：
   - 解析 `## Gate 状态转换记录` 中从 `open/partial -> closed/verified` 的目标事实集合 `E_gate`。
   - 遍历 `## 有效步骤轨迹`，保留 `set(step.evidence_delta) & E_gate != empty` 的步骤（按 `step` 升序去重，最多取 5 步）。
   - 对命令模板执行正则脱敏：将具体内核地址（`0xffff[0-9a-f]{12}`）、PID、CPU 号替换为 `<task_addr>` / `<pid>` / `<cpu>`，产出 `status: "draft"` 的 JSON。
2. **兼容回退路径（旧版 `.audit.md` + `.md` 报告）**：
   - 若 `.audit.md` 不含 `## 有效步骤轨迹`，则按报告中的 `步骤 N` 分块反向匹配证据前缀，并标注 `distill_confidence: "heuristic"` 提醒人工复核。

### 7.2 Q0 晋升分流规则

人工审核 `draft` 时先过 Q0 判断：
- **通用内核/工具规则**（与具体子系统/驱动无关，如偏移进制、参数校验规则）→ 直接快车道合入 `layer0_system.py` / `playbooks.py` / 工具校验，不入案例库。
- **子系统/驱动特定排查路径**（如 XFS AGF/AGI 锁链、NVMe admin/io queue 超时、特定 OOT 驱动私有结构遍历）→ 合入 `cases/store/<case_id>.json` 并置为 `approved`；同一 `pattern_id` 累计达到 3 个及以上独立 `approved` 案例后，评估沉淀为通用 SOP 或确定性诊断工具。

## 8. Phase 1 验证与测试矩阵（`tests/test_case_memory.py`）

| 编号 | 测试场景 | 核心断言 |
| :--- | :--- | :--- |
| T1 | Schema 与 SQLite 索引同步 | 仅索引 `approved`；修改 JSON 后增量更新；删除 `index.db` 可无损重建 |
| T2 | 确定性打分与硬过滤 | 同签名 + OOT + 栈帧 `>= 0.45` 命中；纯上游无 OOT 案例正常命中；`draft`/`deprecated`/异签名过滤；Top 2 截断 |
| T3 | Turn 1 冷启动零检索 | `current_signature_class=None` 时检索计数 `0`，提示词不含 `HISTORICAL CASE REFERENCE` |
| T4 | Turn 2 命中 + 同签名防抖 | 首次分类检索 `1` 次并注入且记入 `consulted_case_refs`；同签名下一轮检索计数仍为 `1` |
| T5 | 签名转向后 0 命中显式清空 | `rcu_stall`（命中）切到 `deadlock`（0 命中）时，返回 dict 显式含 `"case_hints": []` 与 `"case_hint_signature": "deadlock"`，新提示词不含旧案例 |
| T6 | 收尾互斥与红线隔离 | `is_last_step`、`force_terminal_wrapup`、`conclusion_ready`（含豁免期）均抑制注入；`outcome_summary` 永不出现于提示词；`evidence_facts` 永不含 `case_id` |
| T7 | Step 0 `kernel_major`、多步 `effective_step_trace` 累积与 `.audit.md` 渲染 | `_parse_kernel_major` 正确解析 `RELEASE: 5.10.0-... -> "5.10"`；连续 3 步（非空 / 空 / 非空）后 `effective_step_trace` 保留第 1、3 步共 2 条记录且 `commands` 来自 `commands_to_run[i]["display"]`；`.audit.md` 正确渲染两处新增小节 |
| T8 | 既有测试零回归 | `case_retriever=None` 下 `prompt_builder` 等既有行为 100% 保持不变 |

## 9. 计划实施步骤

### Phase 1：在线只读 Case Memory 基础设施与审计留痕（分支：`feat/case-memory-phase1`）

1. **拉取特性分支并确认基线**：从主干切出 `feat/case-memory-phase1`，确认既有测试套件全绿。
2. **搭建 `src/case_memory/` 核心模块**：依次实现 `schema.py`、`store.py`、`retriever.py`、`__init__.py`，补齐 `.gitignore` 对 `cases/index.db` 的忽略规则。
3. **录入种子案例**：创建 `cases/patterns.yaml` 与 `cases/store/case_20261127_rcu_stall_oot_reader.json`（基于 232606 黄金报告脱敏生成，`status: "approved"`）。
4. **接入 `src/react/` 轻量钩子**：
   - `graph_state.py`：新增 5 个覆盖语义状态字段。
   - `graph.py`：`create_agent_graph` 增加 `case_retriever=None` 并透传至 `call_llm_analysis`。
   - `nodes.py`：Step 0 解析 `kernel_major`；`call_crash_tool` 记 `evidence_delta` 日志并合并累积 `effective_step_trace`。
   - `llm_node.py`：实现单次检索、0 命中显式清 `[]`、`consulted_case_refs` 去重合并及 5 处 `return` 全分支写回。
   - `prompt_builder.py`：新增纯函数 `_should_inject_case_hints` 与 `_format_case_hints_section`。
   - `report_generator.py`：更新空守卫并在 `.audit.md` 追加两处审计小节。
5. **编写并运行自动化测试**：落地 `tests/test_case_memory.py`（覆盖 T1–T8），运行全量单测与 `py_compile` 检查，确认零回归。
6. **真机 vmcore 联调验收**：开启 `SqliteCaseRetriever` 跑 1 次已知 `rcu_stall` vmcore 与 1 次无关签名 vmcore，核查 `.audit.md` 中的 `## 参考历史案例（非证据）` 与 `## 有效步骤轨迹`，确认主报告格式与门控逻辑零副作用后合入主干。

### Phase 2：离线蒸馏与人工审核闭环（分支：`feat/case-memory-phase2`）

1. **实现 `src/case_memory/distiller.py`**：支持读取 `.audit.md` 的 `## Gate 状态转换记录` 与 `## 有效步骤轨迹`，按 `E_gate` 交集提取最小有效命令序列并自动脱敏内核地址/PID/CPU；保留旧版报告的启发式回退路径。
2. **提供离线 CLI `scripts/distill_case.py`**：支持 `distill`（从一次运行产出 `draft` JSON）、`approve`（校验必填字段、写入 `reviewed_by` 并置 `approved`）与 `reindex`（重建 `cases/index.db`）。
3. **建立 Q0 评审清单**：在 PR 模板中加入 Q0 检查项，区分“通用规则直入代码”与“子系统案例入库”，并对真实 XFS / NVMe / OOT 案例跑通 3–5 次完整“分析 → 蒸馏 → 审核 → 复用”闭环。

### Phase 3：评测回归与模式沉淀（按需，累计 20–30+ `approved` 案例后启动）

1. **离线回放评测**：基于历史结案样本对比开启/关闭 Case Memory 的推理步数、Token 消耗与门控收敛率，校准四维检索权重与 `0.45` 阈值。
2. **高频模式晋升**：对同一 `pattern_id` 累计达到 3 个以上独立 `approved` 案例的子系统，将稳定排查路径沉淀为通用 SOP 片段或确定性诊断 MCP 工具。
3. **按需演进持久化检查点**：当跨会话中断恢复成为刚需时，将 `graph.py:79` 的 `InMemorySaver()` 升级为 SQLite/Postgres Checkpointer。
