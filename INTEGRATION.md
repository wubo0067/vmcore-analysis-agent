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

```bash
python3 -m unittest tests/test_lock_hang_analyzer.py
```
