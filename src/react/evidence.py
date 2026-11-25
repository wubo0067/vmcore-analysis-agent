"""Structured evidence extraction and set-difference helpers for crash output."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping

from .consistency import (
    parse_struct_layouts,
)

_HEX = r"(?:0x)?[0-9a-fA-F]+"
_RD_LINE_RE = re.compile(rf"^\s*(?P<address>{_HEX})\s*:\s*(?P<words>.*)$")
_DIS_LINE_RE = re.compile(
    rf"^\s*(?P<address>{_HEX})\s+<(?P<symbol>[^>]+)>:\s+(?P<instruction>\S+.*)$"
)
_SYM_LINE_RE = re.compile(
    rf"^\s*(?P<address>{_HEX})\s+(?P<kind>[A-Za-z?])\s+(?P<symbol>\S+)"
)
_VTOP_UNMAPPED_RE = re.compile(
    rf"^\s*(?P<address>{_HEX})\s+\(not mapped\)\s*$",
    re.IGNORECASE,
)
_VTOP_MAPPED_RE = re.compile(
    rf"^\s*(?P<virtual>{_HEX})\s+(?P<physical>{_HEX})\s*$",
    re.IGNORECASE,
)
_VTOP_PTE_RE = re.compile(
    rf"^\s*PTE:\s*(?:{_HEX}\s*=>\s*)?(?P<value>{_HEX})\s*$",
    re.IGNORECASE,
)
_KMEM_RANGE_RE = re.compile(
    rf"^\s*\S+\s+\S+\s+(?P<start>{_HEX})\s+-\s+(?P<end>{_HEX})\s+(?P<size>\d+)\s*$",
    re.IGNORECASE,
)
_KMEM_SLAB_SLOT_RE = re.compile(
    r"^\s*(?:\[\s*(?P<allocated>(?:0x)?[0-9a-fA-F]{8,16})\s*\]|"
    r"(?P<free>(?:0x)?[0-9a-fA-F]{8,16}))\s*$"
)
_KASAN_UAF_RE = re.compile(r"\bKASAN:\s*(?:slab-)?use-after-free\b", re.IGNORECASE)
# kernel_source 工具在输出里标注的源码锚点："SOURCE_REF: path/to/file.c:1203"。
# 该事实只用于审计"源码被真正读过"，不参与门控闭合（闭合仍要求运行时事实）。
_SOURCE_REF_RE = re.compile(r"SOURCE_REF:\s*(?P<file>[^\s:]+):(?P<line>\d+)")
# kernel_source 其余头部行：它们没有 SOURCE_REF，但同样证明"这一轮真的查了源码"，
# 必须计入 evidence_delta，否则合法的 source_status / 0 命中检索会被判成无进展。
_SOURCE_STATUS_RE = re.compile(r"SOURCE_STATUS\s+configured=(?P<configured>true|false)")
_SOURCE_GREP_RE = re.compile(
    r"SOURCE_GREP\s+pattern=(?P<pattern>.+?)\s+hits=(?P<hits>\d+)"
)
_SOURCE_WRITERS_RE = re.compile(
    r"SOURCE_WRITERS\s+field=(?P<field>\S+)\s+hits=(?P<hits>\d+)"
)
_SOURCE_GIT_RE = re.compile(
    r"SOURCE_GIT\s+file=(?P<file>\S+)\s+range=(?P<range>\S+)"
)

# 锁 / 挂死类（rcu_stall / hung_task / soft_lockup / hard_lockup）确定性运行时事实解析正则
_BT_TASK_HEADER_RE = re.compile(
    rf'^\s*PID:\s*(?P<pid>\d+)\s+TASK:\s*(?P<task>{_HEX})\s+CPU:\s*(?P<cpu>\d+)\s+COMMAND:\s*"(?P<comm>[^"]+)"',
    re.IGNORECASE,
)
_BT_FRAME_RE = re.compile(
    rf"^\s*#\d+\s+\[{_HEX}\]\s+(?P<symbol>[A-Za-z_][A-Za-z0-9_.]*)\s+at\s+{_HEX}"
)
_NMI_WATCHDOG_FRAME_TOKENS = (
    "nmi_handle",
    "exc_nmi",
    "asm_exc_nmi",
    "do_nmi",
    "watchdog_overflow_callback",
    "watchdog_timer_fn",
    "hardlockup_detector",
    "perf_event_overflow",
)
_STRUCT_PID_RE = re.compile(r"^\s*pid\s*=\s*(?P<pid>\d+)\s*,?\s*$")
_STRUCT_TASK_STATE_RE = re.compile(
    r"^\s*(?:__state|state)\s*=\s*(?P<val>\d+|0x[0-9a-fA-F]+)\s*,?\s*$"
)
_STRUCT_RCU_NESTING_RE = re.compile(
    r"^\s*rcu_read_lock_nesting\s*=\s*(?P<val>-?\d+)\s*,?\s*$"
)
_STRUCT_RCU_BLOCKED_NODE_RE = re.compile(
    rf"^\s*rcu_blocked_node\s*=\s*(?P<addr>{_HEX})\b"
)
_STRUCT_RCU_GP_TASKS_RE = re.compile(
    rf"^\s*gp_tasks\s*=\s*(?P<addr>{_HEX})\b"
)
_STRUCT_RCU_GP_SEQ_RE = re.compile(
    r"^\s*gp_seq\s*=\s*(?P<val>-?\d+|0x[0-9a-fA-F]+)\s*,?\s*$"
)
_STRUCT_RCU_QSMASK_RE = re.compile(
    r"^\s*qsmask\s*=\s*(?P<val>\d+|0x[0-9a-fA-F]+)\s*,?\s*$"
)
_STRUCT_BLKD_TASKS_NEXT_RE = re.compile(
    rf"blkd_tasks\s*=\s*\{{[^}}]*?next\s*=\s*(?P<addr>{_HEX})",
    re.DOTALL,
)
_STRUCT_LOCK_OWNER_RE = re.compile(
    rf"(?:^|\s)owner\s*=\s*(?:\{{\s*counter\s*=\s*(?P<counter>-?\d+|{_HEX})\s*\}}|(?P<ptr>{_HEX}))"
)
_PRINT_RCU_VAR_RE = re.compile(
    r"^\s*(?P<name>sysctl_panic_on_rcu_stall|rcu_cpu_stall_timeout)\s*=\s*\$\d+\s*=\s*(?P<val>-?\d+)\s*$"
)
_RCU_STATE_GP_SEQ_CMD_RE = re.compile(r"^p\s+rcu_state\.gp_seq\b", re.IGNORECASE)
_GDB_DOLLAR_INT_RE = re.compile(r"^\s*\$\d+\s*=\s*(?P<val>-?\d+)\s*$")
_RUNQ_CPU_HEADER_RE = re.compile(r"^\s*CPU\s+(?P<cpu>\d+)\s+RUNQUEUE:", re.IGNORECASE)
_RUNQ_CURRENT_PID_RE = re.compile(r"^\s*CURRENT:\s*PID:\s*(?P<pid>\d+)\b", re.IGNORECASE)
_PS_TASK_LINE_RE = re.compile(
    rf"^\s*(?:>\s*)?(?P<pid>\d+)\s+\d+\s+\d+\s+{_HEX}\s+(?P<state>UN|RU|IN|ZO|ST)\b"
)
_PS_M_TASK_LINE_RE = re.compile(
    rf"^\s*\[[^\]]+\]\s+\[(?P<state>UN|RU|IN|ZO|ST)\]\s+PID:\s+(?P<pid>\d+)\b"
)

_RCU_TRACE_STATE_PREFIXES = (
    "rcu_reader_nesting:",
    "rcu_blocked_node:",
    "rcu_node_gp_tasks:",
    "rcu_node_blkd_tasks:",
    "rcu_gp_seq:",
    "rcu_qsmask:",
    "rcu_stall_cpu_trace:",
)
_RCU_HOLDER_IDENTITY_PREFIXES = (
    "rcu_reader_nesting:",
    "rcu_blocked_node:",
    "rcu_node_gp_tasks:",
    "lock_holder_task:",
    "lock_owner_word:",
)
_SOFT_LOCKUP_HOLDER_PREFIXES = (
    "lock_holder_task:",
    "lock_owner_word:",
    "spinlock_contender:",
)
_SOFT_LOCKUP_NO_LOCK_PREFIXES = (
    "cpu_lockup_no_spinlock:",
    "cpu_lockup_irq_softirq:",
)
_HUNG_TASK_STATE_PREFIXES = (
    "task_state:",
    "ps_task_state:",
    "wait_graph_edge:",
    "wait_graph_blocker:",
    "wait_graph_cycle:",
    "wait_graph_unresolved:",
)
_WAIT_CHAIN_PREFIXES = (
    "wait_graph_edge:",
    "wait_graph_cycle:",
    "wait_graph_blocker:",
    "lock_holder_task:",
    "lock_owner_word:",
)
_CPU_PROGRESS_PREFIXES = (
    "cpu_lockup_cpu:",
    "cpu_lockup_irq_softirq:",
    "spinlock_contender:",
    "runq_cpu:",
)
_EXECUTION_CONTEXT_PREFIXES = (
    "bt_task:",
    "bt_frame:",
    "dis_instruction:",
    "dis_symbol:",
)


_GATE_COMPLETION_CRITERIA: dict[str, list[str]] = {
    "register_provenance": [
        "faulting register value is present",
        "source object or address evidence is present",
        "field/offset or symbol relation is independently observed",
    ],
    "object_lifetime": [
        "the same slot's current kmem -S state and base-address memory are observed, or "
        "direct temporal lifetime evidence is present",
        "an ALLOCATED snapshot is not treated as excluding use-after-free with reuse",
    ],
    "local_corruption_exclusion": [
        "a relevant disassembly observation is present",
        "a memory observation supports or excludes a local writer",
    ],
    "field_type_classification": [
        "struct field layout evidence is present",
        "a type or symbol observation corroborates the field classification",
    ],
    "rcu_stall_trace": [
        "RCU grace-period or stalled reader/CPU state is observed (rcu_node gp_tasks/blkd_tasks/gp_seq/qsmask, task_struct rcu_read_lock_nesting/rcu_blocked_node, or analyze_cpu_lockup_rcu)",
        "stalled task or CPU execution context is observed via backtrace or disassembly (bt / dis)",
    ],
    "lock_holder": [
        "the blocking RCU reader, lock owner, or lock-free CPU busy-loop state is observed (rcu_read_lock_nesting/rcu_blocked_node/gp_tasks, lock owner word, spinlock contender, lock_hang owner resolution, or lock-free softirq/CPU stall confirmation)",
        "holder or stalled CPU execution context is observed via backtrace or disassembly (bt / dis)",
    ],
    "blocked_task_context": [
        "blocked task execution context is observed via backtrace (bt_task and stack frames)",
        "blocked task state or wait-graph membership is observed (task_struct __state, ps UN state, or analyze_lock_wait_graph)",
    ],
    "wait_chain": [
        "lock/wait dependency chain or blocker identity is observed (analyze_lock_wait_graph edges/cycles/root_blockers or lock owner word)",
        "independent execution or structure evidence corroborates the chain (bt, struct, dis, or rd)",
    ],
    "stack_integrity": [
        "stalled CPU/task backtrace frames are observed (bt_task + bt_frame or analyze_cpu_lockup_rcu)",
        "disassembly or symbol resolution corroborates the execution site (dis / sym)",
    ],
    "nmi_watchdog_evidence": [
        "NMI or watchdog frame / hard-lockup stall context is observed (bt NMI/watchdog frame or analyze_cpu_lockup_rcu irq/softirq stall)",
        "stalled CPU task or disassembly context is observed (bt / dis)",
    ],
    "cpu_progress_state": [
        "CPU runqueue or lockup progress state is observed (runq, analyze_cpu_lockup_rcu active/suspected CPUs, or spinlock contenders)",
        "stalled CPU execution context is observed via backtrace or disassembly (bt / dis)",
    ],
}

MAX_GATE_EVIDENCE_FACTS_PER_CATEGORY = 8

_EVIDENCE_SUMMARY_LINE_RE = re.compile(
    r"^(?P<marker>\[(?:executor-evidence|evidence-delta)\] )"
    r"(?P<category>[a-z0-9_]+): \.\.\. \(\+(?P<count>\d+) more\)$"
)
_EVIDENCE_FACT_LINE_RE = re.compile(
    r"^(?P<marker>\[(?:executor-evidence|evidence-delta)\] )"
    r"(?P<fact>(?P<category>[a-z0-9_]+):.+)$"
)


_PINNED_ADDRESS_RE = re.compile(r"\b(?:0[xX])?[0-9a-fA-F]{8,16}\b")


def extract_pinned_addresses(state: Mapping[str, Any] | None) -> list[str]:
    """从 state 的 current_evidence_goal / current_action_intent 的 target_object 提取十六进制目标地址（支持带或不带 0x/0X 前缀，过滤 <8 位的短偏移并按出现顺序去重）。"""
    if not state:
        return []
    target_object_str = " ".join(
        str(val)
        for val in (
            (state.get("current_evidence_goal") or {}).get("target_object"),
            (state.get("current_action_intent") or {}).get("target_object"),
        )
        if val
    )
    seen: set[str] = set()
    result: list[str] = []
    for tok in _PINNED_ADDRESS_RE.findall(target_object_str):
        key = tok.lower()
        if key not in seen:
            seen.add(key)
            result.append(tok)
    return result


def _closure_pinned_addresses(
    gate_name: str,
    facts: Iterable[str],
) -> set[str]:
    """提取触发 object_lifetime 门控闭合的交集地址，以便在截断时作为 pinned 地址优先保留。"""
    if gate_name != "object_lifetime":
        return set()
    fact_list = list(facts)
    kmem_addrs = {
        fact.split(":", 1)[1].split("=", 1)[0]
        for fact in fact_list
        if fact.startswith("kmem_slab_state:") and "=" in fact
    }
    rd_addrs = {
        fact.split(":", 1)[1].split("=", 1)[0]
        for fact in fact_list
        if fact.startswith("rd_word:") and "=" in fact
    }
    return kmem_addrs & rd_addrs


def _display_order(facts: list[str], pinned: set[str]) -> list[str]:
    """将匹配当前证据目标地址（pinned）的事实排到桶尾，使截断时优先保留（按十六进制词边界精确匹配，兼容带/不带 0x）。"""
    if not pinned:
        return sorted(facts)
    hex_tokens = [
        addr[2:] if addr.lower().startswith("0x") else addr
        for addr in sorted(pinned)
        if addr
    ]
    if not hex_tokens:
        return sorted(facts)
    pinned_re = re.compile(
        rf"(?<![0-9a-f])(?:0x)?(?:{'|'.join(re.escape(tok) for tok in hex_tokens)})(?![0-9a-f])",
        re.IGNORECASE,
    )
    return sorted(
        facts,
        key=lambda f: (bool(pinned_re.search(f)), f),
    )


def _append_bounded_gate_evidence(
    existing_evidence: str | None,
    new_facts: Iterable[str],
    *,
    marker: str,
    max_per_category: int = MAX_GATE_EVIDENCE_FACTS_PER_CATEGORY,
    pinned: Iterable[str] = (),
) -> str:
    """仅在展示层对 gate.evidence 按事实类别截断，保留每类最多 N 条（优先保留目标地址与闭合交集）并重算 (+K more)。"""
    plain_lines: list[str] = []
    buckets: dict[tuple[str, str], dict[str, Any]] = {}

    for line in (existing_evidence or "").splitlines():
        if not line.strip():
            continue
        summary_match = _EVIDENCE_SUMMARY_LINE_RE.match(line)
        if summary_match:
            key = (summary_match.group("marker"), summary_match.group("category"))
            bucket = buckets.setdefault(
                key,
                {
                    "facts": [],
                    "seen": set(),
                    "existing_facts": [],
                    "incoming_seen": set(),
                    "omitted_seed": 0,
                },
            )
            bucket["omitted_seed"] += int(summary_match.group("count"))
            continue

        fact_match = _EVIDENCE_FACT_LINE_RE.match(line)
        if fact_match:
            key = (fact_match.group("marker"), fact_match.group("category"))
            bucket = buckets.setdefault(
                key,
                {
                    "facts": [],
                    "seen": set(),
                    "existing_facts": [],
                    "incoming_seen": set(),
                    "omitted_seed": 0,
                },
            )
            fact = fact_match.group("fact")
            if fact not in bucket["seen"]:
                bucket["seen"].add(fact)
                bucket["facts"].append(fact)
                bucket["existing_facts"].append(fact)
            continue

        plain_lines.append(line)

    for fact in new_facts:
        category = fact.split(":", 1)[0] if ":" in fact else "misc"
        key = (marker, category)
        bucket = buckets.setdefault(
            key,
            {
                "facts": [],
                "seen": set(),
                "existing_facts": [],
                "incoming_seen": set(),
                "omitted_seed": 0,
            },
        )
        bucket["incoming_seen"].add(fact)
        if fact not in bucket["seen"]:
            bucket["seen"].add(fact)
            bucket["facts"].append(fact)

    pinned_set = {
        str(addr).strip().lower() for addr in (pinned or ()) if str(addr).strip()
    }
    rendered_lines = list(plain_lines)
    for (line_marker, category), bucket in buckets.items():
        ordered = _display_order(bucket["facts"], pinned_set)
        display = ordered[-max_per_category:]
        existing_facts: list[str] = bucket["existing_facts"]
        incoming_seen: set[str] = bucket["incoming_seen"]
        omitted_seed: int = bucket["omitted_seed"]
        # 仅用于同一批次幂等重放时避免将已省略项重复计入 omitted_seed；
        # 生产路径每次只传增量 evidence_delta，不会命中该重置分支。
        if (
            omitted_seed > 0
            and existing_facts
            and set(existing_facts).issubset(incoming_seen)
            and len(incoming_seen) == len(existing_facts) + omitted_seed
        ):
            omitted_seed = 0
        omitted = omitted_seed + max(0, len(ordered) - len(display))
        rendered_lines.extend(f"{line_marker}{fact}" for fact in display)
        if omitted > 0:
            rendered_lines.append(f"{line_marker}{category}: ... (+{omitted} more)")

    return "\n".join(rendered_lines).strip()


def gate_completion_criteria(
    gate_name: str, required_for: Iterable[str] = ()
) -> list[str]:
    """Return executor-owned, human-readable completion criteria for a gate."""
    signature_classes = set(required_for)
    if gate_name == "object_lifetime" and "page_not_present" in signature_classes:
        return [
            "the executor currently has no closure rule for this signature-specific gate; "
            "address-linked mapping teardown or lifetime evidence extraction is not implemented"
        ]
    if gate_name == "external_corruption_gate":
        return [
            "the executor rule requires local_corruption_exclusion to be verified and an "
            "external_source fact, but extraction of external_source facts is not implemented; "
            "a protocol-template decode alone therefore cannot close this optional gate"
        ]
    if gate_name == "lock_holder" and not (
        signature_classes & {"rcu_stall", "soft_lockup"}
    ):
        return [
            "no executor closure rule is defined; structured facts are telemetry only"
        ]
    if gate_name == "stack_integrity" and "soft_lockup" not in signature_classes:
        return [
            "no executor closure rule is defined; structured facts are telemetry only"
        ]
    criteria = _GATE_COMPLETION_CRITERIA.get(gate_name)
    if criteria is not None:
        return list(criteria)
    return [
        "no executor closure rule is defined; structured facts are telemetry only"
    ]


def evaluate_gate_closures(
    gates: Mapping[str, Any] | None,
    facts: Iterable[str],
    prior_gates: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, list[dict[str, object]]]:
    """
    应用执行器拥有的闭合规则，并返回可审计的门控状态转换记录。

    该函数通过检查当前证据事实（facts）是否满足每个门控（gate）的预定义完成准则，
    来决定门控是否应该关闭。如果 LLM 尝试关闭一个证据不足的门控，系统会拒绝该请求。

    Args:
        gates: 当前所有门控的映射，键为门控名称，值为门控对象。
        facts: 当前观测到的结构化事实集合。
        prior_gates: 先前的门控状态映射，用于对比状态变化。

    Returns:
        tuple[dict[str, Any] | None, list[dict[str, object]]]:
            - 更新后的门控对象字典。
            - 记录了所有门控状态转换的列表（包含转换原因和证据事实）。
    """
    if not gates:  # 如果没有门控，直接返回
        return None, []

    fact_set = set(facts)  # 将事实转换为集合以提高查找效率
    prior_gates = prior_gates or {}  # 如果没有提供先前的门控，则初始化为空字典
    evaluated: dict[str, Any] = {}  # 存储评估后的门控对象
    transitions: list[dict[str, object]] = []  # 记录状态转换事件

    for gate_name, raw_gate in gates.items():
        # 深度拷贝门控对象，以避免修改原始数据
        gate = (
            raw_gate.model_copy(deep=True)
            if hasattr(raw_gate, "model_copy")
            else raw_gate
        )
        prior = prior_gates.get(gate_name)  # 获取该门控先前的状态
        gate_scope = set(getattr(gate, "required_for", []))
        prior_scope = set(getattr(prior, "required_for", []))
        prior_applies = bool(gate_scope & prior_scope)
        prior_status = (
            getattr(prior, "status", None) if prior_applies else None
        )
        prior_basis = (
            getattr(prior, "closure_basis", None) if prior_applies else None
        )
        requested_evidence = getattr(gate, "evidence", None) or ""
        gate.evidence = (
            getattr(prior, "evidence", None) if prior_applies else None
        )
        requested_status = getattr(gate, "status", "open")  # LLM 请求的状态
        required_for = getattr(gate, "required_for", [])
        gate.completion_criteria = gate_completion_criteria(
            gate_name, required_for
        )  # 设置该门控的完成准则
        gate_fact_count: int | None = None

        def _get_gate_fact_count() -> int:
            nonlocal gate_fact_count
            if gate_fact_count is None:
                gate_fact_count = sum(
                    1 for fact in fact_set if _fact_supports_gate(fact, gate_name)
                )
            return gate_fact_count

        if prior_status == "closed" and prior_basis == "executor_evidence":
            gate.status = prior_status
            gate.closure_basis = prior_basis
        elif prior_status == "n/a" and prior_basis == "executor_na":
            gate.status = prior_status
            gate.closure_basis = prior_basis
        elif _gate_criteria_satisfied(
            gate_name, fact_set, evaluated, required_for
        ):
            gate.status = "closed"
            gate.closure_basis = "executor_evidence"
            gate_facts = [
                fact for fact in fact_set if _fact_supports_gate(fact, gate_name)
            ]
            gate_fact_count = len(gate_facts)
            if gate_facts:
                gate.evidence = _append_bounded_gate_evidence(
                    None,
                    gate_facts,
                    marker="[executor-evidence] ",
                    pinned=_closure_pinned_addresses(gate_name, gate_facts),
                )
        else:
            gate.status = (
                prior_status if prior_status in {"open", "blocked"} else "open"
            )
            gate.closure_basis = None

            if requested_status == "closed":
                transitions.append(
                    {
                        "gate_name": gate_name,
                        "from_status": prior_status or "open",
                        "to_status": gate.status,
                        "event": "llm_close_rejected",
                        "reason": "completion criteria not satisfied by structured evidence",
                        "requested_status": requested_status,
                        "requested_evidence": requested_evidence,
                        "evidence_fact_count": _get_gate_fact_count(),
                    }
                )
            elif not has_executor_closure_rule(
                gate_name, required_for
            ) and _get_gate_fact_count() > 0:
                transitions.append(
                    {
                        "gate_name": gate_name,
                        "from_status": gate.status,
                        "to_status": gate.status,
                        "event": "weak_gate_closure",
                        "reason": "structured facts are telemetry only; no executor closure rule is defined",
                        "evidence_fact_count": _get_gate_fact_count(),
                    }
                )
        if requested_status == "n/a" and not (
            gate.status == "n/a" and gate.closure_basis == "executor_na"
        ):
            transitions.append(
                {
                    "gate_name": gate_name,
                    "from_status": prior_status or "open",
                    "to_status": gate.status,
                    "event": "llm_na_rejected",
                    "reason": "not-applicable status requires an executor-owned rule",
                    "requested_status": requested_status,
                    "requested_evidence": requested_evidence,
                    "evidence_fact_count": _get_gate_fact_count(),
                }
            )
        evaluated[gate_name] = gate  # 将评估后的门控存入结果字典

        current_status = getattr(gate, "status", "open")
        # 如果门控状态发生了变化，记录一次状态转换事件
        if prior_status is not None and current_status != prior_status:
            transitions.append(
                {
                    "gate_name": gate_name,
                    "from_status": prior_status,
                    "to_status": current_status,
                    "event": "gate_transition",
                    "reason": "executor evidence rule satisfied",
                    "evidence_fact_count": _get_gate_fact_count(),
                }
            )

    return evaluated, transitions


def _gate_criteria_satisfied(
    gate_name: str,
    facts: set[str],
    evaluated_gates: Mapping[str, Any],
    required_for: Iterable[str] = (),
) -> bool:
    """
    判断当前提取到的结构化事实是否满足指定门控（gate）的闭合准则。

    不同的分析门控对事实证据的类型有不同的组合要求（例如需要反汇编指令、内存数据、
    结构体字段或符号等独立维度的交叉验证）。部分门控还存在前置门控依赖关系。

    Args:
        gate_name: 门控名称（例如 "register_provenance"、"local_corruption_exclusion" 等）。
        facts: 当前已经观测并提取出的结构化事实字符串集合（如以 "rd_word:"、"struct_" 等开头）。
        evaluated_gates: 当前已完成评估的门控字典映射，用于检查前置门控的状态。

    Returns:
        bool: 如果满足该门控的所有证据要求及前置条件则返回 True，否则返回 False。
    """
    if gate_name == "object_lifetime":
        if "page_not_present" in set(required_for):
            return False
        slab_addresses = {
            fact.split(":", 1)[1].split("=", 1)[0]
            for fact in facts
            if fact.startswith("kmem_slab_state:")
        }
        object_addresses = {
            fact.split(":", 1)[1].split("=", 1)[0]
            for fact in facts
            if fact.startswith("rd_word:")
        }
        return bool(slab_addresses & object_addresses)

    if gate_name == "external_corruption_gate":
        prerequisite = evaluated_gates.get("local_corruption_exclusion")
        if prerequisite is None or getattr(prerequisite, "status", None) != "closed":
            return False
        return any(fact.startswith("external_source:") for fact in facts)

    signature_classes = set(required_for)

    if gate_name == "rcu_stall_trace":
        has_rcu_state = any(
            fact.startswith(_RCU_TRACE_STATE_PREFIXES) for fact in facts
        )
        has_exec_ctx = any(
            fact.startswith(_EXECUTION_CONTEXT_PREFIXES) for fact in facts
        )
        return has_rcu_state and has_exec_ctx

    if gate_name == "lock_holder":
        has_holder_ctx = any(
            fact.startswith(("bt_task:", "dis_instruction:", "dis_symbol:"))
            for fact in facts
        )
        if "rcu_stall" in signature_classes:
            has_rcu_holder = any(
                fact.startswith(_RCU_HOLDER_IDENTITY_PREFIXES) for fact in facts
            )
            return has_rcu_holder and has_holder_ctx
        if "soft_lockup" in signature_classes:
            has_lock_owner = any(
                fact.startswith(_SOFT_LOCKUP_HOLDER_PREFIXES) for fact in facts
            )
            if has_lock_owner and has_holder_ctx:
                return True
            # 无外部锁争抢的纯死循环 / softirq 忙等：需同时具备 CPU 停滞诊断 + bt + dis
            has_lock_free_diag = any(
                fact.startswith(_SOFT_LOCKUP_NO_LOCK_PREFIXES) for fact in facts
            )
            has_bt = any(fact.startswith("bt_task:") for fact in facts)
            has_dis = any(fact.startswith("dis_") for fact in facts)
            return has_lock_free_diag and has_bt and has_dis
        return False

    if gate_name == "blocked_task_context":
        has_bt_task = any(fact.startswith("bt_task:") for fact in facts)
        has_bt_frames = any(
            fact.startswith(("bt_frame:", "dis_symbol:", "dis_instruction:"))
            for fact in facts
        )
        has_blocked_state = any(
            fact.startswith(_HUNG_TASK_STATE_PREFIXES) for fact in facts
        )
        return has_bt_task and has_bt_frames and has_blocked_state

    if gate_name == "wait_chain":
        has_chain = any(fact.startswith(_WAIT_CHAIN_PREFIXES) for fact in facts)
        has_corroboration = any(
            fact.startswith(
                ("bt_task:", "struct_field:", "struct_type:", "dis_", "rd_word:")
            )
            for fact in facts
        )
        return has_chain and has_corroboration

    if gate_name == "stack_integrity":
        if "soft_lockup" not in signature_classes:
            return False
        has_stack = (
            any(fact.startswith("bt_task:") for fact in facts)
            and any(fact.startswith("bt_frame:") for fact in facts)
        ) or any(fact.startswith("cpu_lockup_cpu:") for fact in facts)
        has_code_ref = any(fact.startswith(("dis_", "sym:")) for fact in facts)
        return has_stack and has_code_ref

    if gate_name == "nmi_watchdog_evidence":
        has_nmi = any(
            fact.startswith(("nmi_watchdog_frame:", "cpu_lockup_irq_softirq:"))
            for fact in facts
        )
        has_ctx = any(
            fact.startswith(("bt_task:", "dis_instruction:", "dis_symbol:"))
            for fact in facts
        )
        return has_nmi and has_ctx

    if gate_name == "cpu_progress_state":
        has_progress = any(fact.startswith(_CPU_PROGRESS_PREFIXES) for fact in facts)
        has_ctx = any(
            fact.startswith(("bt_task:", "dis_instruction:", "dis_symbol:"))
            for fact in facts
        )
        return has_progress and has_ctx

    # 统计当前事实集合中命中了哪些维度的证据类别：
    # - "rd": 内存读取证据（以 "rd_word:" 开头，记录指定地址的字值）
    # - "struct": 结构体布局证据（以 "struct_" 开头，记录结构体类型、字段偏移和大小）
    # - "dis": 反汇编证据（以 "dis_" 开头，记录指令地址、助记符和符号）
    # - "sym": 符号表证据（以 "sym:" 开头，记录符号名、地址和类型）
    categories = {
        "rd": any(fact.startswith("rd_word:") for fact in facts),
        "struct": any(fact.startswith("struct_") for fact in facts),
        "dis": any(fact.startswith("dis_") for fact in facts),
        "sym": any(fact.startswith("sym:") for fact in facts),
    }

    # 定义各门控闭合所需的证据组（每个子列表为一个要求组，组内任一类别满足即满足该组，
    # 且所有要求组均须满足）：
    # - register_provenance（故障寄存器来源）: 需内存读取证据，且需反汇编或符号证据
    # - local_corruption_exclusion（局部内存破坏排除）: 需反汇编指令且需内存读取证据
    # - field_type_classification（字段类型分类）: 需结构体信息且需符号表证据
    # - external_corruption_gate（外部破坏门控）: 需至少具备一类结构化证据
    required_groups = {
        "register_provenance": [{"rd"}, {"dis", "sym"}],
        "local_corruption_exclusion": [{"dis"}, {"rd"}],
        "field_type_classification": [{"struct"}, {"sym"}],
    }.get(gate_name)
    if required_groups is None:
        return False

    # 检查是否所有必需的证据组都得到了满足：
    # 每个 group 只要包含的类别中有至少一项为 True，则该 group 计数加 1
    return sum(
        any(categories[name] for name in group) for group in required_groups
    ) >= len(required_groups)


def has_executor_closure_rule(
    gate_name: str, required_for: Iterable[str] = ()
) -> bool:
    signature_classes = set(required_for)
    if gate_name == "object_lifetime" and "page_not_present" in signature_classes:
        return False
    if gate_name == "lock_holder":
        return bool(signature_classes & {"rcu_stall", "soft_lockup"})
    if gate_name == "stack_integrity":
        return "soft_lockup" in signature_classes
    # external_corruption_gate 的规则已定义，但 external_source 事实抽取尚未实现，
    # 因此当前没有可执行能力；接入抽取器后把该门控加回此集合。
    return gate_name in {
        "register_provenance",
        "object_lifetime",
        "local_corruption_exclusion",
        "field_type_classification",
        "rcu_stall_trace",
        "blocked_task_context",
        "wait_chain",
        "nmi_watchdog_evidence",
        "cpu_progress_state",
    }


def extract_evidence_facts(
    tool_name: str,
    raw_args: Any,
    output: str,
) -> set[str]:
    """提取出的事实用于后续的门控（gate）闭合评估，以判断某个诊断假设是否
    有足够的结构化证据支撑。

    Args:
        tool_name: 工具名称，通常为 "run_script"（表示执行多行脚本）或其他直接命令工具。
                该参数决定了如何从 raw_args 中解析出实际的命令列表。
        raw_args: 工具的原始参数字典或字符串。
                - 对于直接命令工具：通常是 {"command": "rd 0x100 8"} 或纯字符串。
                - 对于 run_script：通常是 {"script": "rd 0x100 8\nstruct task_struct"} 或纯字符串。
        output: crash 调试器命令执行后的原始标准输出文本。

    Returns:
        set[str]: 提取出的事实字符串集合。每个事实是一个稳定的、可哈希的字符串，
        格式取决于命令类型：
        - rd 命令 → "rd_word:0x<address>=0x<value>"
        - struct 命令 → "struct_type:<name>"、"struct_field:<name>.<field>@0x<offset>"、
                        "struct_size:<name>=0x<size>"
        - dis 命令 → "dis_instruction:0x<address>=<mnemonic>"、"dis_symbol:<symbol>"
        - sym 命令 → "sym:<symbol>@0x<address>:<kind>"
        - kmem -S 命令 → "kmem_slab_state:0x<address>=allocated|free"
        - KASAN UAF 报告 → unbound lifetime signal (telemetry only)
        - kernel_source 输出中的 SOURCE_REF → "source_ref:<file>:<line>"

        如果命令类型不受支持或输出中无有效内容，则返回空集合。
    """
    # 根据工具类型和参数，解析出实际执行的 crash 命令列表。
    # 例如 run_script 可能包含多行命令，每行会被拆分为独立命令。
    commands = _command_lines(tool_name, raw_args)
    facts: set[str] = set()
    if _KASAN_UAF_RE.search(output):
        facts.add("lifetime_signal:kasan_use_after_free_unbound")
    # 源码锚点与命令类型无关：kernel_source 的只读工具同样会产出 SOURCE_REF。
    for ref in _SOURCE_REF_RE.finditer(output):
        facts.add(f"source_ref:{ref.group('file')}:{ref.group('line')}")

    status = _SOURCE_STATUS_RE.search(output)
    if status is not None:
        facts.add(f"source_status:configured={status.group('configured')}")
    for query in _SOURCE_GREP_RE.finditer(output):
        pattern = query.group("pattern")[:80]
        hits = int(query.group("hits"))
        if hits == 0:
            # 0 命中是"排除性结果"：能证明"这棵树里没有该模式"，但不能作为
            # 门控证据，也不该被当成"查到了"来记账。
            facts.add(f"source_negative:grep:{pattern}")
        else:
            facts.add(f"source_grep:{pattern}:hits={hits}")
    for writers in _SOURCE_WRITERS_RE.finditer(output):
        field = writers.group("field")
        hits = int(writers.group("hits"))
        if hits == 0:
            facts.add(f"source_negative:writers:{field}")
        else:
            facts.add(f"source_writers:{field}:hits={hits}")
    for history in _SOURCE_GIT_RE.finditer(output):
        facts.add(
            f"source_git:{history.group('file')}:{history.group('range')}"
        )

    if tool_name in {"analyze_cpu_lockup_rcu", "analyze_lock_wait_graph"}:
        facts.update(_parse_lock_hang_json(tool_name, output))

    for command in commands:
        # 提取命令的第一个单词（命令名），转为小写以统一匹配
        # 例如 "rd 0x100 8" → "rd"，"struct task_struct" → "struct"
        name = command.split(maxsplit=1)[0].lower() if command.strip() else ""
        if name in {"rd", "compare_memory_blocks"}:
            # 解析内存读取输出，提取每个 8 字节字及其地址
            facts.update(_parse_rd(output))
        elif name == "struct":
            # 解析结构体定义输出，提取类型名、字段偏移和总大小
            facts.update(_parse_struct(output))
            # 解析结构体实例字段值（task_struct RCU/状态字段、rcu_node 队列字段、锁 owner）
            facts.update(_parse_struct_values(output))
        elif name == "bt":
            facts.update(_parse_bt(output))
        elif name == "p":
            facts.update(_parse_print_vars(command, output))
        elif name == "runq":
            facts.update(_parse_runq(output))
        elif name == "ps":
            facts.update(_parse_ps(output))
        elif name == "dis":
            # 解析反汇编输出，提取指令助记符和符号
            facts.update(_parse_dis(output))
        elif name == "sym":
            # 解析符号表输出，提取符号名、地址和类型
            facts.update(_parse_sym(output))
        elif name == "vtop":
            facts.update(_parse_vtop(output))
        elif name == "kmem":
            facts.update(_parse_kmem(output))
        elif name == "inspect_slab_object":
            facts.update(_parse_kmem(output))
            facts.update(_parse_vtop(output))
            facts.update(_parse_rd(output))
            # struct -o / struct <type> <addr> 的输出也在同一个复合工具结果里，
            # 不能漏掉布局事实（struct_type/struct_field/struct_size）。
            facts.update(_parse_struct(output))
    return facts


def update_gate_evidence(
    gates: Mapping[str, Any] | None,
    facts: Iterable[str],
    *,
    pinned_addresses: Iterable[str] = (),
) -> dict[str, Any] | None:
    """
    将新发现的事实（facts）附加到相关的门控（gates）证据中，但不允许事实直接关闭门控。

    该函数会遍历所有的门控，检查传入的事实是否支持某个门控。如果支持，则将该事实
    以特定的标记格式 `[evidence-delta] <fact>` 追加到该门控的 `evidence` 字段中。
    此操作仅用于记录证据的增加，不会改变门控的状态（例如不会将其设为已关闭）。

    Args:
        gates: 一个映射，键为门控名称，值为门控对象（通常是 Pydantic 模型或类字典对象）。
               如果为 None，则返回 None。
        facts: 一个可迭代的事实字符串集合。
        pinned_addresses: 当前证据目标关联的地址集合，展示截断时优先保留。

    Returns:
        包含更新后门控对象的字典，或者如果输入 gates 为 None 则返回 None。
        如果 facts 为空，则返回 gates 的副本。
    """
    if not gates:
        return None

    # 对事实进行去重并排序，确保处理顺序的一致性
    fact_list = sorted(set(facts))
    if not fact_list:
        return dict(gates)

    updated: dict[str, Any] = {}
    for gate_name, raw_gate in gates.items():
        # 深度拷贝门控对象，以避免直接修改原始输入数据
        # 优先使用 Pydantic 的 model_copy 方法，否则进行浅拷贝/直接赋值
        gate = (
            raw_gate.model_copy(deep=True)
            if hasattr(raw_gate, "model_copy")
            else raw_gate
        )

        # 筛选出能够支持当前门控的所有事实
        relevant = [fact for fact in fact_list if _fact_supports_gate(fact, gate_name)]

        if relevant:
            evidence = getattr(gate, "evidence", None) or ""
            gate.evidence = _append_bounded_gate_evidence(
                evidence,
                relevant,
                marker="[evidence-delta] ",
                pinned=pinned_addresses,
            )

        updated[gate_name] = gate

    return updated


def facts_support_goal(facts: Iterable[str], goal: Mapping[str, Any] | None) -> bool:
    """
    判断新发现的事实是否与当前的目标门控相关。

    Args:
        facts: 一个可迭代的事实字符串集合。
        goal: 当前的目标字典，通常包含 "gate_name" 键。

    Returns:
        bool: 如果至少有一个事实支持该门控，则返回 True，否则返回 False。
    """
    if not goal:  # 如果目标为空，直接返回 False
        return False
    gate_name = str(goal.get("gate_name", ""))  # 从目标中获取门控名称
    # 检查事实集合中是否至少有一个事实能支持该门控
    return any(_fact_supports_gate(fact, gate_name) for fact in facts)


def _command_lines(tool_name: str, raw_args: Any) -> list[str]:
    """
    解析工具名称和原始参数，提取出需要执行的命令行列表。

    Args:
        tool_name: 工具名称。如果是 "run_script"，则表示参数中包含多行脚本。
        raw_args: 工具的原始参数。
                - 对于直接命令工具：通常是 {"command": "..."} 或纯字符串。
                - 对于 run_script：通常是 {"script": "..."} 或包含脚本内容的字符串。

    Returns:
        list[str]: 提取出的命令行列表，每行作为一个独立的命令。
    """
    if tool_name != "run_script":  # 如果不是多行脚本模式，处理单条命令
        if isinstance(raw_args, dict):  # 如果参数是字典格式
            command = raw_args.get("command", "")  # 从字典中提取 command 字段
        else:
            command = raw_args
        command = str(command).strip()
        if not command:
            return []
        if command.split(maxsplit=1)[0].lower() != tool_name.lower():
            command = f"{tool_name} {command}"
        return [command]

    # 处理 run_script 模式下的多行脚本
    if isinstance(raw_args, dict):  # 如果参数是字典格式
        script = raw_args.get("script", "")  # 从字典中提取 script 字段
    else:  # 如果参数是字符串
        script = raw_args

    # 将脚本按行拆分，去除每行首尾空格，并过滤掉空行
    return [line.strip() for line in str(script).splitlines() if line.strip()]


def _extract_ascii_facts(byte_map: Mapping[int, int]) -> set[str]:
    """Extract bounded printable-string facts from reconstructed ``rd`` bytes."""
    facts: set[str] = set()
    ordered = sorted(byte_map)
    if not ordered:
        return facts

    max_strings = 8
    index = 0
    while index < len(ordered) and len(facts) < max_strings:
        run_start = ordered[index]
        run = bytearray()
        previous = run_start
        while index < len(ordered):
            address = ordered[index]
            if address != previous + 1:
                if run:
                    break
                run_start = address
            byte = byte_map[address]
            if 0x20 <= byte <= 0x7E:
                run.append(byte)
            else:
                if len(run) >= 8:
                    facts.add(
                        f"rd_ascii:0x{run_start:x}={run.decode('ascii')}"
                    )
                    if len(facts) >= max_strings:
                        return facts
                run = bytearray()
                run_start = address + 1
            previous = address
            index += 1
        if len(run) >= 8:
            facts.add(f"rd_ascii:0x{run_start:x}={run.decode('ascii')}")
    return facts


def _parse_rd(output: str) -> set[str]:
    """
    解析 ``rd``（内存读取）命令的输出并提取事实（facts）。

    crash 的 ``rd`` 命令输出格式为每行一个地址后跟若干十六进制字（word），
    例如::

        ffff0000: 0000000000000010 0000000000000020  ..

    该函数将每个字与其所在地址关联，生成格式为
    ``rd_word:0x<address>=0x<value>`` 的事实。由于 64 位内核中每个字占 8 字节，
    第 index 个字的地址为 ``起始地址 + index * 8``。连续原始内存中长度不少于
    8 的可打印字符串还会生成 ``rd_ascii:0x<address>=<text>`` 事实，作为字符串
    线索，不代表协议语义已被验证。

    Args:
        output (str): ``rd`` 命令的标准输出字符串。

    Returns:
        set[str]: 包含提取出的内存字事实的集合。
    """
    facts: set[str] = set()
    byte_map: dict[int, int] = {}
    for line in output.splitlines():
        # 匹配 "地址: 数据..." 格式的行，例如 "ffff0000: 0000000000000010 ..."
        match = _RD_LINE_RE.match(line)
        if not match:
            continue
        # 该行数据块的起始地址
        address = _to_int(match.group("address"))
        # 逐个提取十六进制字；遇到非十六进制的 token（如行尾的 ASCII 预览
        # ".." 或 "<read error>"）即停止，只保留前面有效的字
        words = []
        for token in match.group("words").split():
            if not re.fullmatch(_HEX, token):
                break
            words.append(token)
        # 每个字按其实际内存地址（起始地址 + 序号*8字节）记录一条事实，
        # 数值统一规范化为十六进制输出
        for index, word in enumerate(words):
            value = _to_int(word)
            facts.add(f"rd_word:0x{address + index * 8:x}=0x{value:x}")
            if value < (1 << 64):
                for offset, byte in enumerate(value.to_bytes(8, "little")):
                    byte_map[address + index * 8 + offset] = byte
    # ASCII 只作为可读字符串线索；协议语义仍需按文档 bit layout 解码。
    facts.update(_extract_ascii_facts(byte_map))
    return facts


def _parse_struct(output: str) -> set[str]:
    """
    解析由内核调试器（如 crash）输出的结构体定义文本，并将其转换为事实（facts）集合。

    字段名与偏移的解析委托给 ``consistency.parse_struct_layouts``：crash 的
    ``struct -o`` 输出形如 ``[112] struct irqaction *action;``，字段名写在声明之后，
    不能把声明中的第一个标识符当作字段名。

    生成的 fact 格式如下：
    - struct_type:<name>: 表示发现了一个结构体类型。
    - struct_field:<name>.<field_name>@0x<offset>: 表示结构体中的一个字段及其偏移量。
    - struct_size:<name>=0x<size>: 表示结构体的总字节大小。

    Args:
        output (str): 包含结构体定义的原始字符串输出。

    Returns:
        set[str]: 包含解析出的结构体相关事实的集合。
    """
    facts: set[str] = set()
    for type_name, layout in parse_struct_layouts(output).items():
        facts.add(f"struct_type:{type_name}")
        size = layout.get("size")
        if isinstance(size, int) and size > 0:
            facts.add(f"struct_size:{type_name}=0x{size:x}")
        for field in layout.get("fields", []):
            facts.add(
                f"struct_field:{type_name}.{field['name']}@0x{field['offset']:x}"
            )
    return facts


def _parse_dis(output: str) -> set[str]:
    """
    解析反汇编（disassembly）输出并提取事实（facts）。

    该函数通过正则表达式匹配反汇编输出的每一行，提取指令地址、指令内容以及符号信息。
    它会将提取到的信息转化为特定格式的字符串，存入事实集合中。

    解析出的事实格式：
    - `dis_instruction:0x<address>=<mnemonic>`: 记录特定地址处的指令助记符。
    - `dis_symbol:<symbol>`: 记录反汇编输出中出现的符号。

    Args:
        output (str): 反汇编工具（如 objdump）的标准输出字符串。

    Returns:
        set[str]: 包含提取出的反汇编相关事实的集合。
    """
    facts: set[str] = set()
    for line in output.splitlines():
        match = _DIS_LINE_RE.match(line)
        if not match:
            continue
        address = _to_int(match.group("address"))
        instruction = " ".join(match.group("instruction").split())
        mnemonic = instruction.split(maxsplit=1)[0]
        facts.add(f"dis_instruction:0x{address:x}={mnemonic}")
        facts.add(f"dis_symbol:{match.group('symbol')}")
    return facts


def _parse_sym(output: str) -> set[str]:
    """
    解析符号表（symbol table）输出并提取事实（facts）。

    该函数解析符号表工具（如 nm）的输出，提取符号名称、内存地址及其类型（kind）。

    解析出的事实格式：
    - `sym:<symbol>@0x<address>:<kind>`: 记录符号及其对应的地址和类型。

    Args:
        output (str): 符号表工具的标准输出字符串。

    Returns:
        set[str]: 包含提取出的符号相关事实的集合。
    """
    facts: set[str] = set()
    for line in output.splitlines():
        match = _SYM_LINE_RE.match(line)
        if match:
            facts.add(
                f"sym:{match.group('symbol')}@0x{_to_int(match.group('address')):x}:{match.group('kind')}"
            )
    return facts


def _parse_vtop(output: str) -> set[str]:
    """
    解析 ``vtop``（虚拟地址转物理地址）命令的输出并提取事实（facts）。

    该函数逐行匹配输出，识别两类映射状态信息：
    1. 地址未映射（"not mapped"）→ 生成 ``vtop_unmapped:0x<address>`` 事实，
       说明该虚拟地址在当前页表中没有对应的物理页。
    2. 页表项（PTE）值 → 生成 ``vtop_pte:0x<value>`` 事实，
       记录该地址对应的页表项内容（可用于判断页面权限、有效性等）。
    3. 已映射地址 → 生成 ``vtop_phys:0x<virtual>=0x<physical>`` 事实，
       供 Slab 页边界和 4KB 对齐分析使用。

    Args:
        output (str): ``vtop`` 命令的标准输出字符串。

    Returns:
        set[str]: 包含提取出的映射状态相关事实的集合。
    """
    facts: set[str] = set()
    for line in output.splitlines():
        # 尝试匹配 "未映射" 行，例如 "0xffff0000 (not mapped)"
        unmapped = _VTOP_UNMAPPED_RE.match(line)
        if unmapped:
            # 将地址转换为整数后以十六进制规范化输出
            address = _to_int(unmapped.group("address"))
            facts.add(f"vtop_unmapped:0x{address:x}")
            continue

        mapped = _VTOP_MAPPED_RE.match(line)
        if mapped:
            virtual = _to_int(mapped.group("virtual"))
            physical = _to_int(mapped.group("physical"))
            facts.add(f"vtop_phys:0x{virtual:x}=0x{physical:x}")
            continue

        # 尝试匹配 PTE 行，例如 "PTE: 0x123456789" 或 "PTE: 0x123 => 0x456"
        pte = _VTOP_PTE_RE.match(line)
        if pte:
            facts.add(f"vtop_pte:0x{_to_int(pte.group('value')):x}")
    return facts


def _parse_kmem(output: str) -> set[str]:
    """
    解析 ``kmem`` 输出中的 vmalloc 范围或 ``kmem -S`` 当前 slab 槽位状态。

    slab 状态事实只表示转储时的状态，不包含该槽位先前的分配历史。

    Args:
        output (str): ``kmem -v`` 命令的标准输出字符串。

    Returns:
        set[str]: 包含提取出的 vmalloc 范围相关事实的集合。
    """
    facts: set[str] = set()
    for line in output.splitlines():
        match = _KMEM_RANGE_RE.match(line)
        if match:
            # 起止地址按十六进制解析
            start = _to_int(match.group("start"))
            end = _to_int(match.group("end"))
            # 大小字段在输出中为十进制数字
            size = int(match.group("size"), 10)
            facts.add(f"kmem_vmap_range:0x{start:x}-0x{end:x}=0x{size:x}")

    lines = output.splitlines()
    slab_header = next(
        (
            index
            for index, line in enumerate(lines)
            if "FREE / [ALLOCATED]" in line.upper()
        ),
        None,
    )
    if slab_header is not None:
        for line in lines[slab_header + 1 :]:
            match = _KMEM_SLAB_SLOT_RE.match(line)
            if not match:
                continue
            allocated = match.group("allocated")
            address = allocated or match.group("free")
            if address is None:
                continue
            status = "allocated" if allocated else "free"
            facts.add(f"kmem_slab_state:0x{_to_int(address):x}={status}")
    return facts


def _parse_bt(output: str) -> set[str]:
    """解析 crash ``bt`` 输出中的任务头、调用栈帧与 NMI/watchdog 关键帧。

    按每个 ``PID:`` 任务块独立限制帧数（每任务前 6 帧，总计最多 48 帧），
    避免多核 ``bt -a`` 时前几个 idle CPU 吃满配额导致后续卡死 CPU 栈帧丢失。
    """
    facts: set[str] = set()
    task_frame_count = 0
    total_frame_count = 0
    max_frames_per_task = 6
    max_total_frames = 48
    for line in output.splitlines():
        header = _BT_TASK_HEADER_RE.match(line)
        if header:
            pid = header.group("pid")
            task_addr = _to_int(header.group("task"))
            cpu = header.group("cpu")
            comm = header.group("comm").strip()
            facts.add(f"bt_task:pid={pid}:task=0x{task_addr:x}:cpu={cpu}:comm={comm}")
            task_frame_count = 0
            continue
        frame = _BT_FRAME_RE.match(line)
        if frame:
            sym = frame.group("symbol")
            if task_frame_count < max_frames_per_task and total_frame_count < max_total_frames:
                facts.add(f"bt_frame:{sym}")
                task_frame_count += 1
                total_frame_count += 1
            sym_low = sym.lower()
            if any(tok in sym_low for tok in _NMI_WATCHDOG_FRAME_TOKENS):
                facts.add(f"nmi_watchdog_frame:{sym}")
    return facts


def _parse_struct_values(output: str) -> set[str]:
    """解析 crash ``struct <type>.<field> <addr>`` 实例字段值（RCU / 任务状态 / 锁 owner）。"""
    facts: set[str] = set()
    pid_val: str | None = None
    nesting_vals: list[int] = []
    state_vals: list[int] = []

    for line in output.splitlines():
        pid_m = _STRUCT_PID_RE.match(line)
        if pid_m:
            pid_val = pid_m.group("pid")
            continue

        state_m = _STRUCT_TASK_STATE_RE.match(line)
        if state_m:
            raw_s = state_m.group("val")
            s_val = int(raw_s, 16) if raw_s.lower().startswith("0x") else int(raw_s, 10)
            state_vals.append(s_val)
            continue

        nest_m = _STRUCT_RCU_NESTING_RE.match(line)
        if nest_m:
            val = int(nest_m.group("val"), 10)
            if val > 0:
                nesting_vals.append(val)
            continue

        blkd_node_m = _STRUCT_RCU_BLOCKED_NODE_RE.match(line)
        if blkd_node_m:
            addr = _to_int(blkd_node_m.group("addr"))
            if addr != 0:
                facts.add(f"rcu_blocked_node:0x{addr:x}")
            continue

        gp_tasks_m = _STRUCT_RCU_GP_TASKS_RE.match(line)
        if gp_tasks_m:
            addr = _to_int(gp_tasks_m.group("addr"))
            if addr != 0:
                facts.add(f"rcu_node_gp_tasks:0x{addr:x}")
            continue

        gp_seq_m = _STRUCT_RCU_GP_SEQ_RE.match(line)
        if gp_seq_m:
            raw_v = gp_seq_m.group("val")
            val = int(raw_v, 16) if raw_v.lower().startswith("0x") else int(raw_v, 10)
            facts.add(f"rcu_gp_seq:{val}")
            continue

        qsmask_m = _STRUCT_RCU_QSMASK_RE.match(line)
        if qsmask_m:
            raw_v = qsmask_m.group("val")
            val = int(raw_v, 16) if raw_v.lower().startswith("0x") else int(raw_v, 10)
            facts.add(f"rcu_qsmask:{val}")
            continue

        owner_m = _STRUCT_LOCK_OWNER_RE.search(line)
        if owner_m:
            raw_owner = owner_m.group("counter") or owner_m.group("ptr")
            if raw_owner is not None:
                try:
                    if raw_owner.lower().startswith("0x"):
                        owner_int = int(raw_owner, 16)
                    elif raw_owner.lstrip("-").isdigit():
                        owner_int = int(raw_owner, 10) & ((1 << 64) - 1)
                    else:
                        owner_int = int(raw_owner, 16)
                except ValueError:
                    owner_int = 0
                if owner_int != 0:
                    facts.add(f"lock_owner_word:0x{owner_int:x}")

    for val in nesting_vals:
        if pid_val is not None:
            facts.add(f"rcu_reader_nesting:pid={pid_val}={val}")
        else:
            facts.add(f"rcu_reader_nesting:{val}")

    for s_val in state_vals:
        if pid_val is not None:
            facts.add(f"task_state:pid={pid_val}={s_val}")
        else:
            facts.add(f"task_state:{s_val}")

    blkd_m = _STRUCT_BLKD_TASKS_NEXT_RE.search(output)
    if blkd_m:
        addr = _to_int(blkd_m.group("addr"))
        if addr != 0:
            facts.add(f"rcu_node_blkd_tasks:0x{addr:x}")

    return facts


def _parse_print_vars(command: str, output: str) -> set[str]:
    """解析 crash ``p`` 输出中的 RCU 全局参数/宽限期变量。"""
    facts: set[str] = set()
    for line in output.splitlines():
        m = _PRINT_RCU_VAR_RE.match(line)
        if m:
            facts.add(f"rcu_sysctl:{m.group('name')}={m.group('val')}")
            continue
        if _RCU_STATE_GP_SEQ_CMD_RE.match(command.strip()):
            dm = _GDB_DOLLAR_INT_RE.match(line)
            if dm:
                val = int(dm.group("val"), 10)
                if val > 0:
                    facts.add(f"rcu_gp_seq:{val}")
    return facts


def _parse_runq(output: str) -> set[str]:
    """解析 crash ``runq`` 输出中的各 CPU 当前运行任务。"""
    facts: set[str] = set()
    current_cpu: str | None = None
    for line in output.splitlines():
        cpu_m = _RUNQ_CPU_HEADER_RE.match(line)
        if cpu_m:
            current_cpu = cpu_m.group("cpu")
            continue
        if current_cpu is not None:
            pid_m = _RUNQ_CURRENT_PID_RE.match(line)
            if pid_m:
                facts.add(f"runq_cpu:cpu={current_cpu}:pid={pid_m.group('pid')}")
                current_cpu = None
    return facts


def _parse_ps(output: str) -> set[str]:
    """解析 crash ``ps`` 与 ``ps -m`` 输出中的 UN（不可中断睡眠）等任务状态（有界抽取）。"""
    facts: set[str] = set()
    for line in output.splitlines():
        m = _PS_M_TASK_LINE_RE.match(line) or _PS_TASK_LINE_RE.match(line)
        if not m:
            continue
        state = m.group("state").upper()
        if state == "UN":
            facts.add(f"ps_task_state:pid={m.group('pid')}={state}")
            if len(facts) >= 16:
                break
    return facts


def _parse_lock_hang_json(tool_name: str, output: str) -> set[str]:
    """解析 lock_hang MCP 工具返回的真实 JSON 摘要，抽取确定性 RCU / 锁 / CPU 停滞事实。"""
    facts: set[str] = set()
    stripped = output.strip()
    if not stripped.startswith("{"):
        return facts
    try:
        data = json.loads(stripped)
    except (ValueError, TypeError):
        return facts
    if not isinstance(data, dict):
        return facts

    if tool_name == "analyze_cpu_lockup_rcu":
        if data.get("rcu_stall_detected"):
            facts.add("rcu_stall_cpu_trace:detected=true")

        rcu_summary = data.get("rcu_state_summary")
        if isinstance(rcu_summary, dict) and rcu_summary:
            if "gp_seq" in rcu_summary and rcu_summary["gp_seq"] is not None:
                facts.add(f"rcu_gp_seq:{rcu_summary['gp_seq']}")
            facts.add("rcu_stall_cpu_trace:rcu_state_summary=present")

        contenders = data.get("spinlock_contenders") or []
        for contender in contenders[:8]:
            if isinstance(contender, dict) and "cpu" in contender:
                pid = contender.get("pid")
                facts.add(
                    f"spinlock_contender:cpu={contender['cpu']}"
                    + (f":pid={pid}" if pid is not None else "")
                )
                facts.add(f"rcu_stall_cpu_trace:spinlock_cpu={contender['cpu']}")

        irq_cpus = data.get("irq_or_softirq_cpus") or []
        for item in irq_cpus[:8]:
            if isinstance(item, dict) and "cpu" in item:
                facts.add(f"cpu_lockup_irq_softirq:cpu={item['cpu']}")

        suspected = data.get("active_or_suspected_cpus") or []
        for cpu_item in suspected[:8]:
            if isinstance(cpu_item, dict) and "cpu" in cpu_item:
                cat = cpu_item.get("wait_category") or "active"
                facts.add(f"cpu_lockup_cpu:cpu={cpu_item['cpu']}={cat}")
                facts.add(f"rcu_stall_cpu_trace:cpu={cpu_item['cpu']}={cat}")
                for fr in (cpu_item.get("top_frames") or [])[:6]:
                    if isinstance(fr, str) and any(
                        tok in fr.lower() for tok in _NMI_WATCHDOG_FRAME_TOKENS
                    ):
                        facts.add(f"nmi_watchdog_frame:{fr}")

        # 若明确完成全核扫描且无自旋锁争抢，同时存在活跃/疑似卡死 CPU，记为无锁死循环线索
        if (
            isinstance(data.get("total_cpus_parsed"), int)
            and data["total_cpus_parsed"] > 0
            and data.get("spinlock_contender_count") == 0
            and (suspected or irq_cpus)
        ):
            facts.add("cpu_lockup_no_spinlock:true")

    elif tool_name == "analyze_lock_wait_graph":
        for cycle in (data.get("deadlock_cycles") or [])[:4]:
            if isinstance(cycle, list) and cycle:
                facts.add("wait_graph_cycle:" + "->".join(str(p) for p in cycle))
        for blocker in (data.get("root_blockers") or [])[:8]:
            if isinstance(blocker, dict) and blocker.get("pid") is not None:
                facts.add(f"wait_graph_blocker:pid={blocker['pid']}")
                facts.add(f"lock_holder_task:pid={blocker['pid']}")
        for edge in (data.get("wait_edges") or [])[:8]:
            if not isinstance(edge, dict):
                continue
            wpid = edge.get("waiter_pid")
            opid = edge.get("owner_pid")
            ltype = edge.get("lock_type") or "lock"
            if wpid is not None:
                facts.add(
                    f"wait_graph_edge:waiter={wpid}:owner={opid if opid is not None else 'unresolved'}:{ltype}"
                )
            if opid is not None:
                facts.add(f"lock_holder_task:pid={opid}")
        for unres in (data.get("non_sleep_lock_or_unresolved_tasks") or [])[:8]:
            if isinstance(unres, dict) and unres.get("pid") is not None:
                facts.add(f"wait_graph_unresolved:pid={unres['pid']}")
        # 兼容 --lock-addr 单锁解析输出
        if data.get("owner_pid") is not None:
            facts.add(f"lock_holder_task:pid={data['owner_pid']}")
            facts.add(f"wait_graph_blocker:pid={data['owner_pid']}")
    return facts


def _fact_supports_gate(fact: str, gate_name: str) -> bool:
    """
    判断某个事实（fact）是否与指定的门控（gate）相关，即是否可作为该门控的证据。

    事实与门控的关联通过事实字符串的前缀来判定，不同门控接受不同类型的事实前缀：
    - register_provenance: 内存读取、反汇编、符号表、虚拟地址映射状态
    - local_corruption_exclusion: 反汇编、内存读取、映射状态、vmalloc 范围
    - field_type_classification: 结构体布局、符号表
    - object_lifetime: kmem -S 当前槽位状态、直接生命周期证据
    - 其他/未知门控: 接受所有已知类型的事实

    Args:
        fact (str): 单个事实字符串（例如 "rd_word:0xffff0000=0x10"）。
        gate_name (str): 门控名称。

    Returns:
        bool: 如果该事实可作为该门控的证据则返回 True，否则返回 False。
    """
    if gate_name == "register_provenance":
        return fact.startswith(
            ("rd_word:", "dis_", "sym:", "vtop_", "source_ref:", "source_writers:")
        )
    if gate_name == "local_corruption_exclusion":
        return fact.startswith(
            (
                "dis_",
                "rd_word:",
                "rd_ascii:",
                "vtop_",
                "kmem_",
                "source_ref:",
                "source_writers:",
            )
        )
    if gate_name == "field_type_classification":
        return fact.startswith(("struct_", "sym:", "source_ref:"))
    if gate_name == "object_lifetime":
        return fact.startswith(("kmem_slab_state:", "rd_word:"))
    if gate_name == "external_corruption_gate":
        return fact.startswith("external_source:")
    if gate_name == "rcu_stall_trace":
        return fact.startswith(
            _RCU_TRACE_STATE_PREFIXES
            + _EXECUTION_CONTEXT_PREFIXES
            + ("rcu_sysctl:",)
        )
    if gate_name == "lock_holder":
        return fact.startswith(
            _RCU_HOLDER_IDENTITY_PREFIXES
            + _SOFT_LOCKUP_HOLDER_PREFIXES
            + _SOFT_LOCKUP_NO_LOCK_PREFIXES
            + _EXECUTION_CONTEXT_PREFIXES
            + ("rd_word:",)
        )
    if gate_name == "blocked_task_context":
        return fact.startswith(
            _HUNG_TASK_STATE_PREFIXES + _EXECUTION_CONTEXT_PREFIXES
        )
    if gate_name == "wait_chain":
        return fact.startswith(
            _WAIT_CHAIN_PREFIXES
            + _EXECUTION_CONTEXT_PREFIXES
            + ("struct_", "rd_word:")
        )
    if gate_name == "stack_integrity":
        return fact.startswith(
            _EXECUTION_CONTEXT_PREFIXES + ("sym:", "cpu_lockup_cpu:")
        )
    if gate_name == "nmi_watchdog_evidence":
        return fact.startswith(
            ("nmi_watchdog_frame:", "cpu_lockup_irq_softirq:")
            + _EXECUTION_CONTEXT_PREFIXES
        )
    if gate_name == "cpu_progress_state":
        return fact.startswith(
            _CPU_PROGRESS_PREFIXES + _EXECUTION_CONTEXT_PREFIXES
        )
    # 兜底：未知门控接受所有已知前缀的事实。
    # source_* 事实刻意不在这里：没有执行器闭合规则的门控（warning_site、
    # mce_log 等）拿到源码事实只会多出一条 weak_gate_closure 遥测噪音。
    return fact.startswith(
        ("rd_word:", "rd_ascii:", "struct_", "dis_", "sym:", "vtop_", "kmem_")
    )


def _to_int(value: str) -> int:
    """
    将十六进制字符串转换为整数。

    crash 输出中的地址/数值通常为十六进制（可能带 "0x" 前缀，也可能不带），
    因此无论是否带前缀都按十六进制解析。

    Args:
        value (str): 待转换的字符串，例如 "0xffff0000" 或 "ffff0000"。

    Returns:
        int: 转换后的整数值。
    """
    return int(value, 16 if value.lower().startswith("0x") else 16)
