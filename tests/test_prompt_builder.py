import sys
import types
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
src_pkg = types.ModuleType("src")
src_pkg.__path__ = [str(root / "src")]
sys.modules.setdefault("src", src_pkg)
react_pkg = types.ModuleType("src.react")
react_pkg.__path__ = [str(root / "src" / "react")]
sys.modules.setdefault("src.react", react_pkg)

from src.react.graph_state import CONVERGENCE_GUARD_STREAK_THRESHOLD
from src.react.prompt_builder import build_executor_state_section
from src.react.schema import GateEntry

OPEN_GATE = {
    "register_provenance": GateEntry(
        status="open", evidence="pending", required_for=["null_deref"]
    )
}
CLOSED_GATE = {
    "register_provenance": GateEntry(
        status="closed",
        evidence="rd+dis",
        required_for=["null_deref"],
        closure_basis="executor_evidence",
    )
}
ALL_DIMENSION_FACTS = [
    "rd_word:0xff292187ae124a80=0x12",
    "struct_type:irqaction",
    "dis_symbol:show_interrupts",
    "sym:show_interrupts@0xffffffffbc379660:t",
]

BASE_STATE = {
    "step_count": 30,
    "current_partial_dump": "partial",
    "managed_active_hypotheses": [],
    "messages": [],
    "evidence_goal_version": 3,
    "evidence_goal_status": "closed",
}

MENU_MARKERS = (
    "Gate closure is not root-cause proof",
    "Mandatory gates are still unresolved",
    "prefer terminating with your conclusion",
    "Untapped evidence dimensions",
    "All four structured evidence dimensions",
    "Pivot requirement",
)


def _render(**overrides: object) -> str:
    state = dict(BASE_STATE)
    state.update(overrides)
    return build_executor_state_section(state)


class ReplanProbeMenuTests(unittest.TestCase):
    """C5：门控全部关闭但无根因时，提示词必须给出可执行的转向方向。"""

    def test_dead_end_replaces_no_outstanding_gate(self) -> None:
        rendered = _render(
            current_signature_class="null_deref",
            current_root_cause_class=None,
            managed_gates=CLOSED_GATE,
            current_evidence_goal=None,
            last_action_status="duplicate",
            duplicate_streak=3,
            no_progress_streak=3,
            replan_required=True,
            evidence_facts=ALL_DIMENSION_FACTS,
        )
        self.assertNotIn("Current gate objective: no outstanding gate", rendered)
        self.assertIn("all mandatory gates are closed but no root cause", rendered)
        self.assertIn("Gate closure is not root-cause proof", rendered)
        self.assertIn("signature_class=null_deref", rendered)
        self.assertIn("Synthesize your closed gates now", rendered)
        self.assertIn("Pivot requirement", rendered)

    def test_layer0_system_contains_bounded_uncertainty_and_payload_rules(self) -> None:
        from src.react.layer0_system import LAYER0_SYSTEM_PROMPT_TEMPLATE
        from src.react.playbooks import PLAYBOOKS
        from src.react.prompt_builder import build_analysis_system_prompt
        from src.react.prompts import simplified_structure_reasoning_prompt
        from src.react.sop_fragments import SOP_FRAGMENTS

        self.assertIn("Bounded uncertainty convergence", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("Corrupted payload handling", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("CORRUPTED PAYLOAD", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("coherent, documented protocol template", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("candidate writers", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("Bounded low-confidence convergence is always preferred", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        # N3: Neither LAYER0 nor the assembled prompt may recommend "memory_corruption" alongside pointer_corruption
        self.assertNotIn('"pointer_corruption" or "memory_corruption"', LAYER0_SYSTEM_PROMPT_TEMPLATE)
        assembled = build_analysis_system_prompt(BASE_STATE, is_last_step=False)
        self.assertNotIn('"pointer_corruption" or "memory_corruption"', assembled)
        self.assertNotIn('`"pointer_corruption"` or `"memory_corruption"`', assembled)
        # B1: struct dot syntax must be explicitly permitted in both LAYER0 and simplified_structure_reasoning_prompt
        self.assertIn("struct <type>.<field>[,<field>] <addr>", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("struct <type>.<field>[,<field>] <addr>", simplified_structure_reasoning_prompt())
        # B3: CR2 classification in step 5 and #PF vs #GP rules must be conditionalized
        self.assertIn("For a General Protection Fault (#GP), the CPU does NOT update CR2", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("fault-address classification (#PF CR2 / #GP non-canonical operand)", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertNotIn("RIP instruction, CR2 classification, and immediate bad operand", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("BUG: unable to handle page fault for address", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        # B4: bt -f consistency across layer0 and SOP 3.8b (only hex task_addr allowed; numeric PID/frame number rejected)
        self.assertNotIn("bt -f <pid>", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("bt -f <task_addr>", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        self.assertIn("bt -f <task_addr>", SOP_FRAGMENTS["stack_overflow"])
        self.assertIn("never pass a frame number or numeric PID to bt -f", SOP_FRAGMENTS["stack_overflow"])
        # B2 & N7: Generic stack_corruption playbook must not unconditionally require a canary slot;
        # Canary Overwrite Value Analysis belongs in stack_protector_canary
        self.assertNotIn("Divide-by-Zero", PLAYBOOKS["general_protection_fault"])
        self.assertNotIn("MANDATORY PRE-CONCLUSION GATE (stack_protector_canary)", PLAYBOOKS["stack_corruption"])
        self.assertNotIn("Canary Overwrite Value Analysis", PLAYBOOKS["stack_corruption"])
        self.assertIn("Canary Overwrite Value Analysis", PLAYBOOKS["stack_protector_canary"])
        self.assertNotIn("Given canary_frame_addr", PLAYBOOKS["stack_corruption"])
        self.assertNotIn("relative to the corrupted canary slot", PLAYBOOKS["stack_corruption"])
        self.assertNotIn("Locate the stack canary check point (__stack_chk_fail call site)", PLAYBOOKS["stack_corruption"])
        # R3: canary-only rules must not remain in the generic (non-canary) stack playbook
        self.assertNotIn("Do NOT attribute canary corruption", PLAYBOOKS["stack_corruption"])
        self.assertNotIn("This restriction applies ONLY to the canary slot", PLAYBOOKS["stack_corruption"])
        self.assertNotIn("{CANARY_", PLAYBOOKS["stack_corruption"])
        # R1: bt -f guidance must never suggest a pid/task target
        self.assertNotIn("concrete pid", LAYER0_SYSTEM_PROMPT_TEMPLATE)
        # R2: every bt -f mention must carry the address form
        self.assertNotIn("Use bt -f,", SOP_FRAGMENTS["advanced_techniques"])

    def test_driver_overlay_requires_signal_or_dma_not_step_count_alone(self) -> None:
        from langchain_core.messages import HumanMessage
        from src.react.prompt_builder import _select_context_overlays, _select_sop_fragments
        from src.react.prompt_overlays import DRIVER_OBJECT_OVERLAY

        # Plain 'sym ' at step_count >= 6 must NOT trigger DRIVER_OBJECT_OVERLAY or duplicate SOP
        state_no_signal = {
            "current_signature_class": "pointer_corruption",
            "current_root_cause_class": None,
            "step_count": 8,
            "messages": [HumanMessage(content="sym ffffffff81000000")],
        }
        recent_no_signal = "sym ffffffff81000000"
        self.assertNotIn(
            DRIVER_OBJECT_OVERLAY,
            _select_context_overlays(state_no_signal, recent_no_signal),
        )
        self.assertEqual(
            _select_sop_fragments(state_no_signal, recent_no_signal),
            [],
        )

        # Concrete driver signal ('mod -s' / '_base_') triggers DRIVER_OBJECT_OVERLAY without duplicate SOP
        recent_with_signal = "mod -s mpt3sas /usr/lib/debug/mpt3sas.ko.debug"
        self.assertIn(
            DRIVER_OBJECT_OVERLAY,
            _select_context_overlays(state_no_signal, recent_with_signal),
        )
        self.assertEqual(
            _select_sop_fragments(state_no_signal, recent_with_signal),
            [],
        )

    def test_repeated_value_conflict_renders_compact_residual(self) -> None:
        from src.react.consistency import MAX_VALUE_CONFLICT_AUDIT_INJECTIONS
        from src.react.prompt_builder import _format_value_conflicts

        fact = (
            "conflict:object_does_not_match_type:irqaction@0xff292187ae124a80:"
            "next@0x18=0x12,thread_fn@0x20=0x5c"
        )
        full = _format_value_conflicts([fact], {fact: 1})
        self.assertIn("next@0x18=0x12", full[0])

        compact = _format_value_conflicts(
            [fact], {fact: MAX_VALUE_CONFLICT_AUDIT_INJECTIONS + 1}
        )
        self.assertIn("already audited", compact[0])
        self.assertNotIn("next@0x18=0x12", compact[0])

    def test_dmesg_rule_distinguishes_payload_provenance_from_dma_writer(self) -> None:
        from src.react.prompt_overlays import DRIVER_OBJECT_OVERLAY
        from src.react.sop_fragments import SOP_FRAGMENTS

        self.assertIn("confirmed payload provenance", DRIVER_OBJECT_OVERLAY)
        self.assertIn("mpt3sas_base_get_reply_virt_addr", DRIVER_OBJECT_OVERLAY)
        self.assertIn("ioc->reply_dma_min_address", DRIVER_OBJECT_OVERLAY)
        self.assertIn("Sub-step C2", SOP_FRAGMENTS["dma_corruption"])
        self.assertIn("reply_dma_min_address", SOP_FRAGMENTS["dma_corruption"])

    def test_protocol_candidate_routes_to_dma_sop(self) -> None:
        from src.react.prompt_builder import _select_sop_fragments
        from src.react.sop_fragments import SOP_FRAGMENTS

        state_with_candidate = {
            "current_signature_class": "pointer_corruption",
            "current_root_cause_class": None,
            "step_count": 26,
            "messages": [],
            "evidence_facts": [
                "rd_ascii:0xff292187ae125ab0=sense pool",
                "vtop_phys:0xff292187ae124a80=0x12e124a80",
            ],
        }

        fragments = _select_sop_fragments(
            state_with_candidate, "rd -x ff292187ae125ab0 2"
        )

        self.assertIn(SOP_FRAGMENTS["dma_corruption"], fragments)

    def test_reply_helper_routes_to_dma_sop(self) -> None:
        from src.react.prompt_builder import _select_sop_fragments
        from src.react.sop_fragments import SOP_FRAGMENTS

        state = {
            "current_signature_class": "pointer_corruption",
            "current_root_cause_class": None,
            "step_count": 26,
            "messages": [],
        }
        fragments = _select_sop_fragments(
            state,
            "call 0xffffffffc21598f0 <mpt3sas_base_get_reply_virt_addr>",
        )
        self.assertIn(SOP_FRAGMENTS["dma_corruption"], fragments)

    def test_no_menu_without_replan(self) -> None:
        rendered = _render(
            current_signature_class="null_deref",
            current_root_cause_class=None,
            managed_gates=OPEN_GATE,
            current_evidence_goal={"goal_id": "register_provenance"},
            last_action_status="executed",
            duplicate_streak=0,
            no_progress_streak=0,
            replan_required=False,
            evidence_facts=["rd_word:0x1=0x2"],
        )
        for marker in MENU_MARKERS:
            self.assertNotIn(marker, rendered)
        self.assertIn(
            "Current gate objective: close register_provenance by tracing the bad register back",
            rendered,
        )

    def test_known_root_cause_steers_to_termination(self) -> None:
        """L1：根因已定且门控全关时，提示词只能剩下"本轮收尾"这一个指令。

        原先只把"prefer terminating"与转向菜单并列输出，同一份提示词里
        "继续换方向探测"与"立即收尾"互相矛盾；run D 中模型跟随后者失败，
        收尾轮被 rd 探测占掉，tool_calls 被剥掉后整轮作废。
        """
        rendered = _render(
            current_signature_class="null_deref",
            current_root_cause_class="use_after_free",
            managed_gates=CLOSED_GATE,
            current_evidence_goal=None,
            last_action_status="executed",
            duplicate_streak=0,
            no_progress_streak=1,
            replan_required=True,
            evidence_facts=ALL_DIMENSION_FACTS,
        )
        self.assertIn("TERMINATE ON THIS TURN", rendered)
        self.assertIn("is NOT a prerequisite for concluding", rendered)
        self.assertIn(
            "terminate on this turn by emitting the final JSON conclusion", rendered
        )
        self.assertNotIn("root_cause_class is still unset", rendered)
        # 转向菜单必须被压制，否则又构成"继续探索"的竞争指令
        self.assertNotIn("Untapped evidence dimensions", rendered)
        self.assertNotIn("All four structured evidence dimensions", rendered)
        self.assertNotIn("Pivot requirement", rendered)
        self.assertNotIn("prefer terminating with your conclusion", rendered)

    def test_root_cause_with_open_gate_still_offers_pivot(self) -> None:
        """根因已定但门控未全关时不能要求收尾，仍保留转向方向。"""
        rendered = _render(
            current_signature_class="null_deref",
            current_root_cause_class="use_after_free",
            managed_gates=OPEN_GATE,
            current_evidence_goal={"goal_id": "register_provenance"},
            last_action_status="rejected",
            duplicate_streak=0,
            no_progress_streak=2,
            replan_required=True,
            evidence_facts=["rd_word:0x1=0x2"],
        )
        self.assertIn("prefer terminating with your conclusion", rendered)
        self.assertNotIn("TERMINATE ON THIS TURN", rendered)
        self.assertIn("Untapped evidence dimensions", rendered)
        self.assertIn("Pivot requirement", rendered)

    def test_unregistered_gates_never_trigger_terminate_only(self) -> None:
        """门控尚未注册（None/{}）时不得声称"每个强制门控都已关闭"。"""
        for unregistered in (None, {}):
            with self.subTest(managed_gates=unregistered):
                rendered = _render(
                    current_signature_class="null_deref",
                    current_root_cause_class="use_after_free",
                    managed_gates=unregistered,
                    current_evidence_goal=None,
                    last_action_status="rejected",
                    duplicate_streak=0,
                    no_progress_streak=2,
                    replan_required=True,
                    evidence_facts=["rd_word:0x1=0x2"],
                )
                self.assertNotIn("TERMINATE ON THIS TURN", rendered)
                self.assertIn("Pivot requirement", rendered)

    def test_open_gate_replan_never_claims_gates_closed(self) -> None:
        """C1 的 DEDUP-BLOCKED 走 rejected 分支时门控可能仍未关闭。"""
        rendered = _render(
            current_signature_class="null_deref",
            current_root_cause_class=None,
            managed_gates=OPEN_GATE,
            current_evidence_goal={"goal_id": "register_provenance"},
            last_action_status="rejected",
            duplicate_streak=0,
            no_progress_streak=1,
            replan_required=True,
            evidence_facts=[],
        )
        self.assertNotIn("Gate closure is not root-cause proof", rendered)
        self.assertIn("Mandatory gates are still unresolved", rendered)
        self.assertIn(
            "Current gate objective: close register_provenance by tracing",
            rendered,
        )

    def test_open_optional_gate_is_not_a_probe_objective(self) -> None:
        gates = {
            name: GateEntry(
                status="closed",
                evidence="executor-verified",
                required_for=["pointer_corruption"],
                closure_basis="executor_evidence",
            )
            for name in (
                "register_provenance",
                "object_lifetime",
                "local_corruption_exclusion",
            )
        }
        gates["external_corruption_gate"] = GateEntry(
            status="open",
            required_for=["pointer_corruption"],
        )
        rendered = _render(
            current_signature_class="pointer_corruption",
            current_root_cause_class=None,
            managed_gates=gates,
            current_evidence_goal=None,
            last_action_status="executed",
            duplicate_streak=0,
            no_progress_streak=0,
            replan_required=False,
            evidence_facts=ALL_DIMENSION_FACTS,
        )
        self.assertIn("Current gate objective: no outstanding gate", rendered)
        self.assertIn("Unresolved mandatory gates: none", rendered)
        self.assertIn("external_corruption_gate=open (optional; advisory only)", rendered)
        self.assertNotIn("advance external_corruption_gate", rendered)
        self.assertIn("Stage 6: convergence and bounded conclusion", rendered)
        self.assertNotIn("external_corruption_gate still pending", rendered)

    def test_telemetry_only_required_gate_does_not_invite_repeated_probing(self) -> None:
        # warn_on 的必需门控尚无确定性闭合规则，属于 telemetry-only。
        gates = {
            "warning_site": GateEntry(
                status="open",
                required_for=["warn_on"],
            ),
            "warning_timeline": GateEntry(
                status="closed",
                closure_basis="executor_evidence",
                required_for=["warn_on"],
            ),
        }
        rendered = _render(
            current_signature_class="warn_on",
            current_root_cause_class=None,
            managed_gates=gates,
            current_evidence_goal=None,
            last_action_status="executed",
            duplicate_streak=0,
            no_progress_streak=0,
            replan_required=False,
            evidence_facts=[],
        )
        self.assertIn("warning_site is telemetry-only", rendered)
        self.assertIn("Do not keep probing solely to close this gate", rendered)
        self.assertIn("result remains non-conclusive", rendered)

    def test_unregistered_gates_never_claim_gates_closed(self) -> None:
        """门控集合尚未注册时，`_format_unresolved_gates` 同样返回 "none"。

        这表示"没有门控"，而非"门控已全部关闭"。早期步或
        `_build_managed_gates` 返回 None 时会走到这里，若误判为门控穷尽，
        就会把"每个强制门控都已关闭"这条错误事实注入提示词。
        """
        for unregistered in (None, {}):
            with self.subTest(managed_gates=unregistered):
                rendered = _render(
                    current_signature_class="null_deref",
                    current_root_cause_class=None,
                    managed_gates=unregistered,
                    current_evidence_goal=None,
                    last_action_status="rejected",
                    duplicate_streak=0,
                    no_progress_streak=1,
                    replan_required=True,
                    evidence_facts=["rd_word:0x1=0x2"],
                )
                self.assertNotIn("Gate closure is not root-cause proof", rendered)
                self.assertNotIn("every mandatory gate", rendered)
                self.assertIn("Mandatory gates are still unresolved", rendered)

    def test_unclassified_signature_is_not_presented_as_gate_exhaustion(self) -> None:
        rendered = _render(
            current_signature_class="unknown",
            current_root_cause_class="pointer_corruption",
            managed_gates=None,
            current_evidence_goal=None,
            last_action_status="rejected",
            duplicate_streak=0,
            no_progress_streak=2,
            replan_required=True,
            evidence_facts=[],
        )
        self.assertIn("no registered policy, conclusion prohibited", rendered)
        self.assertIn("no gate policy is registered", rendered)
        self.assertNotIn("all mandatory gates are closed", rendered)

    def test_untapped_dimensions_exclude_observed_ones(self) -> None:
        rendered = _render(
            current_signature_class="pointer_corruption",
            current_root_cause_class=None,
            managed_gates=CLOSED_GATE,
            current_evidence_goal=None,
            last_action_status="duplicate",
            duplicate_streak=3,
            no_progress_streak=3,
            replan_required=True,
            evidence_facts=["rd_word:0x1=0x2", "dis_symbol:show_interrupts"],
        )
        self.assertIn("Untapped evidence dimensions", rendered)
        self.assertIn("struct -o <type>", rendered)
        self.assertIn("sym <address>", rendered)
        self.assertNotIn("`rd <address> <count>`", rendered)
        self.assertNotIn("dis -rl <symbol>", rendered)

    def test_unknown_root_cause_never_claims_conclusion(self) -> None:
        """P0-2：`current_root_cause_class="unknown"` 表示尚未定论。

        `unknown` 是 RootCauseClass 的合法成员，`bool("unknown")` 为 True；
        若按真值判断，门控全关时会输出 "TERMINATE ON THIS TURN: root_cause_class=unknown
        is set"，等于告诉模型一个不存在的结论已经成立。
        """
        rendered = _render(
            current_signature_class="null_deref",
            current_root_cause_class="unknown",
            managed_gates=CLOSED_GATE,
            current_evidence_goal=None,
            last_action_status="rejected",
            duplicate_streak=0,
            no_progress_streak=1,
            replan_required=True,
            evidence_facts=["rd_word:0x1=0x2"],
        )
        self.assertNotIn("TERMINATE ON THIS TURN", rendered)
        self.assertNotIn("prefer terminating with your conclusion", rendered)
        self.assertIn("root_cause_class is still unset", rendered)

    def test_no_progress_spin_offers_forced_choice_without_root_cause(self) -> None:
        """P0-1：空转时提示词必须给出"提交结论 / 声明新取证目标"的二选一。"""
        rendered = _render(
            current_signature_class="null_deref",
            current_root_cause_class=None,
            managed_gates=CLOSED_GATE,
            current_evidence_goal=None,
            last_action_status="rejected",
            duplicate_streak=0,
            no_progress_streak=CONVERGENCE_GUARD_STREAK_THRESHOLD,
            replan_required=True,
            evidence_facts=ALL_DIMENSION_FACTS,
        )
        self.assertIn("COMMIT A CONCLUSION", rendered)
        self.assertIn("DECLARE A NEW EVIDENCE TARGET", rendered)
        self.assertIn("Re-reading the same bytes cannot produce new evidence", rendered)

    def test_forced_choice_suppressed_once_root_cause_committed(self) -> None:
        """已提交根因时走 TERMINATE 通道，不再并列二选一，避免自相矛盾。"""
        rendered = _render(
            current_signature_class="null_deref",
            current_root_cause_class="use_after_free",
            managed_gates=CLOSED_GATE,
            current_evidence_goal=None,
            last_action_status="rejected",
            duplicate_streak=0,
            no_progress_streak=CONVERGENCE_GUARD_STREAK_THRESHOLD,
            replan_required=True,
            evidence_facts=ALL_DIMENSION_FACTS,
        )
        self.assertIn("TERMINATE ON THIS TURN", rendered)
        self.assertNotIn("COMMIT A CONCLUSION", rendered)

    def test_forced_choice_suppressed_below_streak_threshold(self) -> None:
        rendered = _render(
            current_signature_class="null_deref",
            current_root_cause_class=None,
            managed_gates=CLOSED_GATE,
            current_evidence_goal=None,
            last_action_status="rejected",
            duplicate_streak=0,
            no_progress_streak=CONVERGENCE_GUARD_STREAK_THRESHOLD - 1,
            replan_required=True,
            evidence_facts=["rd_word:0x1=0x2"],
        )
        self.assertNotIn("COMMIT A CONCLUSION", rendered)

    def test_malformed_evidence_facts_are_tolerated(self) -> None:
        for facts in (None, "notalist", [None, 42, "rd_word:0x1=0x2"]):
            with self.subTest(evidence_facts=facts):
                rendered = _render(
                    current_signature_class="null_deref",
                    current_root_cause_class=None,
                    managed_gates=CLOSED_GATE,
                    current_evidence_goal=None,
                    last_action_status="duplicate",
                    duplicate_streak=1,
                    no_progress_streak=1,
                    replan_required=True,
                    evidence_facts=facts,
                )
                self.assertIn("Pivot requirement", rendered)



LOCK_HANG_DMESG_LINE = (
    "INFO: task kworker/3:1:4321 blocked for more than 120 seconds.\n"
)


def _long_initial_message(signal_line: str) -> str:
    # 模拟真实初始消息：dmesg 位于 sys / sys -t / bt 之后，远超 800 字符截断窗口。
    return ("# Initial Context\n" + "sys / bt output line\n" * 120) + signal_line


class LockHangFastPathTests(unittest.TestCase):
    def test_layer0_lists_analyzers_before_extension_commands(self) -> None:
        from src.react.layer0_system import LAYER0_SYSTEM_PROMPT_TEMPLATE as L0

        new_section = L0.index("## 3.7a Deterministic Lock / Hang Analyzers")
        self.assertLess(new_section, L0.index("## 3.8 Extended Commands"))
        self.assertLess(new_section, L0.index("**hanginfo**"))
        self.assertIn("analyze_lock_wait_graph", L0)
        self.assertIn("analyze_cpu_lockup_rcu", L0)
        self.assertIn("--rcu-pids", L0)
        # hanginfo 不再与 lock_hang 争抢唯一 FIRST
        self.assertNotIn("**hanginfo**: Use as the FIRST command", L0)
        self.assertNotIn("bt -f <pid>", L0)
        # 模板仍可被 str.format 正常渲染（新增文本不得引入花括号）
        L0.format(VMCoreAnalysisStep_Schema="{}")

    def test_playbooks_put_analyzer_before_manual_commands(self) -> None:
        from src.react.playbooks import PLAYBOOKS

        hung = PLAYBOOKS["hung_task"]
        self.assertIn("Mandatory Fast Path", hung)
        self.assertLess(hung.index("analyze_lock_wait_graph"), hung.index("foreach UN bt"))
        for sig in ("soft_lockup", "hard_lockup"):
            with self.subTest(signature=sig):
                book = PLAYBOOKS[sig]
                self.assertIn("Mandatory Fast Path", book)
                self.assertLess(book.index("analyze_cpu_lockup_rcu"), book.index("bt -a"))
        for sig in ("hung_task", "soft_lockup", "hard_lockup"):
            self.assertNotIn("bt -f <pid>", PLAYBOOKS[sig])

    def test_sop_injected_on_first_turn_despite_recent_text_truncation(self) -> None:
        from langchain_core.messages import HumanMessage
        from src.react.prompt_builder import _recent_text_blob, _select_sop_fragments
        from src.react.sop_fragments import SOP_FRAGMENTS

        messages = [HumanMessage(content=_long_initial_message(LOCK_HANG_DMESG_LINE))]
        recent = _recent_text_blob(messages)
        # 前置条件：关键行确实被 800 字符截断窗口裁掉
        self.assertNotIn("blocked for more than", recent.lower())
        state = {
            "current_signature_class": None,
            "current_root_cause_class": None,
            "step_count": 0,
            "messages": messages,
        }
        self.assertIn(SOP_FRAGMENTS["lock_hang_fast_path"], _select_sop_fragments(state, recent))

    def test_sop_detects_each_strong_signal(self) -> None:
        from langchain_core.messages import HumanMessage
        from src.react.prompt_builder import _recent_text_blob, _select_sop_fragments
        from src.react.sop_fragments import SOP_FRAGMENTS

        lines = (
            "watchdog: BUG: soft lockup - CPU#3 stuck for 22s! [insmod:1234]\n",
            "NMI watchdog: Watchdog detected hard LOCKUP on cpu 5\n",
            "rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:\n",
            "rcu: INFO: rcu_sched self-detected stall on CPU\n",
            "Kernel panic - not syncing: hung_task: blocked tasks\n",
        )
        for line in lines:
            with self.subTest(line=line):
                messages = [HumanMessage(content=_long_initial_message(line))]
                state = {
                    "current_signature_class": None,
                    "step_count": 0,
                    "messages": messages,
                }
                self.assertIn(
                    SOP_FRAGMENTS["lock_hang_fast_path"],
                    _select_sop_fragments(state, _recent_text_blob(messages)),
                )

    def test_sop_not_duplicated_when_lock_hang_playbook_active(self) -> None:
        from langchain_core.messages import HumanMessage
        from src.react.prompt_builder import _recent_text_blob, _select_sop_fragments
        from src.react.sop_fragments import SOP_FRAGMENTS

        messages = [HumanMessage(content=_long_initial_message(LOCK_HANG_DMESG_LINE))]
        for sig in ("hung_task", "soft_lockup", "hard_lockup", "rcu_stall"):
            with self.subTest(signature=sig):
                state = {
                    "current_signature_class": sig,
                    "step_count": 4,
                    "messages": messages,
                }
                self.assertNotIn(
                    SOP_FRAGMENTS["lock_hang_fast_path"],
                    _select_sop_fragments(state, _recent_text_blob(messages)),
                )

    def test_sop_retires_once_non_lock_signature_is_classified(self) -> None:
        # 评审回归：初始 dmesg 残留历史锁/挂死日志时，非锁类签名落定后兜底 SOP 必须退场
        from langchain_core.messages import HumanMessage
        from src.react.prompt_builder import _recent_text_blob, _select_sop_fragments
        from src.react.sop_fragments import SOP_FRAGMENTS

        messages = [HumanMessage(content=_long_initial_message(LOCK_HANG_DMESG_LINE))]
        for sig in ("pointer_corruption", "null_deref", "stack_corruption", "bug_on"):
            with self.subTest(signature=sig):
                state = {
                    "current_signature_class": sig,
                    "step_count": 6,
                    "messages": messages,
                }
                self.assertNotIn(
                    SOP_FRAGMENTS["lock_hang_fast_path"],
                    _select_sop_fragments(state, _recent_text_blob(messages)),
                )

    def test_sop_injected_for_unknown_or_empty_signature(self) -> None:
        from langchain_core.messages import HumanMessage
        from src.react.prompt_builder import _recent_text_blob, _select_sop_fragments
        from src.react.sop_fragments import SOP_FRAGMENTS

        messages = [HumanMessage(content=_long_initial_message(LOCK_HANG_DMESG_LINE))]
        for sig in ("unknown", ""):
            with self.subTest(signature=sig):
                state = {
                    "current_signature_class": sig,
                    "step_count": 2,
                    "messages": messages,
                }
                self.assertIn(
                    SOP_FRAGMENTS["lock_hang_fast_path"],
                    _select_sop_fragments(state, _recent_text_blob(messages)),
                )

    def test_sop_not_injected_without_strong_signal(self) -> None:
        from langchain_core.messages import HumanMessage
        from src.react.prompt_builder import _recent_text_blob, _select_sop_fragments
        from src.react.sop_fragments import SOP_FRAGMENTS

        # 弱信号（__mutex_lock 出现在栈中）不应触发兜底 SOP
        messages = [
            HumanMessage(content=_long_initial_message(" #3 [ffffb] __mutex_lock at ffffffff81a0\n"))
        ]
        state = {
            "current_signature_class": "pointer_corruption",
            "step_count": 4,
            "messages": messages,
        }
        self.assertNotIn(
            SOP_FRAGMENTS["lock_hang_fast_path"],
            _select_sop_fragments(state, _recent_text_blob(messages)),
        )

    def test_sop_fragment_syntax_matches_tool_contract(self) -> None:
        from src.react.sop_fragments import SOP_FRAGMENTS

        sop = SOP_FRAGMENTS["lock_hang_fast_path"]
        self.assertIn("--rcu-pids", sop)
        self.assertIn("bt -f <task_addr>", sop)
        self.assertNotIn("bt -f <pid>", sop)



class SelectPlaybookInitialContextTests(unittest.TestCase):
    RCU_LINE = "rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:\n"

    def _state(self, signature, content):
        from langchain_core.messages import HumanMessage

        return {
            "current_signature_class": signature,
            "step_count": 0,
            "messages": [HumanMessage(content=content)],
        }

    def test_rcu_playbook_mounted_on_first_turn_despite_truncation(self) -> None:
        from src.react.playbooks import PLAYBOOKS
        from src.react.prompt_builder import _recent_text_blob, _select_playbook

        for sig in (None, "", "unknown"):
            with self.subTest(signature=sig):
                state = self._state(sig, _long_initial_message(self.RCU_LINE))
                recent = _recent_text_blob(state["messages"])
                # 前置条件：关键行确实被 800 字符截断窗口裁掉
                self.assertNotIn("detected stalls on cpus/tasks", recent.lower())
                self.assertEqual(_select_playbook(state, recent), PLAYBOOKS["rcu_stall"])

    def test_no_playbook_without_rcu_signal_when_unclassified(self) -> None:
        from src.react.prompt_builder import _recent_text_blob, _select_playbook

        state = self._state(None, _long_initial_message("ordinary dmesg line\n"))
        self.assertEqual(_select_playbook(state, _recent_text_blob(state["messages"])), "")

    def test_classified_signature_ignores_residual_rcu_line(self) -> None:
        from src.react.playbooks import PLAYBOOKS
        from src.react.prompt_builder import _recent_text_blob, _select_playbook

        state = self._state("pointer_corruption", _long_initial_message(self.RCU_LINE))
        self.assertEqual(
            _select_playbook(state, _recent_text_blob(state["messages"])),
            PLAYBOOKS["pointer_corruption"],
        )



class TerminateExemptionTests(unittest.TestCase):
    """收尾豁免：只对 tool_error 和"源码可读但 0 SOURCE_REF"生效，且各自只触发一次。"""

    def _ready(self, **overrides):
        state = dict(
            current_signature_class="null_deref",
            current_root_cause_class="use_after_free",
            managed_gates=CLOSED_GATE,
            current_evidence_goal=None,
            last_action_status="executed",
            duplicate_streak=0,
            no_progress_streak=1,
            replan_required=True,
            evidence_facts=ALL_DIMENSION_FACTS,
        )
        state.update(overrides)
        return state

    def _assert_no_terminate_channel(self, rendered: str) -> None:
        # 三处收尾通道都必须让位：菜单、状态段、门控目标行
        self.assertNotIn("TERMINATE ON THIS TURN", rendered)
        self.assertNotIn("terminate on this turn by emitting the final JSON conclusion", rendered)
        self.assertNotIn("the only remaining objective is to emit the final conclusion", rendered)

    def test_tool_error_gets_one_retry(self) -> None:
        rendered = _render(**self._ready(last_action_status="tool_error"))
        self.assertIn("RETRY AFTER TOOL ERROR", rendered)
        self.assertIn("retry the failed tool call ONCE", rendered)
        self._assert_no_terminate_channel(rendered)

    def test_tool_error_retry_is_one_shot(self) -> None:
        rendered = _render(
            **self._ready(last_action_status="tool_error", tool_error_retry_used=True)
        )
        self.assertIn("TERMINATE ON THIS TURN", rendered)

    def test_guard_rejections_do_not_suspend_termination(self) -> None:
        # dedup / convergence-guard 的 rejected 是防空转护栏，不能被豁免 A 解除
        rendered = _render(**self._ready(last_action_status="rejected"))
        self.assertIn("TERMINATE ON THIS TURN", rendered)
        self.assertNotIn("RETRY AFTER TOOL ERROR", rendered)

    def test_streak_bound_disables_exemptions(self) -> None:
        rendered = _render(**self._ready(last_action_status="tool_error", no_progress_streak=3))
        self.assertNotIn("RETRY AFTER TOOL ERROR", rendered)

    def test_missing_source_ref_gets_one_citation_check(self) -> None:
        rendered = _render(**self._ready(kernel_source_root="/root/kernel-sources/x"))
        self.assertIn("SOURCE CITATION CHECK", rendered)
        self.assertIn("cite ONE SOURCE_REF", rendered)
        self._assert_no_terminate_channel(rendered)

    def test_citation_check_is_one_shot_even_if_model_ignored_it(self) -> None:
        # 发出过一次后，即使模型下一步执行的是 rd 而非 read_source，也不再触发
        rendered = _render(
            **self._ready(
                kernel_source_root="/root/kernel-sources/x",
                source_citation_retry_used=True,
            )
        )
        self.assertIn("TERMINATE ON THIS TURN", rendered)
        self.assertNotIn("SOURCE CITATION CHECK", rendered)

    def test_cited_or_unconfigured_source_terminates(self) -> None:
        cited = _render(
            **self._ready(
                kernel_source_root="/root/kernel-sources/x",
                evidence_facts=ALL_DIMENSION_FACTS + ["source_ref:kernel/rcu/tree_plugin.h:318"],
            )
        )
        self.assertIn("TERMINATE ON THIS TURN", cited)
        self.assertIn("TERMINATE ON THIS TURN", _render(**self._ready()))

    def test_issued_exemption_matches_rendering_condition(self) -> None:
        from src.react.prompt_builder import issued_terminate_exemption

        state = dict(BASE_STATE, **self._ready(last_action_status="tool_error"))
        self.assertEqual(issued_terminate_exemption(state), "tool_error_retry")
        state["replan_required"] = False
        self.assertIsNone(issued_terminate_exemption(state))

    def test_non_payload_signature_terminate_text(self) -> None:
        from src.react.schema import required_gates_for

        gates = {
            name: GateEntry(
                status="closed",
                evidence="executor facts",
                required_for=["rcu_stall"],
                closure_basis="executor_evidence",
            )
            for name in (required_gates_for("rcu_stall") or [])
        }
        rendered = _render(
            **self._ready(
                current_signature_class="rcu_stall",
                current_root_cause_class="rcu_misuse",
                managed_gates=gates,
            )
        )
        self.assertIn("TERMINATE ON THIS TURN", rendered)
        self.assertIn("Layer0 2.4", rendered)
        self.assertNotIn("overwritten scalar", rendered)
        line = next(l for l in rendered.splitlines() if "TERMINATE ON THIS TURN" in l)
        self.assertNotIn('confidence="low"', line)


class SourceCitationStatusTests(unittest.TestCase):
    def test_module_dir_counts_only_when_it_contains_sources(self) -> None:
        import tempfile

        from src.react.graph_state import source_citation_status

        with tempfile.TemporaryDirectory() as tmp:
            ko = Path(tmp) / "rcu_stall_mod.ko"
            ko.write_bytes(b"")
            state = {"debug_symbol_paths": [str(ko)]}
            self.assertEqual(source_citation_status(state), ("not_configured", 0))
            (Path(tmp) / "rcu_stall_mod.c").write_text("int x;\n", encoding="utf-8")
            self.assertEqual(source_citation_status(state), ("missing", 0))

    def test_refs_are_counted_once(self) -> None:
        from src.react.graph_state import source_citation_status

        facts = ["source_ref:a.c:1", "source_ref:a.c:1", "source_ref:b.c:2"]
        self.assertEqual(source_citation_status({"evidence_facts": facts}), ("cited", 2))



class ReportEvidenceDisciplineRuleTests(unittest.TestCase):
    """2026-11-27 21:37 报告评审的三处措辞问题对应的提示词约束。"""

    def test_layer0_contains_three_new_rules(self) -> None:
        from src.react.layer0_system import LAYER0_SYSTEM_PROMPT_TEMPLATE as L0

        self.assertIn("Truncated-stack follow-up", L0)
        self.assertIn("run that `bt -f` before emitting the final conclusion", L0)
        self.assertIn("No placeholder values", L0)
        self.assertIn("ffffffffaa42xxxx", L0)
        self.assertIn("SOURCE_REF citation scope", L0)
        self.assertIn("must be labeled as disassembly evidence", L0)
        # 模板仍可被 str.format 渲染（新规则不得引入花括号）
        L0.format(VMCoreAnalysisStep_Schema="{}")

    def test_rules_live_in_the_existing_discipline_block(self) -> None:
        from src.react.layer0_system import LAYER0_SYSTEM_PROMPT_TEMPLATE as L0

        anchor = L0.index("Configured vs. actual duration discipline")
        for marker in ("Truncated-stack follow-up", "No placeholder values", "SOURCE_REF citation scope"):
            self.assertGreater(L0.index(marker), anchor)
            self.assertLess(L0.index(marker), L0.index("## Log Query Budget"))

    def test_rcu_stall_playbook_requires_late_bt_f(self) -> None:
        from src.react.playbooks import PLAYBOOKS

        book = PLAYBOOKS["rcu_stall"]
        self.assertIn("as soon as a later analyzer run reports `waiter_bt_truncated`", book)
        self.assertIn("do not describe the waiter as blocked in `synchronize_rcu()`", book)



class FinalHygieneRuleTests(unittest.TestCase):
    """2026-11-27 22:23 报告评审：偏移进制混写、--rcu-pids 漏传 waiter、误带 --top。"""

    def test_layer0_offset_radix_rule(self) -> None:
        from src.react.layer0_system import LAYER0_SYSTEM_PROMPT_TEMPLATE as L0

        self.assertIn("Disassembly vs. backtrace offset radix", L0)
        self.assertIn("never prefix a decimal `dis` offset with `0x`", L0)
        # 与其他证据纪律规则放在一起，位于 Log Query Budget 之前
        marker = L0.index("Disassembly vs. backtrace offset radix")
        self.assertGreater(marker, L0.index("SOURCE_REF citation scope"))
        self.assertLess(marker, L0.index("## Log Query Budget"))
        L0.format(VMCoreAnalysisStep_Schema="{}")

    def test_sop_asks_for_all_rcu_pids_and_forbids_top(self) -> None:
        from src.react.sop_fragments import SOP_FRAGMENTS

        sop = SOP_FRAGMENTS["lock_hang_fast_path"]
        self.assertIn("--rcu-pids <pid1,pid2,...>", sop)
        self.assertIn("BOTH blocked RCU readers AND any `synchronize_rcu`/GP waiter PIDs", sop)
        self.assertIn("do not pass `--top`", sop)
        # 原来只写"add --rcu-pids"的措辞已被替换
        self.assertNotIn("(add `--rcu-pids", sop)
        # --top 仍是 analyze_lock_wait_graph 第 1 条里的合法示例
        self.assertIn("arguments `--top 12`", sop)


if __name__ == "__main__":
    unittest.main()
