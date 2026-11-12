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

from src.react.evidence import (
    MAX_GATE_EVIDENCE_FACTS_PER_CATEGORY,
    evaluate_gate_closures,
    extract_evidence_facts,
    extract_pinned_addresses,
    facts_support_goal,
    gate_completion_criteria,
    has_executor_closure_rule,
    update_gate_evidence,
)
from src.react.schema import GateEntry, VMCoreLLMAnalysisStep
from src.react.state_manager import _build_evidence_goal, project_managed_analysis_step


class EvidenceExtractionTests(unittest.TestCase):
    def test_extracts_facts_from_supported_commands(self) -> None:
        rd_facts = extract_evidence_facts(
            "rd",
            {"command": "rd -x ffff0000 2"},
            "ffff0000: 0000000000000010 0000000000000020  ........",
        )
        struct_facts = extract_evidence_facts(
            "struct",
            {"command": "struct irqaction ffff0000"},
            "struct irqaction {\n [0] handler\n [16] dev_id\n SIZE: 32\n}",
        )
        dis_facts = extract_evidence_facts(
            "dis",
            {"command": "dis -rl ffff0000"},
            "0xffff0000 <foo>: mov %rax,(%rbx)",
        )
        sym_facts = extract_evidence_facts(
            "sym",
            {"command": "sym -m nvidia"},
            "ffffffff81000000 T irq_handler",
        )

        self.assertIn("rd_word:0xffff0000=0x10", rd_facts)
        self.assertIn("struct_field:irqaction.handler@0x0", struct_facts)
        self.assertIn("struct_size:irqaction=0x20", struct_facts)
        self.assertIn("dis_instruction:0xffff0000=mov", dis_facts)
        self.assertIn("sym:irq_handler@0xffffffff81000000:T", sym_facts)

    def test_struct_dot_syntax_does_not_produce_layout_facts(self) -> None:
        """点号语法只打印字段值，无 struct 头/偏移行，不构成 field_type_classification 的 struct 证据。"""
        dot_facts = extract_evidence_facts(
            "struct",
            {"command": "struct device.driver ffff888100000000"},
            "  driver = 0xffffffffc0123400\n",
        )
        self.assertEqual(dot_facts, set())

    def test_run_script_collects_each_supported_command(self) -> None:
        facts = extract_evidence_facts(
            "run_script",
            {
                "script": (
                    "rd -x ffff0000 1\n"
                    "struct foo ffff0000\n"
                    "dis -rl ffff0000\n"
                    "sym -m nvidia"
                )
            },
            "ffff0000: 0000000000000001\n"
            "struct foo {\n [0] value\n SIZE: 8\n}\n"
            "0xffff0000 <foo>: ret\n"
            "ffffffff81000000 T irq_handler\n",
        )

        self.assertTrue(any(fact.startswith("rd_word:") for fact in facts))
        self.assertTrue(any(fact.startswith("struct_") for fact in facts))
        self.assertTrue(any(fact.startswith("dis_") for fact in facts))
        self.assertTrue(any(fact.startswith("sym:") for fact in facts))

    def test_direct_tools_extract_facts_from_argument_only_payloads(self) -> None:
        rd_facts = extract_evidence_facts(
            "rd",
            {"command": "-x ffffffffc09e7a89 2"},
            "crash> rd -x ffffffffc09e7a89 2\n"
            "ffffffffc09e7a89: 63000000000a7325 6d6f72665f79706f",
        )
        dis_facts = extract_evidence_facts(
            "dis",
            {"command": "-l mxlog_vprintf 2"},
            "crash> dis -l mxlog_vprintf 2\n"
            "0xffffffffc08de97c <mxlog_vprintf+60>: mov (%r9),%rax",
        )

        self.assertIn("rd_word:0xffffffffc09e7a89=0x63000000000a7325", rd_facts)
        self.assertIn("dis_instruction:0xffffffffc08de97c=mov", dis_facts)

    def test_extracts_mapping_and_vmalloc_facts(self) -> None:
        vtop_facts = extract_evidence_facts(
            "vtop",
            {"command": "ffffb2709a1ac000"},
            "ffffb2709a1ac000  (not mapped)\nPTE: 118ea7d60 => 0",
        )
        kmem_facts = extract_evidence_facts(
            "kmem",
            {"command": "-v"},
            "ffff959a401549a0 ffff959a40003fc0 "
            "ffffb27080000000 - ffffb27080002000     8192",
        )

        self.assertIn("vtop_unmapped:0xffffb2709a1ac000", vtop_facts)
        self.assertIn("vtop_pte:0x0", vtop_facts)
        self.assertIn(
            "kmem_vmap_range:0xffffb27080000000-0xffffb27080002000=0x2000",
            kmem_facts,
        )

    def test_extracts_mapped_physical_address_and_ascii_string(self) -> None:
        vtop_facts = extract_evidence_facts(
            "vtop",
            {"command": "ff292187ae124a80"},
            "VIRTUAL           PHYSICAL\n"
            "ff292187ae124a80  12e124a80\n"
            "PTE: 1f4405920 => 800000012e124163\n",
        )
        rd_facts = extract_evidence_facts(
            "rd",
            {"command": "rd -x ff292187ae125ab0 2"},
            "ff292187ae125ab0: 6f702065736e6573 fe52cb0bb9006c6f  sense po\n",
        )

        self.assertIn(
            "vtop_phys:0xff292187ae124a80=0x12e124a80", vtop_facts
        )
        self.assertIn(
            "rd_ascii:0xff292187ae125ab0=sense pool", rd_facts
        )

    def test_mapping_facts_support_lifetime_and_local_exclusion(self) -> None:
        facts = extract_evidence_facts(
            "vtop",
            {"command": "ffffb2709a1ac000"},
            "ffffb2709a1ac000  (not mapped)",
        )

        self.assertFalse(facts_support_goal(facts, {"gate_name": "object_lifetime"}))
        self.assertTrue(
            facts_support_goal(facts, {"gate_name": "local_corruption_exclusion"})
        )

    def test_kasan_uaf_report_without_address_is_telemetry_only(self) -> None:
        facts = extract_evidence_facts(
            "run_script",
            {"script": "log -m | grep -i KASAN"},
            "BUG: KASAN: use-after-free in example+0x10/0x20\n"
            "Freed by task 12:\n"
            "Allocated by task 13:\n",
        )

        self.assertIn("lifetime_signal:kasan_use_after_free_unbound", facts)
        self.assertFalse(facts_support_goal(facts, {"gate_name": "object_lifetime"}))

        gate = GateEntry(required_for=["use_after_free"], status="open")
        evaluated, _ = evaluate_gate_closures({"object_lifetime": gate}, facts)
        self.assertEqual(evaluated["object_lifetime"].status, "open")

    def test_object_lifetime_gate_requires_snapshot_or_temporal_evidence(self) -> None:
        gate = GateEntry(
            required_for=["pointer_corruption"],
            status="open",
        )
        observations = {
            "rd_word:0xffff0000=0x10",
            "struct_type:irqaction",
        }

        evaluated, _ = evaluate_gate_closures(
            {"object_lifetime": gate}, observations
        )
        self.assertEqual(evaluated["object_lifetime"].status, "open")

        evaluated, _ = evaluate_gate_closures(
            {"object_lifetime": gate},
            observations | {"kmem_slab_state:0xffff0000=allocated"},
        )
        self.assertEqual(evaluated["object_lifetime"].status, "closed")

        evaluated, _ = evaluate_gate_closures(
            {"object_lifetime": gate},
            observations | {"kmem_slab_state:0xffff0080=allocated"},
        )
        self.assertEqual(evaluated["object_lifetime"].status, "open")

        evaluated, _ = evaluate_gate_closures(
            {"object_lifetime": gate},
            observations | {"lifetime_proof:kasan_use_after_free"},
        )
        self.assertEqual(evaluated["object_lifetime"].status, "open")

    def test_page_not_present_lifetime_gate_requires_mapping_lifetime_evidence(self) -> None:
        gate = GateEntry(
            required_for=["page_not_present"],
            status="open",
        )
        facts = {
            "vtop_unmapped:0xffffb2709a1ac000",
            "rd_word:0xffffb2709a1ac000=0x1",
            "kmem_slab_state:0xffffb2709a1ac000=allocated",
        }

        evaluated, transitions = evaluate_gate_closures(
            {"object_lifetime": gate}, facts
        )

        self.assertEqual(evaluated["object_lifetime"].status, "open")
        self.assertIn(
            "the executor currently has no closure rule for this signature-specific gate; "
            "address-linked mapping teardown or lifetime evidence extraction is not implemented",
            evaluated["object_lifetime"].completion_criteria,
        )
        self.assertTrue(
            any(item["event"] == "weak_gate_closure" for item in transitions)
        )

    def test_extracts_current_kmem_slot_states(self) -> None:
        facts = extract_evidence_facts(
            "kmem",
            {"command": "kmem -S ffff0000"},
            "FREE / [ALLOCATED]\n"
            "ffff0000\n"
            "  [ffff0080]\n",
        )

        self.assertIn("kmem_slab_state:0xffff0000=free", facts)
        self.assertIn("kmem_slab_state:0xffff0080=allocated", facts)
        self.assertTrue(facts_support_goal(facts, {"gate_name": "object_lifetime"}))
        self.assertNotIn("lifetime_proof:kasan_use_after_free", facts)

    def test_gate_progress_uses_fact_set_difference(self) -> None:
        prior = {"rd_word:0xffff0000=0x10"}
        current = prior | {"struct_field:irqaction.handler@0x0"}
        delta = current - prior
        goal = {"gate_name": "field_type_classification"}
        gates = {
            "field_type_classification": GateEntry(
                required_for=["pointer_corruption"], status="open"
            )
        }
        updated = update_gate_evidence(gates, delta)

        self.assertEqual(delta, {"struct_field:irqaction.handler@0x0"})
        self.assertTrue(facts_support_goal(delta, goal))
        self.assertIn(
            "[evidence-delta] struct_field:irqaction.handler@0x0",
            updated["field_type_classification"].evidence,
        )
        self.assertEqual(updated["field_type_classification"].status, "open")

    def test_llm_close_is_rejected_without_completion_evidence(self) -> None:
        gates = {
            "register_provenance": GateEntry(
                required_for=["pointer_corruption"],
                status="closed",
                evidence="LLM claimed the register chain is complete.",
            )
        }

        evaluated, transitions = evaluate_gate_closures(gates, [])

        self.assertEqual(evaluated["register_provenance"].status, "open")
        self.assertTrue(
            any(item["event"] == "llm_close_rejected" for item in transitions)
        )
        self.assertEqual(len(evaluated["register_provenance"].completion_criteria), 3)

    def test_llm_na_is_rejected_and_claim_is_audited(self) -> None:
        gate = GateEntry(
            required_for=["use_after_free"],
            status="n/a",
            evidence="The model says the gate does not apply.",
        )

        evaluated, transitions = evaluate_gate_closures(
            {"object_lifetime": gate}, []
        )

        self.assertEqual(evaluated["object_lifetime"].status, "open")
        self.assertIsNone(evaluated["object_lifetime"].closure_basis)
        rejected = [item for item in transitions if item["event"] == "llm_na_rejected"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(
            rejected[0]["requested_evidence"],
            "The model says the gate does not apply.",
        )

        legacy_prior = GateEntry(
            required_for=["use_after_free"],
            status="n/a",
            evidence="Unverified legacy claim.",
        )
        evaluated, _ = evaluate_gate_closures(
            {"object_lifetime": gate},
            [],
            {"object_lifetime": legacy_prior},
        )
        self.assertEqual(evaluated["object_lifetime"].status, "open")

        executor_prior = GateEntry(
            required_for=["use_after_free"],
            status="n/a",
            evidence="Executor applicability rule verified.",
            closure_basis="executor_na",
        )
        evaluated, transitions = evaluate_gate_closures(
            {"object_lifetime": gate},
            [],
            {"object_lifetime": executor_prior},
        )
        self.assertEqual(evaluated["object_lifetime"].status, "n/a")
        self.assertFalse(
            any(item["event"] == "llm_na_rejected" for item in transitions)
        )

    def test_unsupported_gate_facts_are_telemetry_not_closure(self) -> None:
        gate = GateEntry(required_for=["soft_lockup"], status="open")

        evaluated, transitions = evaluate_gate_closures(
            {"lock_holder": gate}, {"rd_word:0xffff0000=0x1"}
        )

        self.assertEqual(evaluated["lock_holder"].status, "open")
        self.assertTrue(
            any(item["event"] == "weak_gate_closure" for item in transitions)
        )

    def test_evidence_goal_skips_telemetry_only_and_optional_gates(self) -> None:
        telemetry_only = {
            "stack_integrity": GateEntry(
                required_for=["soft_lockup"], status="open"
            ),
            "lock_holder": GateEntry(required_for=["soft_lockup"], status="open"),
        }
        self.assertIsNone(_build_evidence_goal(telemetry_only, "soft_lockup"))

        optional_only = {
            "register_provenance": GateEntry(
                required_for=["pointer_corruption"],
                status="closed",
                closure_basis="executor_evidence",
            ),
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"],
                status="closed",
                closure_basis="executor_evidence",
            ),
            "local_corruption_exclusion": GateEntry(
                required_for=["pointer_corruption"],
                status="closed",
                closure_basis="executor_evidence",
            ),
            "external_corruption_gate": GateEntry(
                required_for=["pointer_corruption"], status="open"
            ),
        }
        self.assertIsNone(_build_evidence_goal(optional_only, "pointer_corruption"))

    def test_external_gate_requires_an_external_source_fact(self) -> None:
        gates = {
            "local_corruption_exclusion": GateEntry(
                required_for=["pointer_corruption"],
                status="closed",
                closure_basis="executor_evidence",
            ),
            "external_corruption_gate": GateEntry(
                required_for=["pointer_corruption"], status="open"
            ),
        }

        evaluated, _ = evaluate_gate_closures(
            gates,
            {
                "rd_word:0xffff0000=0x1",
                "struct_type:device_private",
            },
            gates,
        )

        self.assertEqual(evaluated["external_corruption_gate"].status, "open")

    def test_external_gate_has_no_executor_closure_rule_yet(self) -> None:
        # 规则已定义，但 external_source 事实抽取尚未实现，因此当前不应声称可闭合。
        self.assertFalse(has_executor_closure_rule("external_corruption_gate"))
        self.assertTrue(has_executor_closure_rule("local_corruption_exclusion"))

    def test_llm_cannot_supply_executor_closure_basis(self) -> None:
        step = VMCoreLLMAnalysisStep.model_validate(
            {
                "step_id": 7,
                "reasoning": "The model claims the gate was verified.",
                "action": None,
                "is_conclusive": False,
                "signature_class": "null_deref",
                "gates": {
                    "register_provenance": {
                        "required_for": ["null_deref"],
                        "status": "closed",
                        "closure_basis": "executor_evidence",
                    }
                },
            }
        )

        self.assertIsNone(step.gates["register_provenance"].closure_basis)

    def test_evaluator_closes_gate_and_records_transition(self) -> None:
        gates = {
            "register_provenance": GateEntry(
                required_for=["pointer_corruption"], status="open"
            )
        }
        facts = {
            "rd_word:0xffff0000=0x10",
            "dis_instruction:0xffff1000=mov",
        }

        evaluated, transitions = evaluate_gate_closures(gates, facts, gates)

        self.assertEqual(evaluated["register_provenance"].status, "closed")
        self.assertEqual(
            evaluated["register_provenance"].completion_criteria,
            gate_completion_criteria("register_provenance"),
        )
        self.assertTrue(any(item["event"] == "gate_transition" for item in transitions))

    def test_state_manager_does_not_accept_llm_gate_closure(self) -> None:
        llm_step = VMCoreLLMAnalysisStep.model_validate(
            {
                "step_id": 5,
                "reasoning": "The model claims register provenance is closed.",
                "action": None,
                "is_conclusive": False,
                "signature_class": "pointer_corruption",
                "partial_dump": "partial",
                "gates": {
                    "register_provenance": {
                        "required_for": ["pointer_corruption"],
                        "status": "closed",
                        "evidence": "model claim only",
                    }
                },
            }
        )

        _, updates = project_managed_analysis_step(
            llm_step,
            {"evidence_facts": [], "gate_transition_history": []},
            original_reasoning="The model claims register provenance is closed.",
        )

        self.assertEqual(updates["managed_gates"]["register_provenance"].status, "open")
        self.assertTrue(
            any(
                item["event"] == "llm_close_rejected"
                for item in updates["gate_transition_history"]
            )
        )

    def test_state_manager_does_not_accept_llm_na(self) -> None:
        llm_step = VMCoreLLMAnalysisStep.model_validate(
            {
                "step_id": 5,
                "reasoning": "The model claims the lifetime gate is not applicable.",
                "action": None,
                "is_conclusive": False,
                "signature_class": "use_after_free",
                "partial_dump": "partial",
                "gates": {
                    "object_lifetime": {
                        "required_for": ["use_after_free"],
                        "status": "n/a",
                        "evidence": "Model-only applicability claim.",
                    }
                },
            }
        )

        _, updates = project_managed_analysis_step(
            llm_step,
            {"evidence_facts": [], "gate_transition_history": []},
            original_reasoning="The model claims the lifetime gate is not applicable.",
        )

        self.assertEqual(updates["managed_gates"]["object_lifetime"].status, "open")
        self.assertIsNone(updates["managed_gates"]["object_lifetime"].evidence)
        self.assertIsNone(
            updates["managed_gates"]["object_lifetime"].closure_basis
        )
        self.assertTrue(
            any(
                item["event"] == "llm_na_rejected"
                for item in updates["gate_transition_history"]
            )
        )

    def test_unknown_signature_does_not_inherit_prior_gates(self) -> None:
        llm_step = VMCoreLLMAnalysisStep.model_validate(
            {
                "step_id": 6,
                "reasoning": "The crash signature cannot be classified.",
                "action": None,
                "is_conclusive": False,
                "signature_class": "unknown",
                "partial_dump": "partial",
            }
        )
        prior_gates = {
            "register_provenance": GateEntry(
                required_for=["pointer_corruption"],
                status="closed",
                closure_basis="executor_evidence",
            )
        }

        _, updates = project_managed_analysis_step(
            llm_step,
            {
                "current_signature_class": "pointer_corruption",
                "managed_gates": prior_gates,
                "evidence_facts": [],
                "gate_transition_history": [],
            },
            original_reasoning="The crash signature cannot be classified.",
        )

        self.assertIsNone(updates["managed_gates"])

    def test_signature_change_does_not_reuse_prior_gate_closure(self) -> None:
        llm_step = VMCoreLLMAnalysisStep.model_validate(
            {
                "step_id": 8,
                "reasoning": "The missing mapping is being classified separately.",
                "action": None,
                "is_conclusive": False,
                "signature_class": "page_not_present",
                "partial_dump": "partial",
            }
        )
        prior_gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"],
                status="closed",
                evidence="Evidence for a different signature.",
                closure_basis="executor_evidence",
            )
        }

        _, updates = project_managed_analysis_step(
            llm_step,
            {
                "current_signature_class": "pointer_corruption",
                "managed_gates": prior_gates,
                "evidence_facts": [
                    "rd_word:0xffffb2709a1ac000=0x1",
                    "kmem_slab_state:0xffffb2709a1ac000=allocated",
                ],
                "gate_transition_history": [],
            },
            original_reasoning="The missing mapping is being classified separately.",
        )

        self.assertEqual(updates["managed_gates"]["object_lifetime"].status, "open")
        self.assertEqual(
            updates["managed_gates"]["object_lifetime"].required_for,
            ["page_not_present"],
        )

    def test_update_gate_evidence_caps_per_category_and_accumulates_omitted_count(
        self,
    ) -> None:
        gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"], status="open"
            )
        }
        first_batch = {
            f"kmem_slab_state:0xffff0000{i:04x}=allocated" for i in range(12)
        }
        updated_once = update_gate_evidence(gates, first_batch)
        ev1 = updated_once["object_lifetime"].evidence or ""
        kmem_lines_1 = [
            line
            for line in ev1.splitlines()
            if line.startswith("[evidence-delta] kmem_slab_state:")
            and not line.endswith("more)")
        ]
        self.assertEqual(len(kmem_lines_1), MAX_GATE_EVIDENCE_FACTS_PER_CATEGORY)
        self.assertIn(
            "[evidence-delta] kmem_slab_state: ... (+4 more)", ev1.splitlines()
        )

        second_batch = {
            f"kmem_slab_state:0xffff0000{i:04x}=allocated" for i in range(10, 20)
        }
        updated_twice = update_gate_evidence(updated_once, second_batch)
        ev2 = updated_twice["object_lifetime"].evidence or ""
        kmem_lines_2 = [
            line
            for line in ev2.splitlines()
            if line.startswith("[evidence-delta] kmem_slab_state:")
            and not line.endswith("more)")
        ]
        self.assertEqual(len(kmem_lines_2), MAX_GATE_EVIDENCE_FACTS_PER_CATEGORY)
        # 12 initial + 8 new distinct (12..19) = 20 total -> 8 retained + 12 omitted
        self.assertIn(
            "[evidence-delta] kmem_slab_state: ... (+12 more)", ev2.splitlines()
        )
        self.assertIn(
            "[evidence-delta] kmem_slab_state:0xffff00000013=allocated",
            kmem_lines_2,
        )

    def test_evaluate_gate_closures_prioritizes_intersecting_address_under_truncation(
        self,
    ) -> None:
        gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"], status="open"
            )
        }
        facts = {
            f"kmem_slab_state:0xffff9999{i:04x}=allocated" for i in range(25)
        }
        # Smallest address is the only one intersecting with rd_word
        facts.add("kmem_slab_state:0xffff00000001=allocated")
        facts.add("rd_word:0xffff00000001=0xdeadbeef")

        evaluated, _ = evaluate_gate_closures(gates, facts, gates)
        gate = evaluated["object_lifetime"]
        self.assertEqual(gate.status, "closed")
        self.assertIsNotNone(gate.evidence)
        lines = (gate.evidence or "").splitlines()
        self.assertIn(
            "[executor-evidence] kmem_slab_state:0xffff00000001=allocated", lines
        )
        self.assertIn(
            "[executor-evidence] rd_word:0xffff00000001=0xdeadbeef", lines
        )
        self.assertIn(
            "[executor-evidence] kmem_slab_state: ... (+18 more)", lines
        )

    def test_transitions_do_not_embed_full_fact_set(self) -> None:
        gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"],
                status="closed",
                evidence="LLM requests closure prematurely",
            )
        }
        prior_gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"],
                status="open",
            )
        }
        # Mixed 500 facts: 400 non-supporting struct_field/dis_instruction + 100 supporting kmem_slab_state
        facts = {f"struct_field:foo+{i}=bar" for i in range(200)}
        facts |= {f"dis_instruction:0xffff1000{i:04x}=mov" for i in range(200)}
        facts |= {
            f"kmem_slab_state:0xffff0000{i:04x}=allocated" for i in range(100)
        }
        _, transitions = evaluate_gate_closures(gates, facts, prior_gates)
        rejected = [
            item for item in transitions if item["event"] == "llm_close_rejected"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertNotIn("evidence_facts", rejected[0])
        self.assertEqual(rejected[0]["evidence_fact_count"], 100)

        # Now add an intersecting rd_word so gate_transition is emitted and verify its count
        facts_closing = set(facts) | {"rd_word:0xffff00000000=0x1"}
        open_gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"],
                status="open",
            )
        }
        _, close_transitions = evaluate_gate_closures(
            open_gates, facts_closing, prior_gates
        )
        closed_events = [
            item
            for item in close_transitions
            if item["event"] == "gate_transition"
        ]
        self.assertEqual(len(closed_events), 1)
        self.assertNotIn("evidence_facts", closed_events[0])
        self.assertEqual(closed_events[0]["evidence_fact_count"], 101)

    def test_update_gate_evidence_keeps_pinned_target_address(self) -> None:
        gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"], status="open"
            )
        }
        facts = {
            f"kmem_slab_state:0xffff9999{i:04x}=allocated" for i in range(30)
        }
        facts.add("kmem_slab_state:0x12e124000=allocated")
        # Superstring address with extra trailing 0 must not falsely match 0x12e124000
        facts.add("kmem_slab_state:0x12e1240000=allocated")

        updated = update_gate_evidence(
            gates,
            facts,
            pinned_addresses=["0x12e124000"],
        )
        ev = updated["object_lifetime"].evidence or ""
        lines = ev.splitlines()
        self.assertIn(
            "[evidence-delta] kmem_slab_state:0x12e124000=allocated", lines
        )
        self.assertNotIn(
            "[evidence-delta] kmem_slab_state:0x12e1240000=allocated", lines
        )
        self.assertIn(
            "[evidence-delta] kmem_slab_state: ... (+24 more)", lines
        )

    def test_extract_pinned_addresses_supports_bare_and_prefixed_hex(self) -> None:
        state = {
            "current_evidence_goal": {
                "target_object": "mpt3sas adapters ff292192012c0a58 and ff2922870f930a58"
            },
            "current_action_intent": {
                "target_object": "reply_dma=0x12e124000"
            },
        }
        pinned = extract_pinned_addresses(state)
        self.assertEqual(
            pinned,
            ["ff292192012c0a58", "ff2922870f930a58", "0x12e124000"],
        )

        gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"], status="open"
            )
        }
        facts = {
            f"kmem_slab_state:0xffff9999{i:04x}=allocated" for i in range(30)
        }
        facts.add("kmem_slab_state:0xff292192012c0a58=allocated")
        facts.add("kmem_slab_state:0xff2922870f930a58=allocated")
        updated = update_gate_evidence(gates, facts, pinned_addresses=pinned)
        lines = (updated["object_lifetime"].evidence or "").splitlines()
        self.assertIn(
            "[evidence-delta] kmem_slab_state:0xff292192012c0a58=allocated",
            lines,
        )
        self.assertIn(
            "[evidence-delta] kmem_slab_state:0xff2922870f930a58=allocated",
            lines,
        )

    def test_extract_pinned_addresses_ignores_short_offsets(self) -> None:
        state = {
            "current_evidence_goal": {
                "target_object": "desc+0xf8, next at 0x18, addr ff292192012c0a58"
            }
        }
        self.assertEqual(
            extract_pinned_addresses(state),
            ["ff292192012c0a58"],
        )

    def test_extract_pinned_addresses_deduplicates_in_order(self) -> None:
        state = {
            "current_evidence_goal": {
                "target_object": "adapter ff292192012c0a58 and 0x12e124000"
            },
            "current_action_intent": {
                "target_object": "check FF292192012C0A58 and 0X12E124000 then ff2922870f930a58"
            },
        }
        self.assertEqual(
            extract_pinned_addresses(state),
            ["ff292192012c0a58", "0x12e124000", "ff2922870f930a58"],
        )

    def test_extract_pinned_addresses_supports_uppercase_0x_prefix(self) -> None:
        state = {
            "current_evidence_goal": {
                "target_object": "reply_dma=0X12E124000"
            }
        }
        pinned = extract_pinned_addresses(state)
        self.assertEqual(pinned, ["0X12E124000"])

        gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"], status="open"
            )
        }
        facts = {
            f"kmem_slab_state:0xffff9999{i:04x}=allocated" for i in range(30)
        }
        facts.add("kmem_slab_state:0x12e124000=allocated")
        updated = update_gate_evidence(gates, facts, pinned_addresses=pinned)
        lines = (updated["object_lifetime"].evidence or "").splitlines()
        self.assertIn(
            "[evidence-delta] kmem_slab_state:0x12e124000=allocated",
            lines,
        )

    def test_truncation_summary_is_idempotent(self) -> None:
        gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"], status="open"
            )
        }
        batch = {
            f"kmem_slab_state:0xffff0000{i:04x}=allocated" for i in range(12)
        }
        updated_once = update_gate_evidence(gates, batch)
        updated_twice = update_gate_evidence(updated_once, batch)
        self.assertEqual(
            updated_once["object_lifetime"].evidence,
            updated_twice["object_lifetime"].evidence,
        )
        self.assertIn(
            "[evidence-delta] kmem_slab_state: ... (+4 more)",
            (updated_twice["object_lifetime"].evidence or "").splitlines(),
        )

        updated_plus_one = update_gate_evidence(
            updated_twice,
            {"kmem_slab_state:0xffff00000099=allocated"},
        )
        self.assertIn(
            "[evidence-delta] kmem_slab_state: ... (+5 more)",
            (updated_plus_one["object_lifetime"].evidence or "").splitlines(),
        )

    def test_large_fact_set_closure_deduplication_is_bounded(self) -> None:
        gates = {
            "object_lifetime": GateEntry(
                required_for=["pointer_corruption"], status="open"
            )
        }
        facts = {
            f"kmem_slab_state:0xffff8888{i:04x}=allocated" for i in range(5_000)
        }
        facts.add("rd_word:0xffff88880000=0x1")
        evaluated, _ = evaluate_gate_closures(gates, facts, gates)
        gate = evaluated["object_lifetime"]
        self.assertEqual(gate.status, "closed")
        lines = (gate.evidence or "").splitlines()
        self.assertIn(
            "[executor-evidence] kmem_slab_state:0xffff88880000=allocated",
            lines,
        )
        self.assertIn(
            "[executor-evidence] kmem_slab_state: ... (+4992 more)",
            lines,
        )


class CompositeToolEvidenceTests(unittest.TestCase):
    def test_inspect_slab_object_evidence_includes_struct_layout(self) -> None:
        from src.react.evidence import extract_evidence_facts

        output = (
            "struct irq_desc {\n"
            "  [0] struct irq_common_data irq_common_data;\n"
            "  [112] struct irqaction *action;\n"
            "  SIZE: 448\n"
            "}\n"
            "ff292187ae124a80:  0000000000000001 0000000000000002\n"
        )
        facts = extract_evidence_facts(
            "inspect_slab_object",
            {"command": "inspect_slab_object 0xff292187ae124a80 irq_desc"},
            output,
        )
        self.assertIn("struct_type:irq_desc", facts)
        self.assertIn("struct_field:irq_desc.action@0x70", facts)
        self.assertIn("rd_word:0xff292187ae124a80=0x1", facts)


if __name__ == "__main__":
    unittest.main()
