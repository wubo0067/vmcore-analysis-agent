"""Regression tests for the report-level executor audits.

These cover the three defects found in report
127.0.0.1-2026-06-02-16_11_39-20261109-230701:
  * the DMA evidence-family detector matched negated prose,
  * an empty tool result was treated as verification,
  * suspect_code pointed at the victim file the fix section exempts.
"""

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

from src.react.output_parser import (
    _audit_open_action_closure,
    _audit_suspect_code_consistency,
    _collect_dma_evidence_families,
)


class DmaEvidenceFamilyTests(unittest.TestCase):
    def test_negated_overlap_is_not_counted(self) -> None:
        text = "current DMA-range overlap cannot be demonstrated from this partial dump"
        self.assertEqual(_collect_dma_evidence_families(text.lower()), set())

    def test_affirmed_overlap_is_counted(self) -> None:
        text = "the victim page overlaps the HBA reply_frames_dma range"
        self.assertIn("dma_overlap", _collect_dma_evidence_families(text.lower()))

    def test_descriptor_decode_wording_is_recognised(self) -> None:
        text = (
            "Decoding those records against the documented MPI2 layout gives "
            "IOCStatus=0x8022 and IOCLogInfo=0x30030109"
        )
        self.assertIn("descriptor_decode", _collect_dma_evidence_families(text.lower()))


class OpenActionClosureTests(unittest.TestCase):
    def _step(self, *, conclusive: bool) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            is_conclusive=conclusive,
            confidence="medium",
            reasoning="analysis",
            additional_notes=None,
        )

    def test_conclusion_is_blocked_while_an_action_has_no_output(self) -> None:
        step = self._step(conclusive=True)
        state = {"unanswered_actions": [{"display": "irq -s | grep ff...", "step": 61}]}
        result = _audit_open_action_closure(step, state)
        self.assertFalse(result.is_conclusive)
        self.assertEqual(result.confidence, "low")

    def test_no_open_actions_leaves_conclusion_alone(self) -> None:
        step = self._step(conclusive=True)
        result = _audit_open_action_closure(step, {"unanswered_actions": []})
        self.assertTrue(result.is_conclusive)

    def test_expired_checks_become_a_caveat_without_blocking(self) -> None:
        step = self._step(conclusive=True)
        state = {
            "unanswered_actions": [],
            "expired_unresolved": [
                {"display": 'irq -s | grep -i "ff292187ae124"', "step": 61}
            ],
        }
        result = _audit_open_action_closure(step, state)
        self.assertTrue(result.is_conclusive)
        self.assertIn("Executor caveat", result.additional_notes)
        self.assertIn("irq -s | grep", result.additional_notes)


class SuspectCodeAuditTests(unittest.TestCase):
    def test_victim_file_is_reset_to_indeterminate(self) -> None:
        diagnosis = types.SimpleNamespace(
            fix_suggestion=(
                "treat /proc/interrupts readers as victims only - no change is "
                "needed in kernel/irq/proc.c."
            ),
            detailed_analysis="",
            suspect_code=types.SimpleNamespace(
                file="kernel/irq/proc.c", function="show_interrupts", line="516"
            ),
        )
        step = types.SimpleNamespace(
            final_diagnosis=diagnosis, reasoning="", additional_notes=None
        )
        result = _audit_suspect_code_consistency(step)
        self.assertEqual(result.final_diagnosis.suspect_code.file, "indeterminate")

    def test_unrelated_fix_text_is_left_alone(self) -> None:
        diagnosis = types.SimpleNamespace(
            fix_suggestion="no change is needed in kernel/irq/proc.c",
            detailed_analysis="",
            suspect_code=types.SimpleNamespace(
                file="drivers/scsi/mpt3sas/mpt3sas_base.c", function="x", line="1"
            ),
        )
        step = types.SimpleNamespace(
            final_diagnosis=diagnosis, reasoning="", additional_notes=None
        )
        result = _audit_suspect_code_consistency(step)
        self.assertEqual(
            result.final_diagnosis.suspect_code.file,
            "drivers/scsi/mpt3sas/mpt3sas_base.c",
        )


class OpenActionLifecycleTests(unittest.TestCase):
    """Registration / clearing / expiry rules in nodes.py."""

    def test_empty_output_registers_an_open_action(self) -> None:
        from src.react.nodes import _update_open_actions

        actions = _update_open_actions(
            [],
            fingerprint="f1",
            display="rd -x ff00 1",
            content="crash> rd -x ff00 1",
            step_index=10,
        )
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["reason"], "empty")

    def test_grep_without_match_is_a_negative_result(self) -> None:
        from src.react.nodes import _classify_tool_output

        self.assertEqual(
            _classify_tool_output("crash> log -m | grep reset", "log -m | grep reset"),
            "negative",
        )

    def test_crash_error_marks_the_action_failed_even_with_output(self) -> None:
        from src.react.nodes import _classify_tool_output

        content = (
            "crash> irq 494\n IRQ   IRQ_DESC/_DATA      IRQACTION\n"
            " 494  ff2921879ce79000  ff292187ae124a80\n"
            "irq: invalid kernel virtual address: 62  type: \"irqaction name\""
        )
        self.assertEqual(_classify_tool_output(content, "irq 494"), "failed")

    def test_success_clears_the_same_fingerprint(self) -> None:
        from src.react.nodes import _update_open_actions

        actions = [{"fingerprint": "f1", "display": "x", "step": 1}]
        actions = _update_open_actions(
            actions,
            fingerprint="f1",
            display="x",
            content="ff00:  0000000000000001",
            step_index=2,
        )
        self.assertEqual(actions, [])

    def test_repeated_failure_is_deduplicated(self) -> None:
        from src.react.nodes import _update_open_actions

        actions: list[dict[str, object]] = []
        for _ in range(3):
            actions = _update_open_actions(
                actions, fingerprint="f1", display="x", content="", step_index=1
            )
        self.assertEqual(len(actions), 1)

    def test_expiry_moves_old_entries_out_and_caps_the_list(self) -> None:
        from src.react.nodes import _expire_open_actions

        actions = [
            {"fingerprint": "stale", "step": 0},
            {"fingerprint": "fresh", "step": 9},
        ]
        fresh, expired = _expire_open_actions(actions, 10)
        self.assertEqual([entry["fingerprint"] for entry in fresh], ["fresh"])
        self.assertEqual([entry["fingerprint"] for entry in expired], ["stale"])

        many = [{"fingerprint": str(i), "step": 10} for i in range(8)]
        fresh, _ = _expire_open_actions(many, 10)
        self.assertEqual(len(fresh), 5)

    def test_merge_expired_stamps_and_drops_resolved_entries(self) -> None:
        from src.react.nodes import _merge_expired

        merged = _merge_expired(
            [{"fingerprint": "old", "display": "a", "step": 1}],
            [{"fingerprint": "new", "display": "b", "step": 9}],
            resolved_fingerprints={"old"},
            step_index=10,
        )
        self.assertEqual([entry["fingerprint"] for entry in merged], ["new"])
        self.assertEqual(merged[0]["expired_at"], 10)


if __name__ == "__main__":
    unittest.main()