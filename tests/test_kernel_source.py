"""Tests for the kernel_source provider (resolver + tools + evidence hooks)."""

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

root = Path(__file__).resolve().parents[1]
src_pkg = types.ModuleType("src")
src_pkg.__path__ = [str(root / "src")]
sys.modules.setdefault("src", src_pkg)
react_pkg = types.ModuleType("src.react")
react_pkg.__path__ = [str(root / "src" / "react")]
sys.modules.setdefault("src.react", react_pkg)

from src.mcp_tools.kernel_source import tools
from src.mcp_tools.kernel_source.resolver import (
    SourceTreeError,
    normalize_kver,
    resolve_tree,
    tree_version,
)
from src.react.evidence import extract_evidence_facts

_VERSION = "4.18.0-305.el8"


def _write_tree(base: Path) -> Path:
    """Create a minimal but realistic kernel tree layout."""

    (base / "kernel").mkdir(parents=True, exist_ok=True)
    (base / "Makefile").write_text(
        "VERSION = 4\nPATCHLEVEL = 18\nSUBLEVEL = 0\nEXTRAVERSION = -305.el8\n",
        encoding="utf-8",
    )
    demo_dir = base / "drivers" / "net"
    demo_dir.mkdir(parents=True, exist_ok=True)
    (demo_dir / "demo.c").write_text(
        "\n".join(
            [
                "static int demo_init(struct demo *p, int v)",
                "{",
                "\tp->sk_state = v;",
                "\tif (p->sk_state == 0)",
                "\t\treturn -EINVAL;",
                "\tp->sk_state |= 1;",
                "\treturn 0;",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    return base


class KernelSourceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.tree = _write_tree(self.base / _VERSION)

    def _env(self, root_path: Path | str) -> mock._patch:
        return mock.patch.dict(
            os.environ, {"KERNEL_SOURCE_ROOT": str(root_path)}, clear=False
        )


class ResolverTests(KernelSourceTestCase):
    def test_reads_version_from_makefile(self) -> None:
        self.assertEqual(tree_version(self.tree), _VERSION)

    def test_resolves_single_configured_tree(self) -> None:
        with self._env(self.tree):
            resolved = resolve_tree()
        self.assertEqual(resolved.version, _VERSION)
        self.assertEqual(resolved.root, self.tree.resolve())
        self.assertFalse(resolved.has_git)

    def test_resolves_version_subtree_by_kver(self) -> None:
        other = _write_tree(self.base / "5.14.0-100.el9")
        (other / "Makefile").write_text(
            "VERSION = 5\nPATCHLEVEL = 14\nSUBLEVEL = 0\nEXTRAVERSION = -100.el9\n",
            encoding="utf-8",
        )
        with self._env(self.base):
            resolved = resolve_tree("5.14.0-100.el9")
        self.assertEqual(resolved.root, other.resolve())
        self.assertEqual(resolved.version, "5.14.0-100.el9")

    def test_ambiguous_root_requires_kver(self) -> None:
        _write_tree(self.base / "5.14.0-100.el9")
        with self._env(self.base):
            with self.assertRaises(SourceTreeError) as ctx:
                resolve_tree()
        self.assertIn("multiple kernel source trees", str(ctx.exception))

    def test_mismatched_kver_is_rejected(self) -> None:
        with self._env(self.tree):
            with self.assertRaises(SourceTreeError) as ctx:
                resolve_tree("5.14.0-100.el9")
        self.assertIn("SOURCE_TREE_MISMATCH", str(ctx.exception))

    def test_normalize_kver_collapses_whitespace(self) -> None:
        self.assertEqual(normalize_kver("  4.18.0-305.el8 \n"), _VERSION)


class SourceToolTests(KernelSourceTestCase):
    def test_status_reports_configured_tree(self) -> None:
        with self._env(self.tree):
            output = tools.source_status_impl()
        self.assertIn("SOURCE_STATUS configured=true", output)
        self.assertIn(f"tree_version={_VERSION}", output)

    def test_status_reports_missing_configuration(self) -> None:
        with self._env(""):
            output = tools.source_status_impl()
        self.assertIn("SOURCE_STATUS configured=false", output)
        self.assertIn("from memory", output)

    def test_read_source_emits_source_ref_and_numbered_lines(self) -> None:
        with self._env(self.tree):
            output = tools.read_source_impl(
                "drivers/net/demo.c", kver=_VERSION, line=3, context=1
            )
        self.assertIn("SOURCE_REF: drivers/net/demo.c:3", output)
        self.assertIn("p->sk_state = v;", output)
        self.assertIn("3|", output)

    def test_read_source_accepts_trailing_line_suffix(self) -> None:
        with self._env(self.tree):
            output = tools.read_source_impl("drivers/net/demo.c:4", kver=_VERSION)
        self.assertIn("SOURCE_REF: drivers/net/demo.c:4", output)

    def test_read_source_rejects_parent_traversal(self) -> None:
        with self._env(self.tree):
            output = tools.read_source_impl("../../etc/passwd", kver=_VERSION)
        self.assertIn("SOURCE_ERROR", output)
        self.assertIn("escapes", output)

    def test_read_source_rejects_absolute_path(self) -> None:
        with self._env(self.tree):
            output = tools.read_source_impl("C:/Windows/win.ini")
        self.assertIn("SOURCE_ERROR", output)
        self.assertIn("absolute", output)

    def test_read_source_rejects_version_mismatch(self) -> None:
        with self._env(self.tree):
            output = tools.read_source_impl(
                "drivers/net/demo.c", kver="5.14.0-100.el9"
            )
        self.assertIn("SOURCE_ERROR", output)
        self.assertIn("SOURCE_TREE_MISMATCH", output)

    def test_read_source_reports_line_out_of_range(self) -> None:
        with self._env(self.tree):
            output = tools.read_source_impl("drivers/net/demo.c", line=9999)
        self.assertIn("SOURCE_ERROR", output)
        self.assertIn("outside", output)

    def test_grep_returns_matching_lines(self) -> None:
        with self._env(self.tree):
            output = tools.grep_source_impl("sk_state")
        self.assertIn("SOURCE_GREP", output)
        self.assertIn("drivers/net/demo.c:", output)

    def test_list_writers_returns_assignment_sites_only(self) -> None:
        with self._env(self.tree):
            output = tools.list_writers_impl("sk_state")
        self.assertIn("SOURCE_WRITERS field=sk_state", output)
        self.assertIn("p->sk_state = v;", output)
        self.assertIn("p->sk_state |= 1;", output)
        # The comparison line must not be reported as a writer.
        self.assertNotIn("if (p->sk_state == 0)", output)

    def test_list_writers_accepts_member_syntax(self) -> None:
        with self._env(self.tree):
            output = tools.list_writers_impl("struct demo.sk_state")
        self.assertIn("hits=2", output)

    def test_git_history_without_repository_is_explicit(self) -> None:
        with self._env(self.tree):
            output = tools.git_history_impl("drivers/net/demo.c")
        self.assertIn("SOURCE_ERROR", output)
        self.assertIn("no .git", output)


class RequestScopedRootTests(KernelSourceTestCase):
    """The per-request --kernel-source-root wins over the deployment default."""

    def test_request_root_overrides_environment(self) -> None:
        other = _write_tree(self.base / "linux-5.14.0-100.el9")
        (other / "Makefile").write_text(
            "VERSION = 5\nPATCHLEVEL = 14\nSUBLEVEL = 0\nEXTRAVERSION = -100.el9\n",
            encoding="utf-8",
        )
        with self._env(self.tree):
            output = tools.read_source_impl(
                "drivers/net/demo.c", source_root=str(other)
            )
        self.assertIn("version=5.14.0-100.el9", output)

    def test_rpmbuild_build_layout_is_discovered(self) -> None:
        # rpmbuild -bp leaves BUILD/kernel-<ver>/linux-<full>/ ; the caller may
        # point at BUILD or at the kernel-<ver> directory.
        build = self.base / "BUILD"
        nested = build / "kernel-4.18.0-305.el8" / "linux-4.18.0-305.el8.x86_64"
        _write_tree(nested)
        with self._env(""):
            output = tools.read_source_impl(
                "drivers/net/demo.c", source_root=str(build)
            )
        self.assertIn("SOURCE_REF: drivers/net/demo.c", output)

    def test_rpmbuild_topdir_layout_is_discovered(self) -> None:
        # get-kernel-source.sh builds <topdir>/BUILD/kernel-<ver>/linux-<ver>/;
        # pointing at <topdir> must still find the tree.
        topdir = self.base / "8" / "5.14.0-362.24.1.el9_3"
        nested = topdir / "BUILD" / "kernel-5.14.0-362.el9" / "linux-5.14.0-362.24.1.el9_3.x86_64"
        _write_tree(nested)
        (nested / "Makefile").write_text(
            "VERSION = 5\nPATCHLEVEL = 14\nSUBLEVEL = 0\n"
            "EXTRAVERSION = -362.24.1.el9_3.x86_64\n",
            encoding="utf-8",
        )
        with self._env(""):
            output = tools.read_source_impl(
                "drivers/net/demo.c", source_root=str(topdir)
            )
        self.assertIn("SOURCE_REF: drivers/net/demo.c", output)
        self.assertIn("version=5.14.0-362.24.1.el9_3.x86_64", output)

    def test_version_falls_back_to_directory_name(self) -> None:
        tree = self.base / "linux-4.18.0-305.130.1.el8_4.x86_64"
        _write_tree(tree)
        (tree / "Makefile").write_text(
            "VERSION = 4\nPATCHLEVEL = 18\nSUBLEVEL = 0\nEXTRAVERSION =\n",
            encoding="utf-8",
        )
        self.assertEqual(tree_version(tree), "4.18.0-305.130.1.el8_4.x86_64")

    def test_directory_that_is_not_a_tree_is_rejected(self) -> None:
        empty = self.base / "not-a-tree"
        empty.mkdir()
        with self._env(""):
            output = tools.read_source_impl("drivers/net/demo.c", source_root=str(empty))
        self.assertIn("SOURCE_ERROR", output)
        self.assertIn("no kernel source tree", output)

    def test_allowlist_blocks_paths_outside_it(self) -> None:
        allowed = self.base / "allowed"
        _write_tree(allowed)
        with mock.patch.dict(
            os.environ,
            {"KERNEL_SOURCE_ALLOWED_ROOTS": str(allowed), "KERNEL_SOURCE_ROOT": ""},
            clear=False,
        ):
            output = tools.read_source_impl(
                "drivers/net/demo.c", source_root=str(self.tree)
            )
        self.assertIn("SOURCE_ERROR", output)
        self.assertIn("KERNEL_SOURCE_ALLOWED_ROOTS", output)

    def test_request_path_wins_over_model_supplied_path(self) -> None:
        from src.mcp_tools.kernel_source.client import build_tool_payload

        payload = build_tool_payload(
            "read_source",
            {"file": "drivers/net/demo.c", "source_root": "/model/chosen"},
            {"kernel_source_root": "/request/chosen"},
        )
        self.assertEqual(payload["source_root"], "/request/chosen")

    def test_model_supplied_path_is_dropped_without_request_path(self) -> None:
        from src.mcp_tools.kernel_source.client import build_tool_payload

        payload = build_tool_payload(
            "read_source", {"file": "x.c", "source_root": "/model/chosen"}, {}
        )
        self.assertNotIn("source_root", payload)


class ToolCallShapeTests(unittest.TestCase):
    """The action -> tool_calls bridge must carry structured parameters."""

    def test_parameters_are_passed_through(self) -> None:
        import types

        from src.react.output_parser import build_tool_calls
        from src.react.schema import ToolCall

        action = ToolCall(
            command_name="read_source",
            parameters={
                "file": "drivers/net/demo.c",
                "line": 3,
                "kver": "4.18.0-305.el8",
            },
        )
        stub = types.SimpleNamespace(action=action, step_id="step-1")
        calls = build_tool_calls(stub, is_last_step=False)
        self.assertEqual(calls[0]["name"], "read_source")
        self.assertEqual(calls[0]["args"]["file"], "drivers/net/demo.c")
        self.assertEqual(calls[0]["args"]["line"], 3)

    def test_crash_command_still_uses_a_command_string(self) -> None:
        import types

        from src.react.output_parser import build_tool_calls
        from src.react.schema import ToolCall

        action = ToolCall(command_name="rd", arguments=["0xffff", "8"])
        stub = types.SimpleNamespace(action=action, step_id="step-2")
        calls = build_tool_calls(stub, is_last_step=False)
        self.assertIn("command", calls[0]["args"])
        self.assertIn("0xffff", calls[0]["args"]["command"])

    def test_legacy_token_command_is_mapped_positionally(self) -> None:
        from src.mcp_tools.kernel_source.client import build_tool_payload

        payload = build_tool_payload(
            "read_source", {"command": "drivers/net/demo.c 1203"}, {}
        )
        self.assertEqual(payload["file"], "drivers/net/demo.c")
        self.assertEqual(payload["line"], 1203)

    def test_unmappable_token_command_explains_the_fix(self) -> None:
        from src.mcp_tools.kernel_source.client import build_tool_payload

        with self.assertRaises(ValueError) as ctx:
            build_tool_payload("read_source", {"command": "a.c 1 4.18.0 x y z"}, {})
        self.assertIn("parameters", str(ctx.exception))


class DistTagToleranceTests(KernelSourceTestCase):
    """rpmbuild names the tree with the host's %{?dist}; tolerate el-tag drift."""

    def _dist_tree(self) -> Path:
        """Tree as produced by rpmbuild on a host with a different %{?dist}."""

        tree = (
            self.base
            / "8"
            / "4.18.0-553.22.1.el8_10"
            / "BUILD"
            / "kernel-4.18.0-553.22.1.el8_10"
            / "linux-4.18.0-553.22.1.el9.x86_64"
        )
        _write_tree(tree)
        (tree / "Makefile").write_text(
            "VERSION = 4\nPATCHLEVEL = 18\nSUBLEVEL = 0\nEXTRAVERSION =\n",
            encoding="utf-8",
        )
        return tree

    def test_dist_tag_mismatch_is_accepted_with_a_note(self) -> None:
        tree = self._dist_tree()
        with self._env(""):
            output = tools.read_source_impl(
                "drivers/net/demo.c",
                kver="4.18.0-553.22.1.el8_10.x86_64",
                source_root=str(tree),
            )
        self.assertIn("SOURCE_REF: drivers/net/demo.c", output)
        self.assertIn("only in its dist/arch suffix", output)

    def test_different_kernel_release_is_still_rejected(self) -> None:
        tree = self._dist_tree()
        with self._env(""):
            output = tools.read_source_impl(
                "drivers/net/demo.c",
                kver="5.14.0-362.24.1.el9_3.x86_64",
                source_root=str(tree),
            )
        self.assertIn("SOURCE_TREE_MISMATCH", output)

    def test_kver_without_arch_suffix_matches_tree(self) -> None:
        tree = self._dist_tree()
        with self._env(""):
            output = tools.read_source_impl(
                "drivers/net/demo.c",
                kver="4.18.0-553.22.1.el8_10",
                source_root=str(tree),
            )
        self.assertIn("SOURCE_REF: drivers/net/demo.c", output)


class ReviewRegressionTests(unittest.TestCase):
    """Regression tests for the pipeline gaps found in the code review."""

    def test_derive_kver_extracts_version_from_vmlinux_path(self) -> None:
        from src.mcp_tools.kernel_source.resolver import derive_kver

        self.assertEqual(
            derive_kver(
                "/usr/lib/debug/lib/modules/4.18.0-553.22.1.el8_10.x86_64/vmlinux"
            ),
            "4.18.0-553.22.1.el8_10.x86_64",
        )

    def test_source_status_output_yields_evidence_fact(self) -> None:
        facts = extract_evidence_facts(
            "source_status", {}, "SOURCE_STATUS configured=true\ntree_version=4.18.0"
        )
        self.assertIn("source_status:configured=true", facts)

    def test_zero_hit_grep_is_recorded_as_a_negative_result(self) -> None:
        facts = extract_evidence_facts(
            "grep_source",
            {"pattern": "foo"},
            "SOURCE_GREP pattern=foo hits=0 truncated=false\n(no match)",
        )
        self.assertIn("source_negative:grep:foo", facts)
        self.assertNotIn("source_grep:foo:hits=0", facts)

    def test_negative_and_status_facts_never_support_a_gate(self) -> None:
        from src.react.evidence import _fact_supports_gate

        self.assertFalse(_fact_supports_gate("source_negative:grep:foo", "register_provenance"))
        self.assertFalse(_fact_supports_gate("source_status:configured=true", "register_provenance"))
        self.assertTrue(_fact_supports_gate("source_writers:sk_state:hits=2", "register_provenance"))
        # Unknown gates must not accumulate weak_gate_closure telemetry from source facts.
        self.assertFalse(_fact_supports_gate("source_ref:a.c:3", "warning_site"))

    def test_source_ref_advances_a_gate_goal(self) -> None:
        from src.react.evidence import facts_support_goal

        self.assertTrue(
            facts_support_goal(
                {"source_ref:drivers/net/demo.c:3"},
                {"gate_name": "register_provenance"},
            )
        )

    def test_structured_args_get_a_stable_distinct_fingerprint(self) -> None:
        from src.react.action_guard import build_command_fingerprint

        first = build_command_fingerprint("read_source", {"file": "a.c", "line": 3})
        second = build_command_fingerprint("read_source", {"file": "b.c", "line": 3})
        self.assertTrue(first)
        self.assertNotEqual(first, second)

    def test_preflight_leaves_non_crash_tools_alone(self) -> None:
        import types
        from unittest import mock

        from src.react import output_parser
        from src.react.schema import ToolCall

        action = ToolCall(command_name="grep_source", parameters={"pattern": "a|b"})
        step = types.SimpleNamespace(
            action=action, reasoning="", signature_class=None, additional_notes=None
        )
        provider = types.SimpleNamespace(package_name="kernel_source")
        with mock.patch.object(
            output_parser, "get_registered_tool_provider", lambda name: provider
        ):
            result = output_parser._preflight_action_with_guard(step, {})
        self.assertEqual(result.action.command_name, "grep_source")

    def test_prompt_history_keeps_structured_parameters(self) -> None:
        from src.react.prompt_builder import _canonical_commands_from_tool_call

        commands = _canonical_commands_from_tool_call(
            "read_source", {"file": "a.c", "line": 3}
        )
        self.assertIn("file=a.c", commands[0])
        self.assertIn("line=3", commands[0])


def test_run_script_promotion_uses_structured_parameters(self) -> None:
        import types
        from unittest import mock

        from src.react import output_parser
        from src.react.schema import ToolCall

        action = ToolCall(command_name="run_script", arguments=["read_source fs/proc/base.c 3"])
        step = types.SimpleNamespace(
            action=action, reasoning="", signature_class=None, additional_notes=None
        )
        provider = types.SimpleNamespace(package_name="kernel_source")
        with mock.patch.object(
            output_parser, "get_registered_tool_provider", lambda name: provider
        ):
            result = output_parser._lift_standalone_mcp_tool_out_of_run_script(step)
        self.assertEqual(result.action.command_name, "read_source")
        self.assertEqual(
            result.action.parameters, {"file": "fs/proc/base.c", "line": 3}
        )
        self.assertEqual(result.action.arguments, [])


class EvidenceHookTests(unittest.TestCase):
    def test_source_ref_fact_is_extracted_without_command_syntax(self) -> None:
        facts = extract_evidence_facts(
            "read_source",
            {"file": "drivers/net/demo.c", "line": 3},
            "[source] tree=4.18.0\nSOURCE_REF: drivers/net/demo.c:3\n   3| code",
        )
        self.assertIn("source_ref:drivers/net/demo.c:3", facts)

    def test_source_ref_facts_do_not_close_gates(self) -> None:
        # source_ref must stay out of gate criteria: it is corroboration only.
        from src.react.evidence import _gate_criteria_satisfied

        self.assertFalse(
            _gate_criteria_satisfied(
                "register_provenance",
                {"source_ref:drivers/net/demo.c:3"},
                {},
            )
        )


if __name__ == "__main__":
    unittest.main()