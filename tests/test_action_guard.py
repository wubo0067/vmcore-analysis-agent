import importlib
import subprocess
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

from src.react.action_guard import (
    _validate_command_line,
    build_command_fingerprint,
    extract_command_lines,
    validate_tool_call_request,
)


class KmemCommandGuardTests(unittest.TestCase):
    def test_kmem_v_requires_concrete_grep_filter(self) -> None:
        self.assertIsNotNone(_validate_command_line("kmem", allow_bt_a=False))
        self.assertIsNotNone(_validate_command_line("kmem -v", allow_bt_a=False))
        self.assertIsNotNone(_validate_command_line("kmem -v | grep", allow_bt_a=False))
        self.assertIsNotNone(
            _validate_command_line("kmem -v | grep -i", allow_bt_a=False)
        )
        self.assertIsNotNone(
            _validate_command_line("kmem -v | head -20", allow_bt_a=False)
        )
        # pipe 后无任何内容，不应 IndexError
        self.assertIsNotNone(_validate_command_line("kmem -v |", allow_bt_a=False))

    def test_crash_server_import_does_not_pull_react(self) -> None:
        # Run in a clean interpreter: mutating sys.modules here would poison
        # other test modules that already hold references to src.react classes.
        code = (
            "import sys\n"
            "import src.mcp_tools.crash.server as server\n"
            "leaked = sorted(m for m in sys.modules "
            "if m == 'src.react' or m.startswith('src.react.'))\n"
            "assert not leaked, leaked\n"
            "assert hasattr(server, 'inspect_slab_object')\n"
            "assert hasattr(server, 'compare_memory_blocks')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_kmem_v_accepts_filtered_and_targeted_forms(self) -> None:
        self.assertIsNone(
            _validate_command_line("kmem -v | grep -i 9a1ac", allow_bt_a=False)
        )
        self.assertIsNone(_validate_command_line("kmem -S ffff0000", allow_bt_a=False))


class StructDotSyntaxGuardTests(unittest.TestCase):
    def test_struct_instance_query_ignores_unrelated_global_offsets(self) -> None:
        layout_cache = {
            "device": {
                "size": 0x40,
                "field_offsets": [0x0, 0x8, 0x10],
            },
            "irqaction": {
                "size": 0x80,
                "field_offsets": [0x0, 0x18, 0x20, 0x50],
            },
        }
        # 0x50 来自别的 crash-path 基址寄存器，不能据此拒绝 device 实例查询。
        ok = validate_tool_call_request(
            "struct",
            {"command": "struct device.driver ffff888100000000"},
            observed_struct_offsets=[0x50],
            struct_layout_cache=layout_cache,
        )
        self.assertIsNone(ok)

        # show_interrupts 同时出现 irq_desc 的 0x1b0 与 irqaction 的 0x50；
        # 全局最大偏移 0x1b0 不能把合法的 irqaction 查询误杀。
        ok = validate_tool_call_request(
            "struct",
            {"command": "struct irqaction ff292187ae124a80"},
            observed_struct_offsets=[0x18, 0x50, 0x1b0],
            struct_layout_cache=layout_cache,
        )
        self.assertIsNone(ok)

    def test_struct_layout_and_instance_in_one_call_still_rejected(self) -> None:
        err = validate_tool_call_request(
            "run_script",
            {"script": "struct -o device\nstruct device ffff888100000000"},
            observed_struct_offsets=[0x8],
            struct_layout_cache={},
        )
        self.assertIsNotNone(err)
        self.assertIn("cannot be combined with first-time struct -o", err or "")

    def test_struct_minus_o_rejects_dot_syntax(self) -> None:
        err = _validate_command_line("struct -o device.driver", allow_bt_a=False)
        self.assertIsNotNone(err)
        self.assertIn("struct -o <type>", err or "")

    def test_bt_f_rejects_numeric_pid_or_frame_and_accepts_hex_task_addr(self) -> None:
        err = _validate_command_line("bt -f 1234", allow_bt_a=False)
        self.assertIsNotNone(err)
        self.assertIn("not a numeric PID or frame number", err or "")
        self.assertIsNone(
            _validate_command_line("bt -f ffff888100000000", allow_bt_a=False)
        )

    def test_bounded_search_options_are_not_address_arithmetic(self) -> None:
        # search -s/-e 是合法的 bounded scan；不能把 -e 当成减法。
        self.assertIsNone(
            _validate_command_line(
                "search -s ff292187ae124000 -e ff292187ae125fff "
                "ffffffffc051f1e0",
                allow_bt_a=False,
            )
        )
        self.assertIsNone(
            _validate_command_line(
                "search -s 0x100 -e 0x200 0xdead", allow_bt_a=False
            )
        )

    def test_inline_address_arithmetic_is_auto_resolved_or_rejected(self) -> None:
        # 字面量十六进制/十进制偏移算术会在 canonicalize_command_line 中自动求值。
        self.assertIsNone(
            _validate_command_line(
                "rd -x ff292187ae124a80+0x10 8", allow_bt_a=False
            )
        )
        # kmalloc-128 这类缓存名不是符号算术，必须被允许。
        self.assertIsNone(
            _validate_command_line("kmem -S kmalloc-128", allow_bt_a=False)
        )
        # 符号或非数值偏移算术仍必须被拒绝。
        err = _validate_command_line(
            "rd -x irq_desc+0x10 8", allow_bt_a=False
        )
        self.assertIsNotNone(err)
        self.assertIn("address arithmetic must be resolved", err or "")
        self.assertIn("sym <symbol>", err or "")

    def test_canonicalize_resolves_literal_arithmetic_and_strips_placeholder(self) -> None:
        from src.react.action_guard import (
            canonicalize_command_line,
            resolve_address_arithmetic_in_line,
            sanitize_action_tokens,
        )

        self.assertEqual(
            sanitize_action_tokens(["-x", "ff292187ae124a80", "_placeholder_do_not_use_directly"]),
            ["-x", "ff292187ae124a80"],
        )
        self.assertEqual(
            resolve_address_arithmetic_in_line("rd -x 0xff292187ae124a80+0x18 4"),
            "rd -x 0xff292187ae124a98 4",
        )
        self.assertEqual(
            resolve_address_arithmetic_in_line("rd -x ff292187ae124a80-0x80 16"),
            "rd -x ff292187ae124a00 16",
        )
        self.assertEqual(
            canonicalize_command_line("rd -x ff292187ae124a80+0x10 8 _placeholder_do_not_use_directly"),
            "rd -x ff292187ae124a90 8",
        )

    def test_composite_crash_tools_validation(self) -> None:
        self.assertIsNone(
            _validate_command_line(
                "inspect_slab_object ff292187ae124a80 irqaction", allow_bt_a=False
            )
        )
        self.assertIsNotNone(
            _validate_command_line(
                "inspect_slab_object not_an_address", allow_bt_a=False
            )
        )
        self.assertIsNone(
            _validate_command_line(
                "compare_memory_blocks ff29218824aa8a80 ff292187ae124a80 16",
                allow_bt_a=False,
            )
        )
        self.assertIsNotNone(
            _validate_command_line(
                "compare_memory_blocks ff29218824aa8a80", allow_bt_a=False
            )
        )
        self.assertIsNone(
            _validate_command_line(
                "compare_memory_blocks ff29218824aa8a80 ff292187ae124a80 16 64",
                allow_bt_a=False,
            )
        )
        self.assertIn(
            "stride_bytes",
            _validate_command_line(
                "compare_memory_blocks ff29218824aa8a80 ff292187ae124a80 16 abc",
                allow_bt_a=False,
            )
            or "",
        )
        self.assertIn(
            "between 8 and 4096",
            _validate_command_line(
                "compare_memory_blocks ff29218824aa8a80 ff292187ae124a80 16 4",
                allow_bt_a=False,
            )
            or "",
        )
        # 合法十六进制 stride 与前导零十进制都必须被接受，且不能抛异常。
        self.assertIsNone(
            _validate_command_line(
                "compare_memory_blocks ff29218824aa8a80 ff292187ae124a80 16 0x4a",
                allow_bt_a=False,
            )
        )
        self.assertIsNone(
            _validate_command_line(
                "compare_memory_blocks ff29218824aa8a80 ff292187ae124a80 16 0128",
                allow_bt_a=False,
            )
        )
        self.assertIsNone(
            validate_tool_call_request(
                "compare_memory_blocks",
                {
                    "command": (
                        "compare_memory_blocks ff29218824aa8a80 "
                        "ff292187ae124a80 16 0128"
                    )
                },
            )
        )
        self.assertIn(
            "qword_count",
            _validate_command_line(
                "compare_memory_blocks ff29218824aa8a80 ff292187ae124a80 abc",
                allow_bt_a=False,
            )
            or "",
        )
        self.assertIn(
            "between 2 and 256",
            _validate_command_line(
                "compare_memory_blocks ff29218824aa8a80 ff292187ae124a80 1",
                allow_bt_a=False,
            )
            or "",
        )
        # inspect_slab_object 的十六进制 slot_size、前导零、模块名参数。
        self.assertIsNone(
            _validate_command_line(
                "inspect_slab_object ff292187ae124a80 0x6a", allow_bt_a=False
            )
        )
        self.assertIsNone(
            _validate_command_line(
                "inspect_slab_object ff292187ae124a80 064", allow_bt_a=False
            )
        )
        self.assertIsNone(
            _validate_command_line(
                "inspect_slab_object ff292187ae124a80 irqaction mpt3sas",
                allow_bt_a=False,
            )
        )
        self.assertIsNotNone(
            _validate_command_line(
                "inspect_slab_object ff292187ae124a80 irqaction mpt3sas "
                "/custom/mpt3sas.ko.debug extra",
                allow_bt_a=False,
            )
        )
        self.assertIsNone(
            _validate_command_line(
                "inspect_slab_object ff292187ae124a80 irqaction mpt3sas "
                "/custom/mpt3sas.ko.debug",
                allow_bt_a=False,
            )
        )
        self.assertIn(
            "between 16 and 4096",
            _validate_command_line(
                "inspect_slab_object ff292187ae124a80 8", allow_bt_a=False
            )
            or "",
        )

    def test_module_symbol_rewrite_skips_composite_tools(self) -> None:
        from src.react.action_guard import maybe_rewrite_module_symbol_tool_call

        debug_paths = ["/lib/modules/4.18.0/mpt3sas.ko.debug"]
        self.assertIsNone(
            maybe_rewrite_module_symbol_tool_call(
                "inspect_slab_object",
                {"command": "inspect_slab_object 0xff292187ae124a80 mpt3sas_adapter"},
                debug_symbol_paths=debug_paths,
            )
        )
        self.assertIsNone(
            maybe_rewrite_module_symbol_tool_call(
                "compare_memory_blocks",
                {
                    "command": (
                        "compare_memory_blocks ff29218824aa8a80 "
                        "ff292187ae124a80 16"
                    )
                },
                debug_symbol_paths=debug_paths,
            )
        )
        # 普通 crash 命令仍应被改写成带 mod -s 的 run_script。
        rewritten = maybe_rewrite_module_symbol_tool_call(
            "struct",
            {"command": "struct MPT3SAS_ADAPTER 0xff292187ae124a80"},
            debug_symbol_paths=debug_paths,
        )
        self.assertIsNotNone(rewritten)
        self.assertEqual(rewritten[0], "run_script")
        self.assertIn("mod -s mpt3sas", rewritten[1]["script"])
        # 未加前缀的 arguments 形式改写后也必须带 native 子命令名。
        rewritten_unprefixed = maybe_rewrite_module_symbol_tool_call(
            "struct",
            {"command": "MPT3SAS_ADAPTER 0xff292187ae124a80"},
            debug_symbol_paths=debug_paths,
        )
        self.assertIsNotNone(rewritten_unprefixed)
        self.assertIn(
            "struct MPT3SAS_ADAPTER", rewritten_unprefixed[1]["script"]
        )

        # 校验层：复合工具必须豁免“单条命令必须走 run_script”的通用拒绝，
        # 但 inspect 使用模块私有类型时必须显式带模块名。
        self.assertIsNone(
            validate_tool_call_request(
                "inspect_slab_object",
                {
                    "command": (
                        "inspect_slab_object 0xff292187ae124a80 "
                        "mpt3sas_adapter mpt3sas"
                    )
                },
                debug_symbol_paths=debug_paths,
            )
        )
        missing_module = validate_tool_call_request(
            "inspect_slab_object",
            {"command": "inspect_slab_object 0xff292187ae124a80 mpt3sas_adapter"},
            debug_symbol_paths=debug_paths,
        )
        self.assertIn("third argument", missing_module or "")
        # 核心类型与 compare 工具不应被误拒绝。
        self.assertIsNone(
            validate_tool_call_request(
                "inspect_slab_object",
                {"command": "inspect_slab_object 0xff292187ae124a80 irqaction"},
                debug_symbol_paths=debug_paths,
            )
        )
        self.assertIsNone(
            validate_tool_call_request(
                "compare_memory_blocks",
                {
                    "command": (
                        "compare_memory_blocks ff29218824aa8a80 "
                        "ff292187ae124a80 16"
                    )
                },
                debug_symbol_paths=debug_paths,
            )
        )

    def test_cross_step_candidate_dedup_uses_address_pair(self) -> None:
        from src.react.nodes import _cross_step_candidate_lines

        content = (
            "[mechanical-analysis]\n"
            "- memory_copy_candidate: 0x1000 <-> 0x9000 const_addr_delta=+0x8000 "
            "identical_prefix=64B (0x40, 8 qwords, spans 1x64B slots)\n"
        )
        summary = (
            "- memory_copy_candidate: 0x1000 <-> 0x9000 const_addr_delta=+0x8000 "
            "identical_prefix=64B (0x40, 8 qwords, spans 1x128B slots)\n"
            "- memory_copy_candidate: 0x2000 <-> 0xa000 const_addr_delta=+0x8000 "
            "identical_prefix=64B (0x40, 8 qwords, spans 1x128B slots)\n"
        )
        lines = _cross_step_candidate_lines(content, summary)
        self.assertEqual(len(lines), 1)
        self.assertIn("0x2000", lines[0])

    def test_inspect_slab_object_rejects_out_of_range_slot_size(self) -> None:
        from src.mcp_tools.crash import server as crash_server_module

        result = crash_server_module.inspect_slab_object.fn(
            "inspect_slab_object 0xff292187ae124a80 8", "vc", "vm"
        )
        self.assertIn("between 16 and 4096", result)

    def test_unprefixed_single_command_is_normalized_before_validation(self) -> None:
        paths = ["/lib/modules/4.18.0/mpt3sas.ko.debug"]
        # 生产路径的 command 只含 arguments，不含 command_name。
        self.assertIsNone(
            validate_tool_call_request(
                "inspect_slab_object",
                {"command": "0xff292187ae124a80 mpt3sas_adapter mpt3sas"},
                debug_symbol_paths=paths,
            )
        )
        self.assertIn(
            "between 16 and 4096",
            validate_tool_call_request(
                "inspect_slab_object", {"command": "0xff292187ae124a80 8"}
            )
            or "",
        )
        self.assertIn(
            "requires",
            validate_tool_call_request(
                "compare_memory_blocks", {"command": "0xff292187ae124a80"}
            )
            or "",
        )
        # 原生子命令的逐行规则也必须重新生效。
        self.assertIn(
            "forbidden shell/register",
            validate_tool_call_request(
                "rd", {"command": "0xff292187ae124a80 $var"}
            )
            or "",
        )
        self.assertIsNone(
            validate_tool_call_request("struct", {"command": "-o irq_desc"})
        )

    def test_validate_normalizes_arguments_form_too(self) -> None:
        self.assertIn(
            "between 16 and 4096",
            validate_tool_call_request(
                "inspect_slab_object",
                {"arguments": ["0xff292187ae124a80", "8"]},
            )
            or "",
        )

    def test_extract_command_lines_normalizes_single_command(self) -> None:
        self.assertEqual(
            extract_command_lines("rd", {"command": "0xff292187ae124a80 16"}),
            ["rd 0xff292187ae124a80 16"],
        )
        self.assertEqual(
            extract_command_lines(
                "rd", {"arguments": ["0xff292187ae124a80", "16"]}
            ),
            ["rd 0xff292187ae124a80 16"],
        )
        # run_script 行本身是完整命令；结构化工具没有命令行。
        self.assertEqual(
            extract_command_lines(
                "run_script", {"script": "rd 0xff292187ae124a80 16"}
            ),
            ["rd 0xff292187ae124a80 16"],
        )
        self.assertEqual(extract_command_lines("read_source", {"file": "a.c"}), [])
        # 跨包装形式指纹必须一致。
        self.assertEqual(
            build_command_fingerprint("rd", {"command": "0xff292187ae124a80 16"}),
            build_command_fingerprint(
                "run_script", {"script": "rd 0xff292187ae124a80 16"}
            ),
        )
        self.assertEqual(
            build_command_fingerprint(
                "crash", {"command": "rd 0xff292187ae124a80 16"}
            ),
            build_command_fingerprint("rd", {"command": "0xff292187ae124a80 16"}),
        )

    def test_unprefixed_rd_hits_spin_guard(self) -> None:
        from src.react import nodes as nodes_mod

        lines = extract_command_lines("rd", {"command": "0xff292187ae124a80 16"})
        state = {
            "no_progress_streak": nodes_mod.CONVERGENCE_GUARD_STREAK_THRESHOLD + 1
        }
        self.assertIsNotNone(
            nodes_mod._no_new_evidence_directive(state, lines)
        )

    def test_canonical_commands_from_tool_call_prefixes_dict_args(self) -> None:
        from src.react.prompt_builder import _canonical_commands_from_tool_call

        self.assertEqual(
            _canonical_commands_from_tool_call(
                "rd", {"command": "0xff292187ae124a80 16"}
            ),
            ["rd 0xff292187ae124a80 16"],
        )

    def test_with_tool_prefix_is_idempotent_and_skips_run_script(self) -> None:
        from src.utils.crash_command import with_tool_prefix

        self.assertEqual(with_tool_prefix("rd", "rd 0xff 1"), "rd 0xff 1")
        self.assertEqual(with_tool_prefix("rd", "0xff 1"), "rd 0xff 1")
        self.assertEqual(with_tool_prefix("run_script", "rd 0xff"), "rd 0xff")
        self.assertEqual(with_tool_prefix("crash", "rd 0xff"), "rd 0xff")

    def test_historical_memory_reads_uses_incremental_cache(self) -> None:
        from src.react import nodes as nodes_mod

        output = "ff292187ae124a80:  0000000000000001 0000000000000002\n"
        reads_once, cache_once = nodes_mod._historical_memory_reads(
            {"k": output}, {}
        )
        self.assertEqual(len(reads_once), 1)
        self.assertEqual(len(cache_once), 1)

        original = nodes_mod.parse_memory_reads
        nodes_mod.parse_memory_reads = lambda _text: (_ for _ in ()).throw(
            AssertionError("cached output must not be parsed again")
        )
        try:
            reads_twice, cache_twice = nodes_mod._historical_memory_reads(
                {"k": output}, cache_once
            )
        finally:
            nodes_mod.parse_memory_reads = original
        self.assertEqual(
            [read.words for read in reads_twice],
            [read.words for read in reads_once],
        )
        self.assertEqual(set(cache_twice), set(cache_once))

    def test_inspect_slab_object_resolves_geometry_before_reading(self) -> None:
        from src.mcp_tools.crash import server as crash_server_module

        kmem_output = (
            "CACHE             OBJSIZE  ALLOCATED     TOTAL  SLABS  SSIZE  NAME\n"
            "ff292187800047c0       96         10        20     2     4k  kmalloc-96\n"
            "  SLAB              MEMORY            NODE  TOTAL  ALLOCATED  FREE\n"
            "  ffca29c406b84900  ff292187ae124000     0     32         31     1\n"
            "  FREE / [ALLOCATED]\n"
            "  [ff292187ae124a80]\n"
        )
        calls: list[tuple[str, str]] = []

        def fake_script(script, *_args, **_kwargs):
            calls.append(("script", script))
            return kmem_output

        def fake_command(command, *_args, **_kwargs):
            calls.append(("command", command))
            return "ff292187ae124a20:  0000000000000001 0000000000000002\n"

        original_script = crash_server_module.run_crash_script
        original_command = crash_server_module.run_crash_command
        crash_server_module.run_crash_script = fake_script
        crash_server_module.run_crash_command = fake_command
        try:
            result = crash_server_module.inspect_slab_object.fn(
                "inspect_slab_object 0xff292187ae124a80 irqaction mpt3sas "
                "/custom/mpt3sas.ko.debug",
                "vc",
                "vm",
            )
        finally:
            crash_server_module.run_crash_script = original_script
            crash_server_module.run_crash_command = original_command

        self.assertTrue(
            calls[0][1].startswith("mod -s mpt3sas /custom/mpt3sas.ko.debug\n")
        )
        self.assertIn("struct -o irqaction", calls[0][1])
        self.assertIn("struct irqaction 0xff292187ae124a80", calls[0][1])
        self.assertEqual(calls[1][0], "command")
        # kmem 报告 objsize=96，邻槽必须按 96 字节步长读，而不是默认 128。
        self.assertIn("rd -x 0x" + format(0xFF292187AE124A80 - 96, "x"), calls[1][1])
        self.assertIn("[mechanical-analysis]", result)


if __name__ == "__main__":
    unittest.main()
