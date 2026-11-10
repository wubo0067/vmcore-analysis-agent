#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# tools.py - kernel_source 工具实现（与 MCP 传输层解耦，便于单元测试）
"""Implementations behind the kernel_source MCP tools.

The functions return plain strings so they can be unit-tested without an MCP
server, and so failures reach the model as tool output (a ToolMessage) rather
than as an exception that aborts the graph node.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Iterator, Optional

from .resolver import (
    ENV_VAR,
    SourceTree,
    SourceTreeError,
    relative_name,
    resolve_relative_file,
    resolve_tree,
)

MAX_LINES_PER_READ = 160
MAX_OUTPUT_CHARS = 14_000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SCANNED_FILES = 40_000
_SOURCE_SUFFIXES = {".c", ".h", ".S", ".cc"}
_PRUNED_DIR_RELATIVE = {
    "Documentation",
    "samples",
    "tools/testing",
    "include/generated",
}


def _tree_or_error(
    kver: str, source_root: str = ""
) -> tuple[Optional[SourceTree], str]:
    try:
        return resolve_tree(kver, source_root), ""
    except SourceTreeError as exc:
        return None, str(exc)


def _status_block(tree: SourceTree) -> str:
    block = (
        f"[source] version={tree.version or 'unknown'} basis={tree.basis} "
        f"root={tree.root}"
    )
    if tree.note:
        block += f"\nnote={tree.note}"
    return block


def _is_probably_text(raw: bytes) -> bool:
    return b"\x00" not in raw[:4096]


def _iter_source_files(tree: SourceTree, prefix: str) -> Iterator[Path]:
    start = tree.root
    if prefix:
        candidate = (tree.root / prefix.replace("\\", "/")).resolve()
        if candidate == tree.root or tree.root in candidate.parents:
            start = candidate if candidate.is_dir() else candidate.parent

    scanned = 0
    for dirpath, dirnames, filenames in os.walk(start):
        try:
            rel_dir = Path(dirpath).resolve().relative_to(tree.root).as_posix()
        except (OSError, ValueError):
            dirnames[:] = []
            continue
        kept = []
        for name in sorted(dirnames):
            if name in {".git", "Documentation", "samples", ".tmp_versions"}:
                continue
            child = name if rel_dir in {"", "."} else f"{rel_dir}/{name}"
            if child in _PRUNED_DIR_RELATIVE:
                continue
            kept.append(name)
        dirnames[:] = kept

        for filename in sorted(filenames):
            if Path(filename).suffix not in _SOURCE_SUFFIXES:
                continue
            path = Path(dirpath) / filename
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            scanned += 1
            if scanned > MAX_SCANNED_FILES:
                return
            yield path


def _trim(text: str, limit: int = 200) -> str:
    text = " ".join(text.strip().split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _split_file_line(file: str) -> tuple[str, int]:
    """Accept the ``path:line`` form that crash prints in ``dis -s`` output."""

    raw = str(file or "").strip().strip("'\"")
    head, sep, tail = raw.rpartition(":")
    if sep and tail.isdigit():
        return head, int(tail)
    return raw, 0


def _not_configured() -> str:
    return (
        "SOURCE_STATUS configured=false\n"
        f"reason=no source root was supplied (--kernel-source-root) and {ENV_VAR} is "
        "not set; kernel source could not be verified for this dump\n"
        "guidance=Do not quote kernel source, line numbers, or backport status from "
        "memory; state explicitly that the source could not be checked."
    )


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------


def source_status_impl(source_root: str = "") -> str:
    try:
        tree = resolve_tree(requested_root=source_root)
    except SourceTreeError as exc:
        message = str(exc)
        if message.startswith("no kernel source tree"):
            return _not_configured()
        return f"SOURCE_STATUS configured=true\nerror={message}"

    lines = [
        "SOURCE_STATUS configured=true",
        f"tree_version={tree.version or 'unknown'}",
        f"basis={tree.basis}",
        f"git={str(tree.has_git).lower()}",
        f"root={tree.root}",
    ]
    if tree.note:
        lines.append(f"note={tree.note}")
    lines.append(
        "guidance=Pass kver with the kernel release from `sys` (`RELEASE:`); a tree from a "
        "different kernel release is rejected, a dist/arch-tag-only difference is "
        "accepted with a note."
    )
    return "\n".join(lines)


def read_source_impl(
    file: str,
    kver: str = "",
    line: int = 0,
    context: int = 20,
    source_root: str = "",
) -> str:
    file, line_hint = _split_file_line(file)
    line = int(line or 0) or line_hint

    tree, error = _tree_or_error(kver, source_root)
    if tree is None:
        return f"SOURCE_ERROR {error}"

    try:
        path = resolve_relative_file(tree, file)
        raw = path.read_bytes()
    except SourceTreeError as exc:
        return f"SOURCE_ERROR {exc}"
    except OSError as exc:
        return f"SOURCE_ERROR cannot read {file!r}: {exc}"

    if not _is_probably_text(raw):
        return f"SOURCE_ERROR not a text source file: {relative_name(tree, path)}"

    lines = raw.decode("utf-8", errors="replace").splitlines()
    total = len(lines)
    if total == 0:
        return f"SOURCE_ERROR empty file: {relative_name(tree, path)}"

    line = max(0, int(line or 0))
    rel = relative_name(tree, path)
    if line > total:
        return (
            f"SOURCE_ERROR line {line} is outside {rel} (1..{total}); "
            "dis -s may have been resolved against a different build"
        )

    span = max(0, min(int(context or 20), 80))
    if line == 0:
        start = 1
        end = min(total, min(2 * span + 1, MAX_LINES_PER_READ))
    else:
        start = max(1, line - span)
        end = min(total, line + span)
        if end - start + 1 > MAX_LINES_PER_READ:
            end = start + MAX_LINES_PER_READ - 1

    anchor = line if line > 0 else start
    body = "\n".join(
        f"{number:6d}| {lines[number - 1]}" for number in range(start, end + 1)
    )
    header = (
        f"{_status_block(tree)}\n"
        f"file={rel} lines={start}-{end}/{total}\n"
        f"SOURCE_REF: {rel}:{anchor}\n"
    )
    output = f"{header}{body}"
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[:MAX_OUTPUT_CHARS] + "\n[truncated]"
    return output


def grep_source_impl(
    pattern: str,
    kver: str = "",
    max_hits: int = 25,
    prefix: str = "",
    source_root: str = "",
) -> str:
    pattern = str(pattern or "").strip()
    if not pattern:
        return "SOURCE_ERROR pattern is required"

    tree, error = _tree_or_error(kver, source_root)
    if tree is None:
        return f"SOURCE_ERROR {error}"

    try:
        regex = re.compile(pattern)
    except re.error:
        regex = re.compile(re.escape(pattern))

    limit = max(1, min(int(max_hits or 25), 80))
    hits: list[str] = []
    truncated = False
    for path in _iter_source_files(tree, prefix):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if not _is_probably_text(raw):
            continue
        text = raw.decode("utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if regex.search(line) is None:
                continue
            hits.append(f"{relative_name(tree, path)}:{number}: {_trim(line)}")
            if len(hits) >= limit:
                truncated = True
                break
        if truncated:
            break

    header = (
        f"{_status_block(tree)}\n"
        f"SOURCE_GREP pattern={pattern} hits={len(hits)} "
        f"truncated={str(truncated).lower()}"
    )
    return "\n".join([header, *hits]) if hits else f"{header}\n(no match)"


def list_writers_impl(
    field: str,
    kver: str = "",
    max_hits: int = 30,
    prefix: str = "drivers",
    source_root: str = "",
) -> str:
    raw_field = str(field or "").strip()
    if not raw_field:
        return "SOURCE_ERROR field is required"
    member = re.split(r"->|\.|\s+", raw_field)[-1].strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", member):
        return f"SOURCE_ERROR invalid field name: {raw_field!r}"

    tree, error = _tree_or_error(kver, source_root)
    if tree is None:
        return f"SOURCE_ERROR {error}"

    assignment = re.compile(
        r"(?:->|\.)\s*"
        + re.escape(member)
        + r"\s*(?:\+\+|--|=(?!=)|\+=|-=|\*=|/=|\|=|&=|\^=|<<=|>>=)"
    )
    constructor = re.compile(
        r"\b(?:memset|memcpy|memmove|WRITE_ONCE|READ_ONCE|atomic_set|"
        r"cmpxchg|strncpy|strscpy)\s*\([^;\n]*(?:->|\.)\s*"
        + re.escape(member)
        + r"\b"
    )
    needle = member.encode()

    limit = max(1, min(int(max_hits or 30), 80))
    hits: list[tuple[int, str]] = []
    truncated = False
    for path in _iter_source_files(tree, prefix):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if needle not in raw:  # cheap pre-filter before decoding
            continue
        if not _is_probably_text(raw):
            continue
        text = raw.decode("utf-8", errors="replace")
        rel = relative_name(tree, path)
        rank = 0 if rel.startswith("drivers/") else 1
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith(("*", "/*", "//")):
                continue
            if assignment.search(line) is None and constructor.search(line) is None:
                continue
            hits.append((rank, f"{rel}:{number}: {_trim(line)}"))
            if len(hits) >= limit:
                truncated = True
                break
        if truncated:
            break

    hits.sort(key=lambda item: item[0])
    lines = [item[1] for item in hits]
    header = (
        f"{_status_block(tree)}\n"
        f"SOURCE_WRITERS field={member} hits={len(lines)} "
        f"truncated={str(truncated).lower()}\n"
        "guidance=each hit is a candidate writer; confirm which one the runtime "
        "value is consistent with before naming a source"
    )
    return "\n".join([header, *lines]) if lines else f"{header}\n(no match)"


def git_history_impl(
    file: str,
    kver: str = "",
    start_line: int = 0,
    end_line: int = 0,
    max_commits: int = 5,
    source_root: str = "",
) -> str:
    tree, error = _tree_or_error(kver, source_root)
    if tree is None:
        return f"SOURCE_ERROR {error}"
    if not (tree.root / ".git").exists():
        return (
            "SOURCE_ERROR no .git in the configured source tree; commit history "
            "and backport status cannot be verified (do not guess them)"
        )

    try:
        path = resolve_relative_file(tree, file)
    except SourceTreeError as exc:
        return f"SOURCE_ERROR {exc}"

    rel = relative_name(tree, path)
    limit = max(1, min(int(max_commits or 5), 20))
    start_line, end_line = int(start_line or 0), int(end_line or 0)
    command = [
        "git",
        "-C",
        str(tree.root),
        "--no-pager",
        "log",
        "--no-color",
        "--date=short",
        "--format=%h %ad %s",
    ]
    if start_line > 0 and end_line >= start_line:
        # `-L` already names the path; adding a pathspec next to it is invalid.
        command.append(f"-L{start_line},{end_line}:{rel}")
        command.append(f"--max-count={limit}")
    else:
        command.extend([f"--max-count={limit}", "--", rel])

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"SOURCE_ERROR git failed: {exc}"

    if completed.returncode != 0:
        detail = (completed.stderr or "").strip() or "unknown git error"
        return f"SOURCE_ERROR git exited {completed.returncode}: {_trim(detail, 400)}"

    output = (completed.stdout or "").strip() or "(no commits for this path/range)"
    header = (
        f"{_status_block(tree)}\n"
        f"SOURCE_GIT file={rel} range={start_line}-{end_line}"
    )
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[:MAX_OUTPUT_CHARS] + "\n[truncated]"
    return f"{header}\n{output}"


_STRUCT_DECL_RE = re.compile(r"^\s*struct\s+(?P<name>[A-Za-z_]\w*)\b")


def _code_without_comments(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """Strip C comments and string/char literals from one line.

    Brace counting on raw text ends the definition early at a ``}`` inside a
    comment or a string literal. Only code braces may affect nesting depth.
    """

    out: list[str] = []
    index = 0
    length = len(line)
    in_string = False
    in_char = False

    while index < length:
        char = line[index]
        following = line[index + 1] if index + 1 < length else ""

        if in_block_comment:
            if char == "*" and following == "/":
                in_block_comment = False
                index += 2
                continue
            index += 1
            continue

        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue

        if in_char:
            if char == "\\":
                index += 2
                continue
            if char == "'":
                in_char = False
            index += 1
            continue

        if char == "/" and following == "*":
            in_block_comment = True
            index += 2
            continue
        if char == "/" and following == "/":
            break
        if char == '"':
            in_string = True
            index += 1
            continue
        if char == "'":
            in_char = True
            index += 1
            continue

        out.append(char)
        index += 1

    return "".join(out), in_block_comment


def find_struct_impl(
    type_name: str,
    kver: str = "",
    prefix: str = "",
    source_root: str = "",
    max_lines: int = 120,
) -> str:
    """Return the full definition body of one struct type in a single hop.

    Looking up a member name normally costs a grep followed by a read; the
    definition itself answers every member question at once, so this tool
    exists to remove that alternation.
    """

    name = str(type_name or "").strip().strip("'\"")
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return f"SOURCE_ERROR invalid struct type name: {type_name!r}"

    tree, error = _tree_or_error(kver, source_root)
    if tree is None:
        return f"SOURCE_ERROR {error}"

    limit = max(10, min(int(max_lines or 120), 400))
    needle = name.encode()

    def _scan(path: Path) -> Optional[str]:
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        if needle not in raw or not _is_probably_text(raw):
            return None

        lines = raw.decode("utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines):
            decl = _STRUCT_DECL_RE.match(line)
            if decl is None or decl.group("name") != name:
                continue
            # The opening brace may sit on the next line (kernel style allows both).
            # Detect it on comment-stripped code so a "{ /* } */" comment cannot
            # masquerade as the body.
            code_line, decl_block = _code_without_comments(line, False)
            if "{" in code_line:
                brace_index = index
                start_in_block = False
            elif index + 1 < len(lines) and "{" in _code_without_comments(
                lines[index + 1], decl_block
            )[0]:
                brace_index = index + 1
                start_in_block = decl_block
            else:
                continue

            body: list[str] = []
            depth = 0
            in_block_comment = start_in_block
            for offset in range(brace_index, min(len(lines), brace_index + limit)):
                current = lines[offset]
                code, in_block_comment = _code_without_comments(
                    current, in_block_comment
                )
                depth += code.count("{") - code.count("}")
                body.append(f"{offset + 1:6d}| {current}")
                if depth <= 0:
                    break

            rel = relative_name(tree, path)
            header = (
                f"{_status_block(tree)}\n"
                f"SOURCE_STRUCT type={name} file={rel} "
                f"lines={brace_index + 1}-{brace_index + len(body)}\n"
                f"SOURCE_REF: {rel}:{index + 1}\n"
            )
            output = header + "\n".join(body)
            if len(body) >= limit:
                output += "\n[truncated: definition longer than max_lines]"
            return output
        return None

    # Headers first: almost every kernel struct is defined in a .h file.
    for wanted in ({".h"}, {".c", ".cc", ".S"}):
        for path in _iter_source_files(tree, prefix):
            if path.suffix not in wanted:
                continue
            found = _scan(path)
            if found is not None:
                return found

    return (
        f"SOURCE_ERROR struct {name} not found in the configured tree; "
        "try grep_source with the member name or a broader prefix"
    )