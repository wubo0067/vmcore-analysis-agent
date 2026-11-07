#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# server.py - Kernel source MCP 服务器
"""MCP server exposing kernel-source tools to the analysis agent.

Tool bodies live in ``tools.py``; this module only declares the MCP surface
(names, parameter descriptions, docstrings) and delegates.
"""

from __future__ import annotations

from fastmcp import FastMCP

from .tools import (
    git_history_impl,
    grep_source_impl,
    list_writers_impl,
    read_source_impl,
    source_status_impl,
)

kernel_source_server = FastMCP(
    "kernel_source_server",
    instructions=(
        "Read the Linux kernel source tree that matches a vmcore. "
        "Use read_source/list_writers/grep_source to verify code paths instead of "
        "recalling kernel code from memory, and git_history to check whether this "
        "exact tree already carries a fix."
    ),
)


@kernel_source_server.tool()
def source_status(source_root: str = "") -> str:
    """Report which kernel source tree is configured (version, git availability).

    `source_root` is injected by the runtime from the analysis request
    (--kernel-source-root); do not set it yourself.

    Call this before the first source lookup. If it reports configured=false,
    source code cannot be verified for this dump: say so instead of quoting
    kernel code from memory.
    """

    return source_status_impl(source_root=source_root)


@kernel_source_server.tool()
def read_source(
    file: str,
    kver: str = "",
    line: int = 0,
    context: int = 20,
    source_root: str = "",
) -> str:
    """Read numbered kernel source around a file:line.

    Args:
        file: Path as printed by `dis -s`, relative to the kernel tree root
            (absolute paths are rejected). A trailing ":<line>" is accepted.
        kver: Exact KERNEL value from `sys`; the tree is rejected when it differs.
        line: Center line. 0 reads the beginning of the file.
        context: Lines before and after `line` (max 80).
        source_root: Injected by the runtime; do not set it yourself.

    The output starts with a SOURCE_REF line; quote that SOURCE_REF when citing
    the code in the analysis.
    """

    return read_source_impl(
        file=file, kver=kver, line=line, context=context, source_root=source_root
    )


@kernel_source_server.tool()
def grep_source(
    pattern: str,
    kver: str = "",
    max_hits: int = 25,
    prefix: str = "",
    source_root: str = "",
) -> str:
    """Search kernel source for a regex and return file:line matches.

    Use it to locate the condition, macro, or call site named in reasoning.
    `prefix` narrows the search to a subtree such as drivers/net.
    `source_root` is injected by the runtime; do not set it yourself.
    """

    return grep_source_impl(
        pattern=pattern,
        kver=kver,
        max_hits=max_hits,
        prefix=prefix,
        source_root=source_root,
    )


@kernel_source_server.tool()
def list_writers(
    field: str,
    kver: str = "",
    max_hits: int = 30,
    prefix: str = "drivers",
    source_root: str = "",
) -> str:
    """Enumerate source sites that assign to a struct field.

    Use it for field/register provenance: after identifying the faulting field,
    list the code paths that can write it, then test each candidate against the
    runtime value. Accepts `sk_state`, `sock->sk_state`, or `struct sock.sk_state`.
    `source_root` is injected by the runtime; do not set it yourself.
    """

    return list_writers_impl(
        field=field,
        kver=kver,
        max_hits=max_hits,
        prefix=prefix,
        source_root=source_root,
    )


@kernel_source_server.tool()
def git_history(
    file: str,
    kver: str = "",
    start_line: int = 0,
    end_line: int = 0,
    max_commits: int = 5,
    source_root: str = "",
) -> str:
    """Show commits that touched a file, or a line range within it.

    With start_line and end_line it uses `git log -L` (the history of that code
    block), which is how you check whether a fix is already present in this tree.
    `source_root` is injected by the runtime; do not set it yourself.
    """

    return git_history_impl(
        file=file,
        kver=kver,
        start_line=start_line,
        end_line=end_line,
        max_commits=max_commits,
        source_root=source_root,
    )


if __name__ == "__main__":
    kernel_source_server.run(transport="stdio", show_banner=False)