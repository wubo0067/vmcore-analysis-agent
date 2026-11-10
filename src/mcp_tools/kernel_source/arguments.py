#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# arguments.py - kernel_source 工具的位置参数映射（provider 与 action 解析共用）
"""Shared positional-argument mapping for kernel_source tools.

The analysis action schema has two arg shapes: structured ``parameters`` (used by
``build_tool_calls``) and a legacy crash-style token list.  Both the provider
payload builder and the run_script promotion path need the same token→field
mapping, so it lives here instead of being duplicated.
"""

from __future__ import annotations

import shlex

POSITIONAL_FIELDS: dict[str, tuple[str, ...]] = {
    "read_source": ("file", "line", "kver"),
    "git_history": ("file", "start_line", "end_line"),
    "list_writers": ("field",),
    "grep_source": ("pattern",),
    "find_struct": ("type_name", "kver", "prefix"),
}

_INTEGER_FIELDS = frozenset({"line", "start_line", "end_line"})


def split_command(command: object) -> list[str]:
    """Split a legacy command string into tokens, tolerating bad quoting."""

    try:
        return shlex.split(str(command or ""))
    except ValueError:
        return str(command or "").split()


def map_positional(tool_name: str, tokens: list[str]) -> dict[str, object]:
    """Map ordered tokens onto the tool's named parameters.

    Raises:
        ValueError: when the tool takes no positional form, or more tokens are
            supplied than it has parameters.  Callers translate this into a
            message telling the model to use ``parameters``.
    """

    fields = POSITIONAL_FIELDS.get(tool_name)
    if not fields:
        return {}
    if len(tokens) > len(fields):
        raise ValueError(
            f"{tool_name} accepts at most {len(fields)} positional value(s) "
            f"({', '.join(fields)}), got {len(tokens)} tokens: {tokens!r}. "
            "Use structured parameters instead, e.g. "
            f'{{"command_name": "{tool_name}", "parameters": '
            f'{{"{fields[0]}": "<value>"}}}}.'
        )

    mapped: dict[str, object] = {}
    for name, token in zip(fields, tokens):
        if name in _INTEGER_FIELDS and token.isdigit():
            mapped[name] = int(token)
        else:
            mapped[name] = token
    return mapped