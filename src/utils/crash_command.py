#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared normalization for single-command crash tool calls.

The structured action schema stores only ``command_name`` + ``arguments``; the
arguments never repeat the command name.  Execution, evidence extraction and
validation must prepend the subcommand identically, otherwise validation sees a
hex address as the command name and silently skips every per-command rule.
"""

from __future__ import annotations

from typing import Iterable

# Generic wrapper tools whose command already carries a concrete subcommand.
GENERIC_TOOL_NAMES = frozenset({"crash"})


def with_tool_prefix(tool_name: str, command: str) -> str:
    """Return ``tool_name command`` unless it already starts with the tool name.

    ``run_script`` lines are complete commands and the generic ``crash``
    wrapper keeps its payload untouched; both are returned unchanged.
    """

    tool = str(tool_name or "").strip()
    text = str(command or "").strip()
    if not text or not tool or tool == "run_script" or tool in GENERIC_TOOL_NAMES:
        return text
    first = text.split(maxsplit=1)[0]
    if first.lower() == tool.lower():
        return text
    return f"{tool} {text}".strip()


def normalize_command_lines(tool_name: str, lines: Iterable[str]) -> list[str]:
    """Apply :func:`with_tool_prefix` to every command line."""

    return [with_tool_prefix(tool_name, line) for line in lines]