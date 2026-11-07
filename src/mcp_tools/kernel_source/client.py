#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# client.py - Kernel Source MCP 客户端实现
"""MCP client for the kernel_source provider.

The provider is discovered automatically by ``src.mcp_tools.registry`` because
this package contains a ``client.py`` exposing the standard provider API.
"""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path
from typing import Any, List, Optional

from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient

from src.utils.logging import logger

# Positional argument order accepted when the model emits a crash-style token
# list instead of structured ``parameters`` (legacy action shape).
_POSITIONAL_FIELDS: dict[str, tuple[str, ...]] = {
    "read_source": ("file", "line", "kver"),
    "git_history": ("file", "start_line", "end_line"),
    "list_writers": ("field",),
    "grep_source": ("pattern",),
}

MCP_SERVER_NAME = "kernel_source"

# The MCP stdio transport inherits only a small allowlist of environment
# variables, so KERNEL_SOURCE_ROOT has to be forwarded explicitly.  Load .env
# here as well: this module may be imported before src.utils.settings runs.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(_PROJECT_ROOT / ".env", override=False)
_SERVER_ENV = dict(os.environ)

kernel_source_client = MultiServerMCPClient(
    {
        MCP_SERVER_NAME: {
            "command": sys.executable,
            "args": ["-m", "src.mcp_tools.kernel_source.server"],
            "transport": "stdio",
            "env": _SERVER_ENV,
        }
    }
)
MCP_CLIENT = kernel_source_client

_source_tools: Optional[List] = None


async def _initialize_tools() -> List:
    global _source_tools
    if _source_tools is not None:
        return _source_tools

    try:
        logger.info("Initializing kernel_source MCP tools...")
        _source_tools = await kernel_source_client.get_tools()
        logger.info(
            "Successfully initialized %d kernel_source tools.\n\t%s",
            len(_source_tools),
            "\n\t".join(f"{tool.name}: {tool.description}" for tool in _source_tools),
        )
        return _source_tools
    except Exception as exc:  # pragma: no cover - depends on subprocess startup
        logger.error("Failed to get tools from kernel_source MCP client: %s", exc)
        _source_tools = []
        return []


async def initialize_tools() -> List:
    return await _initialize_tools()


def _map_positional_command(tool_name: str, command: Any) -> dict[str, object]:
    """Map a crash-style token list onto the tool's named parameters.

    The analysis action schema historically renders every non-``run_script``
    action as ``{"command": "<tokens>"}``.  Kernel-source tools need named
    arguments, so accept that legacy shape positionally and reject anything that
    cannot be mapped unambiguously.
    """

    fields = _POSITIONAL_FIELDS.get(tool_name)
    if not fields:
        return {}

    try:
        tokens = shlex.split(str(command or ""))
    except ValueError:
        tokens = str(command or "").split()
    if not tokens:
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
        integer_field = name in {"line", "start_line", "end_line"}
        mapped[name] = int(token) if integer_field and token.isdigit() else token
    return mapped


def build_tool_payload(
    tool_name: str, raw_args: Any, state: dict[str, object]
) -> dict[str, object]:
    """Forward the model's arguments and inject the per-request source root.

    Accepts both call shapes:

    * ``{"file": ..., "line": ...}`` — produced by the ``parameters`` field of the
      action schema (preferred);
    * ``{"command": "drivers/net/foo.c 1203"}`` — legacy token list, mapped
      positionally by ``_map_positional_command``.

    Empty strings are dropped so the server-side defaults apply.  Numeric zeros
    are preserved on purpose (``line=0`` means "read from the top of the file").

    ``source_root`` always comes from the analysis request, never from the model:
    a model-chosen filesystem path would turn these tools into an arbitrary file
    reader.  When the request carries no path, the key is dropped and the server
    falls back to ``KERNEL_SOURCE_ROOT``.
    """

    if not isinstance(raw_args, dict):
        raise ValueError(
            f"{tool_name} requires a JSON object of arguments, got {type(raw_args).__name__}"
        )

    payload: dict[str, object] = {}
    for key, value in raw_args.items():
        if key == "source_root":
            continue  # runtime-owned; never let the model choose a path
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        payload[str(key)] = value

    if "command" in payload:
        mapped = _map_positional_command(tool_name, payload.pop("command"))
        for key, value in mapped.items():
            payload.setdefault(key, value)

    source_root = str(state.get("kernel_source_root") or "").strip()
    if source_root:
        payload["source_root"] = source_root
    return payload


# Module-level list kept for parity with the other providers.
kernel_source_tools: List = []