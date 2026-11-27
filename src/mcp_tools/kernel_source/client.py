#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# client.py - Kernel Source MCP 客户端实现
"""MCP client for the kernel_source provider.

The provider is discovered automatically by ``src.mcp_tools.registry`` because
this package contains a ``client.py`` exposing the standard provider API.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, List, Optional

from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient

from src.utils.logging import logger

from .arguments import map_positional, split_command

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
    """Map a crash-style token list onto the tool's named parameters."""

    return map_positional(tool_name, split_command(command))


_KS_STR_FIELDS: dict[str, frozenset[str]] = {
    "read_source": frozenset({"file", "kver"}),
    "grep_source": frozenset({"pattern", "kver", "prefix"}),
    "list_writers": frozenset({"field", "kver", "prefix"}),
    "git_history": frozenset({"file", "kver"}),
    "find_struct": frozenset({"type_name", "kver", "prefix", "field_filter"}),
}
_KS_INT_FIELDS: dict[str, frozenset[str]] = {
    "read_source": frozenset({"line", "context", "start_line", "end_line"}),
    "grep_source": frozenset({"max_hits"}),
    "list_writers": frozenset({"max_hits"}),
    "git_history": frozenset({"start_line", "end_line", "max_commits"}),
    "find_struct": frozenset({"max_lines"}),
}


def _validate_and_coerce_payload(tool_name: str, payload: dict[str, object]) -> None:
    """Pre-validate parameter types before MCP dispatch and coerce numeric strings to int."""
    str_fields = _KS_STR_FIELDS.get(tool_name, frozenset())
    int_fields = _KS_INT_FIELDS.get(tool_name, frozenset())
    range_hint = (
        " Call read_source once per file (or use start_line/end_line for a line range)."
        if tool_name == "read_source"
        else f" Call {tool_name} once per target with scalar arguments."
    )

    for key in list(payload.keys()):
        val = payload[key]
        if key in str_fields:
            if isinstance(val, (list, tuple, dict, set)):
                raise ValueError(
                    f"{tool_name} parameter '{key}' must be a single string, not {type(val).__name__}.{range_hint}"
                )
            if not isinstance(val, str):
                payload[key] = str(val)
        elif key in int_fields:
            if isinstance(val, bool) or isinstance(val, (list, tuple, dict, set)):
                raise ValueError(
                    f"{tool_name} parameter '{key}' must be a single integer, not {type(val).__name__}.{range_hint}"
                )
            if isinstance(val, str):
                stripped = val.strip()
                if stripped.lstrip("+-").isdigit():
                    payload[key] = int(stripped)
                else:
                    raise ValueError(
                        f"{tool_name} parameter '{key}' must be an integer, got {val!r}.{range_hint}"
                    )
            elif not isinstance(val, int):
                raise ValueError(
                    f"{tool_name} parameter '{key}' must be an integer, got {type(val).__name__}.{range_hint}"
                )

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
        if key == "module_source_roots":
            continue  # runtime-owned; derived from debug_symbol_paths
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        payload[str(key)] = value

    if "command" in payload:
        mapped = _map_positional_command(tool_name, payload.pop("command"))
        for key, value in mapped.items():
            payload.setdefault(key, value)

    _validate_and_coerce_payload(tool_name, payload)

    source_root = str(state.get("kernel_source_root") or "").strip()
    if source_root:
        payload["source_root"] = source_root

    # Inject module source roots derived from debug_symbol_paths.
    # These allow read_source to handle absolute paths from third-party module
    # DWARF info (dis -s prints the compile-time source path of .ko modules).
    # The model never controls these paths: they come from the analysis request.
    debug_symbol_paths = state.get("debug_symbol_paths")
    if debug_symbol_paths and tool_name in ("read_source", "grep_source", "source_status"):
        from .resolver import derive_module_source_roots

        roots = derive_module_source_roots(list(debug_symbol_paths))
        if roots:
            payload["module_source_roots"] = ",".join(str(r) for r in roots)

    return payload


# Module-level list kept for parity with the other providers.
kernel_source_tools: List = []