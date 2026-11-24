#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runtime settings loaded from environment variables and the project .env file.

配置来源统一为环境变量；项目根目录的 .env 仅作为本地开发的默认值，
进程环境变量优先（便于容器/CI 注入）。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"

# override=False：已存在的进程环境变量优先于 .env。
load_dotenv(_ENV_FILE, override=False)

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}

PARAM_PROFILES = ("deepseek", "openai")
_DEEPSEEK_EFFORTS = ("minimal", "low", "medium", "high", "max")
_STANDARD_EFFORTS = ("minimal", "low", "medium", "high", "xhigh")
CRASH_EXECUTION_MODES = ("daemon", "oneshot")

_logger = logging.getLogger(__name__)


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            f"Copy .env.example to .env and fill it in."
        )
    return value


def _optional(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


def _parse_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in _TRUE_VALUES:
        return True
    if raw in _FALSE_VALUES:
        return False
    raise RuntimeError(
        f"Invalid boolean value for {name}: {raw!r}; expected one of "
        f"{sorted(_TRUE_VALUES | _FALSE_VALUES)}."
    )


def _parse_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise RuntimeError(f"Invalid float value for {name}: {raw!r}") from exc


def _parse_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"Invalid integer value for {name}: {raw!r}") from exc
    if value < minimum:
        raise RuntimeError(
            f"Invalid integer value for {name}: {value}; expected >= {minimum}."
        )
    return value


@dataclass(frozen=True)
class Settings:
    """Validated runtime settings."""

    reasoning_api_key: str
    reasoning_base_url: str
    reasoning_model: str
    reasoning_thinking: str
    reasoning_effort: str
    reasoning_param_profile: str
    reasoning_temperature: float
    reasoning_context_window: int
    reasoning_max_output_tokens: int
    reasoning_min_thinking_output_tokens: int
    reasoning_history_keep: int
    langsmith_tracing: bool
    reasoning_length_failure_threshold: int = 2
    reasoning_degraded_max_output_tokens: int = 16_000
    reasoning_degraded_reasoning_effort: str = "low"
    reasoning_degraded_thinking: bool = False
    kernel_source_root: str = ""
    kernel_source_allowed_roots: str = ""
    # Persistent Crash Session Pool / Daemon settings (float/int types aligned with session_pool.py)
    crash_execution_mode: str = "daemon"
    crash_daemon_endpoint: str = "unix:///tmp/vmcore_crashd.sock"
    crash_pool_max_sessions: int = 4
    crash_pool_slots_per_vmcore: int = 1
    crash_pool_idle_ttl_sec: float = 900.0
    crash_command_timeout_sec: float = 180.0
    crash_startup_timeout_sec: float = 120.0

    @property
    def sends_thinking_field(self) -> bool:
        return self.reasoning_param_profile == "deepseek"

    @property
    def allowed_reasoning_efforts(self) -> tuple[str, ...]:
        return (
            _DEEPSEEK_EFFORTS
            if self.reasoning_param_profile == "deepseek"
            else _STANDARD_EFFORTS
        )

    def masked_summary(self) -> dict[str, Any]:
        """Return a log-safe view of the settings (never includes the API key)."""

        return {
            "reasoning_base_url": self.reasoning_base_url,
            "reasoning_model": self.reasoning_model,
            "reasoning_param_profile": self.reasoning_param_profile,
            "reasoning_thinking": self.reasoning_thinking,
            "reasoning_effort": self.reasoning_effort,
            "reasoning_temperature": self.reasoning_temperature,
            "reasoning_context_window": self.reasoning_context_window,
            "reasoning_max_output_tokens": self.reasoning_max_output_tokens,
            "reasoning_min_thinking_output_tokens": self.reasoning_min_thinking_output_tokens,
            "reasoning_history_keep": self.reasoning_history_keep,
            "langsmith_tracing": self.langsmith_tracing,
            "reasoning_length_failure_threshold": self.reasoning_length_failure_threshold,
            "reasoning_degraded_max_output_tokens": self.reasoning_degraded_max_output_tokens,
            "reasoning_degraded_reasoning_effort": self.reasoning_degraded_reasoning_effort,
            "reasoning_degraded_thinking": self.reasoning_degraded_thinking,
            "kernel_source_root": self.kernel_source_root,
            "kernel_source_allowed_roots": self.kernel_source_allowed_roots,
            "crash_execution_mode": self.crash_execution_mode,
            "crash_daemon_endpoint": self.crash_daemon_endpoint,
            "crash_pool_max_sessions": self.crash_pool_max_sessions,
            "crash_pool_slots_per_vmcore": self.crash_pool_slots_per_vmcore,
            "crash_pool_idle_ttl_sec": self.crash_pool_idle_ttl_sec,
            "crash_command_timeout_sec": self.crash_command_timeout_sec,
            "crash_startup_timeout_sec": self.crash_startup_timeout_sec,
        }


@lru_cache(maxsize=1)
def get_reasoning_model_name(default: str = "unknown") -> str:
    """Return the configured model name without requiring the full settings."""

    return os.environ.get("REASONING_MODEL", "").strip() or default


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load and validate settings once per process."""

    thinking = _optional("REASONING_THINKING", "disabled").lower()
    if thinking not in {"enabled", "disabled"}:
        raise RuntimeError(
            f"Invalid value for REASONING_THINKING: {thinking!r}; "
            "expected 'enabled' or 'disabled'."
        )

    profile = _optional("REASONING_PARAM_PROFILE", "deepseek").lower()
    if profile not in PARAM_PROFILES:
        raise RuntimeError(
            f"Invalid value for REASONING_PARAM_PROFILE: {profile!r}; "
            f"expected one of {', '.join(PARAM_PROFILES)}."
        )

    effort = _optional("REASONING_EFFORT", "max").lower()
    allowed_efforts = (
        _DEEPSEEK_EFFORTS if profile == "deepseek" else _STANDARD_EFFORTS
    )
    if effort not in allowed_efforts:
        raise RuntimeError(
            f"Invalid value for REASONING_EFFORT: {effort!r} is not supported by "
            f"REASONING_PARAM_PROFILE={profile!r}; expected one of "
            f"{', '.join(allowed_efforts)}."
        )

    # 与 executor.get_crash_execution_mode() 保持一致：非法值降级为 warning + fallback，不拖垮启动
    crash_mode = _optional("CRASH_EXECUTION_MODE", "daemon").lower()
    if crash_mode not in CRASH_EXECUTION_MODES:
        if crash_mode == "pool":
            _logger.warning(
                "CRASH_EXECUTION_MODE='pool' has been removed; falling back to 'daemon'."
            )
        else:
            _logger.warning(
                "Invalid CRASH_EXECUTION_MODE=%r; falling back to 'daemon'.", crash_mode
            )
        crash_mode = "daemon"

    context_window = _parse_int("REASONING_CONTEXT_WINDOW", 524_288, 1)
    max_output_tokens = _parse_int("REASONING_MAX_OUTPUT_TOKENS", 48_000, 1)
    min_thinking_output_tokens = _parse_int(
        "REASONING_MIN_THINKING_OUTPUT_TOKENS", 40_960, 1
    )
    if max_output_tokens < min_thinking_output_tokens:
        raise RuntimeError(
            "REASONING_MAX_OUTPUT_TOKENS must be >= "
            "REASONING_MIN_THINKING_OUTPUT_TOKENS."
        )

    return Settings(
        reasoning_api_key=_require("REASONING_API_KEY"),
        reasoning_base_url=_require("REASONING_BASE_URL"),
        reasoning_model=_require("REASONING_MODEL"),
        reasoning_thinking=thinking,
        reasoning_effort=effort,
        reasoning_param_profile=profile,
        reasoning_temperature=_parse_float("REASONING_TEMPERATURE", 0.1),
        reasoning_context_window=context_window,
        reasoning_max_output_tokens=max_output_tokens,
        reasoning_min_thinking_output_tokens=min_thinking_output_tokens,
        reasoning_history_keep=_parse_int("REASONING_HISTORY_KEEP", 2, 0),
        langsmith_tracing=_parse_bool("LANGSMITH_TRACING", False),
        reasoning_length_failure_threshold=_parse_int(
            "REASONING_LENGTH_FAILURE_THRESHOLD", 2, 0
        ),
        reasoning_degraded_max_output_tokens=_parse_int(
            "REASONING_DEGRADED_MAX_OUTPUT_TOKENS", 16_000, 1
        ),
        reasoning_degraded_reasoning_effort=_optional(
            "REASONING_DEGRADED_REASONING_EFFORT", "low"
        ).lower(),
        reasoning_degraded_thinking=_parse_bool("REASONING_DEGRADED_THINKING", False),
        kernel_source_root=_optional("KERNEL_SOURCE_ROOT", ""),
        kernel_source_allowed_roots=_optional("KERNEL_SOURCE_ALLOWED_ROOTS", ""),
        crash_execution_mode=crash_mode,
        crash_daemon_endpoint=_optional(
            "CRASH_DAEMON_ENDPOINT", "unix:///tmp/vmcore_crashd.sock"
        ),
        crash_pool_max_sessions=_parse_int("CRASH_POOL_MAX_SESSIONS", 4, 1),
        crash_pool_slots_per_vmcore=_parse_int("CRASH_POOL_SLOTS_PER_VMCORE", 1, 1),
        crash_pool_idle_ttl_sec=_parse_float("CRASH_POOL_IDLE_TTL_SEC", 900.0),
        crash_command_timeout_sec=_parse_float("CRASH_COMMAND_TIMEOUT_SEC", 180.0),
        crash_startup_timeout_sec=_parse_float("CRASH_STARTUP_TIMEOUT_SEC", 120.0),
    )
