#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for logging configuration and duplicate-log prevention."""

from __future__ import annotations

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.mcp_tools.crash.client import crash_stdio_env
from src.utils.logging import setup_console_logger, setup_logger


class LoggingConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._agent_logger = logging.getLogger("vmcore_analysis_agent")
        self._saved_handlers = list(self._agent_logger.handlers)
        self._saved_level = self._agent_logger.level
        self._agent_logger.handlers.clear()

    def tearDown(self) -> None:
        for handler in list(self._agent_logger.handlers):
            if handler not in self._saved_handlers:
                handler.close()
        self._agent_logger.handlers[:] = self._saved_handlers
        self._agent_logger.setLevel(self._saved_level)

    def test_enable_file_false_does_not_raise_or_create_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_dir = Path(tmpdir) / "unused_logs"
            configured = setup_logger(log_dir=str(missing_dir), enable_file=False)
            self.assertFalse(missing_dir.exists())
            self.assertEqual(len(configured.handlers), 1)
            self.assertNotIsInstance(configured.handlers[0], logging.FileHandler)
            self.assertIsInstance(configured.handlers[0], logging.StreamHandler)
            self.assertIsNotNone(configured.handlers[0].formatter)

    def test_env_vmcore_log_to_file_zero_disables_file_handler(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_dir = Path(tmpdir) / "env_disabled_logs"
            with mock.patch.dict(os.environ, {"VMCORE_LOG_TO_FILE": "0"}):
                configured = setup_logger(log_dir=str(missing_dir))
            self.assertFalse(missing_dir.exists())
            self.assertEqual(len(configured.handlers), 1)
            self.assertNotIsInstance(configured.handlers[0], logging.FileHandler)

    def test_default_log_filename_matches_vmcore_agent_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                with mock.patch.dict(os.environ, {"VMCORE_LOG_TO_FILE": "1"}):
                    configured = setup_logger(log_dir=tmpdir)
                file_handlers = [
                    h
                    for h in configured.handlers
                    if isinstance(h, logging.FileHandler)
                ]
                self.assertEqual(len(file_handlers), 1)
                self.assertEqual(
                    Path(file_handlers[0].baseFilename).name, "vmcore-agent.log"
                )
                self.assertFalse((Path(tmpdir) / "va-agent.log").exists())
            finally:
                for h in list(self._agent_logger.handlers):
                    if h not in self._saved_handlers:
                        h.close()
                self._agent_logger.handlers.clear()

    def test_setup_console_logger_has_no_file_handler(self) -> None:
        name = "test_console_only_logger"
        console_logger = logging.getLogger(name)
        console_logger.handlers.clear()
        try:
            configured = setup_console_logger(name)
            self.assertEqual(len(configured.handlers), 1)
            self.assertNotIsInstance(configured.handlers[0], logging.FileHandler)
            self.assertIsInstance(configured.handlers[0], logging.StreamHandler)
        finally:
            for h in list(console_logger.handlers):
                h.close()
            console_logger.handlers.clear()

    def test_crash_stdio_env_forwards_vmcore_log_to_file(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"VMCORE_LOG_TO_FILE": "0", "REASONING_API_KEY": "secret"},
            clear=False,
        ):
            env = crash_stdio_env()
        self.assertEqual(env.get("VMCORE_LOG_TO_FILE"), "0")
        self.assertNotIn("REASONING_API_KEY", env)


if __name__ == "__main__":
    unittest.main()
