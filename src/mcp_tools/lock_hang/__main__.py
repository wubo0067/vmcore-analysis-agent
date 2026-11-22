#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __main__.py - Lock Hang MCP 服务入口
# Author: CalmWU
# Created: 2026-11-22

from .server import lock_hang_server

if __name__ == "__main__":
    lock_hang_server.run(transport="stdio", show_banner=False)
