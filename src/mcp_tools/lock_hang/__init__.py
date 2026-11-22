#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __init__.py - Lock Hang MCP 工具包
# Author: CalmWU
# Created: 2026-11-22

"""Lock & Hang (Deadlock / Lockup / RCU Stall) MCP 工具包。

提供确定性的锁等待依赖图（Wait-For Graph）构建、死锁环检测以及多核 Lockup / RCU Stall 聚合分析。
不要在包级别导入 client，避免 server 入口在模块解析阶段递归创建 MCP client。
"""
