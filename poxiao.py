#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破晓 — Bug Bounty 自动化工具链
CLI 入口脚本
"""
import sys
import os

# Windows 强制 UTF-8
if sys.platform == "win32":
    # 设置控制台代码页
    os.system("chcp 65001 >nul 2>&1")
    # 设置环境变量
    os.environ["PYTHONIOENCODING"] = "utf-8"
    # 重新配置标准流
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")

# 确保 src 目录在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.cli import main

if __name__ == "__main__":
    main()
