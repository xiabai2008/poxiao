#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破晓 — Bug Bounty 自动化工具链
CLI 入口脚本
"""
import sys
import os

from src.utils.win_utf8 import fix_windows_utf8
fix_windows_utf8()

# 确保 src 目录在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.cli import main

if __name__ == "__main__":
    main()
