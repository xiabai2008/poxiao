"""Windows UTF-8 控制台修复工具"""

import sys
import os


def fix_windows_utf8():
    """在 Windows 下强制设置 UTF-8 编码"""
    if sys.platform != "win32":
        return

    # 设置控制台代码页
    os.system("chcp 65001 >nul 2>&1")  # nosec B605 B607 — 固定常量命令，无用户输入
    # 设置环境变量
    os.environ["PYTHONIOENCODING"] = "utf-8"
    # 重新配置标准流
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
