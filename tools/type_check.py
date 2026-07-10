#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破晓 · 渐进式 mypy 门禁 (Phase 3 / P3-3 / D10 / R2)
=====================================================

渐进式类型化：仅对**已注解且零错误**的模块做关卡（非 --strict）。
全仓约 150+ 处类型错误，按 R2 修订逐模块收紧，不承诺近期全仓 --strict 零错误。

本脚本为门禁的**单一事实来源**：CI 与本地均调用它，避免文件列表漂移。

用法：
  python tools/type_check.py
  python tools/type_check.py --add src/foo/bar.py   # 临时追加模块
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

try:
    from mypy import api as mypy_api
except ImportError:  # pragma: no cover
    print("[type-check] mypy 未安装，跳过（CI 中需先 pip install mypy）")
    sys.exit(0)


# 渐进式门禁模块列表（已注解且零错误）。
# 新增模块前请先 `python -m mypy <模块>` 确认零错误，再登记于此。
CURATED_MODULES: List[str] = [
    # ── Phase 1 核心（P1-4 / R2）──
    "src/config.py",
    "src/utils/redline.py",
    "src/guanxing/db.py",
    "src/guanxing/web.py",
    # ── Phase 3 扩展（P3-3）──
    "src/utils/html_report.py",        # 纯 stdlib 报告引擎（Q5）
    "src/guanxing/notify.py",          # 本地 webhook + JSONL（X3/R4）
    "src/jingzhe/jingzhe.py",          # 漏洞验证核心（1 处注解补齐后零错误）
    "tools/gen_sbom.py",               # SBOM 生成（P3-1，自洽）
    "tools/template_sync.py",          # 模板工具链（P3-2，自洽）
]


def main(argv: List[str] | None = None) -> int:
    modules = list(CURATED_MODULES)
    if argv:
        modules.extend(argv)

    # 仅校验存在的文件
    modules = [m for m in modules if Path(m).exists()]
    if not modules:
        print("[type-check] 无可用模块")
        return 0

    result = mypy_api.run(["--ignore-missing-imports", "--show-error-codes"] + modules)
    stdout, stderr, rc = result

    if stdout:
        sys.stdout.write(stdout)
    if stderr:
        sys.stderr.write(stderr)

    if rc == 0:
        print(f"[type-check] PASS: {len(modules)} 模块零错误（渐进式，非 --strict）")
    else:
        print(f"[type-check] FAIL (exit {rc}): 上述模块存在类型错误")
    return rc


if __name__ == "__main__":
    sys.exit(main())
