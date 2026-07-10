#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破晓 · POC 模板工具链 (Phase 3 / P3-2 / D1 / X1)
=================================================

提供可独立运行的 Nuclei 模板运维 CLI，与 `ci_audit.py`（CI 硬门禁）互补：
  * `validate <dir|file>` —— 单文件/目录的 Nuclei 字段校验（不修改任何模板）。
  * `diff <dirA> <dirB>`   —— 两目录按相对路径 + 内容 sha256 比对，输出
                            added / removed / modified 清单与计数；
                            **差异作指标，不判失败**（用于社区模板增量同步，守 X1）。

设计原则（升级方案 §六.5）：模板同步必然产生 added/modified，
**绝不硬编码 215 为失败断言**，计数仅报告。

用法：
  python tools/template_sync.py validate templates
  python tools/template_sync.py validate templates/default-logins/jenkins-default-login.yaml
  python tools/template_sync.py diff templates community-templates
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


TPL_SEVERITIES = {"critical", "high", "medium", "low", "info"}
TPL_REQUIRED_TOP = {"id", "info"}


def _iter_yaml(d: Path):
    if d.is_file():
        yield d
        return
    yield from sorted(d.rglob("*.yaml"))
    yield from sorted(d.rglob("*.yml"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_path(target: Path) -> Dict[str, Any]:
    """校验单个文件或目录，返回结构化结果（不修改模板）。"""
    res: Dict[str, Any] = {
        "target": str(target),
        "files": 0,
        "valid": 0,
        "field_errors": [],
        "parse_errors": [],
        "sev_warns": [],
    }
    if not target.exists():
        res["parse_errors"].append(f"路径不存在: {target}")
        return res

    for yml in _iter_yaml(target):
        res["files"] += 1
        if yaml is None:
            res["parse_errors"].append("PyYAML 未安装，无法解析校验")
            continue
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception as e:
            res["parse_errors"].append(f"{yml.name}: {e}")
            continue
        if not isinstance(raw, dict):
            res["parse_errors"].append(f"{yml.name}: 顶层非映射")
            continue

        tid = raw.get("id")
        if not tid:
            res["field_errors"].append(f"{yml.name}: 缺 id")
            continue
        res["valid"] += 1

        info = raw.get("info")
        if not isinstance(info, dict):
            res["field_errors"].append(f"{yml.name}: 缺 info 块")
        elif not info.get("name"):
            res["field_errors"].append(f"{tid}: info.name 缺失")
        else:
            sev = str(info.get("severity", "info")).lower()
            if sev not in TPL_SEVERITIES:
                res["sev_warns"].append(f"{tid}: 未知 severity={sev}")

        if not raw.get("http") and not raw.get("requests"):
            res["sev_warns"].append(f"{tid}: 无 http/requests 块（非 HTTP 协议模板？）")
    return res


def diff_dirs(dir_a: Path, dir_b: Path) -> Dict[str, Any]:
    """比对 dirA 与 dirB，返回 added/removed/modified（相对路径）。"""
    def _index(d: Path) -> Dict[str, str]:
        idx: Dict[str, str] = {}
        if not d.exists():
            return idx
        for yml in _iter_yaml(d):
            idx[str(yml.relative_to(d))] = _sha256(yml)
        return idx

    a = _index(dir_a)
    b = _index(dir_b)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    modified = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    return {
        "dir_a": str(dir_a),
        "dir_b": str(dir_b),
        "counts": {"a": len(a), "b": len(b), "added": len(added), "removed": len(removed), "modified": len(modified)},
        "added": added,
        "removed": removed,
        "modified": modified,
    }


def _print_validate(res: Dict[str, Any]) -> None:
    print(f"[validate] {res['target']}")
    print(f"  files={res['files']}  valid={res['valid']}")
    for e in res["parse_errors"]:
        print(f"  [parse-error] {e}")
    for e in res["field_errors"]:
        print(f"  [field-error] {e}")
    for w in res["sev_warns"]:
        print(f"  [warn] {w}")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="破晓 POC 模板工具链")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("validate", help="校验模板字段（不修改）")
    pv.add_argument("target", help="模板文件或目录")

    pd = sub.add_parser("diff", help="两目录模板差异比对（差异非错误）")
    pd.add_argument("dir_a")
    pd.add_argument("dir_b")
    pd.add_argument("--json", default=None, help="将 diff 结果写入 JSON")

    args = parser.parse_args(argv)

    if args.cmd == "validate":
        res = validate_path(Path(args.target))
        _print_validate(res)
        # 校验失败判定：解析错误 / 字段缺失
        if res["parse_errors"] or res["field_errors"]:
            print("RESULT: FAIL (exit 1)")
            return 1
        print("RESULT: PASS (exit 0)")
        return 0

    if args.cmd == "diff":
        d = diff_dirs(Path(args.dir_a), Path(args.dir_b))
        c = d["counts"]
        print(f"[diff] {d['dir_a']}  vs  {d['dir_b']}")
        print(f"  A={c['a']}  B={c['b']}  added={c['added']}  removed={c['removed']}  modified={c['modified']}")
        for p in d["added"]:
            print(f"  [+] {p}")
        for p in d["removed"]:
            print(f"  [-] {p}")
        for p in d["modified"]:
            print(f"  [~] {p}")
        if args.json:
            Path(args.json).write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"  diff json -> {args.json}")
        # diff 始终视为成功：差异是同步指标，非错误（守 X1）
        print("RESULT: OK (exit 0, 差异作指标)")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
