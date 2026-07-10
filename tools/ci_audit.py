#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破晓 · CI 数据治理审计脚本 (P1-1 / D1)
=====================================

职责：
  1. CVE 库治理  —— 校验 `src/dawn/cve_match.py` 中 `BUILTIN_VULNS` 的
     计数 / 唯一性 / 撞号 / 字段完整性 / 组件分布。
  2. 模板治理    —— 遍历 `templates/` 下所有 YAML，校验可解析、必填字段、
     模板 id 唯一性，并在存在基线 checksum 文件时做篡改检测（安全 A08）。

设计原则（见升级方案 §三 Phase 1 / §六.5）：
  * **计数作指标，非门禁** —— 不硬编码 257 / 215 为失败断言，
    避免 Phase 3 社区模板同步致基线漂移误杀 CI。
  * 唯一性 / 撞号 / 字段缺失 / YAML 损坏 / id 冲突 才是硬性失败。

退出码：0 = 通过；1 = 存在硬性错误（用于 CI 红/绿判定）。

用法：
  python tools/ci_audit.py
  python tools/ci_audit.py --src-dir . --templates-dir templates
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import yaml
except ImportError:  # 纯 CVE 审计不强制依赖 yaml
    yaml = None  # type: ignore


# ── 允许的值域 ──
CVE_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CVE_REQUIRED_FIELDS = {"component", "cve", "severity", "cvss", "description", "affected", "fixed"}
TPL_SEVERITIES = {"critical", "high", "medium", "low", "info"}
TPL_REQUIRED_TOP = {"id", "info"}


class AuditResult:
    """累计审计结果"""

    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.metrics: Dict[str, Any] = {}

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def ok(self) -> bool:
        return not self.errors


# ──────────────────────────────────────────────────────────────────────────
# 1. CVE 库审计
# ──────────────────────────────────────────────────────────────────────────
def _extract_builtin_vulns(cve_file: Path) -> List[dict]:
    """用 ast 解析 BUILTIN_VULNS 字面量，避免 import 触发重型依赖"""
    tree = ast.parse(cve_file.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "BUILTIN_VULNS":
                    return ast.literal_eval(node.value)  # type: ignore[no-any-return]
    return []


def audit_cves(cve_file: Path, result: AuditResult) -> None:
    if not cve_file.exists():
        result.error(f"[CVE] 找不到文件: {cve_file}")
        return

    try:
        vulns = _extract_builtin_vulns(cve_file)
    except Exception as e:  # 解析失败时整项失败
        result.error(f"[CVE] 解析 BUILTIN_VULNS 失败: {e}")
        return

    result.metrics["cve_total"] = len(vulns)

    # 字段完整性
    bad_fields: List[str] = []
    for i, v in enumerate(vulns):
        if not isinstance(v, dict):
            bad_fields.append(f"条目#{i} 非 dict")
            continue
        missing = CVE_REQUIRED_FIELDS - set(v.keys())
        if missing:
            bad_fields.append(f"CVE={v.get('cve', '?')} 缺字段 {sorted(missing)}")
    if bad_fields:
        for b in bad_fields:
            result.error(f"[CVE] 字段不完整: {b}")

    # 唯一性 / 撞号
    ids = [v.get("cve") for v in vulns if isinstance(v, dict) and v.get("cve")]
    dup = [k for k, c in Counter(ids).items() if c > 1]
    if dup:
        result.error(f"[CVE] 存在撞号(重复 CVE-id): {sorted(dup)}")
    result.metrics["cve_unique"] = len(set(ids))

    # 非法严重级别（告警）
    bad_sev = [
        v.get("cve")
        for v in vulns
        if isinstance(v, dict) and v.get("severity", "").upper() not in CVE_SEVERITIES
    ]
    if bad_sev:
        result.warn(f"[CVE] 未知严重级别: {bad_sev}")

    # 组件分布（指标）
    comp = Counter(v.get("component", "?") for v in vulns if isinstance(v, dict))
    result.metrics["cve_components"] = dict(comp.most_common())


# ──────────────────────────────────────────────────────────────────────────
# 2. 模板审计
# ──────────────────────────────────────────────────────────────────────────
def _iter_yaml(templates_dir: Path):
    yield from sorted(templates_dir.rglob("*.yaml"))
    yield from sorted(templates_dir.rglob("*.yml"))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def audit_templates(templates_dir: Path, result: AuditResult) -> None:
    if not templates_dir.exists():
        result.error(f"[TPL] 找不到目录: {templates_dir}")
        return

    if yaml is None:
        result.warn("[TPL] PyYAML 未安装，跳过模板解析校验（仅统计文件数）")
        result.metrics["tpl_files"] = sum(1 for _ in _iter_yaml(templates_dir))
        return

    tpl_ids: List[Tuple[str, str]] = []  # (id, relpath)
    parse_errors: List[str] = []
    field_errors: List[str] = []
    sev_warns: List[str] = []
    count = 0

    for yml in _iter_yaml(templates_dir):
        count += 1
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception as e:
            parse_errors.append(f"{yml.name}: {e}")
            continue
        if not isinstance(raw, dict):
            parse_errors.append(f"{yml.name}: 顶层非映射")
            continue

        tid = raw.get("id")
        if not tid:
            field_errors.append(f"{yml.name}: 缺 id")
            continue
        tpl_ids.append((str(tid), str(yml.relative_to(templates_dir))))

        info = raw.get("info")
        if not isinstance(info, dict):
            field_errors.append(f"{yml.name}: 缺 info 块")
        else:
            sev = str(info.get("severity", "info")).lower()
            if sev not in TPL_SEVERITIES:
                sev_warns.append(f"{tid}: 未知 severity={sev}")

        requests = raw.get("http", raw.get("requests"))
        if not requests:
            # 非 HTTP 协议模板（telnet/ftp/rdp/smb/smtp/ssh/dns 等）
            # 不在 HTTP loader 范围，按告警处理而非硬性失败
            result.warn(f"[TPL] {tid}: 无 http/requests 块（非 HTTP 协议模板？）")

    result.metrics["tpl_files"] = count
    result.metrics["tpl_valid"] = len(tpl_ids)

    # 模板 id 唯一性 / 撞号
    rel = Counter(i for i, _ in tpl_ids)
    dup = [k for k, c in rel.items() if c > 1]
    if dup:
        result.error(f"[TPL] 模板 id 撞号: {sorted(dup)}")

    for e in parse_errors:
        result.error(f"[TPL] YAML 解析失败: {e}")
    for e in field_errors:
        result.error(f"[TPL] 字段缺失: {e}")
    for w in sev_warns:
        result.warn(f"[TPL] {w}")

    # checksum 基线（若存在则比对，用于篡改检测 A08）
    baseline = templates_dir / ".checksums.sha256"
    if baseline.exists():
        expected = {}
        for line in baseline.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            h, _, p = line.partition("  ")
            if p:
                expected[p] = h
        mism: List[str] = []
        checked = 0
        for yml in _iter_yaml(templates_dir):
            relp = str(yml.relative_to(templates_dir))
            actual = _sha256(yml)
            checked += 1
            if relp in expected and expected[relp] != actual:
                mism.append(relp)
        result.metrics["tpl_checksum_checked"] = checked
        if mism:
            result.error(f"[TPL] checksum 不一致(疑似篡改): {mism}")


# ──────────────────────────────────────────────────────────────────────────
# 报告
# ──────────────────────────────────────────────────────────────────────────
def _print_report(result: AuditResult) -> None:
    print("=" * 60)
    print("POXIAO CI DATA GOVERNANCE AUDIT / 破晓 CI 数据治理审计")
    print("=" * 60)

    m = result.metrics
    print(f"\n[METRIC] CVE entries total: {m.get('cve_total', '?')}  | unique IDs: {m.get('cve_unique', '?')}")
    if "cve_components" in m:
        comp = m["cve_components"]
        print(f"[METRIC] CVE component spread: {len(comp)} components, top5 = {list(comp.items())[:5]}")
    print(f"[METRIC] template files: {m.get('tpl_files', '?')}  | parseable valid: {m.get('tpl_valid', '?')}")
    if "tpl_checksum_checked" in m:
        print(f"[METRIC] checksum compared: {m['tpl_checksum_checked']} files")

    if result.warnings:
        print(f"\n[WARNING] {len(result.warnings)} item(s)")
        for w in result.warnings:
            print(f"  - {w}")

    if result.errors:
        print(f"\n[FAIL] {len(result.errors)} hard error(s)")
        for e in result.errors:
            print(f"  [x] {e}")
        print("\nRESULT: FAIL (exit 1)")
    else:
        print("\nRESULT: PASS (exit 0)")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="破晓 CI 数据治理审计")
    parser.add_argument("--src-dir", default=".", help="仓库根目录 (默认 .)")
    parser.add_argument("--cve-file", default="src/dawn/cve_match.py", help="含 BUILTIN_VULNS 的文件")
    parser.add_argument("--templates-dir", default="templates", help="模板目录")
    args = parser.parse_args(argv)

    root = Path(args.src_dir)
    result = AuditResult()

    audit_cves(root / args.cve_file, result)
    audit_templates(root / args.templates_dir, result)

    _print_report(result)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
