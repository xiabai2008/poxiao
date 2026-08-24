"""SARIF 2.1.0 报告生成（对齐行业标准，纯标准库）

从破晓扫描汇总（summary_*.json）生成 SARIF 2.1.0 文档，可直接导入
GitHub Code Scanning / GitLab SAST / VS Code SARIF Viewer。

映射规则:
  - CVE 匹配     → ruleId `cve/<CVE-ID>`，level 按严重级别
                   (critical/high → error, medium → warning, low/info → note)
  - 敏感路径发现 → ruleId `sensitive/<category>`，level=note/warning
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from src._version import VERSION

# SARIF 2.1.0 官方 schema
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "poxiao"
TOOL_VERSION = VERSION

# 严重级别 → SARIF level
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# 敏感路径类别 → SARIF level（默认 note，api/debug 等可升级）
_SENSITIVE_DEFAULT_LEVEL = {
    "config": "warning",
    "git": "warning",
    "source": "warning",
    "backup": "warning",
    "debug": "note",
    "admin": "note",
    "api": "note",
    "db": "warning",
    "swagger": "note",
    "actuator": "warning",
}


def _level_for_severity(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get((severity or "info").lower(), "note")


def _finding_rule(rule_id: str, level: str, name: str, description: str,
                  cve_id: str = "") -> Dict[str, Any]:
    """构造规则描述块（按 ruleId 去重）"""
    rule = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": description[:200]},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": level},
    }
    if cve_id:
        rule["properties"] = {"cve": cve_id, "tags": ["security", "cve"]}
    else:
        rule["properties"] = {"tags": ["security", "sensitive-path"]}
    return rule


def build_sarif(summary: Dict[str, Any]) -> Dict[str, Any]:
    """从扫描汇总构建 SARIF 2.1.0 文档

    Args:
        summary: `poxiao scan` 产出的 summary_*.json（含 targets 列表，
                每个 target 含 target_url/cve_matches/sensitive_paths 等）

    Returns:
        SARIF 2.1.0 文档 dict
    """
    targets = summary.get("targets", [])
    scan_time = summary.get("scan_time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    rule_index: Dict[str, int] = {}

    for t in targets:
        url = t.get("target_url", "")
        if not t.get("alive", False):
            continue

        # ── CVE 匹配 → results ──
        for cve in t.get("cve_matches", []):
            cve_id = cve.get("cve", "")
            if not cve_id:
                continue
            rule_id = f"cve/{cve_id}"
            severity = cve.get("severity", "info")
            desc = cve.get("description", "") or f"目标可能受 {cve_id} 影响"

            if rule_id not in rules:
                rules[rule_id] = _finding_rule(
                    rule_id,
                    _level_for_severity(severity),
                    cve_id,
                    desc,
                    cve_id=cve_id,
                )
            results.append({
                "ruleId": rule_id,
                "level": _level_for_severity(severity),
                "message": {"text": f"[{cve_id}] {desc}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": url},
                    }
                }],
                "partialFingerprints": {"cve": cve_id},
            })

        # ── 敏感路径 → results ──
        for p in t.get("sensitive_paths", []):
            category = p.get("category", "unknown")
            rule_id = f"sensitive/{category}"
            purl = p.get("url", url)

            if rule_id not in rules:
                rules[rule_id] = _finding_rule(
                    rule_id,
                    _SENSITIVE_DEFAULT_LEVEL.get(category, "note"),
                    f"sensitive path: {category}",
                    f"敏感路径/信息泄露: {category}（{purl}）",
                )
            results.append({
                "ruleId": rule_id,
                "level": _SENSITIVE_DEFAULT_LEVEL.get(category, "note"),
                "message": {"text": f"敏感路径 {category}: {purl} [HTTP {p.get('status','?')}]"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": purl},
                    }
                }],
            })

    # 按 ruleId 稳定排序规则
    ordered_rule_ids = sorted(rules.keys())
    for idx, rid in enumerate(ordered_rule_ids):
        rule_index[rid] = idx

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/xiabai2008/poxiao",
                    "rules": [rules[rid] for rid in ordered_rule_ids],
                }
            },
            "automationDetails": {
                "id": summary.get("session_id", ""),
                "description": {"text": f"破晓扫描 {scan_time}（{len(targets)} 目标）"},
            },
            "results": results,
            "properties": {
                "scanTime": scan_time,
                "totalTargets": len(targets),
            },
        }],
    }


def write_sarif(summary: Dict[str, Any], output_path: str) -> str:
    """生成 SARIF 文档并写入文件，返回文件路径"""
    doc = build_sarif(summary)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(path)
