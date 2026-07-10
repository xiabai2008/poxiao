"""扫描结果 HTML 报告生成（P2-4 / D6 / Q5 / R3）

技术路线锁定 Q5：仅使用标准库（html + 字符串模板），不引入 Jinja2 / 任何模板引擎。
所有动态文本必须经 html.escape 转义，防止 XSS（对应 web.py 的 _esc 思路）。
"""

import html
from datetime import datetime
from typing import Any, Dict, List


def _tech_list(target: Dict[str, Any]) -> List[str]:
    """统一提取技术栈为字符串列表（兼容 dict / list / 其他）"""
    tech = target.get("tech", {}) or {}
    if isinstance(tech, dict):
        return [str(k) for k in tech.keys()]
    if isinstance(tech, list):
        return [str(x) for x in tech]
    return []


def _risk_level(target: Dict[str, Any]) -> str:
    """根据 CVE / 敏感路径计数粗略评估风险等级"""
    cve = len(target.get("cve_matches", []) or [])
    sens = len(target.get("sensitive_paths", []) or [])
    if cve > 0:
        return "高危"
    if sens > 0:
        return "中危"
    return "低危"


_RISK_COLOR = {
    "高危": "#dc3545",
    "中危": "#ffc107",
    "低危": "#198754",
}


def render_html_report(summary: Dict[str, Any]) -> str:
    """从扫描汇总 dict 生成可读 HTML 报告（纯标准库，动态字段全部转义）。

    summary 期望包含:
      - "targets": 列表，每项字段 target_url/url, alive, tech, sensitive_paths, cve_matches
      - 可选 "scan_time" / "timestamp"
    """
    targets = summary.get("targets", []) or []
    scan_time = summary.get("scan_time") or summary.get("timestamp") or ""

    rows: List[str] = []
    for t in targets:
        url = t.get("target_url") or t.get("url") or ""
        alive = "存活" if t.get("alive") else "不可达"
        techs = _tech_list(t)
        sens = len(t.get("sensitive_paths", []) or [])
        cves = len(t.get("cve_matches", []) or [])
        risk = _risk_level(t)
        color = _RISK_COLOR.get(risk, "#198754")
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(url))}</td>"
            f"<td>{html.escape(alive)}</td>"
            f"<td>{html.escape(', '.join(techs))}</td>"
            f"<td>{sens}</td>"
            f"<td>{cves}</td>"
            f'<td><span style="color:{color};font-weight:700">{html.escape(risk)}</span></td>'
            "</tr>"
        )

    rows_html = "".join(rows) if rows else (
        '<tr><td colspan="6" class="text-muted">无目标数据</td></tr>'
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>破晓 · 扫描报告</title>
<style>
body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 24px; color: #222; }}
h1 {{ font-size: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; font-size: 13px; }}
th {{ background: #f5f5f5; }}
.text-muted {{ color: #999; }}
</style>
</head>
<body>
<h1>破晓 · 扫描报告</h1>
<p class="text-muted">目标数: {len(targets)} | 生成时间: {html.escape(str(scan_time))}</p>
<table>
<thead><tr><th>目标</th><th>状态</th><th>技术栈</th><th>敏感路径</th><th>CVE</th><th>风险</th></tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>"""
