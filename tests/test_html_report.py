"""P2-4 HTML 报告单测：合法性 + 动态字段转义（防 XSS / Q5 锁定 stdlib）"""

import html

from src.utils.html_report import render_html_report


def _sample():
    return {
        "targets": [
            {
                "target_url": "http://example.com",
                "alive": True,
                "tech": {"nginx": "1.2", "php": "8.1"},
                "sensitive_paths": ["/admin", "/.env"],
                "cve_matches": [{"id": "CVE-2024-0001"}],
            },
            {
                "url": "http://dead.test",
                "alive": False,
                "tech": ["apache", "mysql"],
                "sensitive_paths": [],
                "cve_matches": [],
            },
        ],
        "scan_time": "2026-07-10 12:00:00",
    }


def test_legal_html_skeleton():
    doc = render_html_report(_sample())
    assert "<!DOCTYPE html>" in doc
    assert "<html" in doc
    assert "<table>" in doc
    assert "<thead>" in doc
    assert "破晓" in doc
    # 两个目标 -> 两行数据
    assert doc.count("<tr>") >= 3  # 表头 + 2 数据行（统计 <tr> 含闭合拆分无所谓）


def test_tech_list_dict_and_list():
    doc = render_html_report(_sample())
    assert "nginx" in doc and "php" in doc
    assert "apache" in doc and "mysql" in doc


def test_risk_levels_rendered():
    doc = render_html_report(_sample())
    assert "高危" in doc  # 第一个目标有 CVE
    assert "低危" in doc  # 第二个目标无 CVE/敏感路径


def test_dynamic_fields_escaped_script_injection():
    evil = {
        "targets": [
            {
                "target_url": '<script>alert("xss")</script>',
                "alive": True,
                "tech": {'<img src=x onerror=alert(1)>': "1"},
                "sensitive_paths": ['"><svg/onload=alert(2)>'],
                "cve_matches": [],
            }
        ],
        "scan_time": '<b>injected</b>',
    }
    doc = render_html_report(evil)
    # 注入的标签必须被转义：原始 <script> 不应原样出现
    assert "<script>alert" not in doc
    assert "<img src=x" not in doc
    assert "<svg/onload" not in doc
    assert "<b>injected</b>" not in doc
    # 转义后应以实体形式存在
    assert "&lt;script&gt;" in doc
    assert "&lt;b&gt;injected&lt;/b&gt;" in doc
    # 等价性：html.escape 后的字符串确实在输出中
    assert html.escape('<script>alert("xss")</script>') in doc


def test_empty_targets_no_crash():
    doc = render_html_report({"targets": [], "scan_time": ""})
    assert "无目标数据" in doc
    assert "<!DOCTYPE html>" in doc


def test_missing_summary_fields_no_crash():
    doc = render_html_report({})
    assert "<!DOCTYPE html>" in doc
