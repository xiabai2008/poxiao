"""国际化 (i18n / D13) 单元测试

核心设计：键即中文原文，未翻译时回退到原文，保证对既有中文输出零破坏。
"""

import importlib

import pytest

from src.i18n import _, set_locale, get_locale
from src.utils.output import Out
from src.dawn.src_reporter import SRCReporter
from src.utils.html_report import render_html_report


@pytest.fixture(autouse=True)
def _reset_locale():
    """每个测试后重置为中文，避免串扰"""
    yield
    set_locale("zh_CN")


class TestCore:
    def test_default_zh_returns_key(self):
        # 默认 zh_CN：_() 直接返回原文（即使该串有英文译文也不翻译）
        assert get_locale() == "zh_CN"
        assert _("成功") == "成功"
        assert _("任意未管理串") == "任意未管理串"

    def test_en_translates(self):
        set_locale("en")
        assert get_locale() == "en"
        assert _("成功") == "Success"
        assert _("严重") == "Critical"

    def test_en_fallback_unknown(self):
        set_locale("en")
        # 未登记的键回退为原文
        assert _("这个串没有英文") == "这个串没有英文"

    def test_aliases(self):
        assert set_locale("english") == "en"
        assert set_locale("中文") == "zh_CN"
        assert set_locale("zh_cn") == "zh_CN"
        assert set_locale("en_us") == "en"

    def test_env_var_resolution(self, monkeypatch):
        monkeypatch.setenv("POXIAO_LANG", "en")
        import src.i18n as i18n
        try:
            importlib.reload(i18n)
            assert i18n.get_locale() == "en"
            assert i18n._("成功") == "Success"
        finally:
            monkeypatch.delenv("POXIAO_LANG", raising=False)
            importlib.reload(i18n)
            i18n.set_locale("zh_CN")


class TestOutIntegration:
    def test_success_translated(self, capsys):
        set_locale("en")
        Out.success("成功")
        assert "Success" in capsys.readouterr().out

    def test_warning_translated(self, capsys):
        set_locale("en")
        Out.warning("警告")
        assert "Warning" in capsys.readouterr().out

    def test_zh_default_preserved(self, capsys):
        set_locale("zh_CN")
        Out.error("错误")
        assert "错误" in capsys.readouterr().out
        assert "Error" not in capsys.readouterr().out


class TestSrcReport:
    def test_vuln_report_english(self):
        set_locale("en")
        r = SRCReporter()
        report = r.generate_vuln_report(
            title="Test Vuln",
            severity="high",
            vuln_url="http://example.com/a",
            vuln_type="sqli",
            description="desc",
            steps=["step1", "step2"],
        )
        assert "Basic Information" in report
        assert "Severity" in report          # 危害等级 → Severity (butian)
        assert "Vulnerability Type" in report
        assert "SQL Injection" in report
        assert "Reproduction Steps" in report
        assert "Remediation Suggestion" in report
        # 中文标签不应出现（已翻译）
        assert "基本信息" not in report
        assert "修复建议" not in report

    def test_batch_index_english(self):
        set_locale("en")
        r = SRCReporter()
        result = r.generate_batch(
            scan_results=[{
                "host": "example.com",
                "target_url": "http://example.com",
                "cve_matches": [{"cve": "CVE-2021-44228", "severity": "CRITICAL", "description": "Log4j"}],
                "sensitive_paths": [],
                "tech_tags": [],
            }],
            output_dir="_i18n_test_reports",
            platform="butian",
        )
        index_text = open(result["index"], encoding="utf-8").read()
        assert "SRC Report Index" in index_text
        assert "Critical" in index_text
        # 清理生成的测试目录
        import shutil
        shutil.rmtree("_i18n_test_reports", ignore_errors=True)


class TestHtmlReport:
    def test_html_english(self):
        set_locale("en")
        html = render_html_report({
            "targets": [{
                "target_url": "http://example.com",
                "alive": True,
                "tech": {"nginx": {}},
                "sensitive_paths": [{}],
                "cve_matches": [],
            }],
            "scan_time": "2026-07-11",
        })
        assert 'lang="en"' in html
        assert "PoXiao · Scan Report" in html
        assert ">Target<" in html
        assert "Tech Stack" in html
        assert "Risk" in html
        assert "Medium" in html  # 该用例敏感路径>0 → 中危 → Medium

    def test_html_zh_default(self):
        set_locale("zh_CN")
        html = render_html_report({
            "targets": [{
                "target_url": "http://example.com",
                "alive": True,
                "tech": {},
                "sensitive_paths": [],
                "cve_matches": [],
            }],
            "scan_time": "2026",
        })
        assert 'lang="zh-CN"' in html
        assert "破晓 · 扫描报告" in html
        assert "目标" in html
