"""POCEngine 纯逻辑单元测试（变量展开 / 端口提取 / 统计 / 结果输出）"""

import json

import pytest

from src.xiazhi.poc_engine import POCEngine
from src.xiazhi.template import MatchResult


@pytest.fixture
def engine():
    return POCEngine()


class TestExpandVariables:
    def test_no_placeholder_returns_asis(self, engine):
        assert engine._expand_variables("plain text", {"A": "1"}) == "plain text"

    def test_none_text(self, engine):
        assert engine._expand_variables(None, {"A": "1"}) is None

    def test_empty_text(self, engine):
        assert engine._expand_variables("", {"A": "1"}) == ""

    def test_replaces_named_variables(self, engine):
        text = "{{BaseURL}}/path/{{Hostname}}"
        out = engine._expand_variables(text, {"BaseURL": "http://x", "Hostname": "x"})
        assert out == "http://x/path/x"

    def test_replaces_partial_name_does_not_clobber(self, engine):
        # 变量名是另一个变量名的子串时不应错误替换
        out = engine._expand_variables("{{Port}}", {"Port": "8080", "Ports": "9999"})
        assert out == "8080"


class TestResolveRuntimeVars:
    def test_randstr_resolves(self, engine):
        out = engine._resolve_runtime_vars("tok={{randstr}}")
        assert out.startswith("tok=")
        assert len(out) == len("tok=") + 8
        assert out[4:].isalnum()

    def test_randbase64_resolves(self, engine):
        import base64
        out = engine._resolve_runtime_vars("x={{randbase64}}")
        payload = out.split("=", 1)[1]
        # 应能解码为原始随机串
        decoded = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode()
        assert len(decoded) == 12

    def test_timestamp_resolves(self, engine):
        out = engine._resolve_runtime_vars("t={{timestamp}}")
        assert out.startswith("t=")
        assert out[2:].isdigit()

    def test_no_runtime_var_untouched(self, engine):
        assert engine._resolve_runtime_vars("no vars here") == "no vars here"


class TestExtractPort:
    def test_with_port(self, engine):
        assert engine._extract_port("http://example.com:8080/foo") == "8080"

    def test_https_default_443(self, engine):
        assert engine._extract_port("https://example.com/path") == "443"

    def test_http_default_80(self, engine):
        assert engine._extract_port("http://example.com/path") == "80"

    def test_no_scheme_default_80(self, engine):
        # 无 scheme 时不解析端口，回退到 80（_extract_port 仅按 "://" 拆分）
        assert engine._extract_port("example.com:9000") == "80"


class TestCountBySeverity:
    def test_only_matched_counted(self, engine):
        results = [
            MatchResult(template_id="a", template_name="A", severity="high", matched=True),
            MatchResult(template_id="b", template_name="B", severity="high", matched=True),
            MatchResult(template_id="c", template_name="C", severity="low", matched=True),
            MatchResult(template_id="d", template_name="D", severity="medium", matched=False),
        ]
        counts = engine._count_by_severity(results)
        assert counts == {"high": 2, "low": 1}

    def test_empty(self, engine):
        assert engine._count_by_severity([]) == {}


class TestSaveResults:
    def test_writes_json(self, engine, tmp_path):
        out = tmp_path / "sub" / "result.json"
        results = [
            MatchResult(template_id="a", template_name="A", severity="critical",
                        matched=True, url="http://x", request_url="http://x/1"),
            MatchResult(template_id="b", template_name="B", severity="info",
                        matched=False, error="boom"),
        ]
        saved = engine.save_results(results, str(out))
        assert saved == str(out)
        data = json.loads(Path_read(saved))
        assert data["total_findings"] == 2
        assert data["by_severity"] == {"critical": 1}
        # 只有 matched 的进入 findings
        assert len(data["findings"]) == 1
        assert data["findings"][0]["template_id"] == "a"

    def test_creates_parent_dir(self, engine, tmp_path):
        out = tmp_path / "nested" / "deep" / "r.json"
        engine.save_results([], str(out))
        assert out.exists()


class TestPrintResults:
    def test_empty(self, engine, capsys):
        engine.print_results([], target="http://x")
        captured = capsys.readouterr()
        assert "未发现漏洞" in captured.out

    def test_with_results(self, engine, capsys):
        results = [
            MatchResult(template_id="a", template_name="Log4j", severity="critical",
                        matched=True, request_url="http://x/a", response_status=200,
                        response_size=123, response_time=0.5, matcher_name="status 200",
                        extracted={"v": "1.2.3"}, description="RCE", tags=["rce", "java"]),
            MatchResult(template_id="b", template_name="B", severity="high",
                        matched=False, error="timeout"),
        ]
        engine.print_results(results, target="http://x")
        captured = capsys.readouterr()
        assert "发现" in captured.out
        assert "Log4j" in captured.out
        assert "http://x/a" in captured.out
        # 未匹配且有 error 的结果被跳过
        assert "timeout" not in captured.out

    def test_severity_sorting(self, engine, capsys):
        results = [
            MatchResult(template_id="low", template_name="L", severity="low", matched=True,
                        request_url="u", response_status=200, response_size=1, response_time=0.1),
            MatchResult(template_id="crit", template_name="C", severity="critical", matched=True,
                        request_url="u", response_status=200, response_size=1, response_time=0.1),
        ]
        engine.print_results(results)
        captured = capsys.readouterr()
        # critical 应排在 low 之前
        assert captured.out.index("C") < captured.out.index("L")


def Path_read(p):
    from pathlib import Path
    return Path(p).read_text(encoding="utf-8")
