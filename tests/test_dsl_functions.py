"""DSL 函数子集测试（P2-2：白名单求值器 + 嵌套 + 安全边界）"""

import pytest

from src.xiazhi.matcher import MatcherEngine, Matcher


@pytest.fixture
def engine():
    return MatcherEngine()


def _dsl(engine, expr, body="", status=200, headers=None):
    m = Matcher(type="dsl", dsl=[expr])
    return engine.match(m, status, headers or {}, body)[0]


class TestDslFunctions:
    def test_contains_function(self, engine):
        assert _dsl(engine, 'contains(body, "admin")', body="hello admin panel") is True
        assert _dsl(engine, 'contains(body, "admin")', body="hello user panel") is False

    def test_icontains(self, engine):
        assert _dsl(engine, 'icontains(body, "ADMIN")', body="admin") is True

    def test_to_lower_nested(self, engine):
        # 嵌套: to_lower(base64(body)) contains "xxx"
        import base64
        b64 = base64.b64encode(b"Hello Admin").decode()
        assert _dsl(engine, f'contains(to_lower(base64_decode("{b64}")), "admin")') is True

    def test_len_comparison(self, engine):
        assert _dsl(engine, "len(body) > 10", body="x" * 20) is True
        assert _dsl(engine, "len(body) > 100", body="x" * 20) is False

    def test_status_code(self, engine):
        assert _dsl(engine, "status_code == 200", status=200) is True
        assert _dsl(engine, "status_code == 404", status=200) is False

    def test_and_combination(self, engine):
        expr = 'status_code == 200 && contains(body, "ok")'
        assert _dsl(engine, expr, body="ok body", status=200) is True
        assert _dsl(engine, expr, body="no match", status=200) is False
        assert _dsl(engine, expr, body="ok body", status=500) is False

    def test_or_combination(self, engine):
        expr = 'status_code == 500 || contains(body, "error")'
        assert _dsl(engine, expr, body="error!", status=200) is True
        assert _dsl(engine, expr, body="fine", status=200) is False

    def test_md5_sha256(self, engine):
        import hashlib
        h = hashlib.md5(b"admin").hexdigest()
        assert _dsl(engine, f'md5("admin") == "{h}"') is True
        h2 = hashlib.sha256(b"admin").hexdigest()
        assert _dsl(engine, f'sha256("admin") == "{h2}"') is True

    def test_base64_function(self, engine):
        assert _dsl(engine, 'base64("hello") == "aGVsbG8="') is True
        assert _dsl(engine, 'base64_decode("aGVsbG8=") == "hello"') is True

    def test_rand_int_in_range(self, engine):
        assert _dsl(engine, "rand_int(1, 5) >= 1 && rand_int(1, 5) <= 5")

    def test_starts_ends_with(self, engine):
        assert _dsl(engine, 'starts_with(body, "HTTP")', body="HTTP/1.1 ok") is True
        assert _dsl(engine, 'ends_with(body, "ok")', body="HTTP/1.1 ok") is True


class TestDslSafety:
    def test_unknown_function_does_not_match(self, engine):
        # 未知函数保持原样 → 布尔求值 False（不误报）
        assert _dsl(engine, 'exec("rm -rf /")') is False

    def test_dangerous_keywords_blocked(self, engine):
        assert _dsl(engine, "import os") is False
        assert _dsl(engine, "__import__('os').system('x')") is False
        assert _dsl(engine, "getattr(sys, 'x')") is False

    def test_malformed_expr_false(self, engine):
        assert _dsl(engine, "to_lower(") is False
        assert _dsl(engine, "") is False

    def test_nested_depth_limit(self, engine):
        # 超深嵌套不崩溃
        assert _dsl(engine, "to_lower(to_upper(to_lower(to_upper('x'))))") is True

    def test_quoted_comma_in_args(self, engine):
        assert _dsl(engine, 'replace(body, "a,b", "c") == "c"', body="a,b") is True
