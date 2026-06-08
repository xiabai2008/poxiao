"""POC 匹配器测试"""

import pytest
from src.poc.matcher import MatcherEngine, Matcher


@pytest.fixture
def engine():
    return MatcherEngine()


class TestWordMatcher:
    """关键词匹配测试"""

    def test_word_found(self, engine):
        m = Matcher(type="word", words=["admin", "login"])
        matched, desc = engine.match(m, 200, {}, "Welcome admin panel")
        assert matched is True

    def test_word_not_found(self, engine):
        m = Matcher(type="word", words=["admin"])
        matched, desc = engine.match(m, 200, {}, "Hello world")
        assert matched is False

    def test_word_case_insensitive(self, engine):
        m = Matcher(type="word", words=["ADMIN"], case_sensitive=False)
        matched, desc = engine.match(m, 200, {}, "admin panel")
        assert matched is True

    def test_word_case_sensitive(self, engine):
        m = Matcher(type="word", words=["ADMIN"], case_sensitive=True)
        matched, desc = engine.match(m, 200, {}, "admin panel")
        assert matched is False

    def test_multiple_words_or(self, engine):
        m = Matcher(type="word", words=["admin", "login"], condition="or")
        matched, desc = engine.match(m, 200, {}, "Welcome admin")
        assert matched is True

    def test_multiple_words_and(self, engine):
        m = Matcher(type="word", words=["admin", "login"], condition="and")
        matched, desc = engine.match(m, 200, {}, "Welcome admin")
        assert matched is False

    def test_word_in_header(self, engine):
        m = Matcher(type="word", words=["nginx"], part="header")
        matched, desc = engine.match(m, 200, {"Server": "nginx/1.0"}, "body")
        assert matched is True


class TestStatusMatcher:
    """状态码匹配测试"""

    def test_status_match(self, engine):
        m = Matcher(type="status", status=[200])
        matched, desc = engine.match(m, 200, {}, "")
        assert matched is True

    def test_status_mismatch(self, engine):
        m = Matcher(type="status", status=[200])
        matched, desc = engine.match(m, 404, {}, "")
        assert matched is False

    def test_multiple_status(self, engine):
        m = Matcher(type="status", status=[200, 301, 302])
        matched, desc = engine.match(m, 301, {}, "")
        assert matched is True


class TestRegexMatcher:
    """正则匹配测试"""

    def test_regex_match(self, engine):
        m = Matcher(type="regex", regex=[r"version\s*:\s*\d+"])
        matched, desc = engine.match(m, 200, {}, "version: 123")
        assert matched is True

    def test_regex_no_match(self, engine):
        m = Matcher(type="regex", regex=[r"version\s*:\s*\d+"])
        matched, desc = engine.match(m, 200, {}, "no version here")
        assert matched is False

    def test_multiple_regex_or(self, engine):
        m = Matcher(type="regex", regex=[r"admin", r"root"], condition="or")
        matched, desc = engine.match(m, 200, {}, "user: root")
        assert matched is True


class TestSizeMatcher:
    """大小匹配测试"""

    def test_size_match(self, engine):
        m = Matcher(type="size", size=[100, 200])
        matched, desc = engine.match(m, 200, {}, "x" * 150)
        assert matched is True

    def test_size_too_small(self, engine):
        m = Matcher(type="size", size=[100, 200])
        matched, desc = engine.match(m, 200, {}, "x" * 50)
        assert matched is False

    def test_size_too_large(self, engine):
        m = Matcher(type="size", size=[100, 200])
        matched, desc = engine.match(m, 200, {}, "x" * 250)
        assert matched is False


class TestHeaderMatcher:
    """响应头匹配测试"""

    def test_header_present(self, engine):
        m = Matcher(type="header", header="Server")
        matched, desc = engine.match(m, 200, {"Server": "nginx"}, "body")
        assert matched is True

    def test_header_value(self, engine):
        m = Matcher(type="header", header="Server", header_value="nginx")
        matched, desc = engine.match(m, 200, {"Server": "nginx/1.0"}, "body")
        assert matched is True

    def test_header_not_present(self, engine):
        m = Matcher(type="header", header="X-Custom")
        matched, desc = engine.match(m, 200, {"Server": "nginx"}, "body")
        assert matched is False


class TestDSLMAtcher:
    """DSL 匹配测试"""

    def test_dsl_status_eq(self, engine):
        m = Matcher(type="dsl", dsl=["status_code == 200"])
        matched, desc = engine.match(m, 200, {}, "test")
        assert matched is True

    def test_dsl_status_neq(self, engine):
        m = Matcher(type="dsl", dsl=["status_code != 200"])
        matched, desc = engine.match(m, 200, {}, "test")
        assert matched is False

    def test_dsl_contains(self, engine):
        m = Matcher(type="dsl", dsl=["body contains admin"])
        matched, desc = engine.match(m, 200, {}, "welcome admin")
        assert matched is True

    def test_dsl_in(self, engine):
        m = Matcher(type="dsl", dsl=["'admin' in body"])
        matched, desc = engine.match(m, 200, {}, "welcome admin")
        assert matched is True

    def test_dsl_dangerous_blocked(self, engine):
        """危险表达式应该被阻止"""
        m = Matcher(type="dsl", dsl=['__import__("os").system("calc")'])
        matched, desc = engine.match(m, 200, {}, "test")
        assert matched is False

    def test_dsl_exec_blocked(self, engine):
        """exec 注入应该被阻止"""
        m = Matcher(type="dsl", dsl=['exec("import os")'])
        matched, desc = engine.match(m, 200, {}, "test")
        assert matched is False


class TestNegativeMatcher:
    """取反匹配测试"""

    def test_negative_word(self, engine):
        m = Matcher(type="word", words=["admin"], negative=True)
        matched, desc = engine.match(m, 200, {}, "hello world")
        assert matched is True

    def test_negative_status(self, engine):
        m = Matcher(type="status", status=[200], negative=True)
        matched, desc = engine.match(m, 404, {}, "")
        assert matched is True


class TestMatcherCombination:
    """组合匹配测试"""

    def test_and_condition(self, engine):
        matchers = [
            Matcher(type="status", status=[200]),
            Matcher(type="word", words=["admin"]),
        ]
        matched, desc = engine.match_all(matchers, "and", 200, {}, "admin panel")
        assert matched is True

    def test_and_condition_fail(self, engine):
        matchers = [
            Matcher(type="status", status=[200]),
            Matcher(type="word", words=["admin"]),
        ]
        matched, desc = engine.match_all(matchers, "and", 404, {}, "admin panel")
        assert matched is False

    def test_or_condition(self, engine):
        matchers = [
            Matcher(type="status", status=[200]),
            Matcher(type="word", words=["admin"]),
        ]
        matched, desc = engine.match_all(matchers, "or", 404, {}, "admin panel")
        assert matched is True

    def test_empty_matchers(self, engine):
        matched, desc = engine.match_all([], "and", 200, {}, "test")
        assert matched is True
