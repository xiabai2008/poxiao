"""POC 匹配器 — 补充覆盖（binary / dsl / 边界 / _get_target / match_all）"""

import pytest

from src.xiazhi.matcher import MatcherEngine, Matcher


@pytest.fixture
def engine():
    return MatcherEngine()


class TestGetTarget:
    def test_header_part(self, engine):
        t = engine._get_target("header", 200, {"Server": "nginx"}, "body", b"")
        assert "Server: nginx" in t

    def test_all_part(self, engine):
        t = engine._get_target("all", 200, {"Server": "nginx"}, "body", b"")
        assert "Server: nginx" in t and "body" in t and "body" in t


class TestUnknownType:
    def test_unknown(self, engine):
        m = Matcher(type="bogus")
        matched, desc = engine.match(m, 200, {}, "")
        assert matched is False
        assert "Unknown" in desc


class TestEmptyMatchers:
    def test_word_no_words(self, engine):
        m = Matcher(type="word", words=[])
        assert engine.match(m, 200, {}, "x")[0] is False

    def test_status_no_status(self, engine):
        m = Matcher(type="status", status=[])
        assert engine.match(m, 200, {}, "")[0] is False

    def test_regex_no_regex(self, engine):
        m = Matcher(type="regex", regex=[])
        assert engine.match(m, 200, {}, "x")[0] is False

    def test_regex_invalid_pattern(self, engine):
        m = Matcher(type="regex", regex=["(["])
        assert engine.match(m, 200, {}, "x")[0] is False

    def test_size_no_size(self, engine):
        m = Matcher(type="size", size=[])
        assert engine.match(m, 200, {}, "x")[0] is False

    def test_dsl_no_dsl(self, engine):
        m = Matcher(type="dsl", dsl=[])
        assert engine.match(m, 200, {}, "x")[0] is False

    def test_binary_no_binary(self, engine):
        m = Matcher(type="binary", binary=[])
        assert engine.match(m, 200, {}, "x")[0] is False

    def test_header_no_header(self, engine):
        m = Matcher(type="header", header="")
        assert engine.match(m, 200, {}, "x")[0] is False


class TestSizeVariants:
    def test_single_size(self, engine):
        m = Matcher(type="size", size=[5])
        assert engine.match(m, 200, {}, "hello")[0] is True

    def test_three_size(self, engine):
        m = Matcher(type="size", size=[1, 2, 3])
        assert engine.match(m, 200, {}, "ab")[0] is True


class TestDSL:
    def test_contains(self, engine):
        m = Matcher(type="dsl", dsl=["body contains admin"])
        assert engine.match(m, 200, {}, "welcome admin")[0] is True

    def test_in(self, engine):
        m = Matcher(type="dsl", dsl=["'admin' in body"])
        assert engine.match(m, 200, {}, "welcome admin")[0] is True

    def test_ge(self, engine):
        m = Matcher(type="dsl", dsl=["status_code >= 200"])
        assert engine.match(m, 200, {}, "")[0] is True

    def test_le(self, engine):
        m = Matcher(type="dsl", dsl=["status_code <= 200"])
        assert engine.match(m, 200, {}, "")[0] is True

    def test_boolean_true(self, engine):
        m = Matcher(type="dsl", dsl=["true"])
        assert engine.match(m, 200, {}, "")[0] is True


class TestBinary:
    def test_match(self, engine):
        m = Matcher(type="binary", binary=["68656c6c6f"])
        assert engine.match(m, 200, {}, "hello world")[0] is True

    def test_no_match(self, engine):
        m = Matcher(type="binary", binary=["deadbeef"])
        assert engine.match(m, 200, {}, "hello")[0] is False

    def test_invalid_hex(self, engine):
        m = Matcher(type="binary", binary=["zz"])
        assert engine.match(m, 200, {}, "hello")[0] is False


class TestNegativeHeader:
    def test_negative_missing(self, engine):
        m = Matcher(type="header", header="X-Missing", negative=True)
        assert engine.match(m, 200, {}, "x")[0] is True


class TestMatchAll:
    def test_or_all_fail(self, engine):
        matchers = [
            Matcher(type="status", status=[200]),
            Matcher(type="word", words=["admin"]),
        ]
        matched, desc = engine.match_all(matchers, "or", 404, {}, "hello")
        assert matched is False
        assert "no matchers" in desc

    def test_and_fail_description(self, engine):
        matchers = [Matcher(type="status", status=[200])]
        matched, desc = engine.match_all(matchers, "and", 404, {}, "")
        assert matched is False
        assert "failed" in desc
