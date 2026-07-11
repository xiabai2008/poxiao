"""User-Agent 池单元测试"""

import pytest

from src.xiazhi.user_agents import UserAgentPool, CHROME_UAS, MOBILE_UAS, FIREFOX_UAS, SAFARI_UAS, EDGE_UAS


@pytest.fixture
def pool():
    return UserAgentPool()


class TestGet:
    def test_category_returns_valid(self, pool):
        for c in ("chrome", "firefox", "safari", "edge", "mobile", "cn"):
            assert pool.get(c) in pool.CATEGORIES[c]

    def test_random(self, pool):
        ua = pool.get("random")
        assert isinstance(ua, str) and len(ua) > 0

    def test_get_mobile(self, pool):
        assert pool.get_mobile() in MOBILE_UAS

    def test_get_desktop(self, pool):
        assert pool.get_desktop() in CHROME_UAS + FIREFOX_UAS + SAFARI_UAS + EDGE_UAS

    def test_unknown_category_falls_back(self, pool):
        # 未知分类回退到 chrome 池
        assert pool.get("nope") in pool.CATEGORIES["chrome"]


class TestMatchingHeaders:
    def test_chrome_windows(self, pool):
        h = pool.get_matching_headers(CHROME_UAS[0])
        assert h["User-Agent"] == CHROME_UAS[0]
        assert "Sec-Ch-Ua" in h
        assert h["Sec-Ch-Ua-Platform"] == '"Windows"'

    def test_safari_mac(self, pool):
        h = pool.get_matching_headers(SAFARI_UAS[0])
        assert h["User-Agent"] == SAFARI_UAS[0]
        # Safari 不发 Sec-Ch-Ua 系列请求头
        assert "Sec-Ch-Ua" not in h
        assert "Sec-Ch-Ua-Platform" not in h

    def test_edge(self, pool):
        h = pool.get_matching_headers(EDGE_UAS[0])
        assert "Microsoft Edge" in h["Sec-Ch-Ua"]

    def test_firefox_no_sec(self, pool):
        h = pool.get_matching_headers(FIREFOX_UAS[0])
        assert "Sec-Ch-Ua" not in h


class TestExtractPlatform:
    def test_android(self, pool):
        assert pool._extract_platform("Linux; Android 14") == '"Android"'

    def test_ios(self, pool):
        assert pool._extract_platform("iPhone") == '"iOS"'

    def test_linux(self, pool):
        assert pool._extract_platform("Linux x86_64") == '"Linux"'


class TestAllUas:
    def test_non_empty(self, pool):
        assert len(pool.all_uas()) > 0
