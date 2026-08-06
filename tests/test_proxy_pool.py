"""代理池单元测试（xiazhi/proxy_pool.py）— mock HTTP，覆盖纯逻辑与验证

低 ROI 模块（基线 26%）覆盖率提升：ProxyInfo 解析/评分、ProxyPool 加载/选取/
反馈/统计/验证（mock httpx）。
"""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.xiazhi.proxy_pool import ProxyInfo, ProxyPool


# ── 异步客户端 mock ────────────────────────────────────────

class _FakeAsyncResp:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json


class _FakeAsyncClient:
    def __init__(self, status_code=200, json_data=None, raise_exc=None):
        self._status = status_code
        self._json = json_data
        self._exc = raise_exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        if self._exc is not None:
            raise self._exc
        return _FakeAsyncResp(self._status, self._json)


def _patch_client(status=200, json_data=None, raise_exc=None):
    fake = _FakeAsyncClient(status_code=status, json_data=json_data,
                            raise_exc=raise_exc)
    return patch("src.xiazhi.proxy_pool.httpx.AsyncClient",
                 return_value=fake)


# ── ProxyInfo 解析 ─────────────────────────────────────────

class TestProxyInfo:
    def test_parse_http(self):
        p = ProxyInfo(url="http://1.2.3.4:8080")
        assert p.protocol == "http"
        assert p.host == "1.2.3.4"
        assert p.port == 8080

    def test_parse_https(self):
        p = ProxyInfo(url="https://9.9.9.9:3128")
        assert p.protocol == "https"
        assert p.host == "9.9.9.9"
        assert p.port == 3128

    def test_parse_socks5(self):
        p = ProxyInfo(url="socks5://5.6.7.8:1080")
        assert p.protocol == "socks5"
        assert p.host == "5.6.7.8"
        assert p.port == 1080

    def test_parse_auth(self):
        p = ProxyInfo(url="http://user:pass@1.2.3.4:8080")
        assert p.username == "user"
        assert p.password == "pass"
        assert p.host == "1.2.3.4"

    def test_parse_default_port(self):
        p = ProxyInfo(url="http://1.2.3.4")  # 无端口
        assert p.port == 8080  # 默认

    def test_parse_garbage_no_crash(self):
        p = ProxyInfo(url="http://")  # 解析失败不应抛异常，host 保持空
        assert p.host == ""

    def test_success_rate(self):
        p = ProxyInfo(url="http://1.2.3.4:8080")
        assert p.success_rate == 0.0
        p.success_count = 8
        p.fail_count = 2
        assert p.success_rate == 0.8

    def test_score_dead_is_zero(self):
        p = ProxyInfo(url="http://1.2.3.4:8080", alive=False)
        assert p.score == 0.0

    def test_score_alive_bonus(self):
        p = ProxyInfo(url="http://1.2.3.4:8080", alive=True,
                      success_count=10, fail_count=0, latency=0.1)
        assert p.score > 0

    def test_score_consecutive_fail_penalty(self):
        p = ProxyInfo(url="http://1.2.3.4:8080", alive=True,
                      success_count=1, fail_count=1, consecutive_fails=3)
        # 连续失败惩罚应拉低评分
        low = p.score
        p2 = ProxyInfo(url="http://1.2.3.4:8080", alive=True,
                       success_count=1, fail_count=1, consecutive_fails=0)
        assert low < p2.score

    def test_to_dict(self):
        p = ProxyInfo(url="http://1.2.3.4:8080", alive=True, latency=0.2)
        d = p.to_dict()
        assert d["url"] == "http://1.2.3.4:8080"
        assert d["protocol"] == "http"
        assert d["alive"] is True
        assert "score" in d and "success_rate" in d


# ── 加载 ───────────────────────────────────────────────────

class TestProxyPoolLoad:
    def test_load_from_list(self):
        pool = ProxyPool()
        n = pool.load_from_list(["1.2.3.4:8080", "5.6.7.8:1080"])
        assert n == 2
        assert len(pool.proxies) == 2

    def test_load_normalizes_scheme(self):
        pool = ProxyPool()
        pool.load_from_list(["1.2.3.4:8080"])
        assert "http://1.2.3.4:8080" in pool.proxies

    def test_load_dedup(self):
        pool = ProxyPool()
        n = pool.load_from_list(["1.2.3.4:8080", "1.2.3.4:8080"])
        assert n == 1

    def test_load_from_file(self, tmp_path):
        f = tmp_path / "proxies.txt"
        f.write_text("# comment\nhttp://1.2.3.4:8080\n\nhttp://5.6.7.8:1080\n",
                     encoding="utf-8")
        pool = ProxyPool()
        n = pool.load_from_file(str(f))
        assert n == 2

    def test_load_from_file_missing(self):
        pool = ProxyPool()
        assert pool.load_from_file("__no_such__.txt") == 0

    def test_load_from_env(self, monkeypatch):
        monkeypatch.setenv("PROXY_LIST", "http://1.2.3.4:8080,http://5.6.7.8:1080")
        pool = ProxyPool()
        assert pool.load_from_env() == 2

    def test_load_from_env_empty(self, monkeypatch):
        monkeypatch.delenv("PROXY_LIST", raising=False)
        pool = ProxyPool()
        assert pool.load_from_env() == 0

    def test_load_from_api_json_list(self):
        pool = ProxyPool()
        with patch("src.xiazhi.proxy_pool.httpx.get") as g:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = ["http://1.2.3.4:8080", "http://5.6.7.8:1080"]
            g.return_value = resp
            assert pool.load_from_api("http://api") == 2

    def test_load_from_api_text(self):
        pool = ProxyPool()
        with patch("src.xiazhi.proxy_pool.httpx.get") as g:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.side_effect = Exception("boom")
            resp.text = "http://1.2.3.4:8080\nhttp://5.6.7.8:1080\n"
            g.return_value = resp
            assert pool.load_from_api("http://api") == 2

    def test_load_from_api_failure(self):
        pool = ProxyPool()
        with patch("src.xiazhi.proxy_pool.httpx.get", side_effect=Exception("net")):
            assert pool.load_from_api("http://api") == 0


# ── 选取 / 反馈 ────────────────────────────────────────────

class TestProxyPoolSelect:
    def _pool_two(self):
        pool = ProxyPool(min_score=0.0)
        pool.load_from_list(["http://1.2.3.4:8080", "http://5.6.7.8:1080"])
        return pool

    def test_get_returns_alive(self):
        pool = self._pool_two()
        url = pool.get()
        assert url in ("http://1.2.3.4:8080", "http://5.6.7.8:1080")

    def test_get_none_when_empty(self):
        pool = ProxyPool(min_score=0.0)
        assert pool.get() is None

    def test_get_rr_cycles(self):
        pool = self._pool_two()
        a = pool.get_rr()
        b = pool.get_rr()
        assert {a, b} == {"http://1.2.3.4:8080", "http://5.6.7.8:1080"}

    def test_get_random(self):
        pool = self._pool_two()
        url = pool.get_random()
        assert url in ("http://1.2.3.4:8080", "http://5.6.7.8:1080")

    def test_report_success(self):
        pool = self._pool_two()
        url = "http://1.2.3.4:8080"
        pool.report_success(url)
        assert pool.proxies[url].success_count == 1
        assert pool.proxies[url].alive is True

    def test_report_fail_disables(self):
        pool = ProxyPool(max_fails=2, min_score=0.0)
        pool.load_from_list(["http://1.2.3.4:8080"])
        url = "http://1.2.3.4:8080"
        pool.report_fail(url)
        assert pool.proxies[url].alive is True   # 1 < max_fails
        pool.report_fail(url)
        assert pool.proxies[url].alive is False  # 达到阈值

    def test_dead_excluded_from_select(self):
        pool = ProxyPool(min_score=0.0)
        pool.load_from_list(["http://1.2.3.4:8080", "http://5.6.7.8:1080"])
        pool.proxies["http://1.2.3.4:8080"].alive = False
        assert pool.get() == "http://5.6.7.8:1080"


# ── 统计 ───────────────────────────────────────────────────

class TestProxyPoolStats:
    def test_stats(self):
        pool = ProxyPool(min_score=0.0)
        pool.load_from_list(["http://1.2.3.4:8080", "http://5.6.7.8:1080"])
        pool.proxies["http://1.2.3.4:8080"].alive = False
        s = pool.stats()
        assert s["total"] == 2
        assert s["alive"] == 1
        assert s["dead"] == 1

    def test_list_proxies_sorted(self):
        pool = ProxyPool(min_score=0.0)
        pool.load_from_list(["http://1.2.3.4:8080", "http://5.6.7.8:1080"])
        pool.proxies["http://1.2.3.4:8080"].success_count = 10
        ranked = pool.list_proxies(only_alive=True)
        assert ranked[0].url == "http://1.2.3.4:8080"  # 高分在前

    def test_print_stats(self, capsys):
        pool = ProxyPool(min_score=0.0)
        pool.load_from_list(["http://1.2.3.4:8080"])
        pool.print_stats()
        assert "代理池统计" in capsys.readouterr().out


# ── 验证 ───────────────────────────────────────────────────

class TestProxyPoolValidate:
    def test_validate_all_success(self):
        pool = ProxyPool(min_score=0.0)
        pool.load_from_list(["http://1.2.3.4:8080", "http://5.6.7.8:1080"])
        with _patch_client(status=200, json_data={"origin": "1.1.1.1"}):
            results = asyncio.run(pool.validate_all(concurrency=5))
        assert all(results.values())
        for p in pool.proxies.values():
            assert p.alive is True
            assert p.latency >= 0

    def test_validate_all_failure(self):
        pool = ProxyPool(max_fails=5, min_score=0.0)
        pool.load_from_list(["http://1.2.3.4:8080"])
        with _patch_client(status=403):
            results = asyncio.run(pool.validate_all(concurrency=1))
        assert not results["http://1.2.3.4:8080"]
        assert pool.proxies["http://1.2.3.4:8080"].fail_count == 1

    def test_validate_all_exception(self):
        import httpx
        pool = ProxyPool(max_fails=5, min_score=0.0)
        pool.load_from_list(["http://1.2.3.4:8080"])
        with _patch_client(raise_exc=httpx.ConnectError("down")):
            results = asyncio.run(pool.validate_all(concurrency=1))
        assert not results["http://1.2.3.4:8080"]
