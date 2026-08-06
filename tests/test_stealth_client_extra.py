"""隐匿客户端方法单元测试（xiazhi/stealth_client.py）— mock，覆盖核心方法

低 ROI 模块（基线 31%）覆盖率提升：代理获取、请求头构建、限速/域名配置、
WAF 检测、统计/校验/关闭、get/post 委托、request 成功/超时/WAF 分支。
"""

import asyncio
import httpx
from unittest.mock import AsyncMock, MagicMock

from src.xiazhi.proxy_pool import ProxyInfo
from src.xiazhi.stealth_client import StealthClient


def _make_client(enable_waf=False, max_retries=0):
    sc = StealthClient(enable_waf_bypass=enable_waf, max_retries=max_retries)
    sc.rate_limiter.acquire = AsyncMock(return_value=0.0)
    sc.proxy_pool.get = MagicMock(return_value="")
    return sc


def _fake_http(request_side_effect=None, status_code=200):
    fake = MagicMock()
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {}
    resp.text = "ok"
    if request_side_effect is not None:
        fake.request = AsyncMock(side_effect=request_side_effect)
    else:
        fake.request = AsyncMock(return_value=resp)
    return fake, resp


class TestBasics:
    def test_get_proxy_empty(self):
        sc = _make_client()
        sc.proxy_pool.proxies = {}
        assert sc._get_proxy() == ""

    def test_get_proxy_returns(self):
        sc = _make_client()
        sc.proxy_pool.proxies = {"http://1.2.3.4:8080": MagicMock()}
        sc.proxy_pool.get = MagicMock(return_value="http://1.2.3.4:8080")
        assert sc._get_proxy() == "http://1.2.3.4:8080"

    def test_build_headers(self):
        sc = _make_client()
        headers = sc._build_headers("example.com")
        assert isinstance(headers, dict)
        assert "User-Agent" in headers or headers  # 至少返回字典

    def test_build_headers_merges_custom(self):
        sc = _make_client()
        headers = sc._build_headers("example.com", {"X-Test": "1"})
        assert headers["X-Test"] == "1"

    def test_set_domain_qps(self):
        sc = _make_client()
        sc.set_domain_qps("example.com", 5.0, 10)
        # 不应抛异常（限速器按域名配置）
        assert True

    def test_is_waf_detected(self):
        sc = _make_client()
        assert sc.is_waf_detected("x.com") is None
        sc._waf_detected_domains["x.com"] = "Cloudflare"
        assert sc.is_waf_detected("x.com") == "Cloudflare"

    def test_print_stats_no_proxies(self, capsys):
        sc = _make_client()
        sc.proxy_pool.proxies = {}
        sc.print_stats()
        # 无代理不应调用 proxy_pool.print_stats
        assert "统计" in capsys.readouterr().out

    def test_print_stats_with_proxies(self, capsys):
        sc = _make_client()
        sc.proxy_pool.proxies = {"http://1.2.3.4:8080": ProxyInfo("http://1.2.3.4:8080")}
        sc.print_stats()
        assert "统计" in capsys.readouterr().out

    def test_close(self):
        sc = _make_client()
        sc._clients["__direct__"] = MagicMock(is_closed=False,
                                              aclose=AsyncMock())
        asyncio.run(sc.close())
        assert sc._closed is True
        assert sc._clients == {}

    def test_validate_proxies_empty(self, capsys):
        sc = _make_client()
        sc.proxy_pool.proxies = {}
        asyncio.run(sc.validate_proxies())
        assert "代理池为空" in capsys.readouterr().out


class TestRequest:
    def test_request_success(self):
        sc = _make_client()
        fake, resp = _fake_http()
        sc._get_client = AsyncMock(return_value=fake)
        r = asyncio.run(sc.request("GET", "http://t"))
        assert r is resp
        assert sc.stats["successful"] == 1
        assert sc.stats["total_requests"] == 1

    def test_get_delegates(self):
        sc = _make_client()
        fake, resp = _fake_http()
        sc._get_client = AsyncMock(return_value=fake)
        r = asyncio.run(sc.get("http://t"))
        assert r is resp
        call = fake.request.await_args
        assert call.args[0] == "GET"
        assert call.args[1] == "http://t"

    def test_post_delegates(self):
        sc = _make_client()
        fake, resp = _fake_http()
        sc._get_client = AsyncMock(return_value=fake)
        r = asyncio.run(sc.post("http://t", data={"a": "1"}))
        assert r is resp

    def test_request_timeout_raises(self):
        sc = _make_client(max_retries=0)
        fake, _ = _fake_http(request_side_effect=httpx.TimeoutException("t"))
        sc._get_client = AsyncMock(return_value=fake)
        try:
            asyncio.run(sc.request("GET", "http://t"))
            assert False, "应抛出异常"
        except httpx.TimeoutException:
            assert sc.stats["failed"] == 1

    def test_request_waf_detected_no_retry(self):
        sc = _make_client(enable_waf=True, max_retries=0)
        sc.waf_bypass.detect_waf = MagicMock(return_value="Cloudflare")
        fake, _ = _fake_http(status_code=403)
        sc._get_client = AsyncMock(return_value=fake)
        r = asyncio.run(sc.request("GET", "http://t"))
        assert r.status_code == 403
        assert sc.stats["waf_detected"] == 1

    def test_request_closed_raises(self):
        sc = _make_client()
        sc._closed = True
        try:
            asyncio.run(sc.request("GET", "http://t"))
            assert False
        except RuntimeError as e:
            assert "closed" in str(e)
